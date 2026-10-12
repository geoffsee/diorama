use std::fs::OpenOptions;
use std::io::Write;
use std::time::Duration;
use tempfile::tempdir;

use diorama_datastore::client::DatastoreClient;
use diorama_datastore::config::DatastoreConfig;
use diorama_datastore::engine::DatastoreEngine;
use diorama_datastore::lock::DatastoreLock;
use diorama_datastore::supervisor::DatastoreAdapter;
use diorama_supervisor::{ComponentFailure, FailureKind, StopCause, Supervisor, stop_channel};

#[tokio::test]
async fn test_abrupt_restart_preserves_committed_state() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("abrupt-restart-test");

    let config = DatastoreConfig::new(&data_dir);
    let (engine, _) = DatastoreEngine::open(config.clone()).unwrap();
    let client = DatastoreClient::new(engine.clone());

    // Commit mutations
    client
        .create("/registry/pods/p1", b"pod-one".to_vec())
        .await
        .unwrap();
    client
        .create("/registry/pods/p2", b"pod-two".to_vec())
        .await
        .unwrap();
    client
        .update("/registry/pods/p1", b"pod-one-v2".to_vec(), None)
        .await
        .unwrap();
    client.delete("/registry/pods/p2", None).await.unwrap();

    let committed_rev = client.current_revision().await;
    assert_eq!(committed_rev, 4);

    // Abrupt termination: drop engine without checkpoint_snapshot()
    drop(client);
    drop(engine);

    // Reopen engine
    let (restarted_engine, summary) = DatastoreEngine::open(config).unwrap();
    let restarted_client = DatastoreClient::new(restarted_engine);

    assert_eq!(restarted_client.current_revision().await, 4);
    assert_eq!(summary.total_records, 4);
    assert_eq!(summary.max_revision, 4);
    assert_eq!(summary.repaired_corruptions, 0);

    let p1 = restarted_client
        .get("/registry/pods/p1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p1.value, b"pod-one-v2");
    assert_eq!(p1.mod_revision, 3);

    let p2 = restarted_client.get("/registry/pods/p2").await.unwrap();
    assert!(p2.is_none());
}

#[tokio::test]
async fn test_torn_write_and_corrupt_wal_fails_without_opt_in_repair() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("torn-write-test");

    let config = DatastoreConfig::new(&data_dir);
    let (engine, _) = DatastoreEngine::open(config.clone()).unwrap();
    let client = DatastoreClient::new(engine.clone());

    client
        .create("/registry/configmaps/cm1", b"cm-data".to_vec())
        .await
        .unwrap();
    drop(client);
    drop(engine);

    let wal_path = config.wal_path();
    let original_len = std::fs::metadata(&wal_path).unwrap().len();

    // Append torn write bytes to WAL
    {
        let mut f = OpenOptions::new().append(true).open(&wal_path).unwrap();
        // A length prefix claiming 100 bytes followed by only 10 bytes
        f.write_all(&100u32.to_be_bytes()).unwrap();
        f.write_all(b"incomplete").unwrap();
        f.flush().unwrap();
    }

    // Default configuration (auto_repair_wal: false) must fail
    let Err(err) = DatastoreEngine::open(config.clone()) else {
        panic!("expected DatastoreError::CorruptWal without opt-in repair");
    };

    assert!(err.is_corruption());
    assert_eq!(err.diagnostic_code(), "datastore-wal-corrupt");

    // Verify repair was not silently performed
    let current_len = std::fs::metadata(&wal_path).unwrap().len();
    assert_eq!(current_len, original_len + 4 + 10);
}

#[tokio::test]
async fn test_opt_in_repair_truncates_torn_write_and_preserves_valid_data() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("opt-in-repair-test");

    let config = DatastoreConfig::new(&data_dir);
    let (engine, _) = DatastoreEngine::open(config.clone()).unwrap();
    let client = DatastoreClient::new(engine.clone());

    client
        .create("/registry/services/s1", b"service-1".to_vec())
        .await
        .unwrap();
    client
        .create("/registry/services/s2", b"service-2".to_vec())
        .await
        .unwrap();
    drop(client);
    drop(engine);

    let wal_path = config.wal_path();
    let valid_len = std::fs::metadata(&wal_path).unwrap().len();

    // Append torn write
    {
        let mut f = OpenOptions::new().append(true).open(&wal_path).unwrap();
        f.write_all(&50u32.to_be_bytes()).unwrap();
        f.write_all(b"corrupted-tail-data").unwrap();
        f.flush().unwrap();
    }

    // Open with explicit repair enabled
    let repair_config = config.with_wal_repair(true);
    let (repaired_engine, summary) = DatastoreEngine::open(repair_config).unwrap();
    let repaired_client = DatastoreClient::new(repaired_engine);

    // Verify summary reflects repair
    assert_eq!(summary.repaired_corruptions, 1);
    assert_eq!(summary.total_records, 2);
    assert_eq!(summary.max_revision, 2);

    // Verify all valid records prior to corruption remain intact
    let s1 = repaired_client
        .get("/registry/services/s1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s1.value, b"service-1");
    let s2 = repaired_client
        .get("/registry/services/s2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s2.value, b"service-2");

    // Verify WAL was truncated back to valid_len
    let final_wal_len = std::fs::metadata(&wal_path).unwrap().len();
    assert_eq!(final_wal_len, valid_len);

    // Verify subsequent writes succeed and increment revision
    let s3 = repaired_client
        .create("/registry/services/s3", b"service-3".to_vec())
        .await
        .unwrap();
    assert_eq!(s3.mod_revision, 3);
    assert_eq!(repaired_client.current_revision().await, 3);
}

#[tokio::test]
async fn test_fatal_wal_magic_corruption_cannot_be_repaired() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("wal-magic-corruption-test");

    let config = DatastoreConfig::new(&data_dir);
    let (engine, _) = DatastoreEngine::open(config.clone()).unwrap();
    drop(engine);

    let wal_path = config.wal_path();
    // Overwrite WAL magic bytes
    {
        let mut f = OpenOptions::new().write(true).open(&wal_path).unwrap();
        f.write_all(b"BADMAGIC").unwrap();
        f.flush().unwrap();
    }

    // Opening with repair enabled must still fail because invalid magic is fatal
    let repair_config = config.with_wal_repair(true);
    let Err(err) = DatastoreEngine::open(repair_config) else {
        panic!("expected fatal error for corrupted WAL magic");
    };

    assert!(err.is_corruption());
    assert_eq!(err.diagnostic_code(), "datastore-wal-corrupt");
}

#[tokio::test]
async fn test_fatal_snapshot_corruption_distinguishes_from_wal_repair() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("snapshot-corruption-test");

    let config = DatastoreConfig::new(&data_dir);
    let (engine, _) = DatastoreEngine::open(config.clone()).unwrap();
    drop(engine);

    let snapshot_path = config.snapshot_path();
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&snapshot_path)
            .unwrap();
        f.write_all(b"NOT_A_VALID_SNAPSHOT").unwrap();
        f.flush().unwrap();
    }

    let repair_config = config.with_wal_repair(true);
    let Err(err) = DatastoreEngine::open(repair_config) else {
        panic!("expected fatal error for corrupted snapshot");
    };

    assert_eq!(err.diagnostic_code(), "datastore-fatal-error");
}

#[tokio::test]
async fn test_supervisor_preserves_first_failure_diagnostic_on_wal_corruption() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("supervisor-wal-corrupt-test");

    let config = DatastoreConfig::new(&data_dir);
    let (engine, _) = DatastoreEngine::open(config.clone()).unwrap();
    drop(engine);

    // Corrupt WAL file
    let wal_path = config.wal_path();
    {
        let mut f = OpenOptions::new().append(true).open(&wal_path).unwrap();
        f.write_all(&25u32.to_be_bytes()).unwrap();
        f.write_all(b"corrupted-record-tail").unwrap();
        f.flush().unwrap();
    }

    let reg = DatastoreAdapter::registration("datastore", config, Duration::from_millis(500));
    let (_stop_handle, stop_receiver) = stop_channel();
    let supervisor = Supervisor::new(vec![reg]).unwrap();

    let report = supervisor.run(stop_receiver).await;
    assert_eq!(
        report.cause,
        StopCause::Fatal(ComponentFailure {
            component: "datastore".into(),
            kind: FailureKind::Adapter("datastore-wal-corrupt"),
        }),
        "supervisor must preserve first failure diagnostic datastore-wal-corrupt"
    );
}

#[tokio::test]
async fn test_supervisor_preserves_first_failure_diagnostic_on_lock_contention() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("supervisor-lock-contention-test");

    let config = DatastoreConfig::new(&data_dir);

    // Pre-acquire lock externally
    std::fs::create_dir_all(&data_dir).unwrap();
    let _lock = DatastoreLock::acquire(&data_dir).unwrap();

    let reg = DatastoreAdapter::registration("datastore", config, Duration::from_millis(500));
    let (_stop_handle, stop_receiver) = stop_channel();
    let supervisor = Supervisor::new(vec![reg]).unwrap();

    let report = supervisor.run(stop_receiver).await;
    assert_eq!(
        report.cause,
        StopCause::Fatal(ComponentFailure {
            component: "datastore".into(),
            kind: FailureKind::Adapter("datastore-lock-contention"),
        }),
        "supervisor must preserve first failure diagnostic datastore-lock-contention"
    );
}
