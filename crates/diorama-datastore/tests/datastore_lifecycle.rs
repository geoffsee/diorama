use diorama_datastore::{
    DatastoreAdapter, DatastoreClient, DatastoreConfig, DatastoreEngine, DatastoreError,
    WatchEventType,
};
use diorama_supervisor::{Supervisor, stop_channel};
use std::time::Duration;
use tempfile::tempdir;

#[tokio::test]
async fn test_missing_and_healthy_directory_startup() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("missing/etcd/dir");

    // Directory does not exist yet
    assert!(!data_dir.exists());

    let config = DatastoreConfig::new(&data_dir);
    let (engine, summary) = DatastoreEngine::open(config.clone()).unwrap();

    assert!(data_dir.exists());
    assert_eq!(summary.total_records, 0);
    assert_eq!(engine.current_revision().await, 0);

    // Drop engine to release lock
    drop(engine);

    // Reopen existing healthy directory
    let (engine2, summary2) = DatastoreEngine::open(config).unwrap();
    assert_eq!(summary2.total_records, 0);
    assert_eq!(engine2.current_revision().await, 0);
}

#[tokio::test]
async fn test_lock_contention_preserves_original_diagnostic() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("etcd-lock-test");

    let config = DatastoreConfig::new(&data_dir);
    let (engine, _) = DatastoreEngine::open(config.clone()).unwrap();

    // Second open on same data directory must fail with LockContention
    let Err(err) = DatastoreEngine::open(config) else {
        panic!("expected lock contention error");
    };

    assert!(err.is_lock_contention());
    assert_eq!(err.diagnostic_code(), "datastore-lock-contention");

    drop(engine);
}

#[tokio::test]
async fn test_authentication_failure_preserves_diagnostic() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("etcd-auth-test");

    // Configure client_cert_auth with non-existent cert files
    let config = DatastoreConfig::new(&data_dir).with_client_tls(
        data_dir.join("missing-ca.crt"),
        data_dir.join("missing-cert.crt"),
        data_dir.join("missing-key.key"),
    );

    let Err(err) = DatastoreEngine::open(config) else {
        panic!("expected authentication error");
    };

    assert!(err.is_auth_failure());
    assert_eq!(err.diagnostic_code(), "datastore-auth-failure");
}

#[tokio::test]
async fn test_crud_and_resource_version_monotonicity() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("etcd-crud-test");

    let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(&data_dir)).unwrap();
    let client = DatastoreClient::new(engine);

    let key = "/registry/pods/default/nginx";
    let val1 = b"{\"spec\":{\"containers\":[{\"name\":\"nginx\"}]}}".to_vec();

    // 1. Create
    let created = client.create(key, val1.clone()).await.unwrap();
    assert_eq!(created.key, key);
    assert_eq!(created.value, val1);
    assert_eq!(created.create_revision, 1);
    assert_eq!(created.mod_revision, 1);
    assert_eq!(created.version, 1);
    assert_eq!(client.current_revision().await, 1);

    // 2. Duplicate create fails
    let err = client.create(key, b"dup".to_vec()).await.unwrap_err();
    assert!(matches!(err, DatastoreError::KeyAlreadyExists(_)));

    // 3. Update with matching expected revision
    let val2 = b"{\"spec\":{\"containers\":[{\"name\":\"nginx-v2\"}]}}".to_vec();
    let updated = client.update(key, val2.clone(), Some(1)).await.unwrap();
    assert_eq!(updated.key, key);
    assert_eq!(updated.value, val2);
    assert_eq!(updated.create_revision, 1);
    assert_eq!(updated.mod_revision, 2);
    assert_eq!(updated.version, 2);
    assert_eq!(client.current_revision().await, 2);

    // 4. Update with outdated revision fails
    let err = client
        .update(key, b"conflict".to_vec(), Some(1))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        DatastoreError::RevisionMismatch {
            expected: 1,
            actual: 2
        }
    ));

    // 5. Delete with matching expected revision
    let deleted = client.delete(key, Some(2)).await.unwrap().unwrap();
    assert_eq!(deleted.mod_revision, 2);
    assert_eq!(client.current_revision().await, 3);

    // 6. Get deleted returns None
    assert!(client.get(key).await.unwrap().is_none());
}

#[tokio::test]
async fn test_watch_receives_live_events() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("etcd-watch-test");

    let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(&data_dir)).unwrap();
    let client = DatastoreClient::new(engine);

    let mut watcher = client.watch("/registry/pods/").await;

    // Mutation with non-matching prefix must NOT be received by watcher
    client
        .create("/registry/services/default/web", b"web-svc".to_vec())
        .await
        .unwrap();

    let key = "/registry/pods/default/redis";
    client.create(key, b"redis-1".to_vec()).await.unwrap();

    let event1 = watcher.recv().await.unwrap();
    assert_eq!(event1.event_type, WatchEventType::Put);
    assert_eq!(event1.kv.key, key);
    assert_eq!(event1.kv.mod_revision, 2);

    client.update(key, b"redis-2".to_vec(), None).await.unwrap();
    let event2 = watcher.recv().await.unwrap();
    assert_eq!(event2.event_type, WatchEventType::Put);
    assert_eq!(event2.kv.mod_revision, 3);
    assert_eq!(event2.prev_kv.unwrap().mod_revision, 2);

    client.delete(key, None).await.unwrap();
    let event3 = watcher.recv().await.unwrap();
    assert_eq!(event3.event_type, WatchEventType::Delete);
    assert_eq!(event3.kv.key, key);
}

#[tokio::test]
async fn test_clean_restart_preserves_committed_state() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("etcd-restart-test");

    let config = DatastoreConfig::new(&data_dir);
    let (engine, _) = DatastoreEngine::open(config.clone()).unwrap();
    let client = DatastoreClient::new(engine.clone());

    client
        .create("/registry/services/svc1", b"data1".to_vec())
        .await
        .unwrap();
    client
        .create("/registry/services/svc2", b"data2".to_vec())
        .await
        .unwrap();
    client
        .update("/registry/services/svc1", b"data1-updated".to_vec(), None)
        .await
        .unwrap();
    client
        .delete("/registry/services/svc2", None)
        .await
        .unwrap();

    let final_rev = client.current_revision().await;
    assert_eq!(final_rev, 4);

    // Clean checkpoint and shutdown
    engine.checkpoint_snapshot().await.unwrap();
    drop(client);
    drop(engine);

    // Reopen from disk
    let (engine_reopened, summary) = DatastoreEngine::open(config).unwrap();
    let client2 = DatastoreClient::new(engine_reopened);

    assert_eq!(client2.current_revision().await, final_rev);

    let svc1 = client2
        .get("/registry/services/svc1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(svc1.value, b"data1-updated");
    assert_eq!(svc1.version, 2);
    assert_eq!(svc1.mod_revision, 3);

    // svc2 remains deleted
    assert!(
        client2
            .get("/registry/services/svc2")
            .await
            .unwrap()
            .is_none()
    );

    // Total records in WAL
    assert_eq!(summary.total_records, 4);
}

#[tokio::test]
async fn test_supervisor_adapter_lifecycle() {
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("etcd-supervisor-test");

    let config = DatastoreConfig::new(&data_dir);
    let registration =
        DatastoreAdapter::registration("etcd-datastore", config, Duration::from_secs(5));

    let (stop_handle, stop_receiver) = stop_channel();
    let supervisor = Supervisor::new(vec![registration]).unwrap();

    let supervisor_task = tokio::spawn(supervisor.run(stop_receiver));

    // Give it a moment to become ready
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify data directory was created and initialized
    assert!(data_dir.exists());

    // Request stop
    assert!(stop_handle.stop());

    let report = supervisor_task.await.unwrap();
    assert!(
        report.failures.is_empty(),
        "unexpected supervisor failures: {:?}",
        report.failures
    );
    assert!(
        report.cleanup_failures.is_empty(),
        "unexpected cleanup failures: {:?}",
        report.cleanup_failures
    );
}
