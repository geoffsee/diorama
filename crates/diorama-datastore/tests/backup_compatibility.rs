use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use diorama_datastore::backup::{BACKUP_FORMAT_VERSION, BACKUP_META_FILE, BackupMetadata};
use diorama_datastore::client::DatastoreClient;
use diorama_datastore::config::DatastoreConfig;
use diorama_datastore::engine::DatastoreEngine;

async fn populate_kubernetes_cluster_state(client: &DatastoreClient) {
    client
        .create("/registry/namespaces/default", b"ns-default".to_vec())
        .await
        .unwrap();
    client
        .create("/registry/namespaces/kube-system", b"ns-kube-sys".to_vec())
        .await
        .unwrap();
    client
        .create("/registry/pods/default/nginx", b"pod-nginx-v1".to_vec())
        .await
        .unwrap();
    client
        .create(
            "/registry/pods/kube-system/coredns",
            b"pod-coredns".to_vec(),
        )
        .await
        .unwrap();
    client
        .create(
            "/registry/services/specs/default/kubernetes",
            b"svc-k8s".to_vec(),
        )
        .await
        .unwrap();
    client
        .create(
            "/registry/leases/kube-system/kube-scheduler",
            b"lease-sched".to_vec(),
        )
        .await
        .unwrap();
    client
        .update(
            "/registry/pods/default/nginx",
            b"pod-nginx-v2".to_vec(),
            None,
        )
        .await
        .unwrap();
    client
        .delete("/registry/leases/kube-system/kube-scheduler", None)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_disposable_backup_restore_round_trip_preserves_records_and_revisions() {
    let tmp = tempdir().unwrap();
    let source_dir = tmp.path().join("source-etcd");
    let backup_dir = tmp.path().join("backup-store");
    let restore_dir = tmp.path().join("restored-etcd");

    let source_config = DatastoreConfig::new(&source_dir);
    let (engine, _) = DatastoreEngine::open(source_config).unwrap();
    let client = DatastoreClient::new(engine);

    populate_kubernetes_cluster_state(&client).await;

    let backup_revision = client.current_revision().await;
    assert_eq!(backup_revision, 8);

    // Create consistent point-in-time backup
    let meta = client.create_backup(&backup_dir).await.unwrap();
    assert_eq!(meta.format_version, BACKUP_FORMAT_VERSION);
    assert_eq!(meta.revision, 8);
    assert_eq!(meta.total_keys, 5); // 6 created - 1 deleted = 5 keys
    assert_ne!(meta.snapshot_sha256, "");

    // Mutate source datastore after backup to demonstrate divergence
    client
        .create(
            "/registry/pods/default/new-pod",
            b"pod-after-backup".to_vec(),
        )
        .await
        .unwrap();
    client
        .update(
            "/registry/pods/default/nginx",
            b"pod-nginx-v3-diverged".to_vec(),
            None,
        )
        .await
        .unwrap();
    client
        .delete("/registry/namespaces/default", None)
        .await
        .unwrap();
    assert_eq!(client.current_revision().await, 11);

    // Restore backup into a completely clean disposable destination directory
    let restored_meta = DatastoreEngine::restore_backup(&backup_dir, &restore_dir).unwrap();
    assert_eq!(restored_meta, meta);

    // Open restored engine
    let restore_config = DatastoreConfig::new(&restore_dir);
    let (restored_engine, _) = DatastoreEngine::open(restore_config).unwrap();
    let restored_client = DatastoreClient::new(restored_engine);

    // Acceptance criterion: API-visible records and revisions are preserved exactly as of backup time
    assert_eq!(restored_client.current_revision().await, 8);

    let nginx = restored_client
        .get("/registry/pods/default/nginx")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(nginx.value, b"pod-nginx-v2");
    assert_eq!(nginx.version, 2);
    assert_eq!(nginx.mod_revision, 7);

    assert!(
        restored_client
            .get("/registry/leases/kube-system/kube-scheduler")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        restored_client
            .get("/registry/pods/default/new-pod")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        restored_client
            .get("/registry/namespaces/default")
            .await
            .unwrap()
            .is_some()
    );

    let post_restore_pod = restored_client
        .create("/registry/pods/default/restored-op", b"fresh-pod".to_vec())
        .await
        .unwrap();
    assert_eq!(post_restore_pod.mod_revision, 9);
    assert_eq!(restored_client.current_revision().await, 9);
}

#[tokio::test]
async fn test_unsupported_format_reuse_is_explicitly_rejected() {
    let tmp = tempdir().unwrap();
    let backup_dir = tmp.path().join("unsupported-format-backup");
    let dest_dir = tmp.path().join("dest-dir");
    std::fs::create_dir_all(&backup_dir).unwrap();

    // 1. Missing metadata file
    let err = DatastoreEngine::restore_backup(&backup_dir, &dest_dir).unwrap_err();
    assert_eq!(err.diagnostic_code(), "datastore-fatal-error");
    assert!(err.to_string().contains("missing backup metadata file"));

    // 2. Foreign unsupported format version (e.g. SQLite / Kine table format)
    let foreign_meta = BackupMetadata {
        format_version: "sqlite-kine-v1".to_string(),
        revision: 10,
        timestamp_secs: 123_456,
        total_keys: 1,
        snapshot_sha256: "fake-sha".to_string(),
    };
    std::fs::write(
        backup_dir.join(BACKUP_META_FILE),
        serde_json::to_vec(&foreign_meta).unwrap(),
    )
    .unwrap();

    let err = DatastoreEngine::restore_backup(&backup_dir, &dest_dir).unwrap_err();
    assert_eq!(err.diagnostic_code(), "datastore-fatal-error");
    assert!(
        err.to_string()
            .contains("unsupported backup format version")
    );

    // 3. Tampered / checksum mismatch on snapshot payload
    let snapshot_file = backup_dir.join("snapshot.db");
    {
        let mut f = File::create(&snapshot_file).unwrap();
        f.write_all(b"actual-payload-content").unwrap();
    }
    let tampered_meta = BackupMetadata {
        format_version: BACKUP_FORMAT_VERSION.to_string(),
        revision: 10,
        timestamp_secs: 123_456,
        total_keys: 1,
        snapshot_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
    };
    std::fs::write(
        backup_dir.join(BACKUP_META_FILE),
        serde_json::to_vec(&tampered_meta).unwrap(),
    )
    .unwrap();

    let err = DatastoreEngine::restore_backup(&backup_dir, &dest_dir).unwrap_err();
    assert_eq!(err.diagnostic_code(), "datastore-fatal-error");
    assert!(err.to_string().contains("checksum mismatch"));

    // 4. Attempting to start datastore directly from raw SQLite database without diorama format
    let raw_sqlite_dir = tmp.path().join("sqlite-db-dir");
    std::fs::create_dir_all(&raw_sqlite_dir).unwrap();
    {
        let mut f = File::create(raw_sqlite_dir.join("snapshot.db")).unwrap();
        f.write_all(b"SQLite format 3\0").unwrap();
    }

    let config = DatastoreConfig::new(&raw_sqlite_dir);
    let Err(err) = DatastoreEngine::open(config) else {
        panic!("expected raw SQLite file to fail datastore open");
    };
    assert_eq!(err.diagnostic_code(), "datastore-fatal-error");
    assert!(err.to_string().contains("invalid snapshot magic header"));
}
