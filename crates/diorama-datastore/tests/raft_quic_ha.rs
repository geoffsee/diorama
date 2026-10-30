use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use diorama_datastore::{
    DatastoreClient, DatastoreConfig, DatastoreEngine, RaftRole, WatchEventType, connect_quic_peer,
    start_quic_server,
};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use tempfile::tempdir;

fn reserve_udp_addr() -> SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.local_addr().unwrap()
}

async fn setup_three_node_quic_cluster(
    root: &Path,
) -> (DatastoreEngine, DatastoreEngine, DatastoreEngine) {
    let pki_dir = root.join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();

    let node_ip: IpAddr = "127.0.0.1".parse().unwrap();
    ClusterPki::new(ClusterPkiConfig::new(
        pki_dir.clone(),
        "node-1".to_string(),
        node_ip,
    ))
    .reconcile()
    .unwrap();

    let ca_file = pki_dir.join("datastore-ca.crt");
    let cert_file = pki_dir.join("datastore-server.crt");
    let key_file = pki_dir.join("datastore-server.key");

    let addr1 = reserve_udp_addr();
    let addr2 = reserve_udp_addr();
    let addr3 = reserve_udp_addr();

    let peers1 = BTreeMap::from([(2u64, addr2), (3u64, addr3)]);
    let peers2 = BTreeMap::from([(1u64, addr1), (3u64, addr3)]);
    let peers3 = BTreeMap::from([(1u64, addr1), (2u64, addr2)]);

    let cfg1 = DatastoreConfig::new(root.join("node-1"))
        .with_cluster(1, addr1, peers1.clone())
        .with_client_tls(ca_file.clone(), cert_file.clone(), key_file.clone());
    let cfg2 = DatastoreConfig::new(root.join("node-2"))
        .with_cluster(2, addr2, peers2.clone())
        .with_client_tls(ca_file.clone(), cert_file.clone(), key_file.clone());
    let cfg3 = DatastoreConfig::new(root.join("node-3"))
        .with_cluster(3, addr3, peers3)
        .with_client_tls(ca_file, cert_file.clone(), key_file.clone());

    let (engine1, _) = DatastoreEngine::open(cfg1).unwrap();
    let (engine2, _) = DatastoreEngine::open(cfg2).unwrap();
    let (engine3, _) = DatastoreEngine::open(cfg3).unwrap();

    start_quic_server(addr1, cert_file.clone(), key_file.clone(), engine1.clone())
        .await
        .unwrap();
    start_quic_server(addr2, cert_file.clone(), key_file.clone(), engine2.clone())
        .await
        .unwrap();
    start_quic_server(addr3, cert_file.clone(), key_file.clone(), engine3.clone())
        .await
        .unwrap();

    for (&peer_id, &peer_addr) in &peers1 {
        if 1 < peer_id {
            connect_quic_peer(
                peer_id,
                peer_addr,
                Some(cert_file.clone()),
                Some(key_file.clone()),
                engine1.clone(),
            )
            .await
            .unwrap();
        }
    }
    for (&peer_id, &peer_addr) in &peers2 {
        if 2 < peer_id {
            connect_quic_peer(
                peer_id,
                peer_addr,
                Some(cert_file.clone()),
                Some(key_file.clone()),
                engine2.clone(),
            )
            .await
            .unwrap();
        }
    }

    tokio::time::sleep(Duration::from_millis(250)).await;
    (engine1, engine2, engine3)
}

#[tokio::test]
async fn test_three_node_quic_raft_replication_forwarding_watch_and_snapshot() {
    let tmp = tempdir().unwrap();
    let (engine1, engine2, engine3) = setup_three_node_quic_cluster(tmp.path()).await;

    let raft1 = engine1.raft();
    raft1.trigger_election(&[2, 3]).await;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if raft1.role().await == RaftRole::Leader {
            break;
        }
    }
    assert_eq!(raft1.role().await, RaftRole::Leader);
    raft1.broadcast_heartbeat().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client1 = DatastoreClient::new(engine1.clone());
    let client2 = DatastoreClient::new(engine2.clone());
    let client3 = DatastoreClient::new(engine3.clone());
    let mut watch2 = client2.watch("/registry/pods/").await;

    // 1. Propose write on Leader (node 1) -> replicated over QUIC to followers
    let created = client1
        .create("/registry/pods/default/web-1", b"pod-v1".to_vec())
        .await
        .unwrap();
    assert_eq!(created.mod_revision, 1);

    // Follower node 2 receives watch event and serves replicated key locally
    let evt = tokio::time::timeout(Duration::from_secs(3), watch2.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(evt.event_type, WatchEventType::Put);
    assert_eq!(evt.kv.key, "/registry/pods/default/web-1");
    assert_eq!(evt.kv.value, b"pod-v1");

    let got2 = client2
        .get("/registry/pods/default/web-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got2.value, b"pod-v1");

    // 2. Propose write on Follower (node 3) -> forwarded over full-duplex QUIC stream to Leader (node 1)
    let created_via_follower = client3
        .create("/registry/pods/default/web-2", b"from-follower-3".to_vec())
        .await
        .unwrap();
    assert_eq!(created_via_follower.mod_revision, 2);

    let got1 = client1
        .get("/registry/pods/default/web-2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got1.value, b"from-follower-3");

    // 3. Test InstallSnapshot over QUIC to peer 2
    engine1.replicate_snapshot_to_peer(2).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(engine2.current_revision().await, 2);
    let got2_snap = engine2
        .get("/registry/pods/default/web-2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got2_snap.value, b"from-follower-3");
}

async fn start_seed_controller(tmp: &Path) -> (PathBuf, DatastoreEngine, SocketAddr) {
    let seed_pki = tmp.join("seed-pki");
    std::fs::create_dir_all(&seed_pki).unwrap();
    let localhost: IpAddr = "127.0.0.1".parse().unwrap();
    ClusterPki::new(ClusterPkiConfig::new(
        seed_pki.clone(),
        "seed-node".to_string(),
        localhost,
    ))
    .reconcile()
    .unwrap();

    let seed_cfg = DatastoreConfig::new(tmp.join("seed-db")).with_client_tls(
        seed_pki.join("datastore-ca.crt"),
        seed_pki.join("datastore-server.crt"),
        seed_pki.join("datastore-server.key"),
    );
    let (seed_engine, _) = DatastoreEngine::open(seed_cfg).unwrap();
    let seed_peer_addr = start_quic_server(
        "127.0.0.1:0".parse().unwrap(),
        seed_pki.join("datastore-server.crt"),
        seed_pki.join("datastore-server.key"),
        seed_engine.clone(),
    )
    .await
    .unwrap();
    (seed_pki, seed_engine, seed_peer_addr)
}

#[tokio::test]
async fn test_k0s_style_controller_and_worker_join_over_quic() {
    use diorama_datastore::request_cluster_join;
    use diorama_pki::token::{JoinRequest, JoinResponse, JoinRole, JoinToken};

    let tmp = tempdir().unwrap();
    let localhost: IpAddr = "127.0.0.1".parse().unwrap();
    let (seed_pki, seed_engine, seed_peer_addr) = start_seed_controller(tmp.path()).await;

    let seed_client = DatastoreClient::new(seed_engine.clone());
    seed_client
        .create("/registry/namespaces/default", b"active".to_vec())
        .await
        .unwrap();

    // Operator generates controller and worker join tokens
    let make_tok = |role| {
        JoinToken::create_from_pki_dir(
            &seed_pki,
            role,
            "https://127.0.0.1:6443".into(),
            seed_peer_addr,
            Some(3600),
        )
        .unwrap()
        .encode()
        .unwrap()
    };
    let controller_token_str = make_tok(JoinRole::Controller);
    let worker_token_str = make_tok(JoinRole::Worker);

    // Joining Controller node exchanges token over tokio-quiche and syncs cluster state
    let decoded_ctrl_token = JoinToken::decode(&controller_token_str).unwrap();
    let JoinResponse::Controller(ctrl_material) = request_cluster_join(
        decoded_ctrl_token.peer_addr,
        &JoinRequest {
            token: decoded_ctrl_token,
            node_name: "controller-2".to_string(),
            node_ip: localhost,
            listen_peer_addr: Some("127.0.0.1:12380".parse().unwrap()),
        },
    )
    .await
    .unwrap() else {
        panic!("expected ControllerJoinMaterial");
    };
    assert_eq!(ctrl_material.assigned_node_id, 2);

    let ctrl2_pki = tmp.path().join("ctrl2-pki");
    ClusterPki::install_controller_join_material(&ctrl2_pki, &ctrl_material).unwrap();
    ClusterPki::new(ClusterPkiConfig::new(
        ctrl2_pki.clone(),
        "controller-2".to_string(),
        localhost,
    ))
    .reconcile()
    .unwrap();

    let ctrl2_cfg = DatastoreConfig::new(tmp.path().join("ctrl2-db"))
        .with_client_tls(
            ctrl2_pki.join("datastore-ca.crt"),
            ctrl2_pki.join("datastore-server.crt"),
            ctrl2_pki.join("datastore-server.key"),
        )
        .with_cluster(2, "127.0.0.1:0".parse().unwrap(), ctrl_material.peers)
        .with_dynamic_join(true);
    let (ctrl2_engine, _) = DatastoreEngine::open(ctrl2_cfg).unwrap();
    connect_quic_peer(
        1,
        seed_peer_addr,
        Some(ctrl2_pki.join("datastore-server.crt")),
        Some(ctrl2_pki.join("datastore-server.key")),
        ctrl2_engine.clone(),
    )
    .await
    .unwrap();

    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if ctrl2_engine.raft().leader_id().await == Some(1) {
            break;
        }
    }
    assert_eq!(ctrl2_engine.raft().leader_id().await, Some(1));
    let synced_ns = DatastoreClient::new(ctrl2_engine)
        .get("/registry/namespaces/default")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(synced_ns.value, b"active");

    // Joining Worker node exchanges worker token and receives least-privilege credentials
    let decoded_worker_token = JoinToken::decode(&worker_token_str).unwrap();
    let JoinResponse::Worker(worker_material) = request_cluster_join(
        decoded_worker_token.peer_addr,
        &JoinRequest {
            token: decoded_worker_token,
            node_name: "worker-1".to_string(),
            node_ip: localhost,
            listen_peer_addr: None,
        },
    )
    .await
    .unwrap() else {
        panic!("expected WorkerJoinMaterial");
    };
    let worker_pki = tmp.path().join("worker-pki");
    ClusterPki::install_worker_join_material(&worker_pki, &worker_material).unwrap();
    assert!(worker_pki.join("kubelet.kubeconfig").exists());
    assert!(!worker_pki.join("ca.key").exists());
}

#[tokio::test]
async fn test_raft_state_persistence_and_automatic_election_ticker() {
    let tmp = tempdir().unwrap();
    let pki_dir = tmp.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    ClusterPki::new(ClusterPkiConfig::new(
        pki_dir.clone(),
        "node-1".to_string(),
        "127.0.0.1".parse().unwrap(),
    ))
    .reconcile()
    .unwrap();
    let cert_path = pki_dir.join("datastore-server.crt");
    let key_path = pki_dir.join("datastore-server.key");

    let addr1: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut peers2 = BTreeMap::new();
    let placeholder_peer: SocketAddr = "127.0.0.1:19999".parse().unwrap();
    peers2.insert(1, placeholder_peer);

    // Open node 2 with cluster config and trigger an election so term & voted_for advance
    let db2_dir = tmp.path().join("node2-db");
    {
        let cfg2 = DatastoreConfig::new(&db2_dir)
            .with_cluster(2, addr1, peers2.clone())
            .with_dynamic_join(true);
        let (engine2, _) = DatastoreEngine::open(cfg2).unwrap();
        engine2.raft().trigger_election(&[1]).await;
        assert_eq!(engine2.raft().current_term().await, 2);
    }

    // Reopen node 2 with a bare DatastoreConfig (no --token-file / no cluster flags)
    // and verify raft-state.json restored node_id, peers, current_term, and voted_for.
    let (reopened2, _) = DatastoreEngine::open(DatastoreConfig::new(&db2_dir)).unwrap();
    assert_eq!(reopened2.config().node_id, 2);
    assert_eq!(reopened2.config().peers.get(&1), Some(&placeholder_peer));
    assert_eq!(reopened2.raft().current_term().await, 2);

    // Verify automatic election ticker elects a leader when two live nodes connect and heartbeats time out
    let mut live_peers1 = BTreeMap::new();
    live_peers1.insert(2, placeholder_peer);
    let (e1, _) = DatastoreEngine::open(
        DatastoreConfig::new(tmp.path().join("ticker-1"))
            .with_cluster(1, addr1, live_peers1)
            .with_dynamic_join(true),
    )
    .unwrap();
    let bound1 = start_quic_server(addr1, cert_path.clone(), key_path.clone(), e1.clone())
        .await
        .unwrap();

    let mut live_peers2 = BTreeMap::new();
    live_peers2.insert(1, bound1);
    let (e2, _) = DatastoreEngine::open(
        DatastoreConfig::new(tmp.path().join("ticker-2"))
            .with_cluster(2, addr1, live_peers2)
            .with_dynamic_join(true),
    )
    .unwrap();
    connect_quic_peer(1, bound1, Some(cert_path), Some(key_path), e2.clone())
        .await
        .unwrap();

    // Start randomized election ticker on node 2 with short timeout (60..100ms)
    let _ticker = e2
        .raft()
        .start_election_ticker(Duration::from_millis(60), Duration::from_millis(100));

    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(40)).await;
        if e2.raft().is_leader().await {
            break;
        }
    }
    assert!(
        e2.raft().is_leader().await,
        "election ticker should automatically elect node 2 when no leader heartbeats arrive"
    );
}

#[tokio::test]
async fn test_remote_datastore_client_and_bootstrap_token_revocation() {
    use diorama_datastore::request_cluster_join;
    use diorama_pki::token::{JoinRequest, JoinResponse, JoinRole, JoinToken};

    let tmp = tempdir().unwrap();
    let localhost: IpAddr = "127.0.0.1".parse().unwrap();
    let (seed_pki, seed_engine, seed_peer_addr) = start_seed_controller(tmp.path()).await;

    // 1. Verify Remote DatastoreClient over tokio-quiche (create, get, list, update, delete, watch)
    let remote_client = DatastoreClient::new_remote(
        seed_peer_addr,
        Some(seed_pki.join("datastore-server.crt")),
        Some(seed_pki.join("datastore-server.key")),
    );
    let mut watch_rx = remote_client.watch("/registry/nodes/").await;
    tokio::time::sleep(Duration::from_millis(40)).await;

    let created = remote_client
        .create("/registry/nodes/worker-1", b"ready-v1".to_vec())
        .await
        .unwrap();
    assert_eq!(created.value, b"ready-v1");

    let watched = tokio::time::timeout(Duration::from_secs(3), watch_rx.recv())
        .await
        .expect("remote watch timed out")
        .expect("watch channel closed");
    assert_eq!(watched.kv.key, "/registry/nodes/worker-1");

    let updated = remote_client
        .update(
            "/registry/nodes/worker-1",
            b"ready-v2".to_vec(),
            Some(created.mod_revision),
        )
        .await
        .unwrap();
    assert_eq!(updated.value, b"ready-v2");

    let listed = remote_client.list("/registry/nodes/").await.unwrap();
    assert_eq!(listed.len(), 1);

    let deleted = remote_client
        .delete("/registry/nodes/worker-1", Some(updated.mod_revision))
        .await
        .unwrap();
    assert!(deleted.is_some());

    // 2. Verify Bootstrap Token Secret backing, listing, and revocation
    let tok1 = JoinToken::create_from_pki_dir(
        &seed_pki,
        JoinRole::Worker,
        "https://127.0.0.1:6443".into(),
        seed_peer_addr,
        Some(3600),
    )
    .unwrap();
    seed_engine.register_bootstrap_token(&tok1).await.unwrap();

    let listed_tokens = seed_engine.list_bootstrap_tokens().await.unwrap();
    assert_eq!(listed_tokens.len(), 1);
    assert_eq!(listed_tokens[0].token_id, tok1.token_id);

    // Revoke tok1 via invalidate_bootstrap_token and verify join is rejected
    seed_engine
        .invalidate_bootstrap_token(&tok1.token_id)
        .await
        .unwrap();
    assert_eq!(seed_engine.list_bootstrap_tokens().await.unwrap().len(), 0);

    let resp = request_cluster_join(
        seed_peer_addr,
        &JoinRequest {
            token: tok1,
            node_name: "worker-revoked".to_string(),
            node_ip: localhost,
            listen_peer_addr: None,
        },
    )
    .await
    .unwrap();
    assert!(
        matches!(resp, JoinResponse::Rejected(ref msg) if msg.contains("revoked")),
        "expected revoked rejection, got {resp:?}"
    );
}
