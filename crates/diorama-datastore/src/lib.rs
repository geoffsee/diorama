pub mod backup;
pub mod client;
pub mod config;
pub mod engine;
pub mod error;
pub mod lock;
pub mod model;
pub mod quic;
pub mod raft;
pub mod supervisor;
pub mod tls;
pub mod wal;

pub use backup::{BACKUP_FORMAT_VERSION, BackupMetadata};
pub use client::DatastoreClient;
pub use config::DatastoreConfig;
pub use engine::DatastoreEngine;
pub use error::DatastoreError;
pub use lock::DatastoreLock;
pub use model::{
    DatastoreOp, KeyValue, RemoteKvRequest, RemoteKvResponse, WatchEvent, WatchEventType,
    WatchReceiver,
};
pub use quic::{
    connect_quic_peer, execute_remote_kv_rpc, request_cluster_join, start_quic_server,
    start_remote_kv_watch,
};
pub use raft::{
    PersistedRaftState, ProposalCommand, ProposalOutcome, RaftHandle, RaftMessage, RaftRole,
    RaftState,
};
pub use supervisor::DatastoreAdapter;
pub use wal::{Wal, WalRecord, WalSummary};
