//! Raft consensus state machine and length-prefixed frame codec for `diorama-datastore`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};

use crate::engine::DatastoreEngine;
use crate::error::DatastoreError;
use crate::model::{DatastoreOp, KeyValue};

const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaftRole {
    #[default]
    Follower,
    Candidate,
    Leader,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedRaftState {
    pub node_id: u64,
    pub peers: BTreeMap<u64, std::net::SocketAddr>,
    pub current_term: u64,
    pub voted_for: Option<u64>,
}

impl PersistedRaftState {
    pub fn load(path: &std::path::Path) -> Result<Option<Self>, DatastoreError> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)?;
        let parsed: Self = serde_json::from_slice(&bytes)?;
        Ok(Some(parsed))
    }

    pub fn save_atomic(&self, path: &std::path::Path) -> Result<(), DatastoreError> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        std::fs::create_dir_all(parent)?;
        let tmp = parent.join("raft-state.json.tmp");
        let payload = serde_json::to_vec_pretty(self)?;
        std::fs::write(&tmp, payload)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}

fn current_epoch_micros() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
    )
    .unwrap_or(0)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalCommand {
    Create {
        key: String,
        value: Vec<u8>,
    },
    Update {
        key: String,
        value: Vec<u8>,
        expected_mod_revision: Option<u64>,
    },
    Delete {
        key: String,
        expected_mod_revision: Option<u64>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalOutcome {
    Created(KeyValue),
    Updated(KeyValue),
    Deleted(Option<KeyValue>),
    KeyNotFound(String),
    KeyAlreadyExists(String),
    RevisionMismatch { expected: u64, actual: u64 },
    Error(String),
}

impl ProposalOutcome {
    pub fn from_create_result(res: Result<KeyValue, DatastoreError>) -> Self {
        match res {
            Ok(kv) => Self::Created(kv),
            Err(DatastoreError::KeyAlreadyExists(k)) => Self::KeyAlreadyExists(k),
            Err(err) => Self::Error(err.to_string()),
        }
    }

    pub fn from_update_result(res: Result<KeyValue, DatastoreError>) -> Self {
        match res {
            Ok(kv) => Self::Updated(kv),
            Err(DatastoreError::KeyNotFound(k)) => Self::KeyNotFound(k),
            Err(DatastoreError::RevisionMismatch { expected, actual }) => {
                Self::RevisionMismatch { expected, actual }
            },
            Err(err) => Self::Error(err.to_string()),
        }
    }

    pub fn from_delete_result(res: Result<Option<KeyValue>, DatastoreError>) -> Self {
        match res {
            Ok(kv) => Self::Deleted(kv),
            Err(DatastoreError::RevisionMismatch { expected, actual }) => {
                Self::RevisionMismatch { expected, actual }
            },
            Err(err) => Self::Error(err.to_string()),
        }
    }

    pub fn into_kv_result(self) -> Result<KeyValue, DatastoreError> {
        match self {
            Self::Created(kv) | Self::Updated(kv) => Ok(kv),
            Self::KeyNotFound(k) => Err(DatastoreError::KeyNotFound(k)),
            Self::KeyAlreadyExists(k) => Err(DatastoreError::KeyAlreadyExists(k)),
            Self::RevisionMismatch { expected, actual } => {
                Err(DatastoreError::RevisionMismatch { expected, actual })
            },
            Self::Deleted(_) => Err(DatastoreError::Fatal("unexpected delete outcome".into())),
            Self::Error(msg) => Err(DatastoreError::Fatal(msg)),
        }
    }

    pub fn into_delete_result(self) -> Result<Option<KeyValue>, DatastoreError> {
        match self {
            Self::Deleted(kv) => Ok(kv),
            Self::RevisionMismatch { expected, actual } => {
                Err(DatastoreError::RevisionMismatch { expected, actual })
            },
            Self::KeyNotFound(k) => Err(DatastoreError::KeyNotFound(k)),
            Self::KeyAlreadyExists(k) => Err(DatastoreError::KeyAlreadyExists(k)),
            Self::Created(_) | Self::Updated(_) => {
                Err(DatastoreError::Fatal("unexpected put outcome".into()))
            },
            Self::Error(msg) => Err(DatastoreError::Fatal(msg)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub term: u64,
    pub revision: u64,
    pub op: DatastoreOp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaftMessage {
    RequestVote {
        term: u64,
        candidate_id: u64,
        last_log_revision: u64,
        last_log_term: u64,
    },
    RequestVoteReply {
        term: u64,
        from_id: u64,
        vote_granted: bool,
    },
    AppendEntries {
        term: u64,
        leader_id: u64,
        prev_log_revision: u64,
        prev_log_term: u64,
        entries: Vec<LogEntry>,
        leader_commit: u64,
    },
    AppendEntriesAck {
        term: u64,
        from_id: u64,
        match_revision: u64,
        success: bool,
    },
    ProposalRequest {
        request_id: u64,
        from_id: u64,
        command: ProposalCommand,
    },
    ProposalResponse {
        request_id: u64,
        outcome: ProposalOutcome,
    },
    InstallSnapshot {
        term: u64,
        leader_id: u64,
        revision: u64,
        kv: BTreeMap<String, KeyValue>,
    },
    InstallSnapshotAck {
        term: u64,
        from_id: u64,
        revision: u64,
    },
}

pub fn encode_frame(msg: &RaftMessage) -> Result<Bytes, DatastoreError> {
    let payload = serde_json::to_vec(msg)?;
    let len = u32::try_from(payload.len())
        .map_err(|_| DatastoreError::Fatal("raft frame exceeds u32::MAX".into()))?;
    let mut buf = BytesMut::with_capacity(4 + payload.len());
    buf.put_u32(len);
    buf.extend_from_slice(&payload);
    Ok(buf.freeze())
}

#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: BytesMut,
}

impl FrameDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: BytesMut::new(),
        }
    }

    pub fn push_and_decode(&mut self, chunk: &[u8]) -> Result<Vec<RaftMessage>, DatastoreError> {
        self.buf.extend_from_slice(chunk);
        let mut messages = Vec::new();
        while self.buf.len() >= 4 {
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&self.buf[..4]);
            let frame_len = u32::from_be_bytes(len_bytes) as usize;
            if frame_len > MAX_FRAME_LEN {
                return Err(DatastoreError::Fatal(format!(
                    "raft frame size {frame_len} exceeds maximum {MAX_FRAME_LEN}"
                )));
            }
            if self.buf.len() < 4 + frame_len {
                break;
            }
            self.buf.advance(4);
            let frame = self.buf.split_to(frame_len);
            let msg: RaftMessage = serde_json::from_slice(&frame)?;
            messages.push(msg);
        }
        Ok(messages)
    }
}

#[derive(Debug)]
pub struct RaftState {
    pub node_id: u64,
    pub current_term: u64,
    pub voted_for: Option<u64>,
    pub role: RaftRole,
    pub leader_id: Option<u64>,
    pub commit_revision: u64,
    pub last_applied: u64,
    pub log: BTreeMap<u64, LogEntry>,
    pub match_revision: BTreeMap<u64, u64>,
    pub votes_received: BTreeSet<u64>,
}

impl RaftState {
    #[must_use]
    pub fn new(node_id: u64, initial_revision: u64) -> Self {
        Self {
            node_id,
            current_term: 1,
            voted_for: None,
            role: RaftRole::Follower,
            leader_id: None,
            commit_revision: initial_revision,
            last_applied: initial_revision,
            log: BTreeMap::new(),
            match_revision: BTreeMap::new(),
            votes_received: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn last_log_revision_and_term(&self) -> (u64, u64) {
        self.log.last_key_value().map_or(
            (self.commit_revision, self.current_term),
            |(&rev, entry)| (rev, entry.term),
        )
    }

    pub fn become_follower(&mut self, term: u64, leader_id: Option<u64>) {
        if term > self.current_term {
            self.current_term = term;
            self.voted_for = None;
            self.votes_received.clear();
        }
        self.role = RaftRole::Follower;
        if leader_id.is_some() {
            self.leader_id = leader_id;
        }
    }

    pub fn start_election(&mut self) -> RaftMessage {
        self.current_term += 1;
        self.role = RaftRole::Candidate;
        self.voted_for = Some(self.node_id);
        self.leader_id = None;
        self.votes_received.clear();
        self.votes_received.insert(self.node_id);
        let (last_log_revision, last_log_term) = self.last_log_revision_and_term();
        RaftMessage::RequestVote {
            term: self.current_term,
            candidate_id: self.node_id,
            last_log_revision,
            last_log_term,
        }
    }

    pub fn promote_to_leader(&mut self, peer_ids: impl Iterator<Item = u64>) {
        self.role = RaftRole::Leader;
        self.leader_id = Some(self.node_id);
        let (last_rev, _) = self.last_log_revision_and_term();
        self.match_revision.insert(self.node_id, last_rev);
        for peer_id in peer_ids {
            self.match_revision.entry(peer_id).or_insert(0);
        }
    }
}

type PendingProposals = Mutex<BTreeMap<u64, oneshot::Sender<ProposalOutcome>>>;
type PeerSenders = RwLock<BTreeMap<u64, mpsc::UnboundedSender<RaftMessage>>>;

#[derive(Clone, Debug)]
pub struct RaftHandle {
    node_id: u64,
    total_voters: Arc<std::sync::atomic::AtomicUsize>,
    dynamic_peers: Arc<RwLock<BTreeMap<u64, std::net::SocketAddr>>>,
    next_worker_id: Arc<AtomicU64>,
    persist_path: Option<std::path::PathBuf>,
    last_heartbeat_micros: Arc<AtomicU64>,
    state: Arc<RwLock<RaftState>>,
    peer_senders: Arc<PeerSenders>,
    pending_proposals: Arc<PendingProposals>,
    next_request_id: Arc<AtomicU64>,
}

impl RaftHandle {
    #[must_use]
    pub fn new(node_id: u64, peer_ids: &[u64], initial_revision: u64) -> Self {
        let mut state = RaftState::new(node_id, initial_revision);
        if peer_ids.is_empty() {
            state.promote_to_leader(std::iter::empty());
        }
        Self {
            node_id,
            total_voters: Arc::new(std::sync::atomic::AtomicUsize::new(peer_ids.len() + 1)),
            dynamic_peers: Arc::new(RwLock::new(BTreeMap::new())),
            next_worker_id: Arc::new(AtomicU64::new(10)),
            persist_path: None,
            last_heartbeat_micros: Arc::new(AtomicU64::new(current_epoch_micros())),
            state: Arc::new(RwLock::new(state)),
            peer_senders: Arc::new(RwLock::new(BTreeMap::new())),
            pending_proposals: Arc::new(Mutex::new(BTreeMap::new())),
            next_request_id: Arc::new(AtomicU64::new(1)),
        }
    }

    #[must_use]
    pub fn new_persistent(
        node_id: u64,
        peers: BTreeMap<u64, std::net::SocketAddr>,
        initial_revision: u64,
        current_term: u64,
        voted_for: Option<u64>,
        persist_path: Option<std::path::PathBuf>,
    ) -> Self {
        let mut state = RaftState::new(node_id, initial_revision);
        state.current_term = current_term.max(1);
        state.voted_for = voted_for;
        if peers.is_empty() {
            state.promote_to_leader(std::iter::empty());
        }
        if let Some(path) = &persist_path {
            let persisted = PersistedRaftState {
                node_id,
                peers: peers.clone(),
                current_term: state.current_term,
                voted_for: state.voted_for,
            };
            let _ = persisted.save_atomic(path);
        }
        Self {
            node_id,
            total_voters: Arc::new(std::sync::atomic::AtomicUsize::new(peers.len() + 1)),
            dynamic_peers: Arc::new(RwLock::new(peers)),
            next_worker_id: Arc::new(AtomicU64::new(10)),
            persist_path,
            last_heartbeat_micros: Arc::new(AtomicU64::new(current_epoch_micros())),
            state: Arc::new(RwLock::new(state)),
            peer_senders: Arc::new(RwLock::new(BTreeMap::new())),
            pending_proposals: Arc::new(Mutex::new(BTreeMap::new())),
            next_request_id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub async fn persist_state(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let peers = self.dynamic_peers.read().await.clone();
        let (current_term, voted_for) = {
            let state = self.state.read().await;
            (state.current_term, state.voted_for)
        };
        let snapshot = PersistedRaftState {
            node_id: self.node_id,
            peers,
            current_term,
            voted_for,
        };
        let _ = snapshot.save_atomic(path);
    }

    pub fn record_heartbeat(&self) {
        self.last_heartbeat_micros
            .store(current_epoch_micros(), Ordering::Relaxed);
    }

    #[must_use]
    pub fn start_election_ticker(
        &self,
        min_timeout: std::time::Duration,
        max_timeout: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let handle = self.clone();
        let min_us = u64::try_from(min_timeout.as_micros())
            .unwrap_or(150_000)
            .max(20_000);
        let max_us = u64::try_from(max_timeout.as_micros())
            .unwrap_or(300_000)
            .max(min_us + 10_000);
        let span_us = (max_us - min_us).max(1);
        let heartbeat_interval = std::time::Duration::from_micros((min_us / 3).max(10_000));
        tokio::spawn(async move {
            let mut tick: u64 = 0;
            loop {
                tokio::time::sleep(heartbeat_interval).await;
                tick = tick.wrapping_add(1);
                if handle.total_voters.load(Ordering::Relaxed) <= 1 {
                    continue;
                }
                if handle.is_leader().await {
                    handle.broadcast_heartbeat().await;
                    handle.record_heartbeat();
                    continue;
                }
                let jitter = (handle
                    .node_id
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(tick.wrapping_mul(1_442_695_040_888_963_407)))
                    % span_us;
                let timeout_us = min_us + jitter;
                let elapsed_us = current_epoch_micros()
                    .saturating_sub(handle.last_heartbeat_micros.load(Ordering::Relaxed));
                if elapsed_us >= timeout_us {
                    handle.record_heartbeat();
                    let peers: Vec<u64> = handle.dynamic_peers().await.keys().copied().collect();
                    let _ = handle.trigger_election(&peers).await;
                }
            }
        })
    }

    #[must_use]
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    #[must_use]
    pub fn quorum_size(&self) -> usize {
        (self.total_voters.load(Ordering::Relaxed) / 2) + 1
    }

    #[must_use]
    pub fn has_peers(&self) -> bool {
        self.total_voters.load(Ordering::Relaxed) > 1
    }

    /// Dynamically registers a peer in the Raft voter set and returns the updated peer map.
    pub async fn add_peer(&self, peer_id: u64, peer_addr: std::net::SocketAddr) {
        if peer_id == self.node_id {
            return;
        }
        let mut peers = self.dynamic_peers.write().await;
        if peers.insert(peer_id, peer_addr).is_none() {
            self.total_voters.fetch_add(1, Ordering::Relaxed);
        }
        drop(peers);
        self.state
            .write()
            .await
            .match_revision
            .entry(peer_id)
            .or_insert(0);
        self.persist_state().await;
    }

    /// Allocates a `node_id` for a joining controller peer, registers it in the Raft voter set,
    /// and returns `(assigned_node_id, peers_map_for_joiner)`.
    pub async fn allocate_peer_id(
        &self,
        self_addr: std::net::SocketAddr,
        initial_peers: &BTreeMap<u64, std::net::SocketAddr>,
        new_peer_addr: std::net::SocketAddr,
    ) -> (u64, BTreeMap<u64, std::net::SocketAddr>) {
        let mut peers = self.dynamic_peers.write().await;
        for (&id, &addr) in initial_peers {
            peers.entry(id).or_insert(addr);
        }
        let assigned_id = if let Some((&existing_id, _)) =
            peers.iter().find(|(_, addr)| **addr == new_peer_addr)
        {
            existing_id
        } else {
            let max_id = peers
                .keys()
                .copied()
                .max()
                .unwrap_or(self.node_id)
                .max(self.node_id);
            let next_id = max_id + 1;
            peers.insert(next_id, new_peer_addr);
            self.total_voters.store(peers.len() + 1, Ordering::Relaxed);
            next_id
        };
        let mut joiner_peers = peers.clone();
        joiner_peers.remove(&assigned_id);
        joiner_peers.insert(self.node_id, self_addr);
        drop(peers);
        self.state
            .write()
            .await
            .match_revision
            .entry(assigned_id)
            .or_insert(0);
        self.persist_state().await;
        (assigned_id, joiner_peers)
    }

    pub async fn dynamic_peers(&self) -> BTreeMap<u64, std::net::SocketAddr> {
        self.dynamic_peers.read().await.clone()
    }

    #[must_use]
    pub fn allocate_worker_id(&self) -> u64 {
        self.next_worker_id.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn role(&self) -> RaftRole {
        self.state.read().await.role
    }

    pub async fn is_leader(&self) -> bool {
        self.state.read().await.role == RaftRole::Leader
    }

    pub async fn current_term(&self) -> u64 {
        self.state.read().await.current_term
    }

    pub async fn leader_id(&self) -> Option<u64> {
        self.state.read().await.leader_id
    }

    pub async fn register_peer_sender(
        &self,
        peer_id: u64,
        sender: mpsc::UnboundedSender<RaftMessage>,
    ) {
        self.peer_senders.write().await.insert(peer_id, sender);
    }

    pub async fn remove_peer_sender(&self, peer_id: u64) {
        self.peer_senders.write().await.remove(&peer_id);
    }

    pub async fn send_to_peer(&self, peer_id: u64, msg: RaftMessage) -> bool {
        let senders = self.peer_senders.read().await;
        senders.get(&peer_id).is_some_and(|tx| tx.send(msg).is_ok())
    }

    pub async fn broadcast(&self, msg: &RaftMessage) {
        let senders = self.peer_senders.read().await;
        for tx in senders.values() {
            let _ = tx.send(msg.clone());
        }
    }

    pub async fn trigger_election(&self, peer_ids: &[u64]) -> RaftRole {
        let (vote_req, single_voter) = {
            let mut state = self.state.write().await;
            let req = state.start_election();
            if self.quorum_size() <= 1 {
                state.promote_to_leader(peer_ids.iter().copied());
                (req, true)
            } else {
                (req, false)
            }
        };
        self.record_heartbeat();
        self.persist_state().await;
        if single_voter {
            return RaftRole::Leader;
        }
        self.broadcast(&vote_req).await;
        self.role().await
    }

    pub async fn record_local_commit(&self, term: u64, revision: u64, op: DatastoreOp) {
        let append = {
            let mut state = self.state.write().await;
            let (prev_rev, prev_term) = state.last_log_revision_and_term();
            let entry = LogEntry { term, revision, op };
            state.log.insert(revision, entry.clone());
            state.commit_revision = revision;
            state.last_applied = revision;
            state.match_revision.insert(self.node_id, revision);
            if state.role != RaftRole::Leader || self.total_voters.load(Ordering::Relaxed) <= 1 {
                return;
            }
            RaftMessage::AppendEntries {
                term: state.current_term,
                leader_id: self.node_id,
                prev_log_revision: prev_rev,
                prev_log_term: prev_term,
                entries: vec![entry],
                leader_commit: state.commit_revision,
            }
        };
        self.broadcast(&append).await;
    }

    pub async fn broadcast_heartbeat(&self) {
        let msg_opt = {
            let state = self.state.read().await;
            if state.role == RaftRole::Leader {
                let (prev_rev, prev_term) = state.last_log_revision_and_term();
                Some(RaftMessage::AppendEntries {
                    term: state.current_term,
                    leader_id: self.node_id,
                    prev_log_revision: prev_rev,
                    prev_log_term: prev_term,
                    entries: Vec::new(),
                    leader_commit: state.commit_revision,
                })
            } else {
                None
            }
        };
        if let Some(msg) = msg_opt {
            self.broadcast(&msg).await;
        }
    }

    pub async fn forward_proposal(
        &self,
        command: ProposalCommand,
    ) -> Result<ProposalOutcome, DatastoreError> {
        let mut leader_opt = self.leader_id().await;
        if leader_opt.is_none() {
            for _ in 0..50 {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                leader_opt = self.leader_id().await;
                if leader_opt.is_some() {
                    break;
                }
            }
        }
        let leader =
            leader_opt.ok_or_else(|| DatastoreError::Fatal("no active raft leader".into()))?;
        let req_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending_proposals.lock().await.insert(req_id, tx);

        let sent = self
            .send_to_peer(
                leader,
                RaftMessage::ProposalRequest {
                    request_id: req_id,
                    from_id: self.node_id,
                    command,
                },
            )
            .await;
        if !sent {
            self.pending_proposals.lock().await.remove(&req_id);
            return Err(DatastoreError::Fatal(format!(
                "failed to forward proposal to leader {leader}"
            )));
        }

        tokio::time::timeout(std::time::Duration::from_secs(5), rx)
            .await
            .map_err(|_| DatastoreError::Fatal("timed out waiting for leader proposal".into()))?
            .map_err(|_| DatastoreError::Fatal("leader proposal channel closed".into()))
    }

    pub async fn handle_message(
        &self,
        engine: &DatastoreEngine,
        peer_ids: &[u64],
        msg: RaftMessage,
    ) -> Option<(u64, RaftMessage)> {
        match msg {
            RaftMessage::RequestVote {
                term,
                candidate_id,
                last_log_revision,
                last_log_term,
            } => {
                let reply = self
                    .on_request_vote(term, candidate_id, last_log_revision, last_log_term)
                    .await;
                Some((candidate_id, reply))
            },
            RaftMessage::RequestVoteReply {
                term,
                from_id,
                vote_granted,
            } => {
                self.on_vote_reply(term, from_id, vote_granted, peer_ids)
                    .await;
                None
            },
            RaftMessage::AppendEntries {
                term,
                leader_id,
                entries,
                leader_commit,
                ..
            } => {
                let ack = self
                    .on_append_entries(engine, term, leader_id, entries, leader_commit)
                    .await;
                Some((leader_id, ack))
            },
            RaftMessage::AppendEntriesAck {
                term,
                from_id,
                match_revision,
                success,
            } => {
                self.on_append_ack(term, from_id, match_revision, success)
                    .await;
                None
            },
            RaftMessage::ProposalRequest {
                request_id,
                from_id,
                command,
            } => {
                let outcome = execute_leader_proposal(engine, command).await;
                Some((
                    from_id,
                    RaftMessage::ProposalResponse {
                        request_id,
                        outcome,
                    },
                ))
            },
            RaftMessage::ProposalResponse {
                request_id,
                outcome,
            } => {
                if let Some(tx) = self.pending_proposals.lock().await.remove(&request_id) {
                    let _ = tx.send(outcome);
                }
                None
            },
            RaftMessage::InstallSnapshot {
                term,
                leader_id,
                revision,
                kv,
            } => {
                let ack = self
                    .on_install_snapshot(engine, term, leader_id, revision, kv)
                    .await;
                Some((leader_id, ack))
            },
            RaftMessage::InstallSnapshotAck {
                term,
                from_id,
                revision,
            } => {
                self.on_append_ack(term, from_id, revision, true).await;
                None
            },
        }
    }

    async fn on_request_vote(
        &self,
        term: u64,
        candidate_id: u64,
        last_log_revision: u64,
        last_log_term: u64,
    ) -> RaftMessage {
        let (reply, should_persist) = {
            let mut state = self.state.write().await;
            let prev_term = state.current_term;
            let prev_voted = state.voted_for;
            if term > state.current_term {
                state.become_follower(term, None);
            }
            let (local_rev, local_term) = state.last_log_revision_and_term();
            let up_to_date = last_log_term > local_term
                || (last_log_term == local_term && last_log_revision >= local_rev);
            let can_vote = state.voted_for.is_none() || state.voted_for == Some(candidate_id);
            let vote_granted = term == state.current_term && can_vote && up_to_date;
            if vote_granted {
                state.voted_for = Some(candidate_id);
                self.record_heartbeat();
            }
            let changed = state.current_term != prev_term || state.voted_for != prev_voted;
            (
                RaftMessage::RequestVoteReply {
                    term: state.current_term,
                    from_id: self.node_id,
                    vote_granted,
                },
                changed,
            )
        };
        if should_persist {
            self.persist_state().await;
        }
        reply
    }

    async fn on_vote_reply(&self, term: u64, from_id: u64, vote_granted: bool, peer_ids: &[u64]) {
        let (became_leader, stepped_down) = {
            let mut state = self.state.write().await;
            if term > state.current_term {
                state.become_follower(term, None);
                (false, true)
            } else if state.role != RaftRole::Candidate
                || term != state.current_term
                || !vote_granted
            {
                return;
            } else {
                state.votes_received.insert(from_id);
                if state.votes_received.len() >= self.quorum_size() {
                    state.promote_to_leader(peer_ids.iter().copied());
                    (true, false)
                } else {
                    (false, false)
                }
            }
        };
        if stepped_down {
            self.persist_state().await;
            return;
        }
        if became_leader {
            self.record_heartbeat();
            self.broadcast_heartbeat().await;
        }
    }

    async fn on_append_entries(
        &self,
        engine: &DatastoreEngine,
        term: u64,
        leader_id: u64,
        entries: Vec<LogEntry>,
        leader_commit: u64,
    ) -> RaftMessage {
        let (current_term, term_changed) = {
            let mut state = self.state.write().await;
            if term < state.current_term {
                return RaftMessage::AppendEntriesAck {
                    term: state.current_term,
                    from_id: self.node_id,
                    match_revision: state.last_applied,
                    success: false,
                };
            }
            let prev_term = state.current_term;
            state.become_follower(term, Some(leader_id));
            self.record_heartbeat();
            for entry in &entries {
                state.log.insert(entry.revision, entry.clone());
            }
            (state.current_term, state.current_term != prev_term)
        };
        if term_changed {
            self.persist_state().await;
        }

        for entry in entries {
            let _ = engine
                .apply_replicated_record(entry.revision, entry.op)
                .await;
        }

        let mut state = self.state.write().await;
        let current_rev = engine.current_revision().await;
        state.last_applied = current_rev;
        if leader_commit > state.commit_revision {
            state.commit_revision = leader_commit.min(current_rev);
        }

        RaftMessage::AppendEntriesAck {
            term: current_term,
            from_id: self.node_id,
            match_revision: current_rev,
            success: true,
        }
    }

    async fn on_append_ack(&self, term: u64, from_id: u64, match_revision: u64, success: bool) {
        let stepped_down = {
            let mut state = self.state.write().await;
            if term > state.current_term {
                state.become_follower(term, None);
                true
            } else {
                if state.role == RaftRole::Leader && success {
                    let prev = state.match_revision.get(&from_id).copied().unwrap_or(0);
                    state
                        .match_revision
                        .insert(from_id, match_revision.max(prev));
                }
                false
            }
        };
        if stepped_down {
            self.persist_state().await;
        }
    }

    async fn on_install_snapshot(
        &self,
        engine: &DatastoreEngine,
        term: u64,
        leader_id: u64,
        revision: u64,
        kv: BTreeMap<String, KeyValue>,
    ) -> RaftMessage {
        let term_changed = {
            let mut state = self.state.write().await;
            let prev_term = state.current_term;
            if term >= state.current_term {
                state.become_follower(term, Some(leader_id));
                self.record_heartbeat();
            }
            state.current_term != prev_term
        };
        if term_changed {
            self.persist_state().await;
        }
        let _ = engine.install_replicated_snapshot(revision, kv).await;
        let mut state = self.state.write().await;
        state.commit_revision = revision;
        state.last_applied = revision;
        RaftMessage::InstallSnapshotAck {
            term: state.current_term,
            from_id: self.node_id,
            revision,
        }
    }
}

async fn execute_leader_proposal(
    engine: &DatastoreEngine,
    command: ProposalCommand,
) -> ProposalOutcome {
    match command {
        ProposalCommand::Create { key, value } => {
            ProposalOutcome::from_create_result(engine.create(&key, value).await)
        },
        ProposalCommand::Update {
            key,
            value,
            expected_mod_revision,
        } => ProposalOutcome::from_update_result(
            engine.update(&key, value, expected_mod_revision).await,
        ),
        ProposalCommand::Delete {
            key,
            expected_mod_revision,
        } => ProposalOutcome::from_delete_result(engine.delete(&key, expected_mod_revision).await),
    }
}
