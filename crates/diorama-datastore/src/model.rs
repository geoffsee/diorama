use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyValue {
    pub key: String,
    pub value: Vec<u8>,
    pub create_revision: u64,
    pub mod_revision: u64,
    pub version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DatastoreOp {
    Put { key: String, value: Vec<u8> },
    Delete { key: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatchEventType {
    Put,
    Delete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchEvent {
    pub event_type: WatchEventType,
    pub kv: KeyValue,
    pub prev_kv: Option<KeyValue>,
}

#[derive(Debug)]
pub struct WatchReceiver {
    rx: tokio::sync::mpsc::Receiver<WatchEvent>,
}

impl WatchReceiver {
    pub fn new(rx: tokio::sync::mpsc::Receiver<WatchEvent>) -> Self {
        Self { rx }
    }

    pub async fn recv(&mut self) -> Result<WatchEvent, tokio::sync::broadcast::error::RecvError> {
        self.rx
            .recv()
            .await
            .ok_or(tokio::sync::broadcast::error::RecvError::Closed)
    }
}
