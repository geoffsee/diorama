//! Local configuration HTTP API server and supervisor adapter.

pub mod adapter;
pub mod server;

pub use adapter::{COMPONENT_CONFIG_API, ConfigApiAdapter, DEFAULT_STARTUP_TIMEOUT};
pub use server::{ConfigApiListener, ConfigApiServer, MAX_BODY_BYTES, clear_stale_socket};
