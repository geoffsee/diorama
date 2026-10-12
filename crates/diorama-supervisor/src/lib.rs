//! Dependency-aware supervision of cooperative async adapters.
//! OS process ownership and executable signal handling are separate adapters.
mod coordinator;
mod model;
pub use coordinator::Supervisor;
pub use model::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod process;
#[cfg(unix)]
pub mod signals;

#[cfg(unix)]
pub use rustix;

mod diagnostics;
pub use diagnostics::{ComponentDiagnostic, LifecycleObserver, LifecycleSnapshot, ObserverClosed};
