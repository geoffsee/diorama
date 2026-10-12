//! Pure binding of resolved distribution configuration to generic component deadlines.
use std::time::Duration;

use diorama_config::ValidatedConfig;
use diorama_supervisor::ComponentSpec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecyclePolicy {
    startup_timeout: Duration,
}
impl LifecyclePolicy {
    /// The baseline overrides its shared component budget only for positive values.
    /// Preserve the 600-second fallback, using elapsed time rather than retry counts.
    pub fn from_config(config: &ValidatedConfig) -> Self {
        let seconds = u64::try_from(
            config
                .config()
                .kubernetes
                .api_server
                .startup_timeout_seconds,
        )
        .ok()
        .filter(|seconds| *seconds > 0)
        .unwrap_or(600);
        Self {
            startup_timeout: Duration::from_secs(seconds),
        }
    }
    pub fn startup_timeout(&self) -> Duration {
        self.startup_timeout
    }
    /// Apply only the deadline budget; the caller retains graph and policy ownership.
    /// Supervisor construction still validates whether the deadline is representable.
    pub fn apply(&self, mut component: ComponentSpec) -> ComponentSpec {
        component.startup_timeout = self.startup_timeout;
        component
    }
}
