//! Service definitions and lifecycle adapters for host init systems and run modes.
//!
//! Covers systemd, `OpenRC`, `SysVinit`, Upstart, runit, and s6 service definitions,
//! plus foreground and daemon execution modes per the Gate C05 support contract.

pub mod escaping;
pub mod generator;
pub mod lifecycle;
pub mod model;

pub use escaping::{escape_openrc_double_quote, escape_systemd_env, shell_quote};
pub use generator::{generate_service_definition, render_custom_definition};
pub use lifecycle::{
    LifecycleAction, LifecyclePlan, UnsupportedTargetError, plan_lifecycle_action,
};
pub use model::{
    CustomServicePaths, InitBackend, RunMode, ServiceConfig, ServiceDefinition, ServiceFile,
};
