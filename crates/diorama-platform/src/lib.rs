//! Bounded read-only Linux observations, separate from preparation and startup policy.
mod classify;
mod discover;
mod model;
pub use classify::{classify, node_target, parse_mountinfo};
pub use discover::discover;
pub use model::*;
use std::fmt;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformError {
    UnsupportedTarget,
    UnsupportedHost,
    InvalidLimits,
    TooManyPaths,
    PathTooLong,
}
impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "platform discovery: {self:?}")
    }
}
impl std::error::Error for PlatformError {}

pub mod preflight;

pub mod constrained;

pub mod preflight_probe;
