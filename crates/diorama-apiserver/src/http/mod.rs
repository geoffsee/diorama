//! HTTPS front end for the in-process Kubernetes API.

mod dispatch;
pub(crate) mod field_validation;
mod protojson;
pub(crate) mod query;
mod route;
mod server;
pub(crate) mod tls;

pub(crate) use server::{bind_listener, serve};
