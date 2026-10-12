//! HTTPS front end for the in-process Kubernetes API.

mod dispatch;
mod query;
mod route;
mod server;
mod tls;

pub(crate) use server::{bind_listener, serve};
