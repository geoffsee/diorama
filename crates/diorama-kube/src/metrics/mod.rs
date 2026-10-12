//! Operational metrics and health HTTP endpoint module.
//!
//! Exposes Prometheus and `OpenMetrics` compatible exposition format at `/metrics`,
//! health checks at `/healthz`, `/livez`, and `/readyz`, and HTML landing at `/`.

pub mod adapter;
pub mod collectors;
mod negotiation;
pub mod registry;
pub mod server;
mod timed_io;
pub mod types;

pub use adapter::{COMPONENT_METRICS, DEFAULT_METRICS_TIMEOUT, MetricsAdapter};
pub use collectors::{
    BuildInfoCollector, CertificateCollector, ComponentHealthCollector, DatastoreCollector,
    UptimeCollector,
};
pub use registry::{Collector, MetricsRegistry};
pub use server::MetricsServer;
pub use types::{
    MetricFamily, MetricType, ParsedSample, ParsedScrape, Sample, encode_openmetrics,
    encode_prometheus, parse_scrape,
};
