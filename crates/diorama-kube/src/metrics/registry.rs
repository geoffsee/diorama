//! Metrics registry collecting from registered collectors.

use std::sync::RwLock;

use super::types::{MetricFamily, encode_openmetrics, encode_prometheus};

/// Trait implemented by collectors contributing to Prometheus exposition.
pub trait Collector: Send + Sync + 'static {
    fn collect(&self) -> Vec<MetricFamily>;
}

/// Thread-safe registry coordinating metric collectors.
#[derive(Default)]
pub struct MetricsRegistry {
    collectors: RwLock<Vec<Box<dyn Collector>>>,
}

impl MetricsRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            collectors: RwLock::new(Vec::new()),
        }
    }

    /// Registers a new collector into the registry.
    pub fn register(&self, collector: impl Collector) {
        if let Ok(mut lock) = self.collectors.write() {
            lock.push(Box::new(collector));
        }
    }

    /// Gathers all metric families from registered collectors.
    #[must_use]
    pub fn gather(&self) -> Vec<MetricFamily> {
        let mut families = Vec::new();
        if let Ok(lock) = self.collectors.read() {
            for collector in lock.iter() {
                families.extend(collector.collect());
            }
        }
        families
    }

    /// Renders collected metrics in Prometheus text exposition format (version 0.0.4).
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        encode_prometheus(&self.gather())
    }

    /// Renders collected metrics in `OpenMetrics` text exposition format (version 1.0.0).
    #[must_use]
    pub fn render_openmetrics(&self) -> String {
        encode_openmetrics(&self.gather())
    }
}

impl std::fmt::Debug for MetricsRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.collectors.read().map_or(0, |c| c.len());
        f.debug_struct("MetricsRegistry")
            .field("collectors_count", &count)
            .finish()
    }
}
