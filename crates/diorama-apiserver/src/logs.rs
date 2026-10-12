//! Pod log subresource backed by the in-process kubelet.
//!
//! Upstream kube-apiserver proxies `GET .../pods/{name}/log` to the kubelet.
//! Here the kubelet runs in the same process, so it registers a reader with
//! [`crate::ApiserverService`] and the HTTPS gateway calls it directly.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::ApiserverError;

/// Query options accepted by the pod log subresource.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PodLogOptions {
    /// Container to read; the first spec container when absent.
    pub container: Option<String>,
    /// Return only the last `tail_lines` lines.
    pub tail_lines: Option<usize>,
    /// Prefix each line with its RFC 3339 timestamp.
    pub timestamps: bool,
    /// Return only lines newer than this many seconds.
    pub since_seconds: Option<u64>,
    /// Read the previous attempt of the container.
    pub previous: bool,
    /// Stream logs as they arrive.
    pub follow: bool,
}

impl PodLogOptions {
    /// Builds options from already-decoded query parameters.
    #[must_use]
    pub fn from_params(params: &BTreeMap<String, String>) -> Self {
        Self {
            container: params.get("container").filter(|c| !c.is_empty()).cloned(),
            tail_lines: params.get("tailLines").and_then(|v| v.parse().ok()),
            timestamps: params
                .get("timestamps")
                .is_some_and(|v| v == "true" || v == "1"),
            since_seconds: params.get("sinceSeconds").and_then(|v| v.parse().ok()),
            previous: params
                .get("previous")
                .is_some_and(|v| v == "true" || v == "1"),
            follow: params
                .get("follow")
                .is_some_and(|v| v == "true" || v == "1"),
        }
    }
}

/// Reads container output for a stored Pod object.
#[async_trait]
pub trait PodLogReader: std::fmt::Debug + Send + Sync {
    /// Returns the captured stdout and stderr of one container of `pod`.
    async fn read_pod_log(
        &self,
        pod: &Value,
        options: &PodLogOptions,
    ) -> Result<String, ApiserverError>;
}

#[cfg(test)]
mod tests {
    use super::PodLogOptions;
    use std::collections::BTreeMap;

    #[test]
    fn parses_container_tail_timestamps_and_since() {
        let params: BTreeMap<String, String> = [
            ("container", "hello"),
            ("tailLines", "10"),
            ("timestamps", "true"),
            ("sinceSeconds", "30"),
            ("previous", "true"),
            ("follow", "false"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let options = PodLogOptions::from_params(&params);
        assert_eq!(options.container.as_deref(), Some("hello"));
        assert_eq!(options.tail_lines, Some(10));
        assert!(options.timestamps);
        assert_eq!(options.since_seconds, Some(30));
        assert!(options.previous);
        assert!(!options.follow);
        assert_eq!(
            PodLogOptions::from_params(&BTreeMap::new()),
            PodLogOptions::default()
        );
    }
}
