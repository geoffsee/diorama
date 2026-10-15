//! `PodDisruptionBudget` evaluation shared by the eviction subresource and the
//! disruption controller.
//!
//! Single-node simplification of upstream's disruption controller: the
//! expected pod count is the number of live pods selected by the budget rather
//! than the scale of their controllers.

use serde_json::{Value, json};

/// Computed `PodDisruptionBudget` status counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PdbCounts {
    pub expected_pods: i64,
    pub current_healthy: i64,
    pub desired_healthy: i64,
    pub disruptions_allowed: i64,
}

/// Evaluates a `LabelSelector` (`matchLabels` + `matchExpressions`) against labels.
/// An empty selector matches every pod, like `policy/v1`.
#[must_use]
pub fn selector_matches(selector: Option<&Value>, labels: Option<&Value>) -> bool {
    let Some(selector) = selector.and_then(Value::as_object) else {
        return false;
    };
    let labels = labels.and_then(Value::as_object);
    let label = |k: &str| labels.and_then(|m| m.get(k)).and_then(Value::as_str);
    if let Some(ml) = selector.get("matchLabels").and_then(Value::as_object) {
        for (k, v) in ml {
            if label(k) != v.as_str() {
                return false;
            }
        }
    }
    if let Some(exprs) = selector.get("matchExpressions").and_then(Value::as_array) {
        for expr in exprs {
            let key = expr.get("key").and_then(Value::as_str).unwrap_or_default();
            let values: Vec<&str> = expr
                .get("values")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let actual = label(key);
            let ok = match expr.get("operator").and_then(Value::as_str) {
                Some("In") => actual.is_some_and(|a| values.contains(&a)),
                Some("NotIn") => actual.is_none_or(|a| !values.contains(&a)),
                Some("Exists") => actual.is_some(),
                Some("DoesNotExist") => actual.is_none(),
                _ => false,
            };
            if !ok {
                return false;
            }
        }
    }
    true
}

fn is_live(pod: &Value) -> bool {
    pod.pointer("/metadata/deletionTimestamp")
        .and_then(Value::as_str)
        .is_none()
        && !matches!(
            pod.pointer("/status/phase").and_then(Value::as_str),
            Some("Succeeded" | "Failed")
        )
}

/// Returns true for a live pod whose `Ready` condition is `True`.
#[must_use]
pub fn is_healthy(pod: &Value) -> bool {
    is_live(pod)
        && pod
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .is_some_and(|conds| {
                conds.iter().any(|c| {
                    c.get("type").and_then(Value::as_str) == Some("Ready")
                        && c.get("status").and_then(Value::as_str) == Some("True")
                })
            })
}

/// Resolves an int-or-percent against `total`, rounding percentages up.
fn scaled_value(value: &Value, total: i64) -> Option<i64> {
    if let Some(n) = value.as_i64() {
        return Some(n);
    }
    let s = value.as_str()?;
    if let Some(pct) = s.strip_suffix('%') {
        let pct: i64 = pct.trim().parse().ok()?;
        return Some((pct * total + 99) / 100);
    }
    s.parse().ok()
}

/// Selects the live pods a budget governs.
#[must_use]
pub fn selected_pods<'a>(pdb: &Value, pods: &'a [Value]) -> Vec<&'a Value> {
    let selector = pdb.pointer("/spec/selector");
    pods.iter()
        .filter(|p| is_live(p) && selector_matches(selector, p.pointer("/metadata/labels")))
        .collect()
}

/// Computes the budget counters for the pods in the budget's namespace.
#[must_use]
pub fn compute_counts(pdb: &Value, pods: &[Value]) -> PdbCounts {
    let selected = selected_pods(pdb, pods);
    let expected = i64::try_from(selected.len()).unwrap_or(i64::MAX);
    let healthy = i64::try_from(selected.iter().filter(|p| is_healthy(p)).count()).unwrap_or(0);
    let desired = if let Some(min) = pdb.pointer("/spec/minAvailable") {
        scaled_value(min, expected).unwrap_or(1)
    } else if let Some(max) = pdb.pointer("/spec/maxUnavailable") {
        (expected - scaled_value(max, expected).unwrap_or(0)).max(0)
    } else {
        0
    };
    PdbCounts {
        expected_pods: expected,
        current_healthy: healthy,
        desired_healthy: desired,
        disruptions_allowed: (healthy - desired).max(0),
    }
}

/// Builds a `policy/v1` status block for the computed counters.
#[must_use]
pub fn status_value(pdb: &Value, counts: PdbCounts, now: &str) -> Value {
    let generation = pdb
        .pointer("/metadata/generation")
        .and_then(Value::as_i64)
        .unwrap_or(1);
    let allowed = counts.disruptions_allowed > 0;
    let previous = pdb
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .and_then(|c| {
            c.iter()
                .find(|c| c.get("type").and_then(Value::as_str) == Some("DisruptionAllowed"))
        });
    let status_str = if allowed { "True" } else { "False" };
    let transition = previous
        .filter(|c| c.get("status").and_then(Value::as_str) == Some(status_str))
        .and_then(|c| c.get("lastTransitionTime").cloned())
        .unwrap_or_else(|| json!(now));
    json!({
        "observedGeneration": generation,
        "disruptionsAllowed": counts.disruptions_allowed,
        "currentHealthy": counts.current_healthy,
        "desiredHealthy": counts.desired_healthy,
        "expectedPods": counts.expected_pods,
        "disruptedPods": pdb.pointer("/status/disruptedPods").cloned().unwrap_or_else(|| json!({})),
        "conditions": [{
            "type": "DisruptionAllowed",
            "status": status_str,
            "reason": if allowed { "SufficientPods" } else { "InsufficientPods" },
            "message": "",
            "observedGeneration": generation,
            "lastTransitionTime": transition,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod(name: &str, ready: bool) -> Value {
        json!({
            "metadata": { "name": name, "labels": { "app": "x" } },
            "status": {
                "phase": "Running",
                "conditions": [{ "type": "Ready", "status": if ready { "True" } else { "False" } }]
            }
        })
    }

    #[test]
    fn counts_min_available_and_max_unavailable() {
        let pods = vec![pod("a", true), pod("b", true), pod("c", false)];
        let pdb =
            json!({ "spec": { "selector": { "matchLabels": { "app": "x" } }, "minAvailable": 2 } });
        let c = compute_counts(&pdb, &pods);
        assert_eq!(
            (c.expected_pods, c.current_healthy, c.disruptions_allowed),
            (3, 2, 0)
        );

        let pdb = json!({ "spec": { "selector": { "matchLabels": { "app": "x" } }, "maxUnavailable": "50%" } });
        let c = compute_counts(&pdb, &pods);
        assert_eq!((c.desired_healthy, c.disruptions_allowed), (1, 1));
    }

    #[test]
    fn empty_selector_matches_everything() {
        let pods = vec![pod("a", true)];
        let pdb = json!({ "spec": { "selector": {}, "minAvailable": 0 } });
        assert_eq!(compute_counts(&pdb, &pods).disruptions_allowed, 1);
    }
}
