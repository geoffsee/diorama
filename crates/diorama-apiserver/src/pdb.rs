//! `PodDisruptionBudget` evaluation shared by the eviction subresource and the
//! disruption controller.
//!
//! Evaluates `policy/v1` `PodDisruptionBudget` lifecycle rules:
//! - Label selector matching (`matchLabels`, `matchExpressions`).
//! - `minAvailable` and `maxUnavailable` (both integer and percentage) calculation against replica scale.
//! - Counter computation (`expectedPods`, `currentHealthy`, `desiredHealthy`, `disruptionsAllowed`).
//! - Status payload construction and `DisruptionAllowed` condition management.
//! - `spec.unhealthyPodEvictionPolicy` (`IfHealthyBudget` vs `AlwaysAllow`) evaluation during `pods/eviction` admission.

use serde_json::{Value, json};

/// Computed `PodDisruptionBudget` status counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PdbCounts {
    pub expected_pods: i64,
    pub current_healthy: i64,
    pub desired_healthy: i64,
    pub disruptions_allowed: i64,
}

/// Policy governing eviction of unhealthy pods when guarded by a `PodDisruptionBudget`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UnhealthyPodEvictionPolicy {
    /// Unhealthy pods can only be evicted if the budget is not disrupted
    /// (`currentHealthy >= desiredHealthy && desiredHealthy > 0`).
    #[default]
    IfHealthyBudget,
    /// Unhealthy pods can always be evicted, regardless of whether budget is met.
    AlwaysAllow,
}

impl UnhealthyPodEvictionPolicy {
    #[must_use]
    pub fn parse(s: Option<&str>) -> Self {
        match s {
            Some("AlwaysAllow") => Self::AlwaysAllow,
            _ => Self::IfHealthyBudget,
        }
    }

    #[must_use]
    pub fn from_pdb(pdb: &Value) -> Self {
        let s = pdb
            .pointer("/spec/unhealthyPodEvictionPolicy")
            .and_then(Value::as_str);
        Self::parse(s)
    }
}

/// Admission check outcome for an eviction request against a PDB.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvictionAdmission {
    /// Pod eviction is allowed.
    Allowed {
        /// True if this eviction consumed budget from a PDB.
        consumes_budget: bool,
    },
    /// Eviction is rejected because it would violate the disruption budget (HTTP 429).
    TooManyRequests {
        message: String,
        details_message: String,
    },
    /// Multiple matching PDBs found, which is unsupported (HTTP 500).
    MultipleBudgetsNotSupported,
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

/// Returns true if the pod is not in a terminal state (not deleted, not Succeeded/Failed).
#[must_use]
pub fn is_live(pod: &Value) -> bool {
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
#[must_use]
pub fn scaled_value(value: &Value, total: i64) -> Option<i64> {
    if let Some(n) = value.as_i64() {
        return Some(n);
    }
    if let Some(n) = value.as_u64() {
        return i64::try_from(n).ok();
    }
    let s = value.as_str()?.trim();
    if let Some(pct) = s.strip_suffix('%') {
        let pct: i64 = pct.trim().parse().ok()?;
        if pct <= 0 || total <= 0 {
            return Some(0);
        }
        return Some((pct.saturating_mul(total).saturating_add(99)) / 100);
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
    compute_counts_with_scale(pdb, pods, None)
}

/// Computes the budget counters for the pods in the budget's namespace,
/// optionally taking an explicit controller replica scale as the denominator
/// for percentages and expected pods.
#[must_use]
pub fn compute_counts_with_scale(
    pdb: &Value,
    pods: &[Value],
    replica_scale: Option<i64>,
) -> PdbCounts {
    let selected = selected_pods(pdb, pods);
    let scale_from_meta = pdb
        .pointer("/metadata/annotations/diorama.io/replica-scale")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<i64>().ok())
        .or_else(|| pdb.pointer("/spec/replicas").and_then(Value::as_i64));
    let expected = replica_scale
        .or(scale_from_meta)
        .unwrap_or_else(|| i64::try_from(selected.len()).unwrap_or(i64::MAX))
        .max(0);
    let healthy = i64::try_from(selected.iter().filter(|p| is_healthy(p)).count()).unwrap_or(0);
    let desired = if let Some(min) = pdb.pointer("/spec/minAvailable") {
        scaled_value(min, expected).unwrap_or(1).max(0)
    } else if let Some(max) = pdb.pointer("/spec/maxUnavailable") {
        let max_val = scaled_value(max, expected).unwrap_or(0).max(0);
        (expected - max_val).max(0)
    } else {
        0
    };
    let disruptions = if expected <= 0 {
        0
    } else {
        (healthy - desired).max(0)
    };
    PdbCounts {
        expected_pods: expected,
        current_healthy: healthy,
        desired_healthy: desired,
        disruptions_allowed: disruptions,
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

    let new_cond = json!({
        "type": "DisruptionAllowed",
        "status": status_str,
        "reason": if allowed { "SufficientPods" } else { "InsufficientPods" },
        "message": "",
        "observedGeneration": generation,
        "lastTransitionTime": transition,
    });

    let mut conditions = Vec::new();
    let mut replaced = false;
    if let Some(existing) = pdb.pointer("/status/conditions").and_then(Value::as_array) {
        for c in existing {
            if c.get("type").and_then(Value::as_str) == Some("DisruptionAllowed") {
                conditions.push(new_cond.clone());
                replaced = true;
            } else {
                conditions.push(c.clone());
            }
        }
    }
    if !replaced {
        conditions.push(new_cond);
    }

    json!({
        "observedGeneration": generation,
        "disruptionsAllowed": counts.disruptions_allowed,
        "currentHealthy": counts.current_healthy,
        "desiredHealthy": counts.desired_healthy,
        "expectedPods": counts.expected_pods,
        "disruptedPods": pdb.pointer("/status/disruptedPods").cloned().unwrap_or_else(|| json!({})),
        "conditions": conditions,
    })
}

/// Evaluates whether a pod may be evicted according to matching `PodDisruptionBudget`s
/// and the pod's health state, respecting `spec.unhealthyPodEvictionPolicy`.
#[must_use]
pub fn check_eviction_admission(
    pod: &Value,
    matching_pdbs: &[&Value],
    pods_in_namespace: &[Value],
) -> EvictionAdmission {
    check_eviction_admission_with_scale(pod, matching_pdbs, pods_in_namespace, None)
}

/// Evaluates whether a pod may be evicted, optionally passing an explicit controller scale.
#[must_use]
pub fn check_eviction_admission_with_scale(
    pod: &Value,
    matching_pdbs: &[&Value],
    pods_in_namespace: &[Value],
    replica_scale: Option<i64>,
) -> EvictionAdmission {
    if !is_live(pod) {
        return EvictionAdmission::Allowed {
            consumes_budget: false,
        };
    }
    if matching_pdbs.is_empty() {
        return EvictionAdmission::Allowed {
            consumes_budget: false,
        };
    }
    if matching_pdbs.len() > 1 {
        return EvictionAdmission::MultipleBudgetsNotSupported;
    }

    let pdb = matching_pdbs[0];
    let pdb_name = pdb
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let counts = compute_counts_with_scale(pdb, pods_in_namespace, replica_scale);
    let pod_healthy = is_healthy(pod);

    if !pod_healthy {
        let policy = UnhealthyPodEvictionPolicy::from_pdb(pdb);
        match policy {
            UnhealthyPodEvictionPolicy::AlwaysAllow => {
                return EvictionAdmission::Allowed {
                    consumes_budget: false,
                };
            },
            UnhealthyPodEvictionPolicy::IfHealthyBudget => {
                if counts.current_healthy >= counts.desired_healthy && counts.desired_healthy > 0 {
                    return EvictionAdmission::Allowed {
                        consumes_budget: false,
                    };
                }
                let details_message = format!(
                    "The disruption budget {pdb_name} needs {} healthy pods and has {} currently",
                    counts.desired_healthy, counts.current_healthy
                );
                return EvictionAdmission::TooManyRequests {
                    message: "Cannot evict pod as it would violate the pod's disruption budget."
                        .to_string(),
                    details_message,
                };
            },
        }
    }

    if counts.disruptions_allowed <= 0 {
        let details_message = format!(
            "The disruption budget {pdb_name} needs {} healthy pods and has {} currently",
            counts.desired_healthy, counts.current_healthy
        );
        return EvictionAdmission::TooManyRequests {
            message: "Cannot evict pod as it would violate the pod's disruption budget."
                .to_string(),
            details_message,
        };
    }

    EvictionAdmission::Allowed {
        consumes_budget: true,
    }
}

/// Updates a PDB status value after a pod disruption is allowed, decrementing
/// `disruptionsAllowed` and recording the evicted pod into `disruptedPods`.
#[must_use]
pub fn record_disruption_in_pdb(
    pdb: &Value,
    pod_name: &str,
    counts: &PdbCounts,
    now: &str,
) -> Value {
    let mut updated = pdb.clone();
    let status_opt = updated.as_object_mut().and_then(|obj| {
        if !obj.contains_key("status") {
            obj.insert("status".to_string(), status_value(pdb, *counts, now));
        }
        obj.get_mut("status").and_then(Value::as_object_mut)
    });
    if let Some(status) = status_opt {
        let allowed = (counts.disruptions_allowed - 1).max(0);
        status.insert("disruptionsAllowed".to_string(), json!(allowed));
        let disrupted = status
            .entry("disruptedPods".to_string())
            .or_insert_with(|| json!({}));
        if let Some(map) = disrupted.as_object_mut() {
            map.insert(pod_name.to_string(), json!(now));
        }
        if allowed == 0 {
            update_disruption_condition_false(status, now);
        }
    }
    updated
}

fn update_disruption_condition_false(status: &mut serde_json::Map<String, Value>, now: &str) {
    let Some(conds) = status.get_mut("conditions").and_then(Value::as_array_mut) else {
        return;
    };
    for c in conds {
        if c.get("type").and_then(Value::as_str) == Some("DisruptionAllowed")
            && let Some(c_obj) = c.as_object_mut()
        {
            c_obj.insert("status".to_string(), json!("False"));
            c_obj.insert("reason".to_string(), json!("InsufficientPods"));
            c_obj.insert("lastTransitionTime".to_string(), json!(now));
        }
    }
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

    fn unready_pod(name: &str) -> Value {
        json!({
            "metadata": { "name": name, "labels": { "app": "x" } },
            "status": {
                "phase": "Running",
                "conditions": [{ "type": "Ready", "status": "False" }]
            }
        })
    }

    fn terminal_pod(name: &str) -> Value {
        json!({
            "metadata": { "name": name, "labels": { "app": "x" }, "deletionTimestamp": "2026-10-15T12:00:00Z" },
            "status": {
                "phase": "Running",
                "conditions": [{ "type": "Ready", "status": "True" }]
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

    #[test]
    fn scaled_value_integer_and_percentages() {
        assert_eq!(scaled_value(&json!(3), 10), Some(3));
        assert_eq!(scaled_value(&json!("3"), 10), Some(3));
        assert_eq!(scaled_value(&json!("50%"), 3), Some(2)); // ceil(1.5) = 2
        assert_eq!(scaled_value(&json!("50%"), 4), Some(2));
        assert_eq!(scaled_value(&json!("33%"), 3), Some(1)); // ceil(0.99) = 1
        assert_eq!(scaled_value(&json!("1%"), 3), Some(1)); // ceil(0.03) = 1
        assert_eq!(scaled_value(&json!("100%"), 5), Some(5));
        assert_eq!(scaled_value(&json!("0%"), 5), Some(0));
        assert_eq!(scaled_value(&json!("50%"), 0), Some(0));
        assert_eq!(scaled_value(&json!("-10%"), 5), Some(0));
        assert_eq!(scaled_value(&json!("invalid"), 5), None);
    }

    #[test]
    fn max_unavailable_various_scales() {
        let pods = vec![pod("a", true), pod("b", true), pod("c", true)];

        // maxUnavailable: 0 => desiredHealthy = 3, disruptionsAllowed = 0
        let pdb0 = json!({ "spec": { "selector": { "matchLabels": { "app": "x" } }, "maxUnavailable": 0 } });
        let c0 = compute_counts(&pdb0, &pods);
        assert_eq!((c0.desired_healthy, c0.disruptions_allowed), (3, 0));

        // maxUnavailable: 1 => desiredHealthy = 2, disruptionsAllowed = 1
        let pdb1 = json!({ "spec": { "selector": { "matchLabels": { "app": "x" } }, "maxUnavailable": 1 } });
        let c1 = compute_counts(&pdb1, &pods);
        assert_eq!((c1.desired_healthy, c1.disruptions_allowed), (2, 1));

        // maxUnavailable: "100%" => desiredHealthy = 0, disruptionsAllowed = 3
        let pdb_all = json!({ "spec": { "selector": { "matchLabels": { "app": "x" } }, "maxUnavailable": "100%" } });
        let c_all = compute_counts(&pdb_all, &pods);
        assert_eq!((c_all.desired_healthy, c_all.disruptions_allowed), (0, 3));
    }

    #[test]
    fn compute_counts_with_explicit_scale() {
        // 3 live pods running, but controller scale is 6
        let pods = vec![pod("a", true), pod("b", true), pod("c", true)];
        let pdb = json!({
            "metadata": { "name": "scale-test" },
            "spec": { "selector": { "matchLabels": { "app": "x" } }, "minAvailable": "50%" }
        });
        // 50% of 6 is 3 => desired = 3, healthy = 3 => disruptionsAllowed = 0
        let c = compute_counts_with_scale(&pdb, &pods, Some(6));
        assert_eq!(c.expected_pods, 6);
        assert_eq!(c.current_healthy, 3);
        assert_eq!(c.desired_healthy, 3);
        assert_eq!(c.disruptions_allowed, 0);

        // Without scale => expected = 3, 50% of 3 is 2 => desired = 2 => disruptionsAllowed = 1
        let c_default = compute_counts(&pdb, &pods);
        assert_eq!(c_default.expected_pods, 3);
        assert_eq!(c_default.desired_healthy, 2);
        assert_eq!(c_default.disruptions_allowed, 1);
    }

    #[test]
    fn status_value_generation_and_transitions() {
        let pdb = json!({
            "metadata": { "name": "pdb-test", "generation": 2 },
            "status": {
                "disruptedPods": { "old-pod": "2026-10-15T10:00:00Z" },
                "conditions": [{
                    "type": "DisruptionAllowed",
                    "status": "False",
                    "reason": "InsufficientPods",
                    "lastTransitionTime": "2026-10-15T09:00:00Z"
                }]
            }
        });

        // 1. When disruptionsAllowed > 0, transition from False to True updates timestamp to now
        let counts_allowed = PdbCounts {
            expected_pods: 3,
            current_healthy: 3,
            desired_healthy: 2,
            disruptions_allowed: 1,
        };
        let now = "2026-10-15T11:00:00Z";
        let status = status_value(&pdb, counts_allowed, now);
        assert_eq!(status["observedGeneration"], 2);
        assert_eq!(status["disruptionsAllowed"], 1);
        assert_eq!(status["currentHealthy"], 3);
        assert_eq!(status["desiredHealthy"], 2);
        assert_eq!(status["expectedPods"], 3);
        assert_eq!(status["disruptedPods"]["old-pod"], "2026-10-15T10:00:00Z");
        let cond = &status["conditions"][0];
        assert_eq!(cond["type"], "DisruptionAllowed");
        assert_eq!(cond["status"], "True");
        assert_eq!(cond["reason"], "SufficientPods");
        assert_eq!(cond["lastTransitionTime"], now);

        // 2. When disruptionsAllowed == 0, previous condition was False, transition time preserved
        let counts_blocked = PdbCounts {
            expected_pods: 3,
            current_healthy: 2,
            desired_healthy: 2,
            disruptions_allowed: 0,
        };
        let status_blocked = status_value(&pdb, counts_blocked, "2026-10-15T12:00:00Z");
        let cond_blocked = &status_blocked["conditions"][0];
        assert_eq!(cond_blocked["status"], "False");
        assert_eq!(cond_blocked["reason"], "InsufficientPods");
        assert_eq!(cond_blocked["lastTransitionTime"], "2026-10-15T09:00:00Z");
    }

    #[test]
    fn selector_matching_with_expressions() {
        let selector = json!({
            "matchLabels": { "tier": "backend" },
            "matchExpressions": [
                { "key": "env", "operator": "In", "values": ["prod", "stage"] },
                { "key": "retired", "operator": "DoesNotExist" }
            ]
        });

        let matching_labels = json!({ "tier": "backend", "env": "prod" });
        assert!(selector_matches(Some(&selector), Some(&matching_labels)));

        let wrong_env = json!({ "tier": "backend", "env": "dev" });
        assert!(!selector_matches(Some(&selector), Some(&wrong_env)));

        let has_retired = json!({ "tier": "backend", "env": "prod", "retired": "true" });
        assert!(!selector_matches(Some(&selector), Some(&has_retired)));
    }

    #[test]
    fn eviction_admission_blocks_and_unblocks_lifecycle() {
        // Conformance Issue #164:
        // PDB with minAvailable: 3 and 3 healthy pods => disruptionsAllowed = 0 => blocks eviction
        let p1 = pod("pod-1", true);
        let p2 = pod("pod-2", true);
        let p3 = pod("pod-3", true);
        let pods = vec![p1.clone(), p2.clone(), p3.clone()];

        let mut pdb = json!({
            "metadata": { "name": "test-pdb" },
            "spec": { "selector": { "matchLabels": { "app": "x" } }, "minAvailable": 3 }
        });

        let adm = check_eviction_admission(&p1, &[&pdb], &pods);
        assert!(matches!(adm, EvictionAdmission::TooManyRequests { .. }));

        // Update PDB to minAvailable: 2 => disruptionsAllowed = 1 => allowed
        pdb["spec"]["minAvailable"] = json!(2);
        let adm2 = check_eviction_admission(&p1, &[&pdb], &pods);
        assert_eq!(
            adm2,
            EvictionAdmission::Allowed {
                consumes_budget: true
            }
        );

        // Patch PDB to maxUnavailable: 0 => disruptionsAllowed = 0 => blocked
        pdb["spec"].as_object_mut().unwrap().remove("minAvailable");
        pdb["spec"]["maxUnavailable"] = json!(0);
        let adm3 = check_eviction_admission(&p1, &[&pdb], &pods);
        assert!(matches!(adm3, EvictionAdmission::TooManyRequests { .. }));

        // Delete PDB (no matching PDBs) => allowed without consuming budget
        let adm_deleted = check_eviction_admission(&p1, &[], &pods);
        assert_eq!(
            adm_deleted,
            EvictionAdmission::Allowed {
                consumes_budget: false
            }
        );

        // Multiple PDBs => rejected with MultipleBudgetsNotSupported
        let adm_multi = check_eviction_admission(&p1, &[&pdb, &pdb], &pods);
        assert_eq!(adm_multi, EvictionAdmission::MultipleBudgetsNotSupported);
    }

    #[test]
    fn eviction_admission_unhealthy_pod_policies() {
        // 3 unready pods, maxUnavailable: 1 => expected = 3, desiredHealthy = 2, currentHealthy = 0
        let p1 = unready_pod("p1");
        let p2 = unready_pod("p2");
        let p3 = unready_pod("p3");
        let pods = vec![p1.clone(), p2.clone(), p3.clone()];

        // 1. Default / IfHealthyBudget: unready pods blocked when application is disrupted
        let pdb_if_healthy = json!({
            "metadata": { "name": "pdb-unhealthy" },
            "spec": {
                "selector": { "matchLabels": { "app": "x" } },
                "maxUnavailable": 1,
                "unhealthyPodEvictionPolicy": "IfHealthyBudget"
            }
        });
        let adm_blocked = check_eviction_admission(&p1, &[&pdb_if_healthy], &pods);
        assert!(matches!(
            adm_blocked,
            EvictionAdmission::TooManyRequests { .. }
        ));

        // 2. AlwaysAllow: unready pods are ALWAYS evictable without consuming budget
        let pdb_always = json!({
            "metadata": { "name": "pdb-unhealthy" },
            "spec": {
                "selector": { "matchLabels": { "app": "x" } },
                "maxUnavailable": 1,
                "unhealthyPodEvictionPolicy": "AlwaysAllow"
            }
        });
        let adm_always = check_eviction_admission(&p1, &[&pdb_always], &pods);
        assert_eq!(
            adm_always,
            EvictionAdmission::Allowed {
                consumes_budget: false
            }
        );

        // 3. When application is healthy (2 healthy pods, 1 unready, maxUnavailable: 1, desiredHealthy: 2)
        // IfHealthyBudget allows the unready pod to be evicted without consuming budget
        let healthy1 = pod("h1", true);
        let healthy2 = pod("h2", true);
        let mixed_pods = vec![healthy1.clone(), healthy2.clone(), p1.clone()];
        let adm_mixed = check_eviction_admission(&p1, &[&pdb_if_healthy], &mixed_pods);
        assert_eq!(
            adm_mixed,
            EvictionAdmission::Allowed {
                consumes_budget: false
            }
        );

        // Healthy pod in mixed_pods has disruptionsAllowed = 0 (healthy=2, desired=2) => blocked
        let adm_healthy = check_eviction_admission(&healthy1, &[&pdb_if_healthy], &mixed_pods);
        assert!(matches!(
            adm_healthy,
            EvictionAdmission::TooManyRequests { .. }
        ));

        // 4. Terminal pod is always evictable regardless of policy
        let term = terminal_pod("term");
        let adm_term = check_eviction_admission(&term, &[&pdb_if_healthy], &pods);
        assert_eq!(
            adm_term,
            EvictionAdmission::Allowed {
                consumes_budget: false
            }
        );
    }

    #[test]
    fn record_disruption_decrements_allowed_and_updates_status() {
        let pdb = json!({
            "metadata": { "name": "evict-pdb", "generation": 1 },
            "spec": { "selector": { "matchLabels": { "app": "x" } }, "minAvailable": 1 }
        });
        let counts = PdbCounts {
            expected_pods: 2,
            current_healthy: 2,
            desired_healthy: 1,
            disruptions_allowed: 1,
        };
        let now = "2026-10-15T15:30:00Z";
        let updated = record_disruption_in_pdb(&pdb, "evicted-pod", &counts, now);
        assert_eq!(updated["status"]["disruptionsAllowed"], 0);
        assert_eq!(updated["status"]["disruptedPods"]["evicted-pod"], now);
        let cond = &updated["status"]["conditions"][0];
        assert_eq!(cond["type"], "DisruptionAllowed");
        assert_eq!(cond["status"], "False");
        assert_eq!(cond["reason"], "InsufficientPods");
        assert_eq!(cond["lastTransitionTime"], now);
    }
}
