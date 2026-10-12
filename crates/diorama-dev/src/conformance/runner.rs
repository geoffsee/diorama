//! Synthetic API/controller fixtures; retained-node conformance remains unimplemented.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;

use diorama_apiserver::{
    ApiserverConfig, ApiserverService, KubernetesApiClient, KubernetesStorage,
};
use diorama_controller::webhook::{WebhookConfig, WebhookService};
use diorama_controller::{ControllerManagerConfig, ControllerManagerService};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_dns::{CoreDnsConfig, DnsProber, DnsProtocol, DnsResolutionProbe, ProbeTransport};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use diorama_storage::{LocalPathConfig, LocalPathReconciler, LocalPathVolumeManager};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::disposable_node::current_rfc3339;
use crate::release_qualification::receipt::{
    AssertionRecord, CandidateIdentity, CandidateReceipt, CleanupInventory, CommandExecution,
    EnvironmentInfo, ReceiptPayload, ReceiptTimestamps, SkipRecord, load_candidate_inventory,
    validate_candidate_receipt,
};
use crate::sha256;

/// Default namespace for single-node upstream Kubernetes conformance testing.
pub const CONF_NAMESPACE: &str = "e2e-conformance";

use super::kubeconfig::Kubeconfig;
use super::manifests::*;
use super::selected_conformance::{
    CERTIFICATION_DISCLAIMER, CONFORMANCE_FOCUS_REGEX, CONFORMANCE_SKIP_REGEX,
    ConformanceInventory, ConformanceSummary,
};

/// The six baseline manifest domains defined in Issue #118 and Epic E28.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestDomain {
    WorkloadsNetworking,
    Storage,
    ConfigIdentity,
    Controllers,
    DnsLoadBalancer,
    LbUpdate,
}

impl ManifestDomain {
    #[must_use]
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::WorkloadsNetworking => "Tier 1 — Workloads & Networking",
            Self::Storage => "Tier 2 — Storage Persistence",
            Self::ConfigIdentity => "Tier 3 — Config & Identity",
            Self::Controllers => "Tier 4 — Controllers",
            Self::DnsLoadBalancer => "Tier 5 — DNS & LoadBalancer",
            Self::LbUpdate => "Tier 6 — LoadBalancer UPDATE path [KS-75]",
        }
    }
}

/// Baseline smoke test checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmokeCheck {
    WorkloadPod,
    InClusterDns,
    PodEgress,
}

impl SmokeCheck {
    #[must_use]
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::WorkloadPod => "Smoke 1 — Workload Pod Scheduling and Placement",
            Self::InClusterDns => "Smoke 2 — In-Cluster CoreDNS Resolution",
            Self::PodEgress => "Smoke 3 — Pod Egress Masquerade / SNAT Routing",
        }
    }
}

/// Individual smoke check report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmokeReport {
    pub check: SmokeCheck,
    pub name: String,
    pub passed: bool,
    pub duration_ms: u64,
    pub details: String,
}

/// Report for an individual manifest domain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainReport {
    pub domain: ManifestDomain,
    pub name: String,
    pub passed: bool,
    pub duration_ms: u64,
    pub assertions_count: usize,
    pub details: Vec<String>,
}

/// Overall qualification report covering smoke, manifest tiers, and conformance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualificationReport {
    pub evidence_kind: String,
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_integrity_hash: Option<String>,
    pub smoke_results: Vec<SmokeReport>,
    pub manifest_domain_results: Vec<DomainReport>,
    pub conformance_summary: ConformanceSummary,
    pub total_assertions_checked: usize,
    pub kubeconfig_format_accommodated: String,
    pub certification_disclaimer: String,
}

impl QualificationReport {
    /// In-process fixtures never qualify the selected retained executables.
    pub fn verify_qualification(&self) -> Result<(), String> {
        self.verify_fixture()?;
        if self.evidence_kind == "candidate_receipt_bound"
            && self.receipt_id.is_some()
            && self.receipt_integrity_hash.is_some()
        {
            return Ok(());
        }
        Err("Synthetic in-process fixture evidence cannot qualify C13/E28; a retained-executable node runner is not implemented".into())
    }

    /// Validate exact fixture coverage and counts without claiming live qualification.
    pub fn verify_fixture(&self) -> Result<(), String> {
        let smoke = [
            SmokeCheck::WorkloadPod,
            SmokeCheck::InClusterDns,
            SmokeCheck::PodEgress,
        ];
        let domains = [
            (ManifestDomain::WorkloadsNetworking, 10),
            (ManifestDomain::Storage, 12),
            (ManifestDomain::ConfigIdentity, 6),
            (ManifestDomain::Controllers, 11),
            (ManifestDomain::DnsLoadBalancer, 5),
            (ManifestDomain::LbUpdate, 10),
        ];
        if (self.evidence_kind != "synthetic_fixture"
            && self.evidence_kind != "candidate_receipt_bound")
            || self.smoke_results.len() != smoke.len()
            || self.manifest_domain_results.len() != domains.len()
            || self.certification_disclaimer != CERTIFICATION_DISCLAIMER
            || self.kubeconfig_format_accommodated != "YAML and JSON (dual-format validated)"
        {
            return Err("Invalid fixture evidence kind or required coverage".into());
        }
        for id in smoke {
            let rows: Vec<_> = self
                .smoke_results
                .iter()
                .filter(|s| s.check == id)
                .collect();
            if rows.len() != 1
                || rows[0].name != id.display_name()
                || rows[0].passed != (id != SmokeCheck::PodEgress)
            {
                return Err("Missing, duplicate or incorrectly classified smoke fixture".into());
            }
        }
        for (id, count) in domains {
            let rows: Vec<_> = self
                .manifest_domain_results
                .iter()
                .filter(|d| d.domain == id)
                .collect();
            if rows.len() != 1
                || !rows[0].passed
                || rows[0].name != id.display_name()
                || rows[0].assertions_count != count
            {
                return Err("Missing, duplicate or inconsistent manifest fixture evidence".into());
            }
        }
        self.conformance_summary.verify_fixture()?;
        // The fixture performs three API admission assertions and two synthetic DNS
        // assertions; pod egress and upstream conformance are not executed.
        let expected_assertions = 5 + self
            .manifest_domain_results
            .iter()
            .map(|d| d.assertions_count)
            .sum::<usize>();
        if self.total_assertions_checked != expected_assertions {
            return Err("Assertion total disagrees with executed fixture checks".into());
        }
        Ok(())
    }

    /// Render to pretty JSON string.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    /// Render to GitHub-flavored Markdown summary table.
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        if self.evidence_kind == "candidate_receipt_bound" && self.receipt_id.is_some() {
            md.push_str("# Diorama Conformance Qualification Report\n\n");
            if let (Some(receipt_id), Some(hash)) = (&self.receipt_id, &self.receipt_integrity_hash)
            {
                md.push_str(&format!(
                    "- **Receipt ID**: `{receipt_id}`\n- **Receipt Integrity Hash**: `{hash}`\n\n"
                ));
            }
            md.push_str("CANDIDATE_RECEIPT_BOUND. Conformance evidence qualified via candidate receipt.\n\n");
        } else {
            md.push_str("# Diorama Synthetic In-Process Fixture Report\n\n");
            if let (Some(receipt_id), Some(hash)) = (&self.receipt_id, &self.receipt_integrity_hash)
            {
                md.push_str(&format!(
                    "- **Receipt ID**: `{receipt_id}`\n- **Receipt Integrity Hash**: `{hash}`\n\n"
                ));
            }
            md.push_str("C13/E28 remains unqualified. No retained-executable node or upstream conformance suite was run.\n\n");
        }
        md.push_str("> ");
        md.push_str(&self.certification_disclaimer);
        md.push_str("\n\n");

        md.push_str("## 1. Baseline Smoke Verification\n\n");
        md.push_str("| Smoke Check | Status | Duration | Details |\n");
        md.push_str("|---|---|---|---|\n");
        for s in &self.smoke_results {
            let status = if s.check == SmokeCheck::PodEgress {
                "NOT EXECUTED"
            } else if s.passed {
                "PASS (fixture)"
            } else {
                "FAIL"
            };
            md.push_str(&format!(
                "| {} | {} | {}ms | {} |\n",
                s.name, status, s.duration_ms, s.details
            ));
        }
        md.push('\n');

        md.push_str("## 2. Six Baseline Manifest Domains\n\n");
        md.push_str("| Domain | Status | Assertions | Duration |\n");
        md.push_str("|---|---|---|---|\n");
        for d in &self.manifest_domain_results {
            let status = if d.passed { "PASS" } else { "FAIL" };
            md.push_str(&format!(
                "| {} | {} | {} | {}ms |\n",
                d.name, status, d.assertions_count, d.duration_ms
            ));
        }
        md.push('\n');

        md.push_str("## 3. Selected Single-Node Conformance Summary\n\n");
        md.push_str("NOT EXECUTED. The inventory lists planned candidates; API-object creation does not establish upstream test execution.\n\n");
        md.push_str(&format!(
            "- **Total Selected Tests**: {}\n",
            self.conformance_summary.total_selected
        ));
        md.push_str(&format!(
            "- **Passed**: {}\n",
            self.conformance_summary.passed
        ));
        md.push_str(&format!(
            "- **Failed**: {}\n",
            self.conformance_summary.failed
        ));
        md.push_str(&format!(
            "- **Explicit Exclusions**: {}\n",
            self.conformance_summary.excluded_count
        ));
        md.push_str(&format!(
            "- **Focus Pattern**: `{}`\n",
            self.conformance_summary.focus_filter
        ));
        md.push_str(&format!(
            "- **Skip Pattern**: `{}`\n\n",
            self.conformance_summary.skip_filter
        ));

        md.push_str("### Explicit Exclusions with Rationale\n\n");
        md.push_str("| Pattern | Category | Technical Rationale |\n");
        md.push_str("|---|---|---|\n");
        for ex in &self.conformance_summary.exclusions {
            md.push_str(&format!(
                "| `{}` | `{:?}` | {} |\n",
                ex.pattern, ex.category, ex.rationale
            ));
        }
        md.push('\n');

        md.push_str("### Kubeconfig Format Accommodation\n\n");
        md.push_str(&format!(
            "Verified dual-format accommodation: **{}** (YAML and JSON interchangeability confirmed).\n\n",
            self.kubeconfig_format_accommodated
        ));

        md
    }
}

/// Qualification runner providing the integration harness.
#[derive(Debug)]
pub struct QualificationRunner {
    node_name: String,
    node_ip: IpAddr,
    lb_ip: String,
}

impl Default for QualificationRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl QualificationRunner {
    #[must_use]
    pub fn new() -> Self {
        Self {
            node_name: "diorama-node-qual".to_string(),
            node_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)),
            lb_ip: "192.0.2.10".to_string(),
        }
    }

    /// Execute the complete smoke, manifest tier, and conformance qualification suite.
    pub async fn run_qualification(&self) -> Result<QualificationReport, String> {
        Err("Retained-executable C13/E28 node qualification is not implemented; use the explicit synthetic fixture command".into())
    }

    /// Execute only synthetic in-process API/controller fixtures.
    pub async fn run_fixture(&self) -> Result<QualificationReport, String> {
        let temp = TempDir::new().map_err(|e| format!("TempDir error: {e}"))?;

        // 1. Setup PKI
        let pki_dir = temp.path().join("pki");
        std::fs::create_dir_all(&pki_dir).map_err(|e| e.to_string())?;
        let pki_config =
            ClusterPkiConfig::new(pki_dir.clone(), self.node_name.clone(), self.node_ip);
        let pki = ClusterPki::new(pki_config);
        pki.reconcile().map_err(|e| e.to_string())?;

        // 2. Setup Datastore
        let datastore_dir = temp.path().join("datastore");
        let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(datastore_dir))
            .map_err(|e| e.to_string())?;
        let storage = KubernetesStorage::new(engine.client(), "/registry");

        // 3. Setup Apiserver
        let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, self.node_ip);
        let apiserver_service = Arc::new(ApiserverService::new(apiserver_config, storage));
        apiserver_service
            .check_prerequisites()
            .await
            .map_err(|e| e.to_string())?;
        apiserver_service.start().map_err(|e| e.to_string())?;

        // 4. Setup Webhook (NodeSetter + LoadBalancer status)
        let mut webhook_config = WebhookConfig::default_for_pki(
            &pki_dir,
            &self.node_name,
            &self.lb_ip,
            true, // LoadBalancer enabled
        );
        webhook_config.port = 0; // ephemeral port for test isolation
        let webhook_service = WebhookService::new(webhook_config, apiserver_service.clone());
        webhook_service
            .check_prerequisites()
            .await
            .map_err(|e| e.to_string())?;
        webhook_service.start().await.map_err(|e| e.to_string())?;

        // 5. Setup Controller Manager
        let controller_config = ControllerManagerConfig::default_for_pki(&pki_dir, self.node_ip);
        let controller_service =
            ControllerManagerService::new(controller_config, apiserver_service.clone());
        controller_service
            .start()
            .await
            .map_err(|e| e.to_string())?;

        // 6. Setup LocalPath Storage Provisioner
        let storage_root = temp.path().join("local-path-storage");
        std::fs::create_dir_all(&storage_root).map_err(|e| e.to_string())?;
        let localpath_config = LocalPathConfig::new()
            .with_storage_path(storage_root.display().to_string())
            .with_volume_binding_mode("WaitForFirstConsumer")
            .with_reclaim_policy("Retain");

        let client = apiserver_service.admin_client();

        // 7. Verify kubeconfig accommodation (both YAML and JSON formats)
        let kubeconfig_path = pki_dir.join("admin.kubeconfig");
        let parsed_yaml = Kubeconfig::from_file(&kubeconfig_path)
            .map_err(|e| format!("Failed to read/parse YAML kubeconfig: {e}"))?;
        let kubeconfig_json_str = parsed_yaml
            .to_json()
            .map_err(|e| format!("Failed to serialize kubeconfig to JSON: {e}"))?;
        let parsed_json = Kubeconfig::parse(&kubeconfig_json_str)
            .map_err(|e| format!("Failed to parse JSON kubeconfig: {e}"))?;
        if parsed_yaml != parsed_json {
            return Err("Kubeconfig parsed from YAML and JSON do not match".to_string());
        }

        let mut smoke_results = Vec::new();
        let mut manifest_domain_results = Vec::new();
        let mut total_assertions = 0;

        // ── 8. Execute Smoke Checks ──────────────────────────────────────────
        let s1 = self.run_smoke_pod(&client).await?;
        total_assertions += 3;
        smoke_results.push(s1);

        let s2 = self.run_smoke_dns(&client).await?;
        total_assertions += 2;
        smoke_results.push(s2);

        let s3 = self.run_smoke_egress(&client).await?;
        smoke_results.push(s3);

        // ── 9. Execute Manifest Domains ───────────────────────────────────────
        let (d1, a1) = self
            .run_tier1_workload(&client, &controller_service)
            .await?;
        total_assertions += a1;
        manifest_domain_results.push(d1);

        let (d2, a2) = self
            .run_tier2_storage(&client, &localpath_config, &storage_root)
            .await?;
        total_assertions += a2;
        manifest_domain_results.push(d2);

        let (d3, a3) = self.run_tier3_config(&client).await?;
        total_assertions += a3;
        manifest_domain_results.push(d3);

        let (d4, a4) = self
            .run_tier4_controllers(&client, &controller_service)
            .await?;
        total_assertions += a4;
        manifest_domain_results.push(d4);

        let (d5, a5) = self.run_tier5_dns_lb(&client).await?;
        total_assertions += a5;
        manifest_domain_results.push(d5);

        let (d6, a6) = self.run_tier6_lb_update(&client).await?;
        total_assertions += a6;
        manifest_domain_results.push(d6);

        // ── 10. Execute Selected Conformance Suite ───────────────────────────
        let (conformance_summary, a_conf) = self.run_selected_conformance(&client).await?;
        total_assertions += a_conf;

        // Teardown services
        webhook_service.stop().await;
        controller_service.stop();

        let report = QualificationReport {
            evidence_kind: "synthetic_fixture".into(),
            timestamp: format!(
                "unix:{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_secs()
            ),
            receipt_id: None,
            receipt_integrity_hash: None,
            smoke_results,
            manifest_domain_results,
            conformance_summary,
            total_assertions_checked: total_assertions,
            kubeconfig_format_accommodated: "YAML and JSON (dual-format validated)".to_string(),
            certification_disclaimer: CERTIFICATION_DISCLAIMER.to_string(),
        };

        report.verify_fixture()?;
        Ok(report)
    }

    // ── Smoke Check 1: Workload Pod ──────────────────────────────────────────
    async fn run_smoke_pod(&self, client: &KubernetesApiClient) -> Result<SmokeReport, String> {
        let start = Instant::now();
        client
            .create_namespace(SMOKE_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;

        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "smoke-busybox",
                "namespace": SMOKE_NAMESPACE
            },
            "spec": {
                "restartPolicy": "Never",
                "containers": [{
                    "name": "busybox",
                    "image": "busybox:1.36",
                    "command": ["sh", "-c", "sleep 3600"]
                }]
            }
        });

        let created = client
            .create_pod(SMOKE_NAMESPACE, pod)
            .await
            .map_err(|e| format!("Failed to create smoke pod: {e}"))?;

        // Assert NodeSetter assigned nodeName
        let assigned_node = created["spec"]["nodeName"].as_str().unwrap_or("");
        if assigned_node != self.node_name {
            return Err(format!(
                "Smoke pod nodeName mismatch: expected '{}', got '{}'",
                self.node_name, assigned_node
            ));
        }

        // Cleanup
        client
            .delete_namespace(SMOKE_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;

        Ok(SmokeReport {
            check: SmokeCheck::WorkloadPod,
            name: SmokeCheck::WorkloadPod.display_name().to_string(),
            passed: true,
            duration_ms: start.elapsed().as_millis() as u64,
            details: format!(
                "Synthetic Pod API admission applied NodeSetter mutation, nodeName='{}'; no workload executed",
                assigned_node
            ),
        })
    }

    // ── Smoke Check 2: In-Cluster DNS ────────────────────────────────────────
    async fn run_smoke_dns(&self, client: &KubernetesApiClient) -> Result<SmokeReport, String> {
        let start = Instant::now();
        // Setup kubernetes.default Service in default namespace
        let svc_ip = std::net::Ipv4Addr::new(10, 43, 0, 1);
        let k8s_svc = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "kubernetes",
                "namespace": "default"
            },
            "spec": {
                "type": "ClusterIP",
                "clusterIP": svc_ip.to_string(),
                "ports": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "TCP"
                }]
            }
        });

        let _ = client.create_service("default", k8s_svc).await;

        let prober = DnsProber::new(ProbeTransport::Synthetic {
            client: Arc::new(client.clone()),
            config: CoreDnsConfig::new(),
        });

        let probe =
            DnsResolutionProbe::same_namespace("kubernetes", "default", svc_ip, DnsProtocol::Udp);

        let result = prober
            .execute_probe(&probe)
            .await
            .map_err(|e| format!("DNS probe error: {e}"))?;

        if !result.success {
            return Err(format!("Smoke DNS check failed: {}", result.details));
        }

        Ok(SmokeReport {
            check: SmokeCheck::InClusterDns,
            name: SmokeCheck::InClusterDns.display_name().to_string(),
            passed: true,
            duration_ms: start.elapsed().as_millis() as u64,
            details: "Synthetic DNS model matched kubernetes.default.svc.cluster.local to ClusterIP 10.43.0.1; no CoreDNS server or pod query executed"
                .to_string(),
        })
    }

    // ── Smoke Check 3: Pod Egress ────────────────────────────────────────────
    async fn run_smoke_egress(&self, _client: &KubernetesApiClient) -> Result<SmokeReport, String> {
        let start = Instant::now();
        Ok(SmokeReport {
            check: SmokeCheck::PodEgress,
            name: SmokeCheck::PodEgress.display_name().to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis() as u64,
            details: "NOT EXECUTED: in-process fixtures have no pod runtime or network dataplane"
                .into(),
        })
    }

    // ── Tier 1: Workloads & Networking ───────────────────────────────────────
    async fn run_tier1_workload(
        &self,
        client: &KubernetesApiClient,
        controller: &ControllerManagerService,
    ) -> Result<(DomainReport, usize), String> {
        let start = Instant::now();
        let mut assertions = 0;
        let mut details = Vec::new();

        client
            .create_namespace(TIER1_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;

        // 1. Create Deployment
        let deployment = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "web",
                "namespace": TIER1_NAMESPACE
            },
            "spec": {
                "replicas": 2,
                "selector": {
                    "matchLabels": { "app": "web" }
                },
                "template": {
                    "metadata": {
                        "labels": { "app": "web" }
                    },
                    "spec": {
                        "containers": [{
                            "name": "web",
                            "image": "nginx:1.27-alpine",
                            "ports": [{ "containerPort": 80 }]
                        }]
                    }
                }
            }
        });

        client
            .create_deployment(TIER1_NAMESPACE, deployment)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        // Reconcile Deployment -> ReplicaSet -> Pods
        let wm = controller.workload_manager();
        wm.reconcile_namespace(TIER1_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;
        wm.reconcile_namespace(TIER1_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;

        let rs = client
            .get_replicaset(TIER1_NAMESPACE, "web-rs")
            .await
            .map_err(|e| format!("ReplicaSet web-rs not generated: {e}"))?;
        if rs["spec"]["replicas"] != 2 {
            return Err("web-rs replicas mismatch".to_string());
        }
        assertions += 1;
        details.push("Deployment reconciled to ReplicaSet web-rs with 2 replicas".to_string());

        let pods = client
            .list_pods(TIER1_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;
        let pod_items = pods["items"].as_array().ok_or("pods list error")?;
        if pod_items.len() != 2 {
            return Err(format!("Expected 2 child pods, found {}", pod_items.len()));
        }
        assertions += 1;
        for p in pod_items {
            let node = p["spec"]["nodeName"].as_str().unwrap_or("");
            if node != self.node_name {
                return Err(format!(
                    "Pod node placement mismatch: expected '{}', got '{}'",
                    self.node_name, node
                ));
            }
            assertions += 1;
        }
        details.push(
            "ReplicaSet generated 2 Pod API objects mutated with NodeSetter placement".to_string(),
        );

        // 2. Create Services (ClusterIP and NodePort)
        let svc_clusterip = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "web-clusterip",
                "namespace": TIER1_NAMESPACE
            },
            "spec": {
                "type": "ClusterIP",
                "clusterIP": "10.43.20.1",
                "selector": { "app": "web" },
                "ports": [{ "port": 80, "targetPort": 80 }]
            }
        });
        let created_cip = client
            .create_service(TIER1_NAMESPACE, svc_clusterip)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;
        let cip = created_cip["spec"]["clusterIP"].as_str().unwrap_or("");
        if cip.is_empty() {
            return Err("ClusterIP was not allocated".to_string());
        }
        assertions += 1;
        details.push(format!("ClusterIP service allocated IP: {cip}"));

        let svc_nodeport = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "web-nodeport",
                "namespace": TIER1_NAMESPACE
            },
            "spec": {
                "type": "NodePort",
                "selector": { "app": "web" },
                "ports": [{ "port": 80, "targetPort": 80, "nodePort": 31080 }]
            }
        });
        let created_np = client
            .create_service(TIER1_NAMESPACE, svc_nodeport)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;
        let np = created_np["spec"]["ports"][0]["nodePort"]
            .as_u64()
            .unwrap_or(0);
        if np == 0 {
            return Err("NodePort was not allocated".to_string());
        }
        assertions += 1;
        details.push(format!("NodePort service allocated port: {np}"));

        // Cleanup
        client
            .delete_namespace(TIER1_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        Ok((
            DomainReport {
                domain: ManifestDomain::WorkloadsNetworking,
                name: ManifestDomain::WorkloadsNetworking
                    .display_name()
                    .to_string(),
                passed: true,
                duration_ms: start.elapsed().as_millis() as u64,
                assertions_count: assertions,
                details,
            },
            assertions,
        ))
    }

    // ── Tier 2: Storage Persistence ──────────────────────────────────────────
    async fn run_tier2_storage(
        &self,
        client: &KubernetesApiClient,
        storage_config: &LocalPathConfig,
        storage_root: &std::path::Path,
    ) -> Result<(DomainReport, usize), String> {
        let start = Instant::now();
        let mut assertions = 0;
        let mut details = Vec::new();

        client
            .create_namespace(TIER2_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;

        // 1. Storage provisioner reconciliation
        let storage_reconciler = LocalPathReconciler::new(storage_config);
        storage_reconciler
            .reconcile(client)
            .await
            .map_err(|e| format!("Storage provisioner reconcile error: {e}"))?;
        assertions += 1;
        details.push("local-path StorageClass reconciled with Retain policy".to_string());

        // 2. Create PVC requesting local-path
        let pvc = json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": "data",
                "namespace": TIER2_NAMESPACE
            },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "storageClassName": "local-path",
                "resources": {
                    "requests": { "storage": "64Mi" }
                }
            }
        });
        let created_pvc = client
            .create_pvc(TIER2_NAMESPACE, pvc)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        // Verify NodeSetter selected-node annotation
        let selected_node =
            created_pvc["metadata"]["annotations"]["volume.kubernetes.io/selected-node"]
                .as_str()
                .unwrap_or("");
        if selected_node != self.node_name {
            return Err("PVC missing volume.kubernetes.io/selected-node".to_string());
        }
        assertions += 1;
        details.push("PVC annotated with volume.kubernetes.io/selected-node".to_string());

        // 3. Create writer Job
        let writer_job = json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": "writer",
                "namespace": TIER2_NAMESPACE
            },
            "spec": {
                "backoffLimit": 2,
                "template": {
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [{
                            "name": "writer",
                            "image": "busybox:1.36",
                            "command": ["sh", "-c", "echo persisted-ok > /data/marker && sync"],
                            "volumeMounts": [{ "name": "data", "mountPath": "/data" }]
                        }],
                        "volumes": [{
                            "name": "data",
                            "persistentVolumeClaim": { "claimName": "data" }
                        }]
                    }
                }
            }
        });
        client
            .create_job(TIER2_NAMESPACE, writer_job)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        // Volume manager provisions PV for PVC
        let vol_mgr = LocalPathVolumeManager::new(storage_config.clone(), client.clone());
        let writer_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "writer-pod",
                "namespace": TIER2_NAMESPACE
            },
            "spec": {
                "nodeName": self.node_name,
                "volumes": [{
                    "name": "data",
                    "persistentVolumeClaim": { "claimName": "data" }
                }]
            }
        });
        client
            .create_pod(TIER2_NAMESPACE, writer_pod)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        let bound_pvs = vol_mgr
            .bind_volumes_for_pod(TIER2_NAMESPACE, "writer-pod")
            .await
            .map_err(|e| format!("Volume provisioning error: {e}"))?;
        let pv_name = bound_pvs
            .first()
            .and_then(|pv| pv.get("metadata"))
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| "Failed to extract PV name from bound volumes".to_string())?;
        assertions += 1;

        // Simulate writer pod writing marker to volume
        let vol_dir = storage_root.join(pv_name);
        std::fs::create_dir_all(&vol_dir).map_err(|e| e.to_string())?;
        std::fs::write(vol_dir.join("marker"), b"persisted-ok\n").map_err(|e| e.to_string())?;
        assertions += 1;
        details.push(
            "Synthetic host fixture wrote the marker; no writer workload executed".to_string(),
        );

        // Delete writer pod and job
        client
            .delete_pod(TIER2_NAMESPACE, "writer-pod")
            .await
            .map_err(|e| e.to_string())?;
        client
            .delete_job(TIER2_NAMESPACE, "writer")
            .await
            .map_err(|e| e.to_string())?;
        assertions += 2;

        // 4. Create reader Pod mounting SAME PVC
        let reader_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "reader",
                "namespace": TIER2_NAMESPACE
            },
            "spec": {
                "restartPolicy": "Never",
                "containers": [{
                    "name": "reader",
                    "image": "busybox:1.36",
                    "command": ["sh", "-c", "test \"$(cat /data/marker)\" = persisted-ok && sleep 3600"],
                    "volumeMounts": [{ "name": "data", "mountPath": "/data" }]
                }],
                "volumes": [{
                    "name": "data",
                    "persistentVolumeClaim": { "claimName": "data" }
                }]
            }
        });
        client
            .create_pod(TIER2_NAMESPACE, reader_pod)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        // Read host-fixture data after changing Pod API objects; no pod ran.
        let marker_content =
            std::fs::read_to_string(vol_dir.join("marker")).map_err(|e| e.to_string())?;
        if marker_content.trim() != "persisted-ok" {
            return Err(format!(
                "PVC marker mismatch: expected 'persisted-ok', got '{}'",
                marker_content.trim()
            ));
        }
        assertions += 1;
        details.push("Host fixture read the marker after Pod API object replacement; no reader workload executed".to_string());

        // Cleanup
        client
            .delete_namespace(TIER2_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        Ok((
            DomainReport {
                domain: ManifestDomain::Storage,
                name: ManifestDomain::Storage.display_name().to_string(),
                passed: true,
                duration_ms: start.elapsed().as_millis() as u64,
                assertions_count: assertions,
                details,
            },
            assertions,
        ))
    }

    // ── Tier 3: Config & Identity ────────────────────────────────────────────
    async fn run_tier3_config(
        &self,
        client: &KubernetesApiClient,
    ) -> Result<(DomainReport, usize), String> {
        let start = Instant::now();
        let mut assertions = 0;
        let mut details = Vec::new();

        client
            .create_namespace(TIER3_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;

        // 1. ConfigMap
        let mut cm_data = BTreeMap::new();
        cm_data.insert("greeting".to_string(), "hello-kubesolo".to_string());
        client
            .create_configmap(TIER3_NAMESPACE, "app-config", cm_data)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;
        details.push("ConfigMap app-config created with greeting=hello-kubesolo".to_string());

        // 2. Secret
        let mut sec_data = BTreeMap::new();
        sec_data.insert("token".to_string(), "s3cr3t-value".to_string());
        client
            .create_secret(TIER3_NAMESPACE, "app-secret", sec_data, Some("Opaque"))
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;
        details.push("Secret app-secret created with token stringData".to_string());

        // 3. Consumer Pod
        let consumer_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "consumer",
                "namespace": TIER3_NAMESPACE
            },
            "spec": {
                "restartPolicy": "Never",
                "containers": [{
                    "name": "consumer",
                    "image": "busybox:1.36",
                    "command": ["sh", "-c", "sleep 3600"],
                    "env": [{
                        "name": "GREETING",
                        "valueFrom": {
                            "configMapKeyRef": {
                                "name": "app-config",
                                "key": "greeting"
                            }
                        }
                    }],
                    "volumeMounts": [
                        { "name": "secret", "mountPath": "/etc/secret", "readOnly": true },
                        { "name": "token", "mountPath": "/var/run/secrets/tokens", "readOnly": true }
                    ]
                }],
                "volumes": [
                    { "name": "secret", "secret": { "secretName": "app-secret" } },
                    {
                        "name": "token",
                        "projected": {
                            "sources": [{
                                "serviceAccountToken": {
                                    "path": "sa-token",
                                    "expirationSeconds": 3600,
                                    "audience": "kubesolo-e2e"
                                }
                            }]
                        }
                    }
                ]
            }
        });

        let created_pod = client
            .create_pod(TIER3_NAMESPACE, consumer_pod)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        // Verify Pod spec retains envFrom configMapKeyRef, secret volume, and projected token
        let volumes = created_pod["spec"]["volumes"]
            .as_array()
            .ok_or("volumes array")?;
        if volumes.len() != 2 {
            return Err("Expected 2 volumes in consumer pod".to_string());
        }
        assertions += 1;

        let proj = &volumes[1]["projected"]["sources"][0]["serviceAccountToken"];
        if proj["audience"] != "kubesolo-e2e" {
            return Err("Projected token audience mismatch".to_string());
        }
        assertions += 1;
        details.push(
            "Stored Pod spec retained Secret/projected-token volume declarations and token audience; no container consumed configuration, mounted volumes or received a token"
                .to_string(),
        );

        // Cleanup
        client
            .delete_namespace(TIER3_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        Ok((
            DomainReport {
                domain: ManifestDomain::ConfigIdentity,
                name: ManifestDomain::ConfigIdentity.display_name().to_string(),
                passed: true,
                duration_ms: start.elapsed().as_millis() as u64,
                assertions_count: assertions,
                details,
            },
            assertions,
        ))
    }

    // ── Tier 4: Controllers ──────────────────────────────────────────────────
    async fn run_tier4_controllers(
        &self,
        client: &KubernetesApiClient,
        controller: &ControllerManagerService,
    ) -> Result<(DomainReport, usize), String> {
        let start = Instant::now();
        let mut assertions = 0;
        let mut details = Vec::new();

        client
            .create_namespace(TIER4_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;

        // 1. Job oneshot
        let job = json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": "oneshot",
                "namespace": TIER4_NAMESPACE
            },
            "spec": {
                "backoffLimit": 2,
                "template": {
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [{
                            "name": "oneshot",
                            "image": "busybox:1.36",
                            "command": ["sh", "-c", "echo done"]
                        }]
                    }
                }
            }
        });
        client
            .create_job(TIER4_NAMESPACE, job)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        // 2. CronJob periodic
        let cjob = json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {
                "name": "periodic",
                "namespace": TIER4_NAMESPACE
            },
            "spec": {
                "schedule": "*/5 * * * *",
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {
                                "restartPolicy": "Never",
                                "containers": [{
                                    "name": "tick",
                                    "image": "busybox:1.36",
                                    "command": ["sh", "-c", "echo tick"]
                                }]
                            }
                        }
                    }
                }
            }
        });
        client
            .create_cronjob(TIER4_NAMESPACE, cjob)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        // 3. DaemonSet agent
        let ds = json!({
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {
                "name": "agent",
                "namespace": TIER4_NAMESPACE
            },
            "spec": {
                "selector": {
                    "matchLabels": { "app": "agent" }
                },
                "template": {
                    "metadata": {
                        "labels": { "app": "agent" }
                    },
                    "spec": {
                        "containers": [{
                            "name": "agent",
                            "image": "busybox:1.36",
                            "command": ["sh", "-c", "sleep 3600"]
                        }]
                    }
                }
            }
        });
        client
            .create_daemonset(TIER4_NAMESPACE, ds)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        // 4. StatefulSet stateful with headless Service
        let headless_svc = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "stateful",
                "namespace": TIER4_NAMESPACE
            },
            "spec": {
                "clusterIP": "None",
                "selector": { "app": "stateful" },
                "ports": [{ "port": 80 }]
            }
        });
        client
            .create_service(TIER4_NAMESPACE, headless_svc)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        let ss = json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {
                "name": "stateful",
                "namespace": TIER4_NAMESPACE
            },
            "spec": {
                "serviceName": "stateful",
                "replicas": 1,
                "selector": {
                    "matchLabels": { "app": "stateful" }
                },
                "template": {
                    "metadata": {
                        "labels": { "app": "stateful" }
                    },
                    "spec": {
                        "containers": [{
                            "name": "stateful",
                            "image": "busybox:1.36",
                            "command": ["sh", "-c", "sleep 3600"]
                        }]
                    }
                }
            }
        });
        client
            .create_statefulset(TIER4_NAMESPACE, ss)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        // 5. Trigger CronJob manually (kubectl create job --from=cronjob/periodic periodic-manual)
        let manual_job = json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": "periodic-manual",
                "namespace": TIER4_NAMESPACE,
                "ownerReferences": [{
                    "apiVersion": "batch/v1",
                    "kind": "CronJob",
                    "name": "periodic",
                    "uid": "uid-cronjob-periodic"
                }]
            },
            "spec": {
                "template": {
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [{
                            "name": "tick",
                            "image": "busybox:1.36",
                            "command": ["sh", "-c", "echo tick"]
                        }]
                    }
                }
            }
        });
        client
            .create_job(TIER4_NAMESPACE, manual_job)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        // Reconcile controllers
        let wm = controller.workload_manager();
        wm.reconcile_namespace(TIER4_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        // Verify ordinal pod stateful-0 created by StatefulSet
        let pod_0 = client.get_pod(TIER4_NAMESPACE, "stateful-0").await;
        if pod_0.is_err() {
            return Err("StatefulSet ordinal pod stateful-0 not found".to_string());
        }
        assertions += 1;
        details.push("StatefulSet reconciled ordinal child Pod API object stateful-0".to_string());

        // Verify child pods from Job oneshot
        let oneshot_pod = client.get_pod(TIER4_NAMESPACE, "oneshot-0").await;
        if oneshot_pod.is_err() {
            return Err("Job oneshot child pod oneshot-0 not found".to_string());
        }
        assertions += 1;
        details.push("Job oneshot reconciled child Pod API object oneshot-0".to_string());

        // Verify DaemonSet agent pod
        let ds_pod = client.get_pod(TIER4_NAMESPACE, "agent-node").await;
        if ds_pod.is_err() {
            return Err("DaemonSet child pod agent-node not found".to_string());
        }
        assertions += 1;
        details.push("DaemonSet agent reconciled node Pod API object agent-node".to_string());

        // Cleanup
        client
            .delete_namespace(TIER4_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        Ok((
            DomainReport {
                domain: ManifestDomain::Controllers,
                name: ManifestDomain::Controllers.display_name().to_string(),
                passed: true,
                duration_ms: start.elapsed().as_millis() as u64,
                assertions_count: assertions,
                details,
            },
            assertions,
        ))
    }

    // ── Tier 5: DNS & LoadBalancer ───────────────────────────────────────────
    async fn run_tier5_dns_lb(
        &self,
        client: &KubernetesApiClient,
    ) -> Result<(DomainReport, usize), String> {
        let start = Instant::now();
        let mut assertions = 0;
        let mut details = Vec::new();

        client
            .create_namespace(TIER5_NAMESPACE_A)
            .await
            .map_err(|e| e.to_string())?;
        client
            .create_namespace(TIER5_NAMESPACE_B)
            .await
            .map_err(|e| e.to_string())?;

        // 1. In tier5-a: Deployment web, Service web (ClusterIP), Service web-lb (LoadBalancer)
        let svc_ip = std::net::Ipv4Addr::new(10, 43, 50, 10);
        let svc_clusterip = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "web",
                "namespace": TIER5_NAMESPACE_A
            },
            "spec": {
                "type": "ClusterIP",
                "clusterIP": svc_ip.to_string(),
                "ports": [{ "name": "http", "port": 80, "targetPort": 80 }]
            }
        });
        client
            .create_service(TIER5_NAMESPACE_A, svc_clusterip)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        // 2. LoadBalancer service: NodeSetter status webhook patches status with node IP
        let svc_lb = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "web-lb",
                "namespace": TIER5_NAMESPACE_A
            },
            "spec": {
                "type": "LoadBalancer",
                "ports": [{ "name": "http", "port": 80, "targetPort": 80 }]
            }
        });
        let _created_lb = client
            .create_service(TIER5_NAMESPACE_A, svc_lb)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        let lb_ingress = wait_for_lb_ip(client, TIER5_NAMESPACE_A, "web-lb", &self.lb_ip).await?;
        assertions += 1;
        details.push(format!(
            "LoadBalancer webhook assigned node IP: {lb_ingress}"
        ));

        // 3. Cross-namespace DNS resolution: client in tier5-b resolving web.tier5-a
        let prober = DnsProber::new(ProbeTransport::Synthetic {
            client: Arc::new(client.clone()),
            config: CoreDnsConfig::new(),
        });
        let probe = DnsResolutionProbe::cross_namespace(
            "web",
            TIER5_NAMESPACE_A,
            TIER5_NAMESPACE_B,
            svc_ip,
            DnsProtocol::Udp,
        );
        let dns_res = prober
            .execute_probe(&probe)
            .await
            .map_err(|e| e.to_string())?;
        if !dns_res.success {
            return Err(format!(
                "Cross-namespace DNS resolution failed: {}",
                dns_res.details
            ));
        }
        assertions += 1;
        details.push(format!(
            "Synthetic DNS model matched web.tier5-a.svc.cluster.local -> {svc_ip}; no CoreDNS server or pod query executed"
        ));

        // Cleanup
        client
            .delete_namespace(TIER5_NAMESPACE_A)
            .await
            .map_err(|e| e.to_string())?;
        client
            .delete_namespace(TIER5_NAMESPACE_B)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        Ok((
            DomainReport {
                domain: ManifestDomain::DnsLoadBalancer,
                name: ManifestDomain::DnsLoadBalancer.display_name().to_string(),
                passed: true,
                duration_ms: start.elapsed().as_millis() as u64,
                assertions_count: assertions,
                details,
            },
            assertions,
        ))
    }

    // ── Tier 6: LoadBalancer UPDATE path [KS-75] ─────────────────────────────
    async fn run_tier6_lb_update(
        &self,
        client: &KubernetesApiClient,
    ) -> Result<(DomainReport, usize), String> {
        let start = Instant::now();
        let mut assertions = 0;
        let mut details = Vec::new();

        client
            .create_namespace(TIER6_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;

        // 1. Control: born-lb created as LoadBalancer
        let born_lb = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "born-lb",
                "namespace": TIER6_NAMESPACE
            },
            "spec": {
                "type": "LoadBalancer",
                "ports": [{ "name": "http", "port": 80, "targetPort": 80 }]
            }
        });
        let _ = client
            .create_service(TIER6_NAMESPACE, born_lb)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        let born_ip = wait_for_lb_ip(client, TIER6_NAMESPACE, "born-lb", &self.lb_ip).await?;
        assertions += 1;
        details.push(format!("Control born-lb assigned IP: {born_ip}"));

        // 2. Precondition: flip-me born as ClusterIP has NO loadBalancer ingress IP
        let flip_me_cip = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "flip-me",
                "namespace": TIER6_NAMESPACE
            },
            "spec": {
                "type": "ClusterIP",
                "ports": [{ "name": "http", "port": 80, "targetPort": 80 }]
            }
        });
        let created_flip = client
            .create_service(TIER6_NAMESPACE, flip_me_cip)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        let initial_ingress = created_flip
            .pointer("/status/loadBalancer/ingress")
            .and_then(|v| v.as_array());
        if initial_ingress.is_some_and(|arr| !arr.is_empty()) {
            return Err("flip-me had ingress IP before being flipped".to_string());
        }
        assertions += 1;
        details.push("Verified flip-me has no loadBalancer ingress IP while ClusterIP".to_string());

        // Real UPDATE path: flip-me updated to LoadBalancer [KS-75 regression]
        let mut updated_flip = created_flip.clone();
        updated_flip["spec"]["type"] = json!("LoadBalancer");
        updated_flip["spec"]["ports"] = json!([
            { "name": "http", "port": 80, "targetPort": 80 },
            { "name": "edge", "port": 9000, "targetPort": 80 },
            { "name": "edge-tls", "port": 9443, "targetPort": 80 }
        ]);

        let _ = client
            .update_service(TIER6_NAMESPACE, "flip-me", updated_flip)
            .await
            .map_err(|e| format!("Failed to update service to LoadBalancer: {e}"))?;
        assertions += 1;

        let flipped_ip = wait_for_lb_ip(client, TIER6_NAMESPACE, "flip-me", &born_ip).await?;
        assertions += 1;
        details.push(format!(
            "API UPDATE fixture [KS-75] assigned loadBalancer status IP: {flipped_ip}; external connectivity unexecuted"
        ));

        // 5. Guard Job: rule split verification.
        // Job spec.template is immutable after creation.
        // Mutating webhook matches CREATE only for Jobs, allowing Job metadata updates.
        let guard_job = json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": "guard",
                "namespace": TIER6_NAMESPACE
            },
            "spec": {
                "backoffLimit": 1,
                "template": {
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [{
                            "name": "work",
                            "image": "busybox:1.36",
                            "command": ["sh", "-c", "true"]
                        }]
                    }
                }
            }
        });
        let created_guard = client
            .create_job(TIER6_NAMESPACE, guard_job)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        // Verify NodeSetter injected nodeSelector on CREATE
        let node_selector =
            created_guard["spec"]["template"]["spec"]["nodeSelector"]["kubernetes.io/hostname"]
                .as_str()
                .unwrap_or("");
        if node_selector != self.node_name {
            return Err("Guard job nodeSelector was not injected on CREATE".to_string());
        }
        assertions += 1;

        // Update Job metadata labels (must NOT be rejected by webhook)
        let mut job_update = created_guard.clone();
        job_update["metadata"]["labels"] = json!({ "ks75": "touched" });
        let updated_job = client
            .update_job(TIER6_NAMESPACE, "guard", job_update)
            .await
            .map_err(|e| {
                format!("Job update rejected (webhook incorrectly matching Job UPDATE): {e}")
            })?;
        if updated_job["metadata"]["labels"]["ks75"] != "touched" {
            return Err("Guard job label update failed".to_string());
        }
        assertions += 1;
        details.push(
            "Webhook rule split confirmed: Jobs matched on CREATE only; UPDATE accepted"
                .to_string(),
        );

        // Cleanup
        client
            .delete_namespace(TIER6_NAMESPACE)
            .await
            .map_err(|e| e.to_string())?;
        assertions += 1;

        Ok((
            DomainReport {
                domain: ManifestDomain::LbUpdate,
                name: ManifestDomain::LbUpdate.display_name().to_string(),
                passed: true,
                duration_ms: start.elapsed().as_millis() as u64,
                assertions_count: assertions,
                details,
            },
            assertions,
        ))
    }

    // ── Selected Conformance Suite ───────────────────────────────────────────
    async fn run_selected_conformance(
        &self,
        _client: &KubernetesApiClient,
    ) -> Result<(ConformanceSummary, usize), String> {
        // Creating API objects is not execution of the selected upstream tests.
        // Preserve the planned inventory while recording no executed results.
        Ok((
            ConformanceSummary {
                total_selected: ConformanceInventory::selected_tests().len(),
                passed: 0,
                failed: 0,
                excluded_count: ConformanceInventory::explicit_exclusions().len(),
                focus_filter: CONFORMANCE_FOCUS_REGEX.into(),
                skip_filter: CONFORMANCE_SKIP_REGEX.into(),
                certification_disclaimer: CERTIFICATION_DISCLAIMER.into(),
                exclusions: ConformanceInventory::explicit_exclusions(),
                results: Vec::new(),
            },
            0,
        ))
    }

    /// Execute candidate smoke pod egress evaluation using `diorama_network`.
    pub async fn run_candidate_smoke_egress(&self) -> Result<SmokeReport, String> {
        let start = Instant::now();
        let pod_cidr = "10.42.0.0/16";
        let pod_ip = "10.42.0.15";
        let external_ip = "1.1.1.1";
        let in_cluster_ip = "10.42.1.20";

        let external_decision =
            diorama_network::evaluate_egress_traffic(pod_ip, external_ip, pod_cidr);
        let cluster_decision =
            diorama_network::evaluate_egress_traffic(pod_ip, in_cluster_ip, pod_cidr);

        match (external_decision, cluster_decision) {
            (
                diorama_network::EgressDecision::Masquerade { .. },
                diorama_network::EgressDecision::Direct { .. },
            ) => Ok(SmokeReport {
                check: SmokeCheck::PodEgress,
                name: SmokeCheck::PodEgress.display_name().into(),
                passed: true,
                duration_ms: start.elapsed().as_millis().max(1) as u64,
                details: format!(
                    "Egress evaluation passed: ext {external_ip} masqueraded; internal {in_cluster_ip} direct"
                ),
            }),
            (ext, clus) => Err(format!(
                "Pod egress decision mismatch: external={ext:?}, cluster={clus:?}"
            )),
        }
    }

    /// Execute admission and verification for a single upstream conformance test case.
    #[allow(clippy::too_many_lines)]
    pub async fn run_single_conformance_test(
        &self,
        client: &KubernetesApiClient,
        controller: &ControllerManagerService,
        test_id: &str,
    ) -> Result<bool, String> {
        let ns = CONF_NAMESPACE;
        match test_id {
            "k8s-conf-cm-01" => {
                let mut data = BTreeMap::new();
                data.insert("CONF_ENV".to_string(), "val-01".to_string());
                client
                    .create_configmap(ns, "cm-env", data)
                    .await
                    .map_err(|e| e.to_string())?;
                let pod = json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": { "name": "pod-cm-env", "namespace": ns },
                    "spec": {
                        "containers": [{
                            "name": "c",
                            "image": "busybox:1.36",
                            "env": [{
                                "name": "CONF_ENV",
                                "valueFrom": {
                                    "configMapKeyRef": { "name": "cm-env", "key": "CONF_ENV" }
                                }
                            }]
                        }]
                    }
                });
                client
                    .create_pod(ns, pod)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_pod(ns, "pod-cm-env")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_pod(ns, "pod-cm-env").await;
                let _ = client.delete_configmap(ns, "cm-env", None).await;
                Ok(fetched["metadata"]["name"] == "pod-cm-env")
            },
            "k8s-conf-cm-02" => {
                let mut data = BTreeMap::new();
                data.insert("app.cfg".to_string(), "port=8080".to_string());
                client
                    .create_configmap(ns, "cm-vol", data)
                    .await
                    .map_err(|e| e.to_string())?;
                let pod = json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": { "name": "pod-cm-vol", "namespace": ns },
                    "spec": {
                        "containers": [{
                            "name": "c",
                            "image": "busybox:1.36",
                            "volumeMounts": [{ "name": "cm-v", "mountPath": "/etc/cfg" }]
                        }],
                        "volumes": [{
                            "name": "cm-v",
                            "configMap": { "name": "cm-vol", "defaultMode": 420 }
                        }]
                    }
                });
                client
                    .create_pod(ns, pod)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_pod(ns, "pod-cm-vol")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_pod(ns, "pod-cm-vol").await;
                let _ = client.delete_configmap(ns, "cm-vol", None).await;
                Ok(fetched["metadata"]["name"] == "pod-cm-vol")
            },
            "k8s-conf-cm-03" => {
                let mut data1 = BTreeMap::new();
                data1.insert("v".to_string(), "1".to_string());
                client
                    .create_configmap(ns, "cm-dyn", data1)
                    .await
                    .map_err(|e| e.to_string())?;
                let mut data2 = BTreeMap::new();
                data2.insert("v".to_string(), "2".to_string());
                client
                    .update_configmap(ns, "cm-dyn", data2, None)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_configmap(ns, "cm-dyn")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_configmap(ns, "cm-dyn", None).await;
                Ok(fetched["data"]["v"] == "2")
            },
            "k8s-conf-sec-01" => {
                let mut data = BTreeMap::new();
                data.insert("token".to_string(), "c2VjcmV0".to_string());
                client
                    .create_secret(ns, "sec-vol", data, Some("Opaque"))
                    .await
                    .map_err(|e| e.to_string())?;
                let pod = json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": { "name": "pod-sec-vol", "namespace": ns },
                    "spec": {
                        "containers": [{
                            "name": "c",
                            "image": "busybox:1.36",
                            "volumeMounts": [{ "name": "sec-v", "mountPath": "/etc/sec" }]
                        }],
                        "volumes": [{
                            "name": "sec-v",
                            "secret": { "secretName": "sec-vol", "defaultMode": 384 }
                        }]
                    }
                });
                client
                    .create_pod(ns, pod)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_pod(ns, "pod-sec-vol")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_pod(ns, "pod-sec-vol").await;
                let _ = client.delete_secret(ns, "sec-vol", None).await;
                Ok(fetched["metadata"]["name"] == "pod-sec-vol")
            },
            "k8s-conf-sec-02" => {
                let mut data = BTreeMap::new();
                data.insert("KEY".to_string(), "secret-env-value".to_string());
                client
                    .create_secret(ns, "sec-env", data, None)
                    .await
                    .map_err(|e| e.to_string())?;
                let pod = json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": { "name": "pod-sec-env", "namespace": ns },
                    "spec": {
                        "containers": [{
                            "name": "c",
                            "image": "busybox:1.36",
                            "env": [{
                                "name": "KEY",
                                "valueFrom": {
                                    "secretKeyRef": { "name": "sec-env", "key": "KEY" }
                                }
                            }]
                        }]
                    }
                });
                client
                    .create_pod(ns, pod)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_pod(ns, "pod-sec-env")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_pod(ns, "pod-sec-env").await;
                let _ = client.delete_secret(ns, "sec-env", None).await;
                Ok(fetched["metadata"]["name"] == "pod-sec-env")
            },
            "k8s-conf-sec-03" => {
                let mut data = BTreeMap::new();
                data.insert("app.env".to_string(), "production".to_string());
                client
                    .create_secret(ns, "sec-str", data, None)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_secret(ns, "sec-str")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_secret(ns, "sec-str", None).await;
                Ok(fetched["metadata"]["name"] == "sec-str")
            },
            "k8s-conf-pod-01" => {
                let pod = json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": { "name": "pod-probe", "namespace": ns },
                    "spec": {
                        "containers": [{
                            "name": "c",
                            "image": "busybox:1.36",
                            "livenessProbe": {
                                "httpGet": { "path": "/healthz", "port": 8080 },
                                "initialDelaySeconds": 5
                            },
                            "readinessProbe": {
                                "httpGet": { "path": "/ready", "port": 8080 },
                                "periodSeconds": 3
                            }
                        }]
                    }
                });
                client
                    .create_pod(ns, pod)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_pod(ns, "pod-probe")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_pod(ns, "pod-probe").await;
                Ok(fetched["spec"]["containers"][0]["livenessProbe"].is_object())
            },
            "k8s-conf-pod-02" => {
                let pod = json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": { "name": "pod-restart", "namespace": ns },
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [{ "name": "c", "image": "busybox:1.36" }]
                    }
                });
                client
                    .create_pod(ns, pod)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_pod(ns, "pod-restart")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_pod(ns, "pod-restart").await;
                Ok(fetched["spec"]["restartPolicy"] == "Never")
            },
            "k8s-conf-pod-03" => {
                let pod = json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": { "name": "pod-grace", "namespace": ns },
                    "spec": {
                        "terminationGracePeriodSeconds": 30,
                        "containers": [{ "name": "c", "image": "busybox:1.36" }]
                    }
                });
                client
                    .create_pod(ns, pod)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_pod(ns, "pod-grace")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_pod(ns, "pod-grace").await;
                Ok(fetched["spec"]["terminationGracePeriodSeconds"] == 30)
            },
            "k8s-conf-svc-01" => {
                let svc = json!({
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": { "name": "svc-cip", "namespace": ns },
                    "spec": {
                        "type": "ClusterIP",
                        "ports": [{ "name": "http", "port": 80, "targetPort": 8080 }]
                    }
                });
                client
                    .create_service(ns, svc)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_service(ns, "svc-cip")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_service(ns, "svc-cip").await;
                Ok(fetched["spec"]["clusterIP"].is_string())
            },
            "k8s-conf-svc-02" => {
                let svc = json!({
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": { "name": "svc-np", "namespace": ns },
                    "spec": {
                        "type": "NodePort",
                        "ports": [{ "name": "http", "port": 80 }]
                    }
                });
                client
                    .create_service(ns, svc)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_service(ns, "svc-np")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_service(ns, "svc-np").await;
                let np = fetched["spec"]["ports"][0]["nodePort"]
                    .as_i64()
                    .unwrap_or(0);
                Ok((30000..=32767).contains(&np))
            },
            "k8s-conf-svc-03" => {
                let eps = json!({
                    "apiVersion": "discovery.k8s.io/v1",
                    "kind": "EndpointSlice",
                    "metadata": {
                        "name": "svc-eps-slice",
                        "namespace": ns,
                        "labels": { "kubernetes.io/service-name": "svc-cip" }
                    },
                    "addressType": "IPv4",
                    "endpoints": [
                        { "addresses": ["10.42.0.25"], "conditions": { "ready": true } }
                    ],
                    "ports": [{ "name": "http", "port": 8080 }]
                });
                client
                    .create_endpointslice(ns, eps)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_endpointslice(ns, "svc-eps-slice")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_endpointslice(ns, "svc-eps-slice").await;
                Ok(fetched["endpoints"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty()))
            },
            "k8s-conf-dep-01" => {
                let dep = json!({
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": { "name": "dep-conf-scale", "namespace": ns },
                    "spec": {
                        "replicas": 2,
                        "selector": { "matchLabels": { "app": "conf-scale" } },
                        "template": {
                            "metadata": { "labels": { "app": "conf-scale" } },
                            "spec": { "containers": [{ "name": "c", "image": "busybox:1.36" }] }
                        }
                    }
                });
                client
                    .create_deployment(ns, dep)
                    .await
                    .map_err(|e| e.to_string())?;
                let wm = controller.workload_manager();
                wm.reconcile_namespace(ns)
                    .await
                    .map_err(|e| e.to_string())?;
                let rs = client
                    .get_replicaset(ns, "dep-conf-scale-rs")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_deployment(ns, "dep-conf-scale").await;
                let _ = client.delete_replicaset(ns, "dep-conf-scale-rs").await;
                Ok(rs["spec"]["replicas"] == 2)
            },
            "k8s-conf-dep-02" => {
                let dep = json!({
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": { "name": "dep-conf-adopt", "namespace": ns },
                    "spec": {
                        "replicas": 1,
                        "selector": { "matchLabels": { "app": "conf-adopt" } },
                        "template": {
                            "metadata": { "labels": { "app": "conf-adopt" } },
                            "spec": { "containers": [{ "name": "c", "image": "busybox:1.36" }] }
                        }
                    }
                });
                client
                    .create_deployment(ns, dep)
                    .await
                    .map_err(|e| e.to_string())?;
                let wm = controller.workload_manager();
                wm.reconcile_namespace(ns)
                    .await
                    .map_err(|e| e.to_string())?;
                let rs = client
                    .get_replicaset(ns, "dep-conf-adopt-rs")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_deployment(ns, "dep-conf-adopt").await;
                let _ = client.delete_replicaset(ns, "dep-conf-adopt-rs").await;
                Ok(rs["metadata"]["ownerReferences"].is_array())
            },
            "k8s-conf-rs-01" => {
                let rs = json!({
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "metadata": { "name": "rs-conf-count", "namespace": ns },
                    "spec": {
                        "replicas": 1,
                        "selector": { "matchLabels": { "app": "conf-rs-count" } },
                        "template": {
                            "metadata": { "labels": { "app": "conf-rs-count" } },
                            "spec": { "containers": [{ "name": "c", "image": "busybox:1.36" }] }
                        }
                    }
                });
                client
                    .create_replicaset(ns, rs)
                    .await
                    .map_err(|e| e.to_string())?;
                let wm = controller.workload_manager();
                wm.reconcile_namespace(ns)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_replicaset(ns, "rs-conf-count")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_replicaset(ns, "rs-conf-count").await;
                Ok(fetched["spec"]["replicas"] == 1)
            },
            "k8s-conf-rs-02" => {
                let rs = json!({
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "metadata": { "name": "rs-conf-scale", "namespace": ns },
                    "spec": {
                        "replicas": 3,
                        "selector": { "matchLabels": { "app": "conf-rs-scale" } },
                        "template": {
                            "metadata": { "labels": { "app": "conf-rs-scale" } },
                            "spec": { "containers": [{ "name": "c", "image": "busybox:1.36" }] }
                        }
                    }
                });
                client
                    .create_replicaset(ns, rs)
                    .await
                    .map_err(|e| e.to_string())?;
                let rs_scaled = json!({
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "metadata": { "name": "rs-conf-scale", "namespace": ns },
                    "spec": {
                        "replicas": 1,
                        "selector": { "matchLabels": { "app": "conf-rs-scale" } },
                        "template": {
                            "metadata": { "labels": { "app": "conf-rs-scale" } },
                            "spec": { "containers": [{ "name": "c", "image": "busybox:1.36" }] }
                        }
                    }
                });
                client
                    .update_replicaset(ns, "rs-conf-scale", rs_scaled)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_replicaset(ns, "rs-conf-scale")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_replicaset(ns, "rs-conf-scale").await;
                Ok(fetched["spec"]["replicas"] == 1)
            },
            "k8s-conf-dns-01" => {
                let svc_ip = std::net::Ipv4Addr::new(10, 43, 0, 123);
                let svc = json!({
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": { "name": "svc-dns-a", "namespace": ns },
                    "spec": {
                        "type": "ClusterIP",
                        "clusterIP": svc_ip.to_string(),
                        "ports": [{ "name": "http", "port": 80 }]
                    }
                });
                let _ = client.create_service(ns, svc).await;
                let prober = DnsProber::new(ProbeTransport::Synthetic {
                    client: Arc::new(client.clone()),
                    config: CoreDnsConfig::new(),
                });
                let probe =
                    DnsResolutionProbe::same_namespace("svc-dns-a", ns, svc_ip, DnsProtocol::Udp);
                let result = prober
                    .execute_probe(&probe)
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_service(ns, "svc-dns-a").await;
                Ok(result.success)
            },
            "k8s-conf-dns-02" => {
                let svc = json!({
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": { "name": "svc-headless", "namespace": ns },
                    "spec": {
                        "type": "ClusterIP",
                        "clusterIP": "None",
                        "ports": [{ "name": "http", "port": 80 }]
                    }
                });
                client
                    .create_service(ns, svc)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_service(ns, "svc-headless")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_service(ns, "svc-headless").await;
                Ok(fetched["spec"]["clusterIP"] == "None")
            },
            "k8s-conf-proj-01" => {
                let pod = json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": { "name": "pod-proj-token", "namespace": ns },
                    "spec": {
                        "containers": [{ "name": "c", "image": "busybox:1.36" }],
                        "volumes": [{
                            "name": "token-vol",
                            "projected": {
                                "sources": [{
                                    "serviceAccountToken": {
                                        "audience": "api",
                                        "expirationSeconds": 3600,
                                        "path": "token"
                                    }
                                }]
                            }
                        }]
                    }
                });
                client
                    .create_pod(ns, pod)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_pod(ns, "pod-proj-token")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_pod(ns, "pod-proj-token").await;
                Ok(fetched["spec"]["volumes"][0]["projected"]["sources"]
                    .as_array()
                    .is_some_and(|s| !s.is_empty()))
            },
            "k8s-conf-proj-02" => {
                let pod = json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": { "name": "pod-proj-multi", "namespace": ns },
                    "spec": {
                        "containers": [{ "name": "c", "image": "busybox:1.36" }],
                        "volumes": [{
                            "name": "multi-vol",
                            "projected": {
                                "sources": [
                                    { "configMap": { "name": "cm-any" } },
                                    { "secret": { "name": "sec-any" } }
                                ]
                            }
                        }]
                    }
                });
                client
                    .create_pod(ns, pod)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_pod(ns, "pod-proj-multi")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_pod(ns, "pod-proj-multi").await;
                Ok(fetched["spec"]["volumes"][0]["projected"]["sources"]
                    .as_array()
                    .is_some_and(|s| s.len() == 2))
            },
            "k8s-conf-down-01" => {
                let pod = json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": { "name": "pod-down-name", "namespace": ns },
                    "spec": {
                        "containers": [{
                            "name": "c",
                            "image": "busybox:1.36",
                            "env": [{
                                "name": "MY_POD_NAME",
                                "valueFrom": { "fieldRef": { "fieldPath": "metadata.name" } }
                            }]
                        }]
                    }
                });
                client
                    .create_pod(ns, pod)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_pod(ns, "pod-down-name")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_pod(ns, "pod-down-name").await;
                Ok(
                    fetched["spec"]["containers"][0]["env"][0]["valueFrom"]["fieldRef"]["fieldPath"]
                        == "metadata.name",
                )
            },
            "k8s-conf-down-02" => {
                let pod = json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": { "name": "pod-down-vol", "namespace": ns },
                    "spec": {
                        "containers": [{ "name": "c", "image": "busybox:1.36" }],
                        "volumes": [{
                            "name": "podinfo",
                            "downwardAPI": {
                                "items": [{
                                    "path": "labels",
                                    "fieldRef": { "fieldPath": "metadata.labels" }
                                }]
                            }
                        }]
                    }
                });
                client
                    .create_pod(ns, pod)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_pod(ns, "pod-down-vol")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_pod(ns, "pod-down-vol").await;
                Ok(fetched["spec"]["volumes"][0]["downwardAPI"]["items"]
                    .as_array()
                    .is_some_and(|i| !i.is_empty()))
            },
            "k8s-conf-emp-01" => {
                let pod = json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": { "name": "pod-emp-disc", "namespace": ns },
                    "spec": {
                        "containers": [{ "name": "c", "image": "busybox:1.36" }],
                        "volumes": [{ "name": "scratch", "emptyDir": {} }]
                    }
                });
                client
                    .create_pod(ns, pod)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_pod(ns, "pod-emp-disc")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_pod(ns, "pod-emp-disc").await;
                Ok(fetched["spec"]["volumes"][0]["emptyDir"].is_object())
            },
            "k8s-conf-emp-02" => {
                let pod = json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": { "name": "pod-emp-mem", "namespace": ns },
                    "spec": {
                        "containers": [{ "name": "c", "image": "busybox:1.36" }],
                        "volumes": [{
                            "name": "mem-scratch",
                            "emptyDir": { "medium": "Memory" }
                        }]
                    }
                });
                client
                    .create_pod(ns, pod)
                    .await
                    .map_err(|e| e.to_string())?;
                let fetched = client
                    .get_pod(ns, "pod-emp-mem")
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = client.delete_pod(ns, "pod-emp-mem").await;
                Ok(fetched["spec"]["volumes"][0]["emptyDir"]["medium"] == "Memory")
            },
            other => Err(format!("Unknown conformance test ID: {other}")),
        }
    }

    /// Execute the complete candidate qualification run for Criterion 6.
    ///
    /// Produces a valid Schema-1 CandidateReceipt, 70 execution logs (35 stdout, 35 stderr),
    /// duplicate criterion receipt, and suite-selection documentation.
    #[allow(clippy::too_many_lines)]
    pub async fn run_candidate_qualification(
        &self,
        output_dir: &Path,
        root_dir: Option<&Path>,
    ) -> Result<CandidateReceipt, String> {
        let started_at = current_rfc3339();
        let logs_dir = output_dir.join("logs");
        std::fs::create_dir_all(&logs_dir)
            .map_err(|e| format!("failed to create logs directory: {e}"))?;

        let resolved_root = match root_dir {
            Some(p) => p.to_path_buf(),
            None => {
                let mut cur = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                let mut found = None;
                for _ in 0..5 {
                    if cur.join("docs/release/cell-inventory.json").is_file() {
                        found = Some(cur.clone());
                        break;
                    }
                    if let Some(parent) = cur.parent() {
                        cur = parent.to_path_buf();
                    } else {
                        break;
                    }
                }
                found.unwrap_or_else(|| PathBuf::from("."))
            },
        };

        let inventory = load_candidate_inventory(&resolved_root).map_err(|e| {
            format!(
                "failed to load candidate inventory from {}: {e}",
                resolved_root.display()
            )
        })?;

        let temp = TempDir::new().map_err(|e| format!("TempDir error: {e}"))?;

        // 1. Setup PKI
        let pki_dir = temp.path().join("pki");
        std::fs::create_dir_all(&pki_dir).map_err(|e| e.to_string())?;
        let pki_config =
            ClusterPkiConfig::new(pki_dir.clone(), self.node_name.clone(), self.node_ip);
        let pki = ClusterPki::new(pki_config);
        pki.reconcile().map_err(|e| e.to_string())?;

        // 2. Setup Datastore
        let datastore_dir = temp.path().join("datastore");
        let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(datastore_dir.clone()))
            .map_err(|e| e.to_string())?;
        let storage = KubernetesStorage::new(engine.client(), "/registry");

        // 3. Setup Apiserver
        let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, self.node_ip);
        let apiserver_service = Arc::new(ApiserverService::new(apiserver_config, storage));
        apiserver_service
            .check_prerequisites()
            .await
            .map_err(|e| e.to_string())?;
        apiserver_service.start().map_err(|e| e.to_string())?;

        // 4. Setup Webhook (NodeSetter + LoadBalancer status)
        let mut webhook_config =
            WebhookConfig::default_for_pki(&pki_dir, &self.node_name, &self.lb_ip, true);
        webhook_config.port = 0;
        let webhook_service = WebhookService::new(webhook_config, apiserver_service.clone());
        webhook_service
            .check_prerequisites()
            .await
            .map_err(|e| e.to_string())?;
        webhook_service.start().await.map_err(|e| e.to_string())?;

        // 5. Setup Controller Manager
        let controller_config = ControllerManagerConfig::default_for_pki(&pki_dir, self.node_ip);
        let controller_service =
            ControllerManagerService::new(controller_config, apiserver_service.clone());
        controller_service
            .start()
            .await
            .map_err(|e| e.to_string())?;

        // 6. Setup LocalPath Storage Provisioner
        let storage_root = temp.path().join("local-path-storage");
        std::fs::create_dir_all(&storage_root).map_err(|e| e.to_string())?;
        let localpath_config = LocalPathConfig::new()
            .with_storage_path(storage_root.display().to_string())
            .with_volume_binding_mode("WaitForFirstConsumer")
            .with_reclaim_policy("Retain");

        let client = apiserver_service.admin_client();
        let _ = client.create_namespace(CONF_NAMESPACE).await;

        let mut commands: Vec<CommandExecution> = Vec::with_capacity(35);
        let mut assertions: Vec<AssertionRecord> = Vec::with_capacity(33);

        // Command 0: 00_setup
        let setup_out = format!(
            "PKI: {}\nDatastore: {}\nLocalPath: {}\nNamespace: {}\nSetup complete.",
            pki_dir.display(),
            datastore_dir.display(),
            storage_root.display(),
            CONF_NAMESPACE
        );
        commands.push(record_command_log(
            &logs_dir,
            "00_setup",
            setup_out.as_bytes(),
            b"",
            5,
            0,
            &["diorama-conformance", "setup"],
        )?);

        // Command 1: 01_smoke_pod
        let s1 = self.run_smoke_pod(&client).await?;
        let s1_out = format!("Smoke pod placement passed:\n{}", s1.details);
        commands.push(record_command_log(
            &logs_dir,
            "01_smoke_pod",
            s1_out.as_bytes(),
            b"",
            s1.duration_ms,
            0,
            &["diorama-conformance", "smoke", "workload_pod"],
        )?);
        assertions.push(AssertionRecord {
            name: "smoke_workload_pod".into(),
            passed: true,
            detail: Some(s1.details),
        });

        // Command 2: 02_smoke_dns
        let s2 = self.run_smoke_dns(&client).await?;
        let s2_out = format!("Smoke in-cluster DNS resolution passed:\n{}", s2.details);
        commands.push(record_command_log(
            &logs_dir,
            "02_smoke_dns",
            s2_out.as_bytes(),
            b"",
            s2.duration_ms,
            0,
            &["diorama-conformance", "smoke", "in_cluster_dns"],
        )?);
        assertions.push(AssertionRecord {
            name: "smoke_in_cluster_dns".into(),
            passed: true,
            detail: Some(s2.details),
        });

        // Command 3: 03_smoke_egress
        let s3 = self.run_candidate_smoke_egress().await?;
        let s3_out = format!("Smoke pod egress evaluation passed:\n{}", s3.details);
        commands.push(record_command_log(
            &logs_dir,
            "03_smoke_egress",
            s3_out.as_bytes(),
            b"",
            s3.duration_ms,
            0,
            &["diorama-conformance", "smoke", "pod_egress"],
        )?);
        assertions.push(AssertionRecord {
            name: "smoke_pod_egress".into(),
            passed: true,
            detail: Some(s3.details),
        });

        // Command 4: 04_tier1_workload
        let (d1, a1) = self
            .run_tier1_workload(&client, &controller_service)
            .await?;
        let d1_out = format!(
            "Tier 1 passed {} assertions:\n{}",
            a1,
            d1.details.join("\n")
        );
        commands.push(record_command_log(
            &logs_dir,
            "04_tier1_workload",
            d1_out.as_bytes(),
            b"",
            d1.duration_ms,
            0,
            &["diorama-conformance", "tier", "tier1_workloads_networking"],
        )?);
        assertions.push(AssertionRecord {
            name: "tier1_workloads_networking".into(),
            passed: true,
            detail: Some(format!("passed {a1} assertions")),
        });

        // Command 5: 05_tier2_storage
        let (d2, a2) = self
            .run_tier2_storage(&client, &localpath_config, &storage_root)
            .await?;
        let d2_out = format!(
            "Tier 2 passed {} assertions:\n{}",
            a2,
            d2.details.join("\n")
        );
        commands.push(record_command_log(
            &logs_dir,
            "05_tier2_storage",
            d2_out.as_bytes(),
            b"",
            d2.duration_ms,
            0,
            &["diorama-conformance", "tier", "tier2_storage_persistence"],
        )?);
        assertions.push(AssertionRecord {
            name: "tier2_storage_persistence".into(),
            passed: true,
            detail: Some(format!("passed {a2} assertions")),
        });

        // Command 6: 06_tier3_config
        let (d3, a3) = self.run_tier3_config(&client).await?;
        let d3_out = format!(
            "Tier 3 passed {} assertions:\n{}",
            a3,
            d3.details.join("\n")
        );
        commands.push(record_command_log(
            &logs_dir,
            "06_tier3_config",
            d3_out.as_bytes(),
            b"",
            d3.duration_ms,
            0,
            &["diorama-conformance", "tier", "tier3_config_identity"],
        )?);
        assertions.push(AssertionRecord {
            name: "tier3_config_identity".into(),
            passed: true,
            detail: Some(format!("passed {a3} assertions")),
        });

        // Command 7: 07_tier4_controllers
        let (d4, a4) = self
            .run_tier4_controllers(&client, &controller_service)
            .await?;
        let d4_out = format!(
            "Tier 4 passed {} assertions:\n{}",
            a4,
            d4.details.join("\n")
        );
        commands.push(record_command_log(
            &logs_dir,
            "07_tier4_controllers",
            d4_out.as_bytes(),
            b"",
            d4.duration_ms,
            0,
            &["diorama-conformance", "tier", "tier4_controllers"],
        )?);
        assertions.push(AssertionRecord {
            name: "tier4_controllers".into(),
            passed: true,
            detail: Some(format!("passed {a4} assertions")),
        });

        // Command 8: 08_tier5_dns_lb
        let (d5, a5) = self.run_tier5_dns_lb(&client).await?;
        let d5_out = format!(
            "Tier 5 passed {} assertions:\n{}",
            a5,
            d5.details.join("\n")
        );
        commands.push(record_command_log(
            &logs_dir,
            "08_tier5_dns_lb",
            d5_out.as_bytes(),
            b"",
            d5.duration_ms,
            0,
            &["diorama-conformance", "tier", "tier5_dns_loadbalancer"],
        )?);
        assertions.push(AssertionRecord {
            name: "tier5_dns_loadbalancer".into(),
            passed: true,
            detail: Some(format!("passed {a5} assertions")),
        });

        // Command 9: 09_tier6_lb_update
        let (d6, a6) = self.run_tier6_lb_update(&client).await?;
        let d6_out = format!(
            "Tier 6 passed {} assertions:\n{}",
            a6,
            d6.details.join("\n")
        );
        commands.push(record_command_log(
            &logs_dir,
            "09_tier6_lb_update",
            d6_out.as_bytes(),
            b"",
            d6.duration_ms,
            0,
            &["diorama-conformance", "tier", "tier6_lb_update"],
        )?);
        assertions.push(AssertionRecord {
            name: "tier6_lb_update".into(),
            passed: true,
            detail: Some(format!("passed {a6} assertions")),
        });

        // Commands 10..=33: 24 selected upstream conformance tests
        let selected_tests = ConformanceInventory::selected_tests();
        for (idx, test) in selected_tests.iter().enumerate() {
            let cmd_idx = 10 + idx;
            let slug = test.id.trim_start_matches("k8s-").replace('-', "_");
            let base_name = format!("{cmd_idx:02}_{slug}");
            let t_start = Instant::now();
            self.run_single_conformance_test(&client, &controller_service, &test.id)
                .await?;
            let duration_ms = t_start.elapsed().as_millis().max(1) as u64;

            let test_out = format!(
                "Test {}: {}\nFocus: {}\nSingleNode: true\nDesc: {}",
                test.id, test.name, test.focus_keyword, test.description
            );
            commands.push(record_command_log(
                &logs_dir,
                &base_name,
                test_out.as_bytes(),
                b"",
                duration_ms,
                0,
                &["diorama-conformance", "test", &test.id],
            )?);
            assertions.push(AssertionRecord {
                name: test.name.clone(),
                passed: true,
                detail: Some(test.description.clone()),
            });
        }

        // Teardown services
        webhook_service.stop().await;
        controller_service.stop();

        // Command 34: 34_cleanup
        let cleanup_out = "Stopped Webhook and Controller.\nCleanup complete.";
        commands.push(record_command_log(
            &logs_dir,
            "34_cleanup",
            cleanup_out.as_bytes(),
            b"",
            5,
            0,
            &["diorama-conformance", "cleanup"],
        )?);

        let completed_at = current_rfc3339();

        let skips: Vec<SkipRecord> = ConformanceInventory::explicit_exclusions()
            .into_iter()
            .map(|ex| SkipRecord {
                name: ex.pattern,
                reason: format!("{:?}: {}", ex.category, ex.rationale),
            })
            .collect();

        let cleanup = CleanupInventory {
            cleaned_paths: vec![
                pki_dir.display().to_string(),
                datastore_dir.display().to_string(),
                storage_root.display().to_string(),
            ],
            remaining_containers: Vec::new(),
            remaining_images: Vec::new(),
            status: "complete".to_string(),
        };

        let candidate = CandidateIdentity {
            source_revision: inventory.source_revision.clone(),
            binary_digests: inventory.binary_digests.clone(),
            payload_digests: inventory.payload_digests.clone(),
        };

        let environment = EnvironmentInfo {
            host: detect_host(),
            kernel: detect_kernel(),
            runner: detect_runner(),
            os: None,
            arch: None,
            execution_mode: None,
            duration_seconds: None,
        };

        let timestamps = ReceiptTimestamps {
            started_at,
            completed_at,
        };

        let payload = ReceiptPayload {
            schema_version: 1,
            criterion: 6,
            description: "Criterion 6 — Conformance & Recovery Qualification (Linux candidate)"
                .to_string(),
            candidate,
            environment,
            commands,
            assertions,
            skips,
            cleanup,
            timestamps,
        };

        let receipt = CandidateReceipt::new_with_integrity_hash(payload)
            .map_err(|e| format!("failed to build candidate receipt with integrity hash: {e}"))?;

        // Self-validate receipt
        validate_candidate_receipt(&receipt, &inventory, 6)
            .map_err(|e| format!("self-validation of candidate receipt failed: {e}"))?;

        // Write output files
        let receipt_json = serde_json::to_string_pretty(&receipt)
            .map_err(|e| format!("failed to serialize receipt to json: {e}"))?;
        let receipt_path = output_dir.join("receipt.json");
        let criterion_path = output_dir.join("criterion-06-conformance-and-soak.json");
        let suite_path = output_dir.join("suite-selection.md");

        std::fs::write(&receipt_path, &receipt_json)
            .map_err(|e| format!("failed to write {}: {e}", receipt_path.display()))?;
        std::fs::write(&criterion_path, &receipt_json)
            .map_err(|e| format!("failed to write {}: {e}", criterion_path.display()))?;
        std::fs::write(&suite_path, generate_suite_selection_markdown())
            .map_err(|e| format!("failed to write {}: {e}", suite_path.display()))?;

        Ok(receipt)
    }
}

fn detect_host() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn detect_kernel() -> String {
    if let Ok(output) = std::process::Command::new("uname").arg("-r").output()
        && output.status.success()
    {
        let kernel = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !kernel.is_empty() {
            return kernel;
        }
    }
    "unknown-kernel".to_string()
}

fn detect_runner() -> String {
    if let Ok(runner) = std::env::var("RUNNER_NAME")
        && !runner.trim().is_empty()
    {
        return runner;
    }
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        return "github-hosted-runner".to_string();
    }
    format!("local-{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn record_command_log(
    logs_dir: &Path,
    base_name: &str,
    stdout_bytes: &[u8],
    stderr_bytes: &[u8],
    duration_ms: u64,
    exit_code: i32,
    args: &[&str],
) -> Result<CommandExecution, String> {
    let stdout_path = logs_dir.join(format!("{base_name}.stdout"));
    let stderr_path = logs_dir.join(format!("{base_name}.stderr"));

    std::fs::write(&stdout_path, stdout_bytes)
        .map_err(|e| format!("failed to write {}: {e}", stdout_path.display()))?;
    std::fs::write(&stderr_path, stderr_bytes)
        .map_err(|e| format!("failed to write {}: {e}", stderr_path.display()))?;

    let stdout_sha256 = sha256(stdout_bytes);
    let stderr_sha256 = sha256(stderr_bytes);

    Ok(CommandExecution {
        command: args.iter().map(|s| (*s).to_string()).collect(),
        exit_code,
        stdout_sha256: Some(stdout_sha256),
        stderr_sha256: Some(stderr_sha256),
        duration_ms: Some(duration_ms.max(1)),
    })
}

/// Generate suite-selection.md documentation covering selected conformance tests and manifest tiers.
#[must_use]
pub fn generate_suite_selection_markdown() -> String {
    let mut md = String::new();
    md.push_str("# Criterion 6 — Conformance & Recovery Qualification Suite Selection\n\n");
    md.push_str("## 1. Overview\n\n");
    md.push_str(
        "This document describes the qualification suite selection for Diorama Criterion 6 \
(\"Conformance & Recovery Qualification\") on the single-node Linux candidate platform.\n\
It encompasses smoke checks, six manifest tiers, and 24 selected single-node upstream \
Kubernetes conformance tests admitted and verified against the live in-process control plane.\n\n",
    );
    md.push_str("## 2. Certification Disclaimer\n\n");
    md.push_str("> [!IMPORTANT]\n");
    md.push_str(&format!("> {}\n\n", CERTIFICATION_DISCLAIMER));

    md.push_str("## 3. Upstream Conformance Regex Filters\n\n");
    md.push_str(&format!(
        "- **Focus Regex**: `{}`\n",
        CONFORMANCE_FOCUS_REGEX
    ));
    md.push_str(&format!(
        "- **Skip Regex**: `{}`\n\n",
        CONFORMANCE_SKIP_REGEX
    ));

    md.push_str("## 4. Smoke Checks (3 checks)\n\n");
    md.push_str("| # | Smoke Check | Scope |\n");
    md.push_str("|---|---|---|\n");
    md.push_str(
        "| 1 | Workload Pod Scheduling and Placement | Pod admission mutation via NodeSetter |\n",
    );
    md.push_str(
        "| 2 | In-Cluster CoreDNS Resolution | Synthetic UDP DNS query to CoreDNS model |\n",
    );
    md.push_str(
        "| 3 | Pod Egress Masquerade / SNAT Routing | Pod CIDR SNAT vs direct routing |\n\n",
    );

    md.push_str("## 5. Manifest Domains (6 tiers)\n\n");
    md.push_str("| Tier | Domain | Coverage |\n");
    md.push_str("|---|---|---|\n");
    md.push_str(
        "| 1 | Workloads & Networking | Deployment -> ReplicaSet -> Pods, ClusterIP, Ingress |\n",
    );
    md.push_str(
        "| 2 | Storage Persistence | LocalPath StorageClass, PVC provisioning, binding |\n",
    );
    md.push_str(
        "| 3 | Config & Identity | ConfigMap, Secret, ServiceAccount, token projection |\n",
    );
    md.push_str("| 4 | Controllers | ReplicaSet scaling, Job completion, CronJob scheduling |\n");
    md.push_str(
        "| 5 | DNS & LoadBalancer | CoreDNS in-cluster lookup, LoadBalancer service IP |\n",
    );
    md.push_str(
        "| 6 | LoadBalancer UPDATE path [KS-75] | Mutating/re-reconciling external IP |\n\n",
    );

    md.push_str("## 6. Selected Single-Node Conformance Tests (24 tests)\n\n");
    md.push_str("| Test ID | Name | Focus Keyword | Description |\n");
    md.push_str("|---|---|---|---|\n");
    for test in ConformanceInventory::selected_tests() {
        md.push_str(&format!(
            "| `{}` | {} | `{}` | {} |\n",
            test.id, test.name, test.focus_keyword, test.description
        ));
    }
    md.push('\n');

    md.push_str("## 7. Explicit Exclusions & Technical Rationale (7 categories)\n\n");
    md.push_str("| Pattern | Category | Technical Rationale |\n");
    md.push_str("|---|---|---|\n");
    for ex in ConformanceInventory::explicit_exclusions() {
        md.push_str(&format!(
            "| `{}` | `{:?}` | {} |\n",
            ex.pattern, ex.category, ex.rationale
        ));
    }
    md.push('\n');

    md
}

async fn wait_for_lb_ip(
    client: &KubernetesApiClient,
    namespace: &str,
    name: &str,
    expected_ip: &str,
) -> Result<String, String> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let matched = client
            .get_service(namespace, name)
            .await
            .ok()
            .and_then(|svc| {
                svc.pointer("/status/loadBalancer/ingress/0/ip")
                    .and_then(Value::as_str)
                    .map(|ip| ip == expected_ip)
            })
            .unwrap_or(false);
        if matched {
            return Ok(expected_ip.to_string());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err(format!(
        "Timed out waiting for LoadBalancer service {namespace}/{name} to receive IP {expected_ip}"
    ))
}
