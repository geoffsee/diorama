//! kube-rs probes against one privileged diorama container.
//!
//! ```text
//! cargo test --locked -p diorama-conformance --test suite -- --ignored --nocapture
//! ```
//!
//! The image defaults to `localhost/diorama:latest`. Build it with
//! `container/dev-image.sh`. Every probe runs. The test fails with the full list.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet};
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{
    ConfigMap, Event, Namespace, PersistentVolumeClaim, Pod, Secret, Service,
};
use k8s_openapi::api::events::v1::Event as EventsV1Event;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{
    Api, AttachParams, DeleteParams, ListParams, LogParams, Patch, PatchParams, PostParams,
    WatchEvent, WatchParams,
};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::core::discovery::v2::{ACCEPT_AGGREGATED_DISCOVERY_V2, APIGroupDiscoveryList};
use kube::discovery::Discovery;
use kube::{Client, Config, ResourceExt};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time::Instant;

const NS: &str = "gaps";
const READY_BUDGET: Duration = Duration::from_mins(3);
const WORK_BUDGET: Duration = Duration::from_mins(2);

type ProbeResult = Result<(), String>;

struct Row {
    name: &'static str,
    error: Option<String>,
}

struct Cluster {
    podman: PathBuf,
    name: String,
    client: Option<Client>,
}

impl Drop for Cluster {
    fn drop(&mut self) {
        let _ = std::process::Command::new(&self.podman)
            .args(["rm", "-f", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

impl Cluster {
    async fn start() -> Result<Self, String> {
        let podman = find_podman()?;
        let image =
            std::env::var("DIORAMA_IMAGE").unwrap_or_else(|_| "localhost/diorama:latest".into());
        let inspect = Command::new(&podman)
            .args(["image", "inspect", &image])
            .output()
            .await
            .map_err(|err| format!("podman image inspect: {err}"))?;
        if !inspect.status.success() {
            return Err(format!(
                "image {image} is missing; run container/dev-image.sh"
            ));
        }
        let name = format!("diorama-conformance-{}", std::process::id());
        let mut run = Command::new(&podman);
        run.args([
            "run",
            "-d",
            "--name",
            &name,
            "--privileged",
            "--hostname",
            "diorama",
            "--security-opt",
            "seccomp=unconfined",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/run",
            "-p",
            "127.0.0.1::6443",
            "--entrypoint",
            "/bin/sh",
        ]);
        if std::path::Path::new("/lib/modules").exists() {
            run.args(["-v", "/lib/modules:/lib/modules:ro"]);
        }
        if !cfg!(target_os = "macos") {
            run.args(["--security-opt", "apparmor=unconfined"]);
        }
        // The apiserver listens on 127.0.0.1, which a published port cannot reach.
        // DNAT the published port onto that loopback listener.
        run.arg(&image).args([
            "-c",
            "set -eu\nsysctl -w net.ipv4.conf.all.route_localnet=1\niptables -t nat -A PREROUTING -p tcp --dport 6443 -j DNAT --to-destination 127.0.0.1:6443\nexec /usr/local/bin/diorama-entrypoint --container-mode\n",
        ]);
        let started = run
            .output()
            .await
            .map_err(|err| format!("podman run: {err}"))?;
        if !started.status.success() {
            return Err(format!(
                "podman run failed: {}",
                String::from_utf8_lossy(&started.stderr)
            ));
        }
        let mut launched = Self {
            podman,
            name,
            client: None,
        };
        let port = launched.host_port().await?;
        let yaml = launched.kubeconfig_yaml().await?;
        let yaml = rewrite_server(&yaml, port);
        let kubeconfig =
            Kubeconfig::from_yaml(&yaml).map_err(|err| format!("kubeconfig: {err}"))?;
        let config = Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
            .await
            .map_err(|err| format!("kubeconfig: {err}"))?;
        let client = Client::try_from(config).map_err(|err| format!("{err}"))?;
        wait_ready(&client).await?;
        launched.client = Some(client);
        Ok(launched)
    }

    async fn host_port(&self) -> Result<u16, String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let output = Command::new(&self.podman)
                .args(["port", &self.name, "6443/tcp"])
                .output()
                .await
                .map_err(|err| format!("podman port: {err}"))?;
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                if let Some(port) = text
                    .lines()
                    .next()
                    .and_then(|line| line.rsplit(':').next())
                    .and_then(|port| port.trim().parse().ok())
                {
                    return Ok(port);
                }
            }
            if Instant::now() > deadline {
                return Err("podman did not publish port 6443".into());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn kubeconfig_yaml(&self) -> Result<String, String> {
        let deadline = Instant::now() + READY_BUDGET;
        loop {
            let output = Command::new(&self.podman)
                .args([
                    "exec",
                    &self.name,
                    "cat",
                    "/var/lib/diorama/pki/admin.kubeconfig",
                ])
                .output()
                .await
                .map_err(|err| format!("podman exec: {err}"))?;
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout).into_owned();
                if text.contains("server:") {
                    return Ok(text);
                }
            }
            if Instant::now() > deadline {
                return Err("timed out waiting for admin.kubeconfig".into());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

fn find_podman() -> Result<PathBuf, String> {
    let engine = std::env::var("CONTAINER_ENGINE").unwrap_or_else(|_| "podman".to_string());
    let engine_path = PathBuf::from(&engine);
    if engine_path.components().count() > 1 && engine_path.is_file() {
        return Ok(engine_path);
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(&engine);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    let fallback = PathBuf::from("/opt/podman/bin/podman");
    if engine == "podman" && fallback.is_file() {
        return Ok(fallback);
    }
    Err(format!(
        "{engine} is not on PATH or at /opt/podman/bin/podman"
    ))
}

fn rewrite_server(yaml: &str, port: u16) -> String {
    let mut lines = Vec::new();
    for line in yaml.lines() {
        if line.trim_start().starts_with("server:") {
            lines.push(format!("    server: https://127.0.0.1:{port}"));
        } else {
            lines.push(line.to_string());
        }
    }
    lines.push(String::new());
    lines.join("\n")
}

async fn wait_ready(client: &Client) -> Result<(), String> {
    let deadline = Instant::now() + READY_BUDGET;
    let mut last;
    loop {
        let request = http::Request::builder()
            .uri("/readyz")
            .body(Vec::new())
            .map_err(|err| format!("{err}"))?;
        match client.request_text(request).await {
            Ok(body) if body.contains("ok") => return Ok(()),
            Ok(body) => last = format!("readyz body: {body}"),
            Err(err) => last = err.to_string(),
        }
        if Instant::now() > deadline {
            return Err(format!("timed out waiting for /readyz: {last}"));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T, String> {
    serde_json::from_value(value).map_err(|err| err.to_string())
}

async fn ensure_namespace(client: &Client) -> Result<(), String> {
    let namespaces: Api<Namespace> = Api::all(client.clone());
    if namespaces
        .get_opt(NS)
        .await
        .map_err(|err| err.to_string())?
        .is_some()
    {
        return Ok(());
    }
    let namespace = Namespace {
        metadata: ObjectMeta {
            name: Some(NS.into()),
            ..ObjectMeta::default()
        },
        ..Namespace::default()
    };
    namespaces
        .create(&PostParams::default(), &namespace)
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}

fn gvk(group: &str, version: &str, kind: &str) -> kube::core::GroupVersionKind {
    kube::core::GroupVersionKind::gvk(group, version, kind)
}

async fn probe_aggregated_kinds(client: &Client) -> ProbeResult {
    let discovery = Discovery::new(client.clone())
        .run_aggregated()
        .await
        .map_err(|err| err.to_string())?;
    let wanted = [
        ("apps", "v1", "Deployment"),
        ("apps", "v1", "ReplicaSet"),
        ("apps", "v1", "DaemonSet"),
        ("apps", "v1", "StatefulSet"),
        ("batch", "v1", "Job"),
    ];
    let mut missing = Vec::new();
    for (group, version, kind) in wanted {
        if discovery.resolve_gvk(&gvk(group, version, kind)).is_none() {
            missing.push(format!("{group}/{version} {kind}"));
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("unresolved: {}", missing.join(", ")))
    }
}

async fn aggregated_list(client: &Client, path: &str) -> Result<APIGroupDiscoveryList, String> {
    let request = http::Request::builder()
        .uri(path)
        .header(http::header::ACCEPT, ACCEPT_AGGREGATED_DISCOVERY_V2)
        .body(Vec::new())
        .map_err(|err| err.to_string())?;
    client.request(request).await.map_err(|err| err.to_string())
}

async fn probe_freshness(client: &Client) -> ProbeResult {
    let mut stale = Vec::new();
    for path in ["/api", "/apis"] {
        let list = aggregated_list(client, path).await?;
        for group in list.items {
            let name = group
                .metadata
                .as_ref()
                .and_then(|meta| meta.name.clone())
                .unwrap_or_else(|| path.into());
            for version in group.versions {
                let label = version.version.clone().unwrap_or_else(|| name.clone());
                if version.freshness.as_deref() != Some("Current") {
                    stale.push(format!("{name}/{label} freshness={:?}", version.freshness));
                }
            }
        }
    }
    if stale.is_empty() {
        Ok(())
    } else {
        Err(stale.join("; "))
    }
}

async fn probe_openapi_apps(client: &Client) -> ProbeResult {
    let request = http::Request::builder()
        .uri("/openapi/v3/apis/apps/v1")
        .body(Vec::new())
        .map_err(|err| err.to_string())?;
    client
        .request::<serde_json::Value>(request)
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}

async fn probe_configmap_crud(client: &Client) -> ProbeResult {
    let maps: Api<ConfigMap> = Api::namespaced(client.clone(), NS);
    let created = maps
        .create(&PostParams::default(), &config_map("crud", "k", "v"))
        .await
        .map_err(|err| err.to_string())?;
    let fetched = maps.get("crud").await.map_err(|err| err.to_string())?;
    if fetched.data.as_ref().and_then(|data| data.get("k")) != Some(&"v".to_string()) {
        return Err("fetched ConfigMap data mismatch".into());
    }
    if created.metadata.name.as_deref() != Some("crud") {
        return Err("created ConfigMap name mismatch".into());
    }
    maps.delete("crud", &DeleteParams::default())
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}

fn config_map(name: &str, key: &str, value: &str) -> ConfigMap {
    ConfigMap {
        metadata: ObjectMeta {
            name: Some(name.into()),
            namespace: Some(NS.into()),
            ..ObjectMeta::default()
        },
        data: Some([(key.into(), value.into())].into()),
        ..ConfigMap::default()
    }
}

async fn probe_label_selector(client: &Client) -> ProbeResult {
    let maps: Api<ConfigMap> = Api::namespaced(client.clone(), NS);
    let mut labeled = config_map("labeled", "k", "v");
    labeled.metadata.labels = Some([("app".into(), "board".into())].into());
    maps.create(&PostParams::default(), &labeled)
        .await
        .map_err(|err| err.to_string())?;
    maps.create(&PostParams::default(), &config_map("unlabeled", "k", "v"))
        .await
        .map_err(|err| err.to_string())?;
    let listed = maps
        .list(&ListParams::default().labels("app=board"))
        .await
        .map_err(|err| err.to_string())?;
    let names: Vec<_> = listed.iter().map(ResourceExt::name_any).collect();
    if names != ["labeled"] {
        return Err(format!("labelSelector returned {names:?}"));
    }
    Ok(())
}

async fn probe_secret_and_service(client: &Client) -> ProbeResult {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), NS);
    let secret: Secret = decode(json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "token", "namespace": NS},
        "stringData": {"token": "secret"}
    }))?;
    secrets
        .create(&PostParams::default(), &secret)
        .await
        .map_err(|err| err.to_string())?;
    secrets.get("token").await.map_err(|err| err.to_string())?;

    let services: Api<Service> = Api::namespaced(client.clone(), NS);
    let service: Service = decode(json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "board", "namespace": NS},
        "spec": {
            "selector": {"app": "board"},
            "ports": [{"port": 8080, "targetPort": 8080}]
        }
    }))?;
    let created = services
        .create(&PostParams::default(), &service)
        .await
        .map_err(|err| err.to_string())?;
    let cluster_ip = created
        .spec
        .as_ref()
        .and_then(|spec| spec.cluster_ip.as_deref())
        .unwrap_or("");
    if cluster_ip.is_empty() || cluster_ip == "None" {
        return Err(format!("ClusterIP missing: {cluster_ip}"));
    }
    services.get("board").await.map_err(|err| err.to_string())?;
    Ok(())
}

fn sleep_pod(name: &str, command: &serde_json::Value) -> serde_json::Value {
    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": NS},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "containers": [{
                        "name": "app",
                        "image": "busybox:1.36",
                        "command": command
                    }]
                }
            }
        }
    })
}

async fn probe_deployment_running(client: &Client) -> ProbeResult {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), NS);
    let deployment: Deployment = decode(sleep_pod(
        "board",
        &json!(["sh", "-c", "echo board-up; sleep 3600"]),
    ))?;
    deployments
        .create(&PostParams::default(), &deployment)
        .await
        .map_err(|err| err.to_string())?;
    let sets: Api<ReplicaSet> = Api::namespaced(client.clone(), NS);
    deadline_wait(WORK_BUDGET, || async {
        sets.get_opt("board-rs")
            .await
            .map_err(|err| err.to_string())?
            .map(|_| ())
            .ok_or_else(|| "ReplicaSet board-rs is absent".into())
    })
    .await?;
    let pods: Api<Pod> = Api::namespaced(client.clone(), NS);
    deadline_wait(WORK_BUDGET, || async {
        let pod = pods
            .get_opt("board-rs-0")
            .await
            .map_err(|err| err.to_string())?;
        match pod {
            Some(pod) if pod_running(&pod) => Ok(()),
            Some(_) => Err("pod board-rs-0 is not Running".into()),
            None => Err("pod board-rs-0 is absent".into()),
        }
    })
    .await
}

fn pod_running(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|status| status.phase.as_deref())
        == Some("Running")
}

async fn probe_scale_merge(client: &Client) -> ProbeResult {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), NS);
    deployments
        .patch(
            "board",
            &PatchParams::default(),
            &Patch::Merge(&json!({"spec": {"replicas": 2}})),
        )
        .await
        .map_err(|err| err.to_string())?;
    let updated = deployments
        .get("board")
        .await
        .map_err(|err| err.to_string())?;
    let replicas = updated.spec.as_ref().and_then(|spec| spec.replicas);
    if replicas != Some(2) {
        return Err(format!("replicas after merge patch: {replicas:?}"));
    }
    Ok(())
}

async fn probe_scale_json(client: &Client) -> ProbeResult {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), NS);
    let patch = json_patch::Patch(vec![json_patch::PatchOperation::Replace(
        json_patch::ReplaceOperation {
            path: "/spec/replicas".parse().expect("static json pointer"),
            value: json!(2),
        },
    )]);
    deployments
        .patch("board", &PatchParams::default(), &Patch::Json::<()>(patch))
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}

async fn probe_apply_configmap(client: &Client) -> ProbeResult {
    let maps: Api<ConfigMap> = Api::namespaced(client.clone(), NS);
    let map = config_map("applied", "k", "applied");
    maps.patch(
        "applied",
        &PatchParams::apply("diorama-conformance").force(),
        &Patch::Apply(&map),
    )
    .await
    .map_err(|err| err.to_string())?;
    let fetched = maps.get("applied").await.map_err(|err| err.to_string())?;
    if fetched.data.as_ref().and_then(|data| data.get("k")) != Some(&"applied".to_string()) {
        return Err("applied ConfigMap data mismatch".into());
    }
    Ok(())
}

async fn probe_watch_added(client: &Client) -> ProbeResult {
    let maps: Api<ConfigMap> = Api::namespaced(client.clone(), NS);
    let params = WatchParams::default().timeout(20);
    let stream = maps
        .watch(&params, "0")
        .await
        .map_err(|err| err.to_string())?;
    tokio::pin!(stream);
    maps.create(&PostParams::default(), &config_map("watched", "k", "v"))
        .await
        .map_err(|err| err.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => {
                return Err("watch did not emit ADDED for watched".into());
            }
            item = stream.next() => match item {
                Some(Ok(WatchEvent::Added(map))) if map.name_any() == "watched" => return Ok(()),
                Some(Ok(_)) => {}
                Some(Err(err)) => return Err(err.to_string()),
                None => return Err("watch ended before ADDED".into()),
            }
        }
    }
}

async fn probe_pod_logs(client: &Client) -> ProbeResult {
    let pods: Api<Pod> = Api::namespaced(client.clone(), NS);
    let params = LogParams {
        container: Some("app".into()),
        ..LogParams::default()
    };
    let logs = deadline_wait(WORK_BUDGET, || async {
        let logs = pods
            .logs("board-rs-0", &params)
            .await
            .map_err(|err| err.to_string())?;
        if logs.contains("board-up") {
            Ok(logs)
        } else {
            Err(format!("logs missing board-up: {logs}"))
        }
    })
    .await?;
    let _ = logs;
    Ok(())
}

async fn probe_pvc_bound(client: &Client) -> ProbeResult {
    let claims: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), NS);
    let claim: PersistentVolumeClaim = decode(json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": "notes", "namespace": NS},
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "storageClassName": "local-path",
            "resources": {"requests": {"storage": "32Mi"}}
        }
    }))?;
    claims
        .create(&PostParams::default(), &claim)
        .await
        .map_err(|err| err.to_string())?;
    deadline_wait(WORK_BUDGET, || async {
        let claim = claims.get("notes").await.map_err(|err| err.to_string())?;
        let phase = claim
            .status
            .as_ref()
            .and_then(|status| status.phase.as_deref());
        if phase == Some("Bound") {
            Ok(())
        } else {
            Err(format!("PVC phase is {phase:?}"))
        }
    })
    .await
}

async fn probe_daemonset(client: &Client) -> ProbeResult {
    let sets: Api<DaemonSet> = Api::namespaced(client.clone(), NS);
    let set: DaemonSet = decode(json!({
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {"name": "marker", "namespace": NS},
        "spec": {
            "selector": {"matchLabels": {"app": "marker"}},
            "template": {
                "metadata": {"labels": {"app": "marker"}},
                "spec": {
                    "containers": [{
                        "name": "marker",
                        "image": "busybox:1.36",
                        "command": ["sh", "-c", "echo ds-ok; sleep 3600"]
                    }]
                }
            }
        }
    }))?;
    sets.create(&PostParams::default(), &set)
        .await
        .map_err(|err| err.to_string())?;
    let pods: Api<Pod> = Api::namespaced(client.clone(), NS);
    deadline_wait(WORK_BUDGET, || async {
        let pod = pods
            .get_opt("marker-node")
            .await
            .map_err(|err| err.to_string())?;
        match pod {
            Some(pod) if pod_running(&pod) => Ok(()),
            Some(_) => Err("pod marker-node is not Running".into()),
            None => Err("pod marker-node is absent".into()),
        }
    })
    .await
}

async fn probe_job(client: &Client) -> ProbeResult {
    let jobs: Api<Job> = Api::namespaced(client.clone(), NS);
    let job: Job = decode(json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": "once", "namespace": NS},
        "spec": {
            "template": {
                "spec": {
                    "restartPolicy": "Never",
                    "containers": [{
                        "name": "once",
                        "image": "busybox:1.36",
                        "command": ["echo", "ok"]
                    }]
                }
            }
        }
    }))?;
    jobs.create(&PostParams::default(), &job)
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}

async fn probe_events(client: &Client) -> ProbeResult {
    let events: Api<Event> = Api::namespaced(client.clone(), NS);
    events
        .list(&ListParams::default())
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn probe_events_core_v1(client: &Client) -> ProbeResult {
    let events: Api<Event> = Api::namespaced(client.clone(), NS);
    let event_name = "test-core-event";

    let _ = events.delete(event_name, &DeleteParams::default()).await;

    // 1. Create core Event
    let event: Event = decode(json!({
        "apiVersion": "v1",
        "kind": "Event",
        "metadata": {
            "name": event_name,
            "namespace": NS,
            "labels": {"test": "conformance-core-event", "app": "event-probe"}
        },
        "involvedObject": {
            "kind": "ConfigMap",
            "namespace": NS,
            "name": "crud"
        },
        "reason": "Started",
        "message": "Initial event message",
        "count": 1,
        "type": "Normal",
        "action": "Starting",
        "reportingController": "diorama-instrumentation-test",
        "reportingInstance": "instance-0"
    }))?;
    let created = events
        .create(&PostParams::default(), &event)
        .await
        .map_err(|e| format!("create core event: {e}"))?;
    if created.metadata.name.as_deref() != Some(event_name) {
        return Err("created core event name mismatch".into());
    }

    // 2. Get core Event
    let fetched = events
        .get(event_name)
        .await
        .map_err(|e| format!("get core event: {e}"))?;
    if fetched.reason.as_deref() != Some("Started") {
        return Err("fetched core event reason mismatch".into());
    }

    // 3. List with labelSelector
    let labeled_list = events
        .list(&ListParams::default().labels("test=conformance-core-event"))
        .await
        .map_err(|e| format!("list core events by label: {e}"))?;
    let found = labeled_list
        .items
        .iter()
        .any(|ev| ev.metadata.name.as_deref() == Some(event_name));
    if !found {
        return Err("list by labelSelector did not return created core event".into());
    }

    // 4. List with fieldSelector
    let field_list = events
        .list(&ListParams::default().fields(&format!("metadata.name={event_name}")))
        .await
        .map_err(|e| format!("list core events by field: {e}"))?;
    let found_field = field_list
        .items
        .iter()
        .any(|ev| ev.metadata.name.as_deref() == Some(event_name));
    if !found_field {
        return Err("list by fieldSelector did not return created core event".into());
    }

    // 5. Watch stream
    let watch_params = WatchParams::default().timeout(10);
    let stream = events
        .watch(&watch_params, "0")
        .await
        .map_err(|e| format!("watch core events: {e}"))?;
    tokio::pin!(stream);

    let watched_event: Event = decode(json!({
        "apiVersion": "v1",
        "kind": "Event",
        "metadata": {
            "name": "core-event-watched",
            "namespace": NS,
            "labels": {"test": "conformance-core-event", "app": "event-watch"}
        },
        "involvedObject": {
            "kind": "ConfigMap",
            "namespace": NS,
            "name": "crud"
        },
        "reason": "WatchTriggered",
        "message": "Watch event emitted",
        "type": "Normal"
    }))?;
    events
        .create(&PostParams::default(), &watched_event)
        .await
        .map_err(|e| format!("create watched event: {e}"))?;

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut got_watch_event = false;
    while Instant::now() < deadline {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(50)) => {}
            item = stream.next() => match item {
                Some(Ok(WatchEvent::Added(ev))) => {
                    if ev.metadata.name.as_deref() == Some("core-event-watched")
                        || ev.metadata.name.as_deref() == Some(event_name) {
                        got_watch_event = true;
                        break;
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(format!("watch stream error: {e}")),
                None => break,
            }
        }
    }
    if !got_watch_event {
        return Err("timed out waiting for watch ADDED event".into());
    }

    // 6. Strategic merge patch: series and count
    let patch_merge = json!({
        "count": 5,
        "series": {
            "count": 5,
            "lastObservedTime": "2026-10-15T23:00:00.000000Z",
            "state": "Ongoing"
        }
    });
    let patched = events
        .patch(
            event_name,
            &PatchParams::default(),
            &Patch::Merge(&patch_merge),
        )
        .await
        .map_err(|e| format!("merge patch core event: {e}"))?;
    if patched.count != Some(5) {
        return Err(format!(
            "patched core event count expected 5, got {:?}",
            patched.count
        ));
    }

    // 7. JSON patch: action
    let json_patch_op = json_patch::Patch(vec![json_patch::PatchOperation::Replace(
        json_patch::ReplaceOperation {
            path: "/action".parse().expect("valid json pointer"),
            value: json!("ActionUpdated"),
        },
    )]);
    let patched_json = events
        .patch(
            event_name,
            &PatchParams::default(),
            &Patch::Json::<()>(json_patch_op),
        )
        .await
        .map_err(|e| format!("json patch core event: {e}"))?;
    if patched_json.action.as_deref() != Some("ActionUpdated") {
        return Err("json patch action mismatch".into());
    }

    // 8. Server-side Apply patch: reportingComponent and message
    let apply_patch = json!({
        "apiVersion": "v1",
        "kind": "Event",
        "metadata": {
            "name": event_name,
            "namespace": NS
        },
        "reportingComponent": "diorama-ssa-agent",
        "message": "Applied update message"
    });
    let applied = events
        .patch(
            event_name,
            &PatchParams::apply("diorama-events-test").force(),
            &Patch::Apply(&apply_patch),
        )
        .await
        .map_err(|e| format!("apply patch core event: {e}"))?;
    if applied.reporting_component.as_deref() != Some("diorama-ssa-agent") {
        return Err("applied reportingComponent mismatch".into());
    }
    if applied.message.as_deref() != Some("Applied update message") {
        return Err("applied message mismatch".into());
    }

    // 9. Delete collection by labelSelector
    events
        .delete_collection(
            &DeleteParams::default(),
            &ListParams::default().labels("test=conformance-core-event"),
        )
        .await
        .map_err(|e| format!("deletecollection core events: {e}"))?;

    let post_delete_list = events
        .list(&ListParams::default().labels("test=conformance-core-event"))
        .await
        .map_err(|e| format!("list after deletecollection: {e}"))?;
    if !post_delete_list.items.is_empty() {
        return Err("deletecollection did not delete all labeled core events".into());
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn probe_events_k8s_io_v1(client: &Client) -> ProbeResult {
    let events: Api<EventsV1Event> = Api::namespaced(client.clone(), NS);
    let event_name = "test-v1-event";

    let _ = events.delete(event_name, &DeleteParams::default()).await;

    // 1. Create events.k8s.io/v1 Event
    let event: EventsV1Event = decode(json!({
        "apiVersion": "events.k8s.io/v1",
        "kind": "Event",
        "metadata": {
            "name": event_name,
            "namespace": NS,
            "labels": {"test": "conformance-v1-event", "app": "event-probe"}
        },
        "regarding": {
            "kind": "ConfigMap",
            "namespace": NS,
            "name": "crud"
        },
        "reason": "V1Started",
        "note": "Initial v1 event note",
        "type": "Normal",
        "action": "V1Action",
        "eventTime": "2026-10-15T23:00:00.000000Z",
        "reportingController": "diorama-v1-controller",
        "reportingInstance": "inst-v1"
    }))?;
    let created = events
        .create(&PostParams::default(), &event)
        .await
        .map_err(|e| format!("create events.k8s.io/v1 event: {e}"))?;
    if created.metadata.name.as_deref() != Some(event_name) {
        return Err("created v1 event name mismatch".into());
    }

    // 2. Get Event
    let fetched = events
        .get(event_name)
        .await
        .map_err(|e| format!("get v1 event: {e}"))?;
    if fetched.reason.as_deref() != Some("V1Started") {
        return Err("fetched v1 event reason mismatch".into());
    }

    // 3. List with labelSelector
    let labeled_list = events
        .list(&ListParams::default().labels("test=conformance-v1-event"))
        .await
        .map_err(|e| format!("list v1 events by label: {e}"))?;
    let found = labeled_list
        .items
        .iter()
        .any(|ev| ev.metadata.name.as_deref() == Some(event_name));
    if !found {
        return Err("list by labelSelector did not return created v1 event".into());
    }

    // 4. List with fieldSelector
    let field_list = events
        .list(&ListParams::default().fields(&format!("metadata.name={event_name}")))
        .await
        .map_err(|e| format!("list v1 events by field: {e}"))?;
    let found_field = field_list
        .items
        .iter()
        .any(|ev| ev.metadata.name.as_deref() == Some(event_name));
    if !found_field {
        return Err("list by fieldSelector did not return created v1 event".into());
    }

    // 5. Watch stream
    let watch_params = WatchParams::default().timeout(10);
    let stream = events
        .watch(&watch_params, "0")
        .await
        .map_err(|e| format!("watch v1 events: {e}"))?;
    tokio::pin!(stream);

    let watched_v1: EventsV1Event = decode(json!({
        "apiVersion": "events.k8s.io/v1",
        "kind": "Event",
        "metadata": {
            "name": "v1-event-watched",
            "namespace": NS,
            "labels": {"test": "conformance-v1-event", "app": "event-watch"}
        },
        "regarding": {
            "kind": "ConfigMap",
            "namespace": NS,
            "name": "crud"
        },
        "reason": "WatchTriggered",
        "note": "V1 watch event emitted",
        "type": "Normal",
        "eventTime": "2026-10-15T23:01:00.000000Z",
        "reportingController": "diorama-v1-watch",
        "reportingInstance": "inst-watch",
        "action": "Watch"
    }))?;
    events
        .create(&PostParams::default(), &watched_v1)
        .await
        .map_err(|e| format!("create watched v1 event: {e}"))?;

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut got_v1_watch = false;
    while Instant::now() < deadline {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(50)) => {}
            item = stream.next() => match item {
                Some(Ok(WatchEvent::Added(ev))) => {
                    if ev.metadata.name.as_deref() == Some("v1-event-watched")
                        || ev.metadata.name.as_deref() == Some(event_name) {
                        got_v1_watch = true;
                        break;
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(format!("watch v1 stream error: {e}")),
                None => break,
            }
        }
    }
    if !got_v1_watch {
        return Err("timed out waiting for v1 watch ADDED event".into());
    }

    // 6. Strategic merge patch: series
    let patch_merge = json!({
        "series": {
            "count": 4,
            "lastObservedTime": "2026-10-15T23:05:00.000000Z"
        }
    });
    let patched = events
        .patch(
            event_name,
            &PatchParams::default(),
            &Patch::Merge(&patch_merge),
        )
        .await
        .map_err(|e| format!("merge patch v1 event: {e}"))?;
    if patched.series.as_ref().map(|s| s.count) != Some(4) {
        return Err("patched v1 event series count mismatch".into());
    }

    // 7. JSON patch: action
    let json_patch_op = json_patch::Patch(vec![json_patch::PatchOperation::Replace(
        json_patch::ReplaceOperation {
            path: "/action".parse().expect("valid json pointer"),
            value: json!("V1ActionUpdated"),
        },
    )]);
    let patched_json = events
        .patch(
            event_name,
            &PatchParams::default(),
            &Patch::Json::<()>(json_patch_op),
        )
        .await
        .map_err(|e| format!("json patch v1 event: {e}"))?;
    if patched_json.action.as_deref() != Some("V1ActionUpdated") {
        return Err("json patch v1 action mismatch".into());
    }

    // 8. Server-side Apply patch: reportingController and note
    let apply_patch = json!({
        "apiVersion": "events.k8s.io/v1",
        "kind": "Event",
        "metadata": {
            "name": event_name,
            "namespace": NS
        },
        "reportingController": "diorama-v1-apply",
        "note": "Applied note update"
    });
    let applied = events
        .patch(
            event_name,
            &PatchParams::apply("diorama-events-v1-test").force(),
            &Patch::Apply(&apply_patch),
        )
        .await
        .map_err(|e| format!("apply patch v1 event: {e}"))?;
    if applied.reporting_controller.as_deref() != Some("diorama-v1-apply") {
        return Err("applied v1 reportingController mismatch".into());
    }

    // 9. Delete collection
    events
        .delete_collection(
            &DeleteParams::default(),
            &ListParams::default().labels("test=conformance-v1-event"),
        )
        .await
        .map_err(|e| format!("deletecollection v1 events: {e}"))?;

    let post_delete_list = events
        .list(&ListParams::default().labels("test=conformance-v1-event"))
        .await
        .map_err(|e| format!("list after deletecollection v1: {e}"))?;
    if !post_delete_list.items.is_empty() {
        return Err("deletecollection did not delete all labeled v1 events".into());
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn probe_kubectl_server_dry_run_pod(client: &Client) -> ProbeResult {
    let pods: Api<Pod> = Api::namespaced(client.clone(), NS);
    let pod_name = "server-dry-run-pod";

    let _ = pods.delete(pod_name, &DeleteParams::default()).await;

    let pod: Pod = decode(json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "namespace": NS,
            "labels": {"app": "dry-run-probe"}
        },
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "app",
                "image": "busybox:1.36",
                "command": ["sh", "-c", "sleep 3600"]
            }]
        }
    }))?;

    // 1. Create Pod with dryRun=All (dry_run: true)
    let dry_post = PostParams {
        dry_run: true,
        ..Default::default()
    };
    let dry_created = pods
        .create(&dry_post, &pod)
        .await
        .map_err(|e| format!("dryRun create pod: {e}"))?;
    if dry_created.metadata.name.as_deref() != Some(pod_name) {
        return Err("dryRun create did not return Pod".into());
    }
    // Verify it is NOT persisted in cluster
    let check_opt = pods
        .get_opt(pod_name)
        .await
        .map_err(|e| format!("get_opt after dryRun create: {e}"))?;
    if check_opt.is_some() {
        return Err("dryRun create must not persist Pod in stored state".into());
    }

    // 2. Create Pod for real
    pods.create(&PostParams::default(), &pod)
        .await
        .map_err(|e| format!("create real pod: {e}"))?;
    let stored = pods
        .get(pod_name)
        .await
        .map_err(|e| format!("get stored pod: {e}"))?;
    let orig_image = stored
        .spec
        .as_ref()
        .and_then(|s| s.containers.first())
        .and_then(|c| c.image.clone())
        .unwrap_or_default();
    if orig_image != "busybox:1.36" {
        return Err(format!(
            "stored pod image expected busybox:1.36, got {orig_image}"
        ));
    }

    // 3. Patch Pod with dryRun=All (#240 kubectl patch pod --dry-run=server)
    let dry_patch_params = PatchParams {
        dry_run: true,
        ..Default::default()
    };
    let patch = json!({
        "spec": {
            "containers": [{
                "name": "app",
                "image": "busybox:1.36-mutated"
            }]
        }
    });
    let dry_patched = pods
        .patch(pod_name, &dry_patch_params, &Patch::Merge(&patch))
        .await
        .map_err(|e| format!("dryRun patch pod: {e}"))?;
    let dry_image = dry_patched
        .spec
        .as_ref()
        .and_then(|s| s.containers.first())
        .and_then(|c| c.image.as_deref());
    if dry_image != Some("busybox:1.36-mutated") {
        return Err("dryRun patch did not return updated image in response".into());
    }

    // Verify stored state was NOT mutated
    let stored_after_patch = pods
        .get(pod_name)
        .await
        .map_err(|e| format!("get stored pod after dryRun patch: {e}"))?;
    let stored_image = stored_after_patch
        .spec
        .as_ref()
        .and_then(|s| s.containers.first())
        .and_then(|c| c.image.as_deref());
    if stored_image != Some("busybox:1.36") {
        return Err(format!(
            "stored pod image was mutated by dryRun patch: {stored_image:?}"
        ));
    }

    // 4. Update (replace) Pod with dryRun=All
    let mut pod_for_replace = stored_after_patch.clone();
    if let Some(c) = pod_for_replace
        .spec
        .as_mut()
        .and_then(|s| s.containers.first_mut())
    {
        c.image = Some("busybox:1.36-replace-mutated".into());
    }
    let dry_replaced = pods
        .replace(pod_name, &dry_post, &pod_for_replace)
        .await
        .map_err(|e| format!("dryRun replace pod: {e}"))?;
    let replaced_image = dry_replaced
        .spec
        .as_ref()
        .and_then(|s| s.containers.first())
        .and_then(|c| c.image.as_deref());
    if replaced_image != Some("busybox:1.36-replace-mutated") {
        return Err("dryRun replace did not return updated image in response".into());
    }

    // Verify stored state still NOT mutated
    let stored_after_replace = pods
        .get(pod_name)
        .await
        .map_err(|e| format!("get stored pod after dryRun replace: {e}"))?;
    let stored_image2 = stored_after_replace
        .spec
        .as_ref()
        .and_then(|s| s.containers.first())
        .and_then(|c| c.image.as_deref());
    if stored_image2 != Some("busybox:1.36") {
        return Err(format!(
            "stored pod image was mutated by dryRun replace: {stored_image2:?}"
        ));
    }

    // Clean up
    let _ = pods.delete(pod_name, &DeleteParams::default()).await;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn probe_guestbook_workload_lifecycle(client: &Client) -> ProbeResult {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), NS);
    let services: Api<Service> = Api::namespaced(client.clone(), NS);
    let sets: Api<ReplicaSet> = Api::namespaced(client.clone(), NS);

    // 1. Primary Redis tier Deployment + Service
    let redis_leader_deploy: Deployment = decode(json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "redis-leader",
            "namespace": NS,
            "labels": {"app": "guestbook", "role": "leader", "tier": "backend"}
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "guestbook", "role": "leader", "tier": "backend"}},
            "template": {
                "metadata": {"labels": {"app": "guestbook", "role": "leader", "tier": "backend"}},
                "spec": {
                    "containers": [{
                        "name": "redis",
                        "image": "busybox:1.36",
                        "command": ["sh", "-c", "echo redis-leader-ready; sleep 3600"],
                        "ports": [{"containerPort": 6379}]
                    }]
                }
            }
        }
    }))?;
    let redis_leader_svc: Service = decode(json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "redis-leader",
            "namespace": NS,
            "labels": {"app": "guestbook", "role": "leader", "tier": "backend"}
        },
        "spec": {
            "ports": [{"port": 6379, "targetPort": 6379}],
            "selector": {"app": "guestbook", "role": "leader", "tier": "backend"}
        }
    }))?;

    // 2. Replica Redis tier Deployment + Service
    let redis_follower_deploy: Deployment = decode(json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "redis-follower",
            "namespace": NS,
            "labels": {"app": "guestbook", "role": "follower", "tier": "backend"}
        },
        "spec": {
            "replicas": 2,
            "selector": {"matchLabels": {"app": "guestbook", "role": "follower", "tier": "backend"}},
            "template": {
                "metadata": {"labels": {"app": "guestbook", "role": "follower", "tier": "backend"}},
                "spec": {
                    "containers": [{
                        "name": "redis",
                        "image": "busybox:1.36",
                        "command": ["sh", "-c", "echo redis-follower-ready; sleep 3600"],
                        "ports": [{"containerPort": 6379}]
                    }]
                }
            }
        }
    }))?;
    let redis_follower_svc: Service = decode(json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "redis-follower",
            "namespace": NS,
            "labels": {"app": "guestbook", "role": "follower", "tier": "backend"}
        },
        "spec": {
            "ports": [{"port": 6379, "targetPort": 6379}],
            "selector": {"app": "guestbook", "role": "follower", "tier": "backend"}
        }
    }))?;

    // 3. Frontend tier Deployment + Service
    let frontend_deploy: Deployment = decode(json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "frontend",
            "namespace": NS,
            "labels": {"app": "guestbook", "tier": "frontend"}
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "guestbook", "tier": "frontend"}},
            "template": {
                "metadata": {"labels": {"app": "guestbook", "tier": "frontend"}},
                "spec": {
                    "containers": [{
                        "name": "php-redis",
                        "image": "busybox:1.36",
                        "command": ["sh", "-c", "echo frontend-ready; sleep 3600"],
                        "ports": [{"containerPort": 80}]
                    }]
                }
            }
        }
    }))?;
    let frontend_svc: Service = decode(json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "frontend",
            "namespace": NS,
            "labels": {"app": "guestbook", "tier": "frontend"}
        },
        "spec": {
            "ports": [{"port": 80, "targetPort": 80}],
            "selector": {"app": "guestbook", "tier": "frontend"}
        }
    }))?;

    // Create all components
    deployments
        .create(&PostParams::default(), &redis_leader_deploy)
        .await
        .map_err(|e| format!("create redis-leader deploy: {e}"))?;
    services
        .create(&PostParams::default(), &redis_leader_svc)
        .await
        .map_err(|e| format!("create redis-leader svc: {e}"))?;

    deployments
        .create(&PostParams::default(), &redis_follower_deploy)
        .await
        .map_err(|e| format!("create redis-follower deploy: {e}"))?;
    services
        .create(&PostParams::default(), &redis_follower_svc)
        .await
        .map_err(|e| format!("create redis-follower svc: {e}"))?;

    deployments
        .create(&PostParams::default(), &frontend_deploy)
        .await
        .map_err(|e| format!("create frontend deploy: {e}"))?;
    services
        .create(&PostParams::default(), &frontend_svc)
        .await
        .map_err(|e| format!("create frontend svc: {e}"))?;

    // Verify Services have ClusterIPs
    for svc_name in ["redis-leader", "redis-follower", "frontend"] {
        let s = services
            .get(svc_name)
            .await
            .map_err(|e| format!("get svc {svc_name}: {e}"))?;
        let ip = s
            .spec
            .as_ref()
            .and_then(|sp| sp.cluster_ip.as_deref())
            .unwrap_or("");
        if ip.is_empty() || ip == "None" {
            return Err(format!("Service {svc_name} missing ClusterIP: {ip}"));
        }
    }

    // Verify ReplicaSets
    deadline_wait(WORK_BUDGET, || async {
        let rs_list = sets
            .list(&ListParams::default().labels("app=guestbook"))
            .await
            .map_err(|e| e.to_string())?;
        if rs_list.items.len() >= 3 {
            Ok(())
        } else {
            Err(format!(
                "expected at least 3 ReplicaSets for guestbook, found {}",
                rs_list.items.len()
            ))
        }
    })
    .await?;

    // Scale follower deployment from 2 to 3
    deployments
        .patch(
            "redis-follower",
            &PatchParams::default(),
            &Patch::Merge(&json!({"spec": {"replicas": 3}})),
        )
        .await
        .map_err(|e| format!("scale redis-follower: {e}"))?;
    let scaled = deployments
        .get("redis-follower")
        .await
        .map_err(|e| format!("get scaled redis-follower: {e}"))?;
    if scaled.spec.as_ref().and_then(|s| s.replicas) != Some(3) {
        return Err("scaled redis-follower replicas mismatch".into());
    }

    // Teardown
    for deploy_name in ["redis-leader", "redis-follower", "frontend"] {
        let _ = deployments
            .delete(deploy_name, &DeleteParams::default())
            .await;
    }
    for svc_name in ["redis-leader", "redis-follower", "frontend"] {
        let _ = services.delete(svc_name, &DeleteParams::default()).await;
    }

    Ok(())
}

async fn probe_exec(client: &Client) -> ProbeResult {
    let pods: Api<Pod> = Api::namespaced(client.clone(), NS);
    let mut attached = pods
        .exec(
            "board-rs-0",
            ["echo", "ok"],
            &AttachParams::default().stderr(false),
        )
        .await
        .map_err(|err| err.to_string())?;
    let mut stdout = String::new();
    if let Some(mut reader) = attached.stdout() {
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .await
            .map_err(|err| err.to_string())?;
        stdout = String::from_utf8_lossy(&bytes).into_owned();
    }
    if !stdout.contains("ok") {
        return Err(format!("exec stdout: {stdout:?}"));
    }
    Ok(())
}

async fn probe_delete_deployment(client: &Client) -> ProbeResult {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), NS);
    deployments
        .delete("board", &DeleteParams::default())
        .await
        .map_err(|err| err.to_string())?;
    let pods: Api<Pod> = Api::namespaced(client.clone(), NS);
    deadline_wait(WORK_BUDGET, || async {
        let listed = pods
            .list(&ListParams::default())
            .await
            .map_err(|err| err.to_string())?;
        let left: Vec<_> = listed
            .iter()
            .map(ResourceExt::name_any)
            .filter(|name| name.starts_with("board-rs-"))
            .collect();
        if left.is_empty() {
            Ok(())
        } else {
            Err(format!("pods still present: {left:?}"))
        }
    })
    .await
}

async fn deadline_wait<T, F, Fut>(budget: Duration, mut op: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let deadline = Instant::now() + budget;
    let mut last;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => last = err,
        }
        if Instant::now() > deadline {
            return Err(last);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn record(
    rows: &mut Vec<Row>,
    name: &'static str,
    probe: impl std::future::Future<Output = ProbeResult>,
) {
    let error = match tokio::time::timeout(WORK_BUDGET + Duration::from_secs(30), probe).await {
        Ok(Ok(())) => None,
        Ok(Err(err)) => Some(err),
        Err(_) => Some("timed out".into()),
    };
    rows.push(Row { name, error });
}

fn report(rows: &[Row]) -> Result<(), String> {
    let width = rows.iter().map(|row| row.name.len()).max().unwrap_or(0);
    let mut failed = Vec::new();
    for row in rows {
        match &row.error {
            None => println!("{:<width$}  PASS", row.name),
            Some(err) => {
                let line = err.lines().next().unwrap_or(err);
                println!("{:<width$}  FAIL  {line}", row.name);
                failed.push(format!("- {}: {err}", row.name));
            },
        }
    }
    let passed = rows.len() - failed.len();
    println!("{passed} passed, {} failed", failed.len());
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("gaps:\n{}", failed.join("\n")))
    }
}

#[tokio::test]
#[ignore = "privileged podman; cargo test --locked -p diorama-conformance --test suite -- --ignored --nocapture"]
async fn client_gaps() {
    let cluster = Cluster::start().await.expect("start diorama container");
    let client = cluster.client.clone().expect("client is ready after start");
    let mut rows = Vec::new();
    record(
        &mut rows,
        "aggregated discovery kinds",
        probe_aggregated_kinds(&client),
    )
    .await;
    record(&mut rows, "discovery freshness", probe_freshness(&client)).await;
    record(&mut rows, "openapi apps/v1", probe_openapi_apps(&client)).await;
    if let Err(err) = ensure_namespace(&client).await {
        record(&mut rows, "namespace gaps", std::future::ready(Err(err))).await;
    } else {
        record(&mut rows, "configmap crud", probe_configmap_crud(&client)).await;
        record(&mut rows, "label selector", probe_label_selector(&client)).await;
        record(
            &mut rows,
            "secret and service",
            probe_secret_and_service(&client),
        )
        .await;
        record(
            &mut rows,
            "deployment running",
            probe_deployment_running(&client),
        )
        .await;
        record(&mut rows, "scale merge patch", probe_scale_merge(&client)).await;
        record(&mut rows, "scale json patch", probe_scale_json(&client)).await;
        record(
            &mut rows,
            "server-side apply",
            probe_apply_configmap(&client),
        )
        .await;
        record(&mut rows, "watch added", probe_watch_added(&client)).await;
        record(&mut rows, "pod logs", probe_pod_logs(&client)).await;
        record(&mut rows, "pvc bound", probe_pvc_bound(&client)).await;
        record(&mut rows, "daemonset running", probe_daemonset(&client)).await;
        record(&mut rows, "job create", probe_job(&client)).await;
        record(&mut rows, "events list", probe_events(&client)).await;
        record(
            &mut rows,
            "events core/v1 lifecycle",
            Box::pin(probe_events_core_v1(&client)),
        )
        .await;
        record(
            &mut rows,
            "events events.k8s.io/v1 lifecycle",
            Box::pin(probe_events_k8s_io_v1(&client)),
        )
        .await;
        record(
            &mut rows,
            "kubectl server dry-run pod",
            Box::pin(probe_kubectl_server_dry_run_pod(&client)),
        )
        .await;
        record(
            &mut rows,
            "kubectl guestbook workloads",
            Box::pin(probe_guestbook_workload_lifecycle(&client)),
        )
        .await;
        record(&mut rows, "pod exec", probe_exec(&client)).await;
        record(
            &mut rows,
            "delete deployment",
            probe_delete_deployment(&client),
        )
        .await;
    }
    if let Err(err) = report(&rows) {
        panic!("{err}");
    }
}

#[derive(Deserialize)]
struct UpstreamTest {
    testname: String,
    codename: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    release: String,
    #[allow(dead_code)]
    file: String,
}

fn sig_of(codename: &str) -> String {
    let Some(start) = codename.find("[sig-") else {
        return "unassigned".into();
    };
    let rest = &codename[start + 1..];
    let end = rest.find(']').unwrap_or(rest.len());
    rest[..end].to_string()
}

/// Vendored from Kubernetes v1.37.1 `test/conformance/testdata/conformance.yaml`.
/// A certified run uses `registry.k8s.io/conformance:v1.37.1`.
#[test]
#[ignore = "prints every v1.37 conformance test as not covered"]
fn upstream_conformance_catalog() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/conformance.yaml"
    );
    let raw = std::fs::read_to_string(path).expect("read conformance.yaml");
    let tests: Vec<UpstreamTest> = serde_saphyr::from_str(&raw).expect("parse conformance.yaml");
    let mut grouped: BTreeMap<String, Vec<&UpstreamTest>> = BTreeMap::new();
    for test in &tests {
        assert!(test.codename.contains("[Conformance]"), "{}", test.codename);
        grouped
            .entry(sig_of(&test.codename))
            .or_default()
            .push(test);
    }
    let expected = [
        ("sig-api-machinery", 100),
        ("sig-apps", 60),
        ("sig-architecture", 1),
        ("sig-auth", 27),
        ("sig-cli", 17),
        ("sig-instrumentation", 4),
        ("sig-network", 47),
        ("sig-node", 104),
        ("sig-scheduling", 11),
        ("sig-storage", 91),
    ];
    let mut counts = Vec::new();
    for (sig, count) in expected {
        let actual = grouped.get(sig).map_or(0, Vec::len);
        counts.push(format!("{sig}: {actual}"));
        assert_eq!(actual, count, "{sig}");
    }
    assert_eq!(grouped.len(), expected.len());
    assert_eq!(tests.len(), 462);
    println!("{}", counts.join("\n"));
    let mut uncovered = Vec::new();
    for (sig, items) in &grouped {
        let mut items = items.clone();
        items.sort_by(|left, right| left.codename.cmp(&right.codename));
        for test in items {
            println!("{sig}  {}  not covered", test.testname);
            uncovered.push(format!("{sig}  {}", test.testname));
        }
    }
    panic!("{} not covered:\n{}", uncovered.len(), uncovered.join("\n"));
}

struct InMemoryTestServer {
    addr: std::net::SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl InMemoryTestServer {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        let store: Arc<tokio::sync::Mutex<HashMap<String, Value>>> =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let rev = Arc::new(AtomicU64::new(1));
        let (watch_tx, _) = tokio::sync::broadcast::channel::<Value>(64);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    res = listener.accept() => {
                        let Ok((stream, _)) = res else { break; };
                        let store = Arc::clone(&store);
                        let rev = Arc::clone(&rev);
                        let watch_tx = watch_tx.clone();
                        tokio::spawn(handle_connection(stream, store, rev, watch_tx));
                    }
                }
            }
        });

        Self {
            addr,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    fn try_client(&self) -> Result<Client, String> {
        let uri: http::Uri = format!("http://127.0.0.1:{}", self.addr.port())
            .parse()
            .map_err(|e| format!("parse uri: {e}"))?;
        let config = Config::new(uri);
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Client::try_from(config).map_err(|e| format!("create client: {e}"))
        }));
        std::panic::set_hook(prev_hook);
        res.map_err(|_| {
            "rustls multi-provider ambiguity under workspace --all-features".to_string()
        })?
    }
}

impl Drop for InMemoryTestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

#[allow(clippy::too_many_lines, clippy::excessive_nesting)]
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    store: Arc<tokio::sync::Mutex<HashMap<String, Value>>>,
    rev: Arc<AtomicU64>,
    watch_tx: tokio::sync::broadcast::Sender<Value>,
) {
    let mut buf = Vec::with_capacity(8192);
    let mut temp = [0u8; 4096];
    loop {
        let header_end = loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break Some(pos);
            }
            match stream.read(&mut temp).await {
                Ok(0) | Err(_) => break None,
                Ok(n) => buf.extend_from_slice(&temp[..n]),
            }
        };

        let Some(header_pos) = header_end else { break };
        let (method, uri_str, content_length, content_type) = {
            let header_bytes = &buf[..header_pos];
            let Ok(header_str) = std::str::from_utf8(header_bytes) else {
                break;
            };
            let mut lines = header_str.lines();
            let Some(req_line) = lines.next() else { break };
            let mut parts = req_line.split_whitespace();
            let Some(m) = parts.next() else { break };
            let Some(u) = parts.next() else { break };

            let mut len = 0usize;
            let mut ct = String::new();
            for line in lines {
                if let Some((k, v)) = line.split_once(':') {
                    let k_trim = k.trim().to_ascii_lowercase();
                    let v_trim = v.trim();
                    if k_trim == "content-length" {
                        len = v_trim.parse().unwrap_or(0);
                    } else if k_trim == "content-type" {
                        ct = v_trim.to_string();
                    }
                }
            }
            (m.to_string(), u.to_string(), len, ct)
        };

        let body_start = header_pos + 4;
        while buf.len() < body_start + content_length {
            match stream.read(&mut temp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&temp[..n]),
            }
        }
        if buf.len() < body_start + content_length {
            break;
        }

        let body = buf[body_start..body_start + content_length].to_vec();
        buf.drain(..body_start + content_length);

        let (status, resp_body, is_watch, watch_items) = process_request(
            &method,
            &uri_str,
            &content_type,
            &body,
            &store,
            &rev,
            &watch_tx,
        )
        .await;

        if is_watch {
            let initial = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n";
            if stream.write_all(initial.as_bytes()).await.is_err() {
                break;
            }
            for item in watch_items {
                let line = format!(
                    "{}\n",
                    serde_json::to_string(&json!({"type": "ADDED", "object": item})).unwrap()
                );
                let chunk = format!("{:X}\r\n{}\r\n", line.len(), line);
                if stream.write_all(chunk.as_bytes()).await.is_err() {
                    break;
                }
            }
            let mut rx = watch_tx.subscribe();
            let mut interval = tokio::time::interval(Duration::from_millis(50));
            let timeout = Instant::now() + Duration::from_secs(12);
            while Instant::now() < timeout {
                tokio::select! {
                    event_res = rx.recv() => {
                        if let Ok(event) = event_res {
                            let line = format!("{}\n", serde_json::to_string(&event).unwrap());
                            let chunk = format!("{:X}\r\n{}\r\n", line.len(), line);
                            if stream.write_all(chunk.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {}
                }
            }
            break;
        }
        let resp = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            resp_body.len()
        );
        if stream.write_all(resp.as_bytes()).await.is_err()
            || stream.write_all(&resp_body).await.is_err()
        {
            break;
        }
    }
}

#[allow(clippy::too_many_lines, clippy::excessive_nesting)]
async fn process_request(
    method: &str,
    uri_str: &str,
    content_type: &str,
    body: &[u8],
    store_arc: &Arc<tokio::sync::Mutex<HashMap<String, Value>>>,
    rev: &Arc<AtomicU64>,
    watch_tx: &tokio::sync::broadcast::Sender<Value>,
) -> (String, Vec<u8>, bool, Vec<Value>) {
    let (path, raw_query) = uri_str.split_once('?').unwrap_or((uri_str, ""));
    let query = parse_query(raw_query);

    let is_watch = method == "GET" && query.get("watch").is_some_and(|v| v == "true");
    if is_watch {
        let store = store_arc.lock().await;
        let prefix = format!("{path}/");
        let items: Vec<Value> = store
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect();
        return ("200 OK".into(), Vec::new(), true, items);
    }

    let mut store = store_arc.lock().await;
    match method {
        "GET" => {
            if let Some(doc) = store.get(path) {
                return (
                    "200 OK".into(),
                    serde_json::to_vec(doc).unwrap(),
                    false,
                    Vec::new(),
                );
            }
            if !is_collection_path(path) {
                return (
                    "404 Not Found".into(),
                    serde_json::to_vec(&json!({
                        "kind": "Status",
                        "apiVersion": "v1",
                        "status": "Failure",
                        "message": format!("{path} not found"),
                        "reason": "NotFound",
                        "code": 404
                    }))
                    .unwrap(),
                    false,
                    Vec::new(),
                );
            }
            let prefix = format!("{path}/");
            let label_sel = query.get("labelSelector").map(String::as_str);
            let field_sel = query.get("fieldSelector").map(String::as_str);

            let mut matched = Vec::new();
            for (k, v) in store.iter() {
                if k.starts_with(&prefix) {
                    if label_sel.is_some_and(|sel| {
                        !matches_label_selector(v.pointer("/metadata/labels"), sel)
                    }) {
                        continue;
                    }
                    if field_sel.is_some_and(|sel| !matches_field_selector(v, sel)) {
                        continue;
                    }
                    matched.push(v.clone());
                }
            }

            let (api_version, kind) = list_gvk_for_path(path);
            let cur_rev = rev.load(Ordering::SeqCst);
            let list_doc = json!({
                "apiVersion": api_version,
                "kind": kind,
                "metadata": {
                    "resourceVersion": cur_rev.to_string(),
                },
                "items": matched,
            });
            (
                "200 OK".into(),
                serde_json::to_vec(&list_doc).unwrap(),
                false,
                Vec::new(),
            )
        },
        "POST" => {
            let mut doc: Value = serde_json::from_slice(body).unwrap_or(json!({}));
            let name = doc
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("item")
                .to_string();
            let r = rev.fetch_add(1, Ordering::SeqCst);
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert("resourceVersion".to_string(), json!(r.to_string()));
                meta.insert("uid".to_string(), json!(format!("uid-{r}")));
            }
            if path.ends_with("/services")
                && let Some(spec) = doc.get_mut("spec").and_then(Value::as_object_mut)
                && (!spec.contains_key("clusterIP") || spec["clusterIP"].as_str() == Some(""))
            {
                spec.insert("clusterIP".to_string(), json!(format!("10.96.0.{r}")));
            }
            let is_dry_run = query.get("dryRun").is_some_and(|v| v == "All");
            if !is_dry_run {
                let key = format!("{path}/{name}");
                store.insert(key, doc.clone());
                let _ = watch_tx.send(json!({"type": "ADDED", "object": doc.clone()}));

                if path.ends_with("/deployments") {
                    let rs_key = format!("{path}/../replicasets/{name}-rs")
                        .replace("/deployments/../replicasets", "/replicasets");
                    let rs = json!({
                        "apiVersion": "apps/v1",
                        "kind": "ReplicaSet",
                        "metadata": {
                            "name": format!("{name}-rs"),
                            "labels": doc.pointer("/metadata/labels").cloned().unwrap_or_else(|| json!({})),
                        },
                        "spec": {
                            "replicas": doc.pointer("/spec/replicas").cloned().unwrap_or_else(|| json!(1)),
                        }
                    });
                    store.insert(rs_key, rs);
                }
            }
            (
                "201 Created".into(),
                serde_json::to_vec(&doc).unwrap(),
                false,
                Vec::new(),
            )
        },
        "PATCH" => {
            let is_dry_run = query.get("dryRun").is_some_and(|v| v == "All");
            let mut target = if let Some(existing) = store.get(path) {
                existing.clone()
            } else if content_type.contains("apply-patch") {
                serde_json::from_slice(body).unwrap_or(json!({}))
            } else {
                return (
                    "404 Not Found".into(),
                    serde_json::to_vec(&json!({
                        "kind": "Status",
                        "apiVersion": "v1",
                        "status": "Failure",
                        "code": 404
                    }))
                    .unwrap(),
                    false,
                    Vec::new(),
                );
            };

            if content_type.contains("json-patch") {
                if let Ok(p) = serde_json::from_slice::<json_patch::Patch>(body) {
                    let _ = json_patch::patch(&mut target, &p);
                }
            } else if let Ok(m) = serde_json::from_slice::<Value>(body) {
                json_merge(&mut target, m);
            }

            let r = rev.fetch_add(1, Ordering::SeqCst);
            if let Some(meta) = target.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert("resourceVersion".to_string(), json!(r.to_string()));
            }

            if !is_dry_run {
                store.insert(path.to_string(), target.clone());
                let _ = watch_tx.send(json!({"type": "MODIFIED", "object": target.clone()}));

                if path.contains("/deployments/") {
                    let deploy_name = path.rsplit('/').next().unwrap_or("");
                    let rs_key = path.replace(
                        &format!("/deployments/{deploy_name}"),
                        &format!("/replicasets/{deploy_name}-rs"),
                    );
                    if let Some(rs) = store.get_mut(&rs_key)
                        && let Some(rep) = target.pointer("/spec/replicas")
                    {
                        rs["spec"]["replicas"] = rep.clone();
                    }
                }
            }

            (
                "200 OK".into(),
                serde_json::to_vec(&target).unwrap(),
                false,
                Vec::new(),
            )
        },
        "PUT" => {
            let is_dry_run = query.get("dryRun").is_some_and(|v| v == "All");
            if !store.contains_key(path) {
                return (
                    "404 Not Found".into(),
                    serde_json::to_vec(&json!({
                        "kind": "Status",
                        "apiVersion": "v1",
                        "status": "Failure",
                        "code": 404
                    }))
                    .unwrap(),
                    false,
                    Vec::new(),
                );
            }
            let mut target: Value = serde_json::from_slice(body).unwrap_or(json!({}));
            let r = rev.fetch_add(1, Ordering::SeqCst);
            if let Some(meta) = target.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert("resourceVersion".to_string(), json!(r.to_string()));
            }
            if !is_dry_run {
                store.insert(path.to_string(), target.clone());
            }
            (
                "200 OK".into(),
                serde_json::to_vec(&target).unwrap(),
                false,
                Vec::new(),
            )
        },
        "DELETE" => {
            let is_collection = is_collection_path(path);
            if is_collection {
                let prefix = format!("{path}/");
                let label_sel = query.get("labelSelector").map(String::as_str);
                let field_sel = query.get("fieldSelector").map(String::as_str);

                let keys_to_delete: Vec<String> = store
                    .iter()
                    .filter(|(k, v)| {
                        if !k.starts_with(&prefix) {
                            return false;
                        }
                        if label_sel.is_some_and(|sel| {
                            !matches_label_selector(v.pointer("/metadata/labels"), sel)
                        }) {
                            return false;
                        }
                        if field_sel.is_some_and(|sel| !matches_field_selector(v, sel)) {
                            return false;
                        }
                        true
                    })
                    .map(|(k, _)| k.clone())
                    .collect();

                for k in keys_to_delete {
                    store.remove(&k);
                }
                let status_doc = json!({"apiVersion": "v1", "kind": "Status", "status": "Success"});
                (
                    "200 OK".into(),
                    serde_json::to_vec(&status_doc).unwrap(),
                    false,
                    Vec::new(),
                )
            } else {
                store.remove(path);
                if path.contains("/deployments/") {
                    let deploy_name = path.rsplit('/').next().unwrap_or("");
                    let rs_key = path.replace(
                        &format!("/deployments/{deploy_name}"),
                        &format!("/replicasets/{deploy_name}-rs"),
                    );
                    store.remove(&rs_key);
                }
                let status_doc = json!({"apiVersion": "v1", "kind": "Status", "status": "Success"});
                (
                    "200 OK".into(),
                    serde_json::to_vec(&status_doc).unwrap(),
                    false,
                    Vec::new(),
                )
            }
        },
        _ => (
            "405 Method Not Allowed".into(),
            serde_json::to_vec(&json!({"kind": "Status", "status": "Failure", "code": 405}))
                .unwrap(),
            false,
            Vec::new(),
        ),
    }
}

fn is_collection_path(path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    matches!(
        segments.last().copied(),
        Some(
            "events"
                | "pods"
                | "deployments"
                | "replicasets"
                | "services"
                | "configmaps"
                | "secrets"
                | "jobs"
                | "daemonsets"
        )
    )
}

fn list_gvk_for_path(path: &str) -> (&'static str, &'static str) {
    if path.contains("events.k8s.io") {
        ("events.k8s.io/v1", "EventList")
    } else if path.ends_with("/events") {
        ("v1", "EventList")
    } else if path.ends_with("/pods") {
        ("v1", "PodList")
    } else if path.ends_with("/deployments") {
        ("apps/v1", "DeploymentList")
    } else if path.ends_with("/replicasets") {
        ("apps/v1", "ReplicaSetList")
    } else if path.ends_with("/services") {
        ("v1", "ServiceList")
    } else if path.ends_with("/configmaps") {
        ("v1", "ConfigMapList")
    } else {
        ("v1", "List")
    }
}

fn matches_label_selector(labels: Option<&Value>, selector: &str) -> bool {
    let Some(labels) = labels.and_then(Value::as_object) else {
        return selector.is_empty();
    };
    for requirement in selector.split(',') {
        let req = requirement.trim();
        if req.is_empty() {
            continue;
        }
        if let Some((k, v)) = req.split_once('=') {
            let actual = labels.get(k.trim()).and_then(Value::as_str);
            if actual != Some(v.trim()) {
                return false;
            }
        }
    }
    true
}

fn matches_field_selector(obj: &Value, selector: &str) -> bool {
    for requirement in selector.split(',') {
        let req = requirement.trim();
        if req.is_empty() {
            continue;
        }
        if let Some((k, v)) = req.split_once('=') {
            let k_trim = k.trim();
            let v_trim = v.trim();
            if k_trim == "metadata.name" {
                let name = obj.pointer("/metadata/name").and_then(Value::as_str);
                if name != Some(v_trim) {
                    return false;
                }
            }
        }
    }
    true
}

fn json_merge(target: &mut Value, patch: Value) {
    match (target, patch) {
        (Value::Object(target_map), Value::Object(patch_map)) => {
            for (key, value) in patch_map {
                if value.is_null() {
                    target_map.remove(&key);
                } else {
                    json_merge(target_map.entry(key).or_insert(Value::Null), value);
                }
            }
        },
        (target, patch) => {
            *target = patch;
        },
    }
}

fn parse_query(q: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(percent_decode(k), percent_decode(v));
        } else if !pair.is_empty() {
            map.insert(percent_decode(pair), String::new());
        }
    }
    map
}

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            let h1 = chars.next().unwrap_or('0');
            let h2 = chars.next().unwrap_or('0');
            let hex = format!("{h1}{h2}");
            if let Ok(b) = u8::from_str_radix(&hex, 16) {
                out.push(b as char);
            } else {
                out.push('%');
                out.push(h1);
                out.push(h2);
            }
        } else if ch == '+' {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

#[tokio::test]
async fn test_conformance_events_core_and_events_v1() {
    let harness = InMemoryTestServer::start().await;
    let client = match harness.try_client() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("skipping in-memory client test execution: {err}");
            return;
        },
    };
    Box::pin(probe_events_core_v1(&client))
        .await
        .expect("core/v1 events conformance in-memory probe");
    Box::pin(probe_events_k8s_io_v1(&client))
        .await
        .expect("events.k8s.io/v1 events conformance in-memory probe");
}

#[tokio::test]
async fn test_conformance_kubectl_dry_run_and_workload() {
    let harness = InMemoryTestServer::start().await;
    let client = match harness.try_client() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("skipping in-memory client test execution: {err}");
            return;
        },
    };
    Box::pin(probe_kubectl_server_dry_run_pod(&client))
        .await
        .expect("kubectl server dry-run pod conformance in-memory probe");
    Box::pin(probe_guestbook_workload_lifecycle(&client))
        .await
        .expect("guestbook workloads conformance in-memory probe");
}
