//! kube-rs probes against one privileged diorama container.
//!
//! ```text
//! cargo test --locked -p diorama-conformance --test suite -- --ignored --nocapture
//! ```
//!
//! The image defaults to `localhost/diorama:latest`. Build it with
//! `build/image/dev-image.sh`. Every probe runs. The test fails with the full list.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use std::collections::BTreeMap;

use futures::StreamExt;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet};
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{
    ConfigMap, Event, Namespace, PersistentVolumeClaim, Pod, Secret, Service,
};
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
use serde_json::json;
use tokio::io::AsyncReadExt;
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
                "image {image} is missing; run build/image/dev-image.sh"
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
            "-v",
            "/lib/modules:/lib/modules:ro",
            "-p",
            "127.0.0.1::6443",
            "--entrypoint",
            "/bin/sh",
        ]);
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
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("podman");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    let fallback = PathBuf::from("/opt/podman/bin/podman");
    if fallback.is_file() {
        return Ok(fallback);
    }
    Err("podman is not on PATH or at /opt/podman/bin/podman".into())
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
