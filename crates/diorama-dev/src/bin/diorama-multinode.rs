//! Root-only disposable Linux qualification. Foreign processes are operator-owned.
use diorama_dev::Result;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn run(args: &[&str]) -> Result<String> {
    let output = Command::new(args[0]).args(&args[1..]).output()?;
    if !output.status.success() {
        return Err(format!(
            "{} failed: {}",
            args[0],
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
fn require(ok: bool, text: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(text.into()) }
}
fn wait(mut check: impl FnMut() -> Result<bool>, description: &str, seconds: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut last = String::new();
    while Instant::now() < deadline {
        match check() {
            Ok(true) => return Ok(()),
            Err(e) => last = e.to_string(),
            Ok(false) => {},
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(format!("timed out: {description}; {last}").into())
}
fn write(path: &Path, text: impl AsRef<[u8]>) -> Result<()> {
    fs::create_dir_all(path.parent().ok_or("missing parent")?)?;
    let mut options = fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(text.as_ref())?;
    Ok(())
}
fn doc(path: &Path, value: &Value) -> Result<()> {
    write(path, serde_json::to_vec_pretty(value)?)
}
struct Fixture {
    args: BTreeMap<String, String>,
    root: PathBuf,
    prefix: String,
    units: Vec<String>,
    containers: Vec<String>,
    foreign_units: Vec<String>,
    network: bool,
    cp_unit: String,
    bootstrap: Value,
    encoded: String,
    report: Value,
    stage: &'static str,
}
impl Fixture {
    fn new(args: BTreeMap<String, String>) -> Result<Self> {
        let root = PathBuf::from(&args["state"]);
        fs::create_dir(&root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            report: json!({"result":"FAIL","state":root,"checks":[]}),
            args,
            root,
            prefix: format!("diorama-multi-{}", std::process::id()),
            units: vec![],
            containers: vec![],
            foreign_units: vec![],
            network: false,
            cp_unit: String::new(),
            bootstrap: Value::Null,
            encoded: String::new(),
            stage: "prerequisites",
        })
    }
    fn path(&self, relative: &str) -> String {
        self.root.join(relative).display().to_string()
    }
    fn stage(&mut self, name: &'static str) {
        self.stage = name;
        eprintln!("{name}");
    }
    fn passed(&mut self, text: &str) {
        self.report["checks"]
            .as_array_mut()
            .unwrap()
            .push(json!(text));
    }
    fn api(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let ca = self.path("cp/pki/ca.crt");
        let cert = self.path("cp/pki/admin.crt");
        let key = self.path("cp/pki/admin.key");
        let url = format!("https://{}:6443{path}", self.args["gateway"]);
        let input = self.path("request.json");
        let data = format!("@{input}");
        let mut args = vec![
            "curl",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "10",
            "--cacert",
            &ca,
            "--cert",
            &cert,
            "--key",
            &key,
            "-X",
            method,
            &url,
        ];
        if let Some(body) = body {
            doc(Path::new(&input), &body)?;
            args.extend([
                "-H",
                if method == "PATCH" {
                    "Content-Type: application/merge-patch+json"
                } else {
                    "Content-Type: application/json"
                },
                "--data-binary",
                &data,
            ]);
        }
        let output = run(&args)?;
        Ok(serde_json::from_str(&output).unwrap_or_else(|_| json!(output)))
    }
    fn unit(&mut self, suffix: &str, args: &[&str], properties: &[String]) -> Result<String> {
        let unit = format!("{}-{suffix}", self.prefix);
        let flag = format!("--unit={unit}");
        let mut command = vec!["systemd-run", &flag, "--collect"];
        command.extend(properties.iter().map(String::as_str));
        command.extend(args);
        run(&command)?;
        self.units.push(unit.clone());
        Ok(unit)
    }
    fn start_cp(&mut self) -> Result<()> {
        let binary = self.args["diorama"].clone();
        let config = format!("--config={}", self.path("cp.json"));
        self.cp_unit = self.unit(
            "cp",
            &[&binary, &config],
            &[format!(
                "--property=InaccessiblePaths={}",
                self.path("foreign")
            )],
        )?;
        wait(
            || self.api("GET", "/readyz", None).map(|_| true),
            "API startup",
            180,
        )
    }
    fn image(&mut self) -> Result<String> {
        if let Some(image) = self.args.get("ordinary-image") {
            return Ok(image.clone());
        }
        self.stage("ordinary fixture image");
        let context = self.root.join("image");
        fs::create_dir(&context)?;
        fs::copy(&self.args["diorama"], context.join("diorama"))?;
        write(
            &context.join("Containerfile"),
            "FROM registry.fedoraproject.org/fedora:44\nRUN dnf -y install containerd runc containernetworking-plugins cri-tools iptables iproute util-linux procps-ng && dnf clean all\nCOPY diorama /usr/local/bin/diorama\nCMD [\"sleep\", \"infinity\"]\n",
        )?;
        let image = format!("localhost/{}:fixture", self.prefix);
        run(&[
            "podman",
            "build",
            "-t",
            &image,
            &context.display().to_string(),
        ])?;
        Ok(image)
    }
    fn bootstrap(&mut self, image: &str) -> Result<()> {
        self.stage("control plane and pinned scheduler");
        fs::create_dir(self.root.join("foreign"))?;
        fs::create_dir_all(self.root.join("cp/bin"))?;
        fs::copy(
            &self.args["scheduler"],
            self.root.join("cp/bin/kube-scheduler"),
        )?;
        run(&[
            "podman",
            "network",
            "create",
            "--subnet",
            &self.args["subnet"],
            "--gateway",
            &self.args["gateway"],
            &self.prefix,
        ])?;
        self.network = true;
        // Netavark creates the bridge only when a container attaches.
        let anchor = format!("{}-network", self.prefix);
        run(&[
            "podman",
            "run",
            "-d",
            "--name",
            &anchor,
            "--network",
            &self.prefix,
            image,
        ])?;
        self.containers.push(anchor);
        doc(
            &self.root.join("cp.json"),
            &json!({"apiVersion":"kubesolo.io/v1alpha1","kind":"Config","path":self.path("cp"),"kubernetes":{"role":"control-plane","nodeName":"fixture-control-plane","disableLocalKubelet":true},"network":{"nodeIP":self.args["gateway"],"podAddressPool":self.args["pod-pool"]},"storage":{"localPath":{"enabled":true}}}),
        )?;
        self.start_cp()?;
        wait(
            || {
                self.api(
                    "GET",
                    "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases/kube-scheduler",
                    None,
                )
                .map(|_| true)
            },
            "scheduler leadership",
            180,
        )?;
        require(
            self.api("GET", "/api/v1/nodes", None)?["items"]
                .as_array()
                .is_some_and(Vec::is_empty),
            "control plane invented a Node",
        )?;
        self.encoded = run(&[
            &self.args["ctl"],
            "token",
            "create",
            "--role=worker",
            "--expiry=1h",
            "--kubeconfig",
            &self.path("cp/pki/admin.kubeconfig"),
        ])?;
        write(&self.root.join("worker.token"), &self.encoded)?;
        self.bootstrap = serde_json::from_str(&run(&[
            &self.args["ctl"],
            "token",
            "export",
            "--token-file",
            &self.path("worker.token"),
        ])?)?;
        self.passed(
            "control plane and scheduler bootstrap without Nodes, CNI, DNS, or Service routing",
        );
        Ok(())
    }
    fn ordinary(&mut self, image: &str, index: usize) -> Result<String> {
        let name = format!("ordinary-{index}");
        let state = self.root.join(&name);
        fs::create_dir(&state)?;
        let ip = format!(
            "{}.{}",
            self.args["gateway"]
                .rsplit_once('.')
                .ok_or("IPv4 gateway required")?
                .0,
            10 + index
        );
        write(&state.join("join.token"), &self.encoded)?;
        doc(
            &state.join("config.json"),
            &json!({"apiVersion":"kubesolo.io/v1alpha1","kind":"Config","path":"/state/node","kubernetes":{"role":"worker","nodeName":name,"tokenFile":"/state/join.token"},"network":{"nodeIP":ip},"runtime":{"endpoint":"unix:///run/containerd/containerd.sock","containerMode":true}}),
        )?;
        let container = format!("{}-{name}", self.prefix);
        run(&[
            "podman",
            "run",
            "-d",
            "--name",
            &container,
            "--hostname",
            &name,
            "--privileged",
            "--security-opt=label=disable",
            "--cgroupns=private",
            "--network",
            &self.prefix,
            "--ip",
            &ip,
            "-v",
            &format!("{}:/state", state.display()),
            image,
        ])?;
        self.containers.push(container.clone());
        run(&[
            "podman",
            "cp",
            &self.args["diorama"],
            &format!("{container}:/usr/local/bin/diorama"),
        ])?;
        // The container's disposable daemon config belongs to this fixture.
        run(&[
            "podman",
            "exec",
            "-d",
            &container,
            "sh",
            "-c",
            r"mkdir -p /opt/diorama/cni/bin /etc/diorama/cni/net.d /etc/containerd
cp /usr/libexec/cni/loopback /opt/diorama/cni/bin/loopback
cat > /etc/containerd/config.toml <<'CONFIG'
version = 3
root = '/state/containerd'
[plugins.'io.containerd.cri.v1.runtime'.cni]
  bin_dirs = ['/opt/diorama/cni/bin']
  conf_dir = '/etc/diorama/cni/net.d'
CONFIG
containerd --config /etc/containerd/config.toml > /state/containerd.log 2>&1 &
exec diorama --config=/state/config.json > /state/diorama.log 2>&1
",
        ])?;
        Ok(name)
    }
    fn foreign(&mut self, index: usize) -> Result<String> {
        let name = format!("foreign-{index}");
        let state = self.root.join("foreign").join(&name);
        fs::create_dir_all(state.join("logs"))?;
        doc(&state.join("bootstrap.json"), &self.bootstrap)?;
        write(&state.join("resolv.conf"), "")?;
        let path = |s: &str| state.join(s).display().to_string();
        doc(
            &state.join("config.json"),
            &json!({"apiVersion":"kubelet.config.k8s.io/v1beta1","kind":"KubeletConfiguration","containerRuntimeEndpoint":format!("unix://{}",path("cri.sock")),"imageServiceEndpoint":format!("unix://{}",path("cri.sock")),"podLogsDir":path("logs"),"resolvConf":path("resolv.conf"),"syncFrequency":"1s","runtimeRequestTimeout":"10s","enableServer":false,"healthzPort":0,"rotateCertificates":true,"authentication":{"anonymous":{"enabled":false},"webhook":{"enabled":false}},"authorization":{"mode":"AlwaysAllow"},"enableControllerAttachDetach":false,"makeIPTablesUtilChains":false,"hairpinMode":"none","cgroupsPerQOS":false,"cgroupDriver":"cgroupfs","enforceNodeAllocatable":[],"failSwapOn":false,"cpuCFSQuota":false,"singleProcessOOMKill":true,"imageGCHighThresholdPercent":100,"imageGCLowThresholdPercent":99,"evictionHard":{},"clusterDNS":["10.43.0.10"],"clusterDomain":"cluster.local","featureGates":{"EventedPLEG":false,"PodAndContainerStatsFromCRI":false}}),
        )?;
        let runtime = self.args["foreign-runtime"].clone();
        let artifacts = self.args["foreign-artifacts"].clone();
        let unit = self.unit(
            &format!("{name}-cri"),
            &[
                &runtime,
                &path("cri.sock"),
                &artifacts,
                &path("logs"),
                &self.path("foreign"),
            ],
            &["--property=MemorySwapMax=0".into()],
        )?;
        self.foreign_units.push(unit);
        let kubelet = self.args["foreign-kubelet"].clone();
        let unit = self.unit(
            &format!("{name}-kubelet"),
            &[
                &kubelet,
                &format!("--config={}", path("config.json")),
                &format!("--bootstrap-kubeconfig={}", path("bootstrap.json")),
                &format!("--kubeconfig={}", path("kubeconfig")),
                &format!("--root-dir={}", path("kubelet")),
                &format!("--cert-dir={}", path("pki")),
                &format!("--hostname-override={name}"),
                "--node-labels=diorama.io/runtime=foreign",
                "--register-with-taints=diorama.io/foreign-runtime=true:NoSchedule",
                "--v=2",
            ],
            &[],
        )?;
        self.foreign_units.push(unit);
        Ok(name)
    }
    fn node(&self, name: &str) -> Result<Value> {
        self.api("GET", &format!("/api/v1/nodes/{name}"), None)
    }
    fn pod(&self, name: &str) -> Result<Value> {
        self.api(
            "GET",
            &format!("/api/v1/namespaces/default/pods/{name}"),
            None,
        )
    }
    fn lease(&self, name: &str) -> Result<Value> {
        self.api(
            "GET",
            &format!("/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/{name}"),
            None,
        )
    }
    fn running(&self, name: &str) -> Result<bool> {
        Ok(self.pod(name)?["status"]["phase"] == "Running")
    }
    fn registration(&mut self, names: &[String]) -> Result<()> {
        for name in names {
            wait(
                || Ok(self.node(name)?.pointer("/status/nodeInfo").is_some()),
                &format!("{name} status"),
                180,
            )?;
            wait(
                || Ok(self.lease(name)?.pointer("/spec/renewTime").is_some()),
                &format!("{name} Lease"),
                60,
            )?;
            let initial = self.lease(name)?["spec"]["renewTime"].clone();
            wait(
                || Ok(self.lease(name)?["spec"]["renewTime"] != initial),
                &format!("{name} advancing Lease"),
                60,
            )?;
            self.passed(&format!(
                "real registration, status, and advancing Lease: {name}"
            ));
        }

        Ok(())
    }
    fn cordon(&self, name: &str, value: bool) -> Result<()> {
        self.api(
            "PATCH",
            &format!("/api/v1/nodes/{name}"),
            Some(json!({"spec":{"unschedulable":value}})),
        )?;
        Ok(())
    }
    fn create_pod(&self, name: &str, spec: &Value) -> Result<()> {
        self.api("POST","/api/v1/namespaces/default/pods",Some(json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":name,"labels":{"fixture-web":name}},"spec":spec})))?;
        Ok(())
    }
    fn foreign_pod(&self, name: &str, overrides: &Value) -> Result<()> {
        let mut spec = json!({"nodeSelector":{"diorama.io/runtime":"foreign"},"tolerations":[{"key":"diorama.io/foreign-runtime","operator":"Equal","value":"true","effect":"NoSchedule"}],"hostNetwork":true,"dnsPolicy":"None","restartPolicy":"Never","terminationGracePeriodSeconds":1,"automountServiceAccountToken":false,"enableServiceLinks":false,"securityContext":{"seccompProfile":{"type":"Unconfined"}},"volumes":[{"name":"hosts","hostPath":{"path":self.path("foreign/hosts"),"type":"File"}}],"containers":[{"name":"probe","image":"isolate.local/probe:v1","imagePullPolicy":"Always","args":["spin"],"terminationMessagePolicy":"FallbackToLogsOnError","volumeMounts":[{"name":"hosts","mountPath":"/etc/hosts","readOnly":true}]}]});
        spec.as_object_mut().unwrap().extend(
            overrides
                .as_object()
                .ok_or("expected overrides object")?
                .clone(),
        );
        self.create_pod(name, &spec)
    }
    fn placement(&mut self, ordinary: &[String]) -> Result<()> {
        for namespace in ["kube-system", "local-path-storage"] {
            let pods = self.api("GET", &format!("/api/v1/namespaces/{namespace}/pods"), None)?;
            let items = pods["items"].as_array().ok_or("missing system Pods")?;
            require(!items.is_empty(), "controllers created no system Pods")?;
            for pod in items {
                require(
                    pod["spec"]["nodeSelector"]["diorama.io/runtime"] == "ordinary",
                    "system Pod lacks ordinary constraint",
                )?;
                if let Some(node) = pod["spec"]["nodeName"].as_str().filter(|n| !n.is_empty()) {
                    require(
                        ordinary.iter().any(|n| n == node),
                        "system Pod assigned to foreign node",
                    )?;
                }
            }
        }
        self.passed("system workloads select ordinary nodes only");
        Ok(())
    }
    fn exec_pod(&self, name: &str, command: &[&str]) -> Result<String> {
        let pod = self.pod(name)?;
        let node = pod["spec"]["nodeName"].as_str().ok_or("unbound Pod")?;
        let id = pod["status"]["containerStatuses"][0]["containerID"]
            .as_str()
            .ok_or("no container ID")?
            .split_once("://")
            .ok_or("invalid container ID")?
            .1;
        let container = format!("{}-{node}", self.prefix);
        let mut args = vec![
            "podman",
            "exec",
            &container,
            "crictl",
            "--runtime-endpoint=unix:///run/containerd/containerd.sock",
            "exec",
            id,
        ];
        args.extend(command);
        run(&args)
    }
    fn ordinary_checks(&mut self, ordinary: &[String]) -> Result<()> {
        self.stage("ordinary cross-node networking and local storage");
        for node in ordinary {
            wait(
                || {
                    Ok(self.node(node)?["status"]["conditions"]
                        .as_array()
                        .is_some_and(|cs| {
                            cs.iter()
                                .any(|c| c["type"] == "Ready" && c["status"] == "True")
                        }))
                },
                &format!("{node} readiness"),
                600,
            )?;
        }
        for (index, node) in ordinary.iter().take(2).enumerate() {
            let name = format!("net-{index}");
            self.create_pod(&name,&json!({"nodeSelector":{"diorama.io/runtime":"ordinary","kubernetes.io/hostname":node},"containers":[{"name":"web","image":"docker.io/library/busybox:1.37","command":["sh","-c","mkdir -p /www; echo cross-node > /www/index.html; httpd -f -p 8080 -h /www"]}]}))?;
            wait(|| self.running(&name), &name, 180)?;
        }
        self.api("POST","/api/v1/namespaces/default/services",Some(json!({"metadata":{"name":"fixture-web"},"spec":{"selector":{"fixture-web":"net-0"},"ports":[{"port":8080,"targetPort":8080}]}})))?;
        let pod = self.pod("net-0")?;
        let address = pod["status"]["podIP"].as_str().ok_or("missing Pod IP")?;
        let service = self.api(
            "GET",
            "/api/v1/namespaces/default/services/fixture-web",
            None,
        )?;
        let service_ip = service["spec"]["clusterIP"]
            .as_str()
            .ok_or("missing Service IP")?;
        for (ip, desc) in [
            (address, "cross-node Pod traffic"),
            (service_ip, "Service routing"),
        ] {
            wait(
                || {
                    Ok(self
                        .exec_pod(
                            "net-1",
                            &["wget", "-T", "5", "-qO-", &format!("http://{ip}:8080")],
                        )?
                        .contains("cross-node"))
                },
                desc,
                180,
            )?;
            self.passed(desc);
        }
        wait(
            || {
                Ok(self
                    .exec_pod(
                        "net-1",
                        &[
                            "nslookup",
                            "kubernetes.default.svc.cluster.local",
                            "10.43.0.10",
                        ],
                    )?
                    .contains("10.43.0.1"))
            },
            "CoreDNS resolution",
            180,
        )?;
        self.passed("CoreDNS resolution at 10.43.0.10");
        self.api("POST","/api/v1/namespaces/default/persistentvolumeclaims",Some(json!({"metadata":{"name":"local-disk"},"spec":{"storageClassName":"local-path","accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"16Mi"}}}})))?;
        self.create_pod("storage-proof",&json!({"nodeSelector":{"diorama.io/runtime":"ordinary","kubernetes.io/hostname":ordinary[1]},"containers":[{"name":"writer","image":"docker.io/library/busybox:1.37","command":["sh","-c","echo node-local > /data/proof; sleep 3600"],"volumeMounts":[{"name":"data","mountPath":"/data"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"local-disk"}}]}))?;
        wait(
            || self.running("storage-proof"),
            "node-local provisioning",
            300,
        )?;
        let pvc = self.api(
            "GET",
            "/api/v1/namespaces/default/persistentvolumeclaims/local-disk",
            None,
        )?;
        require(
            pvc["metadata"]["annotations"]["volume.kubernetes.io/selected-node"] == ordinary[1],
            "incorrect PVC placement",
        )?;
        require(
            self.exec_pod("storage-proof", &["cat", "/data/proof"])?
                .contains("node-local"),
            "missing volume contents",
        )?;
        require(
            !self.root.join("cp/local-path-storage").exists(),
            "volume directory was provisioned on the control plane",
        )?;
        self.passed("scheduler-selected node-local PVC contains the written data");
        Ok(())
    }
    fn foreign_checks(&mut self, foreign: &[String]) -> Result<String> {
        self.stage("foreign API Pods on alternate workers");
        for name in &foreign[1..] {
            self.cordon(name, true)?;
        }
        self.foreign_pod("foreign-first", &json!({}))?;
        wait(
            || self.running("foreign-first"),
            "first foreign workload",
            180,
        )?;
        require(
            self.pod("foreign-first")?["spec"]["nodeName"] == foreign[0],
            "incorrect foreign placement",
        )?;
        self.cordon(&foreign[0], true)?;
        self.cordon(&foreign[1], false)?;
        self.foreign_pod("foreign-second", &json!({}))?;
        wait(
            || self.running("foreign-second"),
            "second foreign workload",
            180,
        )?;
        require(
            self.pod("foreign-second")?["spec"]["nodeName"] == foreign[1],
            "incorrect alternate placement",
        )?;
        self.passed("compatible API workload executes on either initial foreign node as availability changes");
        let before = fs::read(self.root.join("cp.json"))?;
        let added = self.foreign(foreign.len() + 1)?;
        self.registration(std::slice::from_ref(&added))?;
        require(
            before == fs::read(self.root.join("cp.json"))?,
            "cluster configuration changed to add worker",
        )?;
        self.passed("additional foreign worker joins without cluster configuration changes");
        self.stage("foreign DNS negative controls");
        self.foreign_pod(
            "foreign-clusterfirst",
            &json!({"hostNetwork":false,"dnsPolicy":"ClusterFirst"}),
        )?;
        self.foreign_pod(
            "foreign-dns-control",
            &json!({"dnsConfig":{"nameservers":["10.43.0.10"]}}),
        )?;
        for name in ["foreign-clusterfirst", "foreign-dns-control"] {
            wait(|| self.dns_rejected(name), name, 180)?;
            require(
                !self.running(name)?,
                "foreign sandbox accepted nonempty DNS",
            )?;
        }
        self.passed("foreign ClusterFirst and isolated nonempty-DNS cases fail");
        Ok(added)
    }
    fn dns_rejected(&self, name: &str) -> Result<bool> {
        let events = self.api("GET", "/api/v1/namespaces/default/events", None)?;
        Ok(events["items"].as_array().is_some_and(|events| {
            events.iter().any(|event| {
                event["involvedObject"]["name"] == name
                    && event["message"]
                        .as_str()
                        .is_some_and(|message| message.to_lowercase().contains("dns"))
            })
        }))
    }
    fn pid(unit: &str) -> Result<String> {
        run(&["systemctl", "show", unit, "--property=MainPID", "--value"])
    }
    fn ownership(&mut self, names: &[String]) -> Result<()> {
        self.stage("ownership and API interruption recovery");
        let scheduler_path =
            "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases/kube-scheduler";
        let leader = self.api("GET", scheduler_path, None)?["spec"]["holderIdentity"].clone();
        let owners = self
            .foreign_units
            .iter()
            .map(|u| Ok((u.clone(), Self::pid(u)?)))
            .collect::<Result<Vec<_>>>()?;
        let status = Command::new("nsenter")
            .args([
                "-t",
                &Self::pid(&self.cp_unit)?,
                "-m",
                "test",
                "-S",
                &self.path("foreign/foreign-1/cri.sock"),
            ])
            .status()?;
        require(!status.success(), "foreign socket accessible to diorama")?;
        for node in names.iter().filter(|node| node.starts_with("ordinary-")) {
            let status = Command::new("podman")
                .args([
                    "exec",
                    &format!("{}-{node}", self.prefix),
                    "test",
                    "-S",
                    &self.path("foreign/foreign-1/cri.sock"),
                ])
                .status()?;
            require(
                !status.success(),
                "foreign socket accessible to ordinary worker",
            )?;
        }
        run(&["systemctl", "stop", &self.cp_unit])?;
        for (unit, pid) in &owners {
            require(
                pid != "0" && Self::pid(unit)? == *pid,
                "foreign process terminated with diorama",
            )?;
        }
        self.start_cp()?;
        self.registration(names)?;
        wait(
            || {
                let lease = self.api("GET", scheduler_path, None)?;
                Ok(lease["spec"]["holderIdentity"].is_string()
                    && lease["spec"]["holderIdentity"] != leader)
            },
            "new scheduler acquires leadership after restart",
            90,
        )?;
        for (unit, pid) in &owners {
            require(
                Self::pid(unit)? == *pid,
                "foreign process restarted with diorama",
            )?;
        }
        self.passed(
            "foreign processes survive diorama restart; sockets inaccessible; API clients and scheduler leadership recover",
        );
        Ok(())
    }
    fn qualify(&mut self) -> Result<()> {
        let image = self.image()?;
        self.bootstrap(&image)?;
        self.stage("independent ordinary and foreign joins");
        let ordinary_count = self.args["ordinary-nodes"].parse()?;
        let foreign_count = self.args["foreign-nodes"].parse()?;
        let ordinary = (1..=ordinary_count)
            .map(|n| self.ordinary(&image, n))
            .collect::<Result<Vec<_>>>()?;
        write(&self.root.join("foreign/hosts"), "127.0.0.1 localhost\n")?;
        let foreign = (1..=foreign_count)
            .map(|n| self.foreign(n))
            .collect::<Result<Vec<_>>>()?;
        let mut all = ordinary.clone();
        all.extend(foreign.clone());
        self.registration(&all)?;
        self.placement(&ordinary)?;
        all.push(self.foreign_checks(&foreign)?);
        self.ownership(&all)?;
        self.ordinary_checks(&ordinary)?;
        self.placement(&ordinary)?;
        let allocations = self.api("GET", "/apis/cilium.io/v2/ciliumnodes", None)?;
        for node in &all {
            if ordinary.contains(node) {
                continue;
            }
            let registration = self.node(node)?;
            require(
                registration["spec"]["podCIDR"]
                    .as_str()
                    .is_none_or(str::is_empty)
                    && registration["spec"]["podCIDRs"]
                        .as_array()
                        .is_none_or(Vec::is_empty)
                    && !allocations["items"].as_array().is_some_and(|items| {
                        items.iter().any(|item| item["metadata"]["name"] == *node)
                    }),
                "foreign worker received ordinary PodCIDR allocation",
            )?;
        }
        self.passed("foreign workers receive no ordinary PodCIDR allocation");
        self.report["result"] = json!("PASS");
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        for container in self
            .containers
            .iter()
            .filter(|name| name.contains("-ordinary-"))
        {
            let Ok(output) = run(&[
                "podman",
                "exec",
                container,
                "crictl",
                "--runtime-endpoint=unix:///run/containerd/containerd.sock",
                "ps",
                "-a",
                "-o",
                "json",
            ]) else {
                continue;
            };
            let Ok(containers) = serde_json::from_str::<Value>(&output) else {
                continue;
            };
            for entry in containers["containers"].as_array().into_iter().flatten() {
                let Some(id) = entry["id"]
                    .as_str()
                    .filter(|id| id.bytes().all(|b| b.is_ascii_hexdigit()))
                else {
                    continue;
                };
                if let Ok(log) = run(&[
                    "podman",
                    "exec",
                    container,
                    "crictl",
                    "--runtime-endpoint=unix:///run/containerd/containerd.sock",
                    "logs",
                    "--tail=150",
                    id,
                ]) {
                    write(
                        &self
                            .root
                            .join("container-logs")
                            .join(format!("{container}-{id}.log")),
                        log,
                    )?;
                }
            }
        }
        for unit in &self.units {
            if let Ok(output) = run(&["journalctl", "-u", unit, "--no-pager", "-n", "250"]) {
                write(&self.root.join(format!("{unit}.log")), output)?;
            }
        }
        for resource in ["nodes", "pods", "events"] {
            if let Ok(value) = self.api("GET", &format!("/api/v1/{resource}"), None) {
                doc(&self.root.join(format!("{resource}.json")), &value)?;
            }
        }
        doc(&self.root.join("results.json"), &self.report)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Only this operator fixture owns foreign units. The application never
        // receives their unit names, process IDs, or CRI socket paths.
        for unit in self.units.iter().rev() {
            let _ = Command::new("systemctl")
                .args(["stop", unit])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        for container in &self.containers {
            let _ = Command::new("podman")
                .args(["rm", "-f", container])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        if self.network {
            let _ = Command::new("podman")
                .args(["network", "rm", &self.prefix])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}
fn arguments() -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::from([
        ("ordinary-nodes".into(), "2".into()),
        ("foreign-nodes".into(), "2".into()),
        ("gateway".into(), "172.30.250.1".into()),
        ("subnet".into(), "172.30.250.0/24".into()),
        ("pod-pool".into(), "10.42.0.0/16".into()),
    ]);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let key = arg.strip_prefix("--").ok_or("expected --option value")?;
        require(
            [
                "diorama",
                "ctl",
                "scheduler",
                "foreign-runtime",
                "foreign-artifacts",
                "foreign-kubelet",
                "state",
                "ordinary-image",
                "ordinary-nodes",
                "foreign-nodes",
                "gateway",
                "subnet",
                "pod-pool",
            ]
            .contains(&key),
            "unknown option",
        )?;
        result.insert(key.into(), args.next().ok_or("missing option value")?);
    }
    for key in [
        "diorama",
        "ctl",
        "scheduler",
        "foreign-runtime",
        "foreign-artifacts",
        "foreign-kubelet",
    ] {
        let path =
            Path::new(result.get(key).ok_or_else(|| format!("missing --{key}"))?).canonicalize()?;
        result.insert(key.into(), path.display().to_string());
    }
    let state = std::env::current_dir()?.join(
        result
            .get("state")
            .ok_or("missing --state (must be a new directory)")?,
    );
    result.insert("state".into(), state.display().to_string());
    require(
        result["ordinary-nodes"].parse::<usize>()? >= 2
            && result["foreign-nodes"].parse::<usize>()? >= 2,
        "need at least two ordinary and two foreign workers",
    )?;
    Ok(result)
}
fn main() -> Result<()> {
    let args = arguments()?;
    require(
        std::env::consts::OS == "linux" && run(&["id", "-u"])? == "0",
        "requires root on disposable Linux with systemd, cgroup v2, Podman, and curl",
    )?;
    let mut fixture = Fixture::new(args)?;
    let result = fixture.qualify();
    if let Err(error) = &result {
        fixture.report["failed_stage"] = json!(fixture.stage);
        fixture.report["failure"] = json!(error.to_string());
    }
    fixture.finish()?;
    println!("{}", serde_json::to_string_pretty(&fixture.report)?);
    result
}
