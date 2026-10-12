use serde_json::{Value, json};

// Reviewed suffix inventory from KubeSolo BuildEmbedded, independent of captures.
const PATHS: &[(&str, &str)] = &[
    ("AdminKubeconfigFile", "pki/admin/admin.kubeconfig"),
    ("PKIDir", "pki"),
    ("PKICADir", "pki/ca"),
    ("PKIAdminDir", "pki/admin"),
    ("PKIAPIServerDir", "pki/apiserver"),
    ("PKIControllerDir", "pki/controller-manager"),
    ("PKIKubeletDir", "pki/kubelet"),
    ("PKIWebhookDir", "pki/webhook"),
    ("PKIRequestHeaderDir", "pki/request-header"),
    ("ContainerdDir", "containerd"),
    ("ContainerdSocketFile", "containerd/containerd.sock"),
    ("ContainerdBinaryFile", "containerd/containerd"),
    ("ContainerdImagesDir", "containerd/images"),
    (
        "ContainerdShimBinaryFile",
        "containerd/containerd-shim-runc-v2",
    ),
    ("ContainerdConfigFile", "containerd/config.toml"),
    ("ContainerdRootDir", "containerd/root"),
    ("ContainerdStateDir", "containerd/state"),
    ("ContainerdRegistryConfigDir", "containerd/registry"),
    ("ContainerdCNIDir", "containerd/cni"),
    ("ContainerdCNIPluginsDir", "containerd/cni/plugins"),
    ("ContainerdCNIConfigDir", "containerd/cni/conf"),
    (
        "ContainerdCNIConfigFile",
        "containerd/cni/conf/10-bridge.conflist",
    ),
    ("CrunBinaryFile", "containerd/crun"),
    ("KubeletDir", "kubelet"),
    ("KubeletConfigDir", "kubelet/config"),
    ("KubeletConfigFile", "kubelet/config/config.yaml"),
    ("KubeletKubeConfigFile", "pki/kubelet/kubelet.kubeconfig"),
    ("KubeletPluginsDir", "kubelet/volumeplugins"),
    ("APIServerDir", "apiserver"),
    ("ServiceAccountKeyFile", "pki/apiserver/service-account.key"),
    ("KineDir", "kine/db"),
    ("KineSocketFile", "kine/db/socket"),
    ("ControllerDir", "controller-manager/config"),
    ("WebhookDir", "pki/webhook"),
    (
        "PortainerEdgeImageFile",
        "containerd/images/portainer-agent.tar.gz",
    ),
    ("CorednsImageFile", "containerd/images/coredns.tar.gz"),
    ("SandboxImageFile", "containerd/images/pause.tar.gz"),
    (
        "LocalPathProvisionerImageFile",
        "containerd/images/local-path-provisioner.tar.gz",
    ),
    ("D2KImageFile", "containerd/images/d2k.tar.gz"),
    ("LocalPathStorageDir", "local-path-storage"),
];

fn clean_join(base: &str, suffix: &str) -> String {
    let path = if base.is_empty() {
        suffix.to_owned()
    } else {
        format!("{base}/{suffix}")
    };
    let absolute = path.starts_with('/');
    let mut components = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {},
            ".." if components.last().is_some_and(|last| *last != "..") => {
                components.pop();
            },
            ".." if absolute => {},
            other => components.push(other),
        }
    }
    let prefix = if path.starts_with("//") && !path.starts_with("///") {
        "//"
    } else if absolute {
        "/"
    } else {
        ""
    };
    let joined = format!("{prefix}{}", components.join("/"));
    if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

#[allow(clippy::too_many_lines)]
pub fn expected() -> Value {
    let cases = [
        (
            "default",
            "/var/lib/kubesolo",
            "",
            "fixture-node",
            "",
            false,
        ),
        (
            "custom",
            "/fixture/a/../state//",
            "  Talos-CP-1  ",
            "unused",
            "",
            true,
        ),
        ("empty-path", "", "", "fixture-node", "", false),
        (
            "relative-path",
            "relative/../state",
            "",
            "fixture-node",
            "",
            false,
        ),
        ("raw-hostname", "/fixture", " ", " MIXED-Host ", "", false),
        ("empty-hostname", "/fixture", "", "", "", false),
        (
            "external-path",
            "/fixture",
            "",
            "fixture-node",
            "  /run/crio/crio.sock  ",
            true,
        ),
        (
            "external-url",
            "/fixture",
            "",
            "fixture-node",
            "unix:///run/a/../runtime.sock",
            false,
        ),
        (
            "whitespace-endpoint",
            "/fixture",
            "",
            "fixture-node",
            " \t ",
            false,
        ),
        (
            "relative-endpoint",
            "/fixture",
            "",
            "fixture-node",
            "run/runtime.sock",
            false,
        ),
        (
            "non-unix-endpoint",
            "/fixture",
            "",
            "fixture-node",
            "tcp://127.0.0.1:1234",
            false,
        ),
        (
            "unix-host-endpoint",
            "/fixture",
            "",
            "fixture-node",
            "unix://localhost/run/runtime.sock",
            false,
        ),
        (
            "root-endpoint",
            "/fixture",
            "",
            "fixture-node",
            "unix:///",
            false,
        ),
    ];
    Value::Array(cases.into_iter().map(|(id,path,node_name,hostname,endpoint,changed)| {
        let input = json!({"id":id,"path":path,"node_name":node_name,"hostname":hostname,
            "endpoint":endpoint,"changed":changed});
        let endpoint = endpoint.trim();
        let socket = endpoint.strip_prefix("unix://").unwrap_or(endpoint);
        let external = !endpoint.is_empty();
        let mut record = json!({"input":input,"resolved":{"URL":"","SocketPath":"","External":false},
            "error":"","embedded":null});
        if external && !socket.starts_with('/') {
            record["error"] = format!("invalid container runtime endpoint {endpoint:?}: expected an absolute socket path or a unix:// URL, for example unix:///run/crio/crio.sock").into();
            return record;
        }
        if external {
            record["resolved"] = json!({"URL":format!("unix://{socket}"),"SocketPath":socket,"External":true});
        }
        let join = |suffix: &str| clean_join(path, suffix);
        let mut value = json!({});
        for (key,suffix) in PATHS { value[key] = join(suffix).into(); }
        for (key,component) in [("KubeletCerts","kubelet"),("APIServerCerts","apiserver"),
            ("ControllerManagerCerts","controller-manager"),("AdminCerts","admin"),("WebhookCerts","webhook")] {
            value[key] = json!({"CACert":join("pki/ca/ca.crt"),
                "Cert":join(&format!("pki/{component}/{component}.crt")),
                "Key":join(&format!("pki/{component}/{component}.key"))});
        }
        value["CACerts"] = json!({"Cert":join("pki/ca/ca.crt"),"Key":join("pki/ca/ca.key")});
        value["RequestHeaderCerts"] = json!({
            "CACert":join("pki/request-header/request-header-ca.crt"),
            "CAKey":join("pki/request-header/request-header-ca.key"),
            "ClientCert":join("pki/request-header/request-header-client.crt"),
            "ClientKey":join("pki/request-header/request-header-client.key")});
        value["D2KCerts"] = json!({"CACert":join("pki/ca/ca.crt"),
            "ServerCert":join("pki/d2k/server.crt"),"ServerKey":join("pki/d2k/server.key"),
            "ClientCert":join("pki/d2k/client.crt"),"ClientKey":join("pki/d2k/client.key")});
        let runtime_socket = if external { socket.to_owned() } else { join("containerd/containerd.sock") };
        let normalized = node_name.trim().to_lowercase();
        let node = if normalized.is_empty() { hostname } else { &normalized };
        let dynamic = json!({"NodeName":node,"NodeIP":if changed{"2001:db8::10"}else{"192.0.2.10"},
            "NodeIPSpecified":changed,"MTU":if changed{1280}else{1450},"MTUSpecified":changed,
            "RuntimeExternal":external,"RuntimeEndpoint":format!("unix://{runtime_socket}"),
            "RuntimeSocketPath":runtime_socket,"RuntimeCgroupDriver":"",
            "APIServerExtraSANs":if changed{json!(["fixture.example","192.0.2.55"])}else{Value::Null},
            "LoadBalancer":!changed,"LoadBalancerIP":if changed{"2001:db8::11"}else{"192.0.2.11"},
            "LocalStorage":!changed,"IsPortainerEdge":changed,
            "PortainerEdgeImage":if changed{"fixture.invalid/agent:custom"}else{"docker.io/portainer/agent:lts"},
            "ContainerMode":changed,"DisableIPv6":changed,"D2K":changed,
            "D2KNamespace":if changed{"fixture-d2k"}else{"d2k"},
            "Metrics":{"enabled":changed,"bindAddress":if changed{"127.0.0.1:19105"}else{"127.0.0.1:9105"}},
            "CPUManager":if changed{json!({"policy":"static","reservedCPUs":"0-1","policyOptions":{"full-pcpus-only":"true"}})}
                else{json!({"policy":"none","reservedCPUs":""})},
            "SystemReserved":if changed{json!({"cpu":"200m","memory":"128Mi"})}else{Value::Null}});
        if let (Some(target),Some(fields)) = (value.as_object_mut(),dynamic.as_object()) {
            target.extend(fields.clone());
        }
        record["embedded"] = value;
        record
    }).collect())
}
