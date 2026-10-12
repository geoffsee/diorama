use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum AssetId {
    KubeApiserver,
    KubeControllerManager,
    Kubelet,
    KubeProxy,
    Kine,
    Containerd,
    #[serde(rename = "containerd-shim-runc-v2")]
    ContainerdShim,
    Crun,
    CniBridge,
    CniHostLocal,
    CniPortmap,
    CniLoopback,
    FuseOverlayfsSnapshotter,
    ImageCoredns,
    ImagePause,
    ImageLocalPath,
    ImageLocalPathHelper,
    ImagePortainerAgent,
    ImageD2k,
    ImageKubesolo,
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Identity,
    Zstd,
    Gzip,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Executable,
    Image,
}
/// Source/reference identity is not a resolved production payload pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogEntry {
    pub id: AssetId,
    pub kind: Kind,
    pub reference: &'static str,
    pub encoding: Encoding,
}
const ENTRIES: [CatalogEntry; 20] = [
    entry(
        AssetId::KubeApiserver,
        "kubernetes/v1.35.7/kube-apiserver",
        Encoding::Identity,
    ),
    entry(
        AssetId::KubeControllerManager,
        "kubernetes/v1.35.7/kube-controller-manager",
        Encoding::Identity,
    ),
    entry(
        AssetId::Kubelet,
        "kubernetes/v1.35.7/kubelet",
        Encoding::Identity,
    ),
    entry(
        AssetId::KubeProxy,
        "kubernetes/v1.35.7/kube-proxy",
        Encoding::Identity,
    ),
    entry(AssetId::Kine, "kine/v0.16.3", Encoding::Identity),
    entry(AssetId::Containerd, "containerd/v2.2.5", Encoding::Identity),
    entry(
        AssetId::ContainerdShim,
        "containerd/v2.2.5/containerd-shim-runc-v2",
        Encoding::Zstd,
    ),
    entry(AssetId::Crun, "crun/1.26", Encoding::Zstd),
    entry(
        AssetId::CniBridge,
        "containernetworking/plugins/v1.9.0/bridge",
        Encoding::Zstd,
    ),
    entry(
        AssetId::CniHostLocal,
        "containernetworking/plugins/v1.9.0/host-local",
        Encoding::Zstd,
    ),
    entry(
        AssetId::CniPortmap,
        "containernetworking/plugins/v1.9.0/portmap",
        Encoding::Zstd,
    ),
    entry(
        AssetId::CniLoopback,
        "containernetworking/plugins/v1.9.0/loopback",
        Encoding::Zstd,
    ),
    entry(
        AssetId::FuseOverlayfsSnapshotter,
        "containerd-fuse-overlayfs-grpc/v2.1.7",
        Encoding::Identity,
    ),
    image(AssetId::ImageCoredns, "docker.io/coredns/coredns:1.14.4"),
    image(AssetId::ImagePause, "docker.io/portainer/pause:latest"),
    image(
        AssetId::ImageLocalPath,
        "docker.io/rancher/local-path-provisioner:v0.0.36",
    ),
    image(
        AssetId::ImageLocalPathHelper,
        "docker.io/library/busybox:latest",
    ),
    image(
        AssetId::ImagePortainerAgent,
        "docker.io/portainer/agent:lts",
    ),
    image(AssetId::ImageD2k, "docker.io/portainer/d2k:1.2.3"),
    image(AssetId::ImageKubesolo, "ghcr.io/portainer/kubesolo:latest"),
];
const fn entry(id: AssetId, reference: &'static str, encoding: Encoding) -> CatalogEntry {
    CatalogEntry {
        id,
        kind: Kind::Executable,
        reference,
        encoding,
    }
}
const fn image(id: AssetId, reference: &'static str) -> CatalogEntry {
    CatalogEntry {
        id,
        kind: Kind::Image,
        reference,
        encoding: Encoding::Gzip,
    }
}
pub fn catalog() -> &'static [CatalogEntry] {
    &ENTRIES
}
