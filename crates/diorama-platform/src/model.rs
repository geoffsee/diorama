use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation<T> {
    Present(T),
    Absent,
    Unknown(ProbeFailure),
}
impl<T> Observation<T> {
    pub fn as_ref(&self) -> Observation<&T> {
        match self {
            Self::Present(value) => Observation::Present(value),
            Self::Absent => Observation::Absent,
            Self::Unknown(error) => Observation::Unknown(*error),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeFailure {
    PermissionDenied,
    Io,
    TooLarge,
    NotRegular,
    Malformed,
    UnsupportedPlatform,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    Amd64,
    Arm64,
    ArmV7,
    Riscv64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Libc {
    Glibc,
    Musl,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeTarget {
    pub architecture: Architecture,
    pub libc: Libc,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutableAbi {
    pub os: String,
    pub architecture: String,
    /// Rust target environment; independent from observed host linker landmarks.
    pub environment: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelIdentity {
    pub os: String,
    pub release: String,
    pub machine: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Privileges {
    pub real_uid: u32,
    pub effective_uid: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitSystem {
    Systemd,
    Upstart,
    OpenRc,
    S6,
    Runit,
    SysV,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Environment {
    Container,
    Embedded,
    Arm,
    Standard,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgroupVersion {
    V1,
    V2,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cgroups {
    pub version: CgroupVersion,
    pub controllers: Vec<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    File,
    Directory,
    Symlink,
    Other,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathFacts {
    pub kind: PathKind,
    pub unix_mode: Option<u32>,
    pub symlink_target: Option<PathBuf>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestedPath {
    /// Exact caller spelling; neither canonicalized nor created.
    pub path: PathBuf,
    pub facts: Observation<PathFacts>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountFact {
    pub mount_point: PathBuf,
    pub filesystem: String,
    pub mount_read_only: bool,
    pub superblock_read_only: bool,
    pub propagation: Vec<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeLimits {
    pub bytes_per_file: usize,
    pub directory_entries: usize,
    pub requested_paths: usize,
}
impl Default for ProbeLimits {
    fn default() -> Self {
        Self {
            bytes_per_file: 1024 * 1024,
            directory_entries: 4096,
            requested_paths: 64,
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscoveryRequest {
    pub paths: Vec<PathBuf>,
    pub limits: ProbeLimits,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostEvidence {
    pub executable: ExecutableAbi,
    pub kernel: Observation<KernelIdentity>,
    pub privileges: Observation<Privileges>,
    pub hostname: Observation<String>,
    pub container_environment_set: bool,
    /// Fixed, public system paths only; failures are not silently collapsed into absence.
    pub landmarks: BTreeMap<String, Observation<bool>>,
    pub musl_linkers: Observation<Vec<String>>,
    pub files: BTreeMap<String, Observation<String>>,
    pub requested_paths: Vec<RequestedPath>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailableModule {
    /// Relative to /lib/modules/<running-kernel-release>; index presence is not loadability.
    pub path: PathBuf,
    pub dependencies: Vec<PathBuf>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostCapabilities {
    pub init: Observation<InitSystem>,
    /// Baseline installer classification; distinct from the runtime's indicators.
    pub installer_environment: Observation<Environment>,
    pub runtime_container: Observation<bool>,
    /// A linker-presence heuristic, not proof of ABI compatibility.
    pub host_libc_hint: Observation<Libc>,
    pub cgroups: Observation<Cgroups>,
    pub loaded_modules: Observation<Vec<String>>,
    pub available_modules: Observation<Vec<AvailableModule>>,
    pub builtin_modules: Observation<Vec<PathBuf>>,
    pub mounts: Observation<Vec<MountFact>>,
}
