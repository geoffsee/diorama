//! Migration failure rehearsal and operator recovery across supported starting versions and stages.
//!
//! Epic E30 / Issue #125 (Gate C14):
//! - Rehearses migration failure by interrupting supported transition stages across starting versions
//!   (`v1.1.8`, `v1.2.0`, `v1.3.0`, `v1.3.1-v1.3.3`) on disposable installations.
//! - Executes operator recovery/rollback using retained receipts and pre-upgrade backups.
//! - Verifies recovery restores promised state across all 5 domains (Configuration, PKI, Datastore,
//!   Workloads, PV Storage) and client access (both YAML and JSON kubeconfig formats).
//! - Refuses to rely on missing, incomplete, or corrupted backups, retaining diagnostics and disk state.
//! - Documents operator runbook steps, retained diagnostics, and known limitations for each version.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use dioramactl::upgrade::{
    HostBackend, RecoveryOutcome, Runner, find_active_receipt, recover_interrupted_upgrade,
    run_upgrade, seal_backup, validate_backup_integrity,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use serde::{Deserialize, Serialize};
use tempfile::{TempDir, tempdir};

use crate::state_transition::datastore::compute_file_sha256;
use crate::state_transition::pki::{KubeconfigFormat, parse_kubeconfig, verify_cert_chain};
use crate::state_transition::storage::{assert_pv_storage_preserved, scan_pv_storage};
use crate::state_transition::versions::SupportedStartingVersion;

/// Supported transition stages that can be interrupted during migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TransitionStage {
    /// Pre-transition parameter/version validation (old service running, zero mutations).
    Validation,
    /// Target artifact preparation/download (old service running, zero state mutations).
    Preparation,
    /// Service quiesce / stop before snapshot (old service fails to stop, restart attempted).
    Quiesce,
    /// State snapshot capture to backup directory (snapshot fails, old service restarts).
    Snapshot,
    /// Receipt marker persistence (.upgrade-pending write fails).
    ReceiptPending,
    /// Artifact replacement (binary/container overwritten or killed midway).
    ArtifactReplacement,
    /// Legacy service flag migration or configuration update.
    ConfigMigration,
    /// New service start (binary fails/crashes, datastore dirty writes).
    ServiceStart,
    /// Commit receipt staging (.upgrade-committing marker present).
    ReceiptCommitting,
    /// Post-start commit (cleanup of old container/units).
    Commit,
    /// Post-commit receipt cleanup (.upgrade-completed marker present).
    PostCommitCleanup,
}

impl TransitionStage {
    /// All interruptible stages in chronological execution order.
    pub const ALL: [Self; 11] = [
        Self::Validation,
        Self::Preparation,
        Self::Quiesce,
        Self::Snapshot,
        Self::ReceiptPending,
        Self::ArtifactReplacement,
        Self::ConfigMigration,
        Self::ServiceStart,
        Self::ReceiptCommitting,
        Self::Commit,
        Self::PostCommitCleanup,
    ];

    /// Human-readable name of the transition stage.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Validation => "Validation",
            Self::Preparation => "Preparation",
            Self::Quiesce => "Quiesce",
            Self::Snapshot => "Snapshot",
            Self::ReceiptPending => "ReceiptPending",
            Self::ArtifactReplacement => "ArtifactReplacement",
            Self::ConfigMigration => "ConfigMigration",
            Self::ServiceStart => "ServiceStart",
            Self::ReceiptCommitting => "ReceiptCommitting",
            Self::Commit => "Commit",
            Self::PostCommitCleanup => "PostCommitCleanup",
        }
    }

    /// Whether this stage occurs after the old service is quiesced.
    #[must_use]
    pub const fn is_post_quiesce(self) -> bool {
        !matches!(self, Self::Validation | Self::Preparation)
    }

    /// Whether this stage occurs after pre-upgrade backup creation.
    #[must_use]
    pub const fn has_backup(self) -> bool {
        matches!(
            self,
            Self::ReceiptPending
                | Self::ArtifactReplacement
                | Self::ConfigMigration
                | Self::ServiceStart
                | Self::ReceiptCommitting
                | Self::Commit
                | Self::PostCommitCleanup
        )
    }

    /// Whether this stage performs mutations on the active installation.
    #[must_use]
    pub const fn is_mutating(self) -> bool {
        matches!(
            self,
            Self::ArtifactReplacement
                | Self::ConfigMigration
                | Self::ServiceStart
                | Self::ReceiptCommitting
                | Self::Commit
                | Self::PostCommitCleanup
        )
    }

    /// Whether interruption at this stage leaves the installation requiring rollback to pre-upgrade state.
    #[must_use]
    pub const fn requires_rollback(self) -> bool {
        matches!(
            self,
            Self::ArtifactReplacement | Self::ConfigMigration | Self::ServiceStart
        )
    }
}

/// Simulated condition of the pre-upgrade backup during recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupCondition {
    /// Backup exists, has 0700 permissions, and contains complete PKI and datastore state.
    Valid,
    /// Backup directory is missing or deleted before recovery.
    Missing,
    /// Backup directory is corrupted (e.g. missing PKI or datastore).
    Corrupted,
    /// Backup path is a symlink pointing elsewhere.
    Symlink,
}

/// Known operational limitations documented for a given starting version.
#[must_use]
pub fn version_recovery_limitations(version: SupportedStartingVersion) -> Vec<String> {
    let mut lims = Vec::new();
    match version {
        SupportedStartingVersion::V1_1_8 => {
            lims.push("Legacy CLI flags in service file; --config=/etc/diorama-kube/config.yaml is unsupported in this version.".into());
            lims.push("Recovery removes any migration-created /etc/diorama-kube/config.yaml and restores original service unit arguments.".into());
            lims.push("Systemd daemon-reload is mandatory after service unit restoration.".into());
        },
        SupportedStartingVersion::V1_2_0 => {
            lims.push(
                "Legacy CLI flags in service file; seamless upgrades introduced in Go baseline."
                    .into(),
            );
            lims.push("Recovery cleans up generated YAML config and restores original service unit arguments.".into());
            lims.push(
                "External runtime configuration remains in service arguments, not config file."
                    .into(),
            );
        },
        SupportedStartingVersion::V1_3_0 => {
            lims.push("YAML configuration /etc/diorama-kube/config.yaml supported (MinConfigFileVersion gate).".into());
            lims.push(
                "Rollback restores /etc/diorama-kube/config.yaml with 0600 mode permissions."
                    .into(),
            );
            lims.push("Service unit maintains --config=/etc/diorama-kube/config.yaml flag.".into());
        },
        SupportedStartingVersion::V1_3_1
        | SupportedStartingVersion::V1_3_2
        | SupportedStartingVersion::V1_3_3 => {
            lims.push("YAML configuration supported; baseline KubeSolo commit 2ef1c47.".into());
            lims.push(
                "External CRI runtime sockets and containerd options preserved across rollback."
                    .into(),
            );
            lims.push(
                "Rollback preserves runtime ownership boundaries and restores config file.".into(),
            );
        },
    }
    lims.push(
        "Downtime window: service is quiesced during transition; downtime is non-zero.".into(),
    );
    lims.push(
        "Datastore format: raw SQLite is NOT interchangeable with native RUBXSNP1 snapshots."
            .into(),
    );
    lims.push("Backup integrity: recovery strictly requires an intact, isolated (0700) pre-upgrade backup.".into());
    lims
}

/// A disposable installation layout representing a specific starting version.
#[derive(Debug)]
pub struct DisposableInstallation {
    pub dir: TempDir,
    pub version: SupportedStartingVersion,
    pub data_path: PathBuf,
    pub config_path: PathBuf,
    pub service_path: PathBuf,
    pub binary_path: PathBuf,
    pub staged_binary_path: PathBuf,
    pub kubeconfig_path: PathBuf,
    pub kubeconfig_format: KubeconfigFormat,
    pub manifests_dir: PathBuf,
    pub storage_dir: PathBuf,

    // Baseline records for verification
    pub baseline_ca_cert_pem: String,
    pub baseline_ca_key_pem: String,
    pub baseline_sa_key_pem: String,
    pub baseline_client_cert_pem: String,
    pub baseline_client_key_pem: String,
    pub baseline_kine_db_sha256: String,
    pub baseline_kine_wal_sha256: String,
    pub baseline_service_unit_content: String,
    pub baseline_config_content: Option<String>,
    pub storage_baseline_dir: PathBuf,
}

impl DisposableInstallation {
    /// Constructs and initializes a disposable installation for the given starting version.
    #[allow(clippy::too_many_lines)]
    pub fn new(
        version: SupportedStartingVersion,
        kcfg_format: KubeconfigFormat,
    ) -> io::Result<Self> {
        let dir = tempdir()?;
        let root = dir.path();

        let data_path = root.join("var/lib/diorama-kube");
        let etc_kubesolo = root.join("etc/diorama-kube");
        let config_path = etc_kubesolo.join("config.yaml");
        let systemd_dir = root.join("etc/systemd/system");
        let service_path = systemd_dir.join("kubesolo.service");
        let bin_dir = root.join("usr/local/bin");
        let binary_path = bin_dir.join("kubesolo");
        let staged_binary_path = root.join("staged/kubesolo-staged");
        let kubeconfig_path = etc_kubesolo.join("admin.kubeconfig");
        let manifests_dir = root.join("etc/kubernetes/manifests");
        let storage_dir = data_path.join("local-path-storage/pvc-data");
        let storage_baseline_dir = root.join("storage-baseline");

        fs::create_dir_all(&data_path)?;
        fs::create_dir_all(&etc_kubesolo)?;
        fs::create_dir_all(&systemd_dir)?;
        fs::create_dir_all(&bin_dir)?;
        fs::create_dir_all(root.join("staged"))?;
        fs::create_dir_all(&manifests_dir)?;
        fs::create_dir_all(&storage_dir)?;
        fs::create_dir_all(&storage_baseline_dir)?;

        // 1. Binaries
        let old_bin_content = format!(
            "#!/bin/sh\n# KubeSolo binary {}\necho {}\n",
            version.as_str(),
            version.as_str()
        );
        fs::write(&binary_path, &old_bin_content)?;
        let new_bin_content = "#!/bin/sh\n# Diorama binary v1.4.0\necho v1.4.0\n";
        fs::write(&staged_binary_path, new_bin_content)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&binary_path, fs::Permissions::from_mode(0o755))?;
            fs::set_permissions(&staged_binary_path, fs::Permissions::from_mode(0o755))?;
        }

        // 2. Configuration & Service unit
        let service_content;
        let config_content;
        if version.requires_flag_migration() {
            // v1.1.8 and v1.2.0: legacy flags in service file, NO config file
            service_content = format!(
                "[Unit]\nDescription=kubesolo service\n\n[Service]\nExecStart={} --node-ip=10.0.0.10 --disable-ipv6 --portainer-edge-id=test-edge-id --portainer-edge-key=test-secret-key\n",
                binary_path.display()
            );
            fs::write(&service_path, &service_content)?;
            config_content = None;
        } else {
            // v1.3.0+: config file present and referenced in service file
            let raw_yaml = "apiVersion: kubesolo.io/v1alpha1\nkind: KubeSoloConfiguration\nnetwork:\n  nodeIP: 10.0.0.10\n  disableIPv6: true\nportainer:\n  edgeID: test-edge-id\n  edgeKey: test-secret-key\n";
            fs::write(&config_path, raw_yaml)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;
            }
            config_content = Some(raw_yaml.to_string());
            service_content = format!(
                "[Unit]\nDescription=kubesolo service\n\n[Service]\nExecStart={} --config={}\n",
                binary_path.display(),
                config_path.display()
            );
            fs::write(&service_path, &service_content)?;
        }

        // 3. PKI generation
        let pki_dir = data_path.join("pki");
        fs::create_dir_all(&pki_dir)?;

        let ca_key =
            KeyPair::generate().map_err(|e| io::Error::other(format!("ca key error: {e}")))?;
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "kubesolo-ca");
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .map_err(|e| io::Error::other(format!("ca cert error: {e}")))?;

        let ca_cert_pem = ca_cert.pem();
        let ca_key_pem = ca_key.serialize_pem();
        fs::write(pki_dir.join("ca.crt"), &ca_cert_pem)?;
        fs::write(pki_dir.join("ca.key"), &ca_key_pem)?;

        // ServiceAccount key
        let sa_key =
            KeyPair::generate().map_err(|e| io::Error::other(format!("sa key error: {e}")))?;
        let sa_key_pem = sa_key.serialize_pem();
        let sa_pub_pem = sa_key.public_key_pem();
        fs::write(pki_dir.join("service-account.key"), &sa_key_pem)?;
        fs::write(pki_dir.join("service-account.pub"), &sa_pub_pem)?;

        // Admin client cert signed by CA
        let admin_key =
            KeyPair::generate().map_err(|e| io::Error::other(format!("admin key error: {e}")))?;
        let mut admin_params = CertificateParams::default();
        admin_params
            .distinguished_name
            .push(DnType::CommonName, "admin");
        admin_params
            .distinguished_name
            .push(DnType::OrganizationName, "system:masters");
        admin_params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        admin_params
            .key_usages
            .push(KeyUsagePurpose::KeyEncipherment);
        let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key)
            .map_err(|e| io::Error::other(format!("ca issuer error: {e}")))?;
        let admin_cert = admin_params
            .signed_by(&admin_key, &issuer)
            .map_err(|e| io::Error::other(format!("admin cert error: {e}")))?;

        let admin_cert_pem = admin_cert.pem();
        let admin_key_pem = admin_key.serialize_pem();
        fs::write(pki_dir.join("admin.crt"), &admin_cert_pem)?;
        fs::write(pki_dir.join("admin.key"), &admin_key_pem)?;

        // 4. Kubeconfig generation (supports YAML and JSON)
        let ca_b64 = BASE64_STANDARD.encode(ca_cert_pem.as_bytes());
        let client_cert_b64 = BASE64_STANDARD.encode(admin_cert_pem.as_bytes());
        let client_key_b64 = BASE64_STANDARD.encode(admin_key_pem.as_bytes());

        match kcfg_format {
            KubeconfigFormat::Yaml => {
                let yaml_kcfg = format!(
                    "apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: {ca_b64}\n    server: https://127.0.0.1:6443\n  name: kubesolo\ncontexts:\n- context:\n    cluster: kubesolo\n    user: admin\n  name: admin@kubesolo\ncurrent-context: admin@kubesolo\nkind: Config\npreferences: {{}}\nusers:\n- name: admin\n  user:\n    client-certificate-data: {client_cert_b64}\n    client-key-data: {client_key_b64}\n"
                );
                fs::write(&kubeconfig_path, yaml_kcfg)?;
            },
            KubeconfigFormat::Json => {
                let json_kcfg = serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Config",
                    "current-context": "admin@kubesolo",
                    "clusters": [{
                        "name": "kubesolo",
                        "cluster": {
                            "server": "https://127.0.0.1:6443",
                            "certificate-authority-data": ca_b64
                        }
                    }],
                    "contexts": [{
                        "name": "admin@kubesolo",
                        "context": {
                            "cluster": "kubesolo",
                            "user": "admin"
                        }
                    }],
                    "users": [{
                        "name": "admin",
                        "user": {
                            "client-certificate-data": client_cert_b64,
                            "client-key-data": client_key_b64
                        }
                    }]
                });
                fs::write(
                    &kubeconfig_path,
                    serde_json::to_string_pretty(&json_kcfg).unwrap(),
                )?;
            },
        }

        // 5. Datastore state (Kine SQLite db and WAL)
        let kine_db_dir = data_path.join("kine/db");
        fs::create_dir_all(&kine_db_dir)?;
        let state_db_path = kine_db_dir.join("state.db");
        let state_wal_path = kine_db_dir.join("state.db-wal");

        let db_bytes = format!(
            "SQLite format 3\0-- deterministic kine test database for {}",
            version.as_str()
        )
        .into_bytes();
        let wal_bytes = b"kine-sqlite-wal-index-record-001\n".to_vec();
        fs::write(&state_db_path, &db_bytes)?;
        fs::write(&state_wal_path, &wal_bytes)?;

        let db_sha = compute_file_sha256(&state_db_path)?;
        let wal_sha = compute_file_sha256(&state_wal_path)?;

        // 6. Manifests
        let apiserver_manifest = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: kube-apiserver\n  namespace: kube-system\nspec:\n  containers:\n  - name: kube-apiserver\n    image: registry.k8s.io/kube-apiserver:v1.35.7\n";
        fs::write(
            manifests_dir.join("kube-apiserver.yaml"),
            apiserver_manifest,
        )?;

        // 7. Storage
        let vol_file1 = storage_dir.join("test-app-data.txt");
        let vol_file2 = storage_dir.join("database-store.bin");
        fs::write(&vol_file1, "application state persisted data\n")?;
        fs::write(&vol_file2, [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04])?;

        let base_file1 = storage_baseline_dir.join("test-app-data.txt");
        let base_file2 = storage_baseline_dir.join("database-store.bin");
        fs::write(&base_file1, "application state persisted data\n")?;
        fs::write(
            &base_file2,
            [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04],
        )?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&vol_file1, fs::Permissions::from_mode(0o644))?;
            fs::set_permissions(&vol_file2, fs::Permissions::from_mode(0o600))?;
            fs::set_permissions(&base_file1, fs::Permissions::from_mode(0o644))?;
            fs::set_permissions(&base_file2, fs::Permissions::from_mode(0o600))?;
        }

        Ok(Self {
            dir,
            version,
            data_path,
            config_path,
            service_path,
            binary_path,
            staged_binary_path,
            kubeconfig_path,
            kubeconfig_format: kcfg_format,
            manifests_dir,
            storage_dir,
            baseline_ca_cert_pem: ca_cert_pem,
            baseline_ca_key_pem: ca_key_pem,
            baseline_sa_key_pem: sa_key_pem,
            baseline_client_cert_pem: admin_cert_pem,
            baseline_client_key_pem: admin_key_pem,
            baseline_kine_db_sha256: db_sha,
            baseline_kine_wal_sha256: wal_sha,
            baseline_service_unit_content: service_content,
            baseline_config_content: config_content,
            storage_baseline_dir,
        })
    }
}

/// Scenario configuration for a migration rehearsal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RehearsalScenario {
    pub starting_version: SupportedStartingVersion,
    pub target_version: String,
    pub kubeconfig_format: KubeconfigFormat,
    pub interrupt_stage: TransitionStage,
    pub backup_condition: BackupCondition,
}

/// Complete report of an executed recovery rehearsal.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Independent preservation checks in a serialized evidence record, not mutually exclusive states.
#[allow(clippy::struct_excessive_bools)]
pub struct RehearsalResult {
    pub scenario: RehearsalScenario,
    pub stage_interrupted: TransitionStage,
    pub receipt_observed_before_recovery: Option<String>,
    pub backup_validated: bool,
    pub recovery_executed: bool,
    pub recovery_refused_as_expected: bool,
    pub recovery_diagnostic: Option<String>,
    pub config_restored: bool,
    pub pki_restored: bool,
    pub client_access_verified: bool,
    pub datastore_restored: bool,
    pub storage_restored: bool,
    pub manifests_restored: bool,
    pub receipts_cleaned: bool,
    pub overall_success: bool,
    pub backend_calls: Vec<String>,
    pub retained_backup_count: usize,
    pub known_limitations: Vec<String>,
}

#[derive(Debug, Default)]
struct MockRunner {
    pub calls: Vec<String>,
    pub version: String,
}

impl Runner for MockRunner {
    fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
        let call = format!("{program} {}", args.join(" "));
        self.calls.push(call);
        if program.ends_with("kubesolo") && args.first().is_some_and(|a| a == "--version") {
            return Ok(format!("kubesolo version {}", self.version));
        }
        Ok("ok".into())
    }
}

/// Executes a failure rehearsal and operator recovery workflow on a disposable installation.
pub fn run_rehearsal(scenario: &RehearsalScenario) -> io::Result<RehearsalResult> {
    run_rehearsal_inner(scenario, false)
}

#[allow(clippy::too_many_lines)]
fn run_rehearsal_inner(
    scenario: &RehearsalScenario,
    damage_retained_state: bool,
) -> io::Result<RehearsalResult> {
    let inst = DisposableInstallation::new(scenario.starting_version, scenario.kubeconfig_format)?;

    let mut runner = MockRunner {
        calls: Vec::new(),
        version: scenario.starting_version.as_str().to_string(),
    };

    let mut backend = HostBackend {
        binary: inst.binary_path.clone(),
        staged: inst.staged_binary_path.clone(),
        service: "kubesolo".into(),
        runner: &mut runner,
        systemd: true,
        service_file: Some(inst.service_path.clone()),
        legacy_config: Some(inst.config_path.clone()),
    };

    let stage = scenario.interrupt_stage;
    let manifests_before = scan_pv_storage(&inst.manifests_dir)?;
    let storage_before = scan_pv_storage(&inst.storage_dir)?;
    let pki_before = scan_pv_storage(&inst.data_path.join("pki"))?;
    let datastore_before = scan_pv_storage(&inst.data_path.join("kine/db"))?;
    let binary_before = fs::read(&inst.binary_path)?;
    let mut early_failure_verified = false;
    let mut receipt_observed = None;
    let mut backup_validated = false;
    let mut recovery_executed = false;
    let mut recovery_refused = false;
    let mut diagnostic = None;

    // Execute staged failure simulation
    let backup_dir = inst.data_path.join(format!(
        "backups/pre-upgrade-{}-123456",
        scenario.starting_version.as_str()
    ));

    match stage {
        TransitionStage::Validation => {
            diagnostic = Some(
                run_upgrade(
                    &mut backend,
                    &inst.data_path,
                    Some(&inst.config_path),
                    "invalid-version",
                    1,
                    &mut Vec::new(),
                )
                .unwrap_err()
                .to_string(),
            );
            early_failure_verified = backend.runner.calls.len() == 1;
        },
        TransitionStage::Preparation => {
            // Missing staged binary
            fs::remove_file(&inst.staged_binary_path)?;
            diagnostic = Some(
                run_upgrade(
                    &mut backend,
                    &inst.data_path,
                    Some(&inst.config_path),
                    &scenario.target_version,
                    1,
                    &mut Vec::new(),
                )
                .unwrap_err()
                .to_string(),
            );
            early_failure_verified = backend.runner.calls.len() == 1;
        },
        TransitionStage::Quiesce => {
            let mut failing = EarlyFailureBackend {
                host: &mut backend,
                stage,
                data: &inst.data_path,
            };
            diagnostic = Some(
                run_upgrade(
                    &mut failing,
                    &inst.data_path,
                    Some(&inst.config_path),
                    &scenario.target_version,
                    1,
                    &mut Vec::new(),
                )
                .unwrap_err()
                .to_string(),
            );
            early_failure_verified = backend
                .runner
                .calls
                .iter()
                .any(|c| c == "systemctl start kubesolo");
        },
        TransitionStage::Snapshot => {
            let mut failing = EarlyFailureBackend {
                host: &mut backend,
                stage,
                data: &inst.data_path,
            };
            diagnostic = Some(
                run_upgrade(
                    &mut failing,
                    &inst.data_path,
                    Some(&inst.config_path),
                    &scenario.target_version,
                    1,
                    &mut Vec::new(),
                )
                .unwrap_err()
                .to_string(),
            );
            early_failure_verified = backend
                .runner
                .calls
                .iter()
                .any(|c| c == "systemctl start kubesolo")
                && fs::read_dir(inst.data_path.join("backups"))?
                    .next()
                    .is_none();
        },
        TransitionStage::ReceiptPending => {
            let mut failing = EarlyFailureBackend {
                host: &mut backend,
                stage,
                data: &inst.data_path,
            };
            diagnostic = Some(
                run_upgrade(
                    &mut failing,
                    &inst.data_path,
                    Some(&inst.config_path),
                    &scenario.target_version,
                    1,
                    &mut Vec::new(),
                )
                .unwrap_err()
                .to_string(),
            );
            // The injected directory obstructs persistence; no valid receipt exists.
            fs::remove_dir(inst.data_path.join(".upgrade-pending"))?;
            let retained: Vec<_> =
                fs::read_dir(inst.data_path.join("backups"))?.collect::<io::Result<_>>()?;
            backup_validated =
                retained.len() == 1 && validate_backup_integrity(&retained[0].path()).is_ok();
            early_failure_verified = backend
                .runner
                .calls
                .iter()
                .any(|c| c == "systemctl start kubesolo")
                && backup_validated;
        },
        TransitionStage::ArtifactReplacement => {
            // Snapshot captured, receipt written, binary overwritten with corrupted file
            create_pre_upgrade_backup(&inst, &backup_dir)?;
            write_pending_receipt(
                &inst.data_path,
                scenario.starting_version.as_str(),
                &scenario.target_version,
                &backup_dir,
            )?;
            fs::write(&inst.binary_path, "corrupted-binary-mid-replacement")?;
            receipt_observed = Some(".upgrade-pending".into());
        },
        TransitionStage::ConfigMigration => {
            // Snapshot captured, receipt written, binary replaced, but config migration interrupted
            create_pre_upgrade_backup(&inst, &backup_dir)?;
            write_pending_receipt(
                &inst.data_path,
                scenario.starting_version.as_str(),
                &scenario.target_version,
                &backup_dir,
            )?;
            fs::write(&inst.binary_path, "new-binary")?;
            if scenario.starting_version.requires_flag_migration() {
                // Partial corrupt config created
                fs::write(&inst.config_path, "invalid: yaml: syntax: [unclosed")?;
            }
            receipt_observed = Some(".upgrade-pending".into());
        },
        TransitionStage::ServiceStart => {
            // Snapshot captured, binary replaced, but startup crashed and left dirty datastore writes
            create_pre_upgrade_backup(&inst, &backup_dir)?;
            write_pending_receipt(
                &inst.data_path,
                scenario.starting_version.as_str(),
                &scenario.target_version,
                &backup_dir,
            )?;
            fs::write(&inst.binary_path, "new-binary-that-crashes")?;
            // Dirty writes in datastore
            fs::write(
                inst.data_path.join("kine/db/state.db"),
                "dirty-partial-database-write",
            )?;
            fs::write(inst.data_path.join("pki/ca.key"), "dirty-key-write")?;
            receipt_observed = Some(".upgrade-pending".into());
        },
        TransitionStage::ReceiptCommitting => {
            // Target started, .upgrade-committing written, interrupted before commit
            create_pre_upgrade_backup(&inst, &backup_dir)?;
            fs::write(&inst.binary_path, "committed target binary")?;
            let committing = inst.data_path.join(".upgrade-committing");
            let rec = format!(
                "from={}\ntarget={}\nbackup={}\n",
                scenario.starting_version.as_str(),
                scenario.target_version,
                backup_dir.display()
            );
            fs::write(&committing, rec)?;
            receipt_observed = Some(".upgrade-committing".into());
        },
        TransitionStage::Commit => {
            create_pre_upgrade_backup(&inst, &backup_dir)?;
            fs::write(&inst.binary_path, "committed target binary")?;
            let committing = inst.data_path.join(".upgrade-completed");
            let rec = format!(
                "from={}\ntarget={}\nbackup={}\n",
                scenario.starting_version.as_str(),
                scenario.target_version,
                backup_dir.display()
            );
            fs::write(&committing, rec)?;
            receipt_observed = Some(".upgrade-completed".into());
        },
        TransitionStage::PostCommitCleanup => {
            fs::write(&inst.binary_path, "committed target binary")?;
            // Completed marker left on disk
            let completed = inst.data_path.join(".upgrade-completed");
            fs::write(
                &completed,
                format!(
                    "from={}\ntarget={}\nbackup={}\n",
                    scenario.starting_version.as_str(),
                    scenario.target_version,
                    backup_dir.display()
                ),
            )?;
            receipt_observed = Some(".upgrade-completed".into());
        },
    }

    // Apply backup condition modifications
    if stage.is_mutating() && stage != TransitionStage::PostCommitCleanup {
        match scenario.backup_condition {
            BackupCondition::Valid => {
                backup_validated = validate_backup_integrity(&backup_dir).is_ok();
            },
            BackupCondition::Missing => {
                if backup_dir.exists() {
                    fs::remove_dir_all(&backup_dir)?;
                }
                backup_validated = false;
            },
            BackupCondition::Corrupted => {
                // Remove kine/db state directory from backup to corrupt it
                let db_in_backup = backup_dir.join("kine/db");
                if db_in_backup.exists() {
                    fs::remove_dir_all(&db_in_backup)?;
                }
                backup_validated = false;
            },
            BackupCondition::Symlink => {
                #[cfg(unix)]
                {
                    if backup_dir.exists() {
                        fs::remove_dir_all(&backup_dir)?;
                    }
                    let foreign = inst.dir.path().join("foreign-target");
                    fs::create_dir_all(&foreign)?;
                    std::os::unix::fs::symlink(&foreign, &backup_dir)?;
                }
                backup_validated = false;
            },
        }
    }

    // Refusal must retain exact disk evidence, including active receipt bytes.
    if damage_retained_state {
        fs::write(inst.storage_dir.join("test-app-data.txt"), "lost PV data")?;
        fs::write(
            inst.manifests_dir.join("kube-apiserver.yaml"),
            "changed manifest",
        )?;
    }
    let before_recovery = disk_evidence(&inst)?;
    let calls_before_recovery = backend.runner.calls.len();
    // Execute operator recovery
    let mut recovery_stderr = Vec::new();
    let recovery_result = recover_interrupted_upgrade(
        &mut backend,
        &inst.data_path,
        Some(&inst.config_path),
        &mut recovery_stderr,
    );

    match recovery_result {
        Ok(RecoveryOutcome::RolledBack { .. } | RecoveryOutcome::Committed { .. }) => {
            recovery_executed = true;
        },
        Ok(RecoveryOutcome::AlreadyClean) => {
            // For pre-mutation stages, installation remained clean
            if !stage.is_mutating() {
                recovery_executed = true;
            }
        },
        Err(err) => {
            diagnostic = Some(err.to_string());
            if matches!(
                scenario.backup_condition,
                BackupCondition::Missing | BackupCondition::Corrupted | BackupCondition::Symlink
            ) {
                recovery_refused = true;
            }
        },
    }

    // State domain verifications
    let mut config_restored = true;
    let mut pki_restored = true;
    let mut client_access_verified = true;
    let mut datastore_restored = true;
    let mut storage_restored = true;
    let mut manifests_restored = true;
    let mut receipts_cleaned = true;

    if recovery_executed
        && stage.has_backup()
        && scenario.backup_condition == BackupCondition::Valid
    {
        // 1. Config domain:
        let current_service = fs::read_to_string(&inst.service_path)?;
        if scenario.starting_version.requires_flag_migration() {
            // Original service unit restored, any created config.yaml deleted
            config_restored =
                current_service == inst.baseline_service_unit_content && !inst.config_path.exists();
        } else {
            // Original config.yaml restored with 0600 mode
            if let Some(expected_yaml) = &inst.baseline_config_content {
                let actual_yaml = fs::read_to_string(&inst.config_path)?;
                config_restored = actual_yaml == *expected_yaml
                    && current_service == inst.baseline_service_unit_content;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let meta = fs::metadata(&inst.config_path)?;
                    config_restored =
                        config_restored && ((meta.permissions().mode() & 0o777) == 0o600);
                }
            }
        }

        // 2. PKI domain:
        let cur_ca_cert = fs::read_to_string(inst.data_path.join("pki/ca.crt"))?;
        let cur_ca_key = fs::read_to_string(inst.data_path.join("pki/ca.key"))?;
        let service_account_key =
            fs::read_to_string(inst.data_path.join("pki/service-account.key"))?;
        pki_restored = cur_ca_cert == inst.baseline_ca_cert_pem
            && cur_ca_key == inst.baseline_ca_key_pem
            && service_account_key == inst.baseline_sa_key_pem;

        // 3. Client access domain: dual YAML/JSON kubeconfig verification
        let kcfg_bytes = fs::read(&inst.kubeconfig_path)?;
        let parsed_kcfg = parse_kubeconfig(&kcfg_bytes).map_err(io::Error::other)?;
        client_access_verified = parsed_kcfg.format == scenario.kubeconfig_format
            && parsed_kcfg.server == "https://127.0.0.1:6443"
            && verify_cert_chain(cur_ca_cert.as_bytes(), &parsed_kcfg.client_cert_bytes)
                .unwrap_or(false);

        // 4. Datastore domain: bit-for-bit SHA-256 match
        let cur_db_sha = compute_file_sha256(&inst.data_path.join("kine/db/state.db"))?;
        let cur_wal_sha = compute_file_sha256(&inst.data_path.join("kine/db/state.db-wal"))?;
        datastore_restored = cur_db_sha == inst.baseline_kine_db_sha256
            && cur_wal_sha == inst.baseline_kine_wal_sha256;

        // 5. Storage domain: PV files and checksums match
        let pv_assert = assert_pv_storage_preserved(&inst.storage_baseline_dir, &inst.storage_dir)?;
        storage_restored = pv_assert.all_checksums_match && pv_assert.all_permissions_match;

        // 6. Manifests domain:
        manifests_restored = scan_pv_storage(&inst.manifests_dir)? == manifests_before;
        storage_restored =
            storage_restored && scan_pv_storage(&inst.storage_dir)? == storage_before;

        // 7. Receipts cleaned:
        receipts_cleaned = find_active_receipt(&inst.data_path)?.is_none();
    } else if recovery_refused {
        // Recovery was refused due to corrupt/missing backup: receipts and diagnostics MUST be retained!
        receipts_cleaned = false; // Intentionally retained for operator inspection
        recovery_refused = disk_evidence(&inst)? == before_recovery
            && backend.runner.calls.len() == calls_before_recovery;
    }

    let overall_success = if scenario.backup_condition == BackupCondition::Valid {
        if stage.requires_rollback() {
            recovery_executed
                && config_restored
                && pki_restored
                && client_access_verified
                && datastore_restored
                && storage_restored
                && manifests_restored
                && receipts_cleaned
        } else if stage.is_mutating() {
            // Commit or post-commit stage: target is committed, receipts are cleaned
            recovery_executed
                && receipts_cleaned
                && fs::read(&inst.binary_path)? == b"committed target binary"
                && !backend.runner.calls.iter().any(|c| c.contains(" stop "))
        } else {
            // Pre-mutation stage: installation was never mutated
            recovery_executed
                && receipts_cleaned
                && early_failure_verified
                && fs::read(&inst.binary_path)? == binary_before
                && scan_pv_storage(&inst.data_path.join("pki"))? == pki_before
                && scan_pv_storage(&inst.data_path.join("kine/db"))? == datastore_before
                && scan_pv_storage(&inst.manifests_dir)? == manifests_before
                && scan_pv_storage(&inst.storage_dir)? == storage_before
        }
    } else {
        // Invalid backup: recovery must refuse without mutating
        recovery_refused
    };

    let retained_backup_count = match fs::read_dir(inst.data_path.join("backups")) {
        Ok(entries) => entries.collect::<io::Result<Vec<_>>>()?.len(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e),
    };
    Ok(RehearsalResult {
        scenario: scenario.clone(),
        stage_interrupted: stage,
        receipt_observed_before_recovery: receipt_observed,
        backup_validated,
        recovery_executed,
        recovery_refused_as_expected: recovery_refused,
        recovery_diagnostic: diagnostic,
        config_restored,
        pki_restored,
        client_access_verified,
        datastore_restored,
        storage_restored,
        manifests_restored,
        receipts_cleaned,
        overall_success,
        backend_calls: backend.runner.calls.clone(),
        retained_backup_count,
        known_limitations: version_recovery_limitations(scenario.starting_version),
    })
}

fn disk_evidence(
    inst: &DisposableInstallation,
) -> io::Result<std::collections::BTreeMap<PathBuf, crate::state_transition::storage::PvFileRecord>>
{
    use crate::state_transition::storage::PvEntryKind;
    let mut entries = scan_pv_storage(inst.dir.path())?;
    let lock = inst.data_path.join(".upgrade.lock");
    entries.remove(
        lock.strip_prefix(inst.dir.path())
            .map_err(io::Error::other)?,
    );
    // Lock creation can change directory entry lengths, not their contents or modes.
    for entry in entries.values_mut() {
        if entry.entry_kind == PvEntryKind::Directory {
            entry.size_bytes = 0;
        }
    }
    Ok(entries)
}

fn create_pre_upgrade_backup(inst: &DisposableInstallation, backup_dir: &Path) -> io::Result<()> {
    fs::create_dir_all(backup_dir.join("pki"))?;
    fs::create_dir_all(backup_dir.join("kine/db"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(backup_dir, fs::Permissions::from_mode(0o700))?;
    }

    // Copy PKI
    fs::copy(
        inst.data_path.join("pki/ca.crt"),
        backup_dir.join("pki/ca.crt"),
    )?;
    fs::copy(
        inst.data_path.join("pki/ca.key"),
        backup_dir.join("pki/ca.key"),
    )?;
    fs::copy(
        inst.data_path.join("pki/service-account.key"),
        backup_dir.join("pki/service-account.key"),
    )?;

    // Copy Datastore
    fs::copy(
        inst.data_path.join("kine/db/state.db"),
        backup_dir.join("kine/db/state.db"),
    )?;
    fs::copy(
        inst.data_path.join("kine/db/state.db-wal"),
        backup_dir.join("kine/db/state.db-wal"),
    )?;

    // Copy Host artifacts
    fs::copy(&inst.binary_path, backup_dir.join("kubesolo.bin"))?;
    fs::copy(&inst.service_path, backup_dir.join("service.unit"))?;

    // Copy Config if present
    if inst.config_path.exists() {
        fs::copy(&inst.config_path, backup_dir.join("config.yaml"))?;
    }

    seal_backup(backup_dir)
}

fn write_pending_receipt(
    data_path: &Path,
    from: &str,
    target: &str,
    backup: &Path,
) -> io::Result<()> {
    let pending = data_path.join(".upgrade-pending");
    let record = format!(
        "from={from}\ntarget={target}\nbackup={}\n",
        backup.display()
    );
    fs::write(pending, record)
}

/// Exercises actual pre-receipt failure handling; late-stage fixtures below are
/// deliberately constructed disk states, not process-crash qualification.
struct EarlyFailureBackend<'a, 'b> {
    host: &'a mut HostBackend<'b, MockRunner>,
    stage: TransitionStage,
    data: &'a Path,
}
impl dioramactl::upgrade::TransitionBackend for EarlyFailureBackend<'_, '_> {
    fn current_version(&mut self) -> io::Result<String> {
        self.host.current_version()
    }
    fn prepare(&mut self, target: &str) -> io::Result<()> {
        self.host.prepare(target)
    }
    fn stop(&mut self) -> io::Result<()> {
        if self.stage == TransitionStage::Quiesce {
            self.host
                .runner
                .calls
                .push("systemctl stop kubesolo (injected failure)".into());
            return Err(io::Error::other("injected stop failure"));
        }
        self.host.stop()
    }
    fn snapshot(&mut self, dir: &Path) -> io::Result<()> {
        self.host.snapshot(dir)?;
        if self.stage == TransitionStage::Snapshot {
            fs::write(dir.join("partial-data.tmp"), "incomplete")?;
            return Err(io::Error::other("injected snapshot failure"));
        }
        if self.stage == TransitionStage::ReceiptPending {
            fs::create_dir(self.data.join(".upgrade-pending"))?;
        }
        Ok(())
    }
    fn replace(&mut self, target: &str) -> io::Result<()> {
        self.host.replace(target)
    }
    fn start(&mut self) -> io::Result<()> {
        self.host.start()
    }
    fn restore(&mut self, dir: &Path) -> io::Result<()> {
        self.host.restore(dir)
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;

    #[test]
    fn rehearsal_detects_changed_retained_pv_and_manifest_contents() {
        let scenario = RehearsalScenario {
            starting_version: SupportedStartingVersion::V1_3_0,
            target_version: "v1.4.0".into(),
            kubeconfig_format: KubeconfigFormat::Yaml,
            interrupt_stage: TransitionStage::ServiceStart,
            backup_condition: BackupCondition::Valid,
        };
        let result = run_rehearsal_inner(&scenario, true).unwrap();
        assert!(result.recovery_executed);
        assert!(!result.storage_restored);
        assert!(!result.manifests_restored);
        assert!(!result.overall_success);
    }
}
