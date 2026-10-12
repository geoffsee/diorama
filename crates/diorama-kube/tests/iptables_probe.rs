#![cfg(target_os = "linux")]
use diorama::host_preflight::{VersionFailure, iptables_version};
use diorama_platform::Observation;
use diorama_platform::constrained::ModuleFamily;
use diorama_supervisor::stop_channel;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};
struct Sentinel(Child);
impl Drop for Sentinel {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn case(mode: &str) {
    let executable = Path::new("/usr/sbin/iptables");
    std::fs::write("/tmp/probe-mode", mode).unwrap();
    let _ = std::fs::remove_file("/tmp/probe-started");
    if executable.exists() {
        std::fs::remove_file(executable).unwrap();
    }
    if mode != "missing" {
        std::fs::copy("/iptables.sh", executable).unwrap();
        std::fs::set_permissions(
            executable,
            std::fs::Permissions::from_mode(if mode == "denied" { 0o644 } else { 0o755 }),
        )
        .unwrap();
    }
    let (stop, receiver) = stop_channel();
    let began = Instant::now();
    let running = tokio::spawn(iptables_version(receiver));
    if mode == "cancel" {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !Path::new("/tmp/probe-started").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        stop.stop();
    }
    let result = tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .unwrap()
        .unwrap();
    let failure = match mode {
        "nonzero" | "missing" | "denied" => Some(VersionFailure::Command),
        "overflow" | "held" => Some(VersionFailure::Capture),
        "deadline" => Some(VersionFailure::Deadline),
        "cancel" => Some(VersionFailure::Cancelled),
        _ => None,
    };
    assert_eq!(result.failure, failure, "{mode}");
    assert!(!result.cleanup_uncertain());
    assert!(result.cleanup.thread_joined);
    assert_eq!(
        result.cleanup.spawned,
        !matches!(mode, "missing" | "denied")
    );
    assert_eq!(result.cleanup.leader_reaped, result.cleanup.spawned);
    if failure.is_none() {
        assert_eq!(
            result.family,
            Observation::Present(if matches!(mode, "nft" | "invalid-utf8") {
                ModuleFamily::NfTables
            } else {
                ModuleFamily::Legacy
            })
        );
    } else {
        assert!(matches!(result.family, Observation::Unknown(_)));
    }
    if mode == "deadline" {
        assert!(began.elapsed() >= Duration::from_secs(2));
        assert!(result.cleanup.force_requested);
    }
    println!(
        "diorama_NODE_PROBE case={mode} result={:?} joined=true reaped={} elapsed_ms={}",
        result.failure,
        result.cleanup.leader_reaped,
        began.elapsed().as_millis()
    );
    if mode == "held" {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
#[tokio::test]
#[ignore = "fixed-path fixture writes require disposable Linux namespace"]
async fn disposable_fixed_probe() {
    assert_eq!(std::env::var("diorama_NODE_DISPOSABLE").as_deref(), Ok("1"));
    let mut sentinel = Sentinel(
        Command::new("/node-fixture")
            .arg("sentinel")
            .spawn()
            .unwrap(),
    );
    std::fs::write("/tmp/external-runtime.conf", b"host-owned configuration").unwrap();
    for mode in [
        "nft",
        "legacy",
        "empty",
        "invalid-utf8",
        "nonzero",
        "missing",
        "denied",
        "overflow",
        "deadline",
        "cancel",
        "held",
    ] {
        case(mode).await;
        assert!(sentinel.0.try_wait().unwrap().is_none());
    }
    assert_eq!(
        std::fs::read("/tmp/external-runtime.conf").unwrap(),
        b"host-owned configuration"
    );
    drop(sentinel);
    println!("diorama_NODE_PROBE_COMPLETE cases=11 external_sentinel_preserved=true");
}
