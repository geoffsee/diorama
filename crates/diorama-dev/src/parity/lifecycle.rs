//! Cleanup policy separated from QEMU I/O for adversarial ownership tests.
use super::{Result, process::OwnedChild};
use rustix::process::Signal;
use serde_json::{Value, json};
use std::path::Path;
use std::time::Duration;

pub(crate) trait VmOwner {
    fn poll(&mut self) -> Result<Option<i32>>;
    fn signal(&mut self, signal: Signal) -> Result<()>;
    fn wait(&mut self, timeout: Duration) -> Result<i32>;
    fn absent(&mut self) -> Result<bool>;
}
impl VmOwner for OwnedChild {
    fn poll(&mut self) -> Result<Option<i32>> {
        Ok(Self::poll(self)?.map(super::process::exit_code))
    }
    fn signal(&mut self, signal: Signal) -> Result<()> {
        Self::signal(self, signal)
    }
    fn wait(&mut self, timeout: Duration) -> Result<i32> {
        Ok(super::process::exit_code(Self::wait(self, timeout)?))
    }
    fn absent(&mut self) -> Result<bool> {
        self.group_absent()
    }
}
fn attempt<T>(
    errors: &mut Vec<String>,
    label: &str,
    action: impl FnOnce() -> Result<T>,
) -> Option<T> {
    match action() {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(format!("{label}: {error}"));
            None
        },
    }
}
/// The powerdown callback sends QMP only. This function owns every wait and fallback.
/// Observation after reap never authorizes another signal or deletion while uncertain.
pub(crate) fn settle_vm(
    vm: &mut impl VmOwner,
    mut diagnostics: impl FnMut() -> Result<()>,
    mut powerdown: impl FnMut() -> Result<()>,
    errors: &mut Vec<String>,
) -> Value {
    let mut report = json!({"owned_process_group_absent":false});
    if attempt(errors, "QEMU poll", || vm.poll()) == Some(None) {
        attempt(errors, "diagnostics", &mut diagnostics);
        let shutdown = attempt(errors, "ACPI powerdown", || {
            powerdown()?;
            vm.wait(Duration::from_secs(30))?;
            Ok(())
        });
        if shutdown.is_some() {
            report["shutdown"] = json!("acpi-powerdown");
        } else {
            report["shutdown"] = json!("forced-process-termination");
            // poll may reap an already exited leader. Never signal after that observation.
            if attempt(errors, "QEMU fallback poll", || vm.poll()) == Some(None) {
                attempt(errors, "QEMU terminate", || vm.signal(Signal::TERM));
            }
            if attempt(errors, "QEMU terminate wait", || {
                vm.wait(Duration::from_secs(5))
            })
            .is_none()
            {
                if attempt(errors, "QEMU kill poll", || vm.poll()) == Some(None) {
                    attempt(errors, "QEMU kill", || vm.signal(Signal::KILL));
                }
                attempt(errors, "QEMU kill wait", || vm.wait(Duration::from_secs(5)));
            }
        }
    }
    let status = attempt(errors, "QEMU final poll", || vm.poll()).flatten();
    report["qemu_exit_code"] = json!(status);
    if status != Some(0) {
        errors.push(format!(
            "QEMU exited abnormally or remains unreaped: {status:?}"
        ));
    }
    match attempt(errors, "QEMU process-group check", || vm.absent()) {
        Some(true) => report["owned_process_group_absent"] = json!(true),
        _ => errors.push("QEMU group absence unconfirmed; no post-reap signal sent".into()),
    }
    report
}
pub(crate) fn remove_private(path: &Path, authorized: bool, errors: &mut Vec<String>) -> bool {
    if !authorized {
        errors.push("VM files retained because owned processes are not confirmed absent".into());
        return false;
    }
    if let Err(error) = std::fs::remove_dir_all(path) {
        errors.push(format!("private directory removal: {error}"));
    }
    !path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    #[derive(Debug)]
    struct Fake {
        status: Option<i32>,
        polls: VecDeque<Option<i32>>,
        waits: VecDeque<Option<i32>>,
        signals: Vec<Signal>,
        absent: bool,
    }
    impl VmOwner for Fake {
        fn poll(&mut self) -> Result<Option<i32>> {
            if let Some(v) = self.polls.pop_front() {
                self.status = v;
            }
            Ok(self.status)
        }
        fn wait(&mut self, _: Duration) -> Result<i32> {
            match self.waits.pop_front().unwrap_or(self.status) {
                Some(code) => {
                    self.status = Some(code);
                    Ok(code)
                },
                None => Err("deadline".into()),
            }
        }
        fn signal(&mut self, s: Signal) -> Result<()> {
            assert!(self.status.is_none());
            self.signals.push(s);
            Ok(())
        }
        fn absent(&mut self) -> Result<bool> {
            Ok(self.absent)
        }
    }
    fn fake(status: Option<i32>, absent: bool) -> Fake {
        Fake {
            status,
            polls: VecDeque::new(),
            waits: VecDeque::new(),
            signals: vec![],
            absent,
        }
    }
    #[test]
    fn reaped_present_group_is_never_signalled_and_keeps_files() -> Result<()> {
        let mut vm = fake(Some(0), false);
        let mut errors = vec![];
        let report = settle_vm(&mut vm, || Ok(()), || Ok(()), &mut errors);
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("vm");
        std::fs::create_dir(&path)?;
        assert!(!remove_private(
            &path,
            report["owned_process_group_absent"] == true,
            &mut errors
        ));
        assert!(path.exists());
        assert!(vm.signals.is_empty());
        assert!(!errors.is_empty());
        Ok(())
    }
    #[test]
    fn reaped_absent_group_authorizes_private_removal() -> Result<()> {
        let mut vm = fake(Some(0), true);
        let mut errors = vec![];
        let report = settle_vm(&mut vm, || Ok(()), || Ok(()), &mut errors);
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("vm");
        std::fs::create_dir(&path)?;
        assert!(remove_private(
            &path,
            report["owned_process_group_absent"] == true,
            &mut errors
        ));
        assert!(errors.is_empty());
        assert!(vm.signals.is_empty());
        Ok(())
    }
    #[test]
    fn exit_before_fallback_prevents_numeric_signals() {
        let mut vm = fake(None, true);
        vm.polls = VecDeque::from([None, Some(0)]);
        let mut errors = vec![];
        settle_vm(
            &mut vm,
            || Ok(()),
            || Err("QMP unavailable".into()),
            &mut errors,
        );
        assert!(vm.signals.is_empty());
        assert!(!errors.is_empty());
    }
    #[test]
    fn live_owner_escalates_term_then_kill_and_preserves_failure() {
        let mut vm = fake(None, true);
        vm.waits = VecDeque::from([None, None, Some(0)]);
        let mut errors = vec![];
        let report = settle_vm(
            &mut vm,
            || Err("diagnostics failed".into()),
            || Ok(()),
            &mut errors,
        );
        assert_eq!(vm.signals, [Signal::TERM, Signal::KILL]);
        assert_eq!(report["owned_process_group_absent"], true);
        assert!(errors.iter().any(|e| e.contains("diagnostics failed")));
        assert!(errors.len() >= 3);
    }
    #[test]
    fn cleanup_error_does_not_claim_removed() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("regular");
        std::fs::write(&path, b"recovery").unwrap();
        let mut errors = vec![];
        assert!(!remove_private(&path, true, &mut errors));
        assert!(path.exists());
        assert!(!errors.is_empty());
    }
}
