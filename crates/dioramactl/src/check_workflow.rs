//! Opt-in, bounded preparation followed by complete reobservation.
use crate::preparation::{Cancellation, PreparationExecutor, PreparationPermit};
use crate::{CheckInputs, CheckOptions, platform_failure, render_finding};
use diorama_platform::preflight::{
    CheckStatus, PreflightInputs, PreparationAction, RuntimeOwnership, evaluate_preflight,
};
use diorama_platform::{Observation, PlatformError, ProbeFailure};
use std::io::{self, Write};

/// Execute only the first authorized prerequisite action, then observe every check again.
/// Output and synchronous observations occur only between fully cleaned-up commands.
pub async fn execute_check_with_preparation(
    options: CheckOptions,
    inputs: &mut dyn CheckInputs,
    executor: &mut dyn PreparationExecutor,
    cancellation: &Cancellation,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    let mut shared_effects = false;
    let result = run_workflow(
        options,
        inputs,
        executor,
        cancellation,
        stderr,
        &mut shared_effects,
    )
    .await?;
    if result == 1 && shared_effects {
        writeln!(
            stderr,
            "Shared host state may have changed during this invocation; no rollback was attempted."
        )?;
    }
    Ok(result)
}
async fn run_workflow(
    options: CheckOptions,
    inputs: &mut dyn CheckInputs,
    executor: &mut dyn PreparationExecutor,
    cancellation: &Cancellation,
    stderr: &mut dyn Write,
    shared_effects: &mut bool,
) -> io::Result<u8> {
    let Some(permit) = PreparationPermit::from_options(options) else {
        return crate::execute_check(options, inputs, stderr);
    };
    let mut attempted = [false; 2];
    writeln!(stderr, "\n  dioramactl  check\n\n  > Detecting system")?;
    loop {
        if !cancellation.checkpoint().await {
            return cancelled(stderr);
        }
        let evidence = match inputs.discover() {
            Ok(value) => value,
            Err(error) => return platform_failure(stderr, "system detection", error),
        };
        if let Err(error) = supported(&evidence) {
            return platform_failure(stderr, "system detection", error);
        }
        let supplement = match inputs.supplemental() {
            Ok(value) => value,
            Err(error) => return platform_failure(stderr, "supplemental observations", error),
        };
        let mut policy = policy(options, supplement);
        let report = evaluate_preflight(&evidence, &policy);
        let first = report.findings[..6].iter().find(|finding| {
            !matches!(
                finding.status,
                CheckStatus::Pass | CheckStatus::NotApplicable
            )
        });
        if let Some(finding) = first {
            if finding.status != CheckStatus::NeedsPreparation {
                render_finding(finding, stderr)?;
                return Ok(1);
            }
            let [action] = finding.plans.as_slice() else {
                writeln!(stderr, "error: prerequisite plan is unsupported")?;
                return Ok(1);
            };
            let index = match action {
                PreparationAction::InstallAlpineNetworking { .. } => 0,
                PreparationAction::EnableAlpineCgroups => 1,
            };
            if attempted[index] {
                writeln!(
                    stderr,
                    "error: prerequisite is still missing after preparation; inspect the host before retrying"
                )?;
                return Ok(1);
            }
            if !cancellation.checkpoint().await {
                return cancelled(stderr);
            }
            attempted[index] = true;
            writeln!(
                stderr,
                "  > Preparing {}",
                if index == 0 {
                    "Alpine networking packages"
                } else {
                    "Alpine cgroups service"
                }
            )?;
            let receipt = executor.execute(*action, &permit, cancellation).await;
            *shared_effects |= receipt.shared_effects_possible();
            if receipt
                .commands
                .iter()
                .any(crate::preparation::CommandReceipt::cleanup_uncertain)
                || receipt.failure == Some(crate::preparation::PreparationFailure::Cleanup)
            {
                // Terminal path: do not risk a blocking writer while an owner may still be live.
                return Ok(2);
            }
            if !receipt.succeeded() {
                render_preparation_failure(&receipt, stderr)?;
                return Ok(1);
            }
            // A successful exit is only a reason to reobserve, never proof of readiness.
            continue;
        }
        if !cancellation.checkpoint().await {
            return cancelled(stderr);
        }
        policy.ports = match inputs.ports(options.pprof) {
            Ok(value) => value,
            Err(error) => return platform_failure(stderr, "port observations", error),
        };
        if !cancellation.checkpoint().await {
            return cancelled(stderr);
        }
        let final_report = evaluate_preflight(&evidence, &policy);
        if !render_finding(&final_report.findings[6], stderr)? {
            return Ok(1);
        }
        writeln!(
            stderr,
            "  [ok] All 7 checks passed\n\n  Observed host prerequisites passed; ports are not reserved and runtime readiness is not established."
        )?;
        return Ok(0);
    }
}
fn cancelled(stderr: &mut dyn Write) -> io::Result<u8> {
    writeln!(
        stderr,
        "error: prerequisite workflow cancelled; no further commands will start"
    )?;
    Ok(1)
}

fn render_preparation_failure(
    receipt: &crate::preparation::PreparationReceipt,
    stderr: &mut dyn Write,
) -> io::Result<()> {
    use crate::preparation::PreparationFailure;
    let reason = match receipt.failure {
        Some(PreparationFailure::Cancelled) => "cancelled",
        Some(PreparationFailure::Cleanup) => "owned command cleanup incomplete",
        Some(PreparationFailure::Command) => "command failed or exceeded its deadline",
        Some(PreparationFailure::InvalidAction | PreparationFailure::Graph) => {
            "invalid prerequisite plan"
        },
        None => "not completed",
    };
    writeln!(
        stderr,
        "error: prerequisite preparation {reason}; {}",
        if receipt.shared_effects_possible() {
            "shared host state may have changed; no rollback was attempted"
        } else {
            "no command was observed to start"
        }
    )?;
    if receipt
        .commands
        .iter()
        .any(crate::preparation::CommandReceipt::cleanup_uncertain)
    {
        writeln!(
            stderr,
            "error: owned command cleanup is incomplete; inspect the host before retrying"
        )?;
    }
    Ok(())
}

fn supported(evidence: &diorama_platform::HostEvidence) -> Result<(), PlatformError> {
    if evidence.executable.os != "linux" {
        return Err(PlatformError::UnsupportedHost);
    }
    if !["x86_64", "aarch64", "arm", "riscv64"].contains(&evidence.executable.architecture.as_str())
    {
        return Err(PlatformError::UnsupportedTarget);
    }
    Ok(())
}

fn policy(
    options: CheckOptions,
    supplement: diorama_platform::preflight_probe::SupplementalFacts,
) -> PreflightInputs {
    PreflightInputs {
        install_prerequisites: true,
        pprof: options.pprof,
        runtime: RuntimeOwnership::Managed,
        xt_comment_on_disk: supplement.xt_comment_on_disk,
        alpine_rc_service: supplement.alpine_rc_service,
        ports: [Observation::Unknown(ProbeFailure::Malformed); 4],
    }
}
