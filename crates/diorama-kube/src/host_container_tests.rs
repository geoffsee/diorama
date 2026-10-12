//! Injected operations only: no host filesystem, mounts, cgroups or processes.
use super::*;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Trace {
    calls: Vec<&'static str>,
    wake: Option<tokio::sync::oneshot::Sender<()>>,
    cancel_at: Option<&'static str>,
}
struct Fake {
    trace: Arc<Mutex<Trace>>,
    mount: Result<(), ContainerError>,
    layout: Result<CgroupLayout, ContainerError>,
    migration: Result<(), ContainerError>,
    writes: VecDeque<Mutation>,
    reads: VecDeque<Result<Vec<ControllerName>, ContainerError>>,
}
impl Default for Fake {
    fn default() -> Self {
        Self {
            trace: Arc::default(),
            mount: Ok(()),
            layout: Ok(CgroupLayout::V2),
            migration: Ok(()),
            writes: VecDeque::new(),
            reads: VecDeque::from([Ok(vec![]), Ok(parse_controllers(b"cpu memory").unwrap())]),
        }
    }
}
impl Fake {
    fn call(&self, name: &'static str) {
        let mut trace = self.trace.lock().unwrap();
        trace.calls.push(name);
        if trace.cancel_at == Some(name)
            && let Some(wake) = trace.wake.take()
        {
            let _ = wake.send(());
        }
    }
}
struct Inputs(Option<Fake>);
impl ContainerPreparationInputs for Inputs {
    type Session = Fake;
    fn container_session(&mut self) -> Result<Fake, ContainerError> {
        let fake = self.0.take().unwrap();
        fake.call("anchor");
        Ok(fake)
    }
}
impl ContainerSession for Fake {
    fn make_root_shared(&mut self) -> Mutation {
        self.call("mount");
        Mutation {
            attempted: true,
            result: self.mount,
        }
    }
    fn open_cgroups(&mut self) -> Result<CgroupLayout, ContainerError> {
        self.call("root");
        self.layout
    }
    fn ensure_init(&mut self) -> Mutation {
        self.call("init");
        Mutation {
            attempted: true,
            result: Ok(()),
        }
    }
    fn migrate_current_process(&mut self) -> Mutation {
        self.call("migrate");
        Mutation {
            attempted: true,
            result: self.migration,
        }
    }
    fn available_controllers(&mut self) -> Result<Vec<ControllerName>, ContainerError> {
        self.call("available");
        parse_controllers(b"cpu memory")
    }
    fn enabled_controllers(&mut self) -> Result<Vec<ControllerName>, ContainerError> {
        self.call("readback");
        self.reads.pop_front().unwrap()
    }
    fn enable_controllers(&mut self, names: &[ControllerName]) -> Mutation {
        self.call(if names.len() > 1 { "bulk" } else { "single" });
        self.writes.pop_front().unwrap_or(Mutation {
            attempted: true,
            result: Ok(()),
        })
    }
}
async fn run(fake: Fake) -> ContainerPreparation {
    prepare(
        &mut Cancellation {
            future: Box::pin(std::future::pending()),
            stopped: false,
        },
        &mut Inputs(Some(fake)),
    )
    .await
}
#[test]
fn controller_tokens_reject_operations_duplicates_and_bounds() {
    assert_eq!(parse_controllers(b"cpu memory\npids").unwrap().len(), 3);
    for bytes in [
        b"+cpu".as_slice(),
        b"cpu cpu",
        b"../cpu",
        b"cpu\0",
        b"CPU",
        b"c-pu",
        b"\xff",
    ] {
        assert_eq!(parse_controllers(bytes), Err(ContainerError::Malformed));
    }
    assert_eq!(
        parse_controllers(&[b'a'; 65]),
        Err(ContainerError::TooLarge)
    );
    assert_eq!(
        parse_controllers(&vec![b' '; 4097]),
        Err(ContainerError::TooLarge)
    );
    let names = (0..33)
        .map(|n| format!("c{n}"))
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(
        parse_controllers(names.as_bytes()),
        Err(ContainerError::TooLarge)
    );
    assert!(parse_controllers(b" \n").unwrap().is_empty());
}
#[tokio::test]
async fn ordered_effects_use_independent_controller_readback() {
    let fake = Fake::default();
    let trace = fake.trace.clone();
    let report = run(fake).await;
    assert_eq!(report.status, ContainerStatus::Completed);
    assert!(report.shared_effects_possible);
    assert!(report.missing_after.is_empty());
    assert_eq!(
        trace.lock().unwrap().calls,
        [
            "anchor",
            "mount",
            "root",
            "init",
            "migrate",
            "available",
            "readback",
            "bulk",
            "readback"
        ]
    );
}
#[tokio::test]
async fn mount_failure_and_uncertain_readback_suppress_all_cgroups() {
    for error in [
        ContainerError::PermissionDenied,
        ContainerError::MountReadbackUncertain,
        ContainerError::ContextChanged,
    ] {
        let fake = Fake {
            mount: Err(error),
            ..Default::default()
        };
        let trace = fake.trace.clone();
        let report = run(fake).await;
        assert_eq!(
            report.status,
            ContainerStatus::Fatal {
                stage: ContainerStage::Mount,
                error
            }
        );
        assert_eq!(trace.lock().unwrap().calls, ["anchor", "mount"]);
        assert!(report.shared_effects_possible);
    }
}
#[tokio::test]
async fn only_positive_v1_skips_cgroup_operations() {
    let fake = Fake {
        layout: Ok(CgroupLayout::V1),
        ..Default::default()
    };
    let trace = fake.trace.clone();
    let report = run(fake).await;
    assert_eq!(report.status, ContainerStatus::Completed);
    assert_eq!(report.layout, Some(CgroupLayout::V1));
    assert_eq!(trace.lock().unwrap().calls, ["anchor", "mount", "root"]);
    for error in [
        ContainerError::Missing,
        ContainerError::PermissionDenied,
        ContainerError::WrongType,
        ContainerError::UnsupportedRootType,
        ContainerError::MembershipNotAdmitted,
    ] {
        let report = run(Fake {
            layout: Err(error),
            ..Default::default()
        })
        .await;
        assert_eq!(
            report.status,
            ContainerStatus::Fatal {
                stage: ContainerStage::CgroupRoot,
                error
            }
        );
        assert!(report.init.is_none());
        assert!(report.shared_effects_possible);
    }
}
#[tokio::test]
async fn migration_requires_observed_membership_before_delegation() {
    let fake = Fake {
        migration: Err(ContainerError::MigrationUnobserved),
        ..Default::default()
    };
    let trace = fake.trace.clone();
    let report = run(fake).await;
    assert_eq!(
        report.status,
        ContainerStatus::Fatal {
            stage: ContainerStage::Migration,
            error: ContainerError::MigrationUnobserved
        }
    );
    assert_eq!(trace.lock().unwrap().calls.last(), Some(&"migrate"));
    assert!(report.controller_attempts.is_empty());
}
#[tokio::test]
async fn bulk_and_individual_failures_continue_with_truthful_partial_readback() {
    let mut fake = Fake {
        writes: VecDeque::from([
            Mutation {
                attempted: false,
                result: Err(ContainerError::PermissionDenied),
            },
            Mutation {
                attempted: true,
                result: Ok(()),
            },
            Mutation {
                attempted: true,
                result: Err(ContainerError::ReadOnly),
            },
        ]),
        ..Default::default()
    };
    fake.reads[1] = Ok(parse_controllers(b"cpu").unwrap());
    let report = run(fake).await;
    assert_eq!(report.status, ContainerStatus::Completed);
    assert_eq!(report.controller_attempts.len(), 3);
    assert_eq!(report.missing_after, parse_controllers(b"memory").unwrap());
    assert_eq!(
        report.enabled_after,
        Some(Ok(parse_controllers(b"cpu").unwrap()))
    );
}
#[tokio::test]
async fn successful_write_never_substitutes_for_failed_or_missing_readback() {
    for after in [
        Ok(vec![]),
        Err(ContainerError::PermissionDenied),
        Err(ContainerError::TooLarge),
    ] {
        let mut fake = Fake::default();
        fake.reads[1] = after.clone();
        let report = run(fake).await;
        assert_eq!(report.status, ContainerStatus::Completed);
        assert_eq!(report.enabled_after, Some(after));
    }
}
#[tokio::test]
async fn changed_context_stops_controller_fallback_and_readback() {
    let mut fake = Fake::default();
    fake.writes.push_back(Mutation {
        attempted: false,
        result: Err(ContainerError::ContextChanged),
    });
    let trace = fake.trace.clone();
    let report = run(fake).await;
    assert_eq!(
        report.status,
        ContainerStatus::Fatal {
            stage: ContainerStage::Controllers,
            error: ContainerError::ContextChanged
        }
    );
    assert_eq!(trace.lock().unwrap().calls.last(), Some(&"bulk"));
    assert!(report.enabled_after.is_none());
}
#[tokio::test]
async fn lost_admission_on_final_observation_is_fatal() {
    let mut fake = Fake::default();
    fake.reads[1] = Err(ContainerError::ContextChanged);
    let report = run(fake).await;
    assert_eq!(
        report.status,
        ContainerStatus::Fatal {
            stage: ContainerStage::Controllers,
            error: ContainerError::ContextChanged
        }
    );
    assert!(report.shared_effects_possible);
}
#[tokio::test]
async fn cancellation_future_becoming_ready_between_effects_suppresses_next_effect() {
    for phase in [
        "anchor",
        "mount",
        "root",
        "init",
        "migrate",
        "available",
        "readback",
        "bulk",
    ] {
        let (wake, receiver) = tokio::sync::oneshot::channel();
        let fake = Fake::default();
        let trace = fake.trace.clone();
        {
            let mut state = trace.lock().unwrap();
            state.wake = Some(wake);
            state.cancel_at = Some(phase);
        }
        let report = prepare(
            &mut Cancellation {
                future: Box::pin(async {
                    let _ = receiver.await;
                }),
                stopped: false,
            },
            &mut Inputs(Some(fake)),
        )
        .await;
        assert_eq!(report.status, ContainerStatus::Cancelled, "{phase}");
        assert_eq!(trace.lock().unwrap().calls.last(), Some(&phase), "{phase}");
        assert_eq!(report.shared_effects_possible, phase != "anchor");
    }
}
#[tokio::test]
async fn cancellation_during_failed_controller_write_retains_prior_effects() {
    let (wake, receiver) = tokio::sync::oneshot::channel();
    let mut fake = Fake::default();
    fake.writes.push_back(Mutation {
        attempted: true,
        result: Err(ContainerError::Io),
    });
    let trace = fake.trace.clone();
    {
        let mut state = trace.lock().unwrap();
        state.wake = Some(wake);
        state.cancel_at = Some("bulk");
    }
    let report = prepare(
        &mut Cancellation {
            future: Box::pin(async {
                let _ = receiver.await;
            }),
            stopped: false,
        },
        &mut Inputs(Some(fake)),
    )
    .await;
    assert_eq!(report.status, ContainerStatus::Cancelled);
    assert_eq!(trace.lock().unwrap().calls.last(), Some(&"bulk"));
    assert_eq!(report.controller_attempts.len(), 1);
    assert!(report.shared_effects_possible);
}
#[tokio::test]
async fn initially_ready_cancellation_never_acquires_a_session() {
    let fake = Fake::default();
    let trace = fake.trace.clone();
    let report = prepare(
        &mut Cancellation {
            future: Box::pin(async {}),
            stopped: false,
        },
        &mut Inputs(Some(fake)),
    )
    .await;
    assert_eq!(report.status, ContainerStatus::Cancelled);
    assert!(trace.lock().unwrap().calls.is_empty());
    assert!(!report.shared_effects_possible);
}

#[tokio::test]
async fn cancellation_observed_during_v1_probe_precedes_completed_skip() {
    let (wake, receiver) = tokio::sync::oneshot::channel();
    let fake = Fake {
        layout: Ok(CgroupLayout::V1),
        ..Default::default()
    };
    {
        let mut trace = fake.trace.lock().unwrap();
        trace.wake = Some(wake);
        trace.cancel_at = Some("root");
    }
    let report = prepare(
        &mut Cancellation {
            future: Box::pin(async {
                let _ = receiver.await;
            }),
            stopped: false,
        },
        &mut Inputs(Some(fake)),
    )
    .await;
    assert_eq!(report.status, ContainerStatus::Cancelled);
    assert_eq!(report.layout, Some(CgroupLayout::V1));
    assert!(report.shared_effects_possible);
}
