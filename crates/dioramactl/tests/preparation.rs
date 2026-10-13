use diorama_platform::preflight::{PortAvailability, PreparationAction};
use diorama_platform::preflight_probe::SupplementalFacts;
use diorama_platform::{
    ExecutableAbi, HostEvidence, Observation, PlatformError, Privileges, ProbeFailure,
};
use dioramactl::preparation::{
    Cancellation, PreparationExecutor, PreparationFailure, PreparationFuture, PreparationPermit,
    PreparationReceipt,
};
use dioramactl::{CheckInputs, CheckOptions};
use std::cell::RefCell;
use std::rc::Rc;

// Independent observed facts exercised in combinations.
#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct State {
    tools: bool,
    controllers: bool,
    actions: Vec<PreparationAction>,
    ports: usize,
    observations: usize,
    root: bool,
    unknown: bool,
}
struct Inputs(Rc<RefCell<State>>);
impl CheckInputs for Inputs {
    fn discover(&mut self) -> Result<HostEvidence, PlatformError> {
        let mut state = self.0.borrow_mut();
        state.observations += 1;
        let mut landmarks = [
            "/var/run/docker.sock",
            "/usr/bin/docker",
            "/usr/local/bin/docker",
        ]
        .into_iter()
        .map(|p| (p.into(), Observation::Absent))
        .collect::<std::collections::BTreeMap<_, _>>();
        landmarks.insert("/etc/alpine-release".into(), Observation::Present(true));
        for path in [
            "/usr/sbin/nft",
            "/sbin/nft",
            "/usr/bin/nft",
            "/sbin/iptables",
            "/usr/sbin/iptables",
            "/bin/iptables",
            "/usr/bin/iptables",
        ] {
            landmarks.insert(path.into(), Observation::Present(state.tools));
        }
        Ok(HostEvidence {
            executable: ExecutableAbi {
                os: "linux".into(),
                architecture: "aarch64".into(),
                environment: "musl".into(),
            },
            kernel: Observation::Unknown(ProbeFailure::Malformed),
            privileges: if state.unknown {
                Observation::Unknown(ProbeFailure::PermissionDenied)
            } else {
                Observation::Present(Privileges {
                    real_uid: u32::from(!state.root),
                    effective_uid: 0,
                })
            },
            hostname: Observation::Present("node".into()),
            container_environment_set: false,
            landmarks,
            musl_linkers: Observation::Present(vec![]),
            files: [(
                "/sys/fs/cgroup/cgroup.controllers".into(),
                if state.controllers {
                    Observation::Present("cpuset cpu io memory pids".into())
                } else {
                    Observation::Absent
                },
            )]
            .into_iter()
            .collect(),
            requested_paths: vec![],
        })
    }
    fn supplemental(&mut self) -> Result<SupplementalFacts, PlatformError> {
        Ok(SupplementalFacts {
            xt_comment_on_disk: Observation::Present(true),
            alpine_rc_service: Observation::Present(true),
        })
    }
    fn ports(&mut self, _: bool) -> Result<[Observation<PortAvailability>; 4], PlatformError> {
        self.0.borrow_mut().ports += 1;
        Ok([Observation::Present(PortAvailability::Available); 4])
    }
}
struct Executor {
    state: Rc<RefCell<State>>,
    repair: bool,
    fail: bool,
    cancel: bool,
}
impl PreparationExecutor for Executor {
    fn execute<'a>(
        &'a mut self,
        action: PreparationAction,
        _: &'a PreparationPermit,
        cancellation: &'a Cancellation,
    ) -> PreparationFuture<'a> {
        Box::pin(async move {
            let mut state = self.state.borrow_mut();
            state.actions.push(action);
            if self.cancel {
                cancellation.cancel();
            }
            if self.repair {
                match action {
                    PreparationAction::InstallAlpineNetworking { .. } => state.tools = true,
                    PreparationAction::EnableAlpineCgroups => state.controllers = true,
                }
            }
            PreparationReceipt {
                commands: vec![],
                failure: self.fail.then_some(PreparationFailure::Command),
            }
        })
    }
}
async fn run(state: Rc<RefCell<State>>, repair: bool, fail: bool, cancel: bool) -> (u8, String) {
    let mut output = vec![];
    let code = dioramactl::check_workflow::execute_check_with_preparation(
        CheckOptions {
            install_prerequisites: true,
            pprof: false,
        },
        &mut Inputs(state.clone()),
        &mut Executor {
            state,
            repair,
            fail,
            cancel,
        },
        &Cancellation::default(),
        &mut output,
    )
    .await
    .unwrap();
    (code, String::from_utf8(output).unwrap())
}
#[tokio::test(flavor = "current_thread")]
async fn repairs_in_order_and_requires_fresh_observation_before_ports() {
    let state = Rc::new(RefCell::new(State {
        root: true,
        ..State::default()
    }));
    assert_eq!(run(state.clone(), true, false, false).await.0, 0);
    let state = state.borrow();
    assert_eq!(
        state.actions,
        [
            PreparationAction::InstallAlpineNetworking {
                nftables: true,
                iptables: true
            },
            PreparationAction::EnableAlpineCgroups
        ]
    );
    assert_eq!(state.observations, 3);
    assert_eq!(state.ports, 1);
}
#[tokio::test(flavor = "current_thread")]
async fn success_without_repair_never_passes_or_repeats_action() {
    let state = Rc::new(RefCell::new(State {
        root: true,
        ..State::default()
    }));
    let (code, output) = run(state.clone(), false, false, false).await;
    assert_eq!(code, 1);
    assert!(output.contains("still missing"));
    assert_eq!(state.borrow().actions.len(), 1);
    assert_eq!(state.borrow().ports, 0);
}
#[tokio::test(flavor = "current_thread")]
async fn failure_or_gap_cancellation_prevents_next_action_and_ports() {
    for (fail, cancel) in [(true, false), (false, true)] {
        let state = Rc::new(RefCell::new(State {
            root: true,
            ..State::default()
        }));
        assert_eq!(run(state.clone(), true, fail, cancel).await.0, 1);
        assert_eq!(state.borrow().actions.len(), 1);
        assert_eq!(state.borrow().ports, 0);
    }
}
#[tokio::test(flavor = "current_thread")]
async fn earlier_nonroot_or_unknown_blocks_all_preparation() {
    for (root, unknown) in [(false, false), (true, true)] {
        let state = Rc::new(RefCell::new(State {
            root,
            unknown,
            ..State::default()
        }));
        assert_eq!(run(state.clone(), true, false, false).await.0, 1);
        assert_eq!(
            state.borrow().actions,
            <[diorama_platform::preflight::PreparationAction; 0]>::default()
        );
        assert_eq!(state.borrow().ports, 0);
    }
}
#[tokio::test(flavor = "current_thread")]
async fn pre_cancelled_invocation_has_no_host_effects() {
    let state = Rc::new(RefCell::new(State::default()));
    let cancellation = Cancellation::default();
    cancellation.cancel();
    let code = dioramactl::check_workflow::execute_check_with_preparation(
        CheckOptions {
            install_prerequisites: true,
            pprof: false,
        },
        &mut Inputs(state.clone()),
        &mut Executor {
            state: state.clone(),
            repair: true,
            fail: false,
            cancel: false,
        },
        &cancellation,
        &mut vec![],
    )
    .await
    .unwrap();
    assert_eq!(code, 1);
    assert_eq!(state.borrow().observations, 0);
}

struct ReceiptExecutor {
    returned: Rc<std::cell::Cell<bool>>,
    receipt: PreparationReceipt,
}
impl PreparationExecutor for ReceiptExecutor {
    fn execute<'a>(
        &'a mut self,
        _: PreparationAction,
        _: &'a PreparationPermit,
        _: &'a Cancellation,
    ) -> PreparationFuture<'a> {
        Box::pin(async move {
            self.returned.set(true);
            self.receipt.clone()
        })
    }
}
struct NoWritesAfterReceipt(Rc<std::cell::Cell<bool>>);
impl std::io::Write for NoWritesAfterReceipt {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        assert!(!self.0.get(), "output after incomplete owner receipt");
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[tokio::test(flavor = "current_thread")]
async fn uncertain_cleanup_returns_two_without_further_output_or_effects() {
    use diorama_supervisor::process::ProcessCleanupSnapshot;
    use dioramactl::preparation::{CommandReceipt, PreparationStep};
    for snapshot in [
        ProcessCleanupSnapshot {
            started: true,
            spawned: true,
            ..Default::default()
        },
        ProcessCleanupSnapshot {
            started: true,
            spawned: true,
            thread_joined: true,
            ownership_lost: true,
            ..Default::default()
        },
        ProcessCleanupSnapshot {
            started: true,
            spawned: true,
            thread_joined: true,
            ..Default::default()
        },
    ] {
        let state = Rc::new(RefCell::new(State {
            root: true,
            ..State::default()
        }));
        let returned = Rc::new(std::cell::Cell::new(false));
        let mut executor = ReceiptExecutor {
            returned: returned.clone(),
            receipt: PreparationReceipt {
                commands: vec![CommandReceipt {
                    step: PreparationStep::InstallPackages,
                    cause: diorama_supervisor::StopCause::Requested,
                    cleanup: snapshot,
                }],
                failure: Some(PreparationFailure::Cleanup),
            },
        };
        let result = dioramactl::check_workflow::execute_check_with_preparation(
            CheckOptions {
                install_prerequisites: true,
                pprof: false,
            },
            &mut Inputs(state.clone()),
            &mut executor,
            &Cancellation::default(),
            &mut NoWritesAfterReceipt(returned),
        )
        .await
        .unwrap();
        assert_eq!(result, 2);
        assert_eq!(state.borrow().observations, 1);
        assert_eq!(state.borrow().ports, 0);
    }
}
#[tokio::test(flavor = "current_thread")]
async fn shared_effects_warning_survives_successful_action_and_failed_recheck() {
    use diorama_supervisor::process::{ProcessCleanupSnapshot, ProcessExit};
    use dioramactl::preparation::{CommandReceipt, PreparationStep};
    let state = Rc::new(RefCell::new(State {
        root: true,
        ..State::default()
    }));
    let mut executor = ReceiptExecutor {
        returned: Rc::new(std::cell::Cell::new(false)),
        receipt: PreparationReceipt {
            commands: vec![CommandReceipt {
                step: PreparationStep::InstallPackages,
                cause: diorama_supervisor::StopCause::Finished,
                cleanup: ProcessCleanupSnapshot {
                    started: true,
                    spawned: true,
                    thread_finished: true,
                    thread_joined: true,
                    leader_reaped: true,
                    exit: Some(ProcessExit {
                        code: Some(0),
                        signal: None,
                    }),
                    ..Default::default()
                },
            }],
            failure: None,
        },
    };
    let mut output = vec![];
    assert_eq!(
        dioramactl::check_workflow::execute_check_with_preparation(
            CheckOptions {
                install_prerequisites: true,
                pprof: false
            },
            &mut Inputs(state),
            &mut executor,
            &Cancellation::default(),
            &mut output
        )
        .await
        .unwrap(),
        1
    );
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("still missing"));
    assert!(text.contains("Shared host state may have changed"));
}
