//! Signal handlers are installed only in owned child test processes, never this test runner.
#![cfg(unix)]
use diorama_supervisor::signals::{ShutdownSignal, run_with_signals};
use diorama_supervisor::*;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant};

struct Fixture {
    mode: String,
    dependent: bool,
    started: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
}
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Adapter for Fixture {
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            self.started.fetch_add(1, Ordering::SeqCst);
            self.active.fetch_add(1, Ordering::SeqCst);
            let _active = Active(self.active);
            if self.dependent && self.mode == "fatal" {
                return Err(AdapterError {
                    code: "fixture_worker_failed",
                });
            }
            if self.mode == "partial" {
                assert!(
                    !self.dependent,
                    "partial startup must not release dependent"
                );
                println!("diorama_READY");
            } else {
                context.ready();
                if self.dependent {
                    println!("diorama_READY");
                }
            }
            while context.stop_phase() == StopPhase::Running {
                context.changed().await;
            }
            println!("diorama_STOPPING");
            // Allow the parent to deliver repeated signals while cleanup is in progress.
            tokio::time::sleep(Duration::from_millis(60)).await;
            Ok(())
        })
    }
}

#[test]
#[ignore = "invoked only by the owned-subprocess qualification test"]
fn signal_child() {
    let mode = std::env::var("diorama_SIGNAL_FIXTURE").expect("private child mode");
    let started = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let registrations = [
        ("core", vec![], false),
        ("dependent", vec!["core".into()], true),
    ]
    .into_iter()
    .map(|(id, prerequisites, dependent)| {
        Registration::new(
            ComponentSpec {
                id: id.into(),
                prerequisites,
                kind: ComponentKind::LongRunning,
                failure_policy: FailurePolicy::Fatal,
                startup_timeout: Duration::from_secs(2),
            },
            Fixture {
                mode: mode.clone(),
                dependent,
                started: started.clone(),
                active: active.clone(),
            },
        )
    })
    .collect();
    let supervisor = Supervisor::new(registrations).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let report = runtime.block_on(run_with_signals(supervisor)).unwrap();
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(
        started.load(Ordering::SeqCst),
        if mode == "partial" { 1 } else { 2 }
    );
    assert_eq!(report.supervisor.cleanup_failures, []);
    assert_eq!(report.listener_closed, None);
    if mode == "fatal" {
        assert_eq!(report.first_signal, None);
        assert_eq!(
            report.supervisor.cause,
            StopCause::Fatal(ComponentFailure {
                component: "dependent".into(),
                kind: FailureKind::Adapter("fixture_worker_failed"),
            })
        );
    } else {
        assert_eq!(report.supervisor.cause, StopCause::Requested);
        let expected = std::env::var("diorama_EXPECT_SIGNAL").unwrap();
        assert_eq!(
            report.first_signal,
            Some(if expected == "INT" {
                ShutdownSignal::Interrupt
            } else {
                ShutdownSignal::Terminate
            })
        );
        assert_eq!(report.supervisor.failures, []);
    }
    println!(
        "diorama_RESULT mode={mode} first={:?} active=0 cleanup=clean",
        report.first_signal
    );
}

struct OwnedChild {
    child: Child,
    reaped: bool,
    reader: Option<thread::JoinHandle<String>>,
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
fn wait_marker(receiver: &mpsc::Receiver<String>, marker: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let line = receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|error| panic!("missing child {marker}: {error}"));
        if line == marker {
            return;
        }
    }
}
fn send(child: &mut OwnedChild, signal: &str) {
    if let Some(status) = child.child.try_wait().unwrap() {
        child.reaped = true;
        panic!("fixture exited before signal: {status}");
    }
    // No wait/reap between this check and delivery: even an exiting child retains
    // its PID as our waitable child, so this cannot signal a recycled unrelated PID.
    let status = Command::new("kill")
        .args([format!("-{signal}"), child.child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success(), "owned child signal failed");
}
fn run_case(mode: &str, signal: &str, repeated: bool) {
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "signals::signal_child",
            "--nocapture",
        ])
        .env_clear()
        .env("diorama_SIGNAL_FIXTURE", mode)
        .env("diorama_EXPECT_SIGNAL", signal)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut child = OwnedChild {
        child,
        reaped: false,
        reader: None,
    };
    let stdout = child.child.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    child.reader = Some(thread::spawn(move || {
        let mut output = String::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.unwrap();
            assert!(
                output.len() + line.len() < 64 * 1024,
                "fixture output exceeded budget"
            );
            output.push_str(&line);
            output.push('\n');
            let _ = sender.send(line);
        }
        output
    }));
    let mut stop_requested = Instant::now();
    if mode != "fatal" {
        wait_marker(&receiver, "diorama_READY");
        stop_requested = Instant::now();
        send(&mut child, signal);
        if repeated {
            wait_marker(&receiver, "diorama_STOPPING");
            send(&mut child, if signal == "TERM" { "INT" } else { "TERM" });
            send(&mut child, signal);
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.child.try_wait().unwrap() {
            child.reaped = true;
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "child failed to finish; Drop kills and reaps owned fixture"
        );
        thread::sleep(Duration::from_millis(5));
    };
    let elapsed = stop_requested.elapsed();
    let output = child.reader.take().unwrap().join().unwrap();
    assert!(status.success(), "child failed: {output}");
    assert!(
        output.contains("diorama_RESULT"),
        "missing result: {output}"
    );
    assert!(elapsed < Duration::from_secs(5));
}

#[test]
fn real_unix_signals_and_worker_failure_in_owned_subprocesses() {
    for _ in 0..20 {
        for mode in ["full", "partial"] {
            for signal in ["INT", "TERM"] {
                run_case(mode, signal, false);
                run_case(mode, signal, true);
            }
        }
        run_case("fatal", "TERM", false);
    }
    println!(
        "diorama_QUALIFICATION repetitions=20 full_partial_signal_cases=160 worker_failure_cases=20 all_children_reaped=true"
    );
}
