use diorama_platform::preflight::PortAvailability;
use diorama_platform::preflight_probe::SupplementalFacts;
use diorama_platform::{
    ExecutableAbi, HostEvidence, Observation, PlatformError, Privileges, ProbeFailure,
};
use dioramactl::{CheckInputs, Command, HelpTopic, ParseError};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).into()).collect()
}
#[allow(clippy::struct_excessive_bools)]
struct Fake {
    calls: Vec<&'static str>,
    root: bool,
    port_result: Observation<PortAvailability>,
    expected_pprof: bool,
    failure: Option<&'static str>,
    alpine: bool,
    tools: bool,
}
impl Fake {
    fn new() -> Self {
        Self {
            calls: vec![],
            root: true,
            port_result: Observation::Present(PortAvailability::Available),
            expected_pprof: false,
            failure: None,
            alpine: false,
            tools: true,
        }
    }
}
impl CheckInputs for Fake {
    fn discover(&mut self) -> Result<HostEvidence, PlatformError> {
        self.calls.push("discover");
        if self.failure == Some("discover") {
            return Err(PlatformError::UnsupportedHost);
        }
        let mut landmarks = [
            "/var/run/docker.sock",
            "/usr/bin/docker",
            "/usr/local/bin/docker",
        ]
        .into_iter()
        .map(|p| (p.into(), Observation::Absent))
        .collect::<BTreeMap<_, _>>();
        landmarks.insert(
            "/etc/alpine-release".into(),
            if self.alpine {
                Observation::Present(true)
            } else {
                Observation::Absent
            },
        );
        for path in [
            "/usr/sbin/nft",
            "/sbin/nft",
            "/usr/bin/nft",
            "/sbin/iptables",
            "/usr/sbin/iptables",
            "/bin/iptables",
            "/usr/bin/iptables",
        ] {
            landmarks.insert(
                path.into(),
                if self.tools {
                    Observation::Present(true)
                } else {
                    Observation::Absent
                },
            );
        }
        Ok(HostEvidence {
            executable: ExecutableAbi {
                os: "linux".into(),
                architecture: "aarch64".into(),
                environment: "gnu".into(),
            },
            kernel: Observation::Unknown(ProbeFailure::Malformed),
            privileges: Observation::Present(Privileges {
                real_uid: if self.root { 0 } else { 65534 },
                effective_uid: 0,
            }),
            hostname: Observation::Present("node".into()),
            container_environment_set: false,
            landmarks,
            musl_linkers: Observation::Present(vec![]),
            files: [(
                "/sys/fs/cgroup/cgroup.controllers".into(),
                Observation::Present("cpuset cpu io memory pids".into()),
            )]
            .into_iter()
            .collect(),
            requested_paths: vec![],
        })
    }
    fn supplemental(&mut self) -> Result<SupplementalFacts, PlatformError> {
        self.calls.push("supplemental");
        if self.failure == Some("supplemental") {
            return Err(PlatformError::InvalidLimits);
        }
        Ok(SupplementalFacts {
            xt_comment_on_disk: Observation::Present(true),
            alpine_rc_service: Observation::Absent,
        })
    }
    fn ports(&mut self, pprof: bool) -> Result<[Observation<PortAvailability>; 4], PlatformError> {
        self.calls.push("ports");
        if self.failure == Some("ports") {
            return Err(PlatformError::UnsupportedHost);
        }
        assert_eq!(pprof, self.expected_pprof);
        Ok([self.port_result; 4])
    }
}
fn execute(a: &[&str], fake: &mut Fake) -> (u8, String, String) {
    let (mut out, mut err) = (vec![], vec![]);
    let code = dioramactl::execute(
        &args(a),
        &BTreeMap::new(),
        "fixture",
        fake,
        &mut out,
        &mut err,
    )
    .unwrap();
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}
#[test]
fn actual_cobra_cases_match_independent_parser_expectations() {
    let cases: Vec<Value> = serde_json::from_str(include_str!(
        "../../../tools/parity/fixtures/management-check/cases.json"
    ))
    .unwrap();
    let expected: Vec<Value> = serde_json::from_str(include_str!(
        "../../../tools/parity/fixtures/management-check/expected.json"
    ))
    .unwrap();
    assert_eq!(cases.len(), 56);
    assert_eq!(cases.len(), expected.len());
    for (case, expected) in cases.iter().zip(expected) {
        let args = case["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let env = case["env"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().into()))
            .collect();
        let actual = match dioramactl::parse_command(&args, &env) {
            Ok(Command::Check(options)) => {
                json!({"name":case["name"],"outcome":"check","install":options.install_prerequisites,"pprof":options.pprof})
            },
            result => json!({"name":case["name"],"outcome":match result {
             Ok(Command::Help(HelpTopic::Root))=>"help_root",Ok(Command::Help(HelpTopic::Check))=>"help_check",Ok(Command::Help(HelpTopic::Version))=>"help_version",Ok(Command::Version)=>"version",Ok(Command::UnknownHelp)=>"unknown_help",
             Err(ParseError::UnknownCommand)=>"unknown_command",Err(ParseError::UnknownFlag)=>"unknown_flag",Err(ParseError::InvalidBoolean)=>"invalid_boolean",other=>panic!("unexpected {other:?}"),
            }}),
        };
        assert_eq!(actual, expected, "{}", case["name"]);
    }
}
#[test]
fn help_version_parse_failure_and_unsupported_preparation_have_no_effects() {
    for (arguments, code) in [
        (vec!["check", "--help"], 0),
        (vec!["version"], 0),
        (vec!["check", "--bad=private-token"], 1),
        (vec!["check", "--install-prereqs"], 1),
    ] {
        let mut fake = Fake::new();
        let result = execute(&arguments, &mut fake);
        assert_eq!(result.0, code);
        assert!(fake.calls.is_empty());
        assert!(!result.2.contains("private-token"));
    }
    let mut fake = Fake::new();
    let mut output = vec![];
    assert_eq!(
        dioramactl::execute(
            &args(&["check"]),
            &BTreeMap::from([("KUBESOLO_INSTALL_PREREQS".into(), "yes".into())]),
            "v",
            &mut fake,
            &mut output,
            &mut vec![]
        )
        .unwrap(),
        1
    );
    assert!(fake.calls.is_empty());
}
#[test]
fn earlier_failure_prevents_ports_and_required_port_failure_remains_nonzero() {
    let mut fake = Fake::new();
    fake.root = false;
    let result = execute(&["check"], &mut fake);
    assert_eq!(result.0, 1);
    assert_eq!(fake.calls, ["discover", "supplemental"]);
    assert!(result.2.contains("root privileges required"));
    assert!(!result.2.contains("All 7"));
    let mut fake = Fake::new();
    fake.port_result = Observation::Present(PortAvailability::BindFailed);
    let result = execute(&["check"], &mut fake);
    assert_eq!(result.0, 1);
    assert_eq!(fake.calls, ["discover", "supplemental", "ports"]);
    assert!(result.2.contains("required TCP port could not be bound"));
    assert!(!result.2.contains("All 7"));
}
#[test]
fn successful_pprof_check_reports_only_observed_prerequisites() {
    let mut fake = Fake::new();
    fake.expected_pprof = true;
    let result = execute(&["check", "--pprof-server"], &mut fake);
    assert_eq!(result.0, 0);
    assert!(result.1.is_empty());
    assert!(result.2.contains("All 7 checks passed"));
    assert!(result.2.contains("ports are not reserved"));
    assert_eq!(fake.calls, ["discover", "supplemental", "ports"]);
}
#[test]
fn output_failure_precedes_host_effects_and_input_budget_is_explicit() {
    struct Broken;
    impl io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut fake = Fake::new();
    assert!(
        dioramactl::execute(
            &args(&["check"]),
            &BTreeMap::new(),
            "v",
            &mut fake,
            &mut vec![],
            &mut Broken
        )
        .is_err()
    );
    assert!(fake.calls.is_empty());
    assert_eq!(
        dioramactl::parse_command(&vec!["x".into(); 257], &BTreeMap::new()),
        Err(ParseError::TooManyArguments)
    );
}
#[test]
fn real_help_and_version_executable_do_not_need_host_support() {
    for argument in ["--help", "version"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_dioramactl"))
            .arg(argument)
            .env_clear()
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("dioramactl")
        );
    }
}

#[test]
fn probe_errors_and_unknown_ports_never_pass_or_hide_earlier_progress() {
    for (stage, calls) in [("discover", 1), ("supplemental", 2), ("ports", 3)] {
        let mut fake = Fake::new();
        fake.failure = Some(stage);
        let result = execute(&["check"], &mut fake);
        assert_eq!(result.0, 1);
        assert_eq!(fake.calls.len(), calls);
        assert!(!result.2.contains("All 7 checks passed"));
        if stage == "ports" {
            assert_eq!(result.2.matches("     root privileges\n").count(), 1);
            assert!(result.2.contains("     cgroups controllers\n"));
        }
    }
    let mut fake = Fake::new();
    fake.port_result = Observation::Unknown(ProbeFailure::Io);
    let result = execute(&["check"], &mut fake);
    assert_eq!(result.0, 1);
    assert!(result.2.contains("host information could not be read"));
    assert!(result.2.contains("(uncertain observation)"));
    assert!(!result.2.contains("(fatal error)"));
    assert!(!result.2.contains("All 7 checks passed"));
}

#[test]
fn check_reports_fatal_errors_and_recoverable_limitations() {
    let mut fake = Fake::new();
    fake.root = false;
    let result = execute(&["check"], &mut fake);
    assert_eq!(result.0, 1);
    assert!(result.2.contains("root privileges required (fatal error)"));
    assert!(result.2.contains("Run the check as root."));

    let mut fake_alpine = Fake::new();
    fake_alpine.alpine = true;
    fake_alpine.tools = false;
    let result = execute(&["check"], &mut fake_alpine);
    assert_eq!(result.0, 1);
    assert!(
        result
            .2
            .contains("required Alpine networking tools are missing (recoverable limitation)")
    );
    assert!(
        result
            .2
            .contains("Install the missing networking packages, or opt in with --install-prereqs.")
    );
}
