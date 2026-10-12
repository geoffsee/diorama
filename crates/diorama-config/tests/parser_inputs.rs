//! Both upstream input implementations must terminate and preserve selected YAML 1.1 semantics.
use saphyr_parser::{Event, Parser};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn unicode_inputs_complete_within_deadline() {
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "parser_inputs::parser_inputs_worker",
            "--nocapture",
        ])
        .env("diorama_PARSER_INPUTS_WORKER", "1")
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn isolated parser regression");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("poll parser regression") {
            assert!(
                status.success(),
                "isolated parser regression failed: {status}"
            );
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("parser input failed to make progress within ten seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn events(input: &str) -> Vec<Event<'_>> {
    let string: Vec<_> = Parser::new_from_str(input)
        .map(|event| {
            event
                .unwrap_or_else(|error| panic!("StrInput: {input:?}: {error}"))
                .0
        })
        .collect();
    let buffered: Vec<_> = Parser::new_from_iter(input.chars())
        .map(|event| {
            event
                .unwrap_or_else(|error| panic!("BufferedInput: {input:?}: {error}"))
                .0
        })
        .collect();
    assert_eq!(
        string, buffered,
        "input implementations differ for {input:?}"
    );
    string
}

#[test]
fn parser_inputs_worker() {
    if std::env::var_os("diorama_PARSER_INPUTS_WORKER").is_none() {
        return;
    }
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/linebreak/reference.json"))
            .expect("Go fixture");
    let cases = fixture["cases"].as_array().expect("Go cases");
    assert_eq!(
        cases.len(),
        57,
        "reassess complete independent oracle inventory"
    );
    for case in cases {
        let input = case["input"].as_str().expect("Go input");
        let parsed = events(input);
        let scalars: Vec<_> = parsed
            .iter()
            .filter_map(|event| match event {
                Event::Scalar(value, ..) => Some(value.as_ref()),
                _ => None,
            })
            .collect();
        let namespace = scalars
            .windows(2)
            .find(|pair| pair[0] == "namespace")
            .expect("namespace key from independent fixture")[1];
        assert_eq!(
            namespace,
            case["namespace"].as_str().expect("Go namespace"),
            "{}",
            case["id"]
        );
    }
    for separator in ['\u{85}', '\u{2028}', '\u{2029}'] {
        let input = format!(
            "---{separator}first: one{separator}...{separator}---{separator}second: two{separator}...{separator}"
        );
        let parsed = events(&input);
        assert_eq!(
            parsed
                .iter()
                .filter(|e| matches!(e, Event::DocumentStart(_)))
                .count(),
            2
        );
        assert_eq!(
            parsed
                .iter()
                .filter(|e| matches!(e, Event::DocumentEnd))
                .count(),
            2
        );
        let input =
            format!("# comment{separator}key:{separator}  [one,{separator}   two]{separator}");
        let parsed = events(&input);
        let scalars: Vec<_> = parsed
            .iter()
            .filter_map(|event| match event {
                Event::Scalar(value, ..) => Some(value.as_ref()),
                _ => None,
            })
            .collect();
        assert_eq!(scalars, ["key", "one", "two"]);
    }
}
