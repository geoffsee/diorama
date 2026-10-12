use diorama_config::{DecodeLimits, ErrorKind, decode, decode_with_limits};
use serde_json::Value;
#[test]
fn yaml11_physical_breaks_match_actual_go_read_before_lossy_print() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/linebreak/reference.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let config = decode(case["input"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", case["id"]))
            .config;
        assert_eq!(
            config.d2k.namespace,
            case["namespace"].as_str().unwrap(),
            "{}",
            case["id"]
        );
    }
}
#[test]
fn separator_scan_respects_limits_and_ignores_later_documents() {
    let limits = DecodeLimits {
        input_bytes: 100,
        depth: 1,
        expanded_nodes: 10,
        expanded_bytes: 100,
    };
    assert_eq!(
        decode_with_limits("d2k: {namespace: 'a\u{2028}b'}", limits)
            .unwrap_err()
            .kind,
        ErrorKind::Limit
    );
    assert!(decode("d2k: {namespace: ok}\n---\nbroken: [\u{2028}").is_ok());
}
