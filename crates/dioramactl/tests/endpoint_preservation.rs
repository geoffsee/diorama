use dioramactl::contract::KubeconfigOptions;
use dioramactl::endpoints::{
    PublishedEndpoint, UnavailableEngine, execute_endpoint_command, route_context,
};
use dioramactl::kubeconfig::parse_kubeconfig_content;
use serde_json::json;
use std::collections::BTreeMap;

struct Inspector;

impl dioramactl::endpoints::EnginePortInspector for Inspector {
    fn inspect_port(&mut self, _: &str, _: u16) -> std::io::Result<String> {
        Ok("127.0.0.1:49153".into())
    }
}

#[test]
fn routing_shared_cluster_fails_without_mutation() {
    let mut cfg = json!({"contexts":[{"name":"dev","context":{"cluster":"shared"}},{"name":"neighbor","context":{"cluster":"shared"}}],"clusters":[{"name":"shared","cluster":{"server":"https://original:6443"}}]});
    let original = cfg.clone();
    assert!(route_context(&mut cfg, "dev", PublishedEndpoint { port: 49153 }).is_err());
    assert_eq!(cfg, original);
    let neighbor_cluster = cfg["contexts"][1]["context"]["cluster"].as_str().unwrap();
    let neighbor_server = cfg["clusters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == neighbor_cluster)
        .unwrap()["cluster"]["server"]
        .clone();
    assert_eq!(neighbor_server, "https://original:6443");
}

#[test]
fn remove_preserves_unrelated_exec_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    let cfg = json!({"apiVersion":"v1","kind":"Config","contexts":[{"name":"dev","context":{"cluster":"dev","user":"dev"}},{"name":"neighbor","context":{"cluster":"neighbor","user":"neighbor"}}],"clusters":[{"name":"dev","cluster":{"server":"https://dev:6443"}},{"name":"neighbor","cluster":{"server":"https://neighbor:6443"}}],"users":[{"name":"dev","user":{"token":"abc"}},{"name":"neighbor","user":{"exec":{"apiVersion":"client.authentication.k8s.io/v1","command":"cloud-token","interactiveMode":"Never"}}}],"preferences":{"colors":true},"extensions":[{"name":"unrelated","extension":{"value":"kept"}}]});
    std::fs::write(&path, serde_json::to_string(&cfg).unwrap()).unwrap();
    let options = KubeconfigOptions {
        subcommand: Some("remove".into()),
        name: Some("dev".into()),
        output: Some(path.clone()),
        ..Default::default()
    };
    let env = BTreeMap::from([("HOME".to_string(), dir.path().display().to_string())]);
    let code = execute_endpoint_command(
        &options,
        &mut UnavailableEngine,
        &env,
        &mut Vec::new(),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(code, 0);
    let written = parse_kubeconfig_content(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(
        written["users"][0]["user"]["exec"],
        cfg["users"][1]["user"]["exec"]
    );
}

#[test]
fn yaml_exec_arguments_and_preferences_survive_routing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    let document = "apiVersion: v1\nkind: Config\nclusters:\n- name: dev\n  cluster:\n    server: https://original:6443\ncontexts:\n- name: dev\n  context:\n    cluster: dev\n    user: cloud\nusers:\n- name: cloud\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: cloud-token\n      args:\n      - get-token\n      - '--cluster=dev'\n      interactiveMode: Never\npreferences:\n  colors: true\n";
    std::fs::write(&path, document).unwrap();
    let opts = KubeconfigOptions {
        subcommand: Some("route".into()),
        name: Some("dev".into()),
        output: Some(path.clone()),
        ..Default::default()
    };
    let env = BTreeMap::from([("HOME".into(), dir.path().display().to_string())]);
    let mut expected = parse_kubeconfig_content(document).unwrap();
    expected["clusters"][0]["cluster"]["server"] = json!("https://127.0.0.1:49153");
    assert_eq!(
        execute_endpoint_command(
            &opts,
            &mut Inspector,
            &env,
            &mut Vec::new(),
            &mut Vec::new()
        )
        .unwrap(),
        0
    );
    let written = parse_kubeconfig_content(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(written, expected);
}
