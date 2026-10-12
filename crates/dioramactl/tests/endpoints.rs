use dioramactl::endpoints::*;
use serde_json::{Value, json};

fn cfg() -> Value {
    json!({
        "clusters": [
            {"name": "a", "cluster": {"server": "https://10.0.0.1:6443", "certificate-authority-data": "CA-A"}},
            {"name": "b", "cluster": {"server": "https://10.0.0.2:6443", "certificate-authority-data": "CA-B"}},
            {"name": "other", "cluster": {"server": "https://x:1"}}
        ],
        "contexts": [
            {"name": "a", "context": {"cluster": "a", "user": "ua"}},
            {"name": "b", "context": {"cluster": "b", "user": "ub"}},
            {"name": "other", "context": {"cluster": "other", "user": "uo"}}
        ],
        "users": [
            {"name": "ua", "user": {"token": "ta"}},
            {"name": "ub", "user": {"token": "tb"}},
            {"name": "uo", "user": {"token": "to"}}
        ],
        "current-context": "a"
    })
}

#[test]
fn resolves_port_from_dual_stack_output() {
    let e = resolve_published_endpoint("0.0.0.0:49153\n[::]:49153\n").unwrap();
    assert_eq!(e.server_url(), "https://127.0.0.1:49153");
    assert_eq!(
        resolve_published_endpoint("garbage"),
        Err(EndpointError::NoPublishedPort)
    );
    assert_eq!(
        resolve_published_endpoint(""),
        Err(EndpointError::NoPublishedPort)
    );
}

#[test]
fn routes_two_clusters_to_distinct_ports_keeping_trust() {
    let mut c = cfg();
    route_context(&mut c, "a", PublishedEndpoint { port: 40001 }).unwrap();
    route_context(&mut c, "b", PublishedEndpoint { port: 40002 }).unwrap();
    assert_eq!(
        c["clusters"][0]["cluster"]["server"],
        "https://127.0.0.1:40001"
    );
    assert_eq!(
        c["clusters"][1]["cluster"]["server"],
        "https://127.0.0.1:40002"
    );
    assert_eq!(
        c["clusters"][0]["cluster"]["certificate-authority-data"],
        "CA-A"
    );
    assert_eq!(
        c["clusters"][1]["cluster"]["certificate-authority-data"],
        "CA-B"
    );
    assert_eq!(c["clusters"][2]["cluster"]["server"], "https://x:1");
    assert_eq!(c["users"][0]["user"]["token"], "ta");
}

#[test]
fn route_unknown_context_fails() {
    let mut c = cfg();
    assert_eq!(
        route_context(&mut c, "zzz", PublishedEndpoint { port: 1 }),
        Err(EndpointError::ContextNotFound("zzz".into()))
    );
}

#[test]
fn cleanup_removes_only_selected_entries() {
    let mut c = cfg();
    assert!(remove_instance(&mut c, "a"));
    assert_eq!(c["contexts"].as_array().unwrap().len(), 2);
    assert_eq!(c["clusters"].as_array().unwrap().len(), 2);
    assert_eq!(c["users"].as_array().unwrap().len(), 2);
    assert!(c.get("current-context").is_none());
    assert!(!remove_instance(&mut c, "a"));
}

#[test]
fn cleanup_keeps_shared_cluster_and_user_and_current_context() {
    let mut c = cfg();
    c["contexts"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "a2", "context": {"cluster": "a", "user": "ua"}}));
    assert!(remove_instance(&mut c, "b"));
    assert!(remove_instance(&mut c, "a2"));
    assert_eq!(c["clusters"].as_array().unwrap().len(), 2);
    assert_eq!(c["users"].as_array().unwrap().len(), 2);
    assert_eq!(c["current-context"], "a");
}
