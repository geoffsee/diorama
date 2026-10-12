use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

use crate::Result;

fn patch(path: &str, value: &Value) -> Value {
    json!([{"op":"add","path":path,"value":value}])
}

#[allow(clippy::too_many_lines)]
pub fn expected() -> Result<Value> {
    let name = "webhook.kubesolo.io";
    let mut configurations = json!({"missing_certificate_fails":true});
    for enabled in [false, true] {
        let mut rules = vec![
            json!({"operations":["CREATE"],"apiGroups":["","apps","batch"],
            "apiVersions":["v1"],"resources":["pods","persistentvolumeclaims","jobs"]}),
        ];
        if enabled {
            rules.push(json!({"operations":["CREATE","UPDATE"],"apiGroups":[""],
                "apiVersions":["v1"],"resources":["services"]}));
        }
        configurations[enabled.to_string()] = json!({"metadata":{"name":name},"webhooks":[{
            "name":name,"clientConfig":{"url":"https://127.0.0.1:10443/mutate",
                "caBundle":STANDARD.encode("SYNTHETIC-WEBHOOK-CERT")},
            "rules":rules,"failurePolicy":"Ignore","sideEffects":"NoneOnDryRun",
            "timeoutSeconds":30,"admissionReviewVersions":["v1"],"reinvocationPolicy":"IfNeeded"}]});
    }
    let node = patch("/spec/nodeName", &json!("fixture-node"));
    let pvc = patch(
        "/metadata/annotations",
        &json!({"volume.kubernetes.io/selected-node":"fixture-node"}),
    );
    let job = patch(
        "/spec/template/spec/nodeSelector",
        &json!({"kubernetes.io/hostname":"fixture-node"}),
    );
    let service =
        |kind| json!({"metadata":{"name":"svc","namespace":"default"},"spec":{"type":kind}});
    let inputs = [
        (
            "pod_unassigned",
            "Pod",
            json!({"metadata":{"name":"pod"},"spec":{}}),
            Some(&node),
        ),
        (
            "pod_assigned",
            "Pod",
            json!({"spec":{"nodeName":"other-node"}}),
            None,
        ),
        ("pod_update_direct", "Pod", json!({"spec":{}}), Some(&node)),
        (
            "pvc_empty",
            "PersistentVolumeClaim",
            json!({"metadata":{}}),
            Some(&pvc),
        ),
        (
            "pvc_existing_annotation",
            "PersistentVolumeClaim",
            json!({"metadata":{"annotations":{"keep":"value"}}}),
            Some(&pvc),
        ),
        (
            "pvc_assigned",
            "PersistentVolumeClaim",
            json!({"metadata":{"annotations":{"volume.kubernetes.io/selected-node":"other-node"}}}),
            None,
        ),
        (
            "job_empty",
            "Job",
            json!({"spec":{"template":{"spec":{}}}}),
            Some(&job),
        ),
        (
            "job_existing_selector",
            "Job",
            json!({"spec":{"template":{"spec":{"nodeSelector":{"keep":"value"}}}}}),
            Some(&job),
        ),
        ("unknown_kind", "Unknown", json!({}), None),
        (
            "malformed_typed_object",
            "Pod",
            json!({"spec":"invalid"}),
            None,
        ),
        ("service_dry_run", "Service", service("LoadBalancer"), None),
        ("service_disabled", "Service", service("LoadBalancer"), None),
        (
            "service_no_address",
            "Service",
            service("LoadBalancer"),
            None,
        ),
        ("service_clusterip", "Service", service("ClusterIP"), None),
        ("wrong_content_type", "Pod", json!({"spec":{}}), Some(&node)),
    ];
    let mut requests = json!({});
    for (case, kind, object, patches) in inputs {
        let request = json!({"uid":"fixture-uid","kind":{"group":"","version":"v1","kind":kind},
            "resource":{"group":"","version":"v1","resource":"fixture"},
            "operation":if case=="pod_update_direct"{"UPDATE"}else{"CREATE"},
            "dryRun":case=="service_dry_run","object":object,"oldObject":null,"options":null,"userInfo":{}});
        let mut response = json!({"uid":"fixture-uid","allowed":true});
        if let Some(patches) = patches {
            // serde_json's default map sorts keys, matching the source oracle's canonical patch.
            response["patch"] = STANDARD.encode(serde_json::to_vec(patches)?).into();
            response["patchType"] = "JSONPatch".into();
        }
        requests[case] = json!({"status":200,"content_type":"application/json","scheduled_status_update":false,
            "admission_review":{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview",
                "request":request,"response":response}});
    }
    for (case, status, error) in [
        ("wrong_method", 405, "method not allowed"),
        (
            "malformed_body",
            400,
            "error decoding admission review: couldn't get version/kind; json parse error: unexpected end of JSON input",
        ),
        ("missing_request", 400, "admission review with no request"),
        (
            "read_failure",
            400,
            "error reading request body: synthetic read failure",
        ),
    ] {
        requests[case] = json!({"status":status,"content_type":"text/plain; charset=utf-8",
            "error":format!("{error}\n"),"scheduled_status_update":false});
    }
    let get = json!({"verb":"get","resource":"services","namespace":"default","name":"svc","subresource":""});
    let change = json!({"verb":"patch","resource":"services","namespace":"default","name":"svc",
        "subresource":"status","patch_type":"application/merge-patch+json",
        "patch":{"status":{"loadBalancer":{"ingress":[{"ip":"192.0.2.9"}]}}}});
    let mut statuses = json!({});
    for (case, actions, error) in [
        ("assign", vec![&get, &change], ""),
        ("already_correct", vec![&get], ""),
        ("stale_type", vec![&get, &get, &change], ""),
        ("get_failure", vec![&get, &get, &change], ""),
        ("patch_failure", vec![&get, &change, &get, &change], ""),
        (
            "exhausted",
            vec![&get; 5],
            "timed out waiting for the condition",
        ),
    ] {
        statuses[case] = json!({"actions":actions,"error":error,
            "get_count":actions.iter().filter(|action|action["verb"]=="get").count(),
            "patch_count":actions.iter().filter(|action|action["verb"]=="patch").count()});
    }
    Ok(
        json!({"component":"webhook","configurations":configurations,
        "handler_requests":requests,"fake_client_status":statuses}),
    )
}
