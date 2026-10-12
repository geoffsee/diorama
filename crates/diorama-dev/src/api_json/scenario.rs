use super::{normalize, require, verify};
use crate::{Result, component_boundary::runtime::Runtime, json};
use serde_json::{Map, Value, json as value};
use std::time::{Duration, Instant};
fn request(
    runtime: &mut Runtime,
    name: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
    expected: u16,
    identity: Option<&str>,
) -> Result<Value> {
    let response = runtime.http(method, path, body, identity, 10)?;
    require(
        response.raw.len() <= 2 * 1024 * 1024,
        "bounded API response",
    )?;
    runtime.report["http"].as_array_mut().ok_or("HTTP records")?.push(value!({"name":name,"method":method,"path":path,"request":body,"status":response.status,"raw_response":response.raw,"response":response.body,"raw_headers":response.headers}));
    runtime.check(
        response.status == expected,
        &format!("HTTP {name}: expected status"),
    )?;
    Ok(response.body)
}
#[expect(
    clippy::too_many_lines,
    reason = "Keep the source-reviewed ordered HTTP transaction and watch sequence together"
)]
pub(crate) fn run(runtime: &mut Runtime) -> Result<()> {
    runtime.report["http"] = value!([]);
    runtime.credentials()?;
    runtime.ready("1")?;
    runtime.datastore_negative(None)?;
    runtime.datastore_negative(Some("admin"))?;
    request(
        runtime,
        "anonymous-denied",
        "GET",
        "/api/v1/namespaces",
        None,
        401,
        None,
    )?;
    request(
        runtime,
        "rbac-denied",
        "GET",
        "/api/v1/namespaces",
        None,
        403,
        Some("unprivileged"),
    )?;
    request(
        runtime,
        "namespace",
        "POST",
        "/api/v1/namespaces",
        Some(
            &value!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":"serialization-fixture"}}),
        ),
        201,
        Some("admin"),
    )?;
    let prefix = "/api/v1/namespaces/serialization-fixture";
    request(
        runtime,
        "service-account",
        "POST",
        &format!("{prefix}/serviceaccounts"),
        Some(&value!({"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"default"}})),
        201,
        Some("admin"),
    )?;
    let pod = value!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"quantities","labels":{"fixture":"json"},"annotations":{"example.test/text":"literal: null"},"finalizers":null},"spec":{"automountServiceAccountToken":false,"containers":[{"name":"main","image":"example.invalid/fixture:v1","resources":{"requests":{"cpu":"0.5","memory":"1.5Gi","ephemeral-storage":"1e3"},"limits":{"cpu":"1","memory":"2Gi"}}}],"nodeSelector":null}});
    request(
        runtime,
        "pod-create",
        "POST",
        &format!("{prefix}/pods"),
        Some(&pod),
        201,
        Some("admin"),
    )?;
    request(
        runtime,
        "pod-read",
        "GET",
        &format!("{prefix}/pods/quantities"),
        None,
        200,
        Some("admin"),
    )?;
    let service = value!({"apiVersion":"v1","kind":"Service","metadata":{"name":"ports","annotations":null},"spec":{"clusterIP":"None","selector":{"fixture":"json"},"ports":[{"name":"named","port":80,"targetPort":"http"},{"name":"numeric","port":81,"targetPort":8080}]}});
    request(
        runtime,
        "service-create",
        "POST",
        &format!("{prefix}/services"),
        Some(&service),
        201,
        Some("admin"),
    )?;
    request(
        runtime,
        "service-read",
        "GET",
        &format!("{prefix}/services/ports"),
        None,
        200,
        Some("admin"),
    )?;
    let crd = value!({"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"samples.fixture.diorama.test"},"spec":{"group":"fixture.diorama.test","scope":"Namespaced","names":{"plural":"samples","singular":"sample","kind":"Sample"},"versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","properties":{"spec":{"type":"object","x-kubernetes-preserve-unknown-fields":true}}}}}]}});
    let crd_path = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions";
    request(
        runtime,
        "crd-create",
        "POST",
        crd_path,
        Some(&crd),
        201,
        Some("admin"),
    )?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        runtime.alive()?;
        let observation = request(
            runtime,
            "crd-ready",
            "GET",
            &format!("{crd_path}/samples.fixture.diorama.test"),
            None,
            200,
            Some("admin"),
        )?;
        if observation["status"]["conditions"]
            .as_array()
            .is_some_and(|conditions| {
                conditions
                    .iter()
                    .any(|c| c["type"] == "Established" && c["status"] == "True")
            })
        {
            break;
        }
        require(Instant::now() < deadline, "CRD readiness timeout")?;
        std::thread::sleep(Duration::from_millis(200));
    }
    let custom = value!({"apiVersion":"fixture.diorama.test/v1","kind":"Sample","metadata":{"name":"arbitrary"},"spec":{"unknown":{"metadata":{"uid":"user-value"},"null":null,"bool":false,"integer":17,"decimal":1.25,"list":[null,true,"7",7,{"nested":"value"}]}}});
    let custom_path = "/apis/fixture.diorama.test/v1/namespaces/serialization-fixture/samples";
    request(
        runtime,
        "custom-create",
        "POST",
        custom_path,
        Some(&custom),
        201,
        Some("admin"),
    )?;
    request(
        runtime,
        "custom-read",
        "GET",
        &format!("{custom_path}/arbitrary"),
        None,
        200,
        Some("admin"),
    )?;
    let before = request(
        runtime,
        "watch-before",
        "GET",
        &format!("{prefix}/configmaps"),
        None,
        200,
        Some("admin"),
    )?["metadata"]["resourceVersion"]
        .as_str()
        .ok_or("watch resource version")?
        .to_owned();
    require(
        !before.is_empty() && before.bytes().all(|b| b.is_ascii_digit()),
        "numeric watch version",
    )?;
    let item = value!({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"watched"},"data":{"value":"first"}});
    let mut created = request(
        runtime,
        "watch-create",
        "POST",
        &format!("{prefix}/configmaps"),
        Some(&item),
        201,
        Some("admin"),
    )?;
    created["data"]["value"] = "second".into();
    request(
        runtime,
        "watch-update",
        "PUT",
        &format!("{prefix}/configmaps/watched"),
        Some(&created),
        200,
        Some("admin"),
    )?;
    request(
        runtime,
        "watch-delete",
        "DELETE",
        &format!("{prefix}/configmaps/watched"),
        None,
        200,
        Some("admin"),
    )?;
    let response = runtime.http("GET", &format!("{prefix}/configmaps?watch=true&timeoutSeconds=10&fieldSelector=metadata.name%3Dwatched&resourceVersion={before}"), None, Some("admin"), 15)?;
    require(response.status == 200, "watch HTTP status")?;
    let lines = response.raw.split_inclusive('\n').collect::<Vec<_>>();
    require(
        lines.len() == 3
            && lines
                .iter()
                .all(|line| !line.is_empty() && line.len() <= 1024 * 1024),
        "three bounded watch events",
    )?;
    runtime.report["raw_watch_lines"] = value!(lines);
    runtime.report["watch_headers"] = response.headers.into();
    let watch = lines
        .iter()
        .map(|line| {
            let event = json::parse(line.as_bytes())?;
            Ok(value!({"type":event["type"],"object":normalize(&event["object"])}))
        })
        .collect::<Result<Vec<_>>>()?;
    let records = runtime.report["http"].as_array().ok_or("HTTP records")?;
    let mut cases = Map::new();
    for name in [
        "pod-create",
        "pod-read",
        "service-create",
        "service-read",
        "custom-create",
        "custom-read",
    ] {
        let row = records
            .iter()
            .find(|row| row["name"] == name)
            .ok_or("fixture case")?;
        cases.insert(name.into(), normalize(&row["response"]));
    }
    runtime.report["fixture"] = value!({"schema_version":1,"cases":cases,"watch":watch});
    verify(&runtime.report["fixture"])
}
