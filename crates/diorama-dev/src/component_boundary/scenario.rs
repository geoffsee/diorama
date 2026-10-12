use super::runtime::Runtime;
use crate::{Result, api_json::require};
use serde_json::json;
use std::time::{Duration, Instant};
#[expect(
    clippy::too_many_lines,
    reason = "Ordered crash-recovery protocol must preserve the same object UID across all lifecycle stages"
)]
pub(super) fn run(runtime: &mut Runtime) -> Result<()> {
    runtime.credentials()?;
    runtime.ready("1")?;
    let collection = "/api/v1/namespaces/default/configmaps";
    let item = "/api/v1/namespaces/default/configmaps/boundary-probe";
    let response = runtime.http("GET", collection, None, None, 5)?;
    runtime.check(response.status == 401, "unauthenticated request rejected")?;
    let response = runtime.http("GET", collection, None, Some("unprivileged"), 5)?;
    runtime.check(
        response.status == 403,
        "authenticated identity without RBAC permission rejected",
    )?;
    let body = json!({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"boundary-probe"},"data":{"value":"created"}});
    let created = runtime.http("POST", collection, Some(&body), Some("admin"), 5)?;
    runtime.check(created.status == 201, "authenticated create succeeded")?;
    let response = runtime.http("GET", item, None, Some("admin"), 5)?;
    runtime.check(
        response.status == 200 && response.body["data"]["value"] == "created",
        "authenticated read succeeded",
    )?;
    let mut updated = response.body;
    updated["data"]["value"] = "updated".into();
    let response = runtime.http("PUT", item, Some(&updated), Some("admin"), 5)?;
    runtime.check(
        response.status == 200 && response.body["data"]["value"] == "updated",
        "authenticated update succeeded",
    )?;
    let uid = created.body["metadata"]["uid"]
        .as_str()
        .ok_or("created object UID")?
        .to_owned();
    runtime.shutdown()?;
    runtime.sqlite_check()?;
    runtime.ready("2")?;
    let recovered = runtime.http("GET", item, None, Some("admin"), 5)?;
    runtime.check(
        recovered.status == 200
            && recovered.body["data"]["value"] == "updated"
            && recovered.body["metadata"]["uid"] == uid,
        "same updated object survived component restart",
    )?;
    let mut updated = recovered.body;
    updated["data"]["value"] = "before-abrupt-kill".into();
    let response = runtime.http("PUT", item, Some(&updated), Some("admin"), 5)?;
    runtime.check(
        response.status == 200,
        "update acknowledged before abrupt datastore termination",
    )?;
    runtime.crash_kine()?;
    let api_pid = runtime.api_pid()?;
    let began = Instant::now();
    let deadline = began + Duration::from_secs(30);
    loop {
        runtime.alive()?;
        match runtime.http("GET", "/readyz?verbose", None, Some("admin"), 5) {
            Ok(response) if response.status != 200 => {
                runtime.report["datastore_outage"] =
                    json!({"http_status":response.status,"body":response.body});
                break;
            },
            Err(error) => {
                runtime.alive()?;
                runtime.report["datastore_outage"] = json!({"request_error":error.to_string()});
                break;
            },
            Ok(_) => {},
        }
        require(
            Instant::now() < deadline,
            "API readiness did not reflect datastore outage",
        )?;
        std::thread::sleep(Duration::from_millis(500));
    }
    runtime.start_kine("recovery")?;
    runtime.wait_ready("datastore-recovery", began)?;
    runtime.check(
        runtime.api_pid()? == api_pid,
        "existing API process recovered after datastore-only restart",
    )?;
    let recovered = runtime.http("GET", item, None, Some("admin"), 5)?;
    runtime.check(
        recovered.status == 200
            && recovered.body["data"]["value"] == "before-abrupt-kill"
            && recovered.body["metadata"]["uid"] == uid,
        "acknowledged update survived abrupt datastore restart",
    )?;
    let response = runtime.http("DELETE", item, None, Some("admin"), 5)?;
    runtime.check(response.status == 200, "authenticated delete succeeded")?;
    let response = runtime.http("GET", item, None, Some("admin"), 5)?;
    runtime.check(response.status == 404, "deleted object is absent")?;
    runtime.shutdown()?;
    runtime.ready("4")?;
    let response = runtime.http("GET", item, None, Some("admin"), 5)?;
    runtime.check(
        response.status == 404,
        "deletion survived second component restart",
    )?;
    runtime.shutdown()?;
    runtime.check(
        !runtime.owners_remain(),
        "all owned component processes reaped",
    )
}
