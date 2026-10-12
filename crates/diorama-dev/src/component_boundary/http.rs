use super::runtime::Runtime;
use crate::{Result, api_json::require, defaults::capture::arguments, json, read_bounded};
use serde_json::Value;
use std::{fs, path::Path};
pub(crate) struct HttpResponse {
    pub status: u16,
    pub raw: String,
    pub body: Value,
    pub headers: String,
}
impl Runtime {
    /// curl verifies the pinned fixture CA and uses an explicit certificate identity.
    pub(crate) fn http(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        identity: Option<&str>,
        seconds: u64,
    ) -> Result<HttpResponse> {
        require(
            path.starts_with('/') && !path.contains(['\r', '\n']),
            "HTTP fixture path",
        )?;
        require(
            matches!(identity, None | Some("admin" | "unprivileged")),
            "HTTP certificate identity",
        )?;
        let temporary = tempfile::tempdir_in("/state")?;
        let response = temporary.path().join("response");
        let headers = temporary.path().join("headers");
        let result = (|| {
            let mut args = arguments(&[
                "curl",
                "--silent",
                "--show-error",
                "--noproxy",
                "*",
                "--proto",
                "=https",
                "--connect-timeout",
                "5",
                "--max-time",
                &seconds.to_string(),
                "--max-filesize",
                "3145728",
                "--cacert",
                "/state/ca.crt",
                "--request",
                method,
                "--header",
                "Content-Type: application/json",
                "--output",
            ]);
            args.push(response.as_os_str().to_owned());
            args.extend(arguments(&["--dump-header"]));
            args.push(headers.as_os_str().to_owned());
            args.extend(arguments(&["--write-out", "%{http_code}"]));
            if let Some(identity) = identity {
                args.extend(arguments(&[
                    "--cert",
                    &format!("/state/{identity}.crt"),
                    "--key",
                    &format!("/state/{identity}.key"),
                ]));
            }
            if let Some(body) = body {
                let request = temporary.path().join("request");
                fs::write(&request, serde_json::to_vec(body)?)?;
                args.extend(arguments(&[
                    "--data-binary",
                    &format!("@{}", request.display()),
                ]));
            }
            args.extend(arguments(&[
                "--url",
                &format!("https://127.0.0.1:6443{path}"),
            ]));
            let outcome = self.command(&args, b"", seconds + 2, false, 3 * 1024 * 1024)?;
            require(outcome.code == 0, "HTTP transport failed")?;
            let status = std::str::from_utf8(&outcome.stdout_bytes)?.parse::<u16>()?;
            require((100..600).contains(&status), "HTTP status range")?;
            let raw = String::from_utf8(read_bounded(&response, 3 * 1024 * 1024)?)?;
            let body = if !path.contains("?watch=true") && raw.trim_start().starts_with('{') {
                json::parse(raw.as_bytes())?
            } else {
                raw.clone().into()
            };
            let headers = String::from_utf8(read_bounded(&headers, 65536)?)?;
            Ok(HttpResponse {
                status,
                raw,
                body,
                headers,
            })
        })();
        if self.uncertain() {
            let _ = temporary.keep();
        }
        result
    }
    pub(crate) fn datastore_negative(&mut self, identity: Option<&str>) -> Result<()> {
        require(
            matches!(identity, None | Some("admin")),
            "datastore negative identity",
        )?;
        let mut args = arguments(&[
            "openssl",
            "s_client",
            "-connect",
            "127.0.0.1:2379",
            "-tls1_2",
            "-verify_return_error",
            "-verify_ip",
            "127.0.0.1",
            "-CAfile",
            "/state/datastore-ca.crt",
            "-brief",
        ]);
        if let Some(identity) = identity {
            args.extend(arguments(&[
                "-cert",
                &format!("/state/{identity}.crt"),
                "-key",
                &format!("/state/{identity}.key"),
            ]));
        }
        let output = self.command(&args, b"", 10, false, 65536)?;
        let diagnostic = String::from_utf8(output.stderr_bytes)?;
        if self.report.get("datastore_tls").is_none() {
            self.report["datastore_tls"] = serde_json::json!([]);
        }
        self.report["datastore_tls"].as_array_mut().ok_or("TLS observations")?.push(serde_json::json!({"identity":identity.unwrap_or("absent"),"exit_code":output.code,"diagnostic":diagnostic}));
        let expected = if identity.is_none() {
            "alert handshake failure"
        } else {
            "alert unknown ca"
        };
        self.check(
            output.code == 1 && diagnostic.to_lowercase().contains(expected),
            "dedicated datastore rejects unauthorised certificate",
        )
    }
    pub(crate) fn sqlite_check(&mut self) -> Result<()> {
        require(
            Path::new("/state/state.db").is_file(),
            "SQLite database persisted",
        )?;
        let result = self.command(
            &arguments(&[
                "sqlite3",
                "-readonly",
                "-json",
                "/state/state.db",
                "PRAGMA integrity_check;",
            ]),
            b"",
            10,
            true,
            65536,
        )?;
        self.check(
            json::parse(&result.stdout_bytes)? == serde_json::json!([{"integrity_check":"ok"}]),
            "SQLite integrity check passed",
        )?;
        let result = self.command(&arguments(&["sqlite3", "-readonly", "-json", "/state/state.db", "SELECT count(*) AS matches FROM kine WHERE name='/registry/configmaps/default/boundary-probe';"]), b"", 10, true, 65536)?;
        let rows = json::parse(&result.stdout_bytes)?;
        require(
            rows.as_array().is_some_and(|rows| rows.len() == 1)
                && rows[0].as_object().is_some_and(|row| row.len() == 1),
            "SQLite query shape",
        )?;
        self.check(
            rows[0]["matches"].as_u64().is_some_and(|count| count > 0),
            "independent SQLite query found persisted API object",
        )
    }
}
