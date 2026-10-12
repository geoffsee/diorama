//! Docker CLI adapter for the existing Engine request boundary.
use crate::container::{
    ContainerConfig, ContainerEngineClient, ContainerInspect, CreateNetworkRequest,
    CreateVolumeRequest,
};
use serde_json::Value;
use std::{
    collections::HashMap,
    io::{self, Write},
    time::Duration,
};

#[derive(Debug, Default)]
pub struct DockerEngine;

impl DockerEngine {
    fn output(args: &[&str]) -> io::Result<crate::docker_command::CommandOutput> {
        let timeout =
            if args.first() == Some(&"image") && matches!(args.get(1), Some(&"load" | &"pull")) {
                Duration::from_mins(10)
            } else {
                Duration::from_mins(1)
            };
        crate::docker_command::output("docker", args, timeout)
    }

    fn run(args: &[&str]) -> io::Result<String> {
        let out = Self::output(args)?;
        if !out.successful {
            return Err(io::Error::other(format!(
                "Docker {} failed: {}",
                args[0],
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        String::from_utf8(out.stdout).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn inspect(kind: &str, name: &str) -> io::Result<Option<Value>> {
        let out = Self::output(&[kind, "inspect", "--", name])?;
        if !out.successful {
            let message = String::from_utf8_lossy(&out.stderr);
            let absent = match kind {
                "network" => {
                    message.contains("No such network")
                        || message.contains(&format!("network {name} not found"))
                },
                "volume" => message.contains("no such volume"),
                "image" => message.contains("No such image"),
                "container" => {
                    message.contains("No such container") || message.contains("No such object")
                },
                _ => false,
            };
            if absent {
                return Ok(None);
            }
            return Err(io::Error::other(format!(
                "Docker inspect failed: {}",
                message.trim()
            )));
        }
        let rows: Vec<Value> = serde_json::from_slice(&out.stdout)?;
        if rows.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Docker inspect did not return exactly one object",
            ));
        }
        Ok(rows.into_iter().next())
    }

    /// Query the Engine VM, rather than assuming the management host architecture.
    pub fn architecture() -> io::Result<diorama_assets::Architecture> {
        let info: Value = serde_json::from_str(&Self::run(&["info", "--format", "{{json .}}"])?)?;
        if info["OSType"] != "linux" {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "container installation requires a Linux Docker Engine",
            ));
        }
        match info["Architecture"].as_str() {
            Some("x86_64" | "amd64") => Ok(diorama_assets::Architecture::Amd64),
            Some("aarch64" | "arm64") => Ok(diorama_assets::Architecture::Arm64),
            Some("armv7l" | "armv7" | "arm") => Ok(diorama_assets::Architecture::ArmV7),
            Some("riscv64") => Ok(diorama_assets::Architecture::Riscv64),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported Docker Engine architecture",
            )),
        }
    }
}

impl ContainerEngineClient for DockerEngine {
    fn inspect_network(&mut self, name: &str) -> io::Result<Option<CreateNetworkRequest>> {
        Ok(Self::inspect("network", name)?.map(|v| {
            let mut req = CreateNetworkRequest::new(name, None);
            req.driver = v["Driver"].as_str().unwrap_or_default().into();
            req.options = v["Options"]
                .as_object()
                .map(|o| {
                    o.iter()
                        .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.into())))
                        .collect()
                })
                .unwrap_or_default();
            req
        }))
    }
    fn create_network(&mut self, req: &CreateNetworkRequest) -> io::Result<()> {
        let mut args = vec![
            "network".into(),
            "create".into(),
            "--driver".into(),
            req.driver.clone(),
        ];
        for (k, v) in &req.options {
            args.extend(["--opt".into(), format!("{k}={v}")]);
        }
        args.extend(["--".into(), req.name.clone()]);
        Self::run(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
        Ok(())
    }
    fn remove_network(&mut self, name: &str) -> io::Result<()> {
        Self::run(&["network", "rm", "--", name]).map(|_| ())
    }
    fn inspect_volume(&mut self, name: &str) -> io::Result<Option<()>> {
        Self::inspect("volume", name).map(|v| v.map(|_| ()))
    }
    fn create_volume(&mut self, req: &CreateVolumeRequest) -> io::Result<()> {
        let mut args = vec![
            "volume".into(),
            "create".into(),
            "--driver".into(),
            req.driver.clone(),
        ];
        for (k, v) in &req.labels {
            args.extend(["--label".into(), format!("{k}={v}")]);
        }
        args.extend(["--".into(), req.name.clone()]);
        Self::run(&args.iter().map(String::as_str).collect::<Vec<_>>()).map(|_| ())
    }
    fn remove_volume(&mut self, name: &str) -> io::Result<()> {
        Self::run(&["volume", "rm", "--", name]).map(|_| ())
    }
    fn inspect_image(&mut self, image: &str) -> io::Result<Option<()>> {
        Self::inspect("image", image).map(|v| v.map(|_| ()))
    }
    fn pull_image(&mut self, image: &str) -> io::Result<()> {
        Self::run(&["image", "pull", "--", image]).map(|_| ())
    }
    fn load_image(&mut self, bytes: &[u8]) -> io::Result<()> {
        // A private file keeps validation/import bound to the same bytes without
        // introducing a pipe deadlock if the client rejects a large archive early.
        let mut archive = tempfile::NamedTempFile::new()?;
        archive.write_all(bytes)?;
        Self::run(&[
            "image",
            "load",
            "--input",
            archive.path().to_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "image staging path is not UTF-8",
                )
            })?,
        ])
        .map(|_| ())
    }
    fn inspect_container(&mut self, name: &str) -> io::Result<Option<ContainerInspect>> {
        Self::inspect("container", name)?
            .map(|v| parse_container_inspect(&v))
            .transpose()
    }
    fn create_container(&mut self, name: &str, config: &ContainerConfig) -> io::Result<String> {
        let mut args = vec![
            "container".into(),
            "create".into(),
            "--name".into(),
            name.into(),
            "--hostname".into(),
            config.hostname.clone(),
            "--network".into(),
            config.network_mode.clone(),
            "--restart".into(),
            config.restart_policy.clone(),
            "--cgroupns".into(),
            config.cgroupns_mode.clone(),
        ];
        if config.privileged {
            args.push("--privileged".into());
        }
        for env in &config.env {
            args.extend(["--env".into(), env.clone()]);
        }
        for bind in &config.binds {
            args.extend(["--volume".into(), bind.clone()]);
        }
        for port in &config.exposed_ports {
            args.extend(["--expose".into(), port.clone()]);
        }
        for (port, bindings) in &config.port_bindings {
            for b in bindings {
                args.extend([
                    "--publish".into(),
                    format!("{}:{}:{port}", b.host_ip, b.host_port),
                ]);
            }
        }
        // Prevent create from initiating an implicit registry pull, especially
        // after an offline import or a concurrent removal of the local tag.
        args.extend(["--pull=never".into(), "--".into(), config.image.clone()]);
        Ok(
            Self::run(&args.iter().map(String::as_str).collect::<Vec<_>>())?
                .trim()
                .into(),
        )
    }
    fn start_container(&mut self, id: &str) -> io::Result<()> {
        Self::run(&["container", "start", "--", id]).map(|_| ())
    }
    fn stop_container(&mut self, id: &str, timeout: u32) -> io::Result<()> {
        Self::run(&[
            "container",
            "stop",
            "--time",
            &timeout.to_string(),
            "--",
            id,
        ])
        .map(|_| ())
    }
    fn remove_container(&mut self, id: &str, force: bool) -> io::Result<()> {
        if force {
            Self::run(&["container", "rm", "--force", "--", id]).map(|_| ())
        } else {
            Self::run(&["container", "rm", "--", id]).map(|_| ())
        }
    }
}

fn parse_container_inspect(v: &Value) -> io::Result<ContainerInspect> {
    let mut ports = HashMap::new();
    if let Some(mapping) = v["NetworkSettings"]["Ports"].as_object() {
        for (port, bindings) in mapping {
            if let Some(first) = bindings.as_array().and_then(|b| b.first()) {
                let number = first["HostPort"]
                    .as_str()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "missing Docker HostPort")
                    })?
                    .parse::<u16>()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                ports.insert(port.clone(), number);
            }
        }
    }
    Ok(ContainerInspect {
        id: v["Id"]
            .as_str()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing Docker container ID")
            })?
            .into(),
        name: v["Name"]
            .as_str()
            .unwrap_or_default()
            .trim_start_matches('/')
            .into(),
        running: v["State"]["Running"].as_bool().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing Docker running state")
        })?,
        d2k_enabled: v["Config"]["Env"]
            .as_array()
            .is_some_and(|env| env.iter().any(|v| v == "KUBESOLO_D2K=true")),
        exit_code: v["State"]["ExitCode"]
            .as_i64()
            .and_then(|n| i32::try_from(n).ok())
            .unwrap_or_default(),
        allocated_ports: ports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inspect_preserves_allocated_api_ports_and_effective_d2k_state() {
        let raw = serde_json::json!({"Id":"node","Name":"/kubesolo-x","State":{"Running":true,"ExitCode":0},"Config":{"Env":["KUBESOLO_D2K=true"]},"NetworkSettings":{"Ports":{"6443/tcp":[{"HostIp":"127.0.0.1","HostPort":"32768"}],"2376/tcp":[{"HostIp":"127.0.0.1","HostPort":"32769"}]}}});
        let parsed = parse_container_inspect(&raw).unwrap();
        assert_eq!(parsed.allocated_ports["6443/tcp"], 32768);
        assert!(parsed.d2k_enabled);
        let mut bad = raw;
        bad["NetworkSettings"]["Ports"]["6443/tcp"][0]["HostPort"] = serde_json::json!("999999");
        assert!(parse_container_inspect(&bad).is_err());
    }
}
