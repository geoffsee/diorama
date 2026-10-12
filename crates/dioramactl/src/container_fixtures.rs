//! JSON Engine request fixtures shared by Linux, macOS and WSL2 workflows.
use crate::container::{ContainerConfig, CreateNetworkRequest, CreateVolumeRequest};
use serde_json::{Map, Value, json};

/// Serializes a network creation request with escaped string values.
pub fn serialize_network_create_request(req: &CreateNetworkRequest) -> String {
    json!({"Name": req.name, "Driver": req.driver, "Options": req.options}).to_string()
}

/// Serializes a volume creation request, including labels.
pub fn serialize_volume_create_request(req: &CreateVolumeRequest) -> String {
    json!({"Name": req.name, "Driver": req.driver, "Labels": req.labels}).to_string()
}

/// Serializes a container creation request using the Engine's field names.
pub fn serialize_container_create_request(config: &ContainerConfig) -> String {
    let exposed: Map<String, Value> = config
        .exposed_ports
        .iter()
        .map(|key| (key.clone(), json!({})))
        .collect();
    let bindings: Map<String, Value> = config.port_bindings.iter().map(|(key, values)| (key.clone(), Value::Array(values.iter().map(|binding| json!({"HostIp": binding.host_ip, "HostPort": binding.host_port})).collect()))).collect();
    json!({
        "Image": config.image, "Hostname": config.hostname, "Env": config.env,
        "ExposedPorts": exposed,
        "HostConfig": {
            "Binds": config.binds, "NetworkMode": config.network_mode,
            "PortBindings": bindings, "Privileged": config.privileged,
            "CgroupnsMode": config.cgroupns_mode,
            "RestartPolicy": {"Name": config.restart_policy}
        }
    })
    .to_string()
}
