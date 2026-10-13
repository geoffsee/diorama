//! Decode Kubernetes protobuf request bodies into the JSON objects the rest of
//! the apiserver already stores.
//!
//! client-go sends built-in types as `application/vnd.kubernetes.protobuf`.
//! The payload is `k8s\0` plus a `runtime.Unknown` whose `raw` field is the
//! generated protobuf for that kind. Field names come from the vendored
//! Kubernetes 1.35 `generated.proto` files.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde_json::{Map, Value, json};

use crate::error::ApiserverError;

const SOURCES: &[&str] = &[
    include_str!("../../proto/staging_src_k8s.io_apimachinery_pkg_apis_meta_v1_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_apimachinery_pkg_runtime_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_apimachinery_pkg_runtime_schema_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_apimachinery_pkg_util_intstr_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_apimachinery_pkg_api_resource_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_core_v1_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_apps_v1_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_batch_v1_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_discovery_v1_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_coordination_v1_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_rbac_v1_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_networking_v1_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_storage_v1_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_policy_v1_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_autoscaling_v1_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_autoscaling_v2_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_certificates_v1_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_admissionregistration_v1_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_events_v1_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_node_v1_generated.proto"),
    include_str!("../../proto/staging_src_k8s.io_api_scheduling_v1_generated.proto"),
    include_str!(
        "../../proto/staging_src_k8s.io_apiextensions-apiserver_pkg_apis_apiextensions_v1_generated.proto"
    ),
    include_str!(
        "../../proto/staging_src_k8s.io_kube-aggregator_pkg_apis_apiregistration_v1_generated.proto"
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WireKind {
    String,
    Bytes,
    Bool,
    Int32,
    Int64,
    Uint32,
    Uint64,
    Sint32,
    Sint64,
    Float,
    Double,
    Message,
    Enum,
}

#[derive(Clone, Debug)]
struct FieldDef {
    number: u32,
    name: String,
    kind: WireKind,
    type_name: String,
    repeated: bool,
    map_value: Option<WireKind>,
    map_value_type: String,
}

#[derive(Debug, Default)]
struct Schema {
    messages: HashMap<String, Vec<FieldDef>>,
    enums: HashMap<String, HashMap<i64, String>>,
}

fn schema() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(load_schema)
}

pub(crate) fn decode_k8s_protobuf(
    body: &[u8],
    resource: &str,
) -> Result<Option<Value>, ApiserverError> {
    let payload = body
        .strip_prefix(b"k8s\x00")
        .ok_or_else(|| ApiserverError::BadRequest {
            message: "kubernetes protobuf body is missing the k8s prefix".to_string(),
        })?;
    let (type_meta, raw) = unknown_parts(payload)?;
    if raw.is_empty() {
        return Err(ApiserverError::BadRequest {
            message: "kubernetes protobuf body did not contain an object".to_string(),
        });
    }
    if let Ok(value) = serde_json::from_slice::<Value>(&raw) {
        return Ok(Some(value));
    }
    let Some(message) = message_for(type_meta.as_ref(), resource) else {
        return Ok(None);
    };
    if !schema().messages.contains_key(&message) {
        return Ok(None);
    }
    decode_message(&message, &raw).map(Some)
}

fn message_for(type_meta: Option<&(String, String)>, resource: &str) -> Option<String> {
    if let Some((api_version, kind)) = type_meta {
        if let Some(name) = message_for_gvk(api_version, kind) {
            return Some(name);
        }
    }
    let kind = super::dispatch::kind_name(resource)?;
    message_for_gvk("v1", kind).or_else(|| message_for_gvk(&format!("apps/v1"), kind))
}

fn message_for_gvk(api_version: &str, kind: &str) -> Option<String> {
    let (group, version) = api_version
        .split_once('/')
        .map_or(("", api_version), |(group, version)| (group, version));
    let package = match (group, version) {
        ("", "v1") => "k8s.io.api.core.v1",
        ("apps", "v1") => "k8s.io.api.apps.v1",
        ("batch", "v1") => "k8s.io.api.batch.v1",
        ("policy", "v1") => "k8s.io.api.policy.v1",
        ("autoscaling", "v1") => "k8s.io.api.autoscaling.v1",
        ("autoscaling", "v2") => "k8s.io.api.autoscaling.v2",
        ("networking.k8s.io", "v1") => "k8s.io.api.networking.v1",
        ("storage.k8s.io", "v1") => "k8s.io.api.storage.v1",
        ("certificates.k8s.io", "v1") => "k8s.io.api.certificates.v1",
        ("coordination.k8s.io", "v1") => "k8s.io.api.coordination.v1",
        ("discovery.k8s.io", "v1") => "k8s.io.api.discovery.v1",
        ("rbac.authorization.k8s.io", "v1") => "k8s.io.api.rbac.v1",
        ("admissionregistration.k8s.io", "v1") => "k8s.io.api.admissionregistration.v1",
        ("events.k8s.io", "v1") => "k8s.io.api.events.v1",
        ("node.k8s.io", "v1") => "k8s.io.api.node.v1",
        ("scheduling.k8s.io", "v1") => "k8s.io.api.scheduling.v1",
        ("apiextensions.k8s.io", "v1") => {
            "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1"
        },
        ("apiregistration.k8s.io", "v1") => "k8s.io.kube_aggregator.pkg.apis.apiregistration.v1",
        _ => return None,
    };
    Some(format!("{package}.{kind}"))
}

fn unknown_parts(payload: &[u8]) -> Result<(Option<(String, String)>, Vec<u8>), ApiserverError> {
    let mut input = payload;
    let mut raw = None;
    let mut type_meta = None;
    while !input.is_empty() {
        let (key, rest) = read_varint(input)?;
        input = rest;
        let field = key >> 3;
        let wire = key & 0x07;
        match wire {
            2 => {
                let (chunk, rest) = read_len(input)?;
                input = rest;
                if field == 1 {
                    type_meta = decode_type_meta(chunk);
                } else if field == 2 {
                    raw = Some(chunk.to_vec());
                }
            },
            0 => {
                let (_, rest) = read_varint(input)?;
                input = rest;
            },
            1 => {
                if input.len() < 8 {
                    return Err(truncated());
                }
                input = &input[8..];
            },
            5 => {
                if input.len() < 4 {
                    return Err(truncated());
                }
                input = &input[4..];
            },
            _ => {
                return Err(ApiserverError::BadRequest {
                    message: format!("unsupported kubernetes protobuf wire type {wire}"),
                });
            },
        }
    }
    Ok((
        type_meta,
        raw.ok_or_else(|| ApiserverError::BadRequest {
            message: "kubernetes protobuf body has no raw object".to_string(),
        })?,
    ))
}

fn decode_type_meta(bytes: &[u8]) -> Option<(String, String)> {
    let mut input = bytes;
    let mut api_version = None;
    let mut kind = None;
    while !input.is_empty() {
        let (key, rest) = read_varint(input).ok()?;
        input = rest;
        if key & 0x07 != 2 {
            return None;
        }
        let (chunk, rest) = read_len(input).ok()?;
        input = rest;
        let text = std::str::from_utf8(chunk).ok()?.to_string();
        match key >> 3 {
            1 => api_version = Some(text),
            2 => kind = Some(text),
            _ => {},
        }
    }
    Some((api_version?, kind?))
}

fn decode_message(name: &str, bytes: &[u8]) -> Result<Value, ApiserverError> {
    if let Some(value) = decode_special(name, bytes)? {
        return Ok(value);
    }
    let fields = schema().messages.get(name).cloned().unwrap_or_default();
    let by_number: HashMap<u32, FieldDef> = fields
        .into_iter()
        .map(|field| (field.number, field))
        .collect();
    let mut object = Map::new();
    let mut input = bytes;
    while !input.is_empty() {
        let (key, rest) = read_varint(input)?;
        input = rest;
        let number = u32::try_from(key >> 3).unwrap_or(0);
        let wire = key & 0x07;
        let Some(field) = by_number.get(&number) else {
            input = skip_wire(input, wire)?;
            continue;
        };
        let value = match wire {
            0 => {
                let (raw, rest) = read_varint(input)?;
                input = rest;
                decode_varint(field, raw)
            },
            1 => {
                if input.len() < 8 {
                    return Err(truncated());
                }
                let raw = u64::from_le_bytes(input[..8].try_into().unwrap_or([0; 8]));
                input = &input[8..];
                if field.kind == WireKind::Double {
                    json!(f64::from_bits(raw))
                } else {
                    json!(raw)
                }
            },
            5 => {
                if input.len() < 4 {
                    return Err(truncated());
                }
                let raw = u32::from_le_bytes(input[..4].try_into().unwrap_or([0; 4]));
                input = &input[4..];
                if field.kind == WireKind::Float {
                    json!(f32::from_bits(raw))
                } else {
                    json!(raw)
                }
            },
            2 => {
                let (chunk, rest) = read_len(input)?;
                input = rest;
                decode_length(field, chunk)?
            },
            _ => {
                input = skip_wire(input, wire)?;
                continue;
            },
        };
        store_field(&mut object, field, value);
    }
    Ok(Value::Object(object))
}

fn decode_special(name: &str, bytes: &[u8]) -> Result<Option<Value>, ApiserverError> {
    match name {
        "k8s.io.apimachinery.pkg.api.resource.Quantity"
        | "k8s.io.apimachinery.pkg.api.resource.QuantityValue" => {
            Ok(Some(string_field(bytes, 1).unwrap_or_else(|| json!(""))))
        },
        "k8s.io.apimachinery.pkg.apis.meta.v1.Time"
        | "k8s.io.apimachinery.pkg.apis.meta.v1.MicroTime"
        | "k8s.io.apimachinery.pkg.apis.meta.v1.Timestamp" => {
            let seconds = varint_field(bytes, 1).unwrap_or(0) as i64;
            let nanos = varint_field(bytes, 2).unwrap_or(0) as i32;
            Ok(Some(json!(rfc3339(seconds, nanos))))
        },
        "k8s.io.apimachinery.pkg.util.intstr.IntOrString" => {
            let text = string_field(bytes, 3);
            if let Some(Value::String(value)) = text {
                if !value.is_empty() {
                    return Ok(Some(Value::String(value)));
                }
            }
            let int_val = varint_field(bytes, 2).unwrap_or(0) as i32;
            Ok(Some(json!(int_val)))
        },
        "k8s.io.apimachinery.pkg.runtime.RawExtension" => {
            let raw = bytes_field(bytes, 1).unwrap_or_default();
            if let Ok(value) = serde_json::from_slice::<Value>(&raw) {
                return Ok(Some(value));
            }
            Ok(Some(json!({})))
        },
        _ => Ok(None),
    }
}

fn decode_varint(field: &FieldDef, raw: u64) -> Value {
    match field.kind {
        WireKind::Bool => json!(raw != 0),
        WireKind::Int32 | WireKind::Int64 | WireKind::Uint32 | WireKind::Uint64 => {
            json!(raw as i64)
        },
        WireKind::Sint32 | WireKind::Sint64 => json!(zigzag(raw)),
        WireKind::Enum => {
            let name = schema()
                .enums
                .get(&field.type_name)
                .and_then(|values| values.get(&(raw as i64)))
                .cloned();
            name.map_or_else(|| json!(raw as i64), Value::String)
        },
        _ => json!(raw as i64),
    }
}

fn decode_length(field: &FieldDef, chunk: &[u8]) -> Result<Value, ApiserverError> {
    if field.map_value.is_some() {
        return decode_map_entry(field, chunk);
    }
    match field.kind {
        WireKind::String => Ok(Value::String(String::from_utf8_lossy(chunk).into_owned())),
        WireKind::Bytes => Ok(Value::String(base64(chunk))),
        WireKind::Message => decode_message(&field.type_name, chunk),
        _ => Ok(json!(String::from_utf8_lossy(chunk))),
    }
}

fn decode_map_entry(field: &FieldDef, chunk: &[u8]) -> Result<Value, ApiserverError> {
    let mut input = chunk;
    let mut key = String::new();
    let mut value = Value::Null;
    while !input.is_empty() {
        let (tag, rest) = read_varint(input)?;
        input = rest;
        let number = tag >> 3;
        let wire = tag & 0x07;
        if number == 1 && wire == 2 {
            let (bytes, rest) = read_len(input)?;
            input = rest;
            key = String::from_utf8_lossy(bytes).into_owned();
        } else if number == 2 {
            value = match wire {
                2 => {
                    let (bytes, rest) = read_len(input)?;
                    input = rest;
                    match field.map_value {
                        Some(WireKind::String) => {
                            Value::String(String::from_utf8_lossy(bytes).into_owned())
                        },
                        Some(WireKind::Bytes) => Value::String(base64(bytes)),
                        Some(WireKind::Message) | None => {
                            decode_message(&field.map_value_type, bytes)?
                        },
                        Some(_) => json!(String::from_utf8_lossy(bytes)),
                    }
                },
                0 => {
                    let (raw, rest) = read_varint(input)?;
                    input = rest;
                    json!(raw as i64)
                },
                _ => {
                    input = skip_wire(input, wire)?;
                    Value::Null
                },
            };
        } else {
            input = skip_wire(input, wire)?;
        }
    }
    Ok(json!({ "key": key, "value": value }))
}

fn store_field(object: &mut Map<String, Value>, field: &FieldDef, value: Value) {
    if field.map_value.is_some() {
        let Value::Object(entry) = value else {
            return;
        };
        let key = entry
            .get("key")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mapped = entry.get("value").cloned().unwrap_or(Value::Null);
        let map = object
            .entry(field.name.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(map) = map.as_object_mut() {
            map.insert(key, mapped);
        }
        return;
    }
    if field.repeated {
        let list = object
            .entry(field.name.clone())
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Some(list) = list.as_array_mut() {
            list.push(value);
        }
        return;
    }
    object.insert(field.name.clone(), value);
}

fn string_field(bytes: &[u8], number: u64) -> Option<Value> {
    let mut input = bytes;
    while !input.is_empty() {
        let (key, rest) = read_varint(input).ok()?;
        input = rest;
        if key & 0x07 == 2 && key >> 3 == number {
            let (chunk, _) = read_len(input).ok()?;
            return Some(Value::String(String::from_utf8_lossy(chunk).into_owned()));
        }
        input = skip_wire(input, key & 0x07).ok()?;
    }
    None
}

fn bytes_field(bytes: &[u8], number: u64) -> Option<Vec<u8>> {
    let mut input = bytes;
    while !input.is_empty() {
        let (key, rest) = read_varint(input).ok()?;
        input = rest;
        if key & 0x07 == 2 && key >> 3 == number {
            let (chunk, _) = read_len(input).ok()?;
            return Some(chunk.to_vec());
        }
        input = skip_wire(input, key & 0x07).ok()?;
    }
    None
}

fn varint_field(bytes: &[u8], number: u64) -> Option<u64> {
    let mut input = bytes;
    while !input.is_empty() {
        let (key, rest) = read_varint(input).ok()?;
        input = rest;
        if key & 0x07 == 0 && key >> 3 == number {
            let (value, _) = read_varint(input).ok()?;
            return Some(value);
        }
        input = skip_wire(input, key & 0x07).ok()?;
    }
    None
}

fn zigzag(raw: u64) -> i64 {
    ((raw >> 1) as i64) ^ -((raw & 1) as i64)
}

fn read_varint(input: &[u8]) -> Result<(u64, &[u8]), ApiserverError> {
    let mut value = 0u64;
    let mut shift = 0;
    for (index, byte) in input.iter().enumerate() {
        if shift >= 64 {
            break;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, &input[index + 1..]));
        }
        shift += 7;
    }
    Err(ApiserverError::BadRequest {
        message: "kubernetes protobuf varint is truncated".to_string(),
    })
}

fn read_len(input: &[u8]) -> Result<(&[u8], &[u8]), ApiserverError> {
    let (len, rest) = read_varint(input)?;
    let len = usize::try_from(len).map_err(|_| truncated())?;
    if rest.len() < len {
        return Err(truncated());
    }
    Ok(rest.split_at(len))
}

fn skip_wire(input: &[u8], wire: u64) -> Result<&[u8], ApiserverError> {
    match wire {
        0 => {
            let (_, rest) = read_varint(input)?;
            Ok(rest)
        },
        1 => {
            if input.len() < 8 {
                return Err(truncated());
            }
            Ok(&input[8..])
        },
        2 => {
            let (_, rest) = read_len(input)?;
            Ok(rest)
        },
        5 => {
            if input.len() < 4 {
                return Err(truncated());
            }
            Ok(&input[4..])
        },
        _ => Err(ApiserverError::BadRequest {
            message: format!("unsupported kubernetes object wire type {wire}"),
        }),
    }
}

fn truncated() -> ApiserverError {
    ApiserverError::BadRequest {
        message: "kubernetes protobuf body is truncated".to_string(),
    }
}

fn rfc3339(seconds: i64, nanos: i32) -> String {
    if seconds < 0 {
        return format!("{seconds}");
    }
    let days = seconds.div_euclid(86_400);
    let tod = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = tod / 3600;
    let minute = (tod % 3600) / 60;
    let second = tod % 60;
    if nanos > 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanos:09}Z")
    } else {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (year as i32, month as u32, day as u32)
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let n = (u32::from(bytes[index]) << 16)
            | (u32::from(bytes[index + 1]) << 8)
            | u32::from(bytes[index + 2]);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        index += 3;
    }
    if bytes.len() - index == 1 {
        let n = u32::from(bytes[index]) << 16;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push('=');
        out.push('=');
    } else if bytes.len() - index == 2 {
        let n = (u32::from(bytes[index]) << 16) | (u32::from(bytes[index + 1]) << 8);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}

#[derive(Clone, Debug)]
struct RawField {
    number: u32,
    name: String,
    type_name: String,
    repeated: bool,
    map_value: String,
}

fn load_schema() -> Schema {
    let mut packages = Vec::new();
    let mut raw_messages: HashMap<String, Vec<RawField>> = HashMap::new();
    let mut enum_names = Vec::new();
    let mut enums: HashMap<String, HashMap<i64, String>> = HashMap::new();
    for source in SOURCES {
        parse_proto(
            source,
            &mut packages,
            &mut raw_messages,
            &mut enum_names,
            &mut enums,
        );
    }
    let mut schema = Schema {
        messages: HashMap::new(),
        enums,
    };
    let known: std::collections::HashSet<String> = raw_messages.keys().cloned().collect();
    for (message, fields) in raw_messages {
        let package = package_of(&message);
        let resolved = fields
            .into_iter()
            .map(|field| resolve_field(&message, package, field, &known, &schema.enums))
            .collect();
        schema.messages.insert(message, resolved);
    }
    let _ = packages;
    let _ = enum_names;
    schema
}

fn package_of(message: &str) -> &str {
    message.rsplit_once('.').map_or("", |(package, _)| package)
}

fn resolve_field(
    message: &str,
    package: &str,
    field: RawField,
    messages: &std::collections::HashSet<String>,
    enums: &HashMap<String, HashMap<i64, String>>,
) -> FieldDef {
    let map = !field.map_value.is_empty();
    let type_token = if map {
        field.map_value.as_str()
    } else {
        field.type_name.as_str()
    };
    let resolved = resolve_type(message, package, type_token, messages, enums);
    let kind = scalar_kind(type_token, &resolved, messages, enums);
    let map_value = if map {
        Some(scalar_kind(&field.map_value, &resolved, messages, enums))
    } else {
        None
    };
    FieldDef {
        number: field.number,
        name: field.name,
        kind: if map { WireKind::Message } else { kind },
        type_name: if map { String::new() } else { resolved.clone() },
        repeated: field.repeated || map,
        map_value,
        map_value_type: if map { resolved } else { String::new() },
    }
}

fn resolve_type(
    message: &str,
    package: &str,
    type_name: &str,
    messages: &std::collections::HashSet<String>,
    enums: &HashMap<String, HashMap<i64, String>>,
) -> String {
    let type_name = type_name.trim_start_matches('.');
    if type_name.contains('.') {
        return type_name.to_string();
    }
    for candidate in [
        format!("{message}.{type_name}"),
        format!("{package}.{type_name}"),
    ] {
        if messages.contains(&candidate) || enums.contains_key(&candidate) {
            return candidate;
        }
    }
    type_name.to_string()
}

fn scalar_kind(
    type_token: &str,
    resolved: &str,
    messages: &std::collections::HashSet<String>,
    enums: &HashMap<String, HashMap<i64, String>>,
) -> WireKind {
    match type_token.trim_start_matches('.') {
        "string" => WireKind::String,
        "bytes" => WireKind::Bytes,
        "bool" => WireKind::Bool,
        "int32" | "fixed32" | "sfixed32" => WireKind::Int32,
        "int64" | "fixed64" | "sfixed64" => WireKind::Int64,
        "uint32" => WireKind::Uint32,
        "uint64" => WireKind::Uint64,
        "sint32" => WireKind::Sint32,
        "sint64" => WireKind::Sint64,
        "float" => WireKind::Float,
        "double" => WireKind::Double,
        _ if enums.contains_key(resolved) => WireKind::Enum,
        _ if messages.contains(resolved) => WireKind::Message,
        _ => WireKind::Message,
    }
}

fn parse_proto(
    source: &str,
    _packages: &mut Vec<String>,
    messages: &mut HashMap<String, Vec<RawField>>,
    _enum_names: &mut Vec<String>,
    enums: &mut HashMap<String, HashMap<i64, String>>,
) {
    let text = strip_comments(source);
    let mut package = String::new();
    let mut stack: Vec<Scope> = Vec::new();
    let mut buf = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        buf.push(' ');
        buf.push_str(line);
        if !buf.contains('{') && !buf.contains('}') && !buf.contains(';') {
            continue;
        }
        let stmt = std::mem::take(&mut buf);
        let stmt = stmt.trim();
        if let Some(rest) = stmt.strip_prefix("package ") {
            package = rest.trim().trim_end_matches(';').trim().to_string();
            continue;
        }
        if stmt.starts_with("import ") || stmt.starts_with("option ") || stmt.starts_with("syntax ")
        {
            continue;
        }
        if stmt.starts_with('}')
            || stmt.ends_with('}')
                && !stmt.contains("message ")
                && !stmt.contains("enum ")
                && !stmt.contains("oneof ")
        {
            stack.pop();
            continue;
        }
        if let Some(name) = decl_name(stmt, "message ") {
            let full = qualify(&package, &stack, &name);
            stack.push(Scope::Message(full.clone()));
            messages.entry(full).or_default();
            continue;
        }
        if let Some(name) = decl_name(stmt, "enum ") {
            let full = qualify(&package, &stack, &name);
            stack.push(Scope::Enum(full.clone()));
            enums.entry(full).or_default();
            continue;
        }
        if decl_name(stmt, "oneof ").is_some() {
            stack.push(Scope::Oneof);
            continue;
        }
        if let Some(message) = stack.iter().rev().find_map(|scope| match scope {
            Scope::Message(message) => Some(message.clone()),
            Scope::Enum(_) => None,
            Scope::Oneof => None,
        }) {
            if matches!(stack.last(), Some(Scope::Enum(_))) {
                if let Some(Scope::Enum(name)) = stack.last() {
                    if let Some((label, number)) = parse_enum_value(stmt) {
                        enums.entry(name.clone()).or_default().insert(number, label);
                    }
                }
            } else if let Some(field) = parse_field(stmt) {
                messages.entry(message).or_default().push(field);
            }
        } else if let Some(Scope::Enum(name)) = stack.last() {
            if let Some((label, number)) = parse_enum_value(stmt) {
                enums.entry(name.clone()).or_default().insert(number, label);
            }
        }
    }
}

enum Scope {
    Message(String),
    Enum(String),
    Oneof,
}

fn qualify(package: &str, stack: &[Scope], name: &str) -> String {
    let mut parts = Vec::new();
    if !package.is_empty() {
        parts.push(package.to_string());
    }
    for scope in stack {
        if let Scope::Message(message) = scope {
            let short = message.rsplit('.').next().unwrap_or(message);
            parts.push(short.to_string());
        }
    }
    parts.push(name.to_string());
    parts.join(".")
}

fn decl_name(stmt: &str, prefix: &str) -> Option<String> {
    let rest = stmt.trim().strip_prefix(prefix)?;
    let name = rest
        .split(|ch: char| ch == '{' || ch.is_whitespace())
        .next()?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn parse_field(stmt: &str) -> Option<RawField> {
    let stmt = stmt.trim().trim_end_matches(';').trim();
    let stmt = stmt.split('[').next()?.trim();
    if stmt.is_empty() || stmt.starts_with("reserved") || stmt.starts_with("extensions") {
        return None;
    }
    let (head, number) = stmt.rsplit_once('=')?;
    let number = number.trim().parse().ok()?;
    let mut head = head.trim();
    let mut repeated = false;
    for keyword in ["optional ", "required ", "repeated "] {
        if let Some(rest) = head.strip_prefix(keyword) {
            repeated = keyword.starts_with("repeated");
            head = rest.trim();
            break;
        }
    }
    let (type_token, name) = head.rsplit_once(char::is_whitespace)?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let mut type_name = type_token.trim().to_string();
    let mut map_value = String::new();
    if let Some(inner) = type_name
        .strip_prefix("map<")
        .and_then(|value| value.strip_suffix('>'))
    {
        let (_, value) = inner.split_once(',')?;
        map_value = value.trim().to_string();
        type_name.clear();
        repeated = true;
    }
    Some(RawField {
        number,
        name: name.to_string(),
        type_name,
        repeated,
        map_value,
    })
}

fn parse_enum_value(stmt: &str) -> Option<(String, i64)> {
    let stmt = stmt.trim().trim_end_matches(';').trim();
    let stmt = stmt.split('[').next()?.trim();
    let (name, number) = stmt.split_once('=')?;
    let name = name.trim();
    if name.is_empty() || name.contains(' ') {
        return None;
    }
    Some((name.to_string(), number.trim().parse().ok()?))
}

fn strip_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'/' {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if bytes[index] == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'*' {
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
            continue;
        }
        out.push(bytes[index] as char);
        index += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::decode_k8s_protobuf;

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    fn length_delimited(field: u64, bytes: &[u8]) -> Vec<u8> {
        let mut out = varint((field << 3) | 2);
        out.extend(varint(bytes.len() as u64));
        out.extend(bytes);
        out
    }

    fn string_field(field: u64, text: &str) -> Vec<u8> {
        length_delimited(field, text.as_bytes())
    }

    fn wrap(kind: &str, raw: &[u8]) -> Vec<u8> {
        let mut type_meta = string_field(1, "v1");
        type_meta.extend(string_field(2, kind));
        let mut unknown = length_delimited(1, &type_meta);
        unknown.extend(length_delimited(2, raw));
        let mut body = b"k8s\x00".to_vec();
        body.extend(unknown);
        body
    }

    #[test]
    fn protobuf_service_keeps_the_headless_spec() {
        let metadata = string_field(1, "test");
        let mut spec = string_field(3, "None");
        let mut port = string_field(1, "http");
        port.extend(varint((3 << 3) | 0));
        port.extend(varint(80));
        spec.extend(length_delimited(1, &port));
        let mut service = length_delimited(1, &metadata);
        service.extend(length_delimited(2, &spec));
        let decoded = decode_k8s_protobuf(&wrap("Service", &service), "services")
            .expect("decode")
            .expect("service schema");
        assert_eq!(decoded["metadata"]["name"], "test");
        assert_eq!(decoded["spec"]["clusterIP"], "None");
        assert_eq!(decoded["spec"]["ports"][0]["port"], 80);
        assert_eq!(decoded["spec"]["ports"][0]["name"], "http");
    }

    #[test]
    fn protobuf_cronjob_keeps_suspend() {
        let metadata = string_field(1, "suspended");
        let mut spec = string_field(1, "* * * * *");
        spec.extend(varint((4 << 3) | 0));
        spec.extend(varint(1));
        let mut cronjob = length_delimited(1, &metadata);
        cronjob.extend(length_delimited(2, &spec));
        let mut type_meta = string_field(1, "batch/v1");
        type_meta.extend(string_field(2, "CronJob"));
        let mut unknown = length_delimited(1, &type_meta);
        unknown.extend(length_delimited(2, &cronjob));
        let mut body = b"k8s\x00".to_vec();
        body.extend(unknown);
        let decoded = decode_k8s_protobuf(&body, "cronjobs")
            .expect("decode")
            .expect("cronjob schema");
        assert_eq!(decoded["spec"]["suspend"], true);
        assert_eq!(decoded["spec"]["schedule"], "* * * * *");
    }
}
