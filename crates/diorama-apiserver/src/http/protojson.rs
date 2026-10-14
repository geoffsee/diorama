//! Decode Kubernetes protobuf request bodies into the JSON objects the rest of
//! the apiserver already stores.
//!
//! `client-go` sends built-in types as `application/vnd.kubernetes.protobuf`.
//! The payload is `k8s\0` plus a `runtime.Unknown` whose `raw` field is the
//! generated protobuf for that kind. Field definitions come from the static
//! Kubernetes v1.37.1 schema table in `generated/k8s_proto_schema.rs`,
//! regenerated offline with `diorama-proto-schema`.

// Field numbers and zig-zag values are fixed-width protobuf integers.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::excessive_nesting,
    clippy::type_complexity,
    clippy::unnecessary_wraps,
    clippy::verbose_bit_mask
)]

use serde_json::{Map, Value, json};

use crate::error::ApiserverError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
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

#[derive(Clone, Copy, Debug)]
struct FieldDef {
    number: u32,
    name: &'static str,
    kind: WireKind,
    type_name: &'static str,
    repeated: bool,
    map_value: Option<WireKind>,
    map_value_type: &'static str,
}

impl FieldDef {
    const fn scalar(number: u32, name: &'static str, kind: WireKind) -> Self {
        Self {
            number,
            name,
            kind,
            type_name: "",
            repeated: false,
            map_value: None,
            map_value_type: "",
        }
    }

    const fn repeated_scalar(number: u32, name: &'static str, kind: WireKind) -> Self {
        Self {
            number,
            name,
            kind,
            type_name: "",
            repeated: true,
            map_value: None,
            map_value_type: "",
        }
    }

    const fn typed(
        number: u32,
        name: &'static str,
        kind: WireKind,
        type_name: &'static str,
    ) -> Self {
        Self {
            number,
            name,
            kind,
            type_name,
            repeated: false,
            map_value: None,
            map_value_type: "",
        }
    }

    const fn repeated_typed(
        number: u32,
        name: &'static str,
        kind: WireKind,
        type_name: &'static str,
    ) -> Self {
        Self {
            number,
            name,
            kind,
            type_name,
            repeated: true,
            map_value: None,
            map_value_type: "",
        }
    }

    const fn map(
        number: u32,
        name: &'static str,
        value_kind: WireKind,
        value_type: &'static str,
    ) -> Self {
        Self {
            number,
            name,
            kind: WireKind::Message,
            type_name: "",
            repeated: true,
            map_value: Some(value_kind),
            map_value_type: value_type,
        }
    }
}

include!("generated/k8s_proto_schema.rs");

fn lookup_message(name: &str) -> Option<&'static [FieldDef]> {
    MESSAGES
        .binary_search_by_key(&name, |(message, _)| *message)
        .ok()
        .map(|index| MESSAGES[index].1)
}

fn lookup_field(fields: &'static [FieldDef], number: u32) -> Option<&'static FieldDef> {
    fields
        .binary_search_by_key(&number, |field| field.number)
        .ok()
        .map(|index| &fields[index])
}

fn lookup_enum(type_name: &str, value: i64) -> Option<&'static str> {
    let variants = ENUMS
        .binary_search_by_key(&type_name, |(name, _)| *name)
        .ok()
        .map(|index| ENUMS[index].1)?;
    variants
        .binary_search_by_key(&value, |(number, _)| *number)
        .ok()
        .map(|index| variants[index].1)
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
    if lookup_message(&message).is_none() {
        return Ok(None);
    }
    decode_message(&message, &raw).map(Some)
}

fn message_for(type_meta: Option<&(String, String)>, resource: &str) -> Option<String> {
    if let Some((api_version, kind)) = type_meta
        && let Some(name) = message_for_gvk(api_version, kind)
    {
        return Some(name);
    }
    let kind = super::dispatch::kind_name(resource)?;
    message_for_gvk("v1", kind).or_else(|| message_for_gvk("apps/v1", kind))
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
    let fields = lookup_message(name).unwrap_or(&[]);
    let mut object = Map::new();
    let mut input = bytes;
    while !input.is_empty() {
        let (key, rest) = read_varint(input)?;
        input = rest;
        let number = u32::try_from(key >> 3).unwrap_or(0);
        let wire = key & 0x07;
        let Some(field) = lookup_field(fields, number) else {
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
            if let Some(Value::String(value)) = text
                && !value.is_empty()
            {
                return Ok(Some(Value::String(value)));
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
        WireKind::Enum => lookup_enum(field.type_name, raw as i64).map_or_else(
            || json!(raw as i64),
            |label| Value::String(label.to_string()),
        ),
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
        WireKind::Message => decode_message(field.type_name, chunk),
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
                            decode_message(field.map_value_type, bytes)?
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
            .entry(field.name.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(map) = map.as_object_mut() {
            map.insert(key, mapped);
        }
        return;
    }
    if field.repeated {
        let list = object
            .entry(field.name.to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Some(list) = list.as_array_mut() {
            list.push(value);
        }
        return;
    }
    object.insert(field.name.to_string(), value);
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
        port.extend(varint(3 << 3));
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
        spec.extend(varint(4 << 3));
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

    #[test]
    fn protobuf_cluster_trust_bundle_decodes_v1_37_fields() {
        let metadata = string_field(1, "example-bundle");
        let mut spec = string_field(1, "example.com/signer");
        spec.extend(string_field(2, "-----BEGIN CERTIFICATE-----\n"));
        let mut bundle = length_delimited(1, &metadata);
        bundle.extend(length_delimited(2, &spec));
        let mut type_meta = string_field(1, "certificates.k8s.io/v1");
        type_meta.extend(string_field(2, "ClusterTrustBundle"));
        let mut unknown = length_delimited(1, &type_meta);
        unknown.extend(length_delimited(2, &bundle));
        let mut body = b"k8s\x00".to_vec();
        body.extend(unknown);
        let decoded = decode_k8s_protobuf(&body, "clustertrustbundles")
            .expect("decode")
            .expect("clustertrustbundle schema");
        assert_eq!(decoded["metadata"]["name"], "example-bundle");
        assert_eq!(decoded["spec"]["signerName"], "example.com/signer");
        assert_eq!(
            decoded["spec"]["trustBundle"],
            "-----BEGIN CERTIFICATE-----\n"
        );
    }
}
