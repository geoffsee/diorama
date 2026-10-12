use crate::upstream::{Result, fail, hex};
use serde_json::{Value, json};
fn field(kind: &str, n: u64) -> (String, &'static str) {
    let fields: &[(&str, &str)] = match kind {
        "set" => &[("files", "file")],
        "file" => &[
            ("name", "text"),
            ("package", "text"),
            ("dependencies", "text"),
            ("messages", "message"),
            ("enums", "enum"),
            ("services", "service"),
            ("extensions", "field"),
            ("options", "raw"),
            ("", ""),
            ("", ""),
            ("", ""),
            ("syntax", "text"),
        ],
        "message" => &[
            ("name", "text"),
            ("fields", "field"),
            ("nested", "message"),
            ("enums", "enum"),
            ("extension_ranges", "raw"),
            ("extensions", "field"),
            ("options", "raw"),
            ("oneofs", "oneof"),
            ("reserved_ranges", "raw"),
            ("reserved_names", "text"),
        ],
        "field" => &[
            ("name", "text"),
            ("extendee", "text"),
            ("number", "int"),
            ("label", "int"),
            ("type", "int"),
            ("type_name", "text"),
            ("default", "text"),
            ("options", "raw"),
            ("oneof_index", "int"),
            ("json_name", "text"),
            ("", ""),
            ("", ""),
            ("", ""),
            ("", ""),
            ("", ""),
            ("", ""),
            ("proto3_optional", "int"),
        ],
        "enum" => &[
            ("name", "text"),
            ("values", "enum_value"),
            ("options", "raw"),
            ("reserved_ranges", "raw"),
            ("reserved_names", "text"),
        ],
        "enum_value" => &[("name", "text"), ("number", "int"), ("options", "raw")],
        "oneof" => &[("name", "text"), ("options", "raw")],
        "service" => &[("name", "text"), ("methods", "method"), ("options", "raw")],
        "method" => &[
            ("name", "text"),
            ("input", "text"),
            ("output", "text"),
            ("options", "raw"),
            ("client_streaming", "int"),
            ("server_streaming", "int"),
        ],
        _ => &[],
    };
    if let Some((name, ty)) = n
        .checked_sub(1)
        .and_then(|i| usize::try_from(i).ok())
        .and_then(|i| fields.get(i))
        .filter(|(name, _)| !name.is_empty())
    {
        ((*name).to_owned(), ty)
    } else {
        (format!("unknown_{n}"), "unknown")
    }
}
pub(crate) fn varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result = 0;
    for shift in (0..70).step_by(7) {
        let byte = *data.get(*pos).ok_or("truncated varint")?;
        *pos += 1;
        if shift == 63 && byte > 1 {
            return fail("varint exceeds uint64");
        }
        result |= u64::from(byte & 127) << shift;
        if byte < 128 {
            return Ok(result);
        }
    }
    fail("invalid varint")
}
pub(crate) fn descriptor(data: &[u8], kind: &str, depth: usize) -> Result<Value> {
    if data.len() > 16 * 1024 * 1024 || depth > 64 {
        return fail("descriptor size/depth limit");
    }
    let mut out = serde_json::Map::new();
    let mut pos = 0;
    while pos < data.len() {
        let tag = varint(data, &mut pos)?;
        let (number, wire) = (tag >> 3, tag & 7);
        if number == 0 || number >= 1 << 29 {
            return fail("invalid field number");
        }
        let (name, ty) = field(kind, number);
        let (value, bytes) = match wire {
            0 => (Value::from(varint(data, &mut pos)?), None),
            1 | 2 | 5 => {
                let len = if wire == 2 {
                    usize::try_from(varint(data, &mut pos)?)?
                } else if wire == 1 {
                    8
                } else {
                    4
                };
                let end = pos.checked_add(len).ok_or("field overflow")?;
                let slice = data.get(pos..end).ok_or("truncated field")?;
                pos = end;
                (Value::String(hex(slice)), Some(slice))
            },
            _ => return fail("unsupported descriptor wire type"),
        };
        let value = match ty {
            "int" => {
                if wire != 0 {
                    return fail("wrong integer wire type");
                }
                value
            },
            "unknown" => json!({"wire":wire,"value":value}),
            _ => {
                if wire != 2 {
                    return fail("wrong message wire type");
                }
                let bytes = bytes.ok_or("missing field bytes")?;
                match ty {
                    "text" => std::str::from_utf8(bytes)?.into(),
                    "raw" => value,
                    _ => descriptor(bytes, ty, depth + 1)?,
                }
            },
        };
        out.entry(name)
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or("invalid collection")?
            .push(value);
    }
    Ok(Value::Object(out))
}
