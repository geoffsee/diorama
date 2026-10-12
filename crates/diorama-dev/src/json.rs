//! JSON input with duplicate-key rejection and type-preserving differences.
use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value, json};

use crate::Result;

struct Strict(Value);

struct StrictVisitor;
impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("finite JSON with unique object keys")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::Bool(value)))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::Number(value.into())))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::Number(value.into())))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Strict, E> {
        Number::from_f64(value)
            .map(|n| Strict(Value::Number(n)))
            .ok_or_else(|| E::custom("nonfinite JSON number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::String(value.to_owned())))
    }
    fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::String(value)))
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut sequence: A,
    ) -> std::result::Result<Strict, A::Error> {
        let mut values = Vec::new();
        while let Some(Strict(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(Strict(Value::Array(values)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut entries: A) -> std::result::Result<Strict, A::Error> {
        let mut values = Map::new();
        while let Some((key, Strict(value))) = entries.next_entry::<String, Strict>()? {
            if values.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate JSON key"));
            }
        }
        Ok(Strict(Value::Object(values)))
    }
}
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: de::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

/// Parse a byte-bounded caller input with `serde_json`'s recursion limit enabled.
pub fn parse(raw: &[u8]) -> Result<Value> {
    let Strict(value) = serde_json::from_slice(raw)?;
    Ok(value)
}

fn kind(value: &Value) -> u8 {
    match value {
        Value::Null => 0,
        Value::Bool(_) => 1,
        Value::String(_) => 2,
        Value::Number(n) if n.is_f64() => 3,
        Value::Number(_) => 4,
        Value::Array(_) => 5,
        Value::Object(_) => 6,
    }
}

fn walk(before: Option<&Value>, after: Option<&Value>, path: &str, output: &mut Vec<Value>) {
    match (before, after) {
        (None, Some(after)) => output.push(json!({"path":path,"kind":"added","after":after})),
        (Some(before), None) => output.push(json!({"path":path,"kind":"removed","before":before})),
        (Some(before), Some(after)) if kind(before) != kind(after) => {
            output.push(json!({"path":path,"kind":"type_changed","before":before,"after":after}));
        },
        (Some(Value::Object(before)), Some(Value::Object(after))) => {
            let keys: BTreeSet<_> = before.keys().chain(after.keys()).collect();
            for key in keys {
                walk(
                    before.get(key),
                    after.get(key),
                    &format!("{path}/{}", key.replace('~', "~0").replace('/', "~1")),
                    output,
                );
            }
        },
        (Some(Value::Array(before)), Some(Value::Array(after))) => {
            for index in 0..before.len().max(after.len()) {
                walk(
                    before.get(index),
                    after.get(index),
                    &format!("{path}/{index}"),
                    output,
                );
            }
        },
        (Some(before), Some(after)) if before != after => {
            output.push(json!({"path":path,"kind":"changed","before":before,"after":after}));
        },
        _ => {},
    }
}

pub fn changes(before: &Value, after: &Value) -> Vec<Value> {
    let mut output = Vec::new();
    walk(Some(before), Some(after), "", &mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_duplicate_and_nonfinite_values() {
        for raw in [
            br#"{"x":0,"x":1}"#.as_slice(),
            b"NaN",
            b"Infinity",
            b"1e999",
        ] {
            assert!(parse(raw).is_err());
        }
    }
    #[test]
    fn preserves_types_missing_values_order_and_json_pointers() {
        let diff = changes(&json!({"a/b~":[true,1,2]}), &json!({"a/b~":[1,1.0]}));
        assert_eq!(diff[0]["path"], "/a~1b~0/0");
        assert_eq!(diff[0]["kind"], "type_changed");
        assert_eq!(diff[1]["kind"], "type_changed");
        assert_eq!(diff[2]["kind"], "removed");
    }
}
