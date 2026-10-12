use crate::{Config, FIELDS, FieldType, INPUT_BINDINGS};
use serde::Serialize;
use serde_json::{Value, json};

/// One distribution setting, matching the baseline configuration schema descriptor.
/// Defaults describe the unresolved model, not a discovered or running node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SettingDescriptor {
    pub path: &'static str,
    #[serde(rename = "type")]
    pub json_type: &'static str,
    pub default: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flag: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envar: Option<&'static str>,
    pub mutability: &'static str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub secret: bool,
}

/// Describe every registered setting in lexical path order, without host IO.
///
/// Types come from the field inventory even when a default is null. Secret
/// defaults are always null. Schema metadata (`apiVersion` and `kind`) is not a
/// setting, and derived values such as the socket path remain unresolved.
#[must_use]
pub fn describe_settings() -> Vec<SettingDescriptor> {
    // Config contains only infallibly JSON-serializable scalar/collection types.
    // The same model serialization supplies default values for every field.
    let defaults = json!(Config::default());
    let mut descriptors: Vec<_> = FIELDS
        .iter()
        .map(|field| {
            let binding = INPUT_BINDINGS.iter().find(|input| input.path == field.path);
            SettingDescriptor {
                path: field.path,
                json_type: match field.kind {
                    FieldType::Boolean | FieldType::OptionalBool => "boolean",
                    FieldType::Integer => "integer",
                    FieldType::String => "string",
                    FieldType::StringList => "array",
                    FieldType::StringMap => "object",
                },
                default: if field.secret {
                    Value::Null
                } else {
                    field
                        .path
                        .split('.')
                        .fold(&defaults, |value, key| &value[key])
                        .clone()
                },
                flag: binding.and_then(|input| input.flag),
                envar: binding.map(|input| input.environment),
                mutability: if field.immutable {
                    "immutable"
                } else {
                    "restart"
                },
                secret: field.secret,
            }
        })
        .collect();
    descriptors.sort_unstable_by_key(|descriptor| descriptor.path);
    descriptors
}
