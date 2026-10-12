use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;

use saphyr_parser::{BufferedInput, Event, Parser, ScalarStyle, Tag};
use serde_json::{Map, Number, Value};

use crate::{API_VERSION, Config, KIND};

/// Explicit caller-selected parsing budgets, separate from compatibility semantics.
#[derive(Clone, Copy, Debug)]
pub struct DecodeLimits {
    pub input_bytes: usize,
    pub depth: usize,
    pub expanded_nodes: usize,
    /// Cumulative scalar and tag bytes, including anchor storage and alias clones.
    pub expanded_bytes: usize,
}
impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            input_bytes: 1024 * 1024,
            depth: 128,
            expanded_nodes: 100_000,
            expanded_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Syntax,
    Type,
    Version,
    Limit,
    Io,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    pub kind: ErrorKind,
    pub path: String,
    pub message: String,
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}
impl std::error::Error for ConfigError {}
fn error(kind: ErrorKind, path: &str, message: impl Into<String>) -> ConfigError {
    ConfigError {
        kind,
        path: path.into(),
        message: message.into(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Warning {
    MissingVersion,
    UnexpectedKind(String),
    IgnoredSettings {
        unknown: Vec<String>,
        duplicate: Vec<String>,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    Omitted,
    Null,
    Value,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedConfig {
    pub config: Config,
    pub warnings: Vec<Warning>,
    /// Includes containers and explicitly supplied leaf paths, even null values.
    pub presence: BTreeMap<String, Presence>,
}
impl DecodedConfig {
    pub fn presence(&self, path: &str) -> Presence {
        self.presence
            .get(path)
            .copied()
            .unwrap_or(Presence::Omitted)
    }
}

#[derive(Clone, Debug)]
enum Node {
    Scalar(String, ScalarStyle, Option<Tag>),
    Sequence(Vec<Self>),
    Mapping(Vec<(Self, Self)>),
}
impl Node {
    fn height(&self) -> usize {
        1 + match self {
            Self::Scalar(..) => 0,
            Self::Sequence(v) => v.iter().map(Self::height).max().unwrap_or(0),
            Self::Mapping(v) => v
                .iter()
                .map(|(k, v)| k.height().max(v.height()))
                .max()
                .unwrap_or(0),
        }
    }
    fn bytes(&self) -> usize {
        match self {
            Self::Scalar(value, _, tag) => value.len().saturating_add(
                tag.as_ref()
                    .map_or(0, |tag| tag.handle.len().saturating_add(tag.suffix.len())),
            ),
            Self::Sequence(values) => values
                .iter()
                .fold(0usize, |sum, node| sum.saturating_add(node.bytes())),
            Self::Mapping(values) => values.iter().fold(0usize, |sum, (key, value)| {
                sum.saturating_add(key.bytes())
                    .saturating_add(value.bytes())
            }),
        }
    }
    fn count(&self) -> usize {
        1 + match self {
            Self::Scalar(..) => 0,
            Self::Sequence(v) => v.iter().map(Self::count).sum(),
            Self::Mapping(v) => v.iter().map(|(k, v)| k.count() + v.count()).sum(),
        }
    }
}
struct Tree<'a> {
    parser: Parser<'a, BufferedInput<std::str::Chars<'a>>>,
    anchors: BTreeMap<usize, Node>,
    limits: DecodeLimits,
    nodes: usize,
    bytes: usize,
}
impl<'a> Tree<'a> {
    fn charge(&mut self, nodes: usize, bytes: usize) -> Result<(), ConfigError> {
        self.nodes = self
            .nodes
            .checked_add(nodes)
            .ok_or_else(|| error(ErrorKind::Limit, "", "YAML node budget overflow"))?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| error(ErrorKind::Limit, "", "YAML byte budget overflow"))?;
        if self.nodes > self.limits.expanded_nodes || self.bytes > self.limits.expanded_bytes {
            return Err(error(
                ErrorKind::Limit,
                "",
                "YAML expansion budget exceeded",
            ));
        }
        Ok(())
    }

    fn next(&mut self) -> Result<Event<'a>, ConfigError> {
        self.parser
            .next_event()
            .map_or(Ok(Event::StreamEnd), |result| {
                result
                    .map(|(event, _)| event)
                    .map_err(|e| error(ErrorKind::Syntax, "", e.to_string()))
            })
    }
    fn node(&mut self, event: Event<'a>, depth: usize) -> Result<Node, ConfigError> {
        self.charge(1, 0)?;
        if depth > self.limits.depth || self.nodes > self.limits.expanded_nodes {
            return Err(error(
                ErrorKind::Limit,
                "",
                "YAML expansion/depth budget exceeded",
            ));
        }
        let (anchor, node) = match event {
            Event::Scalar(value, style, anchor, tag) => {
                let bytes = value.len().saturating_add(
                    tag.as_ref()
                        .map_or(0, |tag| tag.handle.len().saturating_add(tag.suffix.len())),
                );
                self.charge(0, bytes)?;
                (
                    anchor,
                    Node::Scalar(
                        value.into_owned(),
                        style,
                        tag.map(std::borrow::Cow::into_owned),
                    ),
                )
            },
            Event::Alias(id) => {
                let node = self.anchors.get(&id).ok_or_else(|| {
                    error(ErrorKind::Syntax, "", "recursive or unavailable YAML alias")
                })?;
                if depth + node.height() > self.limits.depth {
                    return Err(error(
                        ErrorKind::Limit,
                        "",
                        "YAML alias depth budget exceeded",
                    ));
                }
                let (nodes, bytes) = (node.count(), node.bytes());
                self.charge(nodes, bytes)?;
                return Ok(self.anchors[&id].clone());
            },
            Event::SequenceStart(anchor, _) => {
                let mut values = Vec::new();
                loop {
                    let next = self.next()?;
                    if next == Event::SequenceEnd {
                        break;
                    }
                    values.push(self.node(next, depth + 1)?);
                }
                (anchor, Node::Sequence(values))
            },
            Event::MappingStart(anchor, _) => {
                let mut values = Vec::new();
                loop {
                    let next = self.next()?;
                    if next == Event::MappingEnd {
                        break;
                    }
                    let key = self.node(next, depth + 1)?;
                    let next = self.next()?;
                    values.push((key, self.node(next, depth + 1)?));
                }
                (anchor, Node::Mapping(values))
            },
            _ => return Err(error(ErrorKind::Syntax, "", "expected YAML value")),
        };
        if anchor != 0 {
            self.charge(node.count(), node.bytes())?;
            self.anchors.insert(anchor, node.clone());
        }
        Ok(node)
    }
}

fn integer_scalar(clean: &str) -> Option<Value> {
    let (negative, digits) = if let Some(v) = clean.strip_prefix('-') {
        (true, v)
    } else {
        (false, clean.strip_prefix('+').unwrap_or(clean))
    };
    let radix = if let Some(body) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        Some((16, body))
    } else if let Some(body) = digits
        .strip_prefix("0b")
        .or_else(|| digits.strip_prefix("0B"))
    {
        Some((2, body))
    } else if let Some(body) = digits
        .strip_prefix("0o")
        .or_else(|| digits.strip_prefix("0O"))
    {
        Some((8, body))
    } else if digits.len() > 1 && digits.starts_with('0') {
        Some((8, &digits[1..]))
    } else {
        Some((10, digits))
    };
    if let Some((base, body)) = radix
        && !body.starts_with(['+', '-'])
        && let Ok(integer) = i128::from_str_radix(body, base)
        && let Some(integer) = (if negative {
            integer.checked_neg()
        } else {
            Some(integer)
        })
    {
        if let Ok(value) = i64::try_from(integer) {
            return Some(Value::Number(value.into()));
        }
        if let Ok(value) = u64::try_from(integer) {
            return Some(Value::Number(value.into()));
        }
    }
    // go-yaml's legacy lowercase binary fallback permits a sign after 0b.
    if let Some(body) = clean.strip_prefix("0b")
        && let Ok(value) = i64::from_str_radix(body, 2)
    {
        return Some(Value::Number(value.into()));
    }
    None
}

pub(crate) fn scalar(
    text: &str,
    style: ScalarStyle,
    tag: Option<&Tag>,
) -> Result<Value, ConfigError> {
    let explicit = tag
        .filter(|t| t.handle == "tag:yaml.org,2002:" || t.handle == "!!")
        .map(|t| t.suffix.as_str());
    if (tag.is_some() && explicit.is_none())
        || explicit == Some("str")
        || (explicit.is_none() && style != ScalarStyle::Plain)
    {
        return Ok(Value::String(text.into()));
    }
    if matches!(text, "" | "~" | "null" | "Null" | "NULL") && explicit.is_none_or(|t| t == "null") {
        return Ok(Value::Null);
    }
    if matches!(
        text,
        "true" | "True" | "TRUE" | "yes" | "Yes" | "YES" | "on" | "On" | "ON" | "y" | "Y"
    ) && explicit.is_none_or(|t| t == "bool")
    {
        return Ok(Value::Bool(true));
    }
    if matches!(
        text,
        "false" | "False" | "FALSE" | "no" | "No" | "NO" | "off" | "Off" | "OFF" | "n" | "N"
    ) && explicit.is_none_or(|t| t == "bool")
    {
        return Ok(Value::Bool(false));
    }
    let clean = text.replace('_', "");
    if explicit.is_none_or(|t| matches!(t, "int" | "float")) {
        if let Some(value) = integer_scalar(&clean) {
            return Ok(value);
        }
        if let Ok(number) = clean.parse::<f64>() {
            if let Some(value) = Number::from_f64(number) {
                return Ok(Value::Number(value));
            }
            // go-yaml leaves an overflowing implicit float as a string.
            if explicit.is_none() {
                return Ok(Value::String(text.into()));
            }
            return Err(error(
                ErrorKind::Type,
                "",
                "non-finite YAML number cannot be represented as JSON",
            ));
        }
        if matches!(
            clean.to_ascii_lowercase().as_str(),
            ".inf" | "-.inf" | "+.inf" | ".nan"
        ) {
            return Err(error(
                ErrorKind::Type,
                "",
                "non-finite YAML number cannot be represented as JSON",
            ));
        }
    }
    if explicit.is_some_and(|t| matches!(t, "bool" | "int" | "float" | "null")) {
        return Err(error(
            ErrorKind::Type,
            "",
            "invalid explicitly tagged YAML scalar",
        ));
    }
    Ok(Value::String(text.into()))
}

fn normalized(
    node: Node,
    path: &str,
    duplicates: &mut BTreeSet<String>,
) -> Result<Value, ConfigError> {
    match node {
        Node::Scalar(text, style, tag) => scalar(&text, style, tag.as_ref()),
        Node::Sequence(values) => values
            .into_iter()
            .map(|v| normalized(v, path, duplicates))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Node::Mapping(entries) => {
            let mut map = Map::new();
            for (key, node) in entries {
                let merge_key =
                    matches!(&key, Node::Scalar(text, ScalarStyle::Plain, None) if text == "<<");
                let key = normalized(key, path, duplicates)?;
                let key = match key {
                    Value::String(v) => v,
                    Value::Number(v) => v.to_string(),
                    Value::Bool(v) => v.to_string(),
                    _ => {
                        return Err(error(
                            ErrorKind::Type,
                            path,
                            "configuration mapping key is not a string-compatible scalar",
                        ));
                    },
                };
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                let value = normalized(node, &child, duplicates)?;
                if merge_key {
                    merge_mapping(&mut map, value, path, duplicates)?;
                } else {
                    if map.contains_key(&key) {
                        duplicates.insert(child);
                    }
                    map.insert(key, value);
                }
            }
            Ok(Value::Object(map))
        },
    }
}

fn merge_mapping(
    map: &mut Map<String, Value>,
    value: Value,
    path: &str,
    duplicates: &mut BTreeSet<String>,
) -> Result<(), ConfigError> {
    let merge = match value {
        Value::Object(v) => vec![Value::Object(v)],
        Value::Array(v) => v,
        _ => {
            return Err(error(
                ErrorKind::Type,
                path,
                "YAML merge must contain a mapping",
            ));
        },
    };
    // go-yaml v2 visits merge sequences backwards; earlier maps win.
    for value in merge.into_iter().rev() {
        let Value::Object(values) = value else {
            return Err(error(
                ErrorKind::Type,
                path,
                "YAML merge sequence must contain mappings",
            ));
        };
        for (key, value) in values {
            if map.contains_key(&key) {
                duplicates.insert(if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                });
            }
            map.insert(key, value);
        }
    }
    Ok(())
}

fn go_float(number: f64) -> String {
    let abs = number.abs();
    if abs != 0.0 && !(0.0001..1_000_000.0).contains(&abs) {
        let text = format!("{number:e}");
        if let Some((mantissa, exponent)) = text.split_once('e')
            && let Ok(exponent) = exponent.parse::<i32>()
        {
            return format!("{mantissa}e{exponent:+03}");
        }
        text
    } else {
        number.to_string()
    }
}

fn is_map(path: &str) -> bool {
    matches!(
        path,
        "kubernetes.kubelet.cpuManager.policyOptions" | "kubernetes.kubelet.systemReserved"
    )
}
fn nullable(path: &str) -> bool {
    is_map(path)
        || matches!(
            path,
            "runtime.containerMode" | "kubernetes.apiServer.extraSANs"
        )
}
fn string_value(value: Value, path: &str) -> Result<Value, ConfigError> {
    match value {
        Value::String(_) => Ok(value),
        Value::Null => Ok(Value::String(String::new())),
        Value::Bool(v) => Ok(Value::String(v.to_string())),
        Value::Number(v) => Ok(Value::String(
            if let Some(number) = v.as_f64().filter(|_| v.is_f64()) {
                go_float(number)
            } else {
                v.to_string()
            },
        )),
        _ => Err(error(
            ErrorKind::Type,
            path,
            "expected a string-compatible scalar",
        )),
    }
}
fn overlay(
    target: &mut Value,
    input: Value,
    path: &str,
    presence: &mut BTreeMap<String, Presence>,
    unknown: &mut BTreeSet<String>,
) -> Result<(), ConfigError> {
    presence.insert(
        path.into(),
        if input.is_null() {
            Presence::Null
        } else {
            Presence::Value
        },
    );
    if input.is_null() {
        if nullable(path) {
            *target = Value::Null;
        }
        return Ok(());
    }
    if is_map(path) {
        let Value::Object(values) = input else {
            return Err(error(ErrorKind::Type, path, "expected a string map"));
        };
        if target.is_null() {
            *target = Value::Object(Map::new());
        }
        let Some(map) = target.as_object_mut() else {
            return Err(error(ErrorKind::Type, path, "expected a string map"));
        };
        for (key, value) in values {
            map.insert(key, string_value(value, path)?);
        }
        return Ok(());
    }
    if path == "kubernetes.apiServer.extraSANs" {
        let Value::Array(values) = input else {
            return Err(error(ErrorKind::Type, path, "expected an array of strings"));
        };
        *target = Value::Array(
            values
                .into_iter()
                .map(|v| string_value(v, path))
                .collect::<Result<_, _>>()?,
        );
        return Ok(());
    }
    if let Value::Object(fields) = target {
        let Value::Object(values) = input else {
            return Err(error(ErrorKind::Type, path, "expected a mapping"));
        };
        for (key, value) in values {
            let canonical = fields
                .keys()
                .find(|field| **field == key)
                .or_else(|| fields.keys().find(|field| field.eq_ignore_ascii_case(&key)))
                .cloned();
            let Some(key) = canonical else {
                unknown.insert(if path.is_empty() {
                    key
                } else {
                    format!("{path}.{key}")
                });
                continue;
            };
            let child = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };
            if let Some(target) = fields.get_mut(&key) {
                overlay(target, value, &child, presence, unknown)?;
            }
        }
    } else if target.is_string() {
        *target = string_value(input, path)?;
    } else if target.is_boolean() || path == "runtime.containerMode" {
        if !input.is_boolean() {
            return Err(error(ErrorKind::Type, path, "expected a boolean"));
        }
        *target = input;
    } else if target.is_number() {
        let integer = input.as_i64().or_else(|| {
            input
                .as_f64()
                .filter(|n| n.fract() == 0.0)
                .and_then(|n| format!("{n:.0}").parse::<i64>().ok())
        });
        let Some(integer) = integer else {
            return Err(error(
                ErrorKind::Type,
                path,
                "expected a signed 64-bit integer",
            ));
        };
        *target = Value::Number(integer.into());
    } else {
        return Err(error(
            ErrorKind::Type,
            path,
            "unsupported configuration value",
        ));
    }
    Ok(())
}

/// Decode the first YAML document over typed defaults. Does not read environment,
/// discover the host, create files, validate component policy, or start services.
pub fn decode(input: &str) -> Result<DecodedConfig, ConfigError> {
    decode_with_limits(input, DecodeLimits::default())
}

/// Decode a YAML document into a `serde_json::Value` without imposing a configuration schema.
pub fn decode_yaml_value(input: &str) -> Result<Value, ConfigError> {
    decode_yaml_value_with_limits(input, DecodeLimits::default())
}

/// Decode a YAML document into a `serde_json::Value` with custom limits.
pub fn decode_yaml_value_with_limits(
    input: &str,
    limits: DecodeLimits,
) -> Result<Value, ConfigError> {
    let (val, _) = parse_yaml_raw_value(input, limits)?;
    Ok(val)
}

fn parse_yaml_raw_value(
    input: &str,
    limits: DecodeLimits,
) -> Result<(Value, BTreeSet<String>), ConfigError> {
    if input.len() > limits.input_bytes {
        return Err(error(
            ErrorKind::Limit,
            "",
            "configuration input byte budget exceeded",
        ));
    }
    let mut tree = Tree {
        parser: Parser::new_from_iter(input.chars()),
        anchors: BTreeMap::new(),
        limits,
        nodes: 0,
        bytes: 0,
    };
    let mut duplicates = BTreeSet::new();
    let value = loop {
        match tree.next()? {
            Event::StreamStart | Event::DocumentStart(_) => {},
            Event::StreamEnd => break Value::Null,
            event => {
                let node = tree.node(event, 0)?;
                let end = tree.next()?;
                if !matches!(end, Event::DocumentEnd | Event::StreamEnd) {
                    return Err(error(ErrorKind::Syntax, "", "expected document end"));
                }
                break normalized(node, "", &mut duplicates)?;
            },
        }
    };
    Ok((value, duplicates))
}

pub fn decode_with_limits(input: &str, limits: DecodeLimits) -> Result<DecodedConfig, ConfigError> {
    let (value, duplicates) = parse_yaml_raw_value(input, limits)?;
    // The baseline reads schema metadata before decoding known field types.
    let mut metadata = serde_json::json!({"apiVersion": "", "kind": ""});
    overlay(
        &mut metadata,
        value.clone(),
        "",
        &mut BTreeMap::new(),
        &mut BTreeSet::new(),
    )?;
    let version = metadata["apiVersion"].as_str().unwrap_or("");
    if !version.is_empty() && version != API_VERSION {
        return Err(error(
            ErrorKind::Version,
            "apiVersion",
            format!("unsupported version {version:?}; expected {API_VERSION}"),
        ));
    }
    let mut target = serde_json::to_value(Config::default())
        .map_err(|e| error(ErrorKind::Type, "", e.to_string()))?;
    let mut presence = BTreeMap::new();
    let mut unknown = BTreeSet::new();
    overlay(&mut target, value, "", &mut presence, &mut unknown)?;
    let config: Config =
        serde_json::from_value(target).map_err(|e| error(ErrorKind::Type, "", e.to_string()))?;
    let mut warnings = Vec::new();
    if presence.get("apiVersion") != Some(&Presence::Value) || config.api_version.is_empty() {
        warnings.push(Warning::MissingVersion);
    } else if config.api_version != API_VERSION {
        return Err(error(
            ErrorKind::Version,
            "apiVersion",
            format!(
                "unsupported version {:?}; expected {API_VERSION}",
                config.api_version
            ),
        ));
    }
    if !config.kind.is_empty() && config.kind != KIND {
        warnings.push(Warning::UnexpectedKind(config.kind.clone()));
    }
    if !unknown.is_empty() || !duplicates.is_empty() {
        warnings.push(Warning::IgnoredSettings {
            unknown: unknown.into_iter().collect(),
            duplicate: duplicates.into_iter().collect(),
        });
    }
    Ok(DecodedConfig {
        config,
        warnings,
        presence,
    })
}

/// Read a configuration without modifying it. Absence is an explicit result so
/// callers can retain a previously resolved layer without spurious warnings.
pub fn read_file(path: &std::path::Path) -> Result<Option<DecodedConfig>, ConfigError> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(error(
                ErrorKind::Io,
                &path.display().to_string(),
                e.to_string(),
            ));
        },
    };
    let mut bytes = Vec::new();
    file.take(DecodeLimits::default().input_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| error(ErrorKind::Io, &path.display().to_string(), e.to_string()))?;
    decode_bytes(&bytes).map(Some)
}

/// YAML streams may carry UTF-8 or BOM-marked UTF-16, as in the reference reader.
pub fn decode_bytes(bytes: &[u8]) -> Result<DecodedConfig, ConfigError> {
    let limits = DecodeLimits::default();
    if bytes.len() > limits.input_bytes {
        return Err(error(
            ErrorKind::Limit,
            "",
            "configuration input byte budget exceeded",
        ));
    }
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        let little = bytes[0] == 0xff;
        let body = &bytes[2..];
        if !body.len().is_multiple_of(2) {
            return Err(error(ErrorKind::Syntax, "", "truncated UTF-16 YAML stream"));
        }
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|c| {
                if little {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        let text =
            String::from_utf16(&units).map_err(|e| error(ErrorKind::Syntax, "", e.to_string()))?;
        decode_with_limits(&text, limits)
    } else {
        let text =
            std::str::from_utf8(bytes).map_err(|e| error(ErrorKind::Syntax, "", e.to_string()))?;
        decode_with_limits(text, limits)
    }
}
