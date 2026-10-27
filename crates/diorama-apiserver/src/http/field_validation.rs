use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{LazyLock, RwLock};

use saphyr_parser::{BufferedInput, Event, Parser, ScalarStyle, Span};
use serde_json::Value;

use crate::error::ApiserverError;
use crate::http::query;
use crate::http::route::ResourcePath;

/// Server-side field validation directive (`Strict`, `Warn`, `Ignore`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum FieldValidationDirective {
    #[default]
    Ignore,
    Warn,
    Strict,
}

std::thread_local! {
    static CURRENT_WARNINGS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    static CURRENT_DIRECTIVE: std::cell::Cell<Option<FieldValidationDirective>> = const { std::cell::Cell::new(None) };
}

/// Sets the current field validation directive for the executing thread.
pub(crate) fn set_current_directive(directive: FieldValidationDirective) {
    CURRENT_DIRECTIVE.set(Some(directive));
}

/// Returns the current directive in the thread-local context, or default `Ignore`.
#[allow(dead_code)]
#[must_use]
pub(crate) fn current_directive() -> FieldValidationDirective {
    CURRENT_DIRECTIVE.get().unwrap_or_default()
}

/// Clears the current directive from the thread-local context.
#[allow(dead_code)]
pub(crate) fn clear_current_directive() {
    CURRENT_DIRECTIVE.set(None);
}

/// Takes and clears all recorded warnings for the current thread.
#[allow(dead_code)]
#[must_use]
pub(crate) fn take_warnings() -> Vec<String> {
    CURRENT_WARNINGS.with(|w| std::mem::take(&mut *w.borrow_mut()))
}

/// Returns all recorded warnings for the current thread without clearing.
#[allow(dead_code)]
#[must_use]
pub(crate) fn current_warnings() -> Vec<String> {
    CURRENT_WARNINGS.with(|w| w.borrow().clone())
}

/// Adds a warning to the thread-local warning store.
pub(crate) fn add_warning(warning: impl Into<String>) {
    CURRENT_WARNINGS.with(|w| w.borrow_mut().push(warning.into()));
}

/// Clears any recorded warnings for the current thread.
pub(crate) fn clear_warnings() {
    CURRENT_WARNINGS.with(|w| w.borrow_mut().clear());
}

/// Parses the `fieldValidation` query parameter from the request query string.
#[must_use]
pub(crate) fn parse_validation_directive(query: Option<&str>) -> FieldValidationDirective {
    match query::parse(query)
        .get("fieldValidation")
        .map(String::as_str)
    {
        Some(v) if v.eq_ignore_ascii_case("strict") => FieldValidationDirective::Strict,
        Some(v) if v.eq_ignore_ascii_case("warn") => FieldValidationDirective::Warn,
        Some(v) if v.eq_ignore_ascii_case("ignore") => FieldValidationDirective::Ignore,
        _ => FieldValidationDirective::Ignore,
    }
}

/// Returns true if query parameter `fieldValidation` is present and equals "Strict" (case-insensitive).
/// Also sets the thread-local validation directive for downstream decode steps.
#[must_use]
pub(crate) fn is_strict(query: Option<&str>) -> bool {
    let directive = parse_validation_directive(query);
    set_current_directive(directive);
    directive == FieldValidationDirective::Strict
}

static CRD_SCHEMAS: LazyLock<RwLock<BTreeMap<String, Value>>> =
    LazyLock::new(|| RwLock::new(BTreeMap::new()));

/// Registers a CRD `OpenAPI` v3 schema for field validation.
#[allow(dead_code)]
pub(crate) fn register_crd_schema(group: &str, plural: &str, openapi_v3_schema: Value) {
    let key = if group.is_empty() {
        plural.to_string()
    } else {
        format!("{group}/{plural}")
    };
    CRD_SCHEMAS.write().unwrap().insert(key, openapi_v3_schema);
}

/// Unregisters a CRD `OpenAPI` v3 schema.
#[allow(dead_code)]
pub(crate) fn unregister_crd_schema(group: &str, plural: &str) {
    let key = if group.is_empty() {
        plural.to_string()
    } else {
        format!("{group}/{plural}")
    };
    CRD_SCHEMAS.write().unwrap().remove(&key);
}

/// Clears all registered CRD schemas.
#[allow(dead_code)]
pub(crate) fn clear_crd_schemas() {
    CRD_SCHEMAS.write().unwrap().clear();
}

/// Returns a copy of the registered CRD schema if present.
#[must_use]
pub(crate) fn get_crd_schema(group: &str, plural: &str) -> Option<Value> {
    let key = if group.is_empty() {
        plural.to_string()
    } else {
        format!("{group}/{plural}")
    };
    CRD_SCHEMAS.read().unwrap().get(&key).cloned()
}

/// Checks strict decoding constraints on a JSON request payload.
/// Detects duplicate keys at any depth and unknown fields.
#[allow(dead_code)]
pub(crate) fn check_strict_json(body: &[u8], path: &ResourcePath) -> Result<(), ApiserverError> {
    let Ok(text) = std::str::from_utf8(body) else {
        return Err(ApiserverError::BadRequest {
            message: "request body is not valid UTF-8".to_string(),
        });
    };
    let kind = kind_from_path(path);
    let crd_schema = get_crd_schema(&path.group, &path.resource);
    let mut checker = JsonStrictChecker::new(text, kind, crd_schema.as_ref());
    checker.check()
}

/// Decodes request body bytes as JSON or YAML, enforcing field validation rules
/// based on `is_strict` or the currently active `FieldValidationDirective`.
pub(crate) fn decode_body_with_validation(
    body: &[u8],
    content_type: Option<&str>,
    is_strict: bool,
    path: &ResourcePath,
) -> Result<Value, ApiserverError> {
    let directive = CURRENT_DIRECTIVE.get().unwrap_or(if is_strict {
        FieldValidationDirective::Strict
    } else {
        FieldValidationDirective::Ignore
    });
    decode_body_with_directive(body, content_type, directive, path)
}

/// Decodes request body bytes enforcing the given `FieldValidationDirective`.
pub(crate) fn decode_body_with_directive(
    body: &[u8],
    content_type: Option<&str>,
    directive: FieldValidationDirective,
    path: &ResourcePath,
) -> Result<Value, ApiserverError> {
    if body.is_empty() {
        return Ok(Value::Null);
    }
    clear_warnings();

    let is_yaml = content_type.is_some_and(|ct| ct.contains("yaml") || ct.contains("apply-patch"));
    let trimmed = body
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .copied()
        .collect::<Vec<u8>>();
    let looks_like_json = trimmed.first() == Some(&b'{') || trimmed.first() == Some(&b'[');

    if !is_yaml && looks_like_json {
        decode_json_with_directive(body, directive, path)
    } else {
        decode_yaml_with_directive(body, directive, Some(path))
    }
}

fn format_strict_errors(unknown_fields: &[String], duplicate_fields: &[String]) -> String {
    let mut all_errors = Vec::new();
    all_errors.extend(unknown_fields.iter().cloned());
    all_errors.extend(duplicate_fields.iter().cloned());
    for unk in unknown_fields {
        let f = unk
            .strip_prefix("unknown field \"")
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(unk);
        all_errors.push(format!(".{f}: field not declared in schema"));
    }
    for dup in duplicate_fields {
        let d = dup
            .strip_prefix("duplicate field \"")
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(dup);
        all_errors.push(format!(".{d}: duplicate entries for key"));
    }
    format!("strict decoding error: {}", all_errors.join(", "))
}

fn decode_json_with_directive(
    body: &[u8],
    directive: FieldValidationDirective,
    path: &ResourcePath,
) -> Result<Value, ApiserverError> {
    let Ok(text) = std::str::from_utf8(body) else {
        return Err(ApiserverError::BadRequest {
            message: "request body is not valid UTF-8".to_string(),
        });
    };

    let crd_schema = get_crd_schema(&path.group, &path.resource);
    let kind = kind_from_path(path);

    let mut checker = JsonStrictChecker::new(text, kind, crd_schema.as_ref());
    let (unknown_fields, duplicate_fields) = checker.analyze()?;

    match directive {
        FieldValidationDirective::Strict => {
            if !unknown_fields.is_empty() || !duplicate_fields.is_empty() {
                return Err(ApiserverError::InvalidInput {
                    field: "body".to_string(),
                    reason: format_strict_errors(&unknown_fields, &duplicate_fields),
                });
            }
        },
        FieldValidationDirective::Warn => {
            for unk in &unknown_fields {
                let field_path = unk
                    .strip_prefix("unknown field \"")
                    .and_then(|s| s.strip_suffix('"'))
                    .or_else(|| unk.strip_prefix("unknown field "))
                    .unwrap_or(unk);
                add_warning(format!(r#"299 - "Unknown field \"{field_path}\"""#));
            }
            for dup in &duplicate_fields {
                let field_path = dup
                    .strip_prefix("duplicate field \"")
                    .and_then(|s| s.strip_suffix('"'))
                    .or_else(|| dup.strip_prefix("duplicate field "))
                    .unwrap_or(dup);
                add_warning(format!(r#"299 - "duplicate field \"{field_path}\"""#));
            }
        },
        FieldValidationDirective::Ignore => {},
    }

    let mut val: Value =
        serde_json::from_slice(body).map_err(|err| ApiserverError::BadRequest {
            message: format!("request body is not valid JSON: {err}"),
        })?;

    if directive == FieldValidationDirective::Ignore {
        strip_unknown_fields(&mut val, kind, crd_schema.as_ref());
    }

    Ok(val)
}

/// Decodes YAML into `serde_json::Value`, detecting duplicate keys when `is_strict` is true.
pub(crate) fn decode_yaml(body: &[u8], is_strict: bool) -> Result<Value, ApiserverError> {
    let directive = if is_strict {
        FieldValidationDirective::Strict
    } else {
        FieldValidationDirective::Ignore
    };
    decode_yaml_with_directive(body, directive, None)
}

/// Decodes YAML into `serde_json::Value`, enforcing field validation directive.
pub(crate) fn decode_yaml_with_directive(
    body: &[u8],
    directive: FieldValidationDirective,
    path: Option<&ResourcePath>,
) -> Result<Value, ApiserverError> {
    let text = std::str::from_utf8(body).map_err(|err| ApiserverError::BadRequest {
        message: format!("request body is not valid UTF-8: {err}"),
    })?;
    let mut parser = Parser::new(BufferedInput::new(text.chars()));
    let mut anchors = BTreeMap::new();
    let mut root_val = Value::Null;
    let mut duplicate_fields = Vec::new();

    loop {
        let event_opt =
            parser
                .next_event()
                .transpose()
                .map_err(|err| ApiserverError::BadRequest {
                    message: format!("YAML syntax error: {err}"),
                })?;
        let Some((event, span)) = event_opt else {
            break;
        };
        match event {
            Event::StreamStart
            | Event::StreamEnd
            | Event::DocumentStart(_)
            | Event::DocumentEnd => {},
            _ => {
                let mut ctx = YamlDecodeContext {
                    directive,
                    duplicate_fields: &mut duplicate_fields,
                    prefix: String::new(),
                    has_path: path.is_some(),
                    depth: 0,
                };
                root_val = decode_yaml_node(&mut parser, event, span, &mut anchors, &mut ctx)?;
                break;
            },
        }
    }

    if let Some(path) = path {
        let crd_schema = get_crd_schema(&path.group, &path.resource);
        let kind = kind_from_path(path);
        let mut unknown_fields = Vec::new();
        collect_unknown_fields(
            &root_val,
            kind,
            crd_schema.as_ref(),
            "",
            &mut unknown_fields,
        );

        match directive {
            FieldValidationDirective::Strict => {
                if !unknown_fields.is_empty() || !duplicate_fields.is_empty() {
                    return Err(ApiserverError::InvalidInput {
                        field: "body".to_string(),
                        reason: format_strict_errors(&unknown_fields, &duplicate_fields),
                    });
                }
            },
            FieldValidationDirective::Warn => {
                for unk in &unknown_fields {
                    let field_path = unk
                        .strip_prefix("unknown field \"")
                        .and_then(|s| s.strip_suffix('"'))
                        .or_else(|| unk.strip_prefix("unknown field "))
                        .unwrap_or(unk);
                    add_warning(format!(r#"299 - "Unknown field \"{field_path}\"""#));
                }
                for dup in &duplicate_fields {
                    let field_path = dup
                        .strip_prefix("duplicate field \"")
                        .and_then(|s| s.strip_suffix('"'))
                        .or_else(|| dup.strip_prefix("duplicate field "))
                        .unwrap_or(dup);
                    add_warning(format!(r#"299 - "duplicate field \"{field_path}\"""#));
                }
            },
            FieldValidationDirective::Ignore => {
                strip_unknown_fields(&mut root_val, kind, crd_schema.as_ref());
            },
        }
    }

    Ok(root_val)
}

struct YamlDecodeContext<'a> {
    directive: FieldValidationDirective,
    duplicate_fields: &'a mut Vec<String>,
    prefix: String,
    has_path: bool,
    depth: usize,
}

fn decode_yaml_sequence<'a>(
    parser: &mut Parser<'a, BufferedInput<std::str::Chars<'a>>>,
    anchors: &mut BTreeMap<usize, Value>,
    ctx: &mut YamlDecodeContext<'_>,
) -> Result<Value, ApiserverError> {
    let mut list = Vec::new();
    loop {
        let next_opt =
            parser
                .next_event()
                .transpose()
                .map_err(|err| ApiserverError::BadRequest {
                    message: format!("YAML syntax error: {err}"),
                })?;
        let Some((next_event, next_span)) = next_opt else {
            break;
        };
        if next_event == Event::SequenceEnd {
            break;
        }
        ctx.depth += 1;
        let node = decode_yaml_node(parser, next_event, next_span, anchors, ctx);
        ctx.depth -= 1;
        list.push(node?);
    }
    Ok(Value::Array(list))
}

fn decode_yaml_mapping<'a>(
    parser: &mut Parser<'a, BufferedInput<std::str::Chars<'a>>>,
    anchors: &mut BTreeMap<usize, Value>,
    ctx: &mut YamlDecodeContext<'_>,
) -> Result<Value, ApiserverError> {
    let mut map = serde_json::Map::new();
    let mut seen_keys = BTreeSet::new();
    loop {
        let next_opt =
            parser
                .next_event()
                .transpose()
                .map_err(|err| ApiserverError::BadRequest {
                    message: format!("YAML syntax error: {err}"),
                })?;
        let Some((key_event, key_span)) = next_opt else {
            break;
        };
        if key_event == Event::MappingEnd {
            break;
        }
        let key_str = match key_event {
            Event::Scalar(text, _, _, _) => text.into_owned(),
            _ => {
                return Err(ApiserverError::BadRequest {
                    message: "non-scalar YAML mapping key".to_string(),
                });
            },
        };
        let field_path = if ctx.prefix.is_empty() {
            key_str.clone()
        } else {
            format!("{}.{key_str}", ctx.prefix)
        };
        if !seen_keys.insert(key_str.clone()) {
            match ctx.directive {
                FieldValidationDirective::Strict => {
                    if ctx.has_path {
                        ctx.duplicate_fields
                            .push(format!("duplicate field \"{field_path}\""));
                    } else {
                        return Err(ApiserverError::BadRequest {
                            message: format!(
                                "error unmarshaling JSON: while decoding JSON: line {}: key \"{}\" already set in map",
                                key_span.start.line(),
                                key_str
                            ),
                        });
                    }
                },
                FieldValidationDirective::Warn => {
                    ctx.duplicate_fields
                        .push(format!("duplicate field \"{key_str}\""));
                },
                FieldValidationDirective::Ignore => {},
            }
        }
        let val_opt =
            parser
                .next_event()
                .transpose()
                .map_err(|err| ApiserverError::BadRequest {
                    message: format!("YAML syntax error: {err}"),
                })?;
        let (val_event, val_span) = val_opt.ok_or_else(|| ApiserverError::BadRequest {
            message: "unexpected EOF in YAML mapping value".to_string(),
        })?;
        let old_prefix = std::mem::replace(&mut ctx.prefix, field_path);
        ctx.depth += 1;
        let val = decode_yaml_node(parser, val_event, val_span, anchors, ctx);
        ctx.depth -= 1;
        ctx.prefix = old_prefix;
        map.insert(key_str, val?);
    }
    Ok(Value::Object(map))
}

fn decode_yaml_node<'a>(
    parser: &mut Parser<'a, BufferedInput<std::str::Chars<'a>>>,
    event: Event<'a>,
    _span: Span,
    anchors: &mut BTreeMap<usize, Value>,
    ctx: &mut YamlDecodeContext<'_>,
) -> Result<Value, ApiserverError> {
    if ctx.depth > 128 {
        return Err(ApiserverError::BadRequest {
            message: "YAML depth limit exceeded".to_string(),
        });
    }
    let (anchor, val) = match event {
        Event::Scalar(text, style, anchor, _tag) => {
            let val = parse_yaml_scalar(&text, style);
            (anchor, val)
        },
        Event::Alias(id) => {
            let val = anchors
                .get(&id)
                .cloned()
                .ok_or_else(|| ApiserverError::BadRequest {
                    message: "unknown YAML alias".to_string(),
                })?;
            return Ok(val);
        },
        Event::SequenceStart(anchor, _) => {
            let seq = decode_yaml_sequence(parser, anchors, ctx)?;
            (anchor, seq)
        },
        Event::MappingStart(anchor, _) => {
            let map = decode_yaml_mapping(parser, anchors, ctx)?;
            (anchor, map)
        },
        _ => return Ok(Value::Null),
    };
    if anchor != 0 {
        anchors.insert(anchor, val.clone());
    }
    Ok(val)
}

fn parse_yaml_scalar(text: &str, style: ScalarStyle) -> Value {
    if style != ScalarStyle::Plain {
        return Value::String(text.to_string());
    }
    match text {
        "true" | "True" | "TRUE" => Value::Bool(true),
        "false" | "False" | "FALSE" => Value::Bool(false),
        "null" | "Null" | "NULL" | "~" | "" => Value::Null,
        _ => {
            if let Ok(i) = text.parse::<i64>() {
                Value::Number(i.into())
            } else if let Ok(u) = text.parse::<u64>() {
                Value::Number(u.into())
            } else if let Ok(f) = text.parse::<f64>() {
                serde_json::Number::from_f64(f)
                    .map_or_else(|| Value::String(text.to_string()), Value::Number)
            } else {
                Value::String(text.to_string())
            }
        },
    }
}

struct JsonStrictChecker<'a> {
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
    kind: Option<&'a str>,
    crd_schema: Option<&'a Value>,
    unknown_fields: Vec<String>,
    duplicate_fields: Vec<String>,
}

impl<'a> JsonStrictChecker<'a> {
    fn new(src: &'a str, kind: Option<&'a str>, crd_schema: Option<&'a Value>) -> Self {
        Self {
            chars: src.char_indices().peekable(),
            kind,
            crd_schema,
            unknown_fields: Vec::new(),
            duplicate_fields: Vec::new(),
        }
    }

    fn analyze(&mut self) -> Result<(Vec<String>, Vec<String>), ApiserverError> {
        self.parse_value("")?;
        Ok((
            std::mem::take(&mut self.unknown_fields),
            std::mem::take(&mut self.duplicate_fields),
        ))
    }

    fn check(&mut self) -> Result<(), ApiserverError> {
        let (unknown_fields, duplicate_fields) = self.analyze()?;
        if unknown_fields.is_empty() && duplicate_fields.is_empty() {
            Ok(())
        } else {
            Err(ApiserverError::InvalidInput {
                field: "body".to_string(),
                reason: format_strict_errors(&unknown_fields, &duplicate_fields),
            })
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some((_, c)) = self.chars.peek() {
            if c.is_ascii_whitespace() {
                self.chars.next();
            } else {
                break;
            }
        }
    }

    fn parse_string(&mut self) -> Option<String> {
        self.skip_whitespace();
        if self.chars.next()?.1 != '"' {
            return None;
        }
        let mut s = String::new();
        while let Some((_, c)) = self.chars.next() {
            if c == '"' {
                return Some(s);
            }
            if c == '\\' {
                if let Some(ch) = self.parse_escaped_char() {
                    s.push(ch);
                }
            } else {
                s.push(c);
            }
        }
        None
    }

    fn parse_escaped_char(&mut self) -> Option<char> {
        let (_, esc) = self.chars.next()?;
        match esc {
            '"' => Some('"'),
            '\\' => Some('\\'),
            '/' => Some('/'),
            'b' => Some('\x08'),
            'f' => Some('\x0c'),
            'n' => Some('\n'),
            'r' => Some('\r'),
            't' => Some('\t'),
            'u' => self.parse_unicode_escape(),
            _ => Some(esc),
        }
    }

    fn parse_unicode_escape(&mut self) -> Option<char> {
        let mut hex = String::with_capacity(4);
        for _ in 0..4 {
            let (_, h) = self.chars.next()?;
            hex.push(h);
        }
        let code = u32::from_str_radix(&hex, 16).ok()?;
        char::from_u32(code)
    }

    fn parse_value(&mut self, prefix: &str) -> Result<(), ApiserverError> {
        self.skip_whitespace();
        let Some(&(_, c)) = self.chars.peek() else {
            return Ok(());
        };
        match c {
            '{' => self.parse_object(prefix),
            '[' => self.parse_array(prefix),
            '"' => {
                self.parse_string();
                Ok(())
            },
            _ => {
                while let Some(&(_, ch)) = self.chars.peek() {
                    if ch.is_ascii_whitespace() || ch == ',' || ch == '}' || ch == ']' {
                        break;
                    }
                    self.chars.next();
                }
                Ok(())
            },
        }
    }

    fn parse_array(&mut self, prefix: &str) -> Result<(), ApiserverError> {
        self.chars.next();
        let mut idx = 0;
        loop {
            self.skip_whitespace();
            if let Some(&(_, ']')) = self.chars.peek() {
                self.chars.next();
                break;
            }
            let item_prefix = format!("{prefix}[{idx}]");
            self.parse_value(&item_prefix)?;
            idx += 1;
            self.skip_whitespace();
            if let Some(&(_, ',')) = self.chars.peek() {
                self.chars.next();
            } else if let Some(&(_, ']')) = self.chars.peek() {
                self.chars.next();
                break;
            } else {
                break;
            }
        }
        Ok(())
    }

    fn parse_object(&mut self, prefix: &str) -> Result<(), ApiserverError> {
        self.chars.next();
        let mut seen_keys = HashSet::new();
        loop {
            self.skip_whitespace();
            if let Some(&(_, '}')) = self.chars.peek() {
                self.chars.next();
                break;
            }
            let Some(key) = self.parse_string() else {
                break;
            };
            let field_path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            if !seen_keys.insert(key.clone()) {
                self.duplicate_fields
                    .push(format!("duplicate field \"{field_path}\""));
            }

            let is_unknown = if let Some(schema) = self.crd_schema {
                is_unknown_crd_field(schema, prefix, &key)
            } else {
                let is_meta = prefix == "metadata" || prefix.ends_with(".metadata");
                let is_spec = prefix == "spec";
                let is_pod_spec = prefix == "spec.template.spec";
                let is_root = prefix.is_empty();

                (is_meta && !is_known_metadata_key(&key))
                    || (is_spec && !is_known_spec_key(self.kind, &key))
                    || (is_pod_spec && !is_known_pod_spec_key(&key))
                    || (is_root && !is_known_root_key(self.kind, &key))
            };

            if is_unknown {
                self.unknown_fields
                    .push(format!("unknown field \"{field_path}\""));
            }

            self.skip_whitespace();
            if let Some(&(_, ':')) = self.chars.peek() {
                self.chars.next();
            }
            self.parse_value(&field_path)?;
            self.skip_whitespace();
            if let Some(&(_, ',')) = self.chars.peek() {
                self.chars.next();
            } else if let Some(&(_, '}')) = self.chars.peek() {
                self.chars.next();
                break;
            } else {
                break;
            }
        }
        Ok(())
    }
}

fn is_unknown_crd_field(schema: &Value, prefix: &str, key: &str) -> bool {
    let subschema = resolve_subschema(schema, prefix);
    let is_meta = prefix == "metadata" || prefix.ends_with(".metadata");
    if is_meta && !is_known_metadata_key(key) {
        return true;
    }
    let is_embedded = subschema
        .and_then(|s| s.get("x-kubernetes-embedded-resource"))
        .and_then(Value::as_bool)
        == Some(true);
    if (prefix.is_empty() || is_embedded) && matches!(key, "apiVersion" | "kind" | "metadata") {
        return false;
    }
    let Some(sub) = subschema else {
        return false;
    };
    let preserve_unknown = sub
        .get("x-kubernetes-preserve-unknown-fields")
        .and_then(Value::as_bool)
        == Some(true)
        || sub.get("additionalProperties").is_some();
    if preserve_unknown {
        return false;
    }
    if let Some(props) = sub.get("properties").and_then(Value::as_object) {
        !props.contains_key(key)
    } else {
        sub.get("type").and_then(Value::as_str) == Some("object")
    }
}

fn resolve_subschema<'a>(schema: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(schema);
    }
    let mut curr = schema;
    for part in path.split('.') {
        let clean_part = part.split('[').next().unwrap_or(part);
        if clean_part.is_empty() {
            continue;
        }
        let props = curr.get("properties").and_then(Value::as_object)?;
        let next = props.get(clean_part)?;
        curr = next;
        if part.contains('[') {
            let mut sub = curr;
            let mut bracket_part = &part[clean_part.len()..];
            while bracket_part.starts_with('[') {
                sub = sub.get("items").unwrap_or(sub);
                if let Some((_, rest)) = bracket_part.split_once(']') {
                    bracket_part = rest;
                } else {
                    break;
                }
            }
            curr = sub;
        }
    }
    Some(curr)
}

fn validate_embedded_metadata(v: &Value, field_path: &str, unknowns: &mut Vec<String>) {
    let Some(meta_obj) = v.as_object() else {
        return;
    };
    for meta_k in meta_obj.keys() {
        if !is_known_metadata_key(meta_k) {
            unknowns.push(format!("unknown field \"{field_path}.{meta_k}\""));
        }
    }
}

fn collect_unknown_fields(
    val: &Value,
    kind: Option<&str>,
    crd_schema: Option<&Value>,
    prefix: &str,
    unknowns: &mut Vec<String>,
) {
    let Some(obj) = val.as_object() else {
        if let Some(arr) = val.as_array() {
            for (i, item) in arr.iter().enumerate() {
                let item_prefix = format!("{prefix}[{i}]");
                collect_unknown_fields(item, kind, crd_schema, &item_prefix, unknowns);
            }
        }
        return;
    };

    for (k, v) in obj {
        let field_path = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };

        let is_unknown = if let Some(schema) = crd_schema {
            let sub = resolve_subschema(schema, prefix);
            let is_embedded = sub
                .and_then(|s| s.get("x-kubernetes-embedded-resource"))
                .and_then(Value::as_bool)
                == Some(true);
            if is_embedded && k == "metadata" {
                validate_embedded_metadata(v, &field_path, unknowns);
                false
            } else {
                is_unknown_crd_field(schema, prefix, k)
            }
        } else {
            let is_meta = prefix == "metadata" || prefix.ends_with(".metadata");
            let is_spec = prefix == "spec";
            let is_pod_spec = prefix == "spec.template.spec";
            let is_root = prefix.is_empty();

            (is_meta && !is_known_metadata_key(k))
                || (is_spec && !is_known_spec_key(kind, k))
                || (is_pod_spec && !is_known_pod_spec_key(k))
                || (is_root && !is_known_root_key(kind, k))
        };

        if is_unknown {
            unknowns.push(format!("unknown field \"{field_path}\""));
        }

        collect_unknown_fields(v, kind, crd_schema, &field_path, unknowns);
    }
}

pub(crate) fn strip_unknown_crd_fields(val: &mut Value, schema: &Value) {
    strip_node(val, None, Some(schema), "");
}

fn strip_unknown_fields(val: &mut Value, kind: Option<&str>, crd_schema: Option<&Value>) {
    strip_node(val, kind, crd_schema, "");
}

fn strip_node(val: &mut Value, kind: Option<&str>, crd_schema: Option<&Value>, prefix: &str) {
    let Some(obj) = val.as_object_mut() else {
        if let Some(arr) = val.as_array_mut() {
            for (i, item) in arr.iter_mut().enumerate() {
                let item_prefix = format!("{prefix}[{i}]");
                strip_node(item, kind, crd_schema, &item_prefix);
            }
        }
        return;
    };

    if let Some(schema) = crd_schema {
        let subschema = resolve_subschema(schema, prefix);
        let preserve_unknown = subschema
            .and_then(|s| s.get("x-kubernetes-preserve-unknown-fields"))
            .and_then(Value::as_bool)
            == Some(true)
            || subschema
                .and_then(|s| s.get("additionalProperties"))
                .is_some();

        let is_meta = prefix == "metadata" || prefix.ends_with(".metadata");
        if is_meta {
            obj.retain(|k, _| is_known_metadata_key(k));
        } else if !preserve_unknown {
            if let Some(props) = subschema
                .and_then(|s| s.get("properties"))
                .and_then(Value::as_object)
            {
                let is_embedded = subschema
                    .and_then(|s| s.get("x-kubernetes-embedded-resource"))
                    .and_then(Value::as_bool)
                    == Some(true);
                obj.retain(|k, _| {
                    props.contains_key(k)
                        || ((prefix.is_empty() || is_embedded)
                            && matches!(k.as_str(), "apiVersion" | "kind" | "metadata"))
                });
            } else if subschema
                .and_then(|s| s.get("type"))
                .and_then(Value::as_str)
                == Some("object")
            {
                obj.clear();
            }
        }
    } else {
        let is_meta = prefix == "metadata" || prefix.ends_with(".metadata");
        let is_spec = prefix == "spec";
        let is_pod_spec = prefix == "spec.template.spec";
        let is_root = prefix.is_empty();

        if is_meta {
            obj.retain(|k, _| is_known_metadata_key(k));
        } else if is_spec && kind.is_some() {
            obj.retain(|k, _| is_known_spec_key(kind, k));
        } else if is_pod_spec {
            obj.retain(|k, _| is_known_pod_spec_key(k));
        } else if is_root && kind.is_some() {
            obj.retain(|k, _| is_known_root_key(kind, k));
        }
    }

    for (k, v) in obj.iter_mut() {
        let next_prefix = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        strip_node(v, kind, crd_schema, &next_prefix);
    }
}

fn kind_from_path(path: &ResourcePath) -> Option<&'static str> {
    match path.resource.as_str() {
        "deployments" => Some("Deployment"),
        "pods" => Some("Pod"),
        "services" => Some("Service"),
        "jobs" => Some("Job"),
        "statefulsets" => Some("StatefulSet"),
        "daemonsets" => Some("DaemonSet"),
        "replicasets" => Some("ReplicaSet"),
        "replicationcontrollers" => Some("ReplicationController"),
        "configmaps" => Some("ConfigMap"),
        "secrets" => Some("Secret"),
        "persistentvolumeclaims" => Some("PersistentVolumeClaim"),
        "persistentvolumes" => Some("PersistentVolume"),
        "resourcequotas" => Some("ResourceQuota"),
        "limitranges" => Some("LimitRange"),
        "cronjobs" => Some("CronJob"),
        "ingresses" => Some("Ingress"),
        "networkpolicies" => Some("NetworkPolicy"),
        "namespaces" => Some("Namespace"),
        "serviceaccounts" => Some("ServiceAccount"),
        _ => None,
    }
}

fn is_known_root_key(kind: Option<&str>, key: &str) -> bool {
    let Some(kind) = kind else {
        return true;
    };
    if matches!(key, "apiVersion" | "kind" | "metadata" | "status") {
        return true;
    }
    match kind {
        "Deployment"
        | "Pod"
        | "Service"
        | "Job"
        | "StatefulSet"
        | "DaemonSet"
        | "ReplicaSet"
        | "ReplicationController"
        | "CronJob"
        | "PersistentVolumeClaim"
        | "PersistentVolume"
        | "ResourceQuota"
        | "LimitRange"
        | "Ingress"
        | "NetworkPolicy"
        | "Namespace" => key == "spec",
        "ConfigMap" => matches!(key, "data" | "binaryData" | "immutable"),
        "Secret" => matches!(key, "data" | "stringData" | "type" | "immutable"),
        "ServiceAccount" => {
            matches!(
                key,
                "secrets" | "imagePullSecrets" | "automountServiceAccountToken"
            )
        },
        _ => true,
    }
}

fn is_known_metadata_key(key: &str) -> bool {
    matches!(
        key,
        "name"
            | "generateName"
            | "namespace"
            | "selfLink"
            | "uid"
            | "resourceVersion"
            | "generation"
            | "creationTimestamp"
            | "deletionTimestamp"
            | "deletionGracePeriodSeconds"
            | "labels"
            | "annotations"
            | "ownerReferences"
            | "finalizers"
            | "clusterName"
            | "managedFields"
    )
}

fn is_known_pod_spec_key(key: &str) -> bool {
    matches!(
        key,
        "volumes"
            | "initContainers"
            | "containers"
            | "ephemeralContainers"
            | "restartPolicy"
            | "terminationGracePeriodSeconds"
            | "activeDeadlineSeconds"
            | "dnsPolicy"
            | "nodeSelector"
            | "serviceAccountName"
            | "serviceAccount"
            | "automountServiceAccountToken"
            | "nodeName"
            | "hostNetwork"
            | "hostPID"
            | "hostIPC"
            | "shareProcessNamespace"
            | "securityContext"
            | "imagePullSecrets"
            | "hostname"
            | "subdomain"
            | "affinity"
            | "schedulerName"
            | "tolerations"
            | "hostAliases"
            | "priorityClassName"
            | "priority"
            | "dnsConfig"
            | "readinessGates"
            | "runtimeClassName"
            | "enableServiceLinks"
            | "preemptionPolicy"
            | "overhead"
            | "topologySpreadConstraints"
            | "setHostnameAsFQDN"
            | "os"
            | "schedulingGates"
            | "resourceClaims"
    )
}

#[allow(clippy::too_many_lines)]
fn is_known_spec_key(kind: Option<&str>, key: &str) -> bool {
    let Some(kind) = kind else {
        return true;
    };
    match kind {
        "Deployment" => matches!(
            key,
            "replicas"
                | "selector"
                | "template"
                | "strategy"
                | "minReadySeconds"
                | "revisionHistoryLimit"
                | "paused"
                | "progressDeadlineSeconds"
        ),
        "Pod" => is_known_pod_spec_key(key),
        "Service" => matches!(
            key,
            "ports"
                | "selector"
                | "clusterIP"
                | "clusterIPs"
                | "type"
                | "externalIPs"
                | "sessionAffinity"
                | "loadBalancerIP"
                | "loadBalancerSourceRanges"
                | "externalName"
                | "externalTrafficPolicy"
                | "healthCheckNodePort"
                | "publishNotReadyAddresses"
                | "sessionAffinityConfig"
                | "ipFamilies"
                | "ipFamilyPolicy"
                | "allocateLoadBalancerNodePorts"
                | "loadBalancerClass"
                | "internalTrafficPolicy"
                | "trafficDistribution"
        ),
        "Job" => matches!(
            key,
            "parallelism"
                | "completions"
                | "activeDeadlineSeconds"
                | "backoffLimit"
                | "backoffLimitPerIndex"
                | "maxFailedIndexes"
                | "selector"
                | "manualSelector"
                | "template"
                | "ttlSecondsAfterFinished"
                | "completionMode"
                | "suspend"
                | "podReplacementPolicy"
                | "managedBy"
        ),
        "StatefulSet" => matches!(
            key,
            "replicas"
                | "selector"
                | "template"
                | "volumeClaimTemplates"
                | "serviceName"
                | "podManagementPolicy"
                | "updateStrategy"
                | "revisionHistoryLimit"
                | "minReadySeconds"
                | "persistentVolumeClaimRetentionPolicy"
        ),
        "DaemonSet" => matches!(
            key,
            "selector" | "template" | "updateStrategy" | "minReadySeconds" | "revisionHistoryLimit"
        ),
        "ReplicaSet" | "ReplicationController" => matches!(
            key,
            "replicas" | "minReadySeconds" | "selector" | "template"
        ),
        "CronJob" => matches!(
            key,
            "schedule"
                | "startingDeadlineSeconds"
                | "concurrencyPolicy"
                | "suspend"
                | "jobTemplate"
                | "successfulJobsHistoryLimit"
                | "failedJobsHistoryLimit"
                | "timeZone"
        ),
        "PersistentVolumeClaim" => matches!(
            key,
            "accessModes"
                | "selector"
                | "resources"
                | "volumeName"
                | "storageClassName"
                | "volumeMode"
                | "dataSource"
                | "dataSourceRef"
        ),
        "PersistentVolume" => matches!(
            key,
            "capacity"
                | "accessModes"
                | "claimRef"
                | "persistentVolumeReclaimPolicy"
                | "storageClassName"
                | "mountOptions"
                | "volumeMode"
                | "nodeAffinity"
                | "hostPath"
                | "nfs"
                | "csi"
                | "iscsi"
                | "fc"
                | "local"
                | "awsElasticBlockStore"
                | "gcePersistentDisk"
                | "azureDisk"
                | "azureFile"
        ),
        "ResourceQuota" => matches!(key, "hard" | "scopes" | "scopeSelector"),
        "LimitRange" => matches!(key, "limits"),
        "Ingress" => matches!(key, "ingressClassName" | "defaultBackend" | "tls" | "rules"),
        "NetworkPolicy" => matches!(key, "podSelector" | "ingress" | "egress" | "policyTypes"),
        "Namespace" => matches!(key, "finalizers"),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_json_unknown_and_duplicate_fields() {
        let json_body = br#"{
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "my-dep",
                "labels": {"app": "nginx"}
            },
            "spec": {
                "unknownField": "foo",
                "replicas": 2,
                "replicas": 3,
                "selector": {
                    "matchLabels": {"app": "nginx"}
                },
                "template": {
                    "metadata": {"labels": {"app": "nginx"}},
                    "spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]}
                }
            }
        }"#;

        let path = ResourcePath {
            group: "apps".to_string(),
            version: "v1".to_string(),
            namespace: Some("default".to_string()),
            resource: "deployments".to_string(),
            subresource: None,
            name: None,
            trailing_slash: false,
        };

        let err = check_strict_json(json_body, &path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(r#"strict decoding error: unknown field "spec.unknownField", duplicate field "spec.replicas""#),
            "expected strict decoding error with unknown and duplicate fields, got: {msg}"
        );
    }

    #[test]
    fn test_strict_json_unknown_metadata() {
        let json_body = br#"{
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "my-dep",
                "unknownMeta": "foo",
                "labels": {"app": "nginx"}
            }
        }"#;

        let path = ResourcePath {
            group: "apps".to_string(),
            version: "v1".to_string(),
            namespace: Some("default".to_string()),
            resource: "deployments".to_string(),
            subresource: None,
            name: None,
            trailing_slash: false,
        };

        let err = check_strict_json(json_body, &path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(r#"strict decoding error: unknown field "metadata.unknownMeta""#),
            "expected strict decoding error with unknown metadata, got: {msg}"
        );
    }

    #[test]
    fn test_yaml_duplicate_key_detection() {
        let yaml_body = b"apiVersion: example.com/v1\nkind: Noxu\nmetadata:\n  name: my-noxu\nspec:\n  unknown: uk1\n  foo: foo1\n  foo: foo2\n  cronSpec: \"* * * * */5\"\n";
        let err = decode_yaml(yaml_body, true).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("line 8: key \"foo\" already set in map"),
            "expected duplicate key error on line 8, got: {msg}"
        );
    }

    #[test]
    fn test_yaml_decode_valid() {
        let yaml_body =
            b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test-cm\ndata:\n  key: value\n";
        let val = decode_yaml(yaml_body, true).unwrap();
        assert_eq!(val["kind"], "ConfigMap");
        assert_eq!(val["metadata"]["name"], "test-cm");
        assert_eq!(val["data"]["key"], "value");
    }

    #[test]
    fn test_validation_directive_parsing() {
        assert_eq!(
            parse_validation_directive(Some("fieldValidation=Strict")),
            FieldValidationDirective::Strict
        );
        assert_eq!(
            parse_validation_directive(Some("fieldValidation=strict")),
            FieldValidationDirective::Strict
        );
        assert_eq!(
            parse_validation_directive(Some("fieldValidation=Warn")),
            FieldValidationDirective::Warn
        );
        assert_eq!(
            parse_validation_directive(Some("fieldValidation=warn")),
            FieldValidationDirective::Warn
        );
        assert_eq!(
            parse_validation_directive(Some("fieldValidation=Ignore")),
            FieldValidationDirective::Ignore
        );
        assert_eq!(
            parse_validation_directive(Some("fieldValidation=ignore")),
            FieldValidationDirective::Ignore
        );
        assert_eq!(
            parse_validation_directive(None),
            FieldValidationDirective::Ignore
        );
        assert_eq!(
            parse_validation_directive(Some("foo=bar")),
            FieldValidationDirective::Ignore
        );
    }

    #[test]
    fn test_warn_produces_299_warnings() {
        let json_body = br#"{
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "my-dep",
                "badMeta": "val"
            },
            "spec": {
                "badSpec": "val",
                "replicas": 1,
                "replicas": 2,
                "selector": {"matchLabels": {"app": "test"}},
                "template": {
                    "metadata": {"labels": {"app": "test"}, "badTmplMeta": "val"},
                    "spec": {"containers": [{"name": "c", "image": "img"}]}
                }
            }
        }"#;

        let path = ResourcePath {
            group: "apps".to_string(),
            version: "v1".to_string(),
            namespace: Some("default".to_string()),
            resource: "deployments".to_string(),
            subresource: None,
            name: None,
            trailing_slash: false,
        };

        let val = decode_body_with_directive(
            json_body,
            Some("application/json"),
            FieldValidationDirective::Warn,
            &path,
        )
        .unwrap();
        assert_eq!(val["metadata"]["name"], "my-dep");
        let warnings = take_warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains(r#"299 - "Unknown field \"metadata.badMeta\"""#))
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains(r#"299 - "Unknown field \"spec.badSpec\"""#))
        );
        assert!(warnings.iter().any(|w| {
            w.contains(r#"299 - "Unknown field \"spec.template.metadata.badTmplMeta\"""#)
        }));
        assert!(
            warnings
                .iter()
                .any(|w| w.contains(r#"299 - "duplicate field \"spec.replicas\"""#))
        );
    }

    #[test]
    fn test_ignore_strips_unknown_fields() {
        let json_body = br#"{
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "my-dep",
                "badMeta": "val",
                "labels": {"app": "test"}
            },
            "spec": {
                "badSpec": "val",
                "replicas": 1,
                "selector": {"matchLabels": {"app": "test"}},
                "template": {
                    "metadata": {"labels": {"app": "test"}, "badTmplMeta": "val"},
                    "spec": {"containers": [{"name": "c", "image": "img"}]}
                }
            }
        }"#;

        let path = ResourcePath {
            group: "apps".to_string(),
            version: "v1".to_string(),
            namespace: Some("default".to_string()),
            resource: "deployments".to_string(),
            subresource: None,
            name: None,
            trailing_slash: false,
        };

        let val = decode_body_with_directive(
            json_body,
            Some("application/json"),
            FieldValidationDirective::Ignore,
            &path,
        )
        .unwrap();
        assert_eq!(val["metadata"]["name"], "my-dep");
        assert_eq!(val["metadata"]["labels"]["app"], "test");
        assert_eq!(val["metadata"].get("badMeta"), None);
        assert_eq!(val["spec"].get("badSpec"), None);
        assert_eq!(val["spec"]["template"]["metadata"].get("badTmplMeta"), None);
        assert_eq!(val["spec"]["replicas"], 1);
        assert_eq!(take_warnings(), Vec::<String>::new());
    }

    #[test]
    fn test_crd_schema_validation_strict_warn_ignore() {
        let crd_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "properties": {
                        "cronSpec": { "type": "string" },
                        "image": { "type": "string" }
                    }
                }
            }
        });
        register_crd_schema("example.com", "noxus", crd_schema);

        let path = ResourcePath {
            group: "example.com".to_string(),
            version: "v1".to_string(),
            namespace: Some("default".to_string()),
            resource: "noxus".to_string(),
            subresource: None,
            name: None,
            trailing_slash: false,
        };

        let cr_json = br#"{
            "apiVersion": "example.com/v1",
            "kind": "Noxu",
            "metadata": { "name": "my-noxu", "extraMeta": "foo" },
            "spec": {
                "cronSpec": "* * * * *",
                "unknownSpec": "bad"
            }
        }"#;

        // 1. Strict rejects
        let err = decode_body_with_directive(
            cr_json,
            Some("application/json"),
            FieldValidationDirective::Strict,
            &path,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field \"metadata.extraMeta\""),
            "got: {msg}"
        );
        assert!(
            msg.contains("unknown field \"spec.unknownSpec\""),
            "got: {msg}"
        );

        // 2. Warn succeeds and emits 299 warnings
        let val = decode_body_with_directive(
            cr_json,
            Some("application/json"),
            FieldValidationDirective::Warn,
            &path,
        )
        .unwrap();
        assert_eq!(val["kind"], "Noxu");
        let warnings = take_warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains(r#"299 - "Unknown field \"metadata.extraMeta\"""#))
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains(r#"299 - "Unknown field \"spec.unknownSpec\"""#))
        );

        // 3. Ignore succeeds and strips unknown fields
        let val = decode_body_with_directive(
            cr_json,
            Some("application/json"),
            FieldValidationDirective::Ignore,
            &path,
        )
        .unwrap();
        assert_eq!(val["metadata"]["name"], "my-noxu");
        assert_eq!(val["metadata"].get("extraMeta"), None);
        assert_eq!(val["spec"]["cronSpec"], "* * * * *");
        assert_eq!(val["spec"].get("unknownSpec"), None);
        assert_eq!(take_warnings(), Vec::<String>::new());

        unregister_crd_schema("example.com", "noxus");
    }

    #[test]
    fn test_crd_without_schema_succeeds_with_unknown_fields() {
        let path = ResourcePath {
            group: "custom.io".to_string(),
            version: "v1".to_string(),
            namespace: Some("default".to_string()),
            resource: "foos".to_string(),
            subresource: None,
            name: None,
            trailing_slash: false,
        };

        let cr_json = br#"{
            "apiVersion": "custom.io/v1",
            "kind": "Foo",
            "metadata": { "name": "my-foo" },
            "spec": { "arbitraryField": 123 }
        }"#;

        let val = decode_body_with_directive(
            cr_json,
            Some("application/json"),
            FieldValidationDirective::Strict,
            &path,
        )
        .unwrap();
        assert_eq!(val["spec"]["arbitraryField"], 123);
    }

    #[test]
    fn test_crd_preserve_unknown_fields_still_rejects_duplicates_on_strict() {
        let crd_schema = serde_json::json!({
            "type": "object",
            "x-kubernetes-preserve-unknown-fields": true
        });
        register_crd_schema("example.com", "noxus2", crd_schema);

        let path = ResourcePath {
            group: "example.com".to_string(),
            version: "v1".to_string(),
            namespace: Some("default".to_string()),
            resource: "noxus2".to_string(),
            subresource: None,
            name: None,
            trailing_slash: false,
        };

        // Unknown fields should be accepted when preserve-unknown-fields is true
        let valid_cr = br#"{
            "apiVersion": "example.com/v1",
            "kind": "Noxu",
            "metadata": { "name": "my-noxu" },
            "spec": { "preservedField": "val" }
        }"#;
        let val = decode_body_with_directive(
            valid_cr,
            Some("application/json"),
            FieldValidationDirective::Strict,
            &path,
        )
        .unwrap();
        assert_eq!(val["spec"]["preservedField"], "val");

        // But duplicates must still be rejected on strict!
        let dup_cr = br#"{
            "apiVersion": "example.com/v1",
            "kind": "Noxu",
            "metadata": { "name": "my-noxu" },
            "spec": { "foo": 1, "foo": 2 }
        }"#;
        let err = decode_body_with_directive(
            dup_cr,
            Some("application/json"),
            FieldValidationDirective::Strict,
            &path,
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate field \"spec.foo\""));

        unregister_crd_schema("example.com", "noxus2");
    }

    #[test]
    fn test_yaml_warn_and_ignore() {
        let yaml_dup = b"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: dep\nspec:\n  replicas: 1\n  replicas: 2\n  unknownField: bad\n";
        let path = ResourcePath {
            group: "apps".to_string(),
            version: "v1".to_string(),
            namespace: Some("default".to_string()),
            resource: "deployments".to_string(),
            subresource: None,
            name: None,
            trailing_slash: false,
        };

        // Warn produces 299 warnings for unknown and duplicate fields
        let val = decode_yaml_with_directive(yaml_dup, FieldValidationDirective::Warn, Some(&path))
            .unwrap();
        assert_eq!(val["metadata"]["name"], "dep");
        let warnings = take_warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains(r#"299 - "duplicate field \"replicas\"""#))
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains(r#"299 - "Unknown field \"spec.unknownField\"""#))
        );

        // Ignore strips unknown field
        let val_ignore =
            decode_yaml_with_directive(yaml_dup, FieldValidationDirective::Ignore, Some(&path))
                .unwrap();
        assert_eq!(val_ignore["spec"]["replicas"], 2);
        assert_eq!(val_ignore["spec"].get("unknownField"), None);
        assert_eq!(take_warnings(), Vec::<String>::new());
    }

    #[test]
    fn test_decode_body_with_validation_picks_up_is_strict_context() {
        let path = ResourcePath {
            group: "apps".to_string(),
            version: "v1".to_string(),
            namespace: Some("default".to_string()),
            resource: "deployments".to_string(),
            subresource: None,
            name: None,
            trailing_slash: false,
        };

        let json_body = br#"{
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "dep", "unknown": "foo" }
        }"#;

        // 1. When is_strict is called with fieldValidation=Warn:
        assert!(!is_strict(Some("fieldValidation=Warn")));
        let val =
            decode_body_with_validation(json_body, Some("application/json"), false, &path).unwrap();
        assert_eq!(val["metadata"]["name"], "dep");
        let warnings = take_warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains(r#"299 - "Unknown field \"metadata.unknown\"""#))
        );

        // 2. When is_strict is called with fieldValidation=Strict:
        assert!(is_strict(Some("fieldValidation=Strict")));
        let err = decode_body_with_validation(json_body, Some("application/json"), true, &path)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("strict decoding error: unknown field \"metadata.unknown\"")
        );

        // 3. When is_strict is called with fieldValidation=Ignore:
        assert!(!is_strict(Some("fieldValidation=Ignore")));
        let val =
            decode_body_with_validation(json_body, Some("application/json"), false, &path).unwrap();
        assert_eq!(val["metadata"]["name"], "dep");
        assert_eq!(val["metadata"].get("unknown"), None);
        assert_eq!(take_warnings(), Vec::<String>::new());
    }
}
