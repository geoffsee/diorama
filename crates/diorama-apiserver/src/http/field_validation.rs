use std::collections::{BTreeMap, BTreeSet, HashSet};

use saphyr_parser::{BufferedInput, Event, Parser, ScalarStyle, Span};
use serde_json::Value;

use crate::error::ApiserverError;
use crate::http::query;
use crate::http::route::ResourcePath;

/// Returns true if query parameter `fieldValidation` is present and equals "Strict" (case-insensitive).
#[must_use]
pub(crate) fn is_strict(query: Option<&str>) -> bool {
    query::parse(query)
        .get("fieldValidation")
        .is_some_and(|v| v.eq_ignore_ascii_case("strict"))
}

/// Checks strict decoding constraints on a JSON request payload.
/// Detects duplicate keys at any depth and unknown fields under `metadata` or `spec`.
pub(crate) fn check_strict_json(body: &[u8], path: &ResourcePath) -> Result<(), ApiserverError> {
    let Ok(text) = std::str::from_utf8(body) else {
        return Err(ApiserverError::BadRequest {
            message: "request body is not valid UTF-8".to_string(),
        });
    };
    let kind = kind_from_path(path);
    let mut checker = JsonStrictChecker::new(text, kind);
    checker.check()
}

/// Decodes request body bytes as JSON or YAML, enforcing strict field validation rules
/// when `is_strict` is true.
pub(crate) fn decode_body_with_validation(
    body: &[u8],
    content_type: Option<&str>,
    is_strict: bool,
    path: &ResourcePath,
) -> Result<Value, ApiserverError> {
    if body.is_empty() {
        return Ok(Value::Null);
    }
    let is_yaml = content_type.is_some_and(|ct| ct.contains("yaml") || ct.contains("apply-patch"));
    let trimmed = body
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .copied()
        .collect::<Vec<u8>>();
    let looks_like_json = trimmed.first() == Some(&b'{') || trimmed.first() == Some(&b'[');

    if !is_yaml && looks_like_json {
        if is_strict {
            check_strict_json(body, path)?;
        }
        serde_json::from_slice(body).map_err(|err| ApiserverError::BadRequest {
            message: format!("request body is not valid JSON: {err}"),
        })
    } else {
        decode_yaml(body, is_strict)
    }
}

/// Decodes YAML into `serde_json::Value`, detecting duplicate keys when `is_strict` is true.
pub(crate) fn decode_yaml(body: &[u8], is_strict: bool) -> Result<Value, ApiserverError> {
    let text = std::str::from_utf8(body).map_err(|err| ApiserverError::BadRequest {
        message: format!("request body is not valid UTF-8: {err}"),
    })?;
    let mut parser = Parser::new(BufferedInput::new(text.chars()));
    let mut anchors = BTreeMap::new();
    let mut root_val = Value::Null;

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
                root_val = decode_yaml_node(&mut parser, event, span, &mut anchors, is_strict, 0)?;
                break;
            },
        }
    }
    Ok(root_val)
}

fn decode_yaml_sequence<'a>(
    parser: &mut Parser<'a, BufferedInput<std::str::Chars<'a>>>,
    anchors: &mut BTreeMap<usize, Value>,
    is_strict: bool,
    depth: usize,
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
        list.push(decode_yaml_node(
            parser,
            next_event,
            next_span,
            anchors,
            is_strict,
            depth + 1,
        )?);
    }
    Ok(Value::Array(list))
}

fn decode_yaml_mapping<'a>(
    parser: &mut Parser<'a, BufferedInput<std::str::Chars<'a>>>,
    anchors: &mut BTreeMap<usize, Value>,
    is_strict: bool,
    depth: usize,
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
        if is_strict && !seen_keys.insert(key_str.clone()) {
            return Err(ApiserverError::BadRequest {
                message: format!(
                    "error unmarshaling JSON: while decoding JSON: line {}: key \"{}\" already set in map",
                    key_span.start.line(),
                    key_str
                ),
            });
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
        let val = decode_yaml_node(parser, val_event, val_span, anchors, is_strict, depth + 1)?;
        map.insert(key_str, val);
    }
    Ok(Value::Object(map))
}

fn decode_yaml_node<'a>(
    parser: &mut Parser<'a, BufferedInput<std::str::Chars<'a>>>,
    event: Event<'a>,
    _span: Span,
    anchors: &mut BTreeMap<usize, Value>,
    is_strict: bool,
    depth: usize,
) -> Result<Value, ApiserverError> {
    if depth > 128 {
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
            let seq = decode_yaml_sequence(parser, anchors, is_strict, depth)?;
            (anchor, seq)
        },
        Event::MappingStart(anchor, _) => {
            let map = decode_yaml_mapping(parser, anchors, is_strict, depth)?;
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
    unknown_fields: Vec<String>,
    duplicate_fields: Vec<String>,
}

impl<'a> JsonStrictChecker<'a> {
    fn new(src: &'a str, kind: Option<&'a str>) -> Self {
        Self {
            chars: src.char_indices().peekable(),
            kind,
            unknown_fields: Vec::new(),
            duplicate_fields: Vec::new(),
        }
    }

    fn check(&mut self) -> Result<(), ApiserverError> {
        self.parse_value("")?;
        if self.unknown_fields.is_empty() && self.duplicate_fields.is_empty() {
            Ok(())
        } else {
            let mut all_errors = std::mem::take(&mut self.unknown_fields);
            all_errors.extend(std::mem::take(&mut self.duplicate_fields));
            Err(ApiserverError::BadRequest {
                message: format!("strict decoding error: {}", all_errors.join(", ")),
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
                // Primitives (number, boolean, null)
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
        self.chars.next(); // consume '['
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
        self.chars.next(); // consume '{'
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
            let is_unknown = (prefix == "metadata" && !is_known_metadata_key(&key))
                || (prefix == "spec" && !is_known_spec_key(self.kind, &key));
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
        _ => None,
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
            namespace: Some("default".to_string()),
            resource: "deployments".to_string(),
            subresource: None,
            name: None,
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
            namespace: Some("default".to_string()),
            resource: "deployments".to_string(),
            subresource: None,
            name: None,
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
}
