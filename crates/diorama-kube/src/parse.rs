use std::collections::{BTreeMap, BTreeSet};

use diorama_config::{ExplicitFlags, FIELDS, FieldType, INPUT_BINDINGS};

pub(crate) struct Parsed {
    pub flags: ExplicitFlags,
    pub config: String,
    pub version: bool,
    pub print: bool,
    pub full: bool,
}
pub(crate) enum ParseResult {
    Help,
    Parsed(Parsed),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Bool,
    Integer,
    Text,
}
fn definition(name: &str) -> Option<(&str, Kind)> {
    if matches!(name, "version" | "help" | "print-config" | "full") {
        return Some((name, Kind::Bool));
    }
    if name == "config" {
        return Some((name, Kind::Text));
    }
    let binding = INPUT_BINDINGS
        .iter()
        .find(|binding| binding.flag == Some(name))?;
    let field = FIELDS.iter().find(|field| field.path == binding.path)?;
    Some((
        name,
        match field.kind {
            FieldType::Boolean | FieldType::OptionalBool => Kind::Bool,
            FieldType::Integer => Kind::Integer,
            _ => Kind::Text,
        },
    ))
}
fn boolean(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Some(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Some(false),
        _ => None,
    }
}
fn primitive(kind: Kind, value: &str) -> Result<(), String> {
    let valid = match kind {
        Kind::Bool => boolean(value).is_some(),
        Kind::Integer => value.parse::<i64>().is_ok(),
        Kind::Text => true,
    };
    if valid {
        Ok(())
    } else {
        Err(format!("invalid value {value:?}"))
    }
}

type Occurrences = Vec<(String, Kind, String)>;

fn tokenize(args: &[String]) -> (Occurrences, Option<String>) {
    let mut occurrences = Vec::new();
    let mut grammar_error = None;
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        index += 1;
        if token == "--" {
            if index < args.len() {
                grammar_error = Some(format!("unexpected {}", args[index]));
            }
            break;
        }
        let spelling = if token == "-v" {
            "version"
        } else if let Some(long) = token.strip_prefix("--") {
            long
        } else {
            grammar_error = Some(if token.starts_with('-') && token != "-" {
                format!("unknown short flag '{token}'")
            } else {
                format!("unexpected {token}")
            });
            break;
        };
        let (name, attached) = spelling
            .split_once('=')
            .map_or((spelling, None), |(name, value)| (name, Some(value)));
        let (canonical, inverted) = if definition(name).is_some() {
            (name, false)
        } else {
            (
                name.strip_prefix("no-").unwrap_or(name),
                name.starts_with("no-"),
            )
        };
        let Some((_, kind)) = definition(canonical) else {
            grammar_error = Some(format!("unknown long flag '--{name}'"));
            break;
        };
        if inverted && kind != Kind::Bool {
            grammar_error = Some(format!("unknown long flag '--{name}'"));
            break;
        }
        let value = if kind == Kind::Bool {
            occurrences.push((canonical.to_owned(), kind, (!inverted).to_string()));
            if let Some(value) = attached {
                grammar_error = Some(format!("unexpected {value}"));
                break;
            }
            continue;
        } else if let Some(value) = attached {
            value.to_owned()
        } else {
            let Some(value) = args.get(index).filter(|value| !value.starts_with('-')) else {
                grammar_error = Some(format!("expected argument for flag '--{name}'"));
                break;
            };
            index += 1;
            value.clone()
        };
        occurrences.push((canonical.to_owned(), kind, value));
    }
    (occurrences, grammar_error)
}

pub(crate) fn parse(
    args: &[String],
    env: &BTreeMap<String, String>,
) -> Result<ParseResult, String> {
    let (occurrences, grammar_error) = tokenize(args);
    let skip_defaults = occurrences
        .iter()
        .any(|(name, _, _)| name == "help" || name == "version");
    let explicit: BTreeSet<_> = occurrences
        .iter()
        .map(|(name, _, _)| name.as_str())
        .collect();
    let mut config = String::new();
    let mut full = false;
    if !skip_defaults {
        config = env
            .get("KUBESOLO_CONFIG")
            .filter(|value| !value.is_empty())
            .cloned()
            .unwrap_or_else(|| "/etc/diorama/config.yaml".into());
        for binding in INPUT_BINDINGS {
            if let Some(flag) = binding.flag
                && !explicit.contains(flag)
                && let Some(value) = env
                    .get(binding.environment)
                    .filter(|value| !value.is_empty())
                && let Some((_, kind)) = definition(flag)
            {
                primitive(kind, value)?;
            }
        }
        if !explicit.contains("full")
            && let Some(value) = env.get("KUBESOLO_FULL").filter(|value| !value.is_empty())
        {
            full = boolean(value).ok_or_else(|| format!("invalid value {value:?}"))?;
        }
    }
    let mut values = BTreeMap::new();
    let mut conversion_error = None;
    for (name, kind, value) in &occurrences {
        if values.contains_key(name) {
            conversion_error = Some(format!("flag '{name}' cannot be repeated"));
            break;
        }
        if let Err(error) = primitive(*kind, value) {
            conversion_error = Some(error);
            break;
        }
        values.insert(name.clone(), value.clone());
    }
    if let Some(error) = grammar_error {
        return Err(error);
    }
    if occurrences.iter().any(|(name, _, _)| name == "help") {
        return Ok(ParseResult::Help);
    }
    if let Some(error) = conversion_error {
        return Err(error);
    }
    if let Some(value) = values.remove("config") {
        config = value;
    }
    if let Some(value) = values.remove("full") {
        full = value == "true";
    }
    let version = values
        .remove("version")
        .is_some_and(|value| value == "true");
    let print = values
        .remove("print-config")
        .is_some_and(|value| value == "true");
    Ok(ParseResult::Parsed(Parsed {
        flags: ExplicitFlags(values),
        config,
        version,
        print,
        full,
    }))
}
