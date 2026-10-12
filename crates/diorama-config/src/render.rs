use crate::{Config, ConfigError, ErrorKind};
use serde_json::Value;
use std::fmt::Write;

fn failure(message: impl Into<String>) -> ConfigError {
    ConfigError {
        kind: ErrorKind::Type,
        path: String::new(),
        message: message.into(),
    }
}
/// Render the effective legacy document, including secrets, without IO.
/// Like the reference print command, this is deliberately not a redacted API view.
pub fn render_effective_yaml(config: &Config) -> Result<String, ConfigError> {
    let mut value = serde_json::to_value(config).map_err(|e| failure(e.to_string()))?;
    for path in [
        "kubernetes.nodeName",
        "runtime.containerMode",
        "kubernetes.apiServer.extraSANs",
        "kubernetes.kubelet.systemReserved",
        "kubernetes.kubelet.cpuManager.policyOptions",
    ] {
        let (parent, key) = path.rsplit_once('.').unwrap_or(("", path));
        let pointer = if parent.is_empty() {
            String::new()
        } else {
            format!("/{}", parent.replace('.', "/"))
        };
        if let Some(map) = value.pointer_mut(&pointer).and_then(Value::as_object_mut)
            && map.get(key).is_some_and(|v| {
                v.is_null()
                    || v.as_str() == Some("")
                    || v.as_array().is_some_and(Vec::is_empty)
                    || v.as_object().is_some_and(serde_json::Map::is_empty)
            })
        {
            map.remove(key);
        }
    }
    let mut out = String::new();
    mapping(&value, 0, &mut out)?;
    Ok(out)
}
fn mapping(value: &Value, indent: usize, out: &mut String) -> Result<(), ConfigError> {
    let map = value
        .as_object()
        .ok_or_else(|| failure("expected document mapping"))?;
    for (key, value) in map {
        out.push_str(&" ".repeat(indent));
        out.push_str(&inline_string(key)?);
        out.push(':');
        emit(value, indent, out)?;
    }
    Ok(())
}
fn emit(value: &Value, indent: usize, out: &mut String) -> Result<(), ConfigError> {
    match value {
        Value::Object(map) if !map.is_empty() => {
            out.push('\n');
            mapping(value, indent + 2, out)?;
        },
        Value::Array(values) if !values.is_empty() => {
            out.push('\n');
            for value in values {
                out.push_str(&" ".repeat(indent));
                out.push('-');
                emit(value, indent, out)?;
            }
        },
        Value::String(text) if literal_allowed(text) => {
            let trailing = text
                .chars()
                .rev()
                .take_while(|c| matches!(c, '\n' | '\u{2028}' | '\u{2029}'))
                .count();
            out.push_str(" |");
            if text.starts_with([' ', '\n', '\u{2028}', '\u{2029}']) {
                out.push('2');
            }
            match trailing {
                _ if text.chars().all(|c| c == '\n') => out.push('+'),
                0 => out.push('-'),
                1 => (),
                _ => out.push('+'),
            }
            out.push('\n');
            for line in text.split_terminator('\n') {
                if !line.is_empty() {
                    out.push_str(&" ".repeat(indent + 2));
                    out.push_str(line);
                }
                out.push('\n');
            }
        },
        _ => {
            out.push(' ');
            match value {
                Value::String(text) => push_inline(out, &inline_string(text)?, indent + 2),
                Value::Object(_) => out.push_str("{}"),
                Value::Array(_) => out.push_str("[]"),
                _ => out.push_str(&value.to_string()),
            }
            out.push('\n');
        },
    }
    Ok(())
}
fn push_inline(out: &mut String, encoded: &str, continuation: usize) {
    let mut column = out
        .rsplit('\n')
        .next()
        .map_or(0, |line| line.chars().count());
    let characters: Vec<_> = encoded.chars().collect();
    let quoted = encoded.starts_with(['\'', '"']);
    let mut previous_space = false;
    for (index, ch) in characters.iter().copied().enumerate() {
        let followed_space = characters.get(index + 1) == Some(&' ');
        if ch == ' '
            && !previous_space
            && !followed_space
            && column > 80
            && index > 0
            && index + 1 + usize::from(quoted) < characters.len()
        {
            out.push('\n');
            out.push_str(&" ".repeat(continuation));
            column = continuation;
        } else {
            out.push(ch);
            column += 1;
        }
        previous_space = ch == ' ';
    }
}
fn special(c: char) -> bool {
    let n = u32::from(c);
    (c.is_control() && c != '\n') || n > 0xffff || matches!(n, 0xfeff | 0xfffe | 0xffff)
}
fn literal_allowed(text: &str) -> bool {
    text.contains('\n')
        && !text.contains(['\u{85}', '\u{2028}', '\u{2029}'])
        && !text.ends_with(' ')
        && !text.contains(" \n")
        && !text.contains(" \u{2028}")
        && !text.contains(" \u{2029}")
        && !text.chars().any(special)
}
fn double_quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '\u{85}' => out.push_str("\\N"),
            '\u{2028}' => out.push_str("\\L"),
            '\u{2029}' => out.push_str("\\P"),
            '\0' => out.push_str("\\0"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\x0b' => out.push_str("\\v"),
            '\x0c' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '\x1b' => out.push_str("\\e"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if special(c) => {
                let n = u32::from(c);
                if n <= 0xff {
                    let _ = write!(out, "\\x{n:02X}");
                } else if n <= 0xffff {
                    let _ = write!(out, "\\u{n:04X}");
                } else {
                    let _ = write!(out, "\\U{n:08X}");
                }
            },
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
fn timestamp(text: &str) -> Result<bool, ConfigError> {
    let regex = regex::Regex::new(r"^([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})(?:([Tt ])([0-9]{2}):([0-9]{1,2}):([0-9]{1,2})(?:[.,][0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})?)?$").map_err(|e| failure(e.to_string()))?;
    let Some(parts) = regex.captures(text) else {
        return Ok(false);
    };
    let number = |index: usize| {
        parts
            .get(index)
            .and_then(|v| v.as_str().parse::<u32>().ok())
            .unwrap_or(0)
    };
    let (year, month, day) = (number(1), number(2), number(3));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        },
        2 => 28,
        _ => 0,
    };
    if day == 0 || day > days || number(5) > 23 || number(6) > 59 || number(7) > 59 {
        return Ok(false);
    }
    if let Some(separator) = parts.get(4) {
        let zone = parts.get(8);
        if (separator.as_str() == " ") != zone.is_none() {
            return Ok(false);
        }
        if let Some(zone) = zone
            && zone.as_str() != "Z"
        {
            let value = zone.as_str();
            let hour = value[1..3].parse::<u32>().unwrap_or(99);
            let minute = value[4..6].parse::<u32>().unwrap_or(99);
            if hour > 24 || minute > 60 {
                return Ok(false);
            }
        }
    }
    Ok(true)
}
fn inline_string(text: &str) -> Result<String, ConfigError> {
    // YAML 1.1 implicit resolution is needed even when the desired Rust type is String.
    let resolved = crate::decode::scalar(text, saphyr_parser::ScalarStyle::Plain, None);
    let base60 = regex::Regex::new(r"^[+-]?[0-9]+(?::[0-5]?[0-9])+(?:\.[0-9]*)?$")
        .map_err(|e| failure(e.to_string()))?
        .is_match(text);
    if text.contains(['\u{85}', '\u{2028}', '\u{2029}'])
        || text.is_empty()
        || !matches!(resolved, Ok(Value::String(_)))
        || base60
        || timestamp(text)?
        || (text.contains("\u{2028} ")
            || text.contains("\u{2029} ")
            || text.contains(" \u{2028}")
            || text.contains(" \u{2029}"))
        || text.chars().any(|c| special(c) || c == '\n')
    {
        return Ok(double_quoted(text));
    }
    let mut chars = text.chars().peekable();
    let mut previous_blank = true;
    let mut unsafe_plain = text.contains(['\u{2028}', '\u{2029}'])
        || text.starts_with("---")
        || text.starts_with("...")
        || text.starts_with(' ')
        || text.ends_with(' ');
    for (index, ch) in
        std::iter::from_fn(|| chars.next().map(|c| (c, chars.peek().copied()))).enumerate()
    {
        let (ch, next) = ch;
        let next_blank = next.is_none_or(|c| c == ' ' || c == '\t');
        if (index == 0 && "#,[]{}&*!|>'\"%@`".contains(ch))
            || (index == 0 && "?-".contains(ch) && next_blank)
            || (ch == ':' && next_blank)
            || (ch == '#' && previous_blank)
        {
            unsafe_plain = true;
        }
        previous_blank = ch == ' ' || ch == '\t';
    }
    Ok(if unsafe_plain {
        format!("'{}'", text.replace('\'', "''"))
    } else {
        text.into()
    })
}
