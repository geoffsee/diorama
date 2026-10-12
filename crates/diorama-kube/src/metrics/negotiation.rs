//! Select one of the supported exposition formats using HTTP Accept precedence.

use http::{HeaderMap, header};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Exposition {
    Prometheus,
    OpenMetrics,
}

impl Exposition {
    pub(super) fn content_type(self) -> &'static str {
        match self {
            Self::Prometheus => "text/plain; version=0.0.4; charset=utf-8",
            Self::OpenMetrics => "application/openmetrics-text; version=1.0.0; charset=utf-8",
        }
    }

    fn media_type(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Prometheus => ("text", "plain", "0.0.4"),
            Self::OpenMetrics => ("application", "openmetrics-text", "1.0.0"),
        }
    }
}

// Integer thousandths avoid floating-point comparisons and reject invalid q values.
fn quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match whole {
        "1" if fraction.bytes().all(|byte| byte == b'0') => Some(1000),
        "0" => Some(if fraction.is_empty() {
            0
        } else {
            fraction.parse::<u16>().ok()? * 10_u16.pow(3 - u32::try_from(fraction.len()).ok()?)
        }),
        _ => None,
    }
}

fn match_range(range: &str, format: Exposition) -> Option<(u8, usize, u16)> {
    let mut parts = range.split(';');
    let (kind, subtype) = parts.next()?.trim().split_once('/')?;
    let (wanted_kind, wanted_subtype, version) = format.media_type();
    let specificity = if kind == "*" && subtype == "*" {
        0
    } else if kind.eq_ignore_ascii_case(wanted_kind) && subtype == "*" {
        1
    } else if kind.eq_ignore_ascii_case(wanted_kind) && subtype.eq_ignore_ascii_case(wanted_subtype)
    {
        2
    } else {
        return None;
    };
    let mut weight = 1000;
    let mut parameters = 0;
    let mut seen_quality = false;
    for part in parts {
        let (name, value) = part.trim().split_once('=')?;
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("q") {
            if seen_quality {
                return None;
            }
            weight = quality(value)?;
            seen_quality = true;
        } else if !seen_quality {
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            if name.eq_ignore_ascii_case("version") && value == version
                || name.eq_ignore_ascii_case("charset") && value.eq_ignore_ascii_case("utf-8")
            {
                parameters += 1;
            } else {
                return None;
            }
        }
    }
    Some((specificity, parameters, weight))
}

pub(super) fn negotiate(headers: &HeaderMap) -> Option<Exposition> {
    if !headers.contains_key(header::ACCEPT) {
        return Some(Exposition::Prometheus);
    }
    let mut candidates = Vec::new();
    for format in [Exposition::Prometheus, Exposition::OpenMetrics] {
        // The most specific matching media range determines a representation's
        // quality. An explicit q=0 must win over a less specific wildcard.
        let matched = headers
            .get_all(header::ACCEPT)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .filter_map(|range| match_range(range, format))
            .max();
        if let Some((specificity, parameters, weight)) = matched.filter(|(_, _, q)| *q > 0) {
            // Keep the legacy plain-text default for */*, prefer OpenMetrics
            // when both explicitly named representations are equally acceptable.
            let preferred = if specificity == 0 {
                format == Exposition::Prometheus
            } else {
                format == Exposition::OpenMetrics
            };
            candidates.push(((weight, specificity, parameters, preferred), format));
        }
    }
    candidates
        .into_iter()
        .max_by_key(|(score, _)| *score)
        .map(|(_, format)| format)
}
