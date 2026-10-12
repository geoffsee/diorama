//! Prometheus and `OpenMetrics` text exposition formats and scrape parser.

use std::collections::BTreeMap;

/// Metric type according to Prometheus and `OpenMetrics` specifications.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricType {
    Gauge,
    Counter,
    Info,
}

impl MetricType {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gauge => "gauge",
            Self::Counter => "counter",
            Self::Info => "info",
        }
    }
}

/// A single measured sample with key-value labels and a numeric value.
#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    pub labels: Vec<(String, String)>,
    pub value: f64,
}

impl Sample {
    #[must_use]
    pub fn new(labels: Vec<(&str, &str)>, value: f64) -> Self {
        Self {
            labels: labels
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            value,
        }
    }

    #[must_use]
    pub fn without_labels(value: f64) -> Self {
        Self {
            labels: Vec::new(),
            value,
        }
    }
}

/// A family of metrics sharing a name, help documentation, and type.
#[derive(Clone, Debug, PartialEq)]
pub struct MetricFamily {
    pub name: String,
    pub help: String,
    pub metric_type: MetricType,
    pub samples: Vec<Sample>,
}

impl MetricFamily {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        help: impl Into<String>,
        metric_type: MetricType,
        samples: Vec<Sample>,
    ) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            metric_type,
            samples,
        }
    }
}

/// Escapes a label value according to Prometheus/`OpenMetrics` text exposition rules.
fn escape_label_value(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
}

/// Escapes a help string according to Prometheus/`OpenMetrics` text exposition rules.
fn escape_help_string(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
}

/// Formats a float value cleanly (integers without decimal points when whole).
#[allow(clippy::cast_possible_truncation)]
fn format_sample_value(val: f64) -> String {
    if val.is_nan() {
        "NaN".to_string()
    } else if val.is_infinite() {
        if val > 0.0 {
            "+Inf".to_string()
        } else {
            "-Inf".to_string()
        }
    } else if val.fract() == 0.0 && val.abs() <= 9_007_199_254_740_992.0 {
        format!("{}", val as i64)
    } else {
        format!("{val}")
    }
}

fn format_sample(sample: &Sample, name: &str, out: &mut String) {
    out.push_str(name);
    if !sample.labels.is_empty() {
        out.push('{');
        for (idx, (k, v)) in sample.labels.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push_str(k);
            out.push_str("=\"");
            escape_label_value(v, out);
            out.push('"');
        }
        out.push('}');
    }
    out.push(' ');
    out.push_str(&format_sample_value(sample.value));
    out.push('\n');
}

/// Encodes metric families into Prometheus text exposition format (version 0.0.4).
#[must_use]
pub fn encode_prometheus(families: &[MetricFamily]) -> String {
    let mut out = String::new();
    for family in families {
        out.push_str("# HELP ");
        out.push_str(&family.name);
        out.push(' ');
        escape_help_string(&family.help, &mut out);
        out.push('\n');

        out.push_str("# TYPE ");
        out.push_str(&family.name);
        out.push(' ');
        out.push_str(family.metric_type.as_str());
        out.push('\n');

        for sample in &family.samples {
            format_sample(sample, &family.name, &mut out);
        }
    }
    out
}

/// Encodes metric families into `OpenMetrics` text exposition format (version 1.0.0).
#[must_use]
pub fn encode_openmetrics(families: &[MetricFamily]) -> String {
    let mut out = encode_prometheus(families);
    out.push_str("# EOF\n");
    out
}

/// A parsed metric sample extracted from a Prometheus/`OpenMetrics` scrape.
#[derive(Clone, Debug, PartialEq)]
pub struct ParsedSample {
    pub labels: BTreeMap<String, String>,
    pub value: f64,
}

/// A parsed scrape response mapping metric names to parsed samples.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ParsedScrape {
    pub metrics: BTreeMap<String, Vec<ParsedSample>>,
}

impl ParsedScrape {
    #[must_use]
    pub fn get_first_value(&self, name: &str) -> Option<f64> {
        self.metrics.get(name)?.first().map(|s| s.value)
    }

    #[must_use]
    pub fn get_sample(
        &self,
        name: &str,
        label_key: &str,
        label_val: &str,
    ) -> Option<&ParsedSample> {
        self.metrics
            .get(name)?
            .iter()
            .find(|s| s.labels.get(label_key).is_some_and(|v| v == label_val))
    }
}

/// Parses a Prometheus or `OpenMetrics` scrape text output.
pub fn parse_scrape(input: &str) -> Result<ParsedScrape, String> {
    let mut result = ParsedScrape::default();
    for (line_num, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (name_and_labels, value_str) = line
            .rsplit_once(' ')
            .ok_or_else(|| format!("line {}: missing value delimiter", line_num + 1))?;

        let value: f64 = value_str
            .parse()
            .map_err(|e| format!("line {}: invalid float '{}': {e}", line_num + 1, value_str))?;

        let (name, labels) = if let Some(brace_start) = name_and_labels.find('{') {
            let brace_end = name_and_labels
                .rfind('}')
                .ok_or_else(|| format!("line {}: unmatched '{{'", line_num + 1))?;
            let name = &name_and_labels[..brace_start];
            let label_str = &name_and_labels[brace_start + 1..brace_end];
            let parsed_labels = parse_label_pairs(label_str, line_num + 1)?;
            (name.to_string(), parsed_labels)
        } else {
            (name_and_labels.to_string(), BTreeMap::new())
        };

        result
            .metrics
            .entry(name)
            .or_default()
            .push(ParsedSample { labels, value });
    }
    Ok(result)
}

fn parse_quoted_value<I>(
    chars: &mut std::iter::Peekable<I>,
    line_num: usize,
) -> Result<String, String>
where
    I: Iterator<Item = char>,
{
    if chars.next() != Some('"') {
        return Err(format!("line {line_num}: expected '\"' after '='"));
    }
    let mut val = String::new();
    let mut escaped = false;
    for c in chars.by_ref() {
        if escaped {
            match c {
                'n' => val.push('\n'),
                '\\' => val.push('\\'),
                '"' => val.push('"'),
                other => {
                    val.push('\\');
                    val.push(other);
                },
            }
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return Ok(val);
        } else {
            val.push(c);
        }
    }
    Err(format!("line {line_num}: unterminated quoted string"))
}

fn parse_label_pairs(input: &str, line_num: usize) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    if input.trim().is_empty() {
        return Ok(map);
    }

    let mut chars = input.chars().peekable();
    while chars.peek().is_some() {
        // Skip leading whitespace / commas
        while let Some(&c) = chars.peek() {
            if c == ' ' || c == ',' {
                chars.next();
            } else {
                break;
            }
        }
        if chars.peek().is_none() {
            break;
        }

        // Read key
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' {
                chars.next();
                break;
            }
            key.push(c);
            chars.next();
        }
        let key = key.trim().to_string();

        let val = parse_quoted_value(&mut chars, line_num)?;
        map.insert(key, val);
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_encode_and_parse_prometheus() {
        let families = vec![
            MetricFamily::new(
                "kubesolo_build_info",
                "KubeSolo build information",
                MetricType::Gauge,
                vec![Sample::new(
                    vec![("version", "0.1.0"), ("arch", "arm64")],
                    1.0,
                )],
            ),
            MetricFamily::new(
                "kubesolo_uptime_seconds",
                "Uptime in seconds",
                MetricType::Gauge,
                vec![Sample::without_labels(42.0)],
            ),
        ];

        let encoded = encode_prometheus(&families);
        assert!(encoded.contains("# HELP kubesolo_build_info KubeSolo build information\n"));
        assert!(encoded.contains("# TYPE kubesolo_build_info gauge\n"));
        assert!(encoded.contains("kubesolo_build_info{version=\"0.1.0\",arch=\"arm64\"} 1\n"));
        assert!(encoded.contains("kubesolo_uptime_seconds 42\n"));

        let parsed = parse_scrape(&encoded).expect("parse scrape");
        assert_eq!(
            parsed.get_first_value("kubesolo_uptime_seconds"),
            Some(42.0)
        );
        let sample = parsed
            .get_sample("kubesolo_build_info", "version", "0.1.0")
            .expect("sample found");
        assert_eq!(sample.labels.get("arch").map(String::as_str), Some("arm64"));
        assert_eq!(sample.value, 1.0);
    }

    #[test]
    fn test_encode_openmetrics_eof() {
        let families = vec![MetricFamily::new(
            "kubesolo_uptime_seconds",
            "Uptime in seconds",
            MetricType::Gauge,
            vec![Sample::without_labels(10.0)],
        )];
        let om = encode_openmetrics(&families);
        assert!(om.ends_with("# EOF\n"));
    }
}
