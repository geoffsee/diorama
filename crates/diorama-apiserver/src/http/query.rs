//! URL query parsing with percent-decoding.

use std::collections::BTreeMap;

/// Parses `a=b&c=d%3De` into a map; later keys win. Keys and values are decoded.
pub(crate) fn parse(query: Option<&str>) -> BTreeMap<String, String> {
    query
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(key), decode(value))
        })
        .collect()
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => out.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let h1 = bytes[index + 1];
                let h2 = bytes[index + 2];
                match (hex_val(h1), hex_val(h2)) {
                    (Some(v1), Some(v2)) => {
                        out.push((v1 << 4) | v2);
                        index += 2;
                    },
                    _ => out.push(b'%'),
                }
            },
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn decodes_percent_and_plus() {
        let params = parse(Some(
            "watch=true&fieldSelector=metadata.name%3Dhello&resourceVersion=42&x=a+b&bad=%zz",
        ));
        assert_eq!(params["watch"], "true");
        assert_eq!(params["fieldSelector"], "metadata.name=hello");
        assert_eq!(params["resourceVersion"], "42");
        assert_eq!(params["x"], "a b");
        assert_eq!(params["bad"], "%zz");
        assert!(parse(None).is_empty());
    }

    #[test]
    fn decodes_non_ascii_utf8() {
        let params = parse(Some("greeting=你好%20世界&emoji=🚀%2B✨"));
        assert_eq!(params["greeting"], "你好 世界");
        assert_eq!(params["emoji"], "🚀+✨");
    }
}
