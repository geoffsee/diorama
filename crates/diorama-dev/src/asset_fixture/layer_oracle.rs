//! Independent synthetic layer oracle. Never calls the production asset validator.
use super::archive::{Entry, gzip, pack, ungzip, unpack};
use super::common::{Result, array, check, fields, json, sha256, strict, string, unb64};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::io::Read;

pub(super) const LIMIT: usize = 1024 * 1024;
pub(super) const POSITIVES: [&str; 4] = ["gzip", "gzip-concat", "zstd", "zstd-concat"];
pub(super) const NAMES: [&str; 12] = [
    "gzip",
    "gzip-concat",
    "zstd",
    "zstd-concat",
    "gzip-crc",
    "zstd-checksum",
    "gzip-truncated",
    "zstd-truncated",
    "wrong-diffid",
    "outer-crc",
    "decoded-limit",
    "ordered-limit",
];
const ERRORS: [&str; 8] = [
    "policy:Layer(Checksum)",
    "policy:Layer(Decoder)",
    "policy:Layer(Truncated)",
    "policy:Layer(Truncated)",
    "policy:Layer(DiffId)",
    "decode",
    "policy:Layer(DecodedLimit)",
    "policy:Layer(OrderedLimit)",
];
pub(super) type Cases = Vec<(String, Vec<u8>)>;

pub(super) fn observation_schema(row: &Value) -> Result<()> {
    fields(
        row,
        &[
            "case",
            "archive_sha256",
            "observed",
            "retained_budget",
            "retry_retained_budget",
        ],
    )?;
    string(&row["case"])?;
    string(&row["archive_sha256"])?;
    check(
        row["retained_budget"].is_boolean() && row["retry_retained_budget"].is_boolean(),
        "retention bool types",
    )?;
    let observed = &row["observed"];
    if string(&observed["status"])? != "ok" {
        return fields(observed, &["status"]);
    }
    fields(
        observed,
        &["status", "outer_bytes", "outer_sha256", "layers"],
    )?;
    positive(&observed["outer_bytes"])?;
    string(&observed["outer_sha256"])?;
    for layer in array(&observed["layers"])? {
        fields(
            layer,
            &[
                "stored_sha256",
                "stored_bytes",
                "diff_id",
                "decoded_bytes",
                "codec",
                "frames",
            ],
        )?;
        for key in ["stored_bytes", "decoded_bytes", "frames"] {
            positive(&layer[key])?;
        }
        for key in ["stored_sha256", "diff_id", "codec"] {
            string(&layer[key])?;
        }
    }
    Ok(())
}
fn positive(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .filter(|v| *v > 0)
        .ok_or_else(|| "positive integer required".into())
}
fn header() -> [u8; 512] {
    let mut h = [0; 512];
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[136..148].copy_from_slice(b"00000000000\0");
    h[156] = b'0';
    h[257..265].copy_from_slice(b"ustar\x0000");
    h[329..337].copy_from_slice(b"0000000\0");
    h[337..345].copy_from_slice(b"0000000\0");
    h
}
fn known_raw(label: &str) -> Result<Vec<u8>> {
    let body = if label == "a" {
        b"synthetic-layer-a\n".repeat(2049)
    } else {
        (0..1100)
            .flat_map(|index| Sha256::digest(format!("synthetic-layer-b:{index}").as_bytes()))
            .collect()
    };
    pack(&[Entry {
        name: "fixture.txt".into(),
        body,
        header: header(),
    }])
}
pub(super) fn upstream_rows(upstream: &Value) -> Result<()> {
    fields(upstream, &POSITIVES)?;
    for name in POSITIVES {
        let rows = array(&upstream[name])?;
        check(
            rows.len() == 3 && rows[0] == rows[2],
            "upstream repeated references",
        )?;
        for (row, label) in rows.iter().zip(["a", "b", "a"]) {
            fields(
                row,
                &[
                    "stored_sha256",
                    "stored_bytes",
                    "diff_id",
                    "decoded_base64",
                    "frames",
                    "codec",
                ],
            )?;
            let raw = unb64(string(&row["decoded_base64"])?)?;
            check(
                raw == known_raw(label)?,
                "upstream independent whole tar bytes",
            )?;
            check(row["diff_id"] == sha256(&raw), "upstream DiffID identity")?;
            check(
                row["codec"] == name.split('-').next().ok_or("codec")?
                    && positive(&row["frames"])? == if name.ends_with("-concat") { 2 } else { 1 },
                "upstream codec/frame profile",
            )?;
            check(
                positive(&row["stored_bytes"])? <= LIMIT as u64
                    && string(&row["stored_sha256"])?.len() == 64,
                "upstream stored identity",
            )?;
        }
    }
    Ok(())
}
fn falsey(value: &Value) -> bool {
    value.is_null()
        || value == false
        || value == 0
        || value == ""
        || value.as_array().is_some_and(Vec::is_empty)
        || value.as_object().is_some_and(Map::is_empty)
}
fn gzip_layers(stored: &[u8], row: &Value) -> Result<()> {
    let mut remaining = stored;
    let mut decoded = Vec::new();
    let mut frames = 0;
    while !remaining.is_empty() {
        let mut inflater = flate2::bufread::GzDecoder::new(remaining);
        inflater
            .by_ref()
            .take(u64::try_from(LIMIT - decoded.len() + 1)?)
            .read_to_end(&mut decoded)?;
        check(decoded.len() <= LIMIT, "bounded gzip layer")?;
        let tail = inflater.into_inner();
        check(tail.len() < remaining.len(), "gzip progress")?;
        remaining = tail;
        frames += 1;
    }
    check(
        decoded == unb64(string(&row["decoded_base64"])?)? && row["frames"] == frames,
        "independent gzip decode",
    )
}
pub(super) fn expected(encoded: &[u8], name: &str, upstream: &Value) -> Result<Value> {
    check(POSITIVES.contains(&name), "positive image identity")?;
    let raw = ungzip(encoded)?;
    let entries = unpack(&raw)?;
    check(
        entries.len() == 4 && entries[3].name == "manifest.json",
        "unique layers and manifest last",
    )?;
    let config = strict(&entries[0].body)?;
    let manifest = strict(&entries[3].body)?;
    let manifests = array(&manifest)?;
    check(manifests.len() == 1, "single image")?;
    let m = &manifests[0];
    check(
        falsey(&m["LayerSources"])
            && m["Config"] == entries[0].name
            && entries[0].name == format!("sha256:{}", sha256(&entries[0].body)),
        "config identity",
    )?;
    check(
        config["architecture"] == "amd64" && config["os"] == "linux" && falsey(&config["variant"]),
        "platform",
    )?;
    check(
        m["RepoTags"] == json!([format!("example.invalid/layer:{name}")]),
        "synthetic tag",
    )?;
    check(
        m["Layers"] == json!([entries[1].name, entries[2].name, entries[1].name]),
        "ordered repeated layers",
    )?;
    let rows = array(&upstream[name])?;
    check(rows.len() == 3, "upstream count")?;
    let diff_ids = rows
        .iter()
        .map(|row| Ok(format!("sha256:{}", string(&row["diff_id"])?)))
        .collect::<Result<Vec<_>>>()?;
    check(
        config["rootfs"] == json!({"type":"layers","diff_ids":diff_ids}),
        "ordered upstream DiffIDs",
    )?;
    for (entry, row) in entries[1..3].iter().zip(rows) {
        let hash = sha256(&entry.body);
        check(
            entry.name == format!("{hash}.tar.gz")
                && row["stored_sha256"] == hash
                && row["stored_bytes"] == entry.body.len(),
            "stored member binding",
        )?;
        let gzip = row["codec"] == "gzip";
        check(
            entry.body.starts_with(if gzip {
                &[31, 139]
            } else {
                &[40, 181, 47, 253]
            }),
            "actual codec framing",
        )?;
        if gzip {
            gzip_layers(&entry.body, row)?;
        }
    }
    let layers = rows.iter().map(|r| Ok(json!({"stored_sha256":r["stored_sha256"],"stored_bytes":r["stored_bytes"],
        "diff_id":r["diff_id"],"decoded_bytes":unb64(string(&r["decoded_base64"])?)?.len(),"codec":r["codec"],"frames":r["frames"]}))).collect::<Result<Vec<_>>>()?;
    Ok(json!({"status":"ok","outer_bytes":raw.len(),"outer_sha256":sha256(&raw),"layers":layers}))
}

// Preserve the producer's JSON member order when deriving byte-exact mutations.
// serde_json::Value sorts map keys; a seed walks the original document and emits
// the corresponding changed values in original order, just as Python dicts did.
struct Ordered<'a>(&'a Value);
impl<'de> serde::de::DeserializeSeed<'de> for Ordered<'_> {
    type Value = String;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<String, D::Error> {
        struct Visitor<'a>(&'a Value);
        impl<'de> serde::de::Visitor<'de> for Visitor<'_> {
            type Value = String;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("original JSON shape")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<String, A::Error> {
                use serde::de::Error;
                let mut parts = Vec::new();
                while let Some(key) = access.next_key::<String>()? {
                    let value = self
                        .0
                        .get(&key)
                        .ok_or_else(|| A::Error::custom("changed JSON shape"))?;
                    let part = access.next_value_seed(Ordered(value))?;
                    parts.push(format!(
                        "{}:{part}",
                        serde_json::to_string(&key).map_err(A::Error::custom)?
                    ));
                }
                Ok(format!("{{{}}}", parts.join(",")))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<String, A::Error> {
                use serde::de::Error;
                let values = self
                    .0
                    .as_array()
                    .ok_or_else(|| A::Error::custom("changed array shape"))?;
                let mut parts = Vec::new();
                for value in values {
                    parts.push(
                        access
                            .next_element_seed(Ordered(value))?
                            .ok_or_else(|| A::Error::custom("short original array"))?,
                    );
                }
                if access.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom("long original array"));
                }
                Ok(format!("[{}]", parts.join(",")))
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<String, E> {
                serde_json::to_string(self.0).map_err(E::custom)
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<String, E> {
                serde_json::to_string(self.0).map_err(E::custom)
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<String, E> {
                serde_json::to_string(self.0).map_err(E::custom)
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<String, E> {
                serde_json::to_string(self.0).map_err(E::custom)
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<String, E> {
                serde_json::to_string(self.0).map_err(E::custom)
            }
        }
        decoder.deserialize_any(Visitor(self.0))
    }
}
fn ordered(original: &[u8], changed: &Value) -> Result<Vec<u8>> {
    use serde::de::DeserializeSeed;
    let mut decoder = serde_json::Deserializer::from_slice(original);
    let result = Ordered(changed).deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(result.into_bytes())
}
fn rewrite(encoded: &[u8], mutation: &str) -> Result<Vec<u8>> {
    let mut entries = unpack(&ungzip(encoded)?)?;
    check(entries.len() == 4, "mutation archive shape")?;
    let mut manifest = strict(&entries[3].body)?;
    if mutation == "wrong-diffid" {
        let mut config = strict(&entries[0].body)?;
        let zero = format!("sha256:{}", "0".repeat(64));
        config["rootfs"]["diff_ids"][0] = zero.clone().into();
        config["rootfs"]["diff_ids"][2] = zero.into();
        entries[0].body = ordered(&entries[0].body, &config)?;
        entries[0].name = format!("sha256:{}", sha256(&entries[0].body));
        manifest[0]["Config"] = entries[0].name.clone().into();
    } else {
        let entry = &mut entries[1];
        let old = entry.name.clone();
        if mutation.ends_with("truncated") {
            entry.body.pop().ok_or("empty layer")?;
        } else {
            let offset = if mutation == "gzip-crc" { 8 } else { 1 };
            flip(&mut entry.body, offset)?;
        }
        entry.name = format!("{}.tar.gz", sha256(&entry.body));
        for value in manifest[0]["Layers"]
            .as_array_mut()
            .ok_or("manifest layers")?
        {
            if *value == old {
                *value = entry.name.clone().into();
            }
        }
    }
    entries[3].body = ordered(&entries[3].body, &manifest)?;
    gzip(&pack(&entries)?)
}
fn flip(raw: &mut [u8], back: usize) -> Result<()> {
    let index = raw.len().checked_sub(back).ok_or("flip position")?;
    *raw.get_mut(index).ok_or("flip position")? ^= 1;
    Ok(())
}
pub(super) fn cases(positives: &[(String, Vec<u8>)], upstream: &Value) -> Result<Cases> {
    check(
        positives.iter().map(|r| r.0.as_str()).eq(POSITIVES),
        "positive case order",
    )?;
    upstream_rows(upstream)?;
    for (name, raw) in positives {
        expected(raw, name, upstream)?;
    }
    let mut out = positives.to_vec();
    for name in &NAMES[4..9] {
        let source = if name.starts_with("zstd") { 2 } else { 0 };
        out.push(((*name).into(), rewrite(&positives[source].1, name)?));
    }
    let mut outer = positives[0].1.clone();
    flip(&mut outer, 8)?;
    out.push(("outer-crc".into(), outer));
    out.push(("decoded-limit".into(), positives[0].1.clone()));
    out.push(("ordered-limit".into(), positives[2].1.clone()));
    Ok(out)
}
pub(super) fn observations(inputs: &[(String, Vec<u8>)], upstream: &Value) -> Result<Value> {
    check(
        inputs.iter().map(|r| r.0.as_str()).eq(NAMES),
        "exact ordered cases",
    )?;
    check(
        inputs == cases(&inputs[..4], upstream)?,
        "exact independently derived corruptions",
    )?;
    let mut out = Map::new();
    for (index, (name, raw)) in inputs.iter().enumerate() {
        let observed = if index < 4 {
            expected(raw, name, upstream)?
        } else {
            json!({"status":ERRORS[index-4]})
        };
        out.insert(name.clone(),json!({"case":name,"archive_sha256":sha256(raw),"observed":observed,"retained_budget":true,"retry_retained_budget":true}));
    }
    Ok(out.into())
}
#[cfg(test)]
#[path = "layer_oracle_tests.rs"]
pub(super) mod tests;
