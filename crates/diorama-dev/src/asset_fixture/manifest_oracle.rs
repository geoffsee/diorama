//! Independent retained-byte oracle; never calls the production asset validators.
use super::common::{Result, array, check, fields, hex, json, read, sha256, strict, string};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, path::Path};

const INPUTS: &str = include_str!("../../../assets-manifest/inputs.json");
const ARCHIVE_LIMIT: usize = 32 * 1024 * 1024;
const DECODED_LIMIT: u64 = 128 * 1024 * 1024;
const MANIFEST_MEDIA: &str = "application/vnd.docker.distribution.manifest.v2+json";
const CONFIG_MEDIA: &str = "application/vnd.docker.container.image.v1+json";
const LAYER_MEDIA: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";

fn number(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or_else(|| "positive integer required".into())
}
fn hash(value: &Value) -> Result<&str> {
    let value = string(value)?;
    check(hex(value, 64), "canonical SHA256")?;
    Ok(value)
}
fn pinned(raw: &[u8], digest: &Value, size: &Value) -> Result<()> {
    check(
        raw.len() as u64 == number(size)? && sha256(raw) == hash(digest)?,
        "exact retained input bytes",
    )
}
fn descriptor(value: &Value, digest: &Value, size: &Value, media: &str) -> Result<()> {
    fields(value, &["mediaType", "size", "digest"])?;
    check(
        value["mediaType"] == media
            && number(&value["size"])? == number(size)?
            && value["digest"] == format!("sha256:{}", hash(digest)?),
        "exact manifest descriptor",
    )
}
fn gzip_identity(stored: &[u8], limit: u64) -> Result<(String, u64)> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    check(limit > 0 && limit <= DECODED_LIMIT, "finite decoded bound")?;
    let mut decoder = flate2::bufread::GzDecoder::new(stored);
    let mut digest = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 16384];
    loop {
        let remaining = usize::try_from((limit - count + 1).min(buffer.len() as u64))?;
        let length = decoder.read(&mut buffer[..remaining])?;
        if length == 0 {
            break;
        }
        count += length as u64;
        check(count <= limit, "decoded byte bound")?;
        digest.update(&buffer[..length]);
    }
    check(
        decoder.into_inner().is_empty(),
        "exact single gzip frame with no trailing bytes",
    )?;
    let digest = digest
        .finalize()
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect();
    Ok((digest, count))
}
fn retained(directory: &Path, path: &str, digest: &Value, size: &Value) -> Result<Vec<u8>> {
    let limit = number(size)?;
    check(limit <= ARCHIVE_LIMIT as u64, "stored input bound")?;
    let raw = read(&directory.join(path), limit)?;
    pinned(&raw, digest, size)?;
    Ok(raw)
}
fn input_layer(directory: &Path, pin: &Value, descriptor_row: &Value) -> Result<Value> {
    fields(
        pin,
        &[
            "stored_sha256",
            "stored_bytes",
            "diff_id",
            "decoded_bytes",
            "codec",
            "frames",
        ],
    )?;
    check(
        pin["codec"] == "gzip" && pin["frames"].as_u64() == Some(1),
        "single gzip profile",
    )?;
    descriptor(
        descriptor_row,
        &pin["stored_sha256"],
        &pin["stored_bytes"],
        LAYER_MEDIA,
    )?;
    let stored = retained(
        directory,
        &format!("blobs/{}", hash(&pin["stored_sha256"])?),
        &pin["stored_sha256"],
        &pin["stored_bytes"],
    )?;
    let (diff_id, decoded_bytes) = gzip_identity(&stored, number(&pin["decoded_bytes"])?)?;
    check(
        diff_id == hash(&pin["diff_id"])? && decoded_bytes == number(&pin["decoded_bytes"])?,
        "complete independent DiffID and decoded size",
    )?;
    Ok(
        json!({"stored_sha256":sha256(&stored),"stored_bytes":stored.len(),
        "diff_id":diff_id,"decoded_bytes":decoded_bytes,"codec":"gzip","frames":1}),
    )
}
fn inputs(directory: &Path, pins: &Value) -> Result<Value> {
    fields(
        pins,
        &[
            "schema",
            "reference",
            "observed_at",
            "repo_tag",
            "manifest_sha256",
            "manifest_bytes",
            "config_sha256",
            "config_bytes",
            "layers",
        ],
    )?;
    check(pins["schema"].as_u64() == Some(1), "input schema")?;
    for key in ["reference", "observed_at", "repo_tag"] {
        string(&pins[key])?;
    }
    let raw_manifest = retained(
        directory,
        "arm64-manifest.json",
        &pins["manifest_sha256"],
        &pins["manifest_bytes"],
    )?;
    let raw_config = retained(
        directory,
        "arm64-config.json",
        &pins["config_sha256"],
        &pins["config_bytes"],
    )?;
    let manifest = strict(&raw_manifest)?;
    fields(
        &manifest,
        &["schemaVersion", "mediaType", "config", "layers"],
    )?;
    check(
        manifest["schemaVersion"].as_u64() == Some(2) && manifest["mediaType"] == MANIFEST_MEDIA,
        "Docker manifest schema",
    )?;
    descriptor(
        &manifest["config"],
        &pins["config_sha256"],
        &pins["config_bytes"],
        CONFIG_MEDIA,
    )?;
    let config = strict(&raw_config)?;
    check(
        config["os"] == "linux"
            && config["architecture"] == "arm64"
            && config.get("variant").is_none_or(Value::is_null),
        "retained platform",
    )?;
    fields(&config["rootfs"], &["type", "diff_ids"])?;
    check(config["rootfs"]["type"] == "layers", "rootfs type")?;
    let pin_layers = array(&pins["layers"])?;
    let manifest_layers = array(&manifest["layers"])?;
    check(
        pin_layers.len() == 13 && manifest_layers.len() == 13,
        "exact thirteen layers",
    )?;
    let layers = pin_layers
        .iter()
        .zip(manifest_layers)
        .map(|(pin, row)| input_layer(directory, pin, row))
        .collect::<Result<Vec<_>>>()?;
    let diff_ids = layers
        .iter()
        .map(|row| format!("sha256:{}", row["diff_id"].as_str().unwrap_or("")))
        .collect::<Vec<_>>();
    check(
        config["rootfs"]["diff_ids"] == json!(diff_ids),
        "ordered complete config DiffIDs",
    )?;
    let mut files = Map::new();
    files.insert(
        "arm64-manifest.json".into(),
        json!({"sha256":sha256(&raw_manifest),"bytes":raw_manifest.len()}),
    );
    files.insert(
        "arm64-config.json".into(),
        json!({"sha256":sha256(&raw_config),"bytes":raw_config.len()}),
    );
    for row in &layers {
        check(
            files
                .insert(
                    format!("blobs/{}", string(&row["stored_sha256"])?),
                    json!({"sha256":row["stored_sha256"],"bytes":row["stored_bytes"]}),
                )
                .is_none(),
            "unique retained blobs",
        )?;
    }
    Ok(
        json!({"manifest_sha256":sha256(&raw_manifest),"manifest_bytes":raw_manifest.len(),
        "config_sha256":sha256(&raw_config),"config_bytes":raw_config.len(),"os":"linux",
        "architecture":"arm64","variant":null,"layers":layers,"files":files}),
    )
}
pub(super) fn verify_inputs(directory: &Path) -> Result<Value> {
    inputs(directory, &strict(INPUTS.as_bytes())?)
}

fn octal(raw: &[u8]) -> Result<usize> {
    let text = std::str::from_utf8(raw)?.trim_matches(['\0', ' ']);
    check(
        !text.is_empty() && text.bytes().all(|c| (b'0'..=b'7').contains(&c)),
        "canonical octal",
    )?;
    Ok(usize::from_str_radix(text, 8)?)
}
fn members(raw: &[u8]) -> Result<Vec<(&str, &[u8])>> {
    check(raw.len() <= ARCHIVE_LIMIT, "outer tar bound")?;
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(header) = raw.get(cursor..cursor + 512) {
        if header.iter().all(|b| *b == 0) {
            break;
        }
        check(out.len() < 15, "exact member count bound")?;
        let checksum = header
            .iter()
            .enumerate()
            .map(|(i, b)| usize::from(if (148..156).contains(&i) { b' ' } else { *b }))
            .sum::<usize>();
        check(octal(&header[148..156])? == checksum, "tar header checksum")?;
        check(
            &header[257..265] == b"ustar\x0000"
                && header[156] == b'0'
                && header[157..257]
                    .iter()
                    .chain(&header[345..])
                    .all(|b| *b == 0),
            "regular USTAR without extensions",
        )?;
        let end = header[..100]
            .iter()
            .position(|b| *b == 0)
            .ok_or("tar name termination")?;
        check(
            header[end..100].iter().all(|b| *b == 0) && header[..end].is_ascii(),
            "canonical tar name",
        )?;
        let name = std::str::from_utf8(&header[..end])?;
        check(
            !name.is_empty() && !name.contains('/') && !out.iter().any(|(n, _)| *n == name),
            "unique flat member",
        )?;
        let start = cursor + 512;
        let end = start
            .checked_add(octal(&header[124..136])?)
            .ok_or("tar size overflow")?;
        let padded = end.checked_add(511).ok_or("tar padding overflow")? / 512 * 512;
        check(padded <= raw.len(), "complete tar member")?;
        check(raw[end..padded].iter().all(|b| *b == 0), "zero tar padding")?;
        out.push((name, &raw[start..end]));
        cursor = padded;
    }
    check(
        raw.get(cursor..) == Some(&[0u8; 1024][..]),
        "exact tar terminators",
    )?;
    Ok(out)
}
fn outer(encoded: &[u8]) -> Result<Vec<u8>> {
    check(encoded.len() <= ARCHIVE_LIMIT, "encoded archive bound")?;
    let mut decoder = flate2::bufread::GzDecoder::new(encoded);
    let mut raw = Vec::new();
    decoder
        .by_ref()
        .take((ARCHIVE_LIMIT + 1) as u64)
        .read_to_end(&mut raw)?;
    check(
        raw.len() <= ARCHIVE_LIMIT && decoder.into_inner().is_empty(),
        "complete bounded outer gzip",
    )?;
    Ok(raw)
}
fn archive(directory: &Path, encoded: &[u8], pins: &Value) -> Result<Value> {
    let mut result = inputs(directory, pins)?;
    let raw = outer(encoded)?;
    let entries = members(&raw)?;
    check(
        entries.len() == 15 && entries[14].0 == "manifest.json",
        "config thirteen layers manifest order",
    )?;
    let config_name = format!("sha256:{}", hash(&pins["config_sha256"])?);
    check(
        entries[0].0 == config_name
            && entries[0].1
                == retained(
                    directory,
                    "arm64-config.json",
                    &pins["config_sha256"],
                    &pins["config_bytes"],
                )?,
        "raw config byte equality",
    )?;
    let mut names = Vec::new();
    for ((name, body), pin) in entries[1..14].iter().zip(array(&pins["layers"])?) {
        let digest = hash(&pin["stored_sha256"])?;
        check(
            *name == format!("{digest}.tar.gz")
                && *body
                    == retained(
                        directory,
                        &format!("blobs/{digest}"),
                        &pin["stored_sha256"],
                        &pin["stored_bytes"],
                    )?,
            "ordered raw stored blob equality",
        )?;
        names.push(*name);
    }
    let manifest = strict(entries[14].1)?;
    let rows = array(&manifest)?;
    check(rows.len() == 1, "single packaged image")?;
    let row = &rows[0];
    let keys = row.as_object().ok_or("archive manifest object")?;
    check(
        keys.keys()
            .all(|key| ["Config", "RepoTags", "Layers", "LayerSources"].contains(&key.as_str()))
            && row
                .get("LayerSources")
                .is_none_or(|v| v.is_null() || v.as_object().is_some_and(Map::is_empty)),
        "local archive manifest fields",
    )?;
    let tags = json!([string(&pins["repo_tag"])?]);
    check(
        row["Config"] == config_name && row["Layers"] == json!(names) && row["RepoTags"] == tags,
        "packaged identity order and tags",
    )?;
    let additions = BTreeMap::from([
        ("archive_sha256", json!(sha256(encoded))),
        ("archive_bytes", json!(encoded.len())),
        ("outer_sha256", json!(sha256(&raw))),
        ("outer_bytes", json!(raw.len())),
        ("archive_manifest_sha256", json!(sha256(entries[14].1))),
        ("repo_tags", tags),
    ]);
    result.as_object_mut().ok_or("oracle object")?.extend(
        additions
            .into_iter()
            .map(|(key, value)| (key.into(), value)),
    );
    Ok(result)
}
pub(super) fn verify_archive(directory: &Path, encoded: &[u8]) -> Result<Value> {
    archive(directory, encoded, &strict(INPUTS.as_bytes())?)
}
/// Durable, independently audited expectations; runtime still verifies all raw bytes.
pub(super) fn pinned_observation() -> Result<Value> {
    let pins = strict(INPUTS.as_bytes())?;
    let archive = strict(include_bytes!("../../../assets-manifest/archive-pin.json"))?;
    fields(
        &archive,
        &[
            "archive_sha256",
            "archive_bytes",
            "outer_sha256",
            "outer_bytes",
            "archive_manifest_sha256",
            "repo_tags",
        ],
    )?;
    for key in ["archive_sha256", "outer_sha256", "archive_manifest_sha256"] {
        hash(&archive[key])?;
    }
    for key in ["archive_bytes", "outer_bytes"] {
        number(&archive[key])?;
    }
    check(
        archive["repo_tags"] == json!([string(&pins["repo_tag"])?]),
        "pinned tag binding",
    )?;
    let mut files = Map::new();
    for (name, prefix) in [
        ("arm64-manifest.json", "manifest"),
        ("arm64-config.json", "config"),
    ] {
        let digest = hash(&pins[format!("{prefix}_sha256")])?;
        let bytes = number(&pins[format!("{prefix}_bytes")])?;
        files.insert(name.into(), json!({"sha256":digest,"bytes":bytes}));
    }
    for layer in array(&pins["layers"])? {
        let digest = hash(&layer["stored_sha256"])?;
        files.insert(
            format!("blobs/{digest}"),
            json!({"sha256":digest,"bytes":number(&layer["stored_bytes"])?}),
        );
    }
    let mut result = json!({"manifest_sha256":pins["manifest_sha256"],"manifest_bytes":pins["manifest_bytes"],
        "config_sha256":pins["config_sha256"],"config_bytes":pins["config_bytes"],"os":"linux",
        "architecture":"arm64","variant":null,"layers":pins["layers"],"files":files});
    result
        .as_object_mut()
        .ok_or("oracle object")?
        .extend(archive.as_object().ok_or("archive pin object")?.clone());
    Ok(result)
}
#[cfg(test)]
#[path = "manifest_oracle_tests.rs"]
mod tests;
