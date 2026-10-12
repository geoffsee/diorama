use super::common::{
    Result, array, b64, bounded, check, fields, json, load, read, sha256, stream_json, strict,
    string, unb64,
};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, io::Read, path::Path, process::Command};
pub(super) const NAMES: [&str; 8] = [
    "amd64-repeated",
    "armv7-unresolved",
    "outer-crc",
    "member-digest",
    "unsafe-name",
    "missing-reference",
    "duplicate-json",
    "wrong-platform",
];
const ERRORS: [&str; 6] = [
    "decode",
    "policy:MemberDigest",
    "policy:Name",
    "policy:References",
    "policy:Json",
    "policy:PlatformMismatch",
];
const LIMIT: usize = 1024 * 1024;
#[derive(Clone, Debug)]
pub(super) struct Entry {
    pub(super) name: String,
    pub(super) body: Vec<u8>,
    pub(super) header: [u8; 512],
}
pub(super) fn ungzip(encoded: &[u8]) -> Result<Vec<u8>> {
    check(encoded.len() <= LIMIT, "gzip input cap")?;
    let mut decoder = flate2::bufread::GzDecoder::new(encoded);
    let mut out = Vec::new();
    decoder
        .by_ref()
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut out)?;
    check(
        out.len() <= LIMIT && decoder.into_inner().is_empty(),
        "complete single bounded gzip",
    )?;
    Ok(out)
}
fn crc(raw: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in raw {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 == 1 { 0xedb8_8320 } else { 0 };
        }
    }
    !crc
}
pub(super) fn gzip(raw: &[u8]) -> Result<Vec<u8>> {
    check(
        !raw.is_empty() && raw.len() <= LIMIT,
        "stored gzip input cap",
    )?;
    let mut out = vec![31, 139, 8, 0, 0, 0, 0, 0, 0, 255];
    let count = raw.chunks(65535).len();
    for (index, part) in raw.chunks(65535).enumerate() {
        let size = u16::try_from(part.len())?;
        out.push(u8::from(index + 1 == count));
        out.extend(size.to_le_bytes());
        out.extend((!size).to_le_bytes());
        out.extend(part);
    }
    out.extend(crc(raw).to_le_bytes());
    out.extend(u32::try_from(raw.len())?.to_le_bytes());
    Ok(out)
}
fn octal(raw: &[u8]) -> Result<usize> {
    let text = std::str::from_utf8(raw)?.trim_matches(['\0', ' ']);
    check(!text.is_empty(), "octal field")?;
    Ok(usize::from_str_radix(text, 8)?)
}
pub(super) fn unpack(raw: &[u8]) -> Result<Vec<Entry>> {
    check(raw.len() <= LIMIT, "tar limit")?;
    let mut entries: Vec<Entry> = Vec::new();
    let mut cursor = 0usize;
    while raw
        .get(cursor..cursor + 512)
        .is_some_and(|h| h.iter().any(|b| *b != 0))
    {
        let h: [u8; 512] = raw[cursor..cursor + 512].try_into()?;
        let mut check_header = h;
        check_header[148..156].fill(b' ');
        check(
            octal(&h[148..156])? == check_header.iter().map(|b| usize::from(*b)).sum::<usize>(),
            "tar checksum",
        )?;
        check(
            &h[257..265] == b"ustar\x0000" && h[156] == b'0',
            "regular USTAR",
        )?;
        check(
            h[157..257].iter().chain(&h[345..]).all(|b| *b == 0),
            "no link prefix extension",
        )?;
        let end = h[..100]
            .iter()
            .position(|b| *b == 0)
            .ok_or("name terminator")?;
        check(
            h[end..100].iter().all(|b| *b == 0) && h[..end].is_ascii(),
            "canonical name",
        )?;
        let name = String::from_utf8(h[..end].to_vec())?;
        check(!entries.iter().any(|e| e.name == name), "duplicate member")?;
        let size = octal(&h[124..136])?;
        let start = cursor + 512;
        let end = start.checked_add(size).ok_or("tar size overflow")?;
        let padded = end.checked_add(511).ok_or("tar pad overflow")? / 512 * 512;
        check(
            padded <= raw.len() && raw[end..padded].iter().all(|b| *b == 0),
            "tar payload padding",
        )?;
        entries.push(Entry {
            name,
            body: raw[start..end].to_vec(),
            header: h,
        });
        cursor = padded;
    }
    check(
        raw.get(cursor..) == Some(&[0u8; 1024][..]),
        "exact two tar terminators",
    )?;
    Ok(entries)
}
pub(super) fn pack(entries: &[Entry]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for entry in entries {
        check(entry.name.len() < 100, "name length")?;
        let mut h = entry.header;
        h[..100].fill(0);
        h[..entry.name.len()].copy_from_slice(entry.name.as_bytes());
        let size = format!("{:011o}\0", entry.body.len());
        check(size.len() == 12, "size field")?;
        h[124..136].copy_from_slice(size.as_bytes());
        h[148..156].fill(b' ');
        let sum = h.iter().map(|b| usize::from(*b)).sum::<usize>();
        let checksum = format!("{sum:06o}\0 ");
        check(checksum.len() == 8, "checksum field")?;
        h[148..156].copy_from_slice(checksum.as_bytes());
        out.extend(h);
        out.extend(&entry.body);
        out.resize(out.len().div_ceil(512) * 512, 0);
        check(out.len() <= LIMIT - 1024, "packed tar cap")?;
    }
    out.extend([0u8; 1024]);
    Ok(out)
}
pub(super) fn expected(encoded: &[u8], name: &str) -> Result<Value> {
    check(NAMES[..2].contains(&name), "positive identity")?;
    let raw = ungzip(encoded)?;
    let entries = unpack(&raw)?;
    check(
        entries.len() == 4 && entries[3].name == "manifest.json",
        "manifest last/two unique layers",
    )?;
    let manifest = strict(&entries[3].body)?;
    let descriptors = array(&manifest)?;
    check(descriptors.len() == 1, "one image")?;
    let d = &descriptors[0];
    check(
        d.as_object()
            .ok_or("descriptor")?
            .keys()
            .all(|k| ["Config", "Layers", "RepoTags", "LayerSources"].contains(&k.as_str())),
        "descriptor fields",
    )?;
    check(
        d.get("LayerSources")
            .is_none_or(|v| v.is_null() || v.as_object().is_some_and(Map::is_empty)),
        "local layer sources",
    )?;
    let c = &entries[0];
    check(
        c.name == format!("sha256:{}", sha256(&c.body)) && d["Config"] == c.name,
        "config identity",
    )?;
    let config = strict(&c.body)?;
    let arch = if name == NAMES[0] { "amd64" } else { "arm" };
    check(
        config["os"] == "linux"
            && config["architecture"] == arch
            && config.get("variant").is_none_or(|v| v.is_null() || v == ""),
        "synthetic platform",
    )?;
    check(config["rootfs"]["type"] == "layers", "rootfs type")?;
    let tags = json!([format!("example.invalid/fixture:{name}")]);
    check(d["RepoTags"] == tags, "tags")?;
    check(
        d["Layers"] == json!([entries[1].name, entries[2].name, entries[1].name]),
        "ordered repeated refs",
    )?;
    let mut rows = Vec::new();
    let mut diffs = Vec::new();
    for (e, label) in entries[1..3].iter().zip(["synthetic-a", "synthetic-b"]) {
        check(
            e.name == format!("{}.tar.gz", sha256(&e.body)),
            "stored layer hash",
        )?;
        let inner = ungzip(&e.body)?;
        let content = unpack(&inner)?;
        check(
            content.len() == 1
                && content[0].name == "fixture.txt"
                && content[0].body == format!("{label}\n").repeat(1025).as_bytes(),
            "independent synthetic payload",
        )?;
        diffs.push(format!("sha256:{}", sha256(&inner)));
        rows.push(json!({"sha256":sha256(&e.body),"bytes":e.body.len(),"declared_diff_id":sha256(&inner)}));
    }
    check(
        config["rootfs"]["diff_ids"] == json!([diffs[0], diffs[1], diffs[0]]),
        "declared DiffIDs",
    )?;
    Ok(
        json!({"status":"ok","decoded_bytes":raw.len(),"decoded_sha256":sha256(&raw),"config_sha256":sha256(&c.body),"config_bytes":c.body.len(),"os":"linux","architecture":arch,"variant":null,"platform_status":if arch=="amd64"{"DeclaredMatch"}else{"VariantUnresolved"},"archive_manifest_sha256":sha256(&entries[3].body),"repo_tags":tags,"layers":[rows[0],rows[1],rows[0]]}),
    )
}
pub(super) fn cases(first: &[u8], arm: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    expected(first, NAMES[0])?;
    expected(arm, NAMES[1])?;
    let entries = unpack(&ungzip(first)?)?;
    let mut out = vec![
        (NAMES[0].into(), first.to_vec()),
        (NAMES[1].into(), arm.to_vec()),
    ];
    let mut damaged = first.to_vec();
    let at = damaged.len().checked_sub(8).ok_or("gzip trailer")?;
    damaged[at] ^= 1;
    out.push((NAMES[2].into(), damaged));
    let mut changed = entries.clone();
    check(!changed[1].body.is_empty(), "layer bytes")?;
    changed[1].body[0] ^= 1;
    out.push((NAMES[3].into(), gzip(&pack(&changed)?)?));
    let mut changed = entries.clone();
    changed[0].name = "../config".into();
    out.push((NAMES[4].into(), gzip(&pack(&changed)?)?));
    out.push((
        NAMES[5].into(),
        gzip(&pack(&[
            entries[0].clone(),
            entries[1].clone(),
            entries[3].clone(),
        ])?)?,
    ));
    for name in &NAMES[6..] {
        let mut changed = entries.clone();
        let mut body = changed[0].body.clone();
        if *name == "duplicate-json" {
            check(body.pop() == Some(b'}'), "config object")?;
            body.extend(b",\"architecture\":\"amd64\"}");
        } else {
            let mut config = strict(&body)?;
            config["architecture"] = "arm64".into();
            body = serde_json::to_vec(&config)?;
        }
        changed[0].name = format!("sha256:{}", sha256(&body));
        changed[0].body = body;
        let mut manifest = strict(&entries[3].body)?;
        manifest[0]["Config"] = changed[0].name.clone().into();
        changed[3].body = serde_json::to_vec(&manifest)?;
        out.push(((*name).into(), gzip(&pack(&changed)?)?));
    }
    Ok(out)
}
pub(super) fn observations(inputs: &[(String, Vec<u8>)]) -> Result<Value> {
    check(
        inputs.iter().map(|p| p.0.as_str()).eq(NAMES),
        "exact case order",
    )?;
    check(
        inputs == cases(&inputs[0].1, &inputs[1].1)?,
        "exact independent corruptions",
    )?;
    let mut out = Map::new();
    for (index, (name, raw)) in inputs.iter().enumerate() {
        out.insert(name.clone(),json!({"case":name,"archive_sha256":sha256(raw),"observed":if index<2{expected(raw,name)?}else{json!({"status":ERRORS[index-2]})}}));
    }
    Ok(out.into())
}
pub(super) const CONSUMER: [&str; 6] = [
    "/archive-tests",
    "--ignored",
    "--exact",
    "inspect_pinned_crane_serialization",
    "--show-output",
    "--test-threads=1",
];
pub(super) fn parse_consumer(raw: &str) -> Result<Value> {
    let rows: Vec<Value> = raw
        .lines()
        .filter_map(|line| line.strip_prefix("DIORAMA_ARCHIVE "))
        .map(|line| strict(line.as_bytes()))
        .collect::<Result<_>>()?;
    check(
        rows.iter()
            .map(|v| v["case"].as_str().unwrap_or(""))
            .eq(NAMES),
        "consumer exact ordered cases",
    )?;
    let testlines: Vec<_> = raw
        .lines()
        .filter(|l| l.starts_with("test ") && !l.starts_with("test result:"))
        .collect();
    check(
        testlines == ["test inspect_pinned_crane_serialization ... ok"],
        "exact consumer test inventory",
    )?;
    super::native::summary(raw, 1)?;
    let mut out = Map::new();
    for row in rows {
        out.insert(string(&row["case"])?.into(), row);
    }
    Ok(out.into())
}
pub(super) fn emit_log(
    status: Result<()>,
    path: &Path,
    output: &mut impl std::io::Write,
) -> Result<Vec<u8>> {
    let logged = (|| -> Result<Vec<u8>> {
        let raw = read(path, 65536)?;
        output.write_all(&raw)?;
        output.flush()?;
        Ok(raw)
    })();
    // Keep the command failure authoritative even if its bounded log is unreadable.
    status?;
    logged
}
pub(super) fn runtime() -> Result<()> {
    let directory = tempfile::tempdir_in("/tmp")?;
    let result = runtime_in(directory.path());
    super::common::retain(directory, result)
}
fn runtime_in(directory: &Path) -> Result<()> {
    let producer_log = directory.join("producer.log");
    let producer_status = bounded(
        Command::new("/producer").arg(directory),
        &producer_log,
        20,
        65536,
    );
    emit_log(
        producer_status,
        &producer_log,
        &mut std::io::stdout().lock(),
    )?;
    let inputs = cases(
        &read(&directory.join("amd64-repeated.tar.gz"), LIMIT as u64)?,
        &read(&directory.join("armv7-unresolved.tar.gz"), LIMIT as u64)?,
    )?;
    let expected = observations(&inputs)?;
    for (name, raw) in &inputs {
        std::fs::write(directory.join(format!("{name}.tar.gz")), raw)?;
        println!(
            "DIORAMA_INPUT {}",
            json!({"case":name,"gzip_base64":b64(raw)})
        );
    }
    let log = directory.join("consumer.log");
    let status = bounded(
        Command::new(CONSUMER[0])
            .args(&CONSUMER[1..])
            .env("DIORAMA_ARCHIVE_FIXTURE", directory),
        &log,
        20,
        65536,
    );
    let raw = String::from_utf8(emit_log(status, &log, &mut std::io::stdout().lock())?)?;
    check(
        parse_consumer(&raw)? == expected,
        "independent consumer equality",
    )?;
    println!(
        "DIORAMA_COMPLETE {}",
        json!({"cases":NAMES,"consumer_command":CONSUMER})
    );
    Ok(())
}
pub(super) fn graph(actual: &Path, pinned: &Path) -> Result<()> {
    graph_module(actual, pinned, "diorama.invalid/assets-archive-fixture")
}
pub(super) fn graph_module(actual: &Path, pinned: &Path, main_module: &str) -> Result<()> {
    let mut rows = BTreeMap::new();
    let mut mains = 0;
    for row in stream_json(&read(actual, 4 * 1024 * 1024)?)? {
        check(
            row.get("Replace").is_none() && row.get("Error").is_none(),
            "module replacement/error",
        )?;
        if row["Main"] == true {
            mains += 1;
            check(row["Path"] == main_module, "main module")?;
            continue;
        }
        let mut item = Map::new();
        for key in ["Path", "Version", "Sum", "GoModSum"] {
            item.insert(key.into(), string(&row[key])?.into());
        }
        check(
            string(&row["Sum"])?.starts_with("h1:") && string(&row["GoModSum"])?.starts_with("h1:"),
            "module checksums",
        )?;
        check(
            rows.insert(string(&row["Path"])?.to_owned(), Value::Object(item))
                .is_none(),
            "duplicate module",
        )?;
    }
    check(
        mains == 1 && !rows.is_empty() && json!(rows.values().collect::<Vec<_>>()) == load(pinned)?,
        "complete pinned module graph",
    )
}
pub(super) fn records(path: &Path) -> Result<(Value, Value)> {
    let raw = String::from_utf8(read(path, 2 * 1024 * 1024)?)?;
    let lines: Vec<_> = raw.lines().collect();
    let binaries =
        super::native::runtime_binaries(&lines, &["producer", "archive-tests", "fixture"])?;
    check(
        lines.get(3)
            == Some(
                &"DIORAMA_PRODUCER go1.26.2 github.com/google/go-containerregistry v0.21.5 h1:KTJG9Pn/jC0VdZR6ctV3/jcN+q6/Iqlx0sTVz3ywZlM=",
            ),
        "producer provenance/order",
    )?;
    let mut inputs = Vec::new();
    for (index, name) in NAMES.iter().enumerate() {
        let line = lines
            .get(4 + index)
            .and_then(|l| l.strip_prefix("DIORAMA_INPUT "))
            .ok_or("input order")?;
        let row = strict(line.as_bytes())?;
        fields(&row, &["case", "gzip_base64"])?;
        check(row["case"] == *name, "input name")?;
        inputs.push(((*name).into(), unb64(string(&row["gzip_base64"])?)?));
    }
    check(
        raw.lines()
            .filter(|l| l.starts_with("DIORAMA_INPUT "))
            .count()
            == 8,
        "exact inputs",
    )?;
    check(
        lines
            .iter()
            .filter(|line| line.starts_with("DIORAMA_"))
            .all(|line| {
                [
                    "DIORAMA_PRODUCER ",
                    "DIORAMA_INPUT ",
                    "DIORAMA_ARCHIVE ",
                    "DIORAMA_COMPLETE ",
                    "DIORAMA_NAMESPACE ",
                ]
                .iter()
                .any(|prefix| line.starts_with(prefix))
            }),
        "unknown archive record",
    )?;
    check(
        lines
            .iter()
            .filter(|line| line.starts_with("DIORAMA_PRODUCER "))
            .count()
            == 1,
        "exact producer record",
    )?;
    let expected = observations(&inputs)?;
    check(
        parse_consumer(&raw)? == expected,
        "independent archive observations",
    )?;
    let complete: Vec<_> = lines
        .iter()
        .filter_map(|l| l.strip_prefix("DIORAMA_COMPLETE "))
        .collect();
    check(
        complete.len() == 1
            && strict(complete[0].as_bytes())?
                == json!({"cases":NAMES,"consumer_command":CONSUMER}),
        "completion",
    )?;
    check(
        lines.len() >= 2 && lines[lines.len() - 2].starts_with("DIORAMA_COMPLETE "),
        "final completion order",
    )?;
    super::native::namespace(&lines)?;
    Ok((expected, binaries))
}
