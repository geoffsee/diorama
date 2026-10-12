//! Offline published Kubernetes bindings provenance checks.
use super::{
    Result, array, blob_name, digest, fail, read_verified, run, safe_relative, strict_json, text,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::Path,
    process::Command,
};
const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";
fn toml_json(data: &[u8]) -> Result<Value> {
    Ok(serde_json::to_value(toml::from_str::<toml::Value>(
        std::str::from_utf8(data)?,
    )?)?)
}
pub(crate) fn inspect_archive(data: &[u8], contract: &Value) -> Result<usize> {
    let prefix = format!(
        "{}-{}/",
        text(contract, "crate")?,
        text(contract, "version")?
    );
    let wanted = BTreeSet::from(["Cargo.toml", ".cargo_vcs_info.json", "src/v1_35/mod.rs"]);
    let mut selected = BTreeMap::new();
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(data));
    for item in archive.entries()? {
        let mut item = item?;
        let name = std::str::from_utf8(&item.path_bytes())?.to_owned();
        safe_relative(&name)?;
        if !name.starts_with(&prefix) || !names.insert(name.clone()) {
            return fail("unexpected or duplicate crate archive path");
        }
        let kind = item.header().entry_type();
        if !kind.is_file() && !kind.is_dir() {
            return fail("crate archive contains a link or special file");
        }
        let size = item.size();
        total = total.checked_add(size).ok_or("archive total overflow")?;
        if names.len() > 20000 || total > 128 * 1024 * 1024 || size > 8 * 1024 * 1024 {
            return fail("crate archive exceeds inspection limits");
        }
        let relative = name.strip_prefix(&prefix).ok_or("invalid prefix")?;
        if wanted.contains(relative) {
            if !kind.is_file() {
                return fail("crate metadata must be regular files");
            }
            let mut data = Vec::new();
            item.read_to_end(&mut data)?;
            selected.insert(relative.to_owned(), data);
        }
    }
    if selected.len() != wanted.len() {
        return fail("crate archive is missing selected metadata or v1_35 bindings");
    }
    let package = toml_json(&selected["Cargo.toml"])?;
    if package["package"]["version"] != contract["version"]
        || package["package"]["name"] != contract["crate"]
        || package["features"].get(text(contract, "feature")?) != Some(&json!([]))
    {
        return fail("published crate identity or version feature disagrees with contract");
    }
    let vcs = strict_json(&selected[".cargo_vcs_info.json"])?;
    if vcs["git"]["sha1"] != contract["source_commit"] || vcs["path_in_vcs"] != "" {
        return fail("published crate source revision disagrees with contract");
    }
    Ok(names.len())
}
pub(crate) fn check_declaration(manifest: &Value, contract: &Value) -> Result<()> {
    let d = &manifest["dev-dependencies"][text(contract, "crate")?];
    if !d.is_object()
        || d["version"] != format!("={}", text(contract, "version")?)
        || d["default-features"] != false
        || d["features"] != json!([contract["feature"]])
    {
        return fail("maintenance dependency must declare exact version and explicit v1_35 only");
    }
    Ok(())
}
pub(crate) fn check_selection(
    metadata: &Value,
    lock: &Value,
    contract: &Value,
    checksum: &str,
) -> Result<Vec<String>> {
    let packages: Vec<_> = array(metadata, "packages")?
        .iter()
        .filter(|p| p["name"] == contract["crate"])
        .collect();
    if packages.len() != 1 {
        return fail("expected exactly one selected k8s-openapi package");
    }
    let p = packages[0];
    if p["version"] != contract["version"] || p["source"] != REGISTRY {
        return fail("selected Kubernetes binding version/source differs");
    }
    let node = array(&metadata["resolve"], "nodes")?
        .iter()
        .find(|n| n["id"] == p["id"])
        .ok_or("missing resolution node")?;
    let mut features = array(node, "features")?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "invalid feature".into())
        })
        .collect::<Result<Vec<_>>>()?;
    features.sort();
    let versions: Vec<_> = features
        .iter()
        .filter(|f| f.starts_with("v1_") || matches!(f.as_str(), "latest" | "earliest"))
        .collect();
    if versions != [text(contract, "feature")?] {
        return fail("Kubernetes bindings require explicit v1_35 only; aliases forbidden");
    }
    let entries: Vec<_> = array(lock, "package")?
        .iter()
        .filter(|p| p["name"] == contract["crate"])
        .collect();
    if entries.len() != 1
        || entries[0]["version"] != contract["version"]
        || entries[0]["source"] != REGISTRY
        || entries[0]["checksum"] != checksum
    {
        return fail("Cargo.lock does not select the verified published crate checksum");
    }
    Ok(features)
}
pub(crate) fn check_schema(
    data: &BTreeMap<String, Vec<u8>>,
    records: &BTreeMap<String, Value>,
    contract: &Value,
) -> Result<()> {
    if data["k8s-openapi-schema"] != data["openapi"] {
        return fail("published generator schema differs from official target schema");
    }
    let re =
        regex::Regex::new(r#"SupportedVersion::V1_35\s*=>\s*"(https://[^"\n]+swagger\.json)""#)?;
    let source = std::str::from_utf8(&data["k8s-openapi-version-map"])?;
    let found = re
        .captures(source)
        .ok_or("generator version map lacks selected schema")?;
    if &found[1] != text(&records["k8s-openapi-schema"], "url")? {
        return fail("generator version map does not select verified schema");
    }
    if !text(&records["k8s-openapi-version-map"], "url")?
        .contains(&format!("/{}/", text(contract, "source_commit")?))
        || !text(&records["k8s-openapi-schema"], "url")?
            .contains(&format!("/{}/", text(contract, "schema_release")?))
    {
        return fail("generator source/schema release differs");
    }
    Ok(())
}
pub(crate) fn check(inputs: &Value, cache: &Path, root: &Path) -> Result<Value> {
    let contract = &inputs["kubernetes_bindings"];
    let architecture = strict_json(&fs::read(
        root.join("docs/architecture/upstream-inputs.json"),
    )?)?;
    if architecture["accepted_contract"]["published_kubernetes_bindings"]
        != json!({"crate":contract["crate"],"version":contract["version"],"feature":contract["feature"]})
    {
        return fail("published binding selection disagrees with architecture");
    }
    let records = array(inputs, "sources")?
        .iter()
        .map(|r| Ok((text(r, "id")?.to_owned(), r.clone())))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let ids = [
        "k8s-openapi-crate",
        "k8s-openapi-version-map",
        "k8s-openapi-schema",
        "openapi",
    ];
    let mut data = BTreeMap::new();
    for id in ids {
        let r = records.get(id).ok_or("missing schema input")?;
        data.insert(id.to_owned(), read_verified(cache, &blob_name(r)?, r)?);
    }
    let authority = array(&architecture, "sources")?
        .iter()
        .find(|s| s["repository"] == "https://github.com/kubernetes/kubernetes")
        .ok_or("missing official authority")?;
    let official = array(authority, "files")?
        .iter()
        .find(|f| f["path"] == records["openapi"]["path"])
        .ok_or("missing official schema")?;
    for k in ["url", "bytes", "sha256"] {
        if official[k] != records["openapi"][k] {
            return fail("official schema disagrees with architecture");
        }
    }
    check_schema(&data, &records, contract)?;
    let count = inspect_archive(&data["k8s-openapi-crate"], contract)?;
    check_declaration(
        &toml_json(&fs::read(root.join("tools/upstream/Cargo.toml"))?)?,
        contract,
    )?;
    let metadata = strict_json(&run(
        Command::new("cargo")
            .args(["metadata", "--offline", "--locked", "--format-version", "1"])
            .current_dir(root),
        60,
    )?)?;
    let lock = fs::read(root.join("Cargo.lock"))?;
    let features = check_selection(
        &metadata,
        &toml_json(&lock)?,
        contract,
        text(&records["k8s-openapi-crate"], "sha256")?,
    )?;
    let hashes = ids
        .into_iter()
        .map(|id| (id, records[id]["sha256"].clone()))
        .collect::<BTreeMap<_, _>>();
    Ok(
        json!({"status":"verified","target":"published-kubernetes-bindings","contract":contract,"cargo_lock_sha256":digest(&lock),"resolved_features":features,"source_hashes":hashes,"archive_entries":count,"schema_definitions":strict_json(&data["openapi"])?["definitions"].as_object().ok_or("missing definitions")?.len(),"limitations":"Published artifact and identical schema provenance; not generator reproduction or semantic parity."}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn contract() -> Value {
        json!({"crate":"k8s-openapi","version":"0.28.0","feature":"v1_35","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_release":"v1.35.6"})
    }
    fn archive(extra: Option<(&str, u8)>, revision: &str) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        let manifest =
            b"[package]\nname=\"k8s-openapi\"\nversion=\"0.28.0\"\n[features]\nv1_35=[]\n";
        let vcs = serde_json::to_vec(&json!({"git":{"sha1":revision},"path_in_vcs":""})).unwrap();
        for (name, data) in [
            ("Cargo.toml", manifest.as_slice()),
            (".cargo_vcs_info.json", vcs.as_slice()),
            ("src/v1_35/mod.rs", b"//bindings"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, format!("k8s-openapi-0.28.0/{name}"), data)
                .unwrap();
        }
        if let Some((name, kind)) = extra {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::new(kind));
            header.set_link_name("/outside").unwrap();
            header.set_cksum();
            tar.append_data(&mut header, format!("k8s-openapi-0.28.0/{name}"), &[][..])
                .unwrap();
        }
        let raw = tar.into_inner().unwrap();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&raw).unwrap();
        gzip.finish().unwrap()
    }
    #[test]
    fn crate_archive_identity_and_namespace_reject_links_duplicates_and_wrong_revision() {
        let c = contract();
        let revision = text(&c, "source_commit").unwrap();
        assert_eq!(inspect_archive(&archive(None, revision), &c).unwrap(), 3);
        for extra in [
            ("Cargo.toml", b'0'),
            ("link", b'2'),
            ("hard", b'1'),
            ("device", b'3'),
            ("pipe", b'6'),
        ] {
            assert!(inspect_archive(&archive(Some(extra), revision), &c).is_err());
        }
        assert!(
            inspect_archive(
                &archive(None, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                &c
            )
            .is_err()
        );
    }
    #[test]
    fn dependency_declaration_requires_exact_version_and_explicit_feature() {
        let c = contract();
        let valid = json!({"dev-dependencies":{"k8s-openapi":{"version":"=0.28.0","default-features":false,"features":["v1_35"]}}});
        check_declaration(&valid, &c).unwrap();
        for version in ["0.28.0", "^0.28.0", "*"] {
            let mut bad = valid.clone();
            bad["dev-dependencies"]["k8s-openapi"]["version"] = version.into();
            assert!(check_declaration(&bad, &c).is_err());
        }
        let mut bad = valid;
        bad["dev-dependencies"]["k8s-openapi"]["features"] = json!(["latest"]);
        assert!(check_declaration(&bad, &c).is_err());
    }
    fn selection() -> (Value, Value) {
        let p = json!({"id":"selected","name":"k8s-openapi","version":"0.28.0","source":REGISTRY});
        let mut lock = p.clone();
        lock["checksum"] = "cccc".into();
        (
            json!({"packages":[p],"resolve":{"nodes":[{"id":"selected","features":["v1_35"]}]}}),
            json!({"package":[lock]}),
        )
    }
    #[test]
    fn unified_features_versions_sources_and_lock_checksum_are_checked() {
        let c = contract();
        let (m, l) = selection();
        assert_eq!(check_selection(&m, &l, &c, "cccc").unwrap(), ["v1_35"]);
        for features in [
            json!([]),
            json!(["latest"]),
            json!(["v1_35", "latest"]),
            json!(["v1_35", "v1_36"]),
            json!(["earliest", "v1_35"]),
        ] {
            let (mut m, l) = selection();
            m["resolve"]["nodes"][0]["features"] = features;
            assert!(check_selection(&m, &l, &c, "cccc").is_err());
        }
        for key in ["version", "source"] {
            let (mut m, l) = selection();
            m["packages"][0][key] = "wrong".into();
            assert!(check_selection(&m, &l, &c, "cccc").is_err());
        }
        assert!(check_selection(&m, &l, &c, "wrong").is_err());
        let mut duplicate = m.clone();
        duplicate["packages"]
            .as_array_mut()
            .unwrap()
            .push(m["packages"][0].clone());
        assert!(check_selection(&duplicate, &l, &c, "cccc").is_err());
    }
    #[test]
    fn independent_schema_and_version_mapping_require_exact_identity() {
        let c = contract();
        let url = "https://raw.githubusercontent.com/kubernetes/kubernetes/v1.35.6/api/openapi-spec/swagger.json";
        let data = BTreeMap::from([
            ("openapi".to_owned(), b"schema".to_vec()),
            ("k8s-openapi-schema".to_owned(), b"schema".to_vec()),
            (
                "k8s-openapi-version-map".to_owned(),
                format!("SupportedVersion::V1_35 => \"{url}\",").into_bytes(),
            ),
        ]);
        let records = BTreeMap::from([
            ("k8s-openapi-schema".to_owned(), json!({"url":url})),
            (
                "k8s-openapi-version-map".to_owned(),
                json!({"url":format!("https://example.invalid/{}/supported_version.rs",text(&c,"source_commit").unwrap())}),
            ),
        ]);
        check_schema(&data, &records, &c).unwrap();
        for key in ["k8s-openapi-schema", "k8s-openapi-version-map"] {
            let mut changed = data.clone();
            changed.insert(key.to_owned(), b"wrong".to_vec());
            assert!(check_schema(&changed, &records, &c).is_err());
        }
    }
}
