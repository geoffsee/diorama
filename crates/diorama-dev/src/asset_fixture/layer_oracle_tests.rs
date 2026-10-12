use super::super::common::b64;
use super::*;

pub(crate) fn invented() -> Result<(Cases, Value)> {
    let mut upstream = Map::new();
    let mut positives = Vec::new();
    for name in POSITIVES {
        let mut rows = Vec::new();
        let mut entries = Vec::new();
        for label in ["a", "b"] {
            let raw = known_raw(label)?;
            let parts = if name.ends_with("-concat") {
                vec![&raw[..raw.len() / 2], &raw[raw.len() / 2..]]
            } else {
                vec![raw.as_slice()]
            };
            let mut stored = Vec::new();
            for part in &parts {
                if name.starts_with("gzip") {
                    stored.extend(gzip(part)?);
                } else {
                    stored.extend([40, 181, 47, 253, 0, 80]);
                    stored.extend(&((u32::try_from(part.len())? << 3) | 1).to_le_bytes()[..3]);
                    stored.extend_from_slice(part);
                }
            }
            rows.push(json!({"stored_sha256":sha256(&stored),"stored_bytes":stored.len(),"diff_id":sha256(&raw),"decoded_base64":b64(&raw),"frames":parts.len(),"codec":name.split('-').next().unwrap()}));
            entries.push(Entry {
                name: format!("{}.tar.gz", sha256(&stored)),
                body: stored,
                header: header(),
            });
        }
        rows.push(rows[0].clone());
        let config = serde_json::to_vec(
            &json!({"os":"linux","architecture":"amd64","rootfs":{"type":"layers","diff_ids":rows.iter().map(|r|format!("sha256:{}",r["diff_id"].as_str().unwrap())).collect::<Vec<_>>()}}),
        )?;
        let config_name = format!("sha256:{}", sha256(&config));
        let manifest = serde_json::to_vec(
            &json!([{"Config":config_name,"Layers":[entries[0].name,entries[1].name,entries[0].name],"RepoTags":[format!("example.invalid/layer:{name}")]}]),
        )?;
        entries.insert(
            0,
            Entry {
                name: config_name,
                body: config,
                header: header(),
            },
        );
        entries.push(Entry {
            name: "manifest.json".into(),
            body: manifest,
            header: header(),
        });
        positives.push((name.into(), gzip(&pack(&entries)?)?));
        upstream.insert(name.into(), rows.into());
    }
    Ok((positives, upstream.into()))
}
#[test]
fn independent_whole_tar_and_twelve_ordered_observations() {
    let (positives, upstream) = invented().unwrap();
    let inputs = cases(&positives, &upstream).unwrap();
    let rows = observations(&inputs, &upstream).unwrap();
    assert_eq!(rows.as_object().unwrap().len(), 12);
    for name in POSITIVES {
        let observed = &rows[name]["observed"];
        assert_eq!(observed["layers"][0], observed["layers"][2]);
        assert_ne!(observed["layers"][0], observed["layers"][1]);
    }
    for row in rows.as_object().unwrap().values() {
        observation_schema(row).unwrap();
    }
}
#[test]
fn consumer_boolean_integer_types_and_failure_schema_are_exact() {
    let (positives, upstream) = invented().unwrap();
    let rows = observations(&cases(&positives, &upstream).unwrap(), &upstream).unwrap();
    for key in ["retained_budget", "retry_retained_budget"] {
        let mut row = rows["gzip"].clone();
        row[key] = 1.into();
        assert!(observation_schema(&row).is_err());
    }
    for key in ["stored_bytes", "decoded_bytes", "frames"] {
        for value in [json!(true), json!(0), json!(-1), json!(1.0)] {
            let mut row = rows["gzip"].clone();
            row["observed"]["layers"][0][key] = value;
            assert!(observation_schema(&row).is_err());
        }
    }
    let mut row = rows["gzip"].clone();
    row["observed"]["outer_bytes"] = true.into();
    assert!(observation_schema(&row).is_err());
    let mut row = rows["gzip-crc"].clone();
    row["observed"]["layers"] = json!([]);
    assert!(observation_schema(&row).is_err());
}
#[test]
fn mutations_are_exact_and_gzip_rejects_trailing_truncated_or_concatenated_outer_streams() {
    let (positives, upstream) = invented().unwrap();
    let inputs = cases(&positives, &upstream).unwrap();
    for index in 4..10 {
        let mut changed = inputs.clone();
        changed[index].1 = inputs[0].1.clone();
        assert!(observations(&changed, &upstream).is_err());
    }
    for raw in [
        inputs[0].1[..inputs[0].1.len() - 1].to_vec(),
        [inputs[0].1.as_slice(), b"junk"].concat(),
        inputs[0].1.repeat(2),
    ] {
        assert!(ungzip(&raw).is_err());
    }
    assert!(observations(&inputs[..11], &upstream).is_err());
    let mut changed = inputs.clone();
    changed.swap(0, 1);
    assert!(observations(&changed, &upstream).is_err());
    let mut changed = inputs;
    changed.push(("extra".into(), vec![]));
    assert!(observations(&changed, &upstream).is_err());
}
#[test]
fn wrong_diffid_retains_stored_members_and_repeated_reference_closure() {
    let (positives, upstream) = invented().unwrap();
    let inputs = cases(&positives, &upstream).unwrap();
    let before = unpack(&ungzip(&positives[0].1).unwrap()).unwrap();
    let changed = unpack(&ungzip(&inputs[8].1).unwrap()).unwrap();
    for index in 1..3 {
        assert_eq!(changed[index].name, before[index].name);
        assert_eq!(changed[index].body, before[index].body);
        assert_eq!(changed[index].header, before[index].header);
    }
    let cfg = strict(&changed[0].body).unwrap();
    let m = strict(&changed[3].body).unwrap();
    assert_eq!(
        cfg["rootfs"]["diff_ids"][0],
        format!("sha256:{}", "0".repeat(64))
    );
    assert_eq!(cfg["rootfs"]["diff_ids"][0], cfg["rootfs"]["diff_ids"][2]);
    assert_eq!(
        cfg["rootfs"]["diff_ids"][1],
        format!(
            "sha256:{}",
            upstream["gzip"][1]["diff_id"].as_str().unwrap()
        )
    );
    assert_eq!(
        changed[0].name,
        format!("sha256:{}", sha256(&changed[0].body))
    );
    assert_eq!(m[0]["Config"], changed[0].name);
    assert_eq!(
        m[0]["Layers"],
        json!([changed[1].name, changed[2].name, changed[1].name])
    );
}
#[test]
fn sidecar_raw_bytes_digest_codec_and_actual_stored_members_are_bound() {
    let (positives, upstream) = invented().unwrap();
    for (key, value) in [
        ("decoded_base64", json!(b64(b"wrong"))),
        ("diff_id", json!("0".repeat(64))),
        ("frames", json!(7)),
        ("frames", json!(true)),
        ("codec", json!("identity")),
        ("stored_bytes", json!(true)),
    ] {
        let mut changed = upstream.clone();
        changed["gzip"][0][key] = value.clone();
        changed["gzip"][2][key] = value;
        assert!(upstream_rows(&changed).is_err());
    }
    for index in [0, 1] {
        let mut entries = unpack(&ungzip(&positives[0].1).unwrap()).unwrap();
        entries[index].body.push(b'x');
        assert!(expected(&gzip(&pack(&entries).unwrap()).unwrap(), "gzip", &upstream).is_err());
    }
    let mut changed = upstream;
    changed["zstd"][0]["stored_sha256"] = json!("0".repeat(64));
    assert!(expected(&positives[2].1, "zstd", &changed).is_err());
}
#[test]
fn mutation_json_preserves_original_order_and_strict_types() {
    let original = br#"{ "z": ["old",2], "a": {"b":true,"a":null}}"#;
    let mut changed = strict(original).unwrap();
    changed["z"][0] = "new".into();
    assert_eq!(
        ordered(original, &changed).unwrap(),
        br#"{"z":["new",2],"a":{"b":true,"a":null}}"#
    );
    for bad in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"a":NaN}"#,
        br#"{"a":1.5}"#,
    ] {
        assert!(strict(bad).is_err());
    }
}

#[test]
fn historical_upstream_bytes_reproduce_original_mutations_and_observations() {
    // Compatibility regression only: historical execution is never current proof.
    let root =
        diorama_dev::repository_root(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let raw = super::super::common::read(
        &root.join("tools/assets-layer/evidence/first.log"),
        4 * 1024 * 1024,
    )
    .unwrap();
    let text = std::str::from_utf8(&raw).unwrap();
    let mut upstream = None;
    let mut inputs = Vec::new();
    let mut recorded = Map::new();
    for line in text.lines() {
        if let Some(raw) = line.strip_prefix("DIORAMA_UPSTREAM ") {
            assert!(upstream.replace(strict(raw.as_bytes()).unwrap()).is_none());
        } else if let Some(raw) = line.strip_prefix("DIORAMA_INPUT ") {
            let row = strict(raw.as_bytes()).unwrap();
            inputs.push((
                string(&row["case"]).unwrap().into(),
                unb64(string(&row["gzip_base64"]).unwrap()).unwrap(),
            ));
        } else if let Some(raw) = line.strip_prefix("DIORAMA_LAYER ") {
            let row = strict(raw.as_bytes()).unwrap();
            observation_schema(&row).unwrap();
            assert!(
                recorded
                    .insert(string(&row["case"]).unwrap().into(), row)
                    .is_none()
            );
        }
    }
    assert_eq!(
        observations(&inputs, &upstream.unwrap()).unwrap(),
        Value::Object(recorded)
    );
}
