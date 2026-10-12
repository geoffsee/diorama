//! Characterized config writer link behavior; replacements come from a hash-bound fixture.
use super::equal;
use crate::Result;
use serde_json::{Value, json};
use std::path::Path;

const OLD: &str = "# original bytes, preserve comments\nnetwork: {mtu: 1250}\n";
fn regular(bytes: &str, mode: &str) -> Value {
    json!({"kind":"regular","mode":mode,"bytes":bytes})
}
fn directory() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../parity/fixtures/config-write-links")
}

pub fn expected() -> Result<Value> {
    let directory = directory();
    let provenance = super::load(&directory.join("provenance.json"))?;
    equal(
        &provenance["reference_source_sha256"],
        &json!({
        "internal/config/defaults.go":"902db154b17cd88d24f18b4f9aeb87d286470b5113c18b1f2066d20ab596a24b",
        "internal/config/file.go":"9a9af1ea2d94ff1fa1f2306f868721fb88f2e4b1d0d3fa286879b18de61749de",
        "types/config.go":"e59764b93fd6689f091e79a17a633d94e910ebc23ae7db375734e212211ce4fa"}),
    )?;
    equal(
        &provenance["expected_replacement_origin"],
        &json!({"path":"tools/parity/fixtures/config-api/config.json","selector":"[0].first","sha256":"f71e045a1317753738eb44965ae6ffbb83c886d904e06cc5f3b6b66e09302800"}),
    )?;
    let origin = crate::read_bounded(&directory.join("../config-api/config.json"), super::LIMIT)?;
    equal(
        &json!(crate::sha256(&origin)),
        &json!("f71e045a1317753738eb44965ae6ffbb83c886d904e06cc5f3b6b66e09302800"),
    )?;
    let origin = crate::json::parse(&origin)?;
    let replacement = String::from_utf8(crate::read_bounded(
        &directory.join("replacement.yaml"),
        super::LIMIT,
    )?)?;
    equal(&json!(replacement), &origin[0]["first"])?;
    let mut records = Vec::new();
    for name in [
        "destination-symlink",
        "backup-symlink",
        "backup-hardlink",
        "permissive-backup",
        "destination-directory",
        "backup-directory",
        "ordinary",
    ] {
        let failed = ["destination-directory", "backup-directory"].contains(&name);
        let mut entries = json!({"config.yaml":regular(&replacement,"0600"),"config.yaml.bak":regular(OLD,"0600")});
        match name {
            "destination-symlink" => {
                entries["other"] = regular(OLD, "0644");
            },
            "backup-symlink" => {
                entries["config.yaml.bak"] =
                    json!({"kind":"symlink","mode":"0777","bytes":OLD,"link":"other"});
                entries["other"] = regular(OLD, "0644");
            },
            "backup-hardlink" => {
                entries["config.yaml.bak"] = regular(OLD, "0644");
                entries["other"] = regular(OLD, "0644");
            },
            "permissive-backup" => {
                entries["config.yaml.bak"] = regular(OLD, "0644");
            },
            "destination-directory" => {
                entries = json!({"config.yaml":{"kind":"directory","mode":"0700"}});
            },
            "backup-directory" => {
                entries = json!({"config.yaml":regular(OLD,"0644"),"config.yaml.bak":{"kind":"directory","mode":"0700"}});
            },
            _ => {},
        }
        records.push(json!({"case":name,"write_error":failed,"destination_inode_preserved":failed,"backup_other_same_inode":name=="backup-hardlink","entries":entries}));
    }
    Ok(json!(records))
}
pub fn verify(value: &Value) -> Result<()> {
    equal(value, &expected()?)
}

#[cfg(test)]
mod tests {
    use super::super::load;
    use super::*;
    #[test]
    #[ignore = "receipt checks disabled"]
    fn historical_repeats_match_filesystem_semantics_and_original_inputs() -> Result<()> {
        let directory = directory();
        let expected = expected()?;
        equal(&load(&directory.join("reference.json"))?, &expected)?;
        equal(&load(&directory.join("evidence/repeat.json"))?, &expected)?;
        for name in ["first", "repeat"] {
            let raw = crate::read_bounded(
                &directory.join(format!("evidence/{name}.log")),
                super::super::LIMIT,
            )?;
            let records = std::str::from_utf8(&raw)?
                .lines()
                .filter_map(|line| line.strip_prefix("DIORAMA_CAPTURE "))
                .map(|line| crate::json::parse(line.as_bytes()))
                .collect::<Result<Vec<_>>>()?;
            equal(&json!(records), &expected)?;
        }
        let provenance = load(&directory.join("provenance.json"))?;
        for name in [
            "Capture.Dockerfile",
            "capture-receipt.json",
            "evidence/build.log",
            "evidence/first.log",
            "evidence/repeat.json",
            "evidence/repeat.log",
            "file_capture_test.go",
            "reference.json",
            "replacement.yaml",
        ] {
            equal(
                &json!(crate::sha256(&crate::read_bounded(
                    &directory.join(name),
                    16 * super::super::LIMIT
                )?)),
                &provenance["local_sha256"][name],
            )?;
        }
        Ok(())
    }
    #[test]
    fn rejects_permissions_link_target_inode_error_and_type_changes() -> Result<()> {
        for (index, pointer, replacement) in [
            (0, "/entries/config.yaml/mode", json!("0644")),
            (1, "/entries/config.yaml.bak/link", json!("elsewhere")),
            (2, "/backup_other_same_inode", json!(false)),
            (3, "/entries/config.yaml.bak/mode", json!("0600")),
            (4, "/write_error", json!(false)),
            (5, "/destination_inode_preserved", json!(1)),
            (6, "/entries/config.yaml/bytes", json!("corrupt")),
            (0, "/destination_inode_preserved", json!(true)),
            (0, "/entries/other/bytes", json!("corrupt")),
            (1, "/entries/config.yaml.bak/kind", json!("regular")),
            (6, "/entries/config.yaml.bak/bytes", json!("corrupt")),
        ] {
            let mut changed = expected()?;
            *changed[index].pointer_mut(pointer).ok_or("mutation path")? = replacement;
            assert!(verify(&changed).is_err());
        }
        assert!(verify(&json!([])).is_err());
        let mut changed = expected()?;
        changed[6]["entries"]["leaked.tmp"] = regular("partial", "0600");
        assert!(verify(&changed).is_err());
        Ok(())
    }
}
