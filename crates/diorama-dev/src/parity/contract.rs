//! Distribution-neutral validation, staging and assertions. No process effects.
use super::{Result, require};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Artifact {
    pub schema_version: u32,
    pub kind: String,
    pub binary: PathBuf,
    pub sha256: String,
    pub version: String,
    pub source: Source,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Source {
    pub revision: String,
    pub repository: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Suite {
    pub schema_version: u32,
    pub id: String,
    pub cases: Vec<Case>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Case {
    pub id: String,
    pub argv: Vec<String>,
    pub expect: BTreeMap<String, Value>,
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub stdin: String,
    #[serde(default = "timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "privilege")]
    pub privilege: String,
}
fn timeout() -> u64 {
    30
}
fn privilege() -> String {
    "none".into()
}
pub(crate) fn hexadecimal(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn canonical(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        })
}
pub(crate) fn validate_files(case: &Case) -> Result<usize> {
    require(case.files.len() <= 32, "at most 32 fixture paths per case")?;
    let mut size = 0usize;
    for (name, contents) in &case.files {
        require(
            canonical(name),
            "canonical relative POSIX fixture path required",
        )?;
        size = size
            .checked_add(contents.len())
            .ok_or("fixture size overflow")?;
        for parent in Path::new(name).ancestors().skip(1) {
            require(
                !case
                    .files
                    .contains_key(&parent.to_string_lossy().into_owned()),
                "overlapping fixture file and directory",
            )?;
        }
    }
    require(size <= 256 * 1024, "case fixtures exceed 256 KiB")?;
    fixture_argv(case, Path::new("/fixtures/validation"))?;
    Ok(size)
}
pub(crate) fn fixture_argv(case: &Case, root: &Path) -> Result<Vec<String>> {
    case.argv
        .iter()
        .map(|arg| {
            require(!arg.contains('\0'), "argument contains NUL")?;
            if let Some(token) = arg.strip_prefix("{fixture:") {
                let name = token.strip_suffix('}').ok_or("incomplete fixture token")?;
                require(
                    case.files.contains_key(name),
                    "fixture token must name supplied file",
                )?;
                Ok(root.join(name).to_string_lossy().into_owned())
            } else {
                Ok(arg.clone())
            }
        })
        .collect()
}
pub(crate) fn validate(artifact: &Artifact, suite: &Suite) -> Result<()> {
    require(
        artifact.schema_version == 1 && ["go", "rust"].contains(&artifact.kind.as_str()),
        "artifact schema/kind",
    )?;
    require(
        hexadecimal(&artifact.sha256, 64) && hexadecimal(&artifact.source.revision, 40),
        "exact artifact digest/source revision required",
    )?;
    require(
        !artifact.source.repository.is_empty() && !artifact.version.is_empty(),
        "artifact repository/version required",
    )?;
    require(
        suite.schema_version == 1
            && !suite.id.is_empty()
            && !suite.cases.is_empty()
            && suite.cases.len() <= 64,
        "nonempty v1 suite of at most 64 cases",
    )?;
    let mut ids = BTreeSet::new();
    let mut total = 0;
    for case in &suite.cases {
        require(ids.insert(&case.id), "duplicate case ID")?;
        total += validate_files(case)?;
        require(total <= 1024 * 1024, "suite fixtures exceed 1 MiB")?;
        require(
            (1..=120).contains(&case.timeout_seconds),
            "case timeout outside 1..120 seconds",
        )?;
        require(
            ["none", "privileged"].contains(&case.privilege.as_str()),
            "unsupported case privilege",
        )?;
        require(
            case.expect
                .get("exit_code")
                .and_then(Value::as_i64)
                .is_some(),
            "integer expected exit code required",
        )?;
        require(
            case.env
                .iter()
                .all(|(k, v)| !k.is_empty() && !k.contains(['=', '\0']) && !v.contains('\0')),
            "invalid environment",
        )?;
        for (key, value) in &case.expect {
            if key == "exit_code" {
                continue;
            }
            let (stream, mode) = key.rsplit_once('_').ok_or("unknown assertion")?;
            require(
                ["stdout", "stderr", "combined"].contains(&stream),
                "unknown assertion stream",
            )?;
            match mode {
                "contains" => require(
                    value
                        .as_array()
                        .is_some_and(|a| a.iter().all(Value::is_string)),
                    "contains requires string array",
                )?,
                "equals" => require(value.is_string(), "equals requires string")?,
                _ => return Err(format!("unknown assertion: {key}").into()),
            }
        }
    }
    Ok(())
}
pub(crate) fn stage_files(cases: &[Case], root: &Path) -> Result<()> {
    fs::create_dir(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
    for (index, case) in cases.iter().enumerate() {
        validate_files(case)?;
        for (name, contents) in &case.files {
            let target = root.join(format!("{index:03}")).join(name);
            let parent = target.parent().ok_or("fixture parent")?;
            fs::create_dir_all(parent)?;
            for directory in parent.ancestors().take_while(|p| *p != root) {
                fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .open(target)?;
            file.write_all(contents.as_bytes())?;
        }
    }
    Ok(())
}
pub(crate) fn assess(case: &Case, code: i32, stdout: &str, stderr: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let expected = &case.expect;
    if expected.get("exit_code").and_then(Value::as_i64) != Some(i64::from(code)) {
        failures.push(format!("exit {code}, expected {}", expected["exit_code"]));
    }
    let combined = format!("{stdout}{stderr}");
    for (field, actual) in [
        ("stdout", stdout),
        ("stderr", stderr),
        ("combined", &combined),
    ] {
        if let Some(values) = expected
            .get(&format!("{field}_contains"))
            .and_then(Value::as_array)
        {
            for value in values.iter().filter_map(Value::as_str) {
                if !actual.contains(value) {
                    failures.push(format!("{field} missing {value:?}"));
                }
            }
        }
        if let Some(exact) = expected
            .get(&format!("{field}_equals"))
            .and_then(Value::as_str)
            && actual != exact
        {
            failures.push(format!("{field} differs from exact expectation"));
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn case() -> Case {
        serde_json::from_value(json!({"id":"example","argv":["--version"],"expect":{"exit_code":0,"stdout_contains":["version"],"stderr_equals":""}})).unwrap()
    }
    fn artifact() -> Artifact {
        serde_json::from_value(json!({"schema_version":1,"kind":"go","binary":"node","sha256":"a".repeat(64),"version":"test","source":{"repository":"example","revision":"b".repeat(40)}})).unwrap()
    }
    #[test]
    fn both_kinds_share_assertions_and_unknown_assertions_fail() -> Result<()> {
        let mut a = artifact();
        let mut s = Suite {
            schema_version: 1,
            id: "test".into(),
            cases: vec![case()],
        };
        for kind in ["go", "rust"] {
            a.kind = kind.into();
            validate(&a, &s)?;
            assert!(assess(&s.cases[0], 0, "version test", "").is_empty());
        }
        assert_eq!(assess(&s.cases[0], 1, "wrong", "").len(), 2);
        s.cases[0]
            .expect
            .insert("stdout_contians".into(), json!([]));
        assert!(validate(&a, &s).is_err());
        Ok(())
    }
    #[test]
    fn reject_escape_overlap_missing_reference_and_size() {
        for name in [
            "../outside",
            "/absolute",
            "a/../b",
            "a//b",
            "./file",
            "a\\b",
            "a/.",
        ] {
            let mut c = case();
            c.files.insert(name.into(), "data".into());
            assert!(validate_files(&c).is_err());
        }
        let mut c = case();
        c.files.insert("a".into(), "x".into());
        c.files.insert("a/b".into(), "y".into());
        assert!(validate_files(&c).is_err());
        c.files.clear();
        c.files.insert("config".into(), "x".repeat(256 * 1024 + 1));
        assert!(validate_files(&c).is_err());
        c.files.clear();
        c.argv = vec!["{fixture:missing}".into()];
        assert!(validate_files(&c).is_err());
    }
    #[test]
    fn staged_files_are_distinct_read_only_and_literal() -> Result<()> {
        let mut a = case();
        a.files
            .insert("nested/config.yaml".into(), "value: $(touch /bad)\n".into());
        a.argv = vec![
            "{fixture:nested/config.yaml}".into(),
            "$HOME".into(),
            "literal={fixture:nested/config.yaml}".into(),
        ];
        let mut b = a.clone();
        b.files.insert("nested/config.yaml".into(), "other".into());
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("fixtures");
        stage_files(&[a.clone(), b], &root)?;
        let file = root.join("000/nested/config.yaml");
        assert_eq!(fs::read_to_string(&file)?, a.files["nested/config.yaml"]);
        assert_eq!(fs::metadata(&file)?.permissions().mode() & 0o777, 0o444);
        assert_eq!(
            fs::read_to_string(root.join("001/nested/config.yaml"))?,
            "other"
        );
        assert_eq!(fixture_argv(&a, &root.join("000"))?[1], "$HOME");
        Ok(())
    }
    #[test]
    fn exact_revisions_duplicate_cases_and_timeout_are_enforced() {
        let mut a = artifact();
        let mut s = Suite {
            schema_version: 1,
            id: "test".into(),
            cases: vec![case()],
        };
        a.source.revision = "main".into();
        assert!(validate(&a, &s).is_err());
        a = artifact();
        s.cases.push(case());
        assert!(validate(&a, &s).is_err());
        s.cases.pop();
        s.cases[0].timeout_seconds = 121;
        assert!(validate(&a, &s).is_err());
    }
}
