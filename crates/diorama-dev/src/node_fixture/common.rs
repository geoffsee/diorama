pub(super) use diorama_dev::{Result, sha256};
pub(super) use serde_json::{Value, json};
use std::{fs, io::Read, path::Path};
pub(super) fn parse(raw: &[u8]) -> Result<Value> {
    fn integer_only(value: &Value) -> bool {
        match value {
            Value::Number(n) => n.is_i64() || n.is_u64(),
            Value::Array(a) => a.iter().all(integer_only),
            Value::Object(o) => o.values().all(integer_only),
            _ => true,
        }
    }
    let value = diorama_dev::json::parse(raw)?;
    require(integer_only(&value), "integer-only semantic JSON")?;
    Ok(value)
}
pub(super) fn require(value: bool, message: &str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}
pub(super) fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(|| "expected string".into())
}
pub(super) fn fields(value: &Value, names: &[&str]) -> Result<()> {
    require(
        value
            .as_object()
            .is_some_and(|o| o.len() == names.len() && names.iter().all(|k| o.contains_key(*k))),
        "exact fields",
    )
}
pub(super) fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub(super) fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?;
    let file = fs::File::from(fd);
    require(file.metadata()?.is_file(), "regular bounded input")?;
    let mut bytes = Vec::new();
    file.take(limit.checked_add(1).ok_or("limit overflow")?)
        .read_to_end(&mut bytes)?;
    require(u64::try_from(bytes.len())? <= limit, "input limit")?;
    Ok(bytes)
}
pub(super) fn load(path: &Path) -> Result<Value> {
    parse(&read(path, 16 * 1024 * 1024)?)
}
pub(super) fn digest(path: &Path) -> Result<String> {
    Ok(sha256(&read(path, 64 * 1024 * 1024)?))
}
pub(super) fn save(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}
pub(super) fn files(path: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if [
            "target",
            "evidence",
            "rust-evidence",
            "evidence-rust",
            ".git",
            "__pycache__",
            ".DS_Store",
        ]
        .iter()
        .any(|s| entry.file_name() == *s)
        {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_dir() {
            result.extend(files(&entry.path())?);
        } else if kind.is_file() {
            result.push(entry.path());
        } else {
            return Err("source symlink/special file".into());
        }
    }
    result.sort();
    Ok(result)
}
pub(super) fn inventory(root: &Path, family: &str) -> Result<Value> {
    let mut paths = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
        .map(|s| root.join(s))
        .to_vec();
    for name in [
        ".cargo",
        "crates",
        "third_party",
        "tools/upstream",
        "tools/dev",
        "tools/parity",
        &if family == "probes" {
            "tools/parity/fixtures/preflight-probes".to_owned()
        } else {
            format!("tools/node-{family}")
        },
    ] {
        paths.extend(files(&root.join(name))?);
    }
    if family == "constrained" {
        paths.extend(files(&root.join("tools/node-container"))?);
    }
    let mut result = serde_json::Map::new();
    for path in paths {
        let name = path
            .strip_prefix(root)?
            .to_str()
            .ok_or("source path UTF8")?;
        if path.file_name().is_some_and(|n| {
            n == "README.md" || n == "provenance.json" || n == "rust-provenance.json"
        }) {
            continue;
        }
        result.insert(name.into(), digest(&path)?.into());
    }
    Ok(result.into())
}
pub(super) fn uncertain(error: &diorama_dev::Error) -> bool {
    error
        .downcast_ref::<crate::parity::process::CommandFailure>()
        .is_some_and(|f| !f.cleanup_complete)
}
pub(super) fn retain<T>(directory: tempfile::TempDir, result: Result<T>) -> Result<T> {
    if result.as_ref().is_err_and(uncertain) {
        eprintln!("unsettled command; retained {}", directory.keep().display());
    }
    result
}
pub(super) fn block<'a>(raw: &'a str, name: &str) -> Result<(&'a str, String)> {
    let begin = format!("{name}_BEGIN\n");
    let end = format!("{name}_END\n");
    require(
        raw.matches(&begin).count() == 1 && raw.matches(&end).count() == 1,
        "unique complete block",
    )?;
    let (before, tail) = raw.split_once(&begin).ok_or("block begin")?;
    let (body, after) = tail.split_once(&end).ok_or("block end order")?;
    Ok((body, format!("{before}{after}")))
}
pub(super) fn scalar(raw: &str, name: &str, pattern: &str) -> Result<(String, String)> {
    let expression = regex::Regex::new(&format!("(?m)^{} ({pattern})$", regex::escape(name)))?;
    let rows = expression.captures_iter(raw).collect::<Vec<_>>();
    require(rows.len() == 1, "unique scalar")?;
    let value = rows[0][1].to_owned();
    let matched = rows[0].get(0).ok_or("scalar match")?;
    let end = matched.end() + usize::from(raw.as_bytes().get(matched.end()) == Some(&b'\n'));
    Ok((value, format!("{}{}", &raw[..matched.start()], &raw[end..])))
}
