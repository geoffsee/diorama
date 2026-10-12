//! Bounded diagnostics published only after attempted owner settlement.
use serde_json::{Value, json};
use std::{fs::File, io::Read, path::Path};
pub(super) fn failure_log(path: &Path) -> Value {
    let result = (|| -> std::io::Result<Vec<u8>> {
        let mut raw = Vec::new();
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let file = File::from(fd);
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::other("nonregular diagnostic"));
        }
        file.take(65537).read_to_end(&mut raw)?;
        Ok(raw)
    })();
    match result {
        Ok(raw) => {
            json!({"text":String::from_utf8_lossy(&raw[..raw.len().min(65536)]),"truncated":raw.len()>65536,"error":null})
        },
        Err(error) => json!({"text":"","truncated":false,"error":format!("{:?}",error.kind())}),
    }
}
pub(super) fn failure_record(
    case: &str,
    pid: Option<u32>,
    original: &str,
    out: &Path,
    err: &Path,
    settle: impl FnOnce() -> diorama_dev::Result<()>,
) -> Value {
    let cleanup = settle().err().map(|e| e.to_string());
    json!({"schema":1,"event":"consumer_failure","case":case,"pid":pid,"kind":"RustError","message":original,"cleanup_error":cleanup,"stdout":failure_log(out),"stderr":failure_log(err)})
}
