//! Quarantine untrusted Docker tar output, validate every member before publication.
use super::{Result, require};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub(crate) fn publish(raw: &[u8], destination: &Path) -> Result<()> {
    require(
        raw.len() < 64 * 1024 * 1024,
        "evidence archive exceeds 64 MiB",
    )?;
    let mut archive = tar::Archive::new(Cursor::new(raw));
    let mut selected = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();
        let name = path.strip_prefix("./").unwrap_or(&path);
        if entry.header().entry_type().is_dir() && [".", ""].contains(&name) {
            continue;
        }
        let numbered = name.is_ascii()
            && name.len() == 10
            && name[..3].bytes().all(|b| b.is_ascii_digit())
            && [".stdout", ".stderr"].contains(&&name[3..]);
        require(
            entry.header().entry_type().is_file()
                && (name == "result.json" || numbered)
                && seen.insert(name.to_owned()),
            format!("unsafe/duplicate evidence member: {name}"),
        )?;
        let maximum = if name == "result.json" {
            2 * 1024 * 1024
        } else {
            256 * 1024
        };
        require(entry.size() <= maximum, "oversized evidence member")?;
        let owned = name.to_owned();
        let mut data = Vec::new();
        entry.by_ref().take(maximum + 1).read_to_end(&mut data)?;
        require(data.len() as u64 == entry.size(), "complete tar payload")?;
        selected.push((owned, data));
    }
    for (name, data) in selected {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())?)
            .open(destination.join(name))?;
        file.write_all(&data)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn tar(link: bool) -> Result<Vec<u8>> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_path("result.json")?;
        header.set_size(2);
        header.set_mode(0o600);
        header.set_cksum();
        builder.append(&header, &b"{}"[..])?;
        if link {
            let mut h = tar::Header::new_ustar();
            h.set_path("runner-result.json")?;
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_link_name("/outside")?;
            h.set_size(0);
            h.set_cksum();
            builder.append(&h, std::io::empty())?;
        }
        Ok(builder.into_inner()?)
    }
    #[test]
    fn invalid_later_member_publishes_nothing() -> Result<()> {
        let dir = tempfile::tempdir()?;
        assert!(publish(&tar(true)?, dir.path()).is_err());
        assert_eq!(std::fs::read_dir(dir.path())?.count(), 0);
        Ok(())
    }
    #[test]
    fn exclusive_publication_never_overwrites() -> Result<()> {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join("result.json"), b"original")?;
        assert!(publish(&tar(false)?, dir.path()).is_err());
        assert_eq!(std::fs::read(dir.path().join("result.json"))?, b"original");
        Ok(())
    }
}
