//! Safe rustix boundary. No command helpers and no caller-selected paths/PIDs.
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;

use rustix::fs::{self, AtFlags, Mode, OFlags, ResolveFlags, StatxFlags};
use rustix::mount::{MountPropagationFlags, mount_change};

use super::{
    CgroupLayout, ContainerError as Error, ContainerSession, ControllerName, Mutation,
    parse_controllers,
};

// Linux UAPI magic.h, also present in the locked linux-raw-sys bindings.
const CGROUP2_MAGIC: i64 = 0x6367_7270;
const CGROUP1_MAGIC: i64 = 0x0027_e0eb;
const PROC_MAGIC: i64 = 0x0000_9fa0;
const NS_MAGIC: i64 = 0x6e73_6673;
const MOUNT_BYTES: u64 = 1_048_576;
const PID_BYTES: u64 = 65_536;
const DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const BENEATH: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

fn error(kind: io::ErrorKind) -> Error {
    match kind {
        io::ErrorKind::NotFound => Error::Missing,
        io::ErrorKind::PermissionDenied => Error::PermissionDenied,
        io::ErrorKind::ReadOnlyFilesystem => Error::ReadOnly,
        io::ErrorKind::NotADirectory | io::ErrorKind::IsADirectory => Error::WrongType,
        io::ErrorKind::Unsupported => Error::UnsupportedKernel,
        _ => Error::Io,
    }
}
fn errno(e: rustix::io::Errno) -> Error {
    match e {
        rustix::io::Errno::NOSYS => Error::UnsupportedKernel,
        rustix::io::Errno::LOOP | rustix::io::Errno::XDEV => Error::WrongType,
        _ => error(io::Error::from(e).kind()),
    }
}
fn magic(file: &File) -> Result<i64, Error> {
    Ok(fs::fstatfs(file).map_err(errno)?.f_type)
}
fn bounded(mut file: File, limit: u64) -> Result<Vec<u8>, Error> {
    if !file.metadata().map_err(|e| error(e.kind()))?.is_file() {
        return Err(Error::WrongType);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| error(e.kind()))?;
    if bytes.len() as u64 > limit {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}
fn proc_bytes(name: &str, limit: u64) -> Result<Vec<u8>, Error> {
    let file = File::from(
        fs::open(
            format!("/proc/thread-self/{name}"),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(errno)?,
    );
    if magic(&file)? != PROC_MAGIC {
        return Err(Error::WrongFilesystem);
    }
    bounded(file, limit)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    mount: u64,
}
fn identity(file: &File) -> Result<Identity, Error> {
    let metadata = file.metadata().map_err(|e| error(e.kind()))?;
    let stat = fs::statx(file, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID).map_err(errno)?;
    if stat.stx_mask & StatxFlags::MNT_ID.bits() == 0 {
        return Err(Error::UnsupportedKernel);
    }
    Ok(Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mount: stat.stx_mnt_id,
    })
}
fn namespace(name: &str) -> Result<File, Error> {
    // The kernel namespace link must be followed; the retained descriptor pins it.
    let file = File::from(
        fs::open(
            format!("/proc/thread-self/ns/{name}"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno)?,
    );
    if magic(&file)? != NS_MAGIC {
        return Err(Error::WrongFilesystem);
    }
    Ok(file)
}
fn namespace_id(file: &File) -> Result<(u64, u64), Error> {
    let metadata = file.metadata().map_err(|e| error(e.kind()))?;
    Ok((metadata.dev(), metadata.ino()))
}
fn root() -> Result<File, Error> {
    Ok(File::from(
        fs::open("/", DIR, Mode::empty()).map_err(errno)?,
    ))
}
fn cgroup_root(root: &File) -> Result<File, Error> {
    // Cross legitimate /sys and cgroup mount boundaries only during fixed-root acquisition.
    let sys = fs::openat(root, "sys", DIR, Mode::empty()).map_err(errno)?;
    let fs_dir = fs::openat(sys, "fs", DIR, Mode::empty()).map_err(errno)?;
    Ok(File::from(
        fs::openat(fs_dir, "cgroup", DIR, Mode::empty()).map_err(errno)?,
    ))
}
fn child(dir: &File, name: &str, flags: OFlags) -> Result<File, Error> {
    let file = File::from(
        fs::openat2(
            dir,
            name,
            flags | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
            BENEATH,
        )
        .map_err(errno)?,
    );
    if magic(&file)? != CGROUP2_MAGIC {
        return Err(Error::WrongFilesystem);
    }
    Ok(file)
}
fn control(dir: &File, name: &str, limit: u64) -> Result<Vec<u8>, Error> {
    bounded(child(dir, name, OFlags::RDONLY)?, limit)
}
fn domain(dir: &File) -> Result<(), Error> {
    match control(dir, "cgroup.type", 64) {
        Ok(bytes) if bytes.trim_ascii() == b"domain" => Ok(()),
        Ok(bytes)
            if matches!(
                bytes.trim_ascii(),
                b"threaded" | b"domain threaded" | b"domain invalid"
            ) =>
        {
            Err(Error::UnsupportedRootType)
        },
        Ok(_) => Err(Error::Malformed),
        Err(Error::Missing) => Err(Error::UnsupportedRootType),
        Err(e) => Err(e),
    }
}
fn contains_pid(bytes: &[u8], pid: u32) -> Result<bool, Error> {
    if bytes.len() as u64 > PID_BYTES {
        return Err(Error::TooLarge);
    }
    let mut found = false;
    for (index, field) in bytes
        .split(u8::is_ascii_whitespace)
        .filter(|s| !s.is_empty())
        .enumerate()
    {
        if index == 4096 {
            return Err(Error::TooLarge);
        }
        if field.len() > 10 || !field.iter().all(u8::is_ascii_digit) {
            return Err(Error::Malformed);
        }
        let value = std::str::from_utf8(field)
            .map_err(|_| Error::Malformed)?
            .parse::<u32>()
            .map_err(|_| Error::Malformed)?;
        if value == 0 {
            return Err(Error::Malformed);
        }
        found |= value == pid;
    }
    Ok(found)
}
fn member(dir: &File, pid: u32) -> Result<bool, Error> {
    contains_pid(&control(dir, "cgroup.procs", PID_BYTES)?, pid)
}
fn write_control(dir: &File, name: &str, bytes: &[u8]) -> Mutation {
    let mut file = match child(dir, name, OFlags::WRONLY) {
        Ok(file) => file,
        Err(e) => {
            return Mutation {
                attempted: false,
                result: Err(e),
            };
        },
    };
    match file.metadata() {
        Ok(metadata) if metadata.is_file() => {},
        Ok(_) => {
            return Mutation {
                attempted: false,
                result: Err(Error::WrongType),
            };
        },
        Err(e) => {
            return Mutation {
                attempted: false,
                result: Err(error(e.kind())),
            };
        },
    }
    // One syscall only: retrying a short PID/controller write could be a different operation.
    let result = match file.write(bytes) {
        Ok(n) if n == bytes.len() => Ok(()),
        Ok(_) => Err(Error::ShortWrite),
        Err(e) => Err(error(e.kind())),
    };
    Mutation {
        attempted: true,
        result,
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Mount {
    id: u64,
    parent: u64,
    device: Vec<u8>,
    root: Vec<u8>,
    point: Vec<u8>,
    shared: bool,
}
fn number(bytes: &[u8]) -> Result<u64, Error> {
    if bytes.is_empty() || bytes.len() > 20 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(Error::Malformed);
    }
    std::str::from_utf8(bytes)
        .map_err(|_| Error::Malformed)?
        .parse()
        .map_err(|_| Error::Malformed)
}
fn mount_path(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut path = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            let Some(escape) = bytes.get(index..index + 4) else {
                return Err(Error::Malformed);
            };
            let decoded = match escape {
                b"\\040" => b' ',
                b"\\011" => b'\t',
                b"\\012" => b'\n',
                b"\\134" => b'\\',
                _ => return Err(Error::Malformed),
            };
            path.push(decoded);
            index += 4;
        } else {
            path.push(bytes[index]);
            index += 1;
        }
    }
    if !path.starts_with(b"/") || path.contains(&0) {
        return Err(Error::Malformed);
    }
    Ok(path)
}
fn mounts(bytes: &[u8]) -> Result<Vec<Mount>, Error> {
    if bytes.len() as u64 > MOUNT_BYTES {
        return Err(Error::TooLarge);
    }
    if bytes.is_empty() || !bytes.ends_with(b"\n") {
        return Err(Error::Malformed);
    }
    let mut mounts = Vec::new();
    for line in bytes[..bytes.len() - 1].split(|b| *b == b'\n') {
        if mounts.len() == 4096 || line.len() > 16_384 {
            return Err(Error::TooLarge);
        }
        let fields: Vec<_> = line.split(|b| *b == b' ').collect();
        if fields.len() > 128 {
            return Err(Error::TooLarge);
        }
        let Some(separator) = fields.iter().position(|f| *f == b"-") else {
            return Err(Error::Malformed);
        };
        if separator < 6 || fields.len() != separator + 4 || fields.iter().any(|f| f.is_empty()) {
            return Err(Error::Malformed);
        }
        let id = number(fields[0])?;
        if id == 0 || mounts.iter().any(|m: &Mount| m.id == id) {
            return Err(Error::Malformed);
        }
        let mut shared = false;
        for field in &fields[6..separator] {
            if let Some(value) = field.strip_prefix(b"shared:") {
                if shared || number(value)? == 0 {
                    return Err(Error::Malformed);
                }
                shared = true;
            }
        }
        mounts.push(Mount {
            id,
            parent: number(fields[1])?,
            device: fields[2].to_vec(),
            root: mount_path(fields[3])?,
            point: mount_path(fields[4])?,
            shared,
        });
    }
    mounts.sort_by_key(|m| m.id);
    Ok(mounts)
}
fn snapshot(root: Identity) -> Result<Vec<Mount>, Error> {
    validate_tree(mounts(&proc_bytes("mountinfo", MOUNT_BYTES)?)?, root.mount)
}
fn validate_tree(mounts: Vec<Mount>, root_mount: u64) -> Result<Vec<Mount>, Error> {
    if !mounts.iter().any(|m| m.id == root_mount && m.point == b"/") {
        return Err(Error::Malformed);
    }
    // Every visible mount must belong to the anchored root tree; disconnected or cyclic
    // records are not accepted as evidence of complete recursive propagation.
    for mount in &mounts {
        let mut id = mount.id;
        for depth in 0..=256 {
            if id == root_mount {
                break;
            }
            if depth == 256 {
                return Err(Error::TooLarge);
            }
            let Ok(index) = mounts.binary_search_by_key(&id, |m| m.id) else {
                return Err(Error::Malformed);
            };
            id = mounts[index].parent;
        }
    }
    Ok(mounts)
}
fn topology_equal(left: &[Mount], right: &[Mount]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(a, b)| {
            a.id == b.id
                && a.parent == b.parent
                && a.device == b.device
                && a.root == b.root
                && a.point == b.point
        })
}
pub(crate) struct LinuxSession {
    root: File,
    root_id: Identity,
    mount_namespace: File,
    cgroup_namespace: File,
    mounts: Vec<Mount>,
    cgroup: Option<File>,
    init: Option<File>,
    pid: u32,
    migrated: bool,
    shared_verified: bool,
}
impl LinuxSession {
    pub(crate) fn open() -> Result<Self, Error> {
        let root = root()?;
        let root_id = identity(&root)?;
        let mount_namespace = namespace("mnt")?;
        let cgroup_namespace = namespace("cgroup")?;
        let mounts = snapshot(root_id)?;
        let session = Self {
            root,
            root_id,
            mount_namespace,
            cgroup_namespace,
            mounts,
            cgroup: None,
            init: None,
            pid: std::process::id(),
            migrated: false,
            shared_verified: false,
        };
        session.guard()?;
        Ok(session)
    }
    fn guard(&self) -> Result<(), Error> {
        let check = || -> Result<(), Error> {
            if identity(&root()?)? != self.root_id
                || namespace_id(&namespace("mnt")?)? != namespace_id(&self.mount_namespace)?
                || namespace_id(&namespace("cgroup")?)? != namespace_id(&self.cgroup_namespace)?
                || std::process::id() != self.pid
            {
                return Err(Error::ContextChanged);
            }
            let current = snapshot(self.root_id)?;
            if !topology_equal(&self.mounts, &current)
                || (self.shared_verified && !current.iter().all(|m| m.shared))
            {
                return Err(Error::ContextChanged);
            }
            if let Some(ref cgroup) = self.cgroup {
                if identity(&cgroup_root(&self.root)?)? != identity(cgroup)? {
                    return Err(Error::ContextChanged);
                }
                if let Some(ref init) = self.init
                    && identity(&child(cgroup, "init", DIR)?)? != identity(init)?
                {
                    return Err(Error::ContextChanged);
                }
            }
            Ok(())
        };
        check().map_err(|_| Error::ContextChanged)
    }
    fn cgroup(&self) -> Result<&File, Error> {
        self.cgroup.as_ref().ok_or(Error::WrongFilesystem)
    }
    fn admission(&self) -> Result<(), Error> {
        self.guard()?;
        let cgroup = self.cgroup()?;
        domain(cgroup)?;
        if !self.migrated && member(cgroup, self.pid)? {
            return Ok(());
        }
        if let Some(ref init) = self.init {
            domain(init)?;
            if member(init, self.pid)? {
                return Ok(());
            }
        }
        Err(Error::MembershipNotAdmitted)
    }
}
impl ContainerSession for LinuxSession {
    fn make_root_shared(&mut self) -> Mutation {
        if let Err(e) = self.guard() {
            return Mutation {
                attempted: false,
                result: Err(e),
            };
        }
        let result = mount_change(
            "/",
            MountPropagationFlags::SHARED | MountPropagationFlags::REC,
        )
        .map_err(errno);
        if let Err(e) = result {
            return Mutation {
                attempted: true,
                result: Err(e),
            };
        }
        let result = (|| {
            self.guard()?;
            let after = snapshot(self.root_id)?;
            if !topology_equal(&self.mounts, &after) || !after.iter().all(|m| m.shared) {
                return Err(Error::MountReadbackUncertain);
            }
            self.mounts = after;
            self.shared_verified = true;
            Ok(())
        })()
        .map_err(|_| Error::MountReadbackUncertain);
        Mutation {
            attempted: true,
            result,
        }
    }
    fn open_cgroups(&mut self) -> Result<CgroupLayout, Error> {
        self.guard()?;
        let cgroup = cgroup_root(&self.root)?;
        match magic(&cgroup)? {
            CGROUP1_MAGIC => return Ok(CgroupLayout::V1),
            CGROUP2_MAGIC => {},
            _ => return Err(Error::WrongFilesystem),
        }
        domain(&cgroup)?;
        let init = match child(&cgroup, "init", DIR) {
            Ok(init) => {
                domain(&init)?;
                Some(init)
            },
            Err(Error::Missing) => None,
            Err(e) => return Err(e),
        };
        self.cgroup = Some(cgroup);
        self.init = init;
        self.admission()?;
        Ok(CgroupLayout::V2)
    }
    fn ensure_init(&mut self) -> Mutation {
        if let Err(e) = self.admission() {
            return Mutation {
                attempted: false,
                result: Err(e),
            };
        }
        if self.init.is_some() {
            return Mutation {
                attempted: false,
                result: Ok(()),
            };
        }
        let result = (|| {
            let cgroup = self.cgroup()?;
            match fs::mkdirat(cgroup, "init", Mode::from_raw_mode(0o755)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {},
                Err(e) => return Err(errno(e)),
            }
            let init = child(cgroup, "init", DIR)?;
            domain(&init)?;
            self.init = Some(init);
            self.guard()
        })();
        Mutation {
            attempted: true,
            result,
        }
    }
    fn migrate_current_process(&mut self) -> Mutation {
        if let Err(e) = self.admission() {
            return Mutation {
                attempted: false,
                result: Err(e),
            };
        }
        let Some(ref init) = self.init else {
            return Mutation {
                attempted: false,
                result: Err(Error::Missing),
            };
        };
        if let Err(e) = domain(init) {
            return Mutation {
                attempted: false,
                result: Err(e),
            };
        }
        let mut mutation = write_control(init, "cgroup.procs", self.pid.to_string().as_bytes());
        if mutation.result.is_ok() {
            mutation.result = (|| {
                self.guard()?;
                if !member(init, self.pid)? {
                    return Err(Error::MigrationUnobserved);
                }
                Ok(())
            })();
        }
        self.migrated = mutation.result.is_ok();
        mutation
    }
    fn available_controllers(&mut self) -> Result<Vec<ControllerName>, Error> {
        self.admission().map_err(|_| Error::ContextChanged)?;
        parse_controllers(&control(self.cgroup()?, "cgroup.controllers", 4096)?)
    }
    fn enabled_controllers(&mut self) -> Result<Vec<ControllerName>, Error> {
        self.admission().map_err(|_| Error::ContextChanged)?;
        parse_controllers(&control(self.cgroup()?, "cgroup.subtree_control", 4096)?)
    }
    fn enable_controllers(&mut self, names: &[ControllerName]) -> Mutation {
        if self.admission().is_err() {
            return Mutation {
                attempted: false,
                result: Err(Error::ContextChanged),
            };
        }
        if names.is_empty() {
            return Mutation {
                attempted: false,
                result: Ok(()),
            };
        }
        if names.len() > 32 {
            return Mutation {
                attempted: false,
                result: Err(Error::TooLarge),
            };
        }
        let text = names
            .iter()
            .map(|name| format!("+{}", name.as_str()))
            .collect::<Vec<_>>()
            .join(" ");
        let cgroup = match self.cgroup() {
            Ok(cgroup) => cgroup,
            Err(e) => {
                return Mutation {
                    attempted: false,
                    result: Err(e),
                };
            },
        };
        write_control(cgroup, "cgroup.subtree_control", text.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const TABLE: &[u8] = b"1 0 8:1 / / rw shared:1 - ext4 /dev/root rw\n2 1 0:2 / /proc rw shared:2 - proc proc rw\n";
    #[test]
    fn mount_tree_requires_complete_bounded_unique_records() {
        let parsed = mounts(TABLE).unwrap();
        assert_eq!(validate_tree(parsed, 1).unwrap().len(), 2);
        assert_eq!(mounts(&TABLE[..TABLE.len() - 1]), Err(Error::Malformed));
        assert_eq!(mounts(&[TABLE, TABLE].concat()), Err(Error::Malformed));
        assert_eq!(
            mounts(b"1 0 8:1 / / rw shared:1 shared:2 - ext4 root rw\n"),
            Err(Error::Malformed)
        );
        assert_eq!(mounts(&vec![b'a'; 1_048_577]), Err(Error::TooLarge));
        assert_eq!(
            mounts(b"1 0 8:1 / / rw shared:x - ext4 root rw\n"),
            Err(Error::Malformed)
        );
        assert_eq!(
            mounts(b"1 0 8:1 / / rw - ext4 root rw extra\n"),
            Err(Error::Malformed)
        );
    }
    #[test]
    fn mount_tree_rejects_missing_root_disconnected_cycles_and_depth_overflow() {
        assert_eq!(
            validate_tree(mounts(TABLE).unwrap(), 9),
            Err(Error::Malformed)
        );
        for text in [
            "1 0 8:1 / / rw - ext4 root rw\n2 3 0:2 / /proc rw - proc proc rw\n",
            "1 0 8:1 / / rw - ext4 root rw\n2 3 0:2 / /proc rw - proc proc rw\n3 2 0:3 / /sys rw - sysfs sysfs rw\n",
        ] {
            assert!(validate_tree(mounts(text.as_bytes()).unwrap(), 1).is_err());
        }
        let mut text = String::from("1 0 8:1 / / rw - ext4 root rw\n");
        for id in 2..260 {
            use std::fmt::Write as _;
            writeln!(text, "{id} {} 0:2 / /p{id} rw - tmpfs tmpfs rw", id - 1).unwrap();
        }
        assert_eq!(
            validate_tree(mounts(text.as_bytes()).unwrap(), 1),
            Err(Error::TooLarge)
        );
    }
    #[test]
    fn mount_paths_decode_only_kernel_escapes_and_keep_bytes() {
        assert_eq!(
            mount_path(b"/x\\040y\\134z\\011t\\012n\xff").unwrap(),
            b"/x y\\z\tt\nn\xff"
        );
        for path in [b"relative".as_slice(), b"/x\\", b"/x\\777", b"/x\0"] {
            assert_eq!(mount_path(path), Err(Error::Malformed));
        }
        let mut changed = mounts(TABLE).unwrap();
        changed[1].point = b"/elsewhere".to_vec();
        assert!(!topology_equal(&mounts(TABLE).unwrap(), &changed));
        let mut shared = mounts(TABLE).unwrap();
        shared[1].shared = false;
        assert!(topology_equal(&mounts(TABLE).unwrap(), &shared));
        assert!(!shared.iter().all(|m| m.shared));
    }
    #[test]
    fn process_membership_accepts_unordered_duplicates_but_not_truncation_or_bad_tokens() {
        assert!(contains_pid(b"42\n3\n42\n", 42).unwrap());
        assert!(!contains_pid(b"3\n", 42).unwrap());
        assert!(!contains_pid(b"", 42).unwrap());
        for bytes in [b"42x".as_slice(), b"0\n", b"4294967296\n", b"-42\n"] {
            assert_eq!(contains_pid(bytes, 42), Err(Error::Malformed));
        }
        assert_eq!(contains_pid(&vec![b' '; 65_537], 42), Err(Error::TooLarge));
        assert_eq!(
            contains_pid("1\n".repeat(4097).as_bytes(), 42),
            Err(Error::TooLarge)
        );
    }
}
