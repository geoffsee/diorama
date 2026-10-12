//! Bounded observations of the exact identity-encoded bytes declared by an inventory.
use crate::{AssetId, DeclaredInventory, Encoding, VerificationError};
use diorama_platform::{Architecture, Libc};
use object::{
    LittleEndian, elf,
    read::elf::{FileHeader, ProgramHeader, SectionHeader},
};
use std::fmt;

#[derive(Clone, Copy, Debug)]
pub struct ElfLimits {
    pub bytes: usize,
    pub program_headers: usize,
    pub section_headers: usize,
    pub dynamic_entries: usize,
    pub interpreter_bytes: usize,
    pub dependency_names: usize,
    pub dependency_name_bytes: usize,
    pub arm_attribute_bytes: usize,
}
impl Default for ElfLimits {
    fn default() -> Self {
        Self {
            bytes: 256 * 1024 * 1024,
            program_headers: 128,
            section_headers: 4096,
            dynamic_entries: 4096,
            interpreter_bytes: 4096,
            dependency_names: 64,
            dependency_name_bytes: 4096,
            arm_attribute_bytes: 256 * 1024,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoaderFamily {
    Glibc,
    Musl,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoaderRelation {
    KnownMismatch,
    Unresolved,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArmFloatAbi {
    NotArm,
    HardFlag,
    SoftFlag,
    Missing,
    Conflicting,
}
/// Header-level observations only; not a proof that an executable can safely run.
#[derive(Debug, PartialEq, Eq)]
pub struct ElfInspection {
    id: AssetId,
    machine: u16,
    elf_type: u16,
    entry: u64,
    flags: u32,
    interpreter: Option<Vec<u8>>,
    loader: LoaderFamily,
    loader_relation: LoaderRelation,
    needed: Vec<Vec<u8>>,
    arm_float: ArmFloatAbi,
    arm_attributes_present: bool,
}
impl ElfInspection {
    pub fn id(&self) -> AssetId {
        self.id
    }
    pub fn machine(&self) -> u16 {
        self.machine
    }
    pub fn elf_type(&self) -> u16 {
        self.elf_type
    }
    pub fn entry(&self) -> u64 {
        self.entry
    }
    pub fn flags(&self) -> u32 {
        self.flags
    }
    pub fn interpreter(&self) -> Option<&[u8]> {
        self.interpreter.as_deref()
    }
    pub fn loader_family(&self) -> LoaderFamily {
        self.loader
    }
    pub fn loader_relation(&self) -> LoaderRelation {
        self.loader_relation
    }
    pub fn needed(&self) -> &[Vec<u8>] {
        &self.needed
    }
    pub fn arm_float_abi(&self) -> ArmFloatAbi {
        self.arm_float
    }
    pub fn arm_attributes_present(&self) -> bool {
        self.arm_attributes_present
    }
}
#[derive(Debug)]
pub enum ElfError {
    InvalidLimits,
    Limit,
    NotIdentity,
    Encoded(VerificationError),
    Malformed,
    Unsupported,
    TargetMismatch,
}
impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "invalid ELF inspection limits",
            Self::Limit => "ELF inspection limit exceeded",
            Self::NotIdentity => "asset is not identity encoded",
            Self::Encoded(_) => "ELF encoded-byte verification failed",
            Self::Malformed => "malformed ELF structure",
            Self::Unsupported => "unsupported ELF structure",
            Self::TargetMismatch => "ELF machine target mismatch",
        })
    }
}
impl std::error::Error for ElfError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Encoded(e) = self {
            Some(e)
        } else {
            None
        }
    }
}
impl DeclaredInventory {
    pub fn inspect_identity_elf(
        &self,
        id: AssetId,
        bytes: &[u8],
        limits: ElfLimits,
    ) -> Result<ElfInspection, ElfError> {
        limits.validate()?;
        if bytes.len() > limits.bytes {
            return Err(ElfError::Limit);
        }
        let blob = self
            .blobs
            .iter()
            .find(|b| b.id == id)
            .ok_or(ElfError::Encoded(VerificationError::NotBundled(id)))?;
        if blob.encoding != Encoding::Identity {
            return Err(ElfError::NotIdentity);
        }
        self.verification_session()
            .verify_encoded_blob(id, bytes)
            .map_err(ElfError::Encoded)?;
        inspect_elf_bytes(self, id, bytes, limits)
    }
}
impl ElfLimits {
    pub(crate) fn validate(self) -> Result<(), ElfError> {
        if [
            self.bytes,
            self.program_headers,
            self.section_headers,
            self.dynamic_entries,
            self.interpreter_bytes,
            self.dependency_names,
            self.dependency_name_bytes,
            self.arm_attribute_bytes,
        ]
        .contains(&0)
        {
            return Err(ElfError::InvalidLimits);
        }
        Ok(())
    }
}
// Callers must bind these immutable bytes to their completed verification/decoding path.
// Kept private to the crate so arbitrary bytes cannot acquire a public combined observation.
pub(crate) fn inspect_elf_bytes(
    inventory: &DeclaredInventory,
    id: AssetId,
    bytes: &[u8],
    limits: ElfLimits,
) -> Result<ElfInspection, ElfError> {
    limits.validate()?;
    if bytes.len() > limits.bytes {
        return Err(ElfError::Limit);
    }
    if bytes.get(..4) != Some(b"\x7fELF") {
        return Err(ElfError::Malformed);
    }
    if bytes.get(5) != Some(&elf::ELFDATA2LSB) {
        return Err(ElfError::TargetMismatch);
    }
    match bytes.get(4) {
        Some(&elf::ELFCLASS32) => {
            inspect::<elf::FileHeader32<LittleEndian>>(inventory, id, bytes, limits, 32)
        },
        Some(&elf::ELFCLASS64) => {
            inspect::<elf::FileHeader64<LittleEndian>>(inventory, id, bytes, limits, 64)
        },
        _ => Err(ElfError::Malformed),
    }
}

fn bounded_range(bytes: &[u8], offset: u64, size: u64) -> Result<&[u8], ElfError> {
    let end = offset.checked_add(size).ok_or(ElfError::Malformed)?;
    let start = usize::try_from(offset).map_err(|_| ElfError::Malformed)?;
    let end = usize::try_from(end).map_err(|_| ElfError::Malformed)?;
    bytes.get(start..end).ok_or(ElfError::Malformed)
}
fn string(bytes: &[u8], limit: usize) -> Result<Vec<u8>, ElfError> {
    let end = bytes
        .iter()
        .take(limit.saturating_add(1))
        .position(|b| *b == 0)
        .ok_or(ElfError::Limit)?;
    if end == 0 || end > limit {
        return Err(ElfError::Malformed);
    }
    Ok(bytes[..end].to_vec())
}
fn inspect<H: FileHeader<Endian = LittleEndian>>(
    inventory: &DeclaredInventory,
    id: AssetId,
    bytes: &[u8],
    limits: ElfLimits,
    class: u8,
) -> Result<ElfInspection, ElfError> {
    let header = H::parse(bytes).map_err(|_| ElfError::Malformed)?;
    let endian = header.endian().map_err(|_| ElfError::Malformed)?;
    let (machine, expected_class) = match inventory.request.target.architecture {
        Architecture::Amd64 => (elf::EM_X86_64, 64),
        Architecture::Arm64 => (elf::EM_AARCH64, 64),
        Architecture::ArmV7 => (elf::EM_ARM, 32),
        Architecture::Riscv64 => (elf::EM_RISCV, 64),
    };
    if header.e_machine(endian) != machine || class != expected_class {
        return Err(ElfError::TargetMismatch);
    }
    if ![elf::ET_EXEC, elf::ET_DYN].contains(&header.e_type(endian)) {
        return Err(ElfError::Unsupported);
    }
    if header.e_version(endian) != 1
        || usize::from(header.e_ehsize(endian)) != std::mem::size_of::<H>()
    {
        return Err(ElfError::Malformed);
    }
    let phnum = header
        .phnum(endian, bytes)
        .map_err(|_| ElfError::Malformed)?;
    let shnum = header
        .shnum(endian, bytes)
        .map_err(|_| ElfError::Malformed)?;
    if phnum > limits.program_headers || shnum > limits.section_headers {
        return Err(ElfError::Limit);
    }
    let ph = header
        .program_headers(endian, bytes)
        .map_err(|_| ElfError::Malformed)?;
    let sh = header
        .section_headers(endian, bytes)
        .map_err(|_| ElfError::Malformed)?;
    if ph.len() != phnum || sh.len() != shnum {
        return Err(ElfError::Malformed);
    }
    let mut result = ElfInspection {
        id,
        machine,
        elf_type: header.e_type(endian),
        entry: header.e_entry(endian).into(),
        flags: header.e_flags(endian),
        interpreter: None,
        loader: LoaderFamily::Unknown,
        loader_relation: LoaderRelation::Unresolved,
        needed: Vec::new(),
        arm_float: ArmFloatAbi::NotArm,
        arm_attributes_present: false,
    };
    let (loads, dynamic) = segments::<H>(bytes, ph, endian, limits, &mut result)?;
    let mut attribute_bytes = 0usize;
    for section in sh {
        if ![elf::SHT_NOBITS, elf::SHT_NULL].contains(&section.sh_type(endian)) {
            bounded_range(
                bytes,
                section.sh_offset(endian).into(),
                section.sh_size(endian).into(),
            )?;
        }
        if machine == elf::EM_ARM && section.sh_type(endian) == elf::SHT_ARM_ATTRIBUTES {
            attribute_bytes = attribute_bytes
                .checked_add(
                    usize::try_from(section.sh_size(endian).into()).map_err(|_| ElfError::Limit)?,
                )
                .ok_or(ElfError::Limit)?;
            if attribute_bytes > limits.arm_attribute_bytes {
                return Err(ElfError::Limit);
            }
            result.arm_attributes_present = true;
        }
    }
    if machine == elf::EM_ARM {
        result.arm_float = match result.flags & 0x600 {
            0x400 => ArmFloatAbi::HardFlag,
            0x200 => ArmFloatAbi::SoftFlag,
            0x600 => ArmFloatAbi::Conflicting,
            _ => ArmFloatAbi::Missing,
        };
        // Flags are reported, not promoted to a full ARMv7/CPU/PCS compatibility verdict.
    }
    if let Some(data) = dynamic {
        result.needed = dependencies(data, class, bytes, &loads, limits)?;
    }
    result.loader = classify_loader(result.interpreter.as_deref());
    if matches!(
        (inventory.request.target.libc, result.loader),
        (Libc::Musl, LoaderFamily::Glibc) | (Libc::Glibc, LoaderFamily::Musl)
    ) {
        result.loader_relation = LoaderRelation::KnownMismatch;
    }
    Ok(result)
}
type LoadRange = (u64, u64, u64);
fn segments<'a, H: FileHeader<Endian = LittleEndian>>(
    bytes: &'a [u8],
    ph: &[H::ProgramHeader],
    endian: LittleEndian,
    limits: ElfLimits,
    result: &mut ElfInspection,
) -> Result<(Vec<LoadRange>, Option<&'a [u8]>), ElfError> {
    let mut executable_entry = false;
    let mut loads = Vec::new();
    let mut dynamic = None;
    for p in ph {
        let offset = p.p_offset(endian).into();
        let size = p.p_filesz(endian).into();
        let data = bounded_range(bytes, offset, size)?;
        let address: u64 = p.p_vaddr(endian).into();
        let memory: u64 = p.p_memsz(endian).into();
        let end = address.checked_add(memory).ok_or(ElfError::Malformed)?;
        match p.p_type(endian) {
            elf::PT_LOAD => {
                if size > memory {
                    return Err(ElfError::Malformed);
                }
                let align: u64 = p.p_align(endian).into();
                if align > 1 && (!align.is_power_of_two() || address % align != offset % align) {
                    return Err(ElfError::Malformed);
                }
                executable_entry |= p.p_flags(endian) & elf::PF_X != 0
                    && result.entry >= address
                    && result.entry < end;
                loads.push((address, size, offset));
            },
            elf::PT_INTERP => {
                if result.interpreter.is_some()
                    || data.last() != Some(&0)
                    || data.len() > limits.interpreter_bytes
                {
                    return Err(ElfError::Malformed);
                }
                let value = string(data, limits.interpreter_bytes)?;
                if value.len() + 1 != data.len() || !value.starts_with(b"/") {
                    return Err(ElfError::Malformed);
                }
                result.interpreter = Some(value);
            },
            elf::PT_DYNAMIC if dynamic.replace(data).is_some() => return Err(ElfError::Malformed),
            _ => {},
        }
    }
    if !executable_entry || result.entry == 0 {
        return Err(ElfError::Unsupported);
    }
    Ok((loads, dynamic))
}
fn classify_loader(value: Option<&[u8]>) -> LoaderFamily {
    match value {
        Some(
            b"/lib64/ld-linux-x86-64.so.2"
            | b"/lib/ld-linux-aarch64.so.1"
            | b"/lib/ld-linux-armhf.so.3"
            | b"/lib/ld-linux-riscv64-lp64d.so.1",
        ) => LoaderFamily::Glibc,
        Some(
            b"/lib/ld-musl-x86_64.so.1"
            | b"/lib/ld-musl-aarch64.so.1"
            | b"/lib/ld-musl-armhf.so.1"
            | b"/lib/ld-musl-riscv64.so.1",
        ) => LoaderFamily::Musl,
        _ => LoaderFamily::Unknown,
    }
}
fn dependencies(
    data: &[u8],
    class: u8,
    bytes: &[u8],
    loads: &[(u64, u64, u64)],
    limits: ElfLimits,
) -> Result<Vec<Vec<u8>>, ElfError> {
    let width = usize::from(class / 8);
    let stride = width * 2;
    if !data.len().is_multiple_of(stride) {
        return Err(ElfError::Malformed);
    }
    if data.len() / stride > limits.dynamic_entries {
        return Err(ElfError::Limit);
    }
    let word = |b: &[u8]| {
        let mut array = [0u8; 8];
        array[..width].copy_from_slice(b);
        u64::from_le_bytes(array)
    };
    let mut needed = Vec::new();
    let mut table = None;
    let mut size = None;
    let mut terminated = false;
    for chunk in data.chunks_exact(stride) {
        let tag = word(&chunk[..width]);
        let value = word(&chunk[width..]);
        if tag == 0 {
            terminated = true;
            break;
        }
        match tag {
            1 => {
                if needed.len() >= limits.dependency_names {
                    return Err(ElfError::Limit);
                }
                needed.push(value);
            },
            5 if table.replace(value).is_some() => return Err(ElfError::Malformed),
            10 if size.replace(value).is_some() => return Err(ElfError::Malformed),
            _ => {},
        }
    }
    if !terminated {
        return Err(ElfError::Malformed);
    }
    if needed.is_empty() {
        return Ok(Vec::new());
    }
    let address = table.ok_or(ElfError::Malformed)?;
    let size = size.ok_or(ElfError::Malformed)?;
    let end = address.checked_add(size).ok_or(ElfError::Malformed)?;
    let mut found = None;
    for &(start, length, offset) in loads {
        let load_end = start.checked_add(length).ok_or(ElfError::Malformed)?;
        if address >= start && end <= load_end {
            if found.is_some() {
                return Err(ElfError::Malformed);
            }
            found = Some(bounded_range(
                bytes,
                offset
                    .checked_add(address - start)
                    .ok_or(ElfError::Malformed)?,
                size,
            )?);
        }
    }
    let strings = found.ok_or(ElfError::Malformed)?;
    needed
        .into_iter()
        .map(|offset| {
            let offset = usize::try_from(offset).map_err(|_| ElfError::Malformed)?;
            string(
                strings.get(offset..).ok_or(ElfError::Malformed)?,
                limits.dependency_name_bytes,
            )
        })
        .collect()
}
