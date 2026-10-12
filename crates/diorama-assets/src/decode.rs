//! Bounded decoding of exactly hash-matched immutable encoded bytes.
use crate::{
    AssetId, DeclaredInventory, ElfError, ElfInspection, ElfLimits, EncodedBlobMatch, Encoding,
    Kind, VerificationError, VerificationSession, catalog,
};
use sha2::{Digest, Sha256};
use std::{
    collections::TryReserveError,
    convert::Infallible,
    fmt,
    io::{self, Read},
};

#[derive(Clone, Copy, Debug)]
pub struct DecodeLimits {
    pub executable_bytes: u64,
    pub image_bytes: u64,
    /// Output bytes at every decoded level plus an EOF/excess probe per attempt/frame.
    pub total_bytes: u64,
}
impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            executable_bytes: 256 * 1024 * 1024,
            image_bytes: 8 * 1024 * 1024 * 1024,
            total_bytes: 32 * 1024 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodePolicyError {
    InvalidLimits,
    NotCompressed,
    Header,
    HeaderLimit,
    Dictionary,
    Window,
    ContentLimit,
    Budget,
    Trailing,
}
pub enum DecodeError<E> {
    Policy(DecodePolicyError),
    Encoded(VerificationError),
    Decoder(io::Error),
    Observer(E),
}
impl<E> fmt::Debug for DecodeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(policy) => f.debug_tuple("Policy").field(policy).finish(),
            Self::Encoded(_) => f.write_str("Encoded(<source retained>)"),
            Self::Decoder(_) => f.write_str("Decoder(<source retained>)"),
            Self::Observer(_) => f.write_str("Observer(<source retained>)"),
        }
    }
}
impl<E> fmt::Display for DecodeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(p) => write!(f, "asset decode policy: {p:?}"),
            Self::Encoded(_) => f.write_str("asset encoded verification failed"),
            Self::Decoder(_) => f.write_str("asset decoder failed"),
            Self::Observer(_) => f.write_str("asset decoded-byte observer failed"),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for DecodeError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoded(e) => Some(e),
            Self::Decoder(e) => Some(e),
            Self::Observer(e) => Some(e),
            Self::Policy(_) => None,
        }
    }
}
impl fmt::Display for DecodePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "asset decode policy: {self:?}")
    }
}
impl std::error::Error for DecodePolicyError {}
/// Successful decompression/checksum/framing observations, not ELF/archive/OCI validation.
#[derive(Clone, Debug)]
pub struct DecodedObservation {
    encoded: EncodedBlobMatch,
    encoding: Encoding,
    decoded_bytes: u64,
    decoded_sha256: [u8; 32],
}
impl DecodedObservation {
    pub fn encoded(&self) -> &EncodedBlobMatch {
        &self.encoded
    }
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }
    pub fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
    pub fn decoded_sha256(&self) -> &[u8; 32] {
        &self.decoded_sha256
    }
}
/// Complete compressed-byte and ELF observations of the same decoded bytes.
/// Does not establish runtime ABI compatibility, production decoded pins or install permission.
///
/// The observations cannot be assembled from unrelated prior results:
/// ```compile_fail
/// use diorama_assets::{DecodedElfInspection, DecodedObservation, ElfInspection};
/// fn combine(decoded: DecodedObservation, elf: ElfInspection) -> DecodedElfInspection {
///     DecodedElfInspection { decoded, elf }
/// }
/// ```
#[derive(Debug)]
pub struct DecodedElfInspection {
    decoded: DecodedObservation,
    elf: ElfInspection,
}
impl DecodedElfInspection {
    pub fn decoded_observation(&self) -> &DecodedObservation {
        &self.decoded
    }
    pub fn elf(&self) -> &ElfInspection {
        &self.elf
    }
}
#[derive(Debug)]
pub enum CompressedElfError {
    NotExecutable,
    Decode(DecodeError<Infallible>),
    Elf(ElfError),
    BufferLimit,
    Allocation(TryReserveError),
}
impl fmt::Display for CompressedElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotExecutable => "asset is not an executable role",
            Self::Decode(_) => "compressed executable decoding failed",
            Self::Elf(_) => "decoded executable ELF inspection failed",
            Self::BufferLimit => "decoded executable buffer limit exceeded",
            Self::Allocation(_) => "decoded executable buffer allocation failed",
        })
    }
}
impl std::error::Error for CompressedElfError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::Elf(error) => Some(error),
            Self::Allocation(error) => Some(error),
            Self::NotExecutable | Self::BufferLimit => None,
        }
    }
}
enum BufferError {
    Limit,
    Allocation(TryReserveError),
}
impl From<DecodeError<BufferError>> for CompressedElfError {
    fn from(error: DecodeError<BufferError>) -> Self {
        match error {
            DecodeError::Policy(error) => Self::Decode(DecodeError::Policy(error)),
            DecodeError::Encoded(error) => Self::Decode(DecodeError::Encoded(error)),
            DecodeError::Decoder(error) => Self::Decode(DecodeError::Decoder(error)),
            DecodeError::Observer(BufferError::Limit) => Self::BufferLimit,
            DecodeError::Observer(BufferError::Allocation(error)) => Self::Allocation(error),
        }
    }
}
fn append_bounded(buffer: &mut Vec<u8>, chunk: &[u8], limit: u64) -> Result<(), BufferError> {
    let length = buffer
        .len()
        .checked_add(chunk.len())
        .ok_or(BufferError::Limit)?;
    if u64::try_from(length).map_err(|_| BufferError::Limit)? > limit {
        return Err(BufferError::Limit);
    }
    // Grow only for actual returned bytes, never for an advertised frame size/full policy cap.
    buffer
        .try_reserve_exact(chunk.len())
        .map_err(BufferError::Allocation)?;
    buffer.extend_from_slice(chunk);
    Ok(())
}
/// The caller owns session lifetime, execution time and any provisional observer effects.
#[derive(Debug)]
pub struct DecodeSession<'a> {
    inventory: &'a DeclaredInventory,
    encoded: VerificationSession<'a>,
    limits: DecodeLimits,
    remaining: u64,
}
impl DeclaredInventory {
    pub fn decoding_session(
        &self,
        limits: DecodeLimits,
    ) -> Result<DecodeSession<'_>, DecodePolicyError> {
        if [
            limits.executable_bytes,
            limits.image_bytes,
            limits.total_bytes,
        ]
        .contains(&0)
            || limits.executable_bytes == u64::MAX
            || limits.image_bytes == u64::MAX
        {
            return Err(DecodePolicyError::InvalidLimits);
        }
        Ok(DecodeSession {
            inventory: self,
            encoded: self.verification_session(),
            limits,
            remaining: limits.total_bytes,
        })
    }
}
impl DecodeSession<'_> {
    pub fn remaining_decoded_budget(&self) -> u64 {
        self.remaining
    }
    pub fn remaining_encoded_budget(&self) -> u64 {
        self.encoded.remaining_budget()
    }
    /// Privately collect bounded provisional bytes, then inspect only a completed stream.
    /// All charged encoded/decoded budget survives collection, decoder and ELF errors.
    /// No caller callback, filesystem write or executable launch occurs.
    pub fn inspect_compressed_elf(
        &mut self,
        id: AssetId,
        bytes: &[u8],
        limits: ElfLimits,
    ) -> Result<DecodedElfInspection, CompressedElfError> {
        limits.validate().map_err(CompressedElfError::Elf)?;
        if !catalog()
            .iter()
            .any(|entry| entry.id == id && entry.kind == Kind::Executable)
        {
            return Err(CompressedElfError::NotExecutable);
        }
        let limit = u64::try_from(limits.bytes)
            .map_err(|_| CompressedElfError::BufferLimit)?
            .min(self.limits.executable_bytes);
        let mut buffer = Vec::new();
        let decoded = self.inspect_compressed_blob_capped(id, bytes, limit, |chunk| {
            append_bounded(&mut buffer, chunk, limit)
        })?;
        // The decoder has reached EOF and checked checksum/framing; hash and parser see
        // the same owned bytes, with no reopen or public provisional effects in between.
        let elf = crate::elf::inspect_elf_bytes(self.inventory, id, &buffer, limits)
            .map_err(CompressedElfError::Elf)?;
        Ok(DecodedElfInspection { decoded, elf })
    }
    pub(crate) fn archive_target(
        &self,
        id: AssetId,
    ) -> Result<diorama_platform::Architecture, crate::archive::ArchivePolicyError> {
        if !catalog()
            .iter()
            .any(|entry| entry.id == id && entry.kind == Kind::Image)
            || !self
                .inventory
                .blobs
                .iter()
                .any(|blob| blob.id == id && blob.encoding == Encoding::Gzip)
        {
            return Err(crate::archive::ArchivePolicyError::NotGzipImage);
        }
        Ok(self.inventory.request.target.architecture)
    }
    /// Chunks are provisional until this returns Ok. Discard them on any error.
    /// Does not flush/commit/undo observer side effects or catch observer panics.
    pub fn inspect_compressed_blob<E, F: FnMut(&[u8]) -> Result<(), E>>(
        &mut self,
        id: AssetId,
        bytes: &[u8],
        observe: F,
    ) -> Result<DecodedObservation, DecodeError<E>> {
        self.inspect_compressed_blob_capped(id, bytes, u64::MAX, observe)
    }
    pub(crate) fn inspect_compressed_blob_capped<E, F: FnMut(&[u8]) -> Result<(), E>>(
        &mut self,
        id: AssetId,
        bytes: &[u8],
        cap: u64,
        mut observe: F,
    ) -> Result<DecodedObservation, DecodeError<E>> {
        self.inspect_compressed_blob_budgeted(id, bytes, cap, |chunk, _| observe(chunk))
    }
    pub(crate) fn inspect_compressed_blob_budgeted<
        E,
        F: FnMut(&[u8], &mut u64) -> Result<(), E>,
    >(
        &mut self,
        id: AssetId,
        bytes: &[u8],
        cap: u64,
        mut observe: F,
    ) -> Result<DecodedObservation, DecodeError<E>> {
        let blob = self
            .inventory
            .blobs
            .iter()
            .find(|b| b.id == id)
            .ok_or(DecodeError::Encoded(VerificationError::NotBundled(id)))?;
        if blob.encoding == Encoding::Identity {
            return Err(DecodeError::Policy(DecodePolicyError::NotCompressed));
        }
        let encoding = blob.encoding;
        let per_blob = if catalog()
            .iter()
            .any(|entry| entry.id == id && entry.kind == Kind::Image)
        {
            self.limits.image_bytes
        } else {
            self.limits.executable_bytes
        };
        // Reserve a probe before hashing, header parsing, decoder allocation or callbacks.
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(DecodeError::Policy(DecodePolicyError::Budget))?;
        let maximum = per_blob.min(cap);
        let encoded = self
            .encoded
            .verify_encoded_blob(id, bytes)
            .map_err(DecodeError::Encoded)?;
        let (count, sha) = match encoding {
            Encoding::Zstd => {
                zstd_header(bytes, maximum.min(self.remaining)).map_err(DecodeError::Policy)?;
                let mut decoder = zstd::stream::read::Decoder::with_buffer(bytes)
                    .map_err(DecodeError::Decoder)?
                    .single_frame();
                decoder.window_log_max(26).map_err(DecodeError::Decoder)?;
                let result = consume(&mut decoder, maximum, &mut self.remaining, &mut observe)?;
                if !decoder.finish().is_empty() {
                    return Err(DecodeError::Policy(DecodePolicyError::Trailing));
                }
                result
            },
            Encoding::Gzip => {
                gzip_header(bytes).map_err(DecodeError::Policy)?;
                let mut decoder = flate2::bufread::GzDecoder::new(bytes);
                let result = consume(&mut decoder, maximum, &mut self.remaining, &mut observe)?;
                if !decoder.into_inner().is_empty() {
                    return Err(DecodeError::Policy(DecodePolicyError::Trailing));
                }
                result
            },
            Encoding::Identity => {
                return Err(DecodeError::Policy(DecodePolicyError::NotCompressed));
            },
        };
        Ok(DecodedObservation {
            encoded,
            encoding,
            decoded_bytes: count,
            decoded_sha256: sha,
        })
    }
}
fn consume<E, F: FnMut(&[u8], &mut u64) -> Result<(), E>>(
    reader: &mut impl Read,
    maximum: u64,
    remaining: &mut u64,
    observe: &mut F,
) -> Result<(u64, [u8; 32]), DecodeError<E>> {
    let mut count = 0u64;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        // maximum excludes the reserved one-byte excess/EOF probe.
        // Nested observers may debit this same budget. Never reuse a pre-callback allowance.
        let allowance = (maximum - count).min(*remaining);
        let capacity = usize::try_from((allowance + 1).min(8192))
            .map_err(|_| DecodeError::Policy(DecodePolicyError::Budget))?;
        let read = match reader.read(&mut buffer[..capacity]) {
            Ok(read) => read,
            Err(error) => {
                // A decoder can write output and then fail without reporting its length.
                // Retain the offered capacity; the reserved probe covers any excess byte.
                let charge = u64::try_from(capacity)
                    .map_err(|_| DecodeError::Policy(DecodePolicyError::Budget))?
                    .min(allowance);
                *remaining = remaining
                    .checked_sub(charge)
                    .ok_or(DecodeError::Policy(DecodePolicyError::Budget))?;
                return Err(DecodeError::Decoder(error));
            },
        };
        if read == 0 {
            return Ok((count, hash.finalize().into()));
        }
        let read =
            u64::try_from(read).map_err(|_| DecodeError::Policy(DecodePolicyError::Budget))?;
        let admitted = read.min(allowance);
        *remaining = remaining
            .checked_sub(admitted)
            .ok_or(DecodeError::Policy(DecodePolicyError::Budget))?;
        if read > allowance {
            return Err(DecodeError::Policy(DecodePolicyError::ContentLimit));
        }
        count += read;
        let length =
            usize::try_from(read).map_err(|_| DecodeError::Policy(DecodePolicyError::Budget))?;
        hash.update(&buffer[..length]);
        observe(&buffer[..length], remaining).map_err(DecodeError::Observer)?;
    }
}
fn zstd_header(bytes: &[u8], maximum: u64) -> Result<(), DecodePolicyError> {
    if bytes.get(..4) != Some(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Err(DecodePolicyError::Header);
    }
    let descriptor = *bytes.get(4).ok_or(DecodePolicyError::Header)?;
    if descriptor & 0x18 != 0 {
        return Err(DecodePolicyError::Header);
    }
    let single = descriptor & 0x20 != 0;
    let mut position = 5;
    let window = if single {
        None
    } else {
        let descriptor = *bytes.get(position).ok_or(DecodePolicyError::Header)?;
        position += 1;
        let base = 1u64 << (10 + u32::from(descriptor >> 3));
        Some(base + (base / 8) * u64::from(descriptor & 7))
    };
    let dictionary_length = match descriptor & 3 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let dictionary = bytes
        .get(position..position + dictionary_length)
        .ok_or(DecodePolicyError::Header)?;
    if dictionary.iter().any(|byte| *byte != 0) {
        return Err(DecodePolicyError::Dictionary);
    }
    position += dictionary_length;
    let size_length = match descriptor >> 6 {
        0 => usize::from(single),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let field = bytes
        .get(position..position + size_length)
        .ok_or(DecodePolicyError::Header)?;
    let mut size = [0u8; 8];
    size[..size_length].copy_from_slice(field);
    let size = u64::from_le_bytes(size) + if size_length == 2 { 256 } else { 0 };
    if size_length > 0 && size > maximum {
        return Err(DecodePolicyError::ContentLimit);
    }
    if window.unwrap_or(size) > 64 * 1024 * 1024 {
        return Err(DecodePolicyError::Window);
    }
    Ok(())
}
fn gzip_header(bytes: &[u8]) -> Result<(), DecodePolicyError> {
    const LIMIT: usize = 8192;
    if bytes.get(..3) != Some(&[0x1f, 0x8b, 8]) || bytes.len() < 10 {
        return Err(DecodePolicyError::Header);
    }
    let flags = bytes[3];
    if flags & 0xe0 != 0 {
        return Err(DecodePolicyError::Header);
    }
    let mut position = 10usize;
    if flags & 4 != 0 {
        let field = bytes
            .get(position..position + 2)
            .ok_or(DecodePolicyError::Header)?;
        position += 2 + usize::from(u16::from_le_bytes([field[0], field[1]]));
        if position > LIMIT {
            return Err(DecodePolicyError::HeaderLimit);
        }
        if position > bytes.len() {
            return Err(DecodePolicyError::Header);
        }
    }
    for flag in [8, 16] {
        if flags & flag != 0 {
            let bounded = bytes
                .get(position..bytes.len().min(LIMIT))
                .ok_or(DecodePolicyError::HeaderLimit)?;
            let length = bounded
                .iter()
                .position(|byte| *byte == 0)
                .ok_or(DecodePolicyError::HeaderLimit)?;
            position += length + 1;
        }
    }
    if flags & 2 != 0 {
        position += 2;
    }
    if position > LIMIT {
        return Err(DecodePolicyError::HeaderLimit);
    }
    if position > bytes.len() {
        return Err(DecodePolicyError::Header);
    }
    Ok(())
}

#[cfg(test)]
mod error_budget_tests {
    use super::*;
    use std::convert::Infallible;

    struct WritesThenFails;
    impl Read for WritesThenFails {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            buffer.fill(0x61);
            Err(io::Error::other("output length unavailable"))
        }
    }

    struct SucceedsThenFails {
        capacities: Vec<usize>,
    }
    impl Read for SucceedsThenFails {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.capacities.push(buffer.len());
            if self.capacities.len() == 1 {
                buffer[..3].copy_from_slice(b"abc");
                Ok(3)
            } else {
                buffer.fill(b'x');
                Err(io::Error::other("failed after nested observer"))
            }
        }
    }

    #[test]
    fn failed_outer_read_uses_budget_remaining_after_nested_observer() {
        for (after_nested, capacity, charged) in
            [(0, 1, 0), (2, 3, 2), (8191, 8192, 8191), (9000, 8192, 8192)]
        {
            let mut reader = SucceedsThenFails {
                capacities: Vec::new(),
            };
            let mut remaining = 20000;
            let mut callbacks = 0;
            let result = consume(&mut reader, 20000, &mut remaining, &mut |bytes, budget| {
                assert_eq!(bytes, b"abc");
                assert_eq!(*budget, 19997);
                *budget = after_nested;
                callbacks += 1;
                Ok::<_, Infallible>(())
            });
            assert!(matches!(result, Err(DecodeError::Decoder(_))));
            assert_eq!(reader.capacities, [8192, capacity]);
            assert_eq!(remaining, after_nested - charged);
            assert_eq!(callbacks, 1);
        }
    }

    #[test]
    fn failed_read_retains_offered_capacity_without_observing_output() {
        for (allowance, charged) in [(0, 0), (2, 2), (8191, 8191), (9000, 8192)] {
            let mut remaining = allowance;
            let mut callbacks = 0;
            let result = consume(
                &mut WritesThenFails,
                allowance,
                &mut remaining,
                &mut |_, _| {
                    callbacks += 1;
                    Ok::<_, Infallible>(())
                },
            );
            assert!(matches!(result, Err(DecodeError::Decoder(_))));
            assert_eq!(remaining, allowance - charged);
            assert_eq!(callbacks, 0);
        }
    }
}
