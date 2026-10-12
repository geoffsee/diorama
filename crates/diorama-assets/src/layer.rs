//! Bounded nested byte-stream integrity. No inner tar interpretation or materialization.
use crate::archive::{ArchiveParser, LayerObserver};
use crate::{
    ArchiveError, ArchiveLimits, ArchivePolicyError, AssetId, DecodeSession,
    DockerArchiveObservation,
};
use flate2::{Crc, Decompress, FlushDecompress, Status};
use sha2::{Digest, Sha256};
use zstd::stream::raw::{DParameter, Decoder, InBuffer, Operation, OutBuffer};

#[derive(Clone, Copy, Debug)]
pub struct LayerDecodeLimits {
    pub stored_bytes: u64,
    pub decoded_bytes: u64,
    pub unique_decoded_bytes: u64,
    pub ordered_decoded_bytes: u64,
    pub frames: u32,
    /// Maximum gzip header bytes per member, including optional fields (at most 8192).
    pub header_bytes: usize,
    /// Maximum zstd window log, 10 through 26 inclusive.
    pub window_log: u32,
}
impl Default for LayerDecodeLimits {
    fn default() -> Self {
        Self {
            stored_bytes: 8 << 30,
            decoded_bytes: 8 << 30,
            unique_decoded_bytes: 16 << 30,
            ordered_decoded_bytes: 32 << 30,
            frames: 1024,
            header_bytes: 8192,
            window_log: 26,
        }
    }
}
impl LayerDecodeLimits {
    fn validate(self) -> Result<(), LayerPolicyError> {
        if [
            self.stored_bytes,
            self.decoded_bytes,
            self.unique_decoded_bytes,
            self.ordered_decoded_bytes,
        ]
        .iter()
        .any(|n| *n == 0 || *n == u64::MAX)
            || self.frames == 0
            || !(10..=8192).contains(&self.header_bytes)
            || !(10..=26).contains(&self.window_log)
        {
            return Err(LayerPolicyError::InvalidLimits);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayerPolicyError {
    InvalidLimits,
    StoredLimit,
    DecodedLimit,
    UniqueLimit,
    OrderedLimit,
    Budget,
    FrameLimit,
    HeaderLimit,
    UnsupportedCodec,
    Header,
    Dictionary,
    Window,
    Checksum,
    Truncated,
    Decoder,
    NoProgress,
    DiffId,
    Allocation,
}
impl std::fmt::Display for LayerPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "layer byte-stream policy: {self:?}")
    }
}
impl std::error::Error for LayerPolicyError {}
impl From<LayerPolicyError> for ArchivePolicyError {
    fn from(value: LayerPolicyError) -> Self {
        Self::Layer(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayerCodec {
    Gzip,
    Zstd,
}
/// Complete stored-byte and decoded-byte identities; not inner tar structure or safe paths.
#[derive(Clone, Debug)]
pub struct LayerDigestObservation {
    stored_sha256: [u8; 32],
    stored_bytes: u64,
    codec: LayerCodec,
    decoded_bytes: u64,
    diff_id: [u8; 32],
    frames: u32,
}
impl LayerDigestObservation {
    pub fn stored_sha256(&self) -> &[u8; 32] {
        &self.stored_sha256
    }
    pub fn stored_bytes(&self) -> u64 {
        self.stored_bytes
    }
    pub fn codec(&self) -> LayerCodec {
        self.codec
    }
    pub fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
    pub fn diff_id(&self) -> &[u8; 32] {
        &self.diff_id
    }
    pub fn frames(&self) -> u32 {
        self.frames
    }
}
/// Outer archive closure and ordered decoded-stream hashes matched to declared `DiffIDs`.
/// No registry provenance, inner tar safety, encryption detection or import authorization.
/// ```compile_fail
/// use diorama_assets::{DockerArchiveObservation, LayerDigestArchiveObservation};
/// fn forge(archive: DockerArchiveObservation) -> LayerDigestArchiveObservation {
///     LayerDigestArchiveObservation { archive, layers: vec![] }
/// }
/// ```
#[derive(Debug)]
pub struct LayerDigestArchiveObservation {
    archive: DockerArchiveObservation,
    layers: Vec<LayerDigestObservation>,
}
impl LayerDigestArchiveObservation {
    pub fn archive(&self) -> &DockerArchiveObservation {
        &self.archive
    }
    pub fn layers(&self) -> &[LayerDigestObservation] {
        &self.layers
    }
}
impl DecodeSession<'_> {
    /// Match complete nested gzip/zstd byte-stream hashes to ordered declared `DiffIDs`.
    /// Shared session charges survive all failures. No inner tar validation or side effects.
    pub fn verify_crane_image_layer_digests(
        &mut self,
        id: AssetId,
        bytes: &[u8],
        archive_limits: ArchiveLimits,
        layer_limits: LayerDecodeLimits,
    ) -> Result<LayerDigestArchiveObservation, ArchiveError> {
        archive_limits.validate().map_err(ArchiveError::Policy)?;
        layer_limits
            .validate()
            .map_err(|e| ArchiveError::Policy(e.into()))?;
        let architecture = self.archive_target(id).map_err(ArchiveError::Policy)?;
        let mut parser = ArchiveParser::new(archive_limits);
        let mut layers = Layers {
            limits: layer_limits,
            current: None,
            completed: Vec::new(),
            remaining: layer_limits.unique_decoded_bytes,
        };
        let decoded = self
            .inspect_compressed_blob_budgeted(
                id,
                bytes,
                archive_limits.archive_bytes,
                |chunk, budget| parser.push_observing(chunk, &mut layers, budget),
            )
            .map_err(ArchiveError::Decode)?;
        let archive = parser
            .finish(decoded, architecture)
            .map_err(ArchiveError::Policy)?;
        layers
            .finish(archive)
            .map_err(|e| ArchiveError::Policy(e.into()))
    }
}
struct Layers {
    limits: LayerDecodeLimits,
    current: Option<Stream>,
    completed: Vec<LayerDigestObservation>,
    remaining: u64,
}
impl LayerObserver for Layers {
    fn start(&mut self, size: u64, _budget: &mut u64) -> Result<(), ArchivePolicyError> {
        if size > self.limits.stored_bytes {
            return Err(LayerPolicyError::StoredLimit.into());
        }
        self.current = Some(Stream::new(size, self.limits));
        Ok(())
    }
    fn push(&mut self, bytes: &[u8], budget: &mut u64) -> Result<(), ArchivePolicyError> {
        self.current
            .as_mut()
            .ok_or(LayerPolicyError::Header)?
            .push(bytes, budget, &mut self.remaining)
            .map_err(Into::into)
    }
    fn end(&mut self, digest: [u8; 32]) -> Result<(), ArchivePolicyError> {
        let value = self
            .current
            .take()
            .ok_or(LayerPolicyError::Header)?
            .finish(digest)?;
        self.completed
            .try_reserve(1)
            .map_err(|_| LayerPolicyError::Allocation)?;
        self.completed.push(value);
        Ok(())
    }
}
impl Layers {
    fn finish(
        self,
        archive: DockerArchiveObservation,
    ) -> Result<LayerDigestArchiveObservation, LayerPolicyError> {
        let mut layers = Vec::new();
        let mut remaining = self.limits.ordered_decoded_bytes;
        layers
            .try_reserve_exact(archive.layers().len())
            .map_err(|_| LayerPolicyError::Allocation)?;
        for declared in archive.layers() {
            let observed = self
                .completed
                .iter()
                .find(|v| v.stored_sha256 == *declared.sha256())
                .ok_or(LayerPolicyError::DiffId)?;
            if observed.diff_id != *declared.declared_diff_id() {
                return Err(LayerPolicyError::DiffId);
            }
            remaining = remaining
                .checked_sub(observed.decoded_bytes)
                .ok_or(LayerPolicyError::OrderedLimit)?;
            layers.push(observed.clone());
        }
        Ok(LayerDigestArchiveObservation { archive, layers })
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Header,
    GzipHeader,
    GzipBody,
    GzipTrailer,
    ZstdHeader,
    ZstdBody,
}
#[derive(Clone, Copy)]
enum GzipPart {
    Fixed,
    ExtraLength,
    Extra(usize),
    Name,
    Comment,
    Crc,
}
struct Stream {
    limits: LayerDecodeLimits,
    stored: u64,
    codec: Option<LayerCodec>,
    mode: Mode,
    header: [u8; 8192],
    used: usize,
    part: GzipPart,
    flags: u8,
    field_start: usize,
    inflate: Option<Decompress>,
    zstd: Option<Decoder<'static>>,
    crc: Crc,
    hash: Sha256,
    count: u64,
    frames: u32,
}
impl Stream {
    fn new(stored: u64, limits: LayerDecodeLimits) -> Self {
        Self {
            limits,
            stored,
            codec: None,
            mode: Mode::Header,
            header: [0; 8192],
            used: 0,
            part: GzipPart::Fixed,
            flags: 0,
            field_start: 0,
            inflate: None,
            zstd: None,
            crc: Crc::new(),
            hash: Sha256::new(),
            count: 0,
            frames: 0,
        }
    }
    fn push(
        &mut self,
        mut bytes: &[u8],
        budget: &mut u64,
        unique: &mut u64,
    ) -> Result<(), LayerPolicyError> {
        let mut drain = false;
        while !bytes.is_empty() || drain {
            drain = false;
            match self.mode {
                Mode::Header | Mode::GzipHeader | Mode::ZstdHeader => {
                    let Some((&byte, rest)) = bytes.split_first() else {
                        break;
                    };
                    self.header_byte(byte, budget, unique)?;
                    bytes = rest;
                },
                Mode::GzipBody | Mode::ZstdBody => {
                    let (read, again) = self.body_step(bytes, budget, unique)?;
                    bytes = &bytes[read..];
                    drain = again;
                },
                Mode::GzipTrailer => {
                    let Some((&byte, rest)) = bytes.split_first() else {
                        break;
                    };
                    self.trailer_byte(byte)?;
                    bytes = rest;
                },
            }
        }
        Ok(())
    }
    fn header_byte(
        &mut self,
        byte: u8,
        budget: &mut u64,
        unique: &mut u64,
    ) -> Result<(), LayerPolicyError> {
        if self.mode == Mode::Header && self.used == 0 {
            self.frames = self
                .frames
                .checked_add(1)
                .ok_or(LayerPolicyError::FrameLimit)?;
            if self.frames > self.limits.frames {
                return Err(LayerPolicyError::FrameLimit);
            }
            // Charge even empty frames and failed headers before any decoder allocation.
            *budget = budget.checked_sub(1).ok_or(LayerPolicyError::Budget)?;
        }
        if self.used == self.header.len() {
            return Err(LayerPolicyError::HeaderLimit);
        }
        self.header[self.used] = byte;
        self.used += 1;
        if self.mode == Mode::Header && self.used == 4 {
            let codec = if self.header[..3] == [0x1f, 0x8b, 8] {
                LayerCodec::Gzip
            } else if self.header[..4] == [0x28, 0xb5, 0x2f, 0xfd] {
                LayerCodec::Zstd
            } else {
                return Err(LayerPolicyError::UnsupportedCodec);
            };
            if self.codec.is_some_and(|prior| prior != codec) {
                return Err(LayerPolicyError::UnsupportedCodec);
            }
            self.codec = Some(codec);
            self.mode = match codec {
                LayerCodec::Gzip => Mode::GzipHeader,
                LayerCodec::Zstd => Mode::ZstdHeader,
            };
            self.part = GzipPart::Fixed;
        }
        if self.mode == Mode::GzipHeader && self.gzip_header()? {
            self.inflate = Some(Decompress::new(false));
            self.crc.reset();
            self.mode = Mode::GzipBody;
        } else if self.mode == Mode::ZstdHeader && self.zstd_header_ready()? {
            self.check_zstd_header(*budget, *unique)?;
            let mut decoder = Decoder::new().map_err(|_| LayerPolicyError::Decoder)?;
            decoder
                .set_parameter(DParameter::WindowLogMax(self.limits.window_log))
                .map_err(|_| LayerPolicyError::Window)?;
            self.zstd = Some(decoder);
            self.mode = Mode::ZstdBody;
            let mut prefix = [0; 18];
            prefix[..self.used].copy_from_slice(&self.header[..self.used]);
            // A zstd decoder consumes its own bounded frame header before any body.
            let mut input = InBuffer::around(&prefix[..self.used]);
            let mut buffer = [0; 1];
            let mut output = OutBuffer::around(&mut buffer[..]);
            let status = self
                .zstd
                .as_mut()
                .ok_or(LayerPolicyError::Decoder)?
                .run(&mut input, &mut output);
            let written = output.pos();
            let allowance = (self.limits.decoded_bytes - self.count)
                .min(*budget)
                .min(*unique);
            if status.is_err() || input.pos() != self.used || written != 0 {
                self.charge_failed_capacity(buffer.len(), allowance, budget, unique)?;
                return Err(LayerPolicyError::Decoder);
            }
        }
        Ok(())
    }
    fn body_step(
        &mut self,
        bytes: &[u8],
        budget: &mut u64,
        unique: &mut u64,
    ) -> Result<(usize, bool), LayerPolicyError> {
        let allowance = (self.limits.decoded_bytes - self.count)
            .min(*budget)
            .min(*unique);
        let capacity = usize::try_from((allowance + 1).min(8192))
            .map_err(|_| LayerPolicyError::DecodedLimit)?;
        let mut output = [0; 8192];
        let (read, written, ended, failed) = if self.mode == Mode::GzipBody {
            let decoder = self.inflate.as_mut().ok_or(LayerPolicyError::Decoder)?;
            let before_in = decoder.total_in();
            let before_out = decoder.total_out();
            let status = decoder.decompress(bytes, &mut output[..capacity], FlushDecompress::None);
            (
                usize::try_from(decoder.total_in() - before_in)
                    .map_err(|_| LayerPolicyError::Decoder)?,
                usize::try_from(decoder.total_out() - before_out)
                    .map_err(|_| LayerPolicyError::Decoder)?,
                matches!(status, Ok(Status::StreamEnd)),
                status.is_err(),
            )
        } else {
            let mut input = InBuffer::around(bytes);
            let mut out = OutBuffer::around(&mut output[..capacity]);
            let status = self
                .zstd
                .as_mut()
                .ok_or(LayerPolicyError::Decoder)?
                .run(&mut input, &mut out);
            (
                input.pos(),
                out.pos(),
                matches!(status, Ok(0)),
                status.is_err(),
            )
        };
        if failed {
            // A native decoder can write bytes before returning an error without updating
            // output positions. Retain the whole offered capacity, never hash this buffer.
            self.charge_failed_capacity(capacity, allowance, budget, unique)?;
            return Err(LayerPolicyError::Decoder);
        }
        self.admit(&output[..written], allowance, budget, unique)?;
        if ended {
            self.used = 0;
            if self.mode == Mode::GzipBody {
                self.mode = Mode::GzipTrailer;
                self.inflate = None;
            } else {
                self.mode = Mode::Header;
                self.zstd = None;
            }
        } else {
            if read == 0 && written == 0 {
                if bytes.is_empty() {
                    return Ok((0, false));
                }
                return Err(LayerPolicyError::NoProgress);
            }
            return Ok((read, written == capacity));
        }
        Ok((read, false))
    }
    fn trailer_byte(&mut self, byte: u8) -> Result<(), LayerPolicyError> {
        self.header[self.used] = byte;
        self.used += 1;
        if self.used == 8 {
            let crc = u32::from_le_bytes(
                self.header[..4]
                    .try_into()
                    .map_err(|_| LayerPolicyError::Checksum)?,
            );
            let size = u32::from_le_bytes(
                self.header[4..8]
                    .try_into()
                    .map_err(|_| LayerPolicyError::Checksum)?,
            );
            if crc != self.crc.sum() || size != self.crc.amount() {
                return Err(LayerPolicyError::Checksum);
            }
            self.used = 0;
            self.mode = Mode::Header;
        }
        Ok(())
    }
    fn charge_failed_capacity(
        &mut self,
        capacity: usize,
        allowance: u64,
        budget: &mut u64,
        unique: &mut u64,
    ) -> Result<(), LayerPolicyError> {
        let charged = u64::try_from(capacity)
            .map_err(|_| LayerPolicyError::Budget)?
            .min(allowance);
        // Capacity can exceed allowance by only one byte, covered by this frame's
        // already retained probe. Do not count that reserved excess byte twice.
        *budget = budget
            .checked_sub(charged)
            .ok_or(LayerPolicyError::Budget)?;
        *unique = unique
            .checked_sub(charged)
            .ok_or(LayerPolicyError::UniqueLimit)?;
        self.count = self
            .count
            .checked_add(charged)
            .ok_or(LayerPolicyError::DecodedLimit)?;
        Ok(())
    }
    fn admit(
        &mut self,
        bytes: &[u8],
        allowance: u64,
        budget: &mut u64,
        unique: &mut u64,
    ) -> Result<(), LayerPolicyError> {
        let length = u64::try_from(bytes.len()).map_err(|_| LayerPolicyError::DecodedLimit)?;
        let admitted = length.min(allowance);
        *budget = budget
            .checked_sub(admitted)
            .ok_or(LayerPolicyError::Budget)?;
        *unique = unique
            .checked_sub(admitted)
            .ok_or(LayerPolicyError::UniqueLimit)?;
        self.count = self
            .count
            .checked_add(admitted)
            .ok_or(LayerPolicyError::DecodedLimit)?;
        if length > allowance {
            return Err(if self.count == self.limits.decoded_bytes {
                LayerPolicyError::DecodedLimit
            } else if *unique == 0 {
                LayerPolicyError::UniqueLimit
            } else {
                LayerPolicyError::Budget
            });
        }
        self.hash.update(bytes);
        self.crc.update(bytes);
        Ok(())
    }
    fn gzip_header(&mut self) -> Result<bool, LayerPolicyError> {
        if self.used > self.limits.header_bytes {
            return Err(LayerPolicyError::HeaderLimit);
        }
        match self.part {
            GzipPart::Fixed => {
                if self.used < 10 {
                    return Ok(false);
                }
                self.flags = self.header[3];
                if self.flags & 0xe0 != 0 {
                    return Err(LayerPolicyError::Header);
                }
                if self.flags & 4 != 0 {
                    self.part = GzipPart::ExtraLength;
                    self.field_start = self.used;
                    Ok(false)
                } else {
                    Ok(self.gzip_after_extra())
                }
            },
            GzipPart::ExtraLength => {
                if self.used - self.field_start < 2 {
                    return Ok(false);
                }
                let n = usize::from(u16::from_le_bytes([
                    self.header[self.used - 2],
                    self.header[self.used - 1],
                ]));
                if n > self.limits.header_bytes - self.used {
                    return Err(LayerPolicyError::HeaderLimit);
                }
                if n == 0 {
                    Ok(self.gzip_after_extra())
                } else {
                    self.part = GzipPart::Extra(n);
                    Ok(false)
                }
            },
            GzipPart::Extra(n) => {
                if n == 1 {
                    Ok(self.gzip_after_extra())
                } else {
                    self.part = GzipPart::Extra(n - 1);
                    Ok(false)
                }
            },
            GzipPart::Name => {
                if self.header[self.used - 1] == 0 {
                    Ok(self.gzip_after_name())
                } else {
                    Ok(false)
                }
            },
            GzipPart::Comment => {
                if self.header[self.used - 1] == 0 {
                    Ok(self.gzip_after_comment())
                } else {
                    Ok(false)
                }
            },
            GzipPart::Crc => {
                if self.used - self.field_start < 2 {
                    return Ok(false);
                }
                let mut crc = Crc::new();
                crc.update(&self.header[..self.used - 2]);
                let actual =
                    u16::from_le_bytes([self.header[self.used - 2], self.header[self.used - 1]]);
                if actual != (crc.sum() & 0xffff) as u16 {
                    return Err(LayerPolicyError::Checksum);
                }
                Ok(true)
            },
        }
    }
    fn gzip_after_extra(&mut self) -> bool {
        if self.flags & 8 != 0 {
            self.part = GzipPart::Name;
            false
        } else {
            self.gzip_after_name()
        }
    }
    fn gzip_after_name(&mut self) -> bool {
        if self.flags & 16 != 0 {
            self.part = GzipPart::Comment;
            false
        } else {
            self.gzip_after_comment()
        }
    }
    fn gzip_after_comment(&mut self) -> bool {
        if self.flags & 2 != 0 {
            self.part = GzipPart::Crc;
            self.field_start = self.used;
            false
        } else {
            true
        }
    }
    fn zstd_header_ready(&self) -> Result<bool, LayerPolicyError> {
        if self.used < 5 {
            return Ok(false);
        }
        let d = self.header[4];
        if d & 0x18 != 0 {
            return Err(LayerPolicyError::Header);
        }
        if d & 3 != 0 {
            return Err(LayerPolicyError::Dictionary);
        }
        let single = d & 0x20 != 0;
        let n = 5
            + usize::from(!single)
            + match d >> 6 {
                0 => usize::from(single),
                1 => 2,
                2 => 4,
                _ => 8,
            };
        Ok(self.used == n)
    }
    fn check_zstd_header(&self, budget: u64, unique: u64) -> Result<(), LayerPolicyError> {
        let d = self.header[4];
        let single = d & 0x20 != 0;
        let start = 5 + usize::from(!single);
        let length = self.used - start;
        let mut raw = [0; 8];
        raw[..length].copy_from_slice(&self.header[start..self.used]);
        let size = u64::from_le_bytes(raw)
            .checked_add(if length == 2 { 256 } else { 0 })
            .ok_or(LayerPolicyError::Header)?;
        if length > 0 {
            if size > self.limits.decoded_bytes - self.count {
                return Err(LayerPolicyError::DecodedLimit);
            }
            if size > unique {
                return Err(LayerPolicyError::UniqueLimit);
            }
            if size > budget {
                return Err(LayerPolicyError::Budget);
            }
        }
        let window = if single {
            size
        } else {
            let w = self.header[5];
            let base = 1u64 << (10 + u32::from(w >> 3));
            base + (base / 8) * u64::from(w & 7)
        };
        if window > 1u64 << self.limits.window_log {
            return Err(LayerPolicyError::Window);
        }
        Ok(())
    }
    fn finish(self, digest: [u8; 32]) -> Result<LayerDigestObservation, LayerPolicyError> {
        if self.mode != Mode::Header || self.used != 0 || self.frames == 0 {
            return Err(LayerPolicyError::Truncated);
        }
        Ok(LayerDigestObservation {
            stored_sha256: digest,
            stored_bytes: self.stored,
            codec: self.codec.ok_or(LayerPolicyError::UnsupportedCodec)?,
            decoded_bytes: self.count,
            diff_id: self.hash.finalize().into(),
            frames: self.frames,
        })
    }
}

#[cfg(test)]
use crate::archive::vectors as test_vectors;
#[cfg(test)]
mod tests {
    use super::*;
    fn raw_zstd(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0x50];
        out.extend_from_slice(&((u32::try_from(bytes.len()).unwrap() << 3) | 1).to_le_bytes()[..3]);
        out.extend(bytes);
        out
    }
    #[test]
    fn every_byte_boundary_preserves_frames_headers_and_output_budget() {
        let raw = vec![b'x'; 20001];
        for frame in [test_vectors::gzip(&raw), raw_zstd(&raw)] {
            let stored = [frame.as_slice(), frame.as_slice()].concat();
            for chunk in [1, 2, 7, 511, 512, 513, 8192] {
                let mut stream = Stream::new(stored.len() as u64, LayerDecodeLimits::default());
                let mut budget = 40004;
                let mut unique = 40002;
                for bytes in stored.chunks(chunk) {
                    stream.push(bytes, &mut budget, &mut unique).unwrap();
                }
                let observation = stream.finish([0; 32]).unwrap();
                assert_eq!(observation.decoded_bytes, 40002);
                assert_eq!(observation.frames, 2);
                assert_eq!(budget, 0);
                assert_eq!(unique, 0);
                assert_eq!(
                    observation.diff_id,
                    <[u8; 32]>::from(Sha256::digest([raw.as_slice(), raw.as_slice()].concat()))
                );
            }
        }
    }
    #[test]
    fn empty_frames_consume_probes_and_cannot_refresh_the_shared_budget() {
        let gzip_empty = [
            0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, 1, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let zstd_empty = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 1, 0, 0];
        for frame in [&gzip_empty[..], &zstd_empty[..]] {
            let mut stream = Stream::new(frame.len() as u64 * 2, LayerDecodeLimits::default());
            let mut budget = 2;
            let mut unique = 10;
            for byte in [frame, frame].concat() {
                stream.push(&[byte], &mut budget, &mut unique).unwrap();
            }
            let observed = stream.finish([0; 32]).unwrap();
            assert_eq!(observed.frames, 2);
            assert_eq!(observed.decoded_bytes, 0);
            assert_eq!(budget, 0);
            assert_eq!(unique, 10);
            let mut next = Stream::new(frame.len() as u64, LayerDecodeLimits::default());
            assert_eq!(
                next.push(frame, &mut budget, &mut unique),
                Err(LayerPolicyError::Budget)
            );
        }
    }
    #[test]
    fn every_partial_optional_gzip_header_stays_provisional() {
        let base = test_vectors::gzip(b"abc");
        let mut header = base[..10].to_vec();
        header[3] = 0x1e;
        header.extend([2, 0, 42, 43, b'n', 0, b'c', 0]);
        let crc = test_vectors::crc32(&header);
        header.extend_from_slice(&crc.to_le_bytes()[..2]);
        let stored = [header.as_slice(), &base[10..]].concat();
        for split in 1..stored.len() {
            let mut stream = Stream::new(stored.len() as u64, LayerDecodeLimits::default());
            let mut budget = 100;
            let mut unique = 100;
            stream
                .push(&stored[..split], &mut budget, &mut unique)
                .unwrap();
            stream
                .push(&stored[split..], &mut budget, &mut unique)
                .unwrap();
            assert_eq!(stream.finish([0; 32]).unwrap().decoded_bytes, 3);
        }
    }
    #[test]
    fn zstd_error_can_write_output_without_updating_positions() {
        // Exact locked libzstd 1.5.7 counterexample: complete header followed by abc raw
        // block and corrupt XXH64 trailer. The error leaves pos=0 after writing abc.
        let header = [0x28, 0xb5, 0x2f, 0xfd, 0x24, 3];
        let body = [0x19, 0, 0, b'a', b'b', b'c', 0x99, 0x09, 0x77, 0xac];
        let mut decoder = Decoder::new().unwrap();
        let mut header_input = InBuffer::around(&header);
        let mut prefix = [0; 1];
        decoder
            .run(&mut header_input, &mut OutBuffer::around(&mut prefix[..]))
            .unwrap();
        let mut input = InBuffer::around(&body);
        let mut bytes = [0xaa; 8192];
        let mut output = OutBuffer::around(&mut bytes[..]);
        assert!(decoder.run(&mut input, &mut output).is_err());
        assert_eq!(output.pos(), 0);
        assert_eq!(&bytes[..3], b"abc");
        let stored = [&header[..], &body].concat();
        let mut stream = Stream::new(stored.len() as u64, LayerDecodeLimits::default());
        let mut budget = 9000;
        let mut unique = 9000;
        assert_eq!(
            stream.push(&stored, &mut budget, &mut unique),
            Err(LayerPolicyError::Decoder)
        );
        assert_eq!(budget, 807);
        assert_eq!(unique, 808);
        assert_eq!(
            stream.hash.finalize().as_slice(),
            Sha256::digest([]).as_slice()
        );
        let mut retry = Stream::new(stored.len() as u64, LayerDecodeLimits::default());
        assert_eq!(
            retry.push(&stored, &mut budget, &mut unique),
            Err(LayerPolicyError::Decoder)
        );
        assert_eq!(budget, 0);
        assert_eq!(unique, 2);
    }
    #[test]
    fn zstd_checksum_error_retains_prior_output_and_current_failed_capacity() {
        let prefix = [
            0x28, 0xb5, 0x2f, 0xfd, 0x24, 3, 0x19, 0, 0, b'a', b'b', b'c',
        ];
        let bad_checksum = [0x99, 0x09, 0x77, 0xac];
        let mut stream = Stream::new(16, LayerDecodeLimits::default());
        let mut budget = 100;
        let mut unique = 100;
        stream.push(&prefix, &mut budget, &mut unique).unwrap();
        assert_eq!(budget, 96);
        assert_eq!(unique, 97);
        assert_eq!(
            stream.push(&bad_checksum, &mut budget, &mut unique),
            Err(LayerPolicyError::Decoder)
        );
        assert_eq!(budget, 0);
        assert_eq!(unique, 1);
        assert_eq!(
            stream.hash.finalize().as_slice(),
            Sha256::digest(b"abc").as_slice()
        );
    }
}
