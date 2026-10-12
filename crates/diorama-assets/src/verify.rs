use crate::{AssetId, DeclaredInventory};
use sha2::{Digest, Sha256};
use std::{fmt, io};

/// Only an encoded length/SHA-256 match. Not an ELF/OCI/decompression verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedBlobMatch {
    id: AssetId,
    bytes: u64,
    sha256: [u8; 32],
}
impl EncodedBlobMatch {
    pub fn id(&self) -> AssetId {
        self.id
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.bytes
    }
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}
#[derive(Debug)]
pub enum VerificationError {
    NotBundled(AssetId),
    BudgetExceeded(AssetId),
    SizeMismatch {
        asset: AssetId,
        expected: u64,
        observed: u64,
    },
    DigestMismatch(AssetId),
    InvalidReadCount(AssetId),
    Io {
        asset: AssetId,
        source: io::Error,
    },
}
impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotBundled(id) => write!(f, "asset {id:?} is not bundled"),
            Self::BudgetExceeded(id) => {
                write!(f, "asset {id:?}: encoded verification budget exhausted")
            },
            Self::SizeMismatch {
                asset,
                expected,
                observed,
            } => write!(
                f,
                "asset {asset:?}: encoded size {observed}, expected {expected}"
            ),
            Self::DigestMismatch(id) => write!(f, "asset {id:?}: encoded digest mismatch"),
            Self::InvalidReadCount(id) => {
                write!(f, "asset {id:?}: reader returned invalid byte count")
            },
            Self::Io { asset, .. } => write!(f, "asset {asset:?}: encoded input I/O failed"),
        }
    }
}
impl std::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
/// Aggregate budget across all attempts, including failures and repeated IDs.
#[derive(Debug)]
pub struct VerificationSession<'a> {
    inventory: &'a DeclaredInventory,
    remaining: u64,
}
impl DeclaredInventory {
    pub fn verification_session(&self) -> VerificationSession<'_> {
        VerificationSession {
            inventory: self,
            remaining: self.limits.encoded_total_bytes,
        }
    }
}
impl VerificationSession<'_> {
    pub fn remaining_budget(&self) -> u64 {
        self.remaining
    }
    /// Blocking-reader deadlines belong to the caller. Never writes or executes bytes.
    pub fn verify_encoded_blob<R: io::Read>(
        &mut self,
        id: AssetId,
        mut reader: R,
    ) -> Result<EncodedBlobMatch, VerificationError> {
        let blob = self
            .inventory
            .blobs
            .iter()
            .find(|b| b.id == id)
            .ok_or(VerificationError::NotBundled(id))?;
        // Inventory validation already checked size+1 representability.
        let reservation = blob
            .bytes
            .checked_add(1)
            .ok_or(VerificationError::BudgetExceeded(id))?;
        self.remaining = self
            .remaining
            .checked_sub(reservation)
            .ok_or(VerificationError::BudgetExceeded(id))?;
        let mut hash = Sha256::new();
        let mut count = 0u64;
        let mut buffer = [0u8; 8192];
        while count < reservation {
            let capacity = usize::try_from((reservation - count).min(8192))
                .map_err(|_| VerificationError::BudgetExceeded(id))?;
            let read = reader
                .read(&mut buffer[..capacity])
                .map_err(|source| VerificationError::Io { asset: id, source })?;
            if read > capacity {
                return Err(VerificationError::InvalidReadCount(id));
            }
            if read == 0 {
                break;
            }
            count += u64::try_from(read).map_err(|_| VerificationError::BudgetExceeded(id))?;
            hash.update(&buffer[..read]);
        }
        if count != blob.bytes {
            return Err(VerificationError::SizeMismatch {
                asset: id,
                expected: blob.bytes,
                observed: count,
            });
        }
        let sha256: [u8; 32] = hash.finalize().into();
        if sha256 != blob.digest {
            return Err(VerificationError::DigestMismatch(id));
        }
        Ok(EncodedBlobMatch {
            id,
            bytes: count,
            sha256,
        })
    }
}
