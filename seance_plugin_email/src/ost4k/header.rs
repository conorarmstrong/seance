//! The version-36 store header.

use super::crc::ndb_crc;
use super::{le_u16, le_u32, le_u64, Ost4kError};

/// The header is 528 bytes of the first 4 KiB; everything past `dwCRCFull`
/// (offset 524) is unused.
pub const HEADER_LEN: usize = 528;

/// A block reference: a BID and the byte offset it lives at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bref {
    pub bid: u64,
    pub ib: u64,
}

/// What a version-36 header says about the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header4k {
    /// `PST` for client tag `SM`, `OST` for `SO`.
    pub client: &'static str,
    pub version: u16,
    /// `ibFileEof`: how long the header says the file is.
    pub file_eof: u64,
    pub nbt_root: Bref,
    pub bbt_root: Bref,
    /// `bCryptMethod`: 0 none, 1 permute, 2 cyclic, 0x10 Windows Information
    /// Protection.
    pub crypt_method: u8,
}

impl Header4k {
    /// Read and validate a version-36 header.
    ///
    /// The version is checked before either CRC, so a store of another version
    /// is refused by its number rather than as a bad checksum. Both CRCs
    /// (`dwCRCPartial` over bytes 8..479, `dwCRCFull` over 8..524) must match:
    /// the two B-tree roots are inside their span, and a root that is not the
    /// one Outlook wrote would send the whole walk somewhere else.
    pub fn read(data: &[u8]) -> Result<Self, Ost4kError> {
        if data.len() < 12 {
            return Err(Ost4kError::Truncated {
                needed: HEADER_LEN,
                have: data.len(),
            });
        }
        if &data[..4] != b"!BDN" {
            return Err(Ost4kError::NotAStore);
        }
        let version = le_u16(data, 10).unwrap_or(0);
        if version != 36 {
            return Err(Ost4kError::Version(version));
        }
        if data.len() < HEADER_LEN {
            return Err(Ost4kError::Truncated {
                needed: HEADER_LEN,
                have: data.len(),
            });
        }
        let client = match &data[8..10] {
            b"SM" => "PST",
            b"SO" => "OST",
            _ => "unknown client",
        };
        for (what, at, span) in [
            ("header partial", 4usize, 471usize),
            ("header full", 524, 516),
        ] {
            let stored = le_u32(data, at).unwrap_or(0);
            let computed = ndb_crc(&data[8..8 + span]);
            if stored != computed {
                return Err(Ost4kError::Crc {
                    what,
                    stored,
                    computed,
                });
            }
        }
        let bref = |at: usize| Bref {
            bid: le_u64(data, at).unwrap_or(0),
            ib: le_u64(data, at + 8).unwrap_or(0),
        };
        Ok(Self {
            client,
            version,
            file_eof: le_u64(data, 184).unwrap_or(0),
            nbt_root: bref(0xD8),
            bbt_root: bref(0xE8),
            crypt_method: data[0x201],
        })
    }
}
