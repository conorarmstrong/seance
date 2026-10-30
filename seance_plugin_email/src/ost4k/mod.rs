//! Outlook 2013-and-later offline stores: the NDB layer of format version 36.
//!
//! Version 36 keeps the Unicode (version 23) node database's shape — a header,
//! a node B-tree (NBT), a block B-tree (BBT), blocks addressed by BID — and
//! changes its geometry: B-tree pages are 4 KiB with a 24-byte trailer and
//! their metadata 16 bytes above it, blocks are aligned to 512 bytes, and a
//! block may be stored zlib-compressed with its inflated size in the BBT.
//! Microsoft publishes no specification of it. This is a clean-room read of the
//! format as it lies on disk in the one real file this project holds (the NIST
//! Data Leakage OST, `tests/fixtures/ost_v36/`), with `libpff`'s documentation
//! of the format as a guide to what to look for — not a port of any reader.
//!
//! Every structure is bounds-checked against the bytes supplied; nothing here
//! panics on hostile input, and every page or block that could not be read is
//! named in what the walk returns rather than dropped.

pub mod block;
pub mod btree;
pub mod crc;
pub mod header;
pub mod ltp;
pub mod mailbox;
pub mod ndb;
pub mod page;
pub mod recover;

pub use header::{Bref, Header4k};

/// Little-endian reads that answer `None` past the end instead of panicking.
pub(crate) fn le_u16(d: &[u8], at: usize) -> Option<u16> {
    d.get(at..at.checked_add(2)?)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

pub(crate) fn le_u32(d: &[u8], at: usize) -> Option<u32> {
    d.get(at..at.checked_add(4)?)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub(crate) fn le_u64(d: &[u8], at: usize) -> Option<u64> {
    let b = d.get(at..at.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Some(u64::from_le_bytes(a))
}

/// Why the v36 reader could not use a structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ost4kError {
    /// Not `!BDN` at offset 0.
    NotAStore,
    /// A store, of a version this reader does not read (it reads 36 only).
    Version(u16),
    /// The input ends before the structure does.
    Truncated { needed: usize, have: usize },
    /// A stored CRC does not match the bytes.
    Crc {
        what: &'static str,
        stored: u32,
        computed: u32,
    },
    /// A field holds a value the format does not allow.
    Invalid(String),
}

impl std::fmt::Display for Ost4kError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAStore => write!(f, "no !BDN magic at offset 0"),
            Self::Version(v) => write!(f, "format version {v}, not the 4 KiB-page version 36"),
            Self::Truncated { needed, have } => {
                write!(f, "needs {needed} bytes, {have} supplied")
            }
            Self::Crc {
                what,
                stored,
                computed,
            } => write!(
                f,
                "{what} CRC mismatch: stored {stored:#010x}, computed {computed:#010x}"
            ),
            Self::Invalid(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for Ost4kError {}
