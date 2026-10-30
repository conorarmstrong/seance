//! The two container forms an `.sdb` arrives in.
//!
//! `sdbf` is the tag stream directly. `zdbf` wraps it: after the twelve-byte
//! header come a `u32` (observed as 1 in the one real compressed database) and
//! a `u32` **declared inflated size**, then a raw zlib stream from byte 20.
//!
//! Measured on `appraiser.sdb` from the Windows 11 ARM64 ISO: 2,046,855 bytes
//! declaring 9,734,396, which inflates to exactly that, and whose inflated
//! bytes begin with an ordinary `sdbf` header.
//!
//! # Why the declared size is checked rather than trusted
//!
//! It is an attacker-controllable `u32`. Allocating it up front is a
//! 4 GiB allocation on a crafted file — and an allocation the allocator refuses
//! is a process **abort**, which `catch_unwind` cannot contain, so one crafted
//! database would end the whole ingest. The inflate is bounded by
//! [`MAX_INFLATED_BYTES`] and the declared size is compared against what
//! actually came out, with a disagreement reported rather than either ignored
//! or believed.

use flate2::read::ZlibDecoder;
use std::io::Read;

use crate::format::{HEADER_BYTES, MAGIC_SDBF, MAGIC_ZDBF};

/// Where the compressed stream begins in a `zdbf` file.
const ZDBF_STREAM_AT: usize = 20;

/// The largest inflated database this build will hold in memory.
///
/// The largest real one is 9,734,396 bytes. 256 MiB is two orders of magnitude
/// above that and finite, which is the point: a declared `u32` is not.
pub const MAX_INFLATED_BYTES: usize = 256 * 1024 * 1024;

/// Which container a database arrived in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Container {
    Plain,
    ZlibCompressed,
}

impl Container {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plain => "sdbf",
            Self::ZlibCompressed => "zdbf",
        }
    }
}

/// A database's bytes, ready to walk.
#[derive(Clone, Debug)]
pub struct Opened {
    /// The tag stream with its header — inflated, if it was compressed.
    pub body: Vec<u8>,
    pub container: Container,
    pub major_version: u32,
    pub minor_version: u32,
    /// What a `zdbf` header declared its inflated size to be.
    pub declared_inflated_len: Option<u64>,
    /// Set when the inflate stopped at [`MAX_INFLATED_BYTES`] or the declared
    /// length and the inflated length disagree.
    pub incomplete: Option<String>,
}

/// Why a file is not a shim database this build can open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// Shorter than the twelve-byte header.
    TooShort { bytes: usize },
    /// Neither magic. **Not** an error worth a record: a file merely named
    /// `.sdb` that carries neither is not a shim database, and this build says
    /// nothing about it rather than inventing a parse failure.
    NotAShimDatabase,
    /// The compressed stream would not inflate.
    Inflate { detail: String },
}

fn le_u32(d: &[u8], at: usize) -> u32 {
    d.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0)
}

/// Open a database from its bytes.
pub fn open(bytes: &[u8]) -> Result<Opened, OpenError> {
    if bytes.len() < HEADER_BYTES {
        return Err(OpenError::TooShort { bytes: bytes.len() });
    }
    let magic = &bytes[8..12];
    let major_version = le_u32(bytes, 0);
    let minor_version = le_u32(bytes, 4);

    if magic == MAGIC_SDBF {
        return Ok(Opened {
            body: bytes.to_vec(),
            container: Container::Plain,
            major_version,
            minor_version,
            declared_inflated_len: None,
            incomplete: None,
        });
    }
    if magic != MAGIC_ZDBF {
        return Err(OpenError::NotAShimDatabase);
    }

    let declared = le_u32(bytes, 16) as u64;
    let stream = bytes.get(ZDBF_STREAM_AT..).unwrap_or(&[]);
    // Bounded, and never sized from the declared length. See the module
    // comment: an allocation the allocator refuses is an abort, not a panic.
    let mut body = Vec::new();
    let mut reader = ZlibDecoder::new(stream).take(MAX_INFLATED_BYTES as u64 + 1);
    if let Err(e) = reader.read_to_end(&mut body) {
        return Err(OpenError::Inflate {
            detail: e.to_string(),
        });
    }
    let mut incomplete = None;
    if body.len() > MAX_INFLATED_BYTES {
        body.truncate(MAX_INFLATED_BYTES);
        incomplete = Some(format!(
            "The compressed database inflates past this build's {MAX_INFLATED_BYTES}-byte \
             ceiling. The tags below are those in the first {MAX_INFLATED_BYTES} bytes; the \
             rest of the database was not read."
        ));
    } else if declared != body.len() as u64 {
        // Reported, not resolved. Which of the two is right is itself evidence.
        incomplete = Some(format!(
            "The container declares an inflated length of {declared} bytes and the stream \
             inflated to {}. The inflated bytes are what was walked; the declared length is \
             transcribed as found.",
            body.len()
        ));
    }
    Ok(Opened {
        body,
        container: Container::ZlibCompressed,
        major_version,
        minor_version,
        declared_inflated_len: Some(declared),
        incomplete,
    })
}
