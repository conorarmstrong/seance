//! Version-36 blocks.
//!
//! A block sits at a 512-byte-aligned offset in a slot of
//! `align(cb + 24, 512)` bytes; its 24-byte trailer ends the slot: `cb` u16,
//! `wSig` u16, `dwCRC` u32 (over the `cb` stored bytes), `bid` u64, two bytes
//! this reader does not interpret, `cbInflated` u16, and four bytes of padding.
//! Where the block B-tree gives a stored size different from the inflated
//! size, the stored bytes are a zlib stream.

use super::btree::BbtEntry;
use super::crc::{ndb_crc, ndb_sig};
use super::{le_u16, le_u32, le_u64};
use flate2::read::ZlibDecoder;
use std::io::Read;

pub const BLOCK_TRAILER: usize = 24;
pub const BLOCK_ALIGN: u64 = 512;

/// Why a block's data could not be had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockFault {
    /// The block B-tree has no entry for this BID.
    NotInBbt { bid: u64 },
    /// The block lies past the bytes supplied (truncated, or not initialised on
    /// the image).
    PastEnd { bid: u64, ib: u64 },
    /// The block's slot reads as zeros.
    Zeroed { bid: u64, ib: u64 },
    /// The trailer does not describe the block the B-tree named.
    WrongTrailer { bid: u64, ib: u64, detail: String },
    /// The stored CRC does not match the stored bytes.
    BadCrc {
        bid: u64,
        stored: u32,
        computed: u32,
    },
    /// The zlib stream is not valid.
    Inflate { bid: u64, detail: String },
    /// The stream inflates to a size other than the one stated; an overrun is
    /// stopped at one byte past the stated size, so no stream can make the
    /// reader allocate more than the block claims.
    SizeMismatch {
        bid: u64,
        stated: u16,
        got: usize,
        overrun: bool,
    },
}

impl BlockFault {
    /// Whether the block was never there to read (past the data, or zeros),
    /// as against present and damaged.
    pub fn is_unwritten(&self) -> bool {
        matches!(self, Self::PastEnd { .. } | Self::Zeroed { .. })
    }
}

impl std::fmt::Display for BlockFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInBbt { bid } => write!(f, "block {bid:#x} is not in the block B-tree"),
            Self::PastEnd { bid, ib } => write!(
                f,
                "block {bid:#x} at {ib:#x} lies past the bytes supplied (the file is shorter than the \
                 store expects: truncated, or not initialised on the image)"
            ),
            Self::Zeroed { bid, ib } => write!(
                f,
                "block {bid:#x} at {ib:#x} reads as zeros (never written, or not initialised on the image)"
            ),
            Self::WrongTrailer { bid, ib, detail } => {
                write!(f, "block {bid:#x} at {ib:#x}: {detail}")
            }
            Self::BadCrc {
                bid,
                stored,
                computed,
            } => write!(
                f,
                "block {bid:#x} fails its CRC (stored {stored:#010x}, computed {computed:#010x})"
            ),
            Self::Inflate { bid, detail } => {
                write!(f, "block {bid:#x} is not a valid zlib stream: {detail}")
            }
            Self::SizeMismatch {
                bid,
                stated,
                got,
                overrun,
            } => {
                if *overrun {
                    // The inflate is stopped one byte past `stated`, so all
                    // that is known is that the stream is longer than stated.
                    write!(
                        f,
                        "block {bid:#x} inflates to more than {stated} bytes (stopped there) \
                         where {stated} are stated"
                    )
                } else {
                    write!(
                        f,
                        "block {bid:#x} inflates to {got} bytes where {stated} are stated"
                    )
                }
            }
        }
    }
}

/// Read and, where it is compressed, inflate the block `e` describes.
///
/// The trailer must name the same block the B-tree did (its `cb`, BID,
/// signature and inflated size), and the CRC is checked over the stored bytes
/// before anything is inflated.
pub fn read_block(data: &[u8], e: &BbtEntry) -> Result<Vec<u8>, BlockFault> {
    let bid = e.bref.bid;
    let ib = e.bref.ib;
    let cb = usize::from(e.cb);
    let slot = (cb + BLOCK_TRAILER).div_ceil(BLOCK_ALIGN as usize) * BLOCK_ALIGN as usize;
    let start = usize::try_from(ib).map_err(|_| BlockFault::PastEnd { bid, ib })?;
    let bytes = start
        .checked_add(slot)
        .and_then(|end| data.get(start..end))
        .ok_or(BlockFault::PastEnd { bid, ib })?;
    if bytes.iter().all(|&b| b == 0) {
        return Err(BlockFault::Zeroed { bid, ib });
    }
    let t = &bytes[slot - BLOCK_TRAILER..];
    let t_cb = le_u16(t, 0).unwrap_or(0);
    let t_sig = le_u16(t, 2).unwrap_or(0);
    let t_crc = le_u32(t, 4).unwrap_or(0);
    let t_bid = le_u64(t, 8).unwrap_or(0);
    let t_inflated = le_u16(t, 18).unwrap_or(0);
    if t_cb != e.cb || t_bid != bid || t_sig != ndb_sig(ib, bid) || t_inflated != e.cb_inflated {
        return Err(BlockFault::WrongTrailer {
            bid,
            ib,
            detail: format!(
                "trailer says cb {t_cb}, BID {t_bid:#x}, signature {t_sig:#06x}, inflated \
                 {t_inflated}; the block B-tree says cb {}, BID {bid:#x}, inflated {}",
                e.cb, e.cb_inflated
            ),
        });
    }
    let stored = &bytes[..cb];
    let computed = ndb_crc(stored);
    if computed != t_crc {
        return Err(BlockFault::BadCrc {
            bid,
            stored: t_crc,
            computed,
        });
    }
    if e.cb == e.cb_inflated {
        return Ok(stored.to_vec());
    }
    let stated = usize::from(e.cb_inflated);
    let mut out = Vec::with_capacity(stated + 1);
    ZlibDecoder::new(stored)
        .take(stated as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|err| BlockFault::Inflate {
            bid,
            detail: err.to_string(),
        })?;
    if out.len() != stated {
        return Err(BlockFault::SizeMismatch {
            bid,
            stated: e.cb_inflated,
            got: out.len(),
            overrun: out.len() > stated,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    //! Synthetic blocks, honest here because they test only the bound on
    //! inflation, not the format: the real blocks are tested against the
    //! Data Leakage OST in `tests/ost4k_real_test.rs`.
    use super::super::btree::BbtEntry;
    use super::super::Bref;
    use super::*;
    use std::io::Write;

    /// One block at offset 0: `stored` bytes, a trailer claiming
    /// `cb_inflated`, CRC and signature sealed as Outlook would.
    fn block(stored: &[u8], cb_inflated: u16) -> (Vec<u8>, BbtEntry) {
        let bid = 0x404;
        let cb = stored.len() as u16;
        let slot = (stored.len() + BLOCK_TRAILER).div_ceil(512) * 512;
        let mut d = vec![0u8; slot];
        d[..stored.len()].copy_from_slice(stored);
        let t = slot - BLOCK_TRAILER;
        d[t..t + 2].copy_from_slice(&cb.to_le_bytes());
        d[t + 2..t + 4].copy_from_slice(&ndb_sig(0, bid).to_le_bytes());
        d[t + 4..t + 8].copy_from_slice(&ndb_crc(stored).to_le_bytes());
        d[t + 8..t + 16].copy_from_slice(&bid.to_le_bytes());
        d[t + 18..t + 20].copy_from_slice(&cb_inflated.to_le_bytes());
        let e = BbtEntry {
            bref: Bref { bid, ib: 0 },
            cb,
            cb_inflated,
            c_ref: 1,
        };
        (d, e)
    }

    fn zlib(raw: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        z.write_all(raw).unwrap();
        z.finish().unwrap()
    }

    #[test]
    fn a_block_that_inflates_to_its_stated_size_reads() {
        let raw = b"hello, iaman ".repeat(40);
        let (d, e) = block(&zlib(&raw), raw.len() as u16);
        assert_eq!(read_block(&d, &e).unwrap(), raw);
    }

    #[test]
    fn a_block_whose_inflate_overruns_cb_inflated_is_refused() {
        let raw = vec![7u8; 1000];
        let (d, e) = block(&zlib(&raw), 500);
        assert_eq!(
            read_block(&d, &e),
            Err(BlockFault::SizeMismatch {
                bid: 0x404,
                stated: 500,
                got: 501,
                overrun: true
            })
        );
        // And one that falls short is refused too.
        let (d, e) = block(&zlib(&raw), 1500);
        assert!(matches!(
            read_block(&d, &e),
            Err(BlockFault::SizeMismatch { overrun: false, .. })
        ));
    }

    /// 64 MiB of zeros deflates to ~64 KiB. Claimed as an 8 KiB block, it is
    /// refused after inflating one byte past 8 KiB, not 64 MiB.
    #[test]
    fn a_zlib_bomb_is_capped() {
        let bomb = zlib(&vec![0u8; 64 << 20]);
        assert!(bomb.len() < usize::from(u16::MAX), "{}", bomb.len());
        let (d, e) = block(&bomb, 8192);
        let t = std::time::Instant::now();
        assert!(matches!(
            read_block(&d, &e),
            Err(BlockFault::SizeMismatch {
                got: 8193,
                overrun: true,
                ..
            })
        ));
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
    }

    /// The overrun text claims no more than was observed: the inflate stops
    /// at one byte past the stated size, so "more than stated" is all it knows.
    #[test]
    fn a_size_mismatch_says_only_what_was_observed() {
        let raw = vec![7u8; 1000];
        let (d, e) = block(&zlib(&raw), 500);
        let over = read_block(&d, &e).unwrap_err().to_string();
        assert!(over.contains("more than 500 bytes"), "{over}");
        assert!(!over.contains("501"), "{over}");
        let (d, e) = block(&zlib(&raw), 1500);
        let short = read_block(&d, &e).unwrap_err().to_string();
        assert!(
            short.contains("inflates to 1000 bytes where 1500"),
            "{short}"
        );
        let past = read_block(&d[..100], &e).unwrap_err().to_string();
        assert!(past.contains("lies past the bytes supplied"), "{past}");
        assert!(past.contains("truncated"), "{past}");
    }

    #[test]
    fn a_block_with_a_bad_crc_or_a_foreign_trailer_is_refused() {
        let raw = b"plain block".to_vec();
        let (mut d, e) = block(&raw, raw.len() as u16);
        assert_eq!(read_block(&d, &e).unwrap(), raw);
        d[0] ^= 1;
        assert!(matches!(read_block(&d, &e), Err(BlockFault::BadCrc { .. })));
        d[0] ^= 1;
        let other = BbtEntry {
            bref: Bref { bid: 0x408, ib: 0 },
            ..e
        };
        assert!(matches!(
            read_block(&d, &other),
            Err(BlockFault::WrongTrailer { .. })
        ));
        assert!(matches!(
            read_block(&d[..100], &e),
            Err(BlockFault::PastEnd { .. })
        ));
        let zero = vec![0u8; 512];
        assert!(matches!(
            read_block(&zero, &e),
            Err(BlockFault::Zeroed { .. })
        ));
    }
}
