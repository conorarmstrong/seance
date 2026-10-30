//! 4 KiB B-tree pages.
//!
//! A version-36 B-tree page is 4,096 bytes: entries from offset 0, then 16
//! bytes of B-tree metadata at 4056 (`cEnt` u16, `cEntMax` u16, `cbEnt` u8,
//! `cLevel` u8, ten bytes of padding), then the 24-byte page trailer at 4072
//! (`ptype`, `ptypeRepeat`, `wSig` u16, `dwCRC` u32, `bid` u64, and eight bytes
//! this reader does not interpret). The CRC covers bytes 0..4072.

use super::crc::{ndb_crc, ndb_sig};
use super::{le_u16, le_u32, le_u64, Bref};

pub const PAGE_SIZE: usize = 4096;
pub const META_AT: usize = 4056;
pub const TRAILER_AT: usize = 4072;

/// `ptype` of a block B-tree page.
pub const PTYPE_BBT: u8 = 0x80;
/// `ptype` of a node B-tree page.
pub const PTYPE_NBT: u8 = 0x81;

/// Why a page was not walked. Every variant carries the page's offset so the
/// record can name it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageFault {
    /// The page lies wholly or partly past the end of the bytes supplied — on
    /// a partly initialised file, past what was ever written to disk.
    PastEnd { ib: u64, have: u64 },
    /// Every byte of the page is zero: never written, or past the initialised
    /// length on the image, which reads as zeros. Not walked as a page.
    Zeroed { ib: u64 },
    /// The stored CRC does not match the page.
    BadCrc { ib: u64, stored: u32, computed: u32 },
    /// `ptype`/`ptypeRepeat` are not the tree's page type.
    WrongType { ib: u64, expected: u8, found: u8 },
    /// The trailer's BID is not the one the parent pointed at.
    WrongBid { ib: u64, expected: u64, found: u64 },
    /// The trailer's signature is not the one the page's offset and BID give
    /// (a page relocated, or a corrupt trailer), though its BID is right.
    BadSignature { ib: u64, stored: u16, computed: u16 },
    /// The metadata is impossible (entry size, count or level).
    BadMetadata { ib: u64, detail: String },
    /// The page was already walked: it is reached from more than one parent
    /// (a loop, or a child two pages share). Walked once, not again.
    ReachedTwice { ib: u64 },
    /// Deeper than any real tree; the subtree below was not walked.
    TooDeep { ib: u64 },
}

impl PageFault {
    pub fn ib(&self) -> u64 {
        match self {
            Self::PastEnd { ib, .. }
            | Self::Zeroed { ib }
            | Self::BadCrc { ib, .. }
            | Self::WrongType { ib, .. }
            | Self::WrongBid { ib, .. }
            | Self::BadSignature { ib, .. }
            | Self::BadMetadata { ib, .. }
            | Self::ReachedTwice { ib }
            | Self::TooDeep { ib } => *ib,
        }
    }

    /// Whether the page was never there to read (past the data, or zeros),
    /// as against present and damaged.
    pub fn is_unwritten(&self) -> bool {
        matches!(self, Self::PastEnd { .. } | Self::Zeroed { .. })
    }
}

impl std::fmt::Display for PageFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PastEnd { ib, have } => write!(
                f,
                "page at {ib:#x} lies past the {have} bytes supplied (the file is shorter than the \
                 store expects: truncated, or not initialised on the image)"
            ),
            Self::Zeroed { ib } => write!(
                f,
                "page at {ib:#x} reads as zeros (never written, or not initialised on the image)"
            ),
            Self::BadCrc {
                ib,
                stored,
                computed,
            } => write!(
                f,
                "page at {ib:#x} fails its CRC (stored {stored:#010x}, computed {computed:#010x})"
            ),
            Self::WrongType {
                ib,
                expected,
                found,
            } => write!(
                f,
                "page at {ib:#x} has page type {found:#04x} where {expected:#04x} was expected"
            ),
            Self::WrongBid {
                ib,
                expected,
                found,
            } => write!(
                f,
                "page at {ib:#x} carries BID {found:#x} where its parent named {expected:#x}"
            ),
            Self::BadSignature {
                ib,
                stored,
                computed,
            } => write!(
                f,
                "page at {ib:#x} fails its signature check (stored {stored:#06x}, computed \
                 {computed:#06x} for that offset and BID)"
            ),
            Self::BadMetadata { ib, detail } => write!(f, "page at {ib:#x}: {detail}"),
            Self::ReachedTwice { ib } => write!(
                f,
                "page at {ib:#x} is referenced by more than one parent page; walked once, \
                 not again"
            ),
            Self::TooDeep { ib } => write!(
                f,
                "page at {ib:#x} is deeper than any real B-tree; not walked"
            ),
        }
    }
}

/// One validated B-tree page.
#[derive(Debug, Clone)]
pub struct BTreePage<'a> {
    pub ib: u64,
    pub bid: u64,
    pub ptype: u8,
    pub c_ent: u16,
    pub c_ent_max: u16,
    pub cb_ent: u8,
    pub level: u8,
    bytes: &'a [u8],
}

impl<'a> BTreePage<'a> {
    /// Entry `i`'s bytes; `None` past `cEnt`.
    pub fn entry(&self, i: usize) -> Option<&'a [u8]> {
        if i >= usize::from(self.c_ent) {
            return None;
        }
        let cb = usize::from(self.cb_ent);
        self.bytes.get(i * cb..(i + 1) * cb)
    }
}

/// Read the page `bref` names and check it is a page of type `ptype`.
///
/// The checks run in the order that says the most about the evidence: a page
/// past the data or of all zeros was never there to read, and is named as
/// such before a CRC or type check could call it damaged.
pub fn read_btree_page(data: &[u8], bref: Bref, ptype: u8) -> Result<BTreePage<'_>, PageFault> {
    let ib = bref.ib;
    let have = data.len() as u64;
    let end = ib.checked_add(PAGE_SIZE as u64);
    let page = match (usize::try_from(ib), end) {
        (Ok(start), Some(end)) if end <= have => &data[start..start + PAGE_SIZE],
        _ => return Err(PageFault::PastEnd { ib, have }),
    };
    if page.iter().all(|&b| b == 0) {
        return Err(PageFault::Zeroed { ib });
    }
    let stored = le_u32(page, TRAILER_AT + 4).unwrap_or(0);
    let computed = ndb_crc(&page[..TRAILER_AT]);
    if stored != computed {
        return Err(PageFault::BadCrc {
            ib,
            stored,
            computed,
        });
    }
    let (pt, pt_repeat) = (page[TRAILER_AT], page[TRAILER_AT + 1]);
    if pt != ptype || pt_repeat != ptype {
        return Err(PageFault::WrongType {
            ib,
            expected: ptype,
            found: if pt != ptype { pt } else { pt_repeat },
        });
    }
    let bid = le_u64(page, TRAILER_AT + 8).unwrap_or(0);
    let sig = le_u16(page, TRAILER_AT + 2).unwrap_or(0);
    if bid != bref.bid {
        return Err(PageFault::WrongBid {
            ib,
            expected: bref.bid,
            found: bid,
        });
    }
    let computed = ndb_sig(ib, bid);
    if sig != computed {
        return Err(PageFault::BadSignature {
            ib,
            stored: sig,
            computed,
        });
    }
    let c_ent = le_u16(page, META_AT).unwrap_or(0);
    let c_ent_max = le_u16(page, META_AT + 2).unwrap_or(0);
    let cb_ent = page[META_AT + 4];
    let level = page[META_AT + 5];
    if cb_ent == 0 || c_ent > c_ent_max || usize::from(c_ent_max) * usize::from(cb_ent) > META_AT {
        return Err(PageFault::BadMetadata {
            ib,
            detail: format!(
                "impossible B-tree metadata (cEnt {c_ent}, cEntMax {c_ent_max}, cbEnt {cb_ent})"
            ),
        });
    }
    Ok(BTreePage {
        ib,
        bid,
        ptype,
        c_ent,
        c_ent_max,
        cb_ent,
        level,
        bytes: &page[..META_AT],
    })
}

#[cfg(test)]
mod tests {
    use super::super::btree::{walk_nbt, MAX_DEPTH};
    use super::super::crc::ndb_crc;
    use super::super::Bref;
    use super::*;

    const NBT_ROOT: Bref = Bref {
        bid: 0x36EB,
        ib: 0x90000,
    };

    fn fixture() -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ost_v36/iaman.informant_initialised_prefix.ost");
        std::fs::read(&p).unwrap_or_else(|e| panic!("{} is tracked: {e}", p.display()))
    }

    fn reseal(page: &mut [u8]) {
        let crc = ndb_crc(&page[..TRAILER_AT]);
        page[TRAILER_AT + 4..TRAILER_AT + 8].copy_from_slice(&crc.to_le_bytes());
    }

    /// The real file cut at 0x90000, the NBT root's own offset: the root is
    /// past the data, and the walk says so rather than reading nothing and
    /// calling the tree empty.
    #[test]
    fn a_page_past_the_initialised_length_is_reported_not_walked() {
        let data = fixture();
        let cut = &data[..0x90000];
        let w = walk_nbt(cut, NBT_ROOT);
        assert!(w.entries.is_empty());
        assert_eq!(w.pages_walked, 0);
        assert_eq!(
            w.faults,
            vec![PageFault::PastEnd {
                ib: 0x90000,
                have: 0x90000
            }]
        );
        assert!(w.faults[0].is_unwritten());

        // The same page present but zero, as the image reads past the
        // initialised length, is named as zeros, not as a bad page.
        let mut zeroed = data.clone();
        zeroed[0x90000..0x91000].fill(0);
        let w = walk_nbt(&zeroed, NBT_ROOT);
        assert_eq!(w.faults, vec![PageFault::Zeroed { ib: 0x90000 }]);
    }

    /// One leaf with a flipped byte costs that leaf and nothing else: the
    /// root and the other two leaves are still walked, and the fault names
    /// the page.
    #[test]
    fn a_page_with_a_bad_crc_is_named_and_skipped() {
        let mut data = fixture();
        let root = read_btree_page(&data, NBT_ROOT, PTYPE_NBT).expect("real root");
        let first_leaf_ib = le_u64(root.entry(0).unwrap(), 16).unwrap();
        data[first_leaf_ib as usize + 40] ^= 0xFF;
        let w = walk_nbt(&data, NBT_ROOT);
        assert_eq!(w.faults.len(), 1, "{:?}", w.faults);
        assert!(
            matches!(w.faults[0], PageFault::BadCrc { ib, .. } if ib == first_leaf_ib),
            "{:?}",
            w.faults
        );
        assert_eq!(w.pages_walked, 3);
        assert!(!w.entries.is_empty() && w.entries.len() < 351);
    }

    /// A root whose first child is itself: the walk ends, and names the page
    /// reached twice.
    #[test]
    fn a_self_referencing_intermediate_page_terminates() {
        let mut data = fixture();
        let at = NBT_ROOT.ib as usize;
        // Entry 0: btkey(8), bid(8), ib(8). Point it back at the root.
        data[at + 8..at + 16].copy_from_slice(&NBT_ROOT.bid.to_le_bytes());
        data[at + 16..at + 24].copy_from_slice(&NBT_ROOT.ib.to_le_bytes());
        reseal(&mut data[at..at + PAGE_SIZE]);
        let w = walk_nbt(&data, NBT_ROOT);
        assert!(
            w.faults
                .iter()
                .any(|f| matches!(f, PageFault::ReachedTwice { ib } if *ib == NBT_ROOT.ib)),
            "{:?}",
            w.faults
        );
        assert!(w.pages_walked <= MAX_DEPTH + 3);
    }

    /// A page reached from two parents is a shared child, not necessarily a
    /// loop; the fault says what was seen and claims no more.
    #[test]
    fn a_page_reached_twice_is_not_called_a_cycle() {
        let text = PageFault::ReachedTwice { ib: 0x1000 }.to_string();
        assert!(!text.contains("cycle"), "{text}");
        assert!(text.contains("more than one parent"), "{text}");
    }

    /// A page whose BID is right but whose signature is not is a signature
    /// fault, not a "wrong BID" naming the same BID twice. A page past the
    /// data says what it knows about the file's length.
    #[test]
    fn a_corrupt_signature_is_named_as_one() {
        let mut data = fixture();
        let at = NBT_ROOT.ib as usize;
        data[at + TRAILER_AT + 2] ^= 0xFF;
        reseal(&mut data[at..at + PAGE_SIZE]);
        let e = read_btree_page(&data, NBT_ROOT, PTYPE_NBT).unwrap_err();
        assert!(matches!(e, PageFault::BadSignature { .. }), "{e:?}");
        assert!(e.to_string().contains("signature"), "{e}");
        let past = read_btree_page(&data[..0x1000], NBT_ROOT, PTYPE_NBT)
            .unwrap_err()
            .to_string();
        assert!(
            past.contains("lies past the") && past.contains("truncated"),
            "{past}"
        );
    }

    /// Hostile metadata — an entry count past the page — is refused, never
    /// read past the entry area.
    #[test]
    fn impossible_metadata_is_refused() {
        let mut data = fixture();
        let at = NBT_ROOT.ib as usize;
        data[at + META_AT..at + META_AT + 2].copy_from_slice(&500u16.to_le_bytes());
        reseal(&mut data[at..at + PAGE_SIZE]);
        let e = read_btree_page(&data, NBT_ROOT, PTYPE_NBT).unwrap_err();
        assert!(matches!(e, PageFault::BadMetadata { .. }), "{e:?}");
    }
}
