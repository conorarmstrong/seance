//! Deleted-message recovery from a version 14, 15 or 23 store (ROADMAP §3.10).
//!
//! These are the 512-byte-page layouts: version 14 and 15 are the ANSI form
//! (32-bit block and node ids, 12-byte page and block trailers) and version 23
//! is the Unicode form (64-bit ids, 16-byte trailers). The live reader for
//! them is the `outlook-pst` crate, which exposes no scan of what the live
//! trees do not reference, so this module reads the page and block layer
//! itself and hands the property contexts to the heap reader the version 36
//! recovery already uses ([`crate::ost4k::ltp`]).
//!
//! The method is the version 36 one ([`crate::ost4k::recover`]): every
//! 512-byte offset is tried as a B-tree page and every 64-byte boundary as the
//! end of a block, each accepted only when its trailer signature and CRC are
//! the ones Outlook would have written there. A node entry in a leaf page no
//! live tree references, for a message node the live tree no longer has, is a
//! deleted message. The output is the same [`Recovery`], so it is published
//! by the same code.
//!
//! # What is and is not established
//!
//! * The ANSI layout (version 14) is graded on a real Outlook 2000 store
//!   (`tests/fixtures/pst_old/`, and the 2.3 MB Jean mailbox in the corpus
//!   test). The Unicode layout (version 23) has its header, page and entry
//!   structure pinned on a real, empty store; **no Unicode message has been
//!   read from real evidence**.
//! * Attachments and the recipient table are read from the subnode tree
//!   (the table context reader is [`crate::ost4k::ltp::read_tc_with`]).
//! * Cyclic ("high") encryption is decoded from MS-PST §5.2 and graded on synthetic re-encodings of public stores (`PST-CYCLIC-1`).

use crate::ost4k::btree::NbtEntry;
use crate::ost4k::crc::{ndb_crc, ndb_sig};
use crate::ost4k::ltp::{
    read_pc_with, read_tc_with, HeapNode, LtpFault, PropValue, PropertyContext, TableContext,
};
use crate::ost4k::ndb::{Subnode, BID_INTERNAL};
use crate::ost4k::recover::{
    identity, note_attachment_overflow, note_unreadable_attachment, readable_context, Completeness,
    Listed, OtherVersion, RecoveredMessage, Recovery, Scan, ScannedPage, Source, MAX_RECOVERED,
    MF_FAI, NID_TYPE_NORMAL_MESSAGE, PID_TAG_MESSAGE_CLASS, PID_TAG_MESSAGE_FLAGS,
};
use crate::ost4k::{le_u16, le_u32, le_u64, Bref};
use std::collections::{BTreeMap, HashSet};

const PAGE: usize = 512;
const BLOCK_ALIGN: usize = 64;
/// A block, trailer included, is at most this many bytes in either layout.
const MAX_BLOCK_SLOT: usize = 8192;
const PTYPE_BBT: u8 = 0x80;
const PTYPE_NBT: u8 = 0x81;
const MAGIC: &[u8; 4] = b"!BDN";
const NID_TYPE_ATTACHMENT: u32 = 0x05;
const NID_TYPE_RECIPIENT_TABLE: u32 = 0x12;
/// A tree deeper than this is not one Outlook writes.
const MAX_DEPTH: u8 = 8;
/// Folders nested deeper than this are not read as a path; the path says so.
/// Folder nesting is not a B-tree depth, and real mailboxes nest well past 8.
const MAX_FOLDER_DEPTH: usize = 64;
/// More data blocks under one node than this are not real.
const MAX_NODE_BLOCKS: usize = 4096;

/// The two layouts this module reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Versions 14 and 15.
    Ansi,
    /// Version 23.
    Unicode,
}

impl Layout {
    /// Width in bytes of a block id, node id or offset field.
    fn wide(self) -> usize {
        match self {
            Self::Ansi => 4,
            Self::Unicode => 8,
        }
    }

    fn trailer(self) -> usize {
        match self {
            Self::Ansi => 12,
            Self::Unicode => 16,
        }
    }

    /// Where a B-tree page's entry count and sizes sit.
    fn meta_at(self) -> usize {
        match self {
            Self::Ansi => 496,
            Self::Unicode => 488,
        }
    }

    fn read_wide(self, d: &[u8], at: usize) -> Option<u64> {
        match self {
            Self::Ansi => le_u32(d, at).map(u64::from),
            Self::Unicode => le_u64(d, at),
        }
    }

    fn nbt_leaf(self) -> usize {
        self.wide() * 4
    }

    fn bbt_leaf(self) -> usize {
        match self {
            Self::Ansi => 12,
            Self::Unicode => 24,
        }
    }

    fn index(self) -> usize {
        self.wide() * 3
    }
}

/// Why a store could not be read by this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pst512Error {
    /// Not a store this module reads: wrong magic or version, or an encryption
    /// it will not guess at. The text says which.
    NotThisFormat(String),
}

impl std::fmt::Display for Pst512Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotThisFormat(s) => write!(f, "{s}"),
        }
    }
}

/// The permutative decoding table (`mpbbI`) of MS-PST §5.1.
#[rustfmt::skip]
const PERMUTE_DECODE: [u8; 256] = [
    71, 241, 180, 230, 11, 106, 114, 72, 133, 78, 158, 235, 226, 248, 148, 83, 224, 187, 160, 2,
    232, 90, 9, 171, 219, 227, 186, 198, 124, 195, 16, 221, 57, 5, 150, 48, 245, 55, 96, 130,
    140, 201, 19, 74, 107, 29, 243, 251, 143, 38, 151, 202, 145, 23, 1, 196, 50, 45, 110, 49,
    149, 255, 217, 35, 209, 0, 94, 121, 220, 68, 59, 26, 40, 197, 97, 87, 32, 144, 61, 131, 185,
    67, 190, 103, 210, 70, 66, 118, 192, 109, 91, 126, 178, 15, 22, 41, 60, 169, 3, 84, 13, 218,
    93, 223, 246, 183, 199, 98, 205, 141, 6, 211, 105, 92, 134, 214, 20, 247, 165, 102, 117,
    172, 177, 233, 69, 33, 112, 12, 135, 159, 116, 164, 34, 76, 111, 191, 31, 86, 170, 46, 179,
    120, 51, 80, 176, 163, 146, 188, 207, 25, 28, 167, 99, 203, 30, 77, 62, 75, 27, 155, 79,
    231, 240, 238, 173, 58, 181, 89, 4, 234, 64, 85, 37, 81, 229, 122, 137, 56, 104, 82, 123,
    252, 39, 174, 215, 189, 250, 7, 244, 204, 142, 95, 239, 53, 156, 132, 43, 21, 213, 119, 52,
    73, 182, 18, 10, 127, 113, 136, 253, 157, 24, 65, 125, 147, 216, 88, 44, 206, 254, 36, 175,
    222, 184, 54, 200, 161, 128, 166, 153, 152, 168, 47, 14, 129, 101, 115, 228, 194, 162, 138,
    212, 225, 17, 208, 8, 139, 42, 242, 237, 154, 100, 63, 193, 108, 249, 236,
];

/// The first table of `mpbbCrypt` (MS-PST §5.1), `mpbbR`: the permutation's encoder, and the first step of the cyclic algorithm (§5.2).
#[rustfmt::skip]
const CYCLIC_R: [u8; 256] = [
    65, 54, 19, 98, 168, 33, 110, 187, 244, 22, 204, 4, 127, 100, 232, 93, 30, 242, 203, 42,
    116, 197, 94, 53, 210, 149, 71, 158, 150, 45, 154, 136, 76, 125, 132, 63, 219, 172, 49, 182,
    72, 95, 246, 196, 216, 57, 139, 231, 35, 59, 56, 142, 200, 193, 223, 37, 177, 32, 165, 70,
    96, 78, 156, 251, 170, 211, 86, 81, 69, 124, 85, 0, 7, 201, 43, 157, 133, 155, 9, 160,
    143, 173, 179, 15, 99, 171, 137, 75, 215, 167, 21, 90, 113, 102, 66, 191, 38, 74, 107, 152,
    250, 234, 119, 83, 178, 112, 5, 44, 253, 89, 58, 134, 126, 206, 6, 235, 130, 120, 87, 199,
    141, 67, 175, 180, 28, 212, 91, 205, 226, 233, 39, 79, 195, 8, 114, 128, 207, 176, 239, 245,
    40, 109, 190, 48, 77, 52, 146, 213, 14, 60, 34, 50, 229, 228, 249, 159, 194, 209, 10, 129,
    18, 225, 238, 145, 131, 118, 227, 151, 230, 97, 138, 23, 121, 164, 183, 220, 144, 122, 92, 140,
    2, 166, 202, 105, 222, 80, 26, 17, 147, 185, 82, 135, 88, 252, 237, 29, 55, 73, 27, 106,
    224, 41, 51, 153, 189, 108, 217, 148, 243, 64, 84, 111, 240, 198, 115, 184, 214, 62, 101, 24,
    68, 31, 221, 103, 16, 241, 12, 25, 236, 174, 3, 161, 20, 123, 169, 11, 255, 248, 163, 192,
    162, 1, 247, 46, 188, 36, 104, 117, 13, 254, 186, 47, 181, 208, 218, 61,
];

/// The second table of `mpbbCrypt`, `mpbbS`, used only by the cyclic algorithm (§5.2).
#[rustfmt::skip]
const CYCLIC_S: [u8; 256] = [
    20, 83, 15, 86, 179, 200, 122, 156, 235, 101, 72, 23, 22, 21, 159, 2, 204, 84, 124, 131,
    0, 13, 12, 11, 162, 98, 168, 118, 219, 217, 237, 199, 197, 164, 220, 172, 133, 116, 214, 208,
    167, 155, 174, 154, 150, 113, 102, 195, 99, 153, 184, 221, 115, 146, 142, 132, 125, 165, 94, 209,
    93, 147, 177, 87, 81, 80, 128, 137, 82, 148, 79, 78, 10, 107, 188, 141, 127, 110, 71, 70,
    65, 64, 68, 1, 17, 203, 3, 63, 247, 244, 225, 169, 143, 60, 58, 249, 251, 240, 25, 48,
    130, 9, 46, 201, 157, 160, 134, 73, 238, 111, 77, 109, 196, 45, 129, 52, 37, 135, 27, 136,
    170, 252, 6, 161, 18, 56, 253, 76, 66, 114, 100, 19, 55, 36, 106, 117, 119, 67, 255, 230,
    180, 75, 54, 92, 228, 216, 53, 61, 69, 185, 44, 236, 183, 49, 43, 41, 7, 104, 163, 14,
    105, 123, 24, 158, 33, 57, 190, 40, 26, 91, 120, 245, 35, 202, 42, 176, 175, 62, 254, 4,
    140, 231, 229, 152, 50, 149, 211, 246, 74, 232, 166, 234, 233, 243, 213, 47, 112, 32, 242, 31,
    5, 103, 173, 85, 16, 206, 205, 227, 39, 59, 218, 186, 215, 194, 38, 212, 145, 29, 210, 28,
    34, 51, 248, 250, 241, 90, 239, 207, 144, 182, 139, 181, 189, 192, 191, 8, 151, 30, 108, 226,
    97, 224, 198, 193, 89, 171, 187, 88, 222, 95, 223, 96, 121, 126, 178, 138,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Crypt {
    None,
    Permute,
    /// `NDB_CRYPT_CYCLIC` (MS-PST §5.2), keyed by the low DWORD of the block's id.
    Cyclic,
}

/// `CryptCyclic` of MS-PST §5.2, a symmetric cipher: encodes and decodes in place, with `key` the low DWORD of
/// the block's BID. `mpbbI` is [`PERMUTE_DECODE`].
fn crypt_cyclic(data: &mut [u8], key: u32) {
    let mut w = (key ^ (key >> 16)) as u16;
    for x in data {
        let mut b = x.wrapping_add(w as u8);
        b = CYCLIC_R[usize::from(b)];
        b = b.wrapping_add((w >> 8) as u8);
        b = CYCLIC_S[usize::from(b)];
        b = b.wrapping_sub((w >> 8) as u8);
        b = PERMUTE_DECODE[usize::from(b)];
        *x = b.wrapping_sub(w as u8);
        w = w.wrapping_add(1);
    }
}

/// Where a block's data sits in the file.
#[derive(Debug, Clone, Copy)]
struct BlockLoc {
    ib: u64,
    cb: u16,
}

/// A B-tree page that passed every check.
struct Page<'a> {
    bytes: &'a [u8],
    c_ent: usize,
    cb_ent: usize,
    level: u8,
}

impl<'a> Page<'a> {
    fn entry(&self, i: usize) -> Option<&'a [u8]> {
        if i >= self.c_ent {
            return None;
        }
        self.bytes.get(i * self.cb_ent..(i + 1) * self.cb_ent)
    }
}

/// What walking one live tree found.
#[derive(Default)]
struct Walk {
    leaves: Vec<Vec<u8>>,
    pages: HashSet<u64>,
    faults: Vec<String>,
}

/// A store opened for reading: its layout, its live trees and every valid
/// block found by scanning.
pub struct Store<'a> {
    data: &'a [u8],
    layout: Layout,
    crypt: Crypt,
    nbt_root: Bref,
    bbt_root: Bref,
    /// Live nodes by node id.
    nodes: BTreeMap<u32, NbtEntry>,
    /// Block ids the live block B-tree names.
    live_bids: HashSet<u64>,
    /// Every block whose trailer validates, by id with the reserved bit
    /// cleared, referenced or not.
    found: BTreeMap<u64, BlockLoc>,
    live_pages: HashSet<u64>,
    /// Offsets whose block trailer matched but whose CRC did not.
    blocks_unvalidated: Listed<u64>,
    /// What stopped either live tree being read whole.
    faults: Vec<String>,
}

impl<'a> Store<'a> {
    /// Open `data`. Fails only for a store this module does not read; damage
    /// inside one is recorded as faults and does not stop the open.
    pub fn open(data: &'a [u8]) -> Result<Self, Pst512Error> {
        let not = |s: String| Err(Pst512Error::NotThisFormat(s));
        if data.get(..4) != Some(MAGIC.as_slice()) {
            return not("the file does not begin with the store magic '!BDN'".into());
        }
        let version = le_u16(data, 10).unwrap_or(0);
        let (layout, root_at, crypt_at) = match version {
            14 | 15 => (Layout::Ansi, 164usize, 461usize),
            23 => (Layout::Unicode, 180, 513),
            36 | 37 => {
                return not(format!(
                    "version {version} is the 4 KiB-page layout, read by ost4k"
                ))
            }
            v => return not(format!("store version {v} is not one this module reads")),
        };
        let crypt = match data.get(crypt_at) {
            Some(0) => Crypt::None,
            Some(1) => Crypt::Permute,
            Some(2) => Crypt::Cyclic,
            None => return not("the header is too short to hold the encryption byte".into()),
            Some(n) => return not(format!("encryption method {n} is not recognised")),
        };
        // Root: dwReserved, ibFileEof, ibAMapLast, cbAMapFree, cbPMapFree,
        // then the node and block B-tree roots.
        let w = layout.wide();
        let bref = |at: usize| -> Option<Bref> {
            Some(Bref {
                bid: layout.read_wide(data, at)?,
                ib: layout.read_wide(data, at + w)?,
            })
        };
        let brefs_at = root_at + 4 + 4 * w;
        let (Some(nbt_root), Some(bbt_root)) = (bref(brefs_at), bref(brefs_at + 2 * w)) else {
            return not("the header is too short to hold the B-tree roots".into());
        };
        let mut s = Store {
            data,
            layout,
            crypt,
            nbt_root,
            bbt_root,
            nodes: BTreeMap::new(),
            live_bids: HashSet::new(),
            found: BTreeMap::new(),
            live_pages: HashSet::new(),
            blocks_unvalidated: Listed::default(),
            faults: Vec::new(),
        };
        (s.found, s.blocks_unvalidated) = s.scan_blocks();
        let nbt = s.walk(s.nbt_root, PTYPE_NBT);
        let bbt = s.walk(s.bbt_root, PTYPE_BBT);
        s.live_pages.extend(&nbt.pages);
        s.live_pages.extend(&bbt.pages);
        s.faults.extend(nbt.faults.into_iter().chain(bbt.faults));
        for e in &nbt.leaves {
            if let Some(n) = s.nbt_entry(e) {
                s.nodes.insert(n.nid as u32, n);
            }
        }
        for e in &bbt.leaves {
            if let Some(bid) = layout.read_wide(e, 0) {
                s.live_bids.insert(bid & !1);
            }
        }
        Ok(s)
    }

    pub fn layout(&self) -> Layout {
        self.layout
    }

    /// Live message nodes the node B-tree names.
    pub fn live_message_nodes(&self) -> Vec<u32> {
        self.nodes
            .keys()
            .copied()
            .filter(|n| n & 0x1F == NID_TYPE_NORMAL_MESSAGE)
            .collect()
    }

    /// A live message read the way a recovered one is: its properties, its attachments' property
    /// maps, and what could not be read. The linked reader refuses a message with no recipient
    /// table; this one does not need it, and does not read it.
    pub fn read_live_message(&self, nid: u32) -> Result<LiveMessage, String> {
        let n = self
            .nodes
            .get(&nid)
            .ok_or_else(|| format!("node {nid:#x} is not live"))?;
        let a = attempt(self, n.bid_data, n.bid_sub)?;
        Ok(LiveMessage {
            props: a.props,
            props_unreadable: a.props_unreadable,
            attachments: a.attachments,
            attachments_unreadable: a.attachments_unreadable,
            recipients: a.recipients,
            subnodes_read: a.subnodes_read,
            gaps: a.gaps,
        })
    }

    /// The recipient table held in a message's subnode: a table context of the recipients, one row each.
    fn read_recipient_table(&self, sub: &Subnode) -> Result<TableContext, LtpFault> {
        let pages = self.data_pages(sub.bid_data).map_err(LtpFault::Invalid)?;
        let subs = self.subnodes(sub.bid_sub).map_err(LtpFault::Invalid)?;
        let hn = HeapNode::from_pages(pages, subs)?;
        let block_cap = match self.layout {
            Layout::Ansi => 8180,
            Layout::Unicode => 8176,
        };
        read_tc_with(
            hn,
            &|s| self.data_concat(s.bid_data).map_err(LtpFault::Invalid),
            &|s| self.data_pages(s.bid_data).map_err(LtpFault::Invalid),
            block_cap,
        )
    }

    /// The property context of live node `nid`.
    pub fn read_live_pc(&self, nid: u32) -> Result<PropertyContext, LtpFault> {
        let n = self
            .nodes
            .get(&nid)
            .ok_or_else(|| LtpFault::Invalid(format!("node {nid:#x} is not live")))?;
        self.read_pc(n.bid_data, n.bid_sub)
    }

    /// The path of every live folder node, from the display names up the
    /// chain of parent nodes the node B-tree records. A name that will not
    /// read is shown as the node id. A chain that does not reach the root (a
    /// parent the node B-tree lacks or that is not a folder, or nesting past
    /// [`MAX_FOLDER_DEPTH`]) starts with a marker saying so, so a path is never
    /// silently shorter than the chain it stands for.
    pub fn folder_paths(&self) -> std::collections::HashMap<u32, String> {
        const NID_TYPE_FOLDER: u32 = 0x02;
        const PID_DISPLAY_NAME: u16 = 0x3001;
        let name_of = |nid: u32| -> String {
            match self
                .read_live_pc(nid)
                .ok()
                .and_then(|pc| pc.props.get(&PID_DISPLAY_NAME).cloned())
            {
                Some(PropValue::Str(s)) if !s.is_empty() => s,
                _ => format!("(folder node {nid:#x})"),
            }
        };
        // The root folder is its own parent and has no name of its own; it
        // is where every path starts, not a segment of one.
        let is_root = |nid: u32| self.nodes.get(&nid).is_some_and(|n| n.nid_parent == nid);
        let mut out = std::collections::HashMap::new();
        for &nid in self.nodes.keys().filter(|n| *n & 0x1F == NID_TYPE_FOLDER) {
            let mut parts = Vec::new();
            let mut at = nid;
            let mut stopped = Some("(path truncated at depth limit)".to_string());
            for _ in 0..MAX_FOLDER_DEPTH {
                if is_root(at) {
                    stopped = None;
                    break;
                }
                parts.push(name_of(at));
                let parent = self.nodes.get(&at).map_or(at, |n| n.nid_parent);
                if parent & 0x1F != NID_TYPE_FOLDER {
                    stopped = Some(format!("(parent node {parent:#x} is not a folder)"));
                    break;
                }
                if !self.nodes.contains_key(&parent) {
                    stopped = Some(format!("(parent node {parent:#x} not found)"));
                    break;
                }
                at = parent;
            }
            // The last step may have arrived at the root without a turn left
            // to notice it.
            if is_root(at) {
                stopped = None;
            }
            parts.extend(stopped);
            parts.reverse();
            out.insert(nid, parts.join("/"));
        }
        out
    }

    /// What stopped a live tree being read whole; empty when neither was cut.
    pub fn faults(&self) -> &[String] {
        &self.faults
    }

    fn nbt_entry(&self, e: &[u8]) -> Option<NbtEntry> {
        let (l, w) = (self.layout, self.layout.wide());
        Some(NbtEntry {
            nid: l.read_wide(e, 0)?,
            bid_data: l.read_wide(e, w)?,
            bid_sub: l.read_wide(e, 2 * w)?,
            nid_parent: le_u32(e, 3 * w)?,
        })
    }

    /// The page bytes at `ib`, its page type, BID and stored CRC, when the
    /// trailer has the shape of a B-tree page's: the type repeated and the
    /// signature the one that offset and BID give. The CRC is not checked.
    fn page_trailer(&self, ib: u64) -> Option<(&'a [u8], u8, u64, u32)> {
        let start = usize::try_from(ib).ok()?;
        let bytes = self.data.get(start..start.checked_add(PAGE)?)?;
        let t = &bytes[PAGE - self.layout.trailer()..];
        let (crc, bid) = match self.layout {
            Layout::Ansi => (le_u32(t, 8)?, u64::from(le_u32(t, 4)?)),
            Layout::Unicode => (le_u32(t, 4)?, le_u64(t, 8)?),
        };
        let pt = t[0];
        if (pt != PTYPE_BBT && pt != PTYPE_NBT) || t[1] != pt || le_u16(t, 2)? != ndb_sig(ib, bid) {
            return None;
        }
        Some((bytes, pt, bid, crc))
    }

    /// The page at `ib`, when its trailer and CRC are the ones Outlook would
    /// have written there. `expect_bid` is the parent's claim, when there is
    /// a parent; a scan has none and takes the page's own.
    fn page_at(&self, ib: u64, ptype: Option<u8>, expect_bid: Option<u64>) -> Option<Page<'a>> {
        let l = self.layout;
        let (bytes, pt, bid, crc) = self.page_trailer(ib)?;
        if ptype.is_some_and(|p| p != pt)
            || expect_bid.is_some_and(|b| b & !1 != bid & !1)
            || crc != ndb_crc(&bytes[..PAGE - l.trailer()])
        {
            return None;
        }
        let m = &bytes[l.meta_at()..];
        let (c_ent, cb_ent, level) = (usize::from(m[0]), usize::from(m[2]), m[3]);
        if c_ent.checked_mul(cb_ent)? > l.meta_at() {
            return None;
        }
        Some(Page {
            bytes,
            c_ent,
            cb_ent,
            level,
        })
    }

    /// Every leaf entry of the tree rooted at `root`. A page that does not
    /// validate, or an entry of the wrong size, is a fault and the walk goes
    /// on past it.
    fn walk(&self, root: Bref, ptype: u8) -> Walk {
        let l = self.layout;
        let leaf_len = if ptype == PTYPE_NBT {
            l.nbt_leaf()
        } else {
            l.bbt_leaf()
        };
        let mut w = Walk::default();
        let mut stack = vec![(root, MAX_DEPTH)];
        while let Some((r, depth)) = stack.pop() {
            if !w.pages.insert(r.ib) {
                w.faults
                    .push(format!("page {:#x} is named more than once", r.ib));
                continue;
            }
            let Some(p) = self.page_at(r.ib, Some(ptype), Some(r.bid)) else {
                w.faults.push(format!(
                    "the page at {:#x} (block id {:#x}) does not validate as a B-tree page",
                    r.ib, r.bid
                ));
                continue;
            };
            if p.level == 0 {
                if p.cb_ent != leaf_len {
                    w.faults.push(format!(
                        "leaf page {:#x} has {}-byte entries where {leaf_len} belong",
                        r.ib, p.cb_ent
                    ));
                    continue;
                }
                w.leaves
                    .extend((0..p.c_ent).filter_map(|i| p.entry(i)).map(<[u8]>::to_vec));
            } else if depth == 0 || p.cb_ent != l.index() {
                w.faults.push(format!(
                    "index page {:#x} is deeper than {MAX_DEPTH} levels or has {}-byte entries",
                    r.ib, p.cb_ent
                ));
            } else {
                for i in (0..p.c_ent).rev() {
                    let Some(e) = p.entry(i) else { continue };
                    if let (Some(bid), Some(ib)) =
                        (l.read_wide(e, l.wide()), l.read_wide(e, 2 * l.wide()))
                    {
                        stack.push((Bref { bid, ib }, depth - 1));
                    }
                }
            }
        }
        w
    }

    /// Every B-tree page that validates at a 512-byte offset, referenced or
    /// not, and the offsets whose trailer matched but whose CRC or metadata
    /// did not.
    fn scan_pages(&self) -> Scan<ScannedPage> {
        let mut out = Vec::new();
        let mut unvalidated = Listed::default();
        let mut ib = 0usize;
        while ib + PAGE <= self.data.len() {
            match (
                self.page_at(ib as u64, None, None),
                self.page_trailer(ib as u64),
            ) {
                (Some(p), Some((_, ptype, bid, _))) => out.push(ScannedPage {
                    ib: ib as u64,
                    bid,
                    ptype,
                    level: p.level,
                }),
                // A trailer of a page's shape that the CRC or metadata refused.
                (None, Some(_)) => unvalidated.push(ib as u64),
                _ => {}
            }
            ib += PAGE;
        }
        Scan {
            found: out,
            unvalidated,
        }
    }

    /// Every block whose trailer validates at its own offset. Each 64-byte
    /// boundary is tried as the end of a block's slot: the trailer there gives
    /// the stored size, and so where the slot starts; the block is accepted
    /// when the signature is the one that start and its id give and the CRC
    /// over the stored bytes matches. A block id found twice keeps its first
    /// copy. A block whose signature matched but whose CRC did not is returned
    /// in the second value, not dropped.
    fn scan_blocks(&self) -> (BTreeMap<u64, BlockLoc>, Listed<u64>) {
        let l = self.layout;
        let mut out = BTreeMap::new();
        let mut unvalidated = Listed::default();
        let mut end = BLOCK_ALIGN;
        while end <= self.data.len() {
            let t = &self.data[end - l.trailer()..end];
            end += BLOCK_ALIGN;
            let (Some(cb), Some(sig)) = (le_u16(t, 0), le_u16(t, 2)) else {
                continue;
            };
            let (crc, bid) = match l {
                Layout::Ansi => (le_u32(t, 8), le_u32(t, 4).map(u64::from)),
                Layout::Unicode => (le_u32(t, 4), le_u64(t, 8)),
            };
            let (Some(crc), Some(bid)) = (crc, bid) else {
                continue;
            };
            let cb_len = usize::from(cb);
            if cb_len == 0 || cb_len > MAX_BLOCK_SLOT - l.trailer() {
                continue;
            }
            let slot = (cb_len + l.trailer()).div_ceil(BLOCK_ALIGN) * BLOCK_ALIGN;
            let Some(start) = (end - BLOCK_ALIGN).checked_sub(slot) else {
                continue;
            };
            if sig != ndb_sig(start as u64, bid) {
                continue;
            }
            if crc != ndb_crc(&self.data[start..start + cb_len]) {
                unvalidated.push(start as u64);
                continue;
            }
            out.entry(bid & !1).or_insert(BlockLoc {
                ib: start as u64,
                cb,
            });
        }
        (out, unvalidated)
    }

    /// The decoded bytes of block `bid`.
    fn block(&self, bid: u64) -> Result<Vec<u8>, String> {
        let loc = self.found.get(&(bid & !1)).ok_or_else(|| {
            format!("block {bid:#x} was not found anywhere in the bytes supplied")
        })?;
        let start = loc.ib as usize;
        let mut b = self.data[start..start + usize::from(loc.cb)].to_vec();
        if bid & BID_INTERNAL == 0 {
            match self.crypt {
                Crypt::None => {}
                Crypt::Permute => {
                    for x in &mut b {
                        *x = PERMUTE_DECODE[usize::from(*x)];
                    }
                }
                Crypt::Cyclic => crypt_cyclic(&mut b, bid as u32),
            }
        }
        Ok(b)
    }

    /// A node's data as one block per heap page: the block itself, or the
    /// blocks an extended block (or a tree of them) names.
    fn data_pages(&self, bid: u64) -> Result<Vec<Vec<u8>>, String> {
        let first = self.block(bid)?;
        if bid & BID_INTERNAL == 0 {
            return Ok(vec![first]);
        }
        let w = self.layout.wide();
        let children = |x: &[u8], expect_level: u8| -> Result<Vec<u64>, String> {
            if x.first() != Some(&0x01) || x.get(1) != Some(&expect_level) {
                return Err(format!(
                    "an extended block of level {expect_level} was expected, not {:?}/{:?}",
                    x.first(),
                    x.get(1)
                ));
            }
            let n = usize::from(le_u16(x, 2).unwrap_or(0));
            (0..n)
                .map(|i| {
                    self.layout
                        .read_wide(x, 8 + i * w)
                        .ok_or_else(|| "an extended block ends inside its list".to_string())
                })
                .collect()
        };
        let level = first.get(1).copied().unwrap_or(0);
        let mut leaves = Vec::new();
        match level {
            1 => leaves = children(&first, 1)?,
            2 => {
                for sub in children(&first, 2)? {
                    leaves.extend(children(&self.block(sub)?, 1)?);
                }
            }
            n => {
                return Err(format!(
                    "an extended block of level {n} is not one Outlook writes"
                ))
            }
        }
        if leaves.len() > MAX_NODE_BLOCKS {
            return Err("a node names more data blocks than a store holds".to_string());
        }
        leaves.into_iter().map(|b| self.block(b)).collect()
    }

    fn data_concat(&self, bid: u64) -> Result<Vec<u8>, String> {
        Ok(self.data_pages(bid)?.concat())
    }

    /// The subnode tree under `bid_sub`: node id to the subnode's data and
    /// its own subnodes.
    fn subnodes(&self, bid_sub: u64) -> Result<BTreeMap<u32, Subnode>, String> {
        let mut out = BTreeMap::new();
        if bid_sub == 0 {
            return Ok(out);
        }
        let (l, w) = (self.layout, self.layout.wide());
        let mut stack = vec![(bid_sub, MAX_DEPTH)];
        let mut seen = HashSet::new();
        while let Some((bid, depth)) = stack.pop() {
            if !seen.insert(bid) || depth == 0 {
                return Err("a subnode tree names a block twice or is too deep".to_string());
            }
            let x = self.block(bid)?;
            if x.first() != Some(&0x02) {
                return Err(format!("subnode block {bid:#x} is not a subnode block"));
            }
            let n = usize::from(le_u16(&x, 2).unwrap_or(0));
            let head = if l == Layout::Ansi { 4 } else { 8 };
            if x.get(1) == Some(&0) {
                for i in 0..n {
                    let at = head + i * 3 * w;
                    let (Some(nid), Some(bd), Some(bs)) = (
                        l.read_wide(&x, at),
                        l.read_wide(&x, at + w),
                        l.read_wide(&x, at + 2 * w),
                    ) else {
                        return Err("a subnode block ends inside its entries".to_string());
                    };
                    out.insert(
                        nid as u32,
                        Subnode {
                            bid_data: bd,
                            bid_sub: bs,
                        },
                    );
                }
            } else {
                for i in 0..n {
                    let at = head + i * 2 * w;
                    let Some(child) = l.read_wide(&x, at + w) else {
                        return Err("a subnode block ends inside its entries".to_string());
                    };
                    stack.push((child, depth - 1));
                }
            }
        }
        Ok(out)
    }

    /// The property context of the node whose data and subnode trees start
    /// at these blocks, whether or not any live tree names them.
    pub fn read_pc(&self, bid_data: u64, bid_sub: u64) -> Result<PropertyContext, LtpFault> {
        let pages = self.data_pages(bid_data).map_err(LtpFault::Invalid)?;
        let subs = self.subnodes(bid_sub).map_err(LtpFault::Invalid)?;
        let hn = HeapNode::from_pages(pages, subs)?;
        read_pc_with(hn, &|s| {
            self.data_concat(s.bid_data).map_err(LtpFault::Invalid)
        })
    }
}

/// A live message, read by [`Store::read_live_message`].
#[derive(Debug, Clone)]
pub struct LiveMessage {
    pub props: BTreeMap<u16, PropValue>,
    pub props_unreadable: Vec<(u16, String)>,
    pub attachments: Vec<BTreeMap<u16, PropValue>>,
    pub attachments_unreadable: usize,
    /// The recipient table's rows, in table order, when the message has one and it was read; `None`
    /// when it has none or the subnode tree that holds it did not read (`gaps` says which).
    pub recipients: Option<Vec<BTreeMap<u16, PropValue>>>,
    /// Whether the subnode tree (large body, attachments) was read.
    pub subnodes_read: bool,
    /// What could not be read, in words.
    pub gaps: Vec<String>,
}

/// One stale node entry version, read.
struct Attempt {
    props: BTreeMap<u16, PropValue>,
    props_unreadable: Vec<(u16, String)>,
    attachments: Vec<BTreeMap<u16, PropValue>>,
    attachments_unreadable: usize,
    recipients: Option<Vec<BTreeMap<u16, PropValue>>>,
    subnodes_read: bool,
    gaps: Vec<String>,
}

fn attempt(store: &Store<'_>, bid_data: u64, bid_sub: u64) -> Result<Attempt, String> {
    let mut gaps = Vec::new();
    let (pc, subnodes_read) = match store.read_pc(bid_data, bid_sub) {
        Ok(pc) => (pc, bid_sub != 0),
        Err(e) if bid_sub != 0 => {
            let pc = store
                .read_pc(bid_data, 0)
                .map_err(|e2| format!("its data (id {bid_data:#x}) could not be read: {e2}"))?;
            gaps.push(format!(
                "its subnode tree (id {bid_sub:#x}) could not be read ({e}); anything stored in \
                 its subnodes (a large body, recipients, attachments) is not recovered"
            ));
            (pc, false)
        }
        Err(e) => {
            return Err(format!(
                "its data (id {bid_data:#x}) could not be read: {e}"
            ))
        }
    };
    let mut attachments = Vec::new();
    let mut attachments_unreadable = 0;
    for (&snid, sub) in &pc.subnodes {
        if snid & 0x1F != NID_TYPE_ATTACHMENT {
            continue;
        }
        match store.read_pc(sub.bid_data, sub.bid_sub) {
            Ok(a) => attachments.push(a.props),
            Err(e) => note_unreadable_attachment(
                &mut gaps,
                &mut attachments_unreadable,
                snid,
                sub.bid_data,
                &e,
            ),
        }
    }
    note_attachment_overflow(&mut gaps, attachments_unreadable);
    let mut recipients = None;
    if let Some((snid, sub)) = pc
        .subnodes
        .iter()
        .find(|(snid, _)| **snid & 0x1F == NID_TYPE_RECIPIENT_TABLE)
    {
        match store.read_recipient_table(sub) {
            Ok(t) => {
                if !t.unreadable.is_empty() {
                    gaps.push(format!(
                        "{} recipient cell(s) or row(s) of the table in subnode {snid:#x} could not be read",
                        t.unreadable.len()
                    ));
                }
                recipients = Some(t.rows);
            }
            Err(e) => gaps.push(format!(
                "its recipient table (subnode {snid:#x}) could not be read: {e}"
            )),
        }
    }
    if !pc.unreadable.is_empty() {
        gaps.push(format!(
            "{} propert(y/ies) present could not be read",
            pc.unreadable.len()
        ));
    }
    Ok(Attempt {
        props: pc.props,
        props_unreadable: pc.unreadable,
        attachments,
        attachments_unreadable,
        recipients,
        subnodes_read,
        gaps,
    })
}

/// A message's subject and delivery time, when it has both: the pair a draft
/// keeps when it becomes the message it was written to be.
fn subject_and_time(props: &BTreeMap<u16, PropValue>) -> Option<(String, String)> {
    // Only used to match one message against another, so an 8-bit subject in a
    // legacy code page is compared by its stored bytes, not decoded.
    let subject = match props.get(&0x0037)? {
        PropValue::Str(s) => s.clone(),
        PropValue::Other { ptype: 0x001E, raw } => String::from_utf8_lossy(raw).into_owned(),
        _ => return None,
    };
    let time = format!("{:?}", props.get(&0x0E06)?);
    Some((subject, time))
}

/// Recover deleted messages from a version 14, 15 or 23 store.
pub fn recover(data: &[u8]) -> Result<Recovery, Pst512Error> {
    Ok(recover_store(&Store::open(data)?))
}

/// [`recover`] over a store already opened, so a caller that also needs the
/// store (for its folder paths) opens it, and scans it, once.
pub fn recover_store(store: &Store<'_>) -> Recovery {
    recover_up_to(store, MAX_RECOVERED)
}

fn recover_up_to(store: &Store<'_>, cap: usize) -> Recovery {
    let data = store.data;
    let mut r = Recovery {
        pages_scanned: data.len() / PAGE,
        blocks_unvalidated: store.blocks_unvalidated.clone(),
        ..Recovery::default()
    };
    let scanned_pages = store.scan_pages();
    r.pages_unvalidated = scanned_pages.unvalidated;
    let pages = scanned_pages.found;
    let stale: Vec<&ScannedPage> = pages
        .iter()
        .filter(|p| !store.live_pages.contains(&p.ib))
        .collect();
    r.unreferenced_pages = stale.iter().map(|p| p.ib).collect();
    r.blocks_found = store.found.len();
    let unreferenced: Vec<u64> = store
        .found
        .keys()
        .copied()
        .filter(|b| !store.live_bids.contains(b))
        .collect();
    r.unreferenced_blocks = unreferenced.len();

    // Every version of every message node entry the live tree lacks, with the
    // stale pages it was seen in.
    type Versions = BTreeMap<(u64, u64), (u32, Vec<u64>)>;
    let mut entries: BTreeMap<u32, Versions> = BTreeMap::new();
    for p in stale
        .iter()
        .filter(|p| p.ptype == PTYPE_NBT && p.level == 0)
    {
        let Some(page) = store.page_at(p.ib, Some(PTYPE_NBT), None) else {
            continue;
        };
        if page.cb_ent != store.layout.nbt_leaf() {
            continue;
        }
        for i in 0..page.c_ent {
            let Some(n) = page.entry(i).and_then(|e| store.nbt_entry(e)) else {
                continue;
            };
            let nid = n.nid as u32;
            if nid & 0x1F != NID_TYPE_NORMAL_MESSAGE || store.nodes.contains_key(&nid) {
                continue;
            }
            let v = entries
                .entry(nid)
                .or_default()
                .entry((n.bid_data, n.bid_sub))
                .or_insert((n.nid_parent, Vec::new()));
            if !v.1.contains(&p.ib) {
                v.1.push(p.ib);
            }
        }
    }

    let caveat = |what: &str| -> Vec<String> {
        if store.faults.is_empty() {
            Vec::new()
        } else {
            vec![format!(
                "a live B-tree could not be read in full ({} fault(s)), so {what}",
                store.faults.len()
            )]
        }
    };

    let mut used: HashSet<u64> = HashSet::new();
    for versions in entries.values() {
        for (bid_data, _) in versions.keys() {
            used.insert(bid_data & !1);
        }
    }
    // Each live message is read once, in ascending node order, so a later node
    // wins a duplicate subject-and-time key. A draft is rewritten into the
    // message it becomes, and the earlier state can survive in an unreferenced
    // block with every other property different, so `identity` cannot link
    // it; the subject and delivery time can.
    let mut live_ids: HashSet<String> = HashSet::new();
    let mut live_by_subject_and_time: BTreeMap<(String, String), u32> = BTreeMap::new();
    for n in store.live_message_nodes() {
        let Ok(pc) = store.read_live_pc(n) else {
            continue;
        };
        live_ids.extend(identity(&pc.props));
        if let Some(key) = subject_and_time(&pc.props) {
            live_by_subject_and_time.insert(key, n);
        }
    }
    let mut seen = live_ids.clone();
    for (nid, versions) in entries {
        if r.messages.len() >= cap {
            r.capped = true;
            break;
        }
        // Newest first: block ids only grow, so the highest data id is the
        // latest version Outlook wrote.
        let mut order: Vec<_> = versions.into_iter().collect();
        order.sort_by_key(|v| std::cmp::Reverse(v.0 .0));
        let mut chosen = None;
        let mut tried_errors: Vec<String> = Vec::new();
        for (i, ((bd, bs), _)) in order.iter().enumerate() {
            match attempt(store, *bd, *bs) {
                Ok(a) => {
                    chosen = Some((i, a));
                    break;
                }
                Err(e) => tried_errors.push(e),
            }
        }
        let pick = chosen.as_ref().map_or(0, |(i, _)| *i);
        let ((bid_data, bid_sub), (parent_nid, page_offsets)) = order[pick].clone();
        let other_versions = order
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != pick)
            .map(|(i, ((bd, bs), (_, po)))| OtherVersion {
                bid_data: *bd,
                bid_sub: *bs,
                page_offsets: po.clone(),
                newer: i < pick,
                read_error: tried_errors.get(i).cloned(),
            })
            .collect();
        let offset = |bid: u64| store.found.get(&(bid & !1)).map(|l| l.ib);
        let m = match chosen {
            Some((_, a)) if identity(&a.props).is_some_and(|id| live_ids.contains(&id)) => {
                r.copies_of_live.push(nid);
                continue;
            }
            Some((_, mut a)) => {
                if pick > 0 {
                    a.gaps.push(format!(
                        "a newer version of this entry (data id {:#x}) did not read, so this \
                         is an earlier state of the message, not necessarily its last",
                        order[0].0 .0
                    ));
                }
                seen.extend(identity(&a.props));
                RecoveredMessage {
                    nid,
                    parent_nid,
                    bid_data,
                    bid_sub,
                    source: Source::StaleNodeEntry { page_offsets },
                    data_block_offset: offset(bid_data),
                    subnode_block_offset: offset(bid_sub).filter(|_| a.subnodes_read),
                    props: a.props,
                    props_unreadable: a.props_unreadable,
                    attachments: a.attachments,
                    attachments_unreadable: a.attachments_unreadable,
                    recipients: a.recipients,
                    completeness: if a.gaps.is_empty() {
                        Completeness::Complete
                    } else {
                        Completeness::Partial
                    },
                    gaps: a.gaps,
                    other_versions,
                    could_be_live: caveat("this message may be live under another node"),
                }
            }
            None => RecoveredMessage {
                nid,
                parent_nid,
                bid_data,
                bid_sub,
                source: Source::StaleNodeEntry { page_offsets },
                data_block_offset: None,
                subnode_block_offset: None,
                props: BTreeMap::new(),
                props_unreadable: Vec::new(),
                attachments: Vec::new(),
                attachments_unreadable: 0,
                recipients: None,
                completeness: Completeness::EntryOnly,
                // Every version was tried and none read: each reason names
                // its version's block, newest first.
                gaps: tried_errors,
                other_versions,
                could_be_live: caveat("this message may be live under another node"),
            },
        };
        r.messages.push(m);
    }

    // Message property contexts in unreferenced blocks that no recovered
    // entry names, newest first so a superseded copy is the one counted.
    let mut candidates: Vec<u64> = unreferenced
        .into_iter()
        .filter(|b| b & BID_INTERNAL == 0 && !used.contains(b))
        .collect();
    candidates.sort_by_key(|b| std::cmp::Reverse(*b));
    for bid in candidates {
        let Ok(bytes) = store.block(bid) else {
            continue;
        };
        if bytes.get(2) != Some(&0xEC) || bytes.get(3) != Some(&0xBC) {
            continue;
        }
        let Some(pc) = readable_context(
            store.read_pc(bid, 0),
            bid,
            store.found.get(&bid).map_or(0, |l| l.ib),
            &mut r.unread_contexts,
        ) else {
            continue;
        };
        if !matches!(
            pc.props.get(&PID_TAG_MESSAGE_CLASS),
            Some(PropValue::Str(_))
        ) {
            continue;
        }
        if matches!(
            pc.props.get(&PID_TAG_MESSAGE_FLAGS),
            Some(PropValue::I32(f)) if f & MF_FAI != 0
        ) {
            r.associated_items += 1;
            continue;
        }
        if identity(&pc.props).is_some_and(|id| !seen.insert(id)) {
            r.superseded_copies += 1;
            continue;
        }
        if r.fragments.len() >= cap {
            r.capped = true;
            break;
        }
        let mut gaps = vec![
            "no node entry names this block, so its folder and its subnode tree (a large \
             body, recipients, attachments) are unknown and were not read"
                .to_string(),
        ];
        if let Some(live) =
            subject_and_time(&pc.props).and_then(|k| live_by_subject_and_time.get(&k))
        {
            gaps.push(format!(
                "it shares its subject and delivery time with live message node {live:#x}, so \
                 it may be an earlier state of that message (a draft before it was sent, or a \
                 version before an edit) and not a separate deleted one"
            ));
        }
        if !pc.unreadable.is_empty() {
            gaps.push(format!(
                "{} propert(y/ies) present could not be read",
                pc.unreadable.len()
            ));
        }
        r.fragments.push(RecoveredMessage {
            nid: 0,
            parent_nid: 0,
            bid_data: bid,
            bid_sub: 0,
            source: Source::UnreferencedBlock,
            data_block_offset: store.found.get(&bid).map(|l| l.ib),
            subnode_block_offset: None,
            props: pc.props,
            props_unreadable: pc.unreadable,
            attachments: Vec::new(),
            attachments_unreadable: 0,
            recipients: None,
            completeness: Completeness::Partial,
            gaps,
            other_versions: Vec::new(),
            could_be_live: caveat("a node it did not reach may name this block"),
        });
    }
    r
}

/// A copy of `data` whose live node B-tree no longer lists `nid`: its leaf
/// entry is cut out and the page's CRC rewritten, as a deletion rewrites it.
/// Test support: what must come back is then known from the untouched file.
#[cfg(test)]
pub(crate) fn without_live_node(data: &[u8], nid: u32) -> Vec<u8> {
    let store = Store::open(data).expect("opens");
    let l = store.layout;
    let mut out = data.to_vec();
    for &ib in &store.live_pages {
        let Some(p) = store.page_at(ib, Some(PTYPE_NBT), None) else {
            continue;
        };
        if p.level != 0 {
            continue;
        }
        let at = (0..p.c_ent).find(|&i| {
            p.entry(i)
                .and_then(|e| store.nbt_entry(e))
                .is_some_and(|n| n.nid as u32 == nid)
        });
        let Some(at) = at else { continue };
        let page = &mut out[ib as usize..ib as usize + PAGE];
        let cb = p.cb_ent;
        page.copy_within((at + 1) * cb..p.c_ent * cb, at * cb);
        page[l.meta_at()] -= 1;
        let end = PAGE - l.trailer();
        let crc = ndb_crc(&page[..end]).to_le_bytes();
        let crc_at = if l == Layout::Ansi { end + 8 } else { end + 4 };
        page[crc_at..crc_at + 4].copy_from_slice(&crc);
        return out;
    }
    panic!("node {nid:#x} is in no live leaf page");
}

#[cfg(test)]
mod tests {

    //! Graded on real stores: a version 14 Outlook 2000 store from the NPS
    //! M57-Jean image, whose live content was read with libpff, and a real
    //! empty version 23 store (`tests/fixtures/pst_old/PROVENANCE.txt`). The
    //! deleted-message cases remove a live node's entry from a copy of the real
    //! store, so what must come back is known from the untouched file.
    use super::*;

    const V14: &[u8] =
        include_bytes!("../tests/fixtures/pst_old/m57_jean_administrator_outlook.pst");
    const V23: &[u8] = include_bytes!("../tests/fixtures/pst_old/outlook_pst_crate_empty_v23.pst");
    const WELCOME_NODE: u32 = 0x0020_0024;
    const WELCOME_SUBJECT: &str = "Welcome to Microsoft Outlook 2000!";

    /// The subject as the emitter reads it: Outlook's two-character prefix
    /// marker removed, which libpff also hides.
    fn subject(props: &BTreeMap<u16, PropValue>) -> Option<String> {
        match props.get(&0x0037) {
            Some(PropValue::Str(s)) => Some(crate::pst::normalise_subject(s)),
            _ => None,
        }
    }

    #[test]
    fn a_version_14_store_opens_as_ansi_and_its_live_message_reads() {
        let s = Store::open(V14).expect("a real version 14 store opens");
        assert_eq!(s.layout(), Layout::Ansi);
        assert!(s.faults().is_empty(), "{:?}", s.faults());
        assert_eq!(s.live_message_nodes(), vec![WELCOME_NODE]);
        let pc = s.read_live_pc(WELCOME_NODE).expect("the message reads");
        assert_eq!(subject(&pc.props).as_deref(), Some(WELCOME_SUBJECT));
    }

    #[test]
    fn a_recovered_message_is_placed_in_the_folder_libpff_places_it_in() {
        let cut = without_live_node(V14, WELCOME_NODE);
        let r = recover(&cut).unwrap();
        let m = &r.messages[0];
        let paths = Store::open(&cut).unwrap().folder_paths();
        assert_eq!(
            paths.get(&m.parent_nid).map(String::as_str),
            Some("Top of Personal Folders/Inbox"),
            "libpff: //Top of Personal Folders/Inbox"
        );
    }

    #[test]
    fn a_real_unicode_store_pins_the_unicode_layout_and_has_no_message() {
        let s = Store::open(V23).expect("a real version 23 store opens");
        assert_eq!(s.layout(), Layout::Unicode);
        assert!(s.faults().is_empty(), "{:?}", s.faults());
        assert!(s.live_message_nodes().is_empty());
        let r = recover(V23).unwrap();
        assert!(r.messages.is_empty() && r.fragments.is_empty());
    }

    #[test]
    fn an_untouched_store_reports_no_deleted_message() {
        // Its stale pages hold earlier copies of the entry for a message that
        // is still live: that is a superseded version, not a deletion.
        let r = recover(V14).unwrap();
        assert!(r.messages.is_empty(), "{:?}", r.messages);
        assert!(
            !r.unreferenced_pages.is_empty(),
            "the fixture has stale pages"
        );
    }

    #[test]
    fn a_message_whose_live_entry_is_gone_is_recovered_from_a_stale_page() {
        let cut = without_live_node(V14, WELCOME_NODE);
        let live = Store::open(&cut).unwrap();
        assert!(
            live.live_message_nodes().is_empty(),
            "the node is no longer live"
        );

        let r = recover(&cut).unwrap();
        let m = r
            .messages
            .iter()
            .find(|m| m.nid == WELCOME_NODE)
            .expect("the deleted message is recovered");
        assert_eq!(subject(&m.props).as_deref(), Some(WELCOME_SUBJECT));
        assert!(
            matches!(&m.source, Source::StaleNodeEntry { page_offsets } if !page_offsets.is_empty())
        );
        assert_eq!(m.completeness, Completeness::Complete, "{:?}", m.gaps);
        // libpff reads 8 attachments of these sizes from the untouched file.
        let sizes: Vec<usize> = m
            .attachments
            .iter()
            .filter_map(|a| match a.get(&0x3701) {
                Some(PropValue::Bin(b)) => Some(b.len()),
                _ => None,
            })
            .collect();
        let mut want = vec![8679, 1554, 1546, 1983, 1808, 5072, 1831, 911];
        let mut got = sizes;
        want.sort_unstable();
        got.sort_unstable();
        assert_eq!(got, want);
        assert_eq!(m.attachments_unreadable, 0);
        assert!(m.could_be_live.is_empty());
        assert!(m.data_block_offset.is_some());
    }

    fn refusal(bytes: &[u8]) -> String {
        let Pst512Error::NotThisFormat(why) = recover(bytes).expect_err("refused");
        why
    }

    /// A header of `version` with the encryption byte of that layout set to
    /// `crypt`, `len` bytes long.
    fn header(version: u16, crypt: u8, len: usize) -> Vec<u8> {
        let mut d = vec![0u8; len];
        d[..4].copy_from_slice(MAGIC);
        d[10..12].copy_from_slice(&version.to_le_bytes());
        let at = if version == 23 { 513 } else { 461 };
        if let Some(b) = d.get_mut(at) {
            *b = crypt;
        }
        d
    }

    /// Each refusal names its own cause; a reason that only says "something"
    /// would pass for any of them.
    #[test]
    fn a_store_of_another_layout_or_version_is_refused_by_name() {
        let v36 =
            include_bytes!("../tests/fixtures/ost_v36/iaman.informant_initialised_prefix.ost");
        let why = refusal(v36);
        assert!(why.contains("4 KiB") && why.contains("ost4k"), "{why}");
        let why = refusal(b"not a store at all");
        assert!(why.contains("!BDN"), "{why}");
        let mut other = header(99, 0, 600);
        other[10] = 99;
        let why = refusal(&other);
        assert!(why.contains("store version 99"), "{why}");
        // An encryption byte this reader has never seen is named by value.
        let why = refusal(&header(23, 7, 600));
        assert!(
            why.contains("encryption method 7 is not recognised"),
            "{why}"
        );
    }

    /// A header cut off before its encryption byte is a short header, not an
    /// "unrecognised encryption method".
    #[test]
    fn a_header_cut_before_the_encryption_byte_says_it_is_too_short() {
        for (version, len) in [(23, 513), (14, 461)] {
            let why = refusal(&header(version, 0, len));
            assert!(why.contains("too short"), "v{version}: {why}");
            assert!(!why.contains("encryption method"), "v{version}: {why}");
        }
    }

    /// A store with the nodes given (nid, parent) and no data at all: names
    /// fall back to the node id, which is what these paths are built from.
    fn store_of_nodes(nodes: &[(u32, u32)]) -> Store<'static> {
        Store {
            data: &[],
            layout: Layout::Unicode,
            crypt: Crypt::None,
            nbt_root: Bref { bid: 0, ib: 0 },
            bbt_root: Bref { bid: 0, ib: 0 },
            nodes: nodes
                .iter()
                .map(|&(nid, parent)| {
                    (
                        nid,
                        NbtEntry {
                            nid: u64::from(nid),
                            bid_data: 0,
                            bid_sub: 0,
                            nid_parent: parent,
                        },
                    )
                })
                .collect(),
            live_bids: HashSet::new(),
            found: BTreeMap::new(),
            live_pages: HashSet::new(),
            blocks_unvalidated: Listed::default(),
            faults: Vec::new(),
        }
    }

    const ROOT: u32 = 0x122;
    fn folder(i: u32) -> u32 {
        0x8000 + (i << 5) + 2
    }

    /// A folder nested deeper than 8 levels (the B-tree depth bound this used
    /// to share) still has its whole path; only nesting past the folder bound
    /// is marked, and an orphan or a non-folder parent is marked at its start.
    #[test]
    fn a_folder_path_is_whole_or_says_where_it_stops() {
        // ROOT <- 1 <- 2 <- ... <- depth
        let chain = |depth: u32| -> Vec<(u32, u32)> {
            let mut v = vec![(ROOT, ROOT)];
            for i in 1..=depth {
                v.push((folder(i), if i == 1 { ROOT } else { folder(i - 1) }));
            }
            v
        };
        let path = |nodes: &[(u32, u32)], nid: u32| {
            store_of_nodes(nodes).folder_paths().remove(&nid).unwrap()
        };
        // Nine levels: all nine, no marker.
        let p = path(&chain(9), folder(9));
        assert_eq!(p.split('/').count(), 9, "{p}");
        assert!(!p.contains("(path") && !p.contains("(parent"), "{p}");
        // Exactly the folder bound reaches the root on the last step.
        let n = MAX_FOLDER_DEPTH as u32;
        let p = path(&chain(n), folder(n));
        assert_eq!(p.split('/').count(), MAX_FOLDER_DEPTH, "{p}");
        assert!(
            !p.contains("(path"),
            "reaching the root on the last step is not a cut: {p}"
        );
        // One past it is cut, and says so first.
        let p = path(&chain(n + 1), folder(n + 1));
        assert!(p.starts_with("(path truncated at depth limit)/"), "{p}");
        // A parent the node B-tree lacks.
        let p = path(&[(ROOT, ROOT), (folder(1), folder(7))], folder(1));
        assert!(p.starts_with("(parent node 0x80e2 not found)/"), "{p}");
        // A parent that is not a folder.
        let p = path(&[(ROOT, ROOT), (folder(1), 0x24)], folder(1));
        assert!(p.starts_with("(parent node 0x24 is not a folder)/"), "{p}");
        // A folder directly under the root is just its own segment.
        let p = path(&chain(1), folder(1));
        assert_eq!(p.split('/').count(), 1, "{p}");
        assert!(!p.contains("(path") && !p.contains("(parent"), "{p}");
    }

    /// One scan serves both the folder paths and the recovery: the entry point
    /// that opens the store and the one that is handed it agree.
    #[test]
    fn recovering_from_an_open_store_matches_recovering_from_the_bytes() {
        let cut = without_live_node(V14, WELCOME_NODE);
        let a = recover(&cut).unwrap();
        let b = recover_store(&Store::open(&cut).unwrap());
        let key = |r: &Recovery| {
            (
                r.unreferenced_pages.clone(),
                r.unreferenced_blocks,
                r.messages.iter().map(|m| m.nid).collect::<Vec<_>>(),
                r.fragments.len(),
                r.superseded_copies,
            )
        };
        assert_eq!(key(&a), key(&b));
    }

    /// A copy of `data` whose stale node leaf page naming `nid` also names it
    /// with data block `bid_data`: one more (newer) version of the entry.
    fn with_stale_version(data: &[u8], nid: u32, bid_data: u64) -> Vec<u8> {
        let store = Store::open(data).unwrap();
        let l = store.layout;
        let mut out = data.to_vec();
        for p in store.scan_pages().found {
            if p.ptype != PTYPE_NBT || p.level != 0 || store.live_pages.contains(&p.ib) {
                continue;
            }
            let page = store.page_at(p.ib, Some(PTYPE_NBT), None).unwrap();
            let Some(proto) = (0..page.c_ent)
                .filter_map(|i| page.entry(i))
                .find(|e| store.nbt_entry(e).is_some_and(|n| n.nid as u32 == nid))
            else {
                continue;
            };
            let cb = page.cb_ent;
            if (page.c_ent + 1) * cb > l.meta_at() {
                continue;
            }
            let at = p.ib as usize;
            let w = l.wide();
            let mut entry = proto.to_vec();
            entry[w..2 * w].copy_from_slice(&bid_data.to_le_bytes()[..w]);
            let n = page.c_ent;
            out[at + n * cb..at + (n + 1) * cb].copy_from_slice(&entry);
            out[at + l.meta_at()] += 1;
            let end = PAGE - l.trailer();
            let crc = ndb_crc(&out[at..at + end]).to_le_bytes();
            let crc_at = at + if l == Layout::Ansi { end + 8 } else { end + 4 };
            out[crc_at..crc_at + 4].copy_from_slice(&crc);
            return out;
        }
        panic!("no stale leaf page names node {nid:#x}");
    }

    /// When no version of an entry reads, every version was tried, and each
    /// other version carries its own error and the gaps name each one.
    #[test]
    fn an_entry_none_of_whose_versions_read_reports_every_versions_error() {
        // The Welcome message gains a newer version whose data is absent, and
        // its one real version is damaged: two versions, neither reads.
        let cut = with_stale_version(&without_live_node(V14, WELCOME_NODE), WELCOME_NODE, 0xFFFC);
        let store = Store::open(&cut).unwrap();
        let real = recover(&cut).unwrap();
        let m = real
            .messages
            .iter()
            .find(|m| m.nid == WELCOME_NODE)
            .unwrap();
        assert_eq!((m.bid_data, m.other_versions.len()), (0x348, 1));
        assert!(m.other_versions[0].newer && m.other_versions[0].read_error.is_some());
        let bids = [0xFFFCu64, 0x348];
        let mut broken = cut.clone();
        let loc = store.found[&0x348];
        broken[loc.ib as usize] ^= 0xFF;
        let r = recover(&broken).unwrap();
        let m = r.messages.iter().find(|m| m.nid == WELCOME_NODE).unwrap();
        assert_eq!(m.completeness, Completeness::EntryOnly);
        assert_eq!(m.other_versions.len(), bids.len() - 1);
        assert!(
            m.other_versions.iter().all(|v| v.read_error.is_some()),
            "{:?}",
            m.other_versions
        );
        assert_eq!(m.gaps.len(), bids.len(), "{:?}", m.gaps);
    }

    /// A block that carries the property-context signature and does not decode
    /// is counted and located, not dropped. The candidate is an unreferenced
    /// property context of the real store (a superseded copy), with its BTH
    /// header's type byte broken and its CRC resealed so it is still a block.
    #[test]
    fn a_damaged_property_context_block_with_no_entry_is_counted() {
        let store = Store::open(V14).unwrap();
        let baseline = recover(V14).unwrap().unread_contexts.count;
        let bid = store
            .found
            .keys()
            .copied()
            .find(|b| {
                !store.live_bids.contains(b)
                    && b & BID_INTERNAL == 0
                    && store
                        .block(*b)
                        .is_ok_and(|x| x.get(2) == Some(&0xEC) && x.get(3) == Some(&0xBC))
                    && store.read_pc(*b, 0).is_ok()
            })
            .expect("the fixture has an unreferenced property context");
        let loc = store.found[&bid];
        let (start, cb) = (loc.ib as usize, usize::from(loc.cb));
        let block = store.block(bid).unwrap();
        // Heap allocation 1 (the BTH header) starts at the first map offset.
        let map = usize::from(le_u16(&block, 0).unwrap());
        let bth = usize::from(le_u16(&block, map + 4).unwrap());
        // The stored byte that decodes to zero, whatever the encryption.
        let zero = if store.crypt == Crypt::Permute {
            PERMUTE_DECODE.iter().position(|&d| d == 0).unwrap() as u8
        } else {
            0
        };
        let mut broken = V14.to_vec();
        broken[start + bth] = zero;
        let trailer = store.layout.trailer();
        let t = start + (cb + trailer).div_ceil(BLOCK_ALIGN) * BLOCK_ALIGN - trailer;
        let crc = ndb_crc(&broken[start..start + cb]);
        broken[t + 8..t + 12].copy_from_slice(&crc.to_le_bytes());

        let r = recover(&broken).unwrap();
        assert_eq!(
            r.unread_contexts.count,
            baseline + 1,
            "{:?}",
            r.unread_contexts
        );
        let u = r
            .unread_contexts
            .listed
            .iter()
            .find(|u| u.bid == bid)
            .unwrap();
        assert_eq!(u.ib, loc.ib);
        assert!(u.reason.contains("BTH"), "{}", u.reason);
    }

    /// Hostile or damaged input is the normal case for evidence: flipping bytes
    /// anywhere in a real store, and cutting it short anywhere, must give an
    /// answer or a named refusal, never a panic. Deterministic, so a failure
    /// reproduces.
    #[test]
    fn damage_to_a_real_store_never_panics() {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for round in 0..300 {
            let mut d = V14.to_vec();
            for _ in 0..(1 + round % 40) {
                let at = (next() as usize) % d.len();
                d[at] = next() as u8;
            }
            let _ = recover(&d);
            let _ = crate::pst::parse_pst(&d, uuid::Uuid::nil(), uuid::Uuid::nil(), "x.pst");
        }
        for cut in (0..V14.len()).step_by(4099) {
            let _ = recover(&V14[..cut]);
        }
        // Damage to the header and to the B-tree root pages specifically.
        for at in (0..PAGE)
            .chain(0x6600..0x6600 + PAGE)
            .chain(0x6c00..0x6c00 + PAGE)
        {
            let mut d = V14.to_vec();
            d[at] ^= 0xFF;
            let _ = recover(&d);
        }
    }

    /// `CryptCyclic` of MS-PST 5.2, worked by hand for the first byte of key `0x12345678`:
    /// `w = 0x5678 ^ 0x1234 = 0x444C`; byte 0 gives `0 + 0x4C = 76`, `mpbbR[76] = 133`, `+ 0x44 = 201`,
    /// `mpbbS[201] = 103`, `- 0x44 = 35`, `mpbbI[35] = 48`, `- 0x4C = 228`; `w` then advances by one per byte.
    #[test]
    fn the_cyclic_cipher_matches_the_worked_example_and_is_its_own_inverse() {
        let mut data = [0u8, 1, 2, 3];
        crypt_cyclic(&mut data, 0x1234_5678);
        assert_eq!(data, [228, 198, 87, 153]);
        crypt_cyclic(&mut data, 0x1234_5678);
        assert_eq!(data, [0, 1, 2, 3]);
        // The R table is the inverse of the I table the permutation decodes with.
        for x in 0..=255u8 {
            assert_eq!(PERMUTE_DECODE[usize::from(CYCLIC_R[usize::from(x)])], x);
        }
        assert!(
            CYCLIC_S
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == 256
        );
    }

    /// A store whose header says cyclic is opened, not refused; the empty real v23 store has no data block
    /// to misread, so it still opens and finds its blocks.
    #[test]
    fn a_cyclic_header_is_opened() {
        let mut cyclic = V23.to_vec();
        cyclic[513] = 2;
        assert!(Store::open(&cyclic).is_ok());
    }

    #[test]
    fn the_permutation_table_is_a_permutation() {
        let mut seen = [false; 256];
        for b in PERMUTE_DECODE {
            seen[usize::from(b)] = true;
        }
        assert!(seen.iter().all(|s| *s));
    }
}

#[cfg(test)]
#[path = "pst512_corpus_tests.rs"]
mod corpus_tests;

#[cfg(test)]
#[path = "pst512_v23_corpus_tests.rs"]
mod v23_corpus_tests;
