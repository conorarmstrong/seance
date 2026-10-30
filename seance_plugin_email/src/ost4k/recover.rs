//! Deleted-message recovery from a version-36 store (ROADMAP §3.10).
//!
//! The live reader ([`super::ndb`]) reads only what the two B-trees reference.
//! This is the same page and block reading with the allocation map ignored:
//! every 4 KiB-aligned offset of the bytes supplied is tried as a B-tree page
//! and every 512-byte slot as a block, each accepted only when its trailer's
//! signature and CRC are the ones Outlook would have written for that offset.
//! What the live trees do not reference is what this module reports:
//!
//! * a **node B-tree leaf page no live tree references** still holds the node
//!   entries it held when it was superseded. An entry for a message node the
//!   live node B-tree no longer has is a deleted message; its data block (and
//!   subnode tree) are looked for among every block found, referenced or not.
//! * a **block no live tree references** that holds a message's property
//!   context, and is not the data of any entry recovered above, is a
//!   fragment: a message whose node entry is gone too. Its subnode tree is
//!   unknown, so anything stored there (a large body, attachments) is named
//!   as not read.
//!
//! Each recovery says where it came from (page and block offsets) and how
//! complete it is. A copy of a message the live store still lists is not
//! reported as recovered: Outlook writes a new block each time a message
//! changes, so most unreferenced property contexts are superseded versions
//! of live messages, and are counted rather than listed.

use super::block::{read_block, BLOCK_ALIGN, BLOCK_TRAILER};
use super::btree::{BbtEntry, NbtEntry};
use super::crc::{ndb_crc, ndb_sig};
use super::ltp::read_pc;
use super::ltp::{read_pc_tolerating_subnodes, LtpFault, PropValue, PropertyContext};
use super::mailbox::Mailbox;
use super::ndb::{Ndb, BID_INTERNAL};
use super::page::{read_btree_page, PAGE_SIZE, PTYPE_BBT, PTYPE_NBT, TRAILER_AT};
use super::{le_u16, le_u32, le_u64, Bref};
use std::collections::{BTreeMap, HashSet};

/// No more than this many recovered messages or fragments are reported from
/// one store; the summary says when the cap was reached.
pub const MAX_RECOVERED: usize = 10_000;

/// No more than this many entries of a [`Listed`] are kept; its count is
/// always whole, so a store with thousands of them does not flood a report.
pub const MAX_LISTED: usize = 100;

/// A count that is always whole and a list of the first [`MAX_LISTED`] of
/// what was counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed<T> {
    pub count: usize,
    pub listed: Vec<T>,
}

impl<T> Default for Listed<T> {
    fn default() -> Self {
        Self {
            count: 0,
            listed: Vec::new(),
        }
    }
}

impl<T> Listed<T> {
    pub fn push(&mut self, item: T) {
        self.count += 1;
        if self.listed.len() < MAX_LISTED {
            self.listed.push(item);
        }
    }
}

/// An unreferenced block that carries a property-context signature but did
/// not decode as one. It may or may not have been a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadContext {
    pub bid: u64,
    pub ib: u64,
    pub reason: String,
}

/// What a scan found, and the offsets where a signature matched but the page
/// or block was refused (CRC or metadata): something was there that was not
/// read, which is not the same as nothing being there.
#[derive(Debug, Clone)]
pub struct Scan<T> {
    pub found: Vec<T>,
    pub unvalidated: Listed<u64>,
}

/// A B-tree page found by scanning, whose trailer and CRC validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannedPage {
    pub ib: u64,
    pub bid: u64,
    pub ptype: u8,
    pub level: u8,
}

/// How much of a recovered message could be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completeness {
    /// Its property context and subnode tree read with no property lost.
    Complete,
    /// Its property context read, but something it names did not (see
    /// `gaps`).
    Partial,
    /// Only the node entry was found; its data could not be read.
    EntryOnly,
}

impl Completeness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::EntryOnly => "entry_only",
        }
    }
}

/// Where a recovered message was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A node entry in node B-tree leaf pages no live tree references, at
    /// these page offsets.
    StaleNodeEntry { page_offsets: Vec<u64> },
    /// A property-context block no live tree references and no recovered
    /// node entry names.
    UnreferencedBlock,
}

/// One earlier version of a recovered message's node entry, not the one read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtherVersion {
    pub bid_data: u64,
    pub bid_sub: u64,
    pub page_offsets: Vec<u64>,
    /// Whether this version is newer (a higher data BID) than the one read.
    pub newer: bool,
    /// Why this version did not read, when reading it was tried. Versions are
    /// tried newest first until one reads, so every version newer than the one
    /// read was tried, and when none reads every version was tried; a version
    /// older than the one read is not tried, and has none.
    pub read_error: Option<String>,
}

/// A message recovered from bytes the live B-trees do not reference.
#[derive(Debug, Clone)]
pub struct RecoveredMessage {
    /// The node id; 0 for a fragment, whose node entry was not found.
    pub nid: u32,
    /// The parent (folder) node the entry names; 0 for a fragment.
    pub parent_nid: u32,
    pub bid_data: u64,
    pub bid_sub: u64,
    pub source: Source,
    /// Offset of the data block (or the top of its data tree), where found.
    pub data_block_offset: Option<u64>,
    /// Offset of the subnode tree's top block, where found.
    pub subnode_block_offset: Option<u64>,
    pub props: BTreeMap<u16, PropValue>,
    pub props_unreadable: Vec<(u16, String)>,
    pub attachments: Vec<BTreeMap<u16, PropValue>>,
    pub attachments_unreadable: usize,
    /// The recipient table's rows when the message has one and it was read.
    pub recipients: Option<Vec<BTreeMap<u16, PropValue>>>,
    pub completeness: Completeness,
    /// What could not be read, in words.
    pub gaps: Vec<String>,
    /// Other versions of the same node entry found in stale pages.
    pub other_versions: Vec<OtherVersion>,
    /// Why the live walk cannot rule out that this message is still live,
    /// in words; empty when it can, and only then is the message deleted.
    pub could_be_live: Vec<String>,
}

/// Everything the unallocated walk found.
#[derive(Debug, Clone, Default)]
pub struct Recovery {
    /// 4 KiB-aligned offsets tried as B-tree pages.
    pub pages_scanned: usize,
    /// Valid B-tree pages no live tree references, by offset.
    pub unreferenced_pages: Vec<u64>,
    /// Valid blocks found by scanning, referenced or not.
    pub blocks_found: usize,
    /// Of those, blocks whose BID the live block B-tree does not name.
    pub unreferenced_blocks: usize,
    /// Deleted messages from stale node entries.
    pub messages: Vec<RecoveredMessage>,
    /// Message property contexts found with no node entry.
    pub fragments: Vec<RecoveredMessage>,
    /// Unreferenced message property contexts that are copies of a message
    /// listed live or recovered above (superseded versions), not listed.
    pub superseded_copies: usize,
    /// Message nodes the live tree lacks whose message the live store still
    /// holds under another node (moved, or re-created by synchronisation):
    /// deleted nodes, not deleted messages, so not listed as recovered.
    pub copies_of_live: Vec<u32>,
    /// Whether [`MAX_RECOVERED`] stopped the listing.
    pub capped: bool,
    /// Unreferenced property contexts of folder-associated (FAI) items —
    /// views, rules, configuration — counted, not listed as mail.
    pub associated_items: usize,
    /// Offsets whose page trailer matched but whose CRC or metadata did not.
    pub pages_unvalidated: Listed<u64>,
    /// Offsets whose block trailer matched but whose CRC did not.
    pub blocks_unvalidated: Listed<u64>,
    /// Unreferenced blocks that carry the property-context signature and did
    /// not decode (damaged, or past the read budget). They may not have been
    /// messages.
    pub unread_contexts: Listed<UnreadContext>,
}

/// Every 4 KiB-aligned B-tree page of either tree whose trailer and CRC
/// validate, referenced or not.
///
/// A page is accepted only when its page type is repeated, its signature is
/// the one its offset and BID give and its CRC matches — the checks the live
/// reader makes, with the BID taken from the page's own trailer because no
/// parent names it. An offset whose trailer matched but whose CRC or metadata
/// did not is returned in `unvalidated`, not dropped.
pub fn scan_pages(data: &[u8]) -> Scan<ScannedPage> {
    let mut out = Vec::new();
    let mut unvalidated = Listed::default();
    let mut ib = 0usize;
    while ib + PAGE_SIZE <= data.len() {
        let t = &data[ib + TRAILER_AT..ib + PAGE_SIZE];
        let ptype = t[0];
        if (ptype == PTYPE_BBT || ptype == PTYPE_NBT) && t[1] == ptype {
            let bid = le_u64(t, 8).unwrap_or(0);
            let at = ib as u64;
            if le_u16(t, 2) == Some(ndb_sig(at, bid)) {
                match read_btree_page(data, Bref { bid, ib: at }, ptype) {
                    Ok(p) => out.push(ScannedPage {
                        ib: at,
                        bid,
                        ptype,
                        level: p.level,
                    }),
                    Err(_) => unvalidated.push(at),
                }
            }
        }
        ib += PAGE_SIZE;
    }
    Scan {
        found: out,
        unvalidated,
    }
}

/// Every block whose trailer validates at its own offset, referenced or not.
///
/// Each 512-byte boundary is tried as the end of a block's slot: the trailer
/// there gives the stored size, and so where the slot starts; the block is
/// accepted when the signature is the one that start and the BID give and the
/// CRC over the stored bytes matches. The signature is checked first, so bytes
/// that are not blocks cost no CRC. A BID found twice keeps its first copy. A
/// block whose signature matched but whose CRC did not is returned in
/// `unvalidated`: a signature match is 16 bits, so some are chance, but a
/// damaged block is among them.
pub fn scan_blocks(data: &[u8]) -> Scan<BbtEntry> {
    let align = BLOCK_ALIGN as usize;
    let mut out = Vec::new();
    let mut unvalidated = Listed::default();
    let mut seen = HashSet::new();
    let mut end = align;
    while end <= data.len() {
        let t = &data[end - BLOCK_TRAILER..end];
        end += align;
        let (Some(cb), Some(sig), Some(crc), Some(bid), Some(inflated)) = (
            le_u16(t, 0),
            le_u16(t, 2),
            le_u32(t, 4),
            le_u64(t, 8),
            le_u16(t, 18),
        ) else {
            continue;
        };
        if cb == 0 || bid == 0 {
            continue;
        }
        let slot = (usize::from(cb) + BLOCK_TRAILER).div_ceil(align) * align;
        let Some(start) = (end - align).checked_sub(slot) else {
            continue;
        };
        if sig != ndb_sig(start as u64, bid) {
            continue;
        }
        if ndb_crc(&data[start..start + usize::from(cb)]) != crc {
            unvalidated.push(start as u64);
            continue;
        }
        if seen.insert(bid & !1) {
            out.push(BbtEntry {
                bref: Bref {
                    bid,
                    ib: start as u64,
                },
                cb,
                cb_inflated: inflated,
                c_ref: 0,
            });
        }
    }
    Scan {
        found: out,
        unvalidated,
    }
}

/// The pages a live walk from `root` reaches (intermediate and leaf).
fn reachable_pages(data: &[u8], root: Bref, ptype: u8) -> HashSet<u64> {
    let mut seen = HashSet::new();
    let mut stack = vec![(root, 0usize)];
    while let Some((bref, depth)) = stack.pop() {
        if depth > super::btree::MAX_DEPTH || !seen.insert(bref.ib) {
            continue;
        }
        let Ok(p) = read_btree_page(data, bref, ptype) else {
            continue;
        };
        if p.level == 0 {
            continue;
        }
        for i in 0..usize::from(p.c_ent) {
            if let Some(e) = p.entry(i) {
                stack.push((
                    Bref {
                        bid: le_u64(e, 8).unwrap_or(0),
                        ib: le_u64(e, 16).unwrap_or(0),
                    },
                    depth + 1,
                ));
            }
        }
    }
    seen
}

/// The node-id ranges (`[lo, hi)`, `u64::MAX` for unbounded) that live under a
/// page of the live node B-tree which did not read, each with that page's
/// offset. A node whose id falls in one may still be live; the live walk
/// simply never reached it.
fn unread_nbt_ranges(data: &[u8], root: Bref) -> Vec<(u64, u64, u64)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    // (page, lowest key it covers, first key it does not, depth)
    let mut stack = vec![(root, 0u64, u64::MAX, 0usize)];
    while let Some((bref, lo, hi, depth)) = stack.pop() {
        if depth > super::btree::MAX_DEPTH || !seen.insert(bref.ib) {
            continue;
        }
        let Ok(p) = read_btree_page(data, bref, PTYPE_NBT) else {
            out.push((lo, hi, bref.ib));
            continue;
        };
        if p.level == 0 {
            continue;
        }
        let kids: Vec<(u64, Bref)> = (0..usize::from(p.c_ent))
            .filter_map(|i| p.entry(i))
            .map(|e| {
                (
                    le_u64(e, 0).unwrap_or(0),
                    Bref {
                        bid: le_u64(e, 8).unwrap_or(0),
                        ib: le_u64(e, 16).unwrap_or(0),
                    },
                )
            })
            .collect();
        for (i, (key, child)) in kids.iter().enumerate() {
            let next = kids.get(i + 1).map_or(hi, |k| k.0);
            stack.push((*child, (*key).max(lo), next.min(hi), depth + 1));
        }
    }
    out
}

pub(crate) const NID_TYPE_NORMAL_MESSAGE: u32 = 0x04;
pub(crate) const PID_TAG_MESSAGE_FLAGS: u16 = 0x0E07;
/// `mfFAI`: the message is a folder-associated item, not mail.
pub(crate) const MF_FAI: i32 = 0x40;
const NID_TYPE_ATTACHMENT: u32 = 0x05;
pub(crate) const PID_TAG_MESSAGE_CLASS: u16 = 0x001A;
const PID_TAG_SUBJECT: u16 = 0x0037;
const PID_TAG_CLIENT_SUBMIT_TIME: u16 = 0x0039;
const PID_TAG_MESSAGE_DELIVERY_TIME: u16 = 0x0E06;

/// What makes two property contexts the same message for deduplication: its
/// class, subject and the two times it was sent and delivered. A superseded
/// version (the read flag set, a category added) keeps all four.
///
/// `None` when that is not enough to say two messages are one: no subject, or
/// neither time. Messages without an identity are never merged, so two
/// different appointments that share a class and a subject, or two messages
/// whose subject or times did not decode, are both kept.
pub(crate) fn identity(props: &BTreeMap<u16, PropValue>) -> Option<String> {
    props.get(&PID_TAG_SUBJECT)?;
    if !props.contains_key(&PID_TAG_CLIENT_SUBMIT_TIME)
        && !props.contains_key(&PID_TAG_MESSAGE_DELIVERY_TIME)
    {
        return None;
    }
    Some(
        [
            PID_TAG_MESSAGE_CLASS,
            PID_TAG_SUBJECT,
            PID_TAG_CLIENT_SUBMIT_TIME,
            PID_TAG_MESSAGE_DELIVERY_TIME,
        ]
        .iter()
        .map(|t| format!("{:?}", props.get(t)))
        .collect::<Vec<_>>()
        .join("|"),
    )
}

/// How many attachments a recovered message names individually when they did
/// not read; the rest are summarised.
const MAX_ATTACHMENT_GAPS: usize = 10;

/// Record an attachment subnode that did not read, with the reason, so an
/// examiner can tell damage from an exhausted read budget. The first
/// [`MAX_ATTACHMENT_GAPS`] are named; `unreadable` counts all of them.
pub(crate) fn note_unreadable_attachment(
    gaps: &mut Vec<String>,
    unreadable: &mut usize,
    snid: u32,
    bid_data: u64,
    why: &dyn std::fmt::Display,
) {
    *unreadable += 1;
    if *unreadable <= MAX_ATTACHMENT_GAPS {
        gaps.push(format!(
            "attachment subnode {snid:#x} (BID {bid_data:#x}) could not be read: {why}"
        ));
    }
}

/// The summary gap for attachments past [`MAX_ATTACHMENT_GAPS`], if any.
pub(crate) fn note_attachment_overflow(gaps: &mut Vec<String>, unreadable: usize) {
    if unreadable > MAX_ATTACHMENT_GAPS {
        gaps.push(format!(
            "{} more attachment(s) could not be read (not listed one by one)",
            unreadable - MAX_ATTACHMENT_GAPS
        ));
    }
}

/// The outcome of reading an unreferenced block that carries a property-context
/// signature. A read that failed, or one whose message class could not be read,
/// is recorded in `unread` (the block may or may not have been a message) and
/// gives `None`; a clean read is returned for the caller to judge.
pub(crate) fn readable_context(
    read: Result<PropertyContext, LtpFault>,
    bid: u64,
    ib: u64,
    unread: &mut Listed<UnreadContext>,
) -> Option<PropertyContext> {
    let reason = match &read {
        Err(e) => e.to_string(),
        Ok(pc) => match pc
            .unreadable
            .iter()
            .find(|(t, _)| *t == PID_TAG_MESSAGE_CLASS)
        {
            Some((_, why)) => format!("its message class could not be read: {why}"),
            None => return read.ok(),
        },
    };
    unread.push(UnreadContext { bid, ib, reason });
    None
}

/// Block ids of a data tree's blocks: the block itself and, for an XBLOCK or
/// XXBLOCK, every block under it. Tolerant of damage: what cannot be read is
/// simply not listed, since this only decides which blocks an entry claims.
fn data_tree_bids(ndb: &Ndb<'_>, bid: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = vec![(bid, 3u8)];
    while let Some((b, depth)) = stack.pop() {
        if b == 0 || depth == 0 || !seen.insert(b & !1) {
            continue;
        }
        out.push(b & !1);
        if b & BID_INTERNAL == 0 {
            continue;
        }
        let Ok(x) = ndb.block(b) else { continue };
        let c_ent = usize::from(le_u16(&x, 2).unwrap_or(0));
        for i in 0..c_ent {
            if let Some(child) = le_u64(&x, 8 + i * 8) {
                stack.push((child, depth - 1));
            }
        }
    }
    out
}

fn not_found(what: &str, bid: u64) -> String {
    format!(
        "its {what} block {bid:#x} was not found anywhere in the bytes supplied \
         (overwritten since, or past what was supplied)"
    )
}

/// One stale node entry version, read against the store with every found
/// block in its map.
struct Attempt {
    props: BTreeMap<u16, PropValue>,
    props_unreadable: Vec<(u16, String)>,
    attachments: Vec<BTreeMap<u16, PropValue>>,
    attachments_unreadable: usize,
    recipients: Option<Vec<BTreeMap<u16, PropValue>>>,
    subnodes_read: bool,
    gaps: Vec<String>,
}

fn attempt(ext: &Ndb<'_>, bid_data: u64, bid_sub: u64) -> Result<Attempt, String> {
    if ext.block_entry(bid_data).is_none() {
        return Err(not_found("data", bid_data));
    }
    let mut gaps = Vec::new();
    // The data tree is read once; a subnode tree that will not read costs only
    // the subnodes, and its error is kept for the gap.
    let (pc, subnode_error) = read_pc_tolerating_subnodes(ext, bid_data, bid_sub)
        .map_err(|e| format!("its data (BID {bid_data:#x}) could not be read: {e}"))?;
    let subnodes_read = bid_sub != 0 && subnode_error.is_none();
    if let Some(e) = subnode_error {
        gaps.push(if ext.block_entry(bid_sub).is_none() {
            format!(
                "{}; anything stored in its subnodes (a large body, recipients, \
                 attachments) is not recovered",
                not_found("subnode tree", bid_sub)
            )
        } else {
            format!(
                "its subnode tree (BID {bid_sub:#x}) could not be read ({e}); anything \
                 stored in its subnodes is not recovered"
            )
        });
    }
    let mut attachments = Vec::new();
    let mut attachments_unreadable = 0;
    for (&snid, sub) in &pc.subnodes {
        if snid & 0x1F != NID_TYPE_ATTACHMENT {
            continue;
        }
        match read_pc(ext, sub.bid_data, sub.bid_sub) {
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
    if let Some((snid, sub)) = pc.subnodes.iter().find(|(snid, _)| **snid & 0x1F == 0x12) {
        match super::ltp::read_tc(ext, sub.bid_data, sub.bid_sub) {
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

/// Walk the store with the allocation map ignored and report what the live
/// B-trees no longer reference. `live` is the live mailbox, so a copy of a
/// message it lists is counted as superseded rather than reported.
pub fn recover(ndb: &Ndb<'_>, live: &Mailbox) -> Recovery {
    recover_up_to(ndb, live, MAX_RECOVERED)
}

/// [`recover`] with the listing cap given, so the cap can be tested.
fn recover_up_to(ndb: &Ndb<'_>, live: &Mailbox, cap: usize) -> Recovery {
    let data = ndb.data;
    let mut r = Recovery {
        pages_scanned: data.len() / PAGE_SIZE,
        ..Recovery::default()
    };

    let scanned_pages = scan_pages(data);
    r.pages_unvalidated = scanned_pages.unvalidated;
    let pages = scanned_pages.found;
    let mut live_pages = reachable_pages(data, ndb.header.nbt_root, PTYPE_NBT);
    live_pages.extend(reachable_pages(data, ndb.header.bbt_root, PTYPE_BBT));
    let stale: Vec<&ScannedPage> = pages
        .iter()
        .filter(|p| !live_pages.contains(&p.ib))
        .collect();
    r.unreferenced_pages = stale.iter().map(|p| p.ib).collect();

    let scanned_blocks = scan_blocks(data);
    r.blocks_unvalidated = scanned_blocks.unvalidated;
    let blocks = scanned_blocks.found;
    r.blocks_found = blocks.len();
    let unreferenced: Vec<BbtEntry> = blocks
        .into_iter()
        .filter(|b| ndb.block_entry(b.bref.bid).is_none())
        .collect();
    r.unreferenced_blocks = unreferenced.len();
    let ext = ndb.with_unreferenced_blocks(&unreferenced);

    // Every version of every message node entry the live tree lacks, with
    // the stale pages it was seen in.
    type Versions = BTreeMap<(u64, u64), (u32, Vec<u64>)>;
    let mut entries: BTreeMap<u32, Versions> = BTreeMap::new();
    for p in stale
        .iter()
        .filter(|p| p.ptype == PTYPE_NBT && p.level == 0)
    {
        let Ok(page) = read_btree_page(
            data,
            Bref {
                bid: p.bid,
                ib: p.ib,
            },
            PTYPE_NBT,
        ) else {
            continue;
        };
        if page.cb_ent != 32 {
            continue;
        }
        for i in 0..usize::from(page.c_ent) {
            let Some(e) = page.entry(i) else { continue };
            let n = NbtEntry {
                nid: le_u64(e, 0).unwrap_or(0),
                bid_data: le_u64(e, 8).unwrap_or(0),
                bid_sub: le_u64(e, 16).unwrap_or(0),
                nid_parent: le_u32(e, 24).unwrap_or(0),
            };
            let nid = n.nid as u32;
            if nid & 0x1F != NID_TYPE_NORMAL_MESSAGE || ndb.node(nid).is_some() {
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

    // Why the live walk cannot be taken as the whole of what is live.
    let unread = unread_nbt_ranges(data, ndb.header.nbt_root);
    let live_unreadable: Vec<u32> = live
        .nodes_unreadable
        .iter()
        .map(|(n, _)| *n)
        .filter(|n| n & 0x1F == NID_TYPE_NORMAL_MESSAGE)
        .collect();
    let walk_caveats = |nid: Option<u32>| -> Vec<String> {
        let mut w = Vec::new();
        let faulted = !unread.is_empty() || !ndb.nbt.faults.is_empty();
        if let Some(n) = nid {
            if let Some((_, _, ib)) = unread
                .iter()
                .find(|(lo, hi, _)| u64::from(n) >= *lo && u64::from(n) < *hi)
            {
                w.push(format!(
                    "node {n:#x} lies under a live node B-tree page (offset {ib:#x}) that \
                     could not be read, so it may still be live"
                ));
            } else if faulted {
                w.push(
                    "the live node B-tree could not be read in full, so this message may be \
                     live under another node that was not read"
                        .to_string(),
                );
            }
        } else if faulted {
            w.push(
                "the live node B-tree could not be read in full, so a node it did not reach \
                 may name this block"
                    .to_string(),
            );
        }
        if !live_unreadable.is_empty() {
            w.push(format!(
                "{} live message node(s) could not be read, and one of them may be the live \
                 copy of this message",
                live_unreadable.len()
            ));
        }
        w
    };

    // Every entry claims its data blocks (the whole data tree, not just its
    // top block, so the first leaf of a multi-block message is not listed as a
    // fragment of its own), including the ones the cap cuts off, so a block a
    // skipped entry names is not listed as a fragment.
    let mut used: HashSet<u64> = HashSet::new();
    for versions in entries.values() {
        for (bid_data, _) in versions.keys() {
            used.extend(data_tree_bids(&ext, *bid_data));
        }
    }
    let live_ids: HashSet<String> = live
        .messages
        .iter()
        .filter_map(|m| identity(&m.props))
        .collect();
    let mut seen = live_ids.clone();
    for (nid, versions) in entries {
        if r.messages.len() >= cap {
            r.capped = true;
            break;
        }
        // Newest first: BIDs only grow, so the highest data BID is the latest
        // version Outlook wrote.
        let mut order: Vec<_> = versions.into_iter().collect();
        order.sort_by_key(|v| std::cmp::Reverse(v.0 .0));
        let mut chosen = None;
        let mut tried_errors: Vec<String> = Vec::new();
        for (i, ((bd, bs), _)) in order.iter().enumerate() {
            match attempt(&ext, *bd, *bs) {
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
        let offset = |bid: u64| ext.block_entry(bid).map(|e| e.bref.ib);
        let m = match chosen {
            Some((_, a)) if identity(&a.props).is_some_and(|id| live_ids.contains(&id)) => {
                r.copies_of_live.push(nid);
                continue;
            }
            Some((_, mut a)) => {
                if pick > 0 {
                    a.gaps.push(format!(
                        "a newer version of this entry (data BID {:#x}) did not read, so this \
                         is an earlier state of the message, not necessarily its last",
                        order[0].0 .0
                    ));
                }
                let complete = a.gaps.is_empty();
                seen.extend(identity(&a.props));
                RecoveredMessage {
                    nid,
                    parent_nid,
                    bid_data,
                    bid_sub,
                    source: Source::StaleNodeEntry { page_offsets },
                    data_block_offset: offset(bid_data),
                    subnode_block_offset: if a.subnodes_read {
                        offset(bid_sub)
                    } else {
                        None
                    },
                    props: a.props,
                    props_unreadable: a.props_unreadable,
                    attachments: a.attachments,
                    attachments_unreadable: a.attachments_unreadable,
                    recipients: a.recipients,
                    completeness: if complete {
                        Completeness::Complete
                    } else {
                        Completeness::Partial
                    },
                    gaps: a.gaps,
                    other_versions,
                    could_be_live: walk_caveats(Some(nid)),
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
                could_be_live: walk_caveats(Some(nid)),
            },
        };
        r.messages.push(m);
    }

    // Message property contexts in unreferenced blocks that no recovered
    // entry names, newest first so a superseded copy is the one counted.
    let mut candidates: Vec<&BbtEntry> = unreferenced
        .iter()
        .filter(|b| b.bref.bid & BID_INTERNAL == 0 && !used.contains(&(b.bref.bid & !1)))
        .collect();
    candidates.sort_by_key(|b| std::cmp::Reverse(b.bref.bid));
    for b in candidates {
        let Ok(bytes) = read_block(data, b) else {
            continue;
        };
        if bytes.get(2) != Some(&0xEC) || bytes.get(3) != Some(&0xBC) {
            continue;
        }
        let Some(pc) = readable_context(
            read_pc(&ext, b.bref.bid, 0),
            b.bref.bid,
            b.bref.ib,
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
        if !pc.unreadable.is_empty() {
            gaps.push(format!(
                "{} propert(y/ies) present could not be read",
                pc.unreadable.len()
            ));
        }
        r.fragments.push(RecoveredMessage {
            nid: 0,
            parent_nid: 0,
            bid_data: b.bref.bid,
            bid_sub: 0,
            source: Source::UnreferencedBlock,
            data_block_offset: Some(b.bref.ib),
            subnode_block_offset: None,
            props: pc.props,
            props_unreadable: pc.unreadable,
            attachments: Vec::new(),
            attachments_unreadable: 0,
            recipients: None,
            completeness: Completeness::Partial,
            gaps,
            other_versions: Vec::new(),
            could_be_live: walk_caveats(None),
        });
    }
    r
}

#[cfg(test)]
mod tests {
    //! A synthetic store, honest here because it pins the mechanism only —
    //! which unreferenced pages and blocks are read, how each recovery is
    //! graded and deduplicated — not the format. Recovery from a real store
    //! is graded on the Data Leakage OST in `tests/ost4k_recover_real_test.rs`.
    use super::super::mailbox::Message;
    use super::super::page::META_AT;
    use super::*;
    use std::collections::HashMap;

    const LIVE_NBT: u64 = 0x1000;
    const LIVE_BBT: u64 = 0x2000;
    const STALE_NBT: u64 = 0x3000;
    const BLOCKS_AT: usize = 0x4000;

    const LIVE_MSG: u64 = 0x20_0044;
    const DELETED: u64 = 0x20_0064;
    const GONE: u64 = 0x20_0084;
    const NO_SUB: u64 = 0x20_00A4;
    const MOVED: u64 = 0x20_00C4;
    const NEWER_GONE: u64 = 0x20_00E4;
    const FOLDER: u32 = 0x8022;

    /// A property context heap with the given string properties.
    fn pc(strings: &[(u16, &str)]) -> Vec<u8> {
        pc_with(strings, &[])
    }

    /// A property context heap with the given string and 32-bit integer
    /// properties.
    fn pc_with(strings: &[(u16, &str)], ints: &[(u16, u32)]) -> Vec<u8> {
        let mut allocs: Vec<Vec<u8>> = Vec::new();
        let n = strings.len();
        // hid 1: BTH header; hid 2: the records; hid 3..: the strings.
        let mut header = vec![0xB5, 2, 6, 0];
        header.extend_from_slice(&(2u32 << 5).to_le_bytes());
        allocs.push(header);
        let mut recs: Vec<(u16, u16, u32)> = strings
            .iter()
            .enumerate()
            .map(|(i, (tag, _))| (*tag, 0x001F, ((i as u32) + 3) << 5))
            .collect();
        recs.extend(ints.iter().map(|(tag, v)| (*tag, 0x0003, *v)));
        recs.sort_by_key(|r| r.0);
        let mut records = Vec::new();
        for (tag, ty, v) in recs {
            records.extend_from_slice(&tag.to_le_bytes());
            records.extend_from_slice(&ty.to_le_bytes());
            records.extend_from_slice(&v.to_le_bytes());
        }
        allocs.push(records);
        for (_, s) in strings.iter().take(n) {
            allocs.push(s.encode_utf16().flat_map(u16::to_le_bytes).collect());
        }
        let mut p = vec![0u8; 12];
        p[2] = 0xEC;
        p[3] = 0xBC;
        p[4..8].copy_from_slice(&(1u32 << 5).to_le_bytes());
        let mut offs = vec![12u16];
        for a in &allocs {
            p.extend_from_slice(a);
            offs.push(p.len() as u16);
        }
        let map = p.len();
        p[0..2].copy_from_slice(&(map as u16).to_le_bytes());
        p.extend_from_slice(&(allocs.len() as u16).to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());
        for o in offs {
            p.extend_from_slice(&o.to_le_bytes());
        }
        p
    }

    /// A message with the one time the fixtures give every message (a submit
    /// time, as an integer: only its presence and value matter to the
    /// mechanism under test), so that it has an identity to deduplicate on.
    fn msg(subject: &str) -> Vec<u8> {
        pc_with(&[(0x001A, "IPM.Note"), (0x0037, subject)], &[(0x0039, 1)])
    }

    /// An SLBLOCK with one entry.
    fn slblock(nid: u64, data: u64) -> Vec<u8> {
        let mut b = vec![2, 0, 1, 0, 0, 0, 0, 0];
        b.extend_from_slice(&nid.to_le_bytes());
        b.extend_from_slice(&data.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b
    }

    struct Synth {
        data: Vec<u8>,
        live_blocks: Vec<BbtEntry>,
        offsets: HashMap<u64, u64>,
    }

    impl Synth {
        fn new() -> Self {
            Self {
                data: vec![0u8; BLOCKS_AT],
                live_blocks: Vec::new(),
                offsets: HashMap::new(),
            }
        }

        /// Append a sealed, uncompressed block; `live` puts it in the BBT.
        fn block(&mut self, bid: u64, stored: &[u8], live: bool) -> &mut Self {
            self.sealed(bid, stored, stored.len() as u16, live)
        }

        /// Append a sealed block whose trailer states `inflated` bytes: a zlib
        /// stream when that differs from the stored size.
        fn sealed(&mut self, bid: u64, stored: &[u8], inflated: u16, live: bool) -> &mut Self {
            let ib = self.data.len() as u64;
            let slot = (stored.len() + BLOCK_TRAILER).div_ceil(512) * 512;
            let mut d = vec![0u8; slot];
            d[..stored.len()].copy_from_slice(stored);
            let t = slot - BLOCK_TRAILER;
            let cb = stored.len() as u16;
            d[t..t + 2].copy_from_slice(&cb.to_le_bytes());
            d[t + 2..t + 4].copy_from_slice(&ndb_sig(ib, bid).to_le_bytes());
            d[t + 4..t + 8].copy_from_slice(&ndb_crc(stored).to_le_bytes());
            d[t + 8..t + 16].copy_from_slice(&bid.to_le_bytes());
            d[t + 18..t + 20].copy_from_slice(&inflated.to_le_bytes());
            self.data.extend_from_slice(&d);
            self.offsets.insert(bid, ib);
            if live {
                self.live_blocks.push(BbtEntry {
                    bref: Bref { bid, ib },
                    cb,
                    cb_inflated: inflated,
                    c_ref: 1,
                });
            }
            self
        }

        /// Write a sealed leaf page of `ptype` at `ib` holding `entries`.
        fn page(&mut self, ib: u64, bid: u64, ptype: u8, cb_ent: u8, entries: &[Vec<u8>]) {
            self.page_at(ib, bid, ptype, cb_ent, 0, entries);
        }

        /// Write a sealed page of `ptype` and `level` at `ib`.
        fn page_at(
            &mut self,
            ib: u64,
            bid: u64,
            ptype: u8,
            cb_ent: u8,
            level: u8,
            entries: &[Vec<u8>],
        ) {
            let at = ib as usize;
            if self.data.len() < at + PAGE_SIZE {
                self.data.resize(at + PAGE_SIZE, 0);
            }
            let p = &mut self.data[at..at + PAGE_SIZE];
            p.fill(0);
            for (i, e) in entries.iter().enumerate() {
                p[i * usize::from(cb_ent)..][..e.len()].copy_from_slice(e);
            }
            let max = (META_AT / usize::from(cb_ent)) as u16;
            p[META_AT..META_AT + 2].copy_from_slice(&(entries.len() as u16).to_le_bytes());
            p[META_AT + 2..META_AT + 4].copy_from_slice(&max.to_le_bytes());
            p[META_AT + 4] = cb_ent;
            p[META_AT + 5] = level;
            p[TRAILER_AT] = ptype;
            p[TRAILER_AT + 1] = ptype;
            p[TRAILER_AT + 2..TRAILER_AT + 4].copy_from_slice(&ndb_sig(ib, bid).to_le_bytes());
            p[TRAILER_AT + 8..TRAILER_AT + 16].copy_from_slice(&bid.to_le_bytes());
            let crc = ndb_crc(&p[..TRAILER_AT]);
            p[TRAILER_AT + 4..TRAILER_AT + 8].copy_from_slice(&crc.to_le_bytes());
        }
    }

    fn nbt_entry(nid: u64, data: u64, sub: u64, parent: u32) -> Vec<u8> {
        let mut e = Vec::new();
        e.extend_from_slice(&nid.to_le_bytes());
        e.extend_from_slice(&data.to_le_bytes());
        e.extend_from_slice(&sub.to_le_bytes());
        e.extend_from_slice(&parent.to_le_bytes());
        e.extend_from_slice(&[0; 4]);
        e
    }

    fn bbt_entry(e: &BbtEntry) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&e.bref.bid.to_le_bytes());
        b.extend_from_slice(&e.bref.ib.to_le_bytes());
        b.extend_from_slice(&e.cb.to_le_bytes());
        b.extend_from_slice(&e.cb_inflated.to_le_bytes());
        b.extend_from_slice(&e.c_ref.to_le_bytes());
        b.extend_from_slice(&[0; 2]);
        b
    }

    /// The store: one live message; a stale NBT page naming it and four
    /// deleted messages (one whole, one whose data block is gone, one whose
    /// subnode tree is gone, one whose newest version's data is gone but an
    /// older version's is not, plus an older version of the whole one); an
    /// orphan property context with no entry; and an orphan copy of the live
    /// message.
    fn store() -> (Vec<u8>, HashMap<u64, u64>, Mailbox) {
        let mut s = Synth::new();
        s.block(0x100, &msg("Live"), true)
            .block(0x104, &msg("Deleted one"), false)
            .block(0x0F0, &msg("Deleted one (draft)"), false)
            .block(0x10C, &msg("No subnodes"), false)
            .block(0x114, &msg("Orphan fragment"), false)
            .block(0x118, &msg("Live"), false)
            .block(0x11C, &slblock(0x3F, 0x120), false)
            .block(0x124, &msg("Live"), false)
            .block(0x12C, &msg("Earlier state"), false);
        let live_bbt: Vec<Vec<u8>> = s.live_blocks.iter().map(bbt_entry).collect();
        s.page(
            LIVE_NBT,
            0x10,
            PTYPE_NBT,
            32,
            &[nbt_entry(LIVE_MSG, 0x100, 0, FOLDER)],
        );
        s.page(LIVE_BBT, 0x14, PTYPE_BBT, 24, &live_bbt);
        s.page(
            STALE_NBT,
            0x08,
            PTYPE_NBT,
            32,
            &[
                nbt_entry(LIVE_MSG, 0x0FC, 0, FOLDER),
                nbt_entry(DELETED, 0x0F0, 0, FOLDER),
                nbt_entry(DELETED, 0x104, 0x11C, FOLDER),
                nbt_entry(GONE, 0x108, 0, FOLDER),
                nbt_entry(NO_SUB, 0x10C, 0x110, FOLDER),
                nbt_entry(MOVED, 0x124, 0, FOLDER),
                nbt_entry(NEWER_GONE, 0x12C, 0, FOLDER),
                nbt_entry(NEWER_GONE, 0x134, 0, FOLDER),
            ],
        );
        let mut live_props = BTreeMap::new();
        live_props.insert(0x001A, PropValue::Str("IPM.Note".into()));
        live_props.insert(0x0037, PropValue::Str("Live".into()));
        live_props.insert(0x0039, PropValue::I32(1));
        let mb = Mailbox {
            messages: vec![Message {
                nid: LIVE_MSG as u32,
                folder_nid: FOLDER,
                props: live_props,
                props_unreadable: Vec::new(),
                attachments: Vec::new(),
                attachments_unreadable: 0,
                recipients: None,
                recipients_error: None,
            }],
            ..Mailbox::default()
        };
        (s.data, s.offsets, mb)
    }

    fn roots() -> (Bref, Bref) {
        (
            Bref {
                bid: 0x10,
                ib: LIVE_NBT,
            },
            Bref {
                bid: 0x14,
                ib: LIVE_BBT,
            },
        )
    }

    fn subject(m: &RecoveredMessage) -> &str {
        match m.props.get(&0x0037) {
            Some(PropValue::Str(s)) => s,
            _ => "",
        }
    }

    fn run() -> (Recovery, HashMap<u64, u64>) {
        let (data, offsets, mb) = store();
        let (n, b) = roots();
        let ndb = Ndb::from_roots(&data, n, b);
        assert_eq!(ndb.nodes().count(), 1, "the synthetic live tree reads");
        (recover(&ndb, &mb), offsets)
    }

    #[test]
    fn the_scan_finds_pages_and_blocks_the_live_trees_do_not_reference() {
        let (data, _, _) = store();
        let pages = scan_pages(&data).found;
        assert_eq!(
            pages.iter().map(|p| p.ib).collect::<Vec<_>>(),
            vec![LIVE_NBT, LIVE_BBT, STALE_NBT]
        );
        assert_eq!(scan_blocks(&data).found.len(), 9);
        let (r, _) = run();
        assert_eq!(r.unreferenced_pages, vec![STALE_NBT]);
        assert_eq!(r.blocks_found, 9);
        assert_eq!(r.unreferenced_blocks, 8);
    }

    #[test]
    fn a_deleted_message_in_a_stale_node_page_is_recovered_with_its_offsets() {
        let (r, off) = run();
        let m = r
            .messages
            .iter()
            .find(|m| u64::from(m.nid) == DELETED)
            .expect("the deleted message is recovered");
        // The newest version (the higher data BID) is the one read; the
        // older is listed, not dropped.
        assert_eq!(subject(m), "Deleted one");
        assert_eq!(m.parent_nid, FOLDER);
        assert_eq!(
            m.source,
            Source::StaleNodeEntry {
                page_offsets: vec![STALE_NBT]
            }
        );
        assert_eq!(m.data_block_offset, Some(off[&0x104]));
        assert_eq!(m.subnode_block_offset, Some(off[&0x11C]));
        assert_eq!(m.completeness, Completeness::Complete, "{:?}", m.gaps);
        assert_eq!(
            m.other_versions,
            vec![OtherVersion {
                bid_data: 0x0F0,
                bid_sub: 0,
                page_offsets: vec![STALE_NBT],
                newer: false,
                read_error: None,
            }]
        );
        // With the live walk whole, a node it lacks is deleted.
        assert!(m.could_be_live.is_empty(), "{:?}", m.could_be_live);
        // A node the live tree still has is not "recovered".
        assert!(r.messages.iter().all(|m| u64::from(m.nid) != LIVE_MSG));
    }

    #[test]
    fn a_stale_entry_whose_data_is_gone_is_reported_as_the_entry_alone() {
        let (r, _) = run();
        let m = r
            .messages
            .iter()
            .find(|m| u64::from(m.nid) == GONE)
            .expect("the entry is reported even though its data is gone");
        assert_eq!(m.completeness, Completeness::EntryOnly);
        assert!(m.props.is_empty());
        assert!(m.data_block_offset.is_none());
        assert!(
            m.gaps.iter().any(|g| g.contains("0x108")),
            "the gap names the block: {:?}",
            m.gaps
        );
    }

    #[test]
    fn a_stale_entry_whose_subnode_tree_is_gone_is_partial() {
        let (r, _) = run();
        let m = r
            .messages
            .iter()
            .find(|m| u64::from(m.nid) == NO_SUB)
            .unwrap();
        assert_eq!(subject(m), "No subnodes");
        assert_eq!(m.completeness, Completeness::Partial);
        assert!(m.subnode_block_offset.is_none());
        assert!(m.gaps.iter().any(|g| g.contains("subnode")), "{:?}", m.gaps);
    }

    #[test]
    fn an_unreferenced_message_block_with_no_entry_is_a_fragment_and_a_live_copy_is_not() {
        let (r, off) = run();
        assert_eq!(r.messages.len(), 4, "{:?}", r.messages);
        let subjects: Vec<_> = r.fragments.iter().map(subject).collect();
        assert_eq!(subjects, vec!["Orphan fragment"]);
        let f = &r.fragments[0];
        assert_eq!(f.source, Source::UnreferencedBlock);
        assert_eq!(f.data_block_offset, Some(off[&0x114]));
        assert_eq!(f.nid, 0);
        assert_eq!(f.completeness, Completeness::Partial);
        assert!(f.could_be_live.is_empty(), "{:?}", f.could_be_live);
        // The orphan copy of "Live" is a superseded version, counted.
        assert_eq!(r.superseded_copies, 1);
        assert!(!r.capped);
    }

    /// When the newest version of an entry does not read and an older one
    /// does, the older one is published, but not as the message's final
    /// state: it is partial, a gap says a newer version was not read, and the
    /// newer version is listed as newer with why it did not read.
    #[test]
    fn an_older_version_read_in_place_of_a_newer_one_says_so() {
        let (r, _) = run();
        let m = r
            .messages
            .iter()
            .find(|m| u64::from(m.nid) == NEWER_GONE)
            .expect("the older version is recovered");
        assert_eq!(subject(m), "Earlier state");
        assert_eq!(m.bid_data, 0x12C);
        assert_eq!(m.completeness, Completeness::Partial);
        assert!(
            m.gaps
                .iter()
                .any(|g| g.contains("0x134") && g.contains("earlier state")),
            "{:?}",
            m.gaps
        );
        assert_eq!(m.other_versions.len(), 1);
        let v = &m.other_versions[0];
        assert_eq!(v.bid_data, 0x134);
        assert!(v.newer);
        assert!(
            v.read_error.as_deref().is_some_and(|e| e.contains("0x134")),
            "{v:?}"
        );
    }

    /// A store whose live node B-tree is an intermediate page over the live
    /// leaf and a second leaf past the end of the bytes (keys from
    /// `0x20_0080` up): the live walk faults, as on a partly initialised file.
    fn faulted_store() -> (Vec<u8>, Bref, Bref, Mailbox) {
        let (data, _, mb) = store();
        let mut s = Synth {
            data,
            live_blocks: Vec::new(),
            offsets: HashMap::new(),
        };
        let top = s.data.len().div_ceil(PAGE_SIZE) as u64 * PAGE_SIZE as u64;
        let child = |key: u64, bid: u64, ib: u64| {
            let mut e = key.to_le_bytes().to_vec();
            e.extend_from_slice(&bid.to_le_bytes());
            e.extend_from_slice(&ib.to_le_bytes());
            e
        };
        s.page_at(
            top,
            0x1C,
            PTYPE_NBT,
            24,
            1,
            &[child(0, 0x10, LIVE_NBT), child(0x20_0080, 0x18, 0x10_0000)],
        );
        let (_, bbt) = roots();
        (s.data, Bref { bid: 0x1C, ib: top }, bbt, mb)
    }

    /// The live walk not reaching a node is not the node being deleted. When
    /// a page of the live node B-tree could not be read, a node entry whose
    /// key falls under that page may be live; one that does not is gone from
    /// the live tree, but its message may be live under a node that was not
    /// read. Neither is called deleted, and each says why.
    #[test]
    fn a_faulted_live_walk_does_not_make_what_it_missed_deleted() {
        let (data, nbt, bbt, mb) = faulted_store();
        let ndb = Ndb::from_roots(&data, nbt, bbt);
        assert_eq!(ndb.nbt.faults.len(), 1, "{:?}", ndb.nbt.faults);
        assert!(ndb.node(LIVE_MSG as u32).is_some(), "the live leaf reads");
        let r = recover(&ndb, &mb);
        assert_eq!(r.unreferenced_pages, vec![STALE_NBT]);
        for m in r.messages.iter().chain(&r.fragments) {
            assert!(
                !m.could_be_live.is_empty(),
                "{:#x} {} is called deleted",
                m.nid,
                subject(m)
            );
        }
        let reason = |nid: u64| {
            r.messages
                .iter()
                .find(|m| u64::from(m.nid) == nid)
                .map(|m| m.could_be_live.join("; "))
                .unwrap()
        };
        // Under the page that did not read: the node itself may be live.
        assert!(reason(GONE).contains("node 0x200084"), "{}", reason(GONE));
        assert!(
            reason(GONE).contains("may still be live"),
            "{}",
            reason(GONE)
        );
        // Not under it: the node is gone, its message may not be.
        assert!(
            reason(DELETED).contains("another node"),
            "{}",
            reason(DELETED)
        );
        assert!(!r.fragments.is_empty());
    }

    /// A live message node that could not be read may be the live copy of a
    /// recovery, so the recovery is not called deleted either.
    #[test]
    fn an_unreadable_live_message_leaves_every_recovery_undecided() {
        let (data, _, mut mb) = store();
        mb.nodes_unreadable
            .push((0x20_0104, "its data block is gone".into()));
        let (n, b) = roots();
        let ndb = Ndb::from_roots(&data, n, b);
        let r = recover(&ndb, &mb);
        assert!(!r.messages.is_empty());
        for m in r.messages.iter().chain(&r.fragments) {
            assert!(
                m.could_be_live
                    .iter()
                    .any(|w| w.contains("could not be read")),
                "{:?}",
                m.could_be_live
            );
        }
    }

    /// The cap stops the listing, and an entry the cap cut off still claims
    /// its data block, so that block is not listed as a fragment instead.
    #[test]
    fn the_cap_stops_the_listing_without_turning_skipped_entries_into_fragments() {
        let (data, _, mb) = store();
        let (n, b) = roots();
        let ndb = Ndb::from_roots(&data, n, b);
        let r = recover_up_to(&ndb, &mb, 1);
        assert!(r.capped);
        assert_eq!(r.messages.len(), 1);
        let subjects: Vec<_> = r.fragments.iter().map(subject).collect();
        assert_eq!(subjects, vec!["Orphan fragment"]);
    }

    /// A folder-associated item (a view, a rule, a configuration message:
    /// PidTagMessageFlags carries mfFAI) found with no node entry is not
    /// mail, and is counted rather than listed as a deleted message.
    #[test]
    fn an_unreferenced_associated_item_is_not_a_mail_fragment() {
        let (mut data, _, mb) = store();
        let mut s = Synth {
            data: std::mem::take(&mut data),
            live_blocks: Vec::new(),
            offsets: HashMap::new(),
        };
        let fai = pc_with(
            &[
                (0x001A, "IPM.Configuration.WorkHours"),
                (0x0037, "WorkHours"),
            ],
            &[(0x0E07, 0x49)],
        );
        s.block(0x200, &fai, false);
        let (n, b) = roots();
        let ndb = Ndb::from_roots(&s.data, n, b);
        let r = recover(&ndb, &mb);
        assert!(
            r.fragments.iter().all(|f| subject(f) != "WorkHours"),
            "{:?}",
            r.fragments
        );
        assert_eq!(r.associated_items, 1);
    }

    /// A deleted node whose message the live store still holds under another
    /// node (Outlook re-creates a message it moves or re-synchronises) is not
    /// a deleted message: it is named as a copy, not listed as recovered.
    #[test]
    fn a_stale_entry_holding_a_live_message_is_a_copy_not_a_recovery() {
        let (r, _) = run();
        assert!(r.messages.iter().all(|m| u64::from(m.nid) != MOVED));
        assert_eq!(r.copies_of_live, vec![MOVED as u32]);
    }

    /// A recovery over a store built from `blocks` and the stale node entries
    /// given, with no live message at all.
    fn custom_with_cap(
        blocks: impl FnOnce(&mut Synth),
        stale: &[Vec<u8>],
        cap: usize,
    ) -> (Recovery, Synth) {
        let mut s = Synth::new();
        blocks(&mut s);
        let live: Vec<Vec<u8>> = s.live_blocks.iter().map(bbt_entry).collect();
        s.page(LIVE_NBT, 0x10, PTYPE_NBT, 32, &[]);
        s.page(LIVE_BBT, 0x14, PTYPE_BBT, 24, &live);
        s.page(STALE_NBT, 0x08, PTYPE_NBT, 32, stale);
        let (n, b) = roots();
        let r = {
            let ndb = Ndb::from_roots(&s.data, n, b);
            recover_up_to(&ndb, &Mailbox::default(), cap)
        };
        (r, s)
    }

    fn custom(blocks: impl FnOnce(&mut Synth), stale: &[Vec<u8>]) -> Recovery {
        custom_with_cap(blocks, stale, MAX_RECOVERED).0
    }

    /// When no version of an entry reads, every version was tried: each other
    /// version carries its own error, and the entry's gaps name each one. The
    /// record must not read as though the older versions were not attempted.
    #[test]
    fn an_entry_none_of_whose_versions_read_reports_every_versions_error() {
        let r = custom(
            |_| {},
            &[
                nbt_entry(DELETED, 0x400, 0, FOLDER),
                nbt_entry(DELETED, 0x408, 0, FOLDER),
                nbt_entry(DELETED, 0x410, 0, FOLDER),
            ],
        );
        let m = &r.messages[0];
        assert_eq!(m.completeness, Completeness::EntryOnly);
        assert_eq!(m.other_versions.len(), 2);
        for v in &m.other_versions {
            let why = v.read_error.as_deref().expect("it was tried and failed");
            assert!(why.contains(&format!("{:#x}", v.bid_data)), "{why}");
            assert!(!v.newer);
        }
        // Newest first: 0x410 is the one reported on, 0x408 and 0x400 follow.
        assert_eq!(m.bid_data, 0x410);
        assert_eq!(m.gaps.len(), 3, "{:?}", m.gaps);
        for bid in ["0x410", "0x408", "0x400"] {
            assert!(
                m.gaps.iter().any(|g| g.contains(bid)),
                "{bid}: {:?}",
                m.gaps
            );
        }
    }

    /// Two different appointments with the same class and subject and no times
    /// have the same "identity" only because the fields that tell them apart
    /// are absent. Both are listed; neither is a superseded copy of the other.
    #[test]
    fn messages_without_an_identity_are_never_merged() {
        let appt = |subject: &str| pc(&[(0x001A, "IPM.Appointment"), (0x0037, subject)]);
        let r = custom(
            |s| {
                s.block(0x500, &appt("Weekly sync"), false).block(
                    0x504,
                    &appt("Weekly sync"),
                    false,
                );
            },
            &[],
        );
        assert_eq!(r.fragments.len(), 2, "{:?}", r.fragments);
        assert_eq!(r.superseded_copies, 0);
        // And a message whose subject did not decode has no identity either.
        assert!(identity(&BTreeMap::new()).is_none());
        let mut p = BTreeMap::new();
        p.insert(0x0037, PropValue::Str("x".into()));
        assert!(identity(&p).is_none(), "a subject alone is not an identity");
        p.insert(0x0039, PropValue::I32(1));
        assert!(identity(&p).is_some());
    }

    /// A block that carries the property-context signature and does not decode
    /// is counted and located, not dropped as though nothing were there.
    #[test]
    fn an_unreferenced_block_with_a_damaged_heap_is_counted_not_dropped() {
        let mut damaged = msg("Damaged");
        damaged[12] = 0x00; // the BTH header's type byte
        let (r, s) = custom_with_cap(
            |s| {
                s.block(0x600, &damaged, false)
                    // Not a property context at all: no signature, not counted.
                    .block(0x604, &[0x55; 64], false);
            },
            &[],
            MAX_RECOVERED,
        );
        assert!(r.fragments.is_empty());
        assert_eq!(r.unread_contexts.count, 1, "{:?}", r.unread_contexts);
        let u = &r.unread_contexts.listed[0];
        assert_eq!((u.bid, u.ib), (0x600, s.offsets[&0x600]));
        assert!(u.reason.contains("BTH"), "{}", u.reason);
    }

    /// The store-wide read budget runs out partway through, and an
    /// unreferenced property context read after that is recorded as unread for
    /// that reason, not as absent.
    #[test]
    fn a_property_context_past_the_read_budget_is_recorded_as_unread() {
        let big = |subject: &str, pad: usize| {
            pc(&[
                (0x001A, "IPM.Note"),
                (0x0037, subject),
                (0x1000, &"x".repeat(pad)),
            ])
        };
        // 60 stale entries naming one 60 KB property context each re-read it,
        // which is what spends the budget (about 8 times the store's bytes).
        let entries: Vec<Vec<u8>> = (0..60u64)
            .map(|i| nbt_entry(0x20_0004 + (i << 5), 0x700, 0, FOLDER))
            .collect();
        let r = custom(
            |s| {
                s.block(0x700, &big("Entry", 30_000), false).block(
                    0x704,
                    &big("Candidate", 31_000),
                    false,
                );
            },
            &entries,
        );
        assert!(
            r.messages
                .iter()
                .any(|m| m.completeness == Completeness::EntryOnly),
            "the budget should have run out inside the entries"
        );
        assert!(
            r.unread_contexts
                .listed
                .iter()
                .any(|u| u.bid == 0x704 && u.reason.contains("read budget")),
            "{:?}",
            r.unread_contexts
        );
    }

    /// The first leaf of a multi-block data tree is a heap page of its own and
    /// reads as a property context alone. The entry that names the tree claims
    /// it, so it is not listed as a fragment of a message that has an entry.
    #[test]
    fn the_leaves_of_an_entrys_data_tree_are_not_listed_as_fragments() {
        let leaf = msg("Big message");
        let mut x = vec![1, 1, 1, 0];
        x.extend_from_slice(&(leaf.len() as u32).to_le_bytes());
        x.extend_from_slice(&0x500u64.to_le_bytes());
        let r = custom(
            |s| {
                s.block(0x500, &leaf, false).block(0x502, &x, false);
            },
            &[nbt_entry(DELETED, 0x502, 0, FOLDER)],
        );
        assert_eq!(r.messages.len(), 1, "{:?}", r.messages);
        assert_eq!(subject(&r.messages[0]), "Big message");
        assert!(r.fragments.is_empty(), "{:?}", r.fragments);
        assert_eq!(r.superseded_copies, 0);
    }

    /// A stale entry whose subnode tree is gone reads its data tree once; the
    /// budget is charged for one read of the data, not two.
    #[test]
    fn a_missing_subnode_tree_costs_one_read_of_the_data() {
        let (data, _, _) = store();
        let (n, b) = roots();
        let ndb = Ndb::from_roots(&data, n, b);
        let unreferenced = scan_blocks(&data).found;
        let ext = ndb.with_unreferenced_blocks(&unreferenced);
        let before = ext.bytes_read().0;
        let a = attempt(&ext, 0x10C, 0x110).expect("the data reads");
        let spent = ext.bytes_read().0 - before;
        assert_eq!(
            a.props.get(&0x0037),
            Some(&PropValue::Str("No subnodes".into()))
        );
        assert!(!a.subnodes_read);
        assert!(a.gaps.iter().any(|g| g.contains("0x110")), "{:?}", a.gaps);
        assert_eq!(
            spent,
            u64::from(ext.block_entry(0x10C).unwrap().cb_inflated)
        );
    }

    /// An attachment that will not read is named with its node, its block and
    /// the reason, not counted in a bare "N attachment(s)".
    #[test]
    fn an_unreadable_attachment_names_its_node_block_and_reason() {
        let r = custom(
            |s| {
                s.block(0x800, &msg("With attachment"), false)
                    .block(0x804, &slblock(0x25, 0x808), false)
                    // Sealed, so it is found and read, and is not a heap.
                    .block(0x808, &[0x77; 40], false);
            },
            &[nbt_entry(DELETED, 0x800, 0x804, FOLDER)],
        );
        let m = &r.messages[0];
        assert_eq!(m.attachments_unreadable, 1);
        let g = m
            .gaps
            .iter()
            .find(|g| g.contains("attachment"))
            .expect("a gap for the attachment");
        assert!(g.contains("0x25") && g.contains("0x808"), "{g}");
        assert!(g.contains("heap signature"), "{g}");
        assert_eq!(m.completeness, Completeness::Partial);
    }

    /// A page and a block whose trailers match and whose CRC does not are
    /// counted and located, so "nothing more was deleted" is not read off a
    /// scan that could not validate what it found.
    #[test]
    fn candidates_that_match_a_trailer_but_fail_their_crc_are_counted() {
        let (mut data, off, _) = {
            let (d, o, m) = store();
            (d, o, m)
        };
        data[STALE_NBT as usize + 3] ^= 0xFF; // inside the entries, CRC now wrong
        data[off[&0x114] as usize + 5] ^= 0xFF; // inside the stored block
        let pages = scan_pages(&data);
        assert_eq!(pages.found.len(), 2);
        assert_eq!(pages.unvalidated.listed, vec![STALE_NBT]);
        let blocks = scan_blocks(&data);
        assert_eq!(blocks.found.len(), 8);
        assert_eq!(blocks.unvalidated.listed, vec![off[&0x114]]);

        let (n, b) = roots();
        let ndb = Ndb::from_roots(&data, n, b);
        let (_, _, mb) = store();
        let r = recover(&ndb, &mb);
        assert_eq!(r.pages_unvalidated.count, 1);
        assert_eq!(r.blocks_unvalidated.count, 1);
    }

    /// The listing cap applies to fragments as well as to messages.
    #[test]
    fn the_fragment_cap_stops_the_listing() {
        let (r, _) = custom_with_cap(
            |s| {
                s.block(0x900, &msg("First fragment"), false).block(
                    0x904,
                    &msg("Second fragment"),
                    false,
                );
            },
            &[],
            1,
        );
        assert!(r.capped);
        assert_eq!(r.fragments.len(), 1);
        assert!(r.messages.is_empty());
    }

    /// A BID found twice keeps its first copy; BIDs differing only in the
    /// reserved bit are one block.
    #[test]
    fn a_bid_found_twice_keeps_its_first_copy() {
        let mut s = Synth::new();
        let first = s.data.len() as u64;
        s.block(0xA00, &msg("First copy"), false)
            .block(0xA00, &msg("Second copy"), false)
            .block(0xA01, &msg("Reserved bit"), false);
        let found = scan_blocks(&s.data).found;
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].bref.ib, first);
    }

    /// A block stored compressed (cb differs from cbInflated) is accepted by
    /// the scan with its inflated size.
    #[test]
    fn a_compressed_block_is_found_with_its_inflated_size() {
        use std::io::Write;
        let raw = vec![7u8; 3000];
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        z.write_all(&raw).unwrap();
        let stored = z.finish().unwrap();
        assert!(stored.len() < raw.len());
        let mut s = Synth::new();
        s.sealed(0xB00, &stored, raw.len() as u16, false);
        let found = scan_blocks(&s.data).found;
        assert_eq!(found.len(), 1);
        assert_eq!(usize::from(found[0].cb), stored.len());
        assert_eq!(usize::from(found[0].cb_inflated), raw.len());
    }

    #[test]
    fn a_scan_of_hostile_bytes_ends_and_finds_nothing() {
        let data: Vec<u8> = (0..(1u32 << 20))
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let t = std::time::Instant::now();
        let (pages, blocks) = (scan_pages(&data), scan_blocks(&data));
        assert!(pages.found.is_empty() && blocks.found.is_empty());
        // Hostile bytes are not read as damaged blocks either: a chance
        // signature match is rare, and none here has a CRC to fail.
        assert_eq!(pages.unvalidated.count, 0);
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
    }
}
