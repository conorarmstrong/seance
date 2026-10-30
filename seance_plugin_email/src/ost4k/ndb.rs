//! The node database of a version-36 store: its two trees and the blocks they
//! name.

use super::block::{read_block, BlockFault};
use super::btree::{walk_bbt, walk_nbt, BbtEntry, NbtEntry, Walk};
use super::{le_u16, le_u32, le_u64, Bref, Header4k, Ost4kError};
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};

/// An opened store: the header, and the walks of both B-trees with every
/// page they could not read.
pub struct Ndb<'a> {
    pub data: &'a [u8],
    pub header: Header4k,
    pub nbt: Walk<NbtEntry>,
    pub bbt: Walk<BbtEntry>,
    nodes: BTreeMap<u64, NbtEntry>,
    blocks: HashMap<u64, BbtEntry>,
    /// Inflated bytes node reads may still assemble (see [`READ_FACTOR`]).
    read_budget: Cell<u64>,
    read_budget_total: u64,
}

/// Node reads (data trees and subnode trees) may assemble at most this many
/// times the inflated bytes the block B-tree holds, plus [`READ_FLOOR`].
/// Honest reading touches each block about once (a block Outlook shares
/// between nodes is read once per node that names it); the budget is what
/// stops many nodes that each name one large tree from making the reader's
/// work grow with the square of the input.
pub const READ_FACTOR: u64 = 8;
pub const READ_FLOOR: u64 = 1 << 20;

impl<'a> Ndb<'a> {
    pub fn open(data: &'a [u8]) -> Result<Self, Ost4kError> {
        let header = Header4k::read(data)?;
        Ok(Self::from_header(data, header))
    }

    /// Open from two roots given by the caller rather than read from a
    /// header — for the fuzz target, which must reach the page, block and LTP
    /// readers without first forging two CRCs. The header fields it reports
    /// are the roots and the input length; nothing else is claimed.
    pub fn from_roots(data: &'a [u8], nbt_root: Bref, bbt_root: Bref) -> Self {
        let header = Header4k {
            client: "unknown client",
            version: 36,
            file_eof: data.len() as u64,
            nbt_root,
            bbt_root,
            crypt_method: 0,
        };
        Self::from_header(data, header)
    }

    fn from_header(data: &'a [u8], header: Header4k) -> Self {
        let nbt = walk_nbt(data, header.nbt_root);
        let bbt = walk_bbt(data, header.bbt_root);
        Self::assemble(data, header, nbt, bbt)
    }

    /// An NDB over walks already made (the unit tests build these by hand).
    fn assemble(
        data: &'a [u8],
        header: Header4k,
        nbt: Walk<NbtEntry>,
        bbt: Walk<BbtEntry>,
    ) -> Self {
        let nodes = nbt.entries.iter().map(|e| (e.nid, *e)).collect();
        let blocks: HashMap<u64, BbtEntry> =
            bbt.entries.iter().map(|e| (e.bref.bid & !1, *e)).collect();
        let held: u64 = blocks.values().map(|e| u64::from(e.cb_inflated)).sum();
        let budget = held.saturating_mul(READ_FACTOR).saturating_add(READ_FLOOR);
        Self {
            data,
            header,
            nbt,
            bbt,
            nodes,
            blocks,
            read_budget: Cell::new(budget),
            read_budget_total: budget,
        }
    }

    pub fn node(&self, nid: u32) -> Option<&NbtEntry> {
        self.nodes.get(&u64::from(nid))
    }

    pub fn nodes(&self) -> impl Iterator<Item = &NbtEntry> {
        self.nodes.values()
    }

    /// Inflated bytes node reads have assembled so far, and the store-wide
    /// budget they are held to.
    pub fn bytes_read(&self) -> (u64, u64) {
        (
            self.read_budget_total - self.read_budget.get(),
            self.read_budget_total,
        )
    }

    pub fn block_entry(&self, bid: u64) -> Option<&BbtEntry> {
        self.blocks.get(&(bid & !1))
    }

    /// The same store with `extra` added to its block map: blocks a scan of
    /// the bytes found that the block B-tree no longer names (deleted-message
    /// recovery, [`super::recover`]). A BID the block B-tree does name keeps
    /// the tree's entry. The read budget is re-made over the larger map.
    pub fn with_unreferenced_blocks(&self, extra: &[BbtEntry]) -> Ndb<'a> {
        let mut bbt = self.bbt.clone();
        bbt.entries.extend(
            extra
                .iter()
                .filter(|e| self.block_entry(e.bref.bid).is_none())
                .copied(),
        );
        Self::assemble(self.data, self.header.clone(), self.nbt.clone(), bbt)
    }
}

/// The internal-block bit of a BID: the block holds BIDs, not data.
pub const BID_INTERNAL: u64 = 0x2;
/// A data tree deeper than an XXBLOCK is not one Outlook writes.
const MAX_TREE_LEVEL: u8 = 2;

/// One subnode: its data and its own subnode tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnode {
    pub bid_data: u64,
    pub bid_sub: u64,
}

/// Why a node's data could not be assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeFault {
    Block(BlockFault),
    /// An XBLOCK, XXBLOCK, SLBLOCK or SIBLOCK that is not well formed.
    Internal {
        bid: u64,
        detail: String,
    },
    /// The store-wide read budget ran out before this block could be read.
    ReadBudget {
        bid: u64,
        budget: u64,
    },
}

impl std::fmt::Display for NodeFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block(b) => write!(f, "{b}"),
            Self::Internal { bid, detail } => write!(f, "internal block {bid:#x}: {detail}"),
            Self::ReadBudget { bid, budget } => write!(
                f,
                "block {bid:#x} not read: the store-wide read budget of {budget} bytes \
                 ({READ_FACTOR} times what the block B-tree holds) was exhausted by the nodes \
                 read before it"
            ),
        }
    }
}

impl From<BlockFault> for NodeFault {
    fn from(b: BlockFault) -> Self {
        Self::Block(b)
    }
}

impl Ndb<'_> {
    /// One block's data, inflated.
    pub fn block(&self, bid: u64) -> Result<Vec<u8>, BlockFault> {
        let e = self.block_entry(bid).ok_or(BlockFault::NotInBbt { bid })?;
        read_block(self.data, e)
    }

    /// One block read on behalf of a node, charged to the store-wide read
    /// budget before it is inflated.
    fn charged_block(&self, bid: u64) -> Result<Vec<u8>, NodeFault> {
        let e = self.block_entry(bid).ok_or(BlockFault::NotInBbt { bid })?;
        let cost = u64::from(e.cb_inflated).max(1);
        let left = self.read_budget.get();
        if cost > left {
            return Err(NodeFault::ReadBudget {
                bid,
                budget: self.read_budget_total,
            });
        }
        self.read_budget.set(left - cost);
        Ok(read_block(self.data, e)?)
    }

    /// A node's data as its data blocks, in order: the block itself, or the
    /// leaves of its XBLOCK / XXBLOCK tree.
    ///
    /// The tree is bounded three ways, so a small hostile store cannot make
    /// the reader assemble more than the store holds: a block named twice
    /// in one tree is refused (so the tree reads each block at most once),
    /// every XBLOCK and XXBLOCK's `lcbTotal` must equal what its leaves hold
    /// and reading stops as soon as the leaves pass it, and every block read
    /// is charged to the store-wide read budget.
    pub fn data_tree(&self, bid: u64) -> Result<Vec<Vec<u8>>, NodeFault> {
        if bid == 0 {
            return Ok(Vec::new());
        }
        let mut t = DataTree {
            out: Vec::new(),
            total: 0,
            visited: HashSet::new(),
        };
        self.data_tree_into(bid, MAX_TREE_LEVEL + 1, usize::MAX, &mut t)?;
        Ok(t.out)
    }

    /// A node's data as one run of bytes.
    pub fn data(&self, bid: u64) -> Result<Vec<u8>, NodeFault> {
        let blocks = self.data_tree(bid)?;
        let mut out = Vec::with_capacity(blocks.iter().map(Vec::len).sum());
        for b in blocks {
            out.extend_from_slice(&b);
        }
        Ok(out)
    }

    fn data_tree_into(
        &self,
        bid: u64,
        max_level: u8,
        limit: usize,
        t: &mut DataTree,
    ) -> Result<(), NodeFault> {
        let bad = |detail: String| NodeFault::Internal { bid, detail };
        if !t.visited.insert(bid & !1) {
            return Err(bad(
                "named more than once in one data tree (a real tree names each block once)".into(),
            ));
        }
        let b = self.charged_block(bid)?;
        if bid & BID_INTERNAL == 0 {
            t.total += b.len();
            t.out.push(b);
            if t.total > limit {
                return Err(bad(format!(
                    "the leaves pass the {limit} bytes the tree above states (lcbTotal)"
                )));
            }
            return Ok(());
        }
        let (btype, level) = (b.first().copied(), b.get(1).copied());
        let (Some(1), Some(level)) = (btype, level) else {
            return Err(bad(format!(
                "block type {btype:?} where an XBLOCK (1) belongs"
            )));
        };
        if level == 0 || level >= max_level {
            return Err(bad(format!(
                "XBLOCK level {level} below a level-{max_level} parent"
            )));
        }
        let c_ent = usize::from(le_u16(&b, 2).unwrap_or(0));
        let lcb_total = le_u32(&b, 4).unwrap_or(0) as usize;
        if 8 + c_ent * 8 > b.len() {
            return Err(bad(format!(
                "{c_ent} entries do not fit in {} bytes",
                b.len()
            )));
        }
        let before = t.total;
        let own_limit = limit.min(before.saturating_add(lcb_total));
        for i in 0..c_ent {
            let child = le_u64(&b, 8 + i * 8).unwrap_or(0);
            self.data_tree_into(child, level, own_limit, t)?;
        }
        let got = t.total - before;
        if got != lcb_total {
            return Err(bad(format!(
                "lcbTotal {lcb_total} but the leaves hold {got} bytes"
            )));
        }
        Ok(())
    }

    /// A node's subnodes, from its SLBLOCK / SIBLOCK tree, by NID. A block
    /// named twice in one tree is refused, and every block read is charged
    /// to the store-wide read budget.
    pub fn subnodes(&self, bid: u64) -> Result<BTreeMap<u32, Subnode>, NodeFault> {
        let mut out = BTreeMap::new();
        if bid != 0 {
            self.subnodes_into(bid, MAX_TREE_LEVEL, &mut out, &mut HashSet::new())?;
        }
        Ok(out)
    }

    fn subnodes_into(
        &self,
        bid: u64,
        max_level: u8,
        out: &mut BTreeMap<u32, Subnode>,
        visited: &mut HashSet<u64>,
    ) -> Result<(), NodeFault> {
        let bad = |detail: String| NodeFault::Internal { bid, detail };
        if !visited.insert(bid & !1) {
            return Err(bad(
                "named more than once in one subnode tree (a real tree names each block once)"
                    .into(),
            ));
        }
        let b = self.charged_block(bid)?;
        let (btype, level) = (b.first().copied(), b.get(1).copied().unwrap_or(0xFF));
        if btype != Some(2) || level >= max_level {
            return Err(bad(format!(
                "block type {btype:?} level {level} where a subnode block (2) belongs"
            )));
        }
        let c_ent = usize::from(le_u16(&b, 2).unwrap_or(0));
        let cb = if level == 0 { 24 } else { 16 };
        if 8 + c_ent * cb > b.len() {
            return Err(bad(format!(
                "{c_ent} entries do not fit in {} bytes",
                b.len()
            )));
        }
        for i in 0..c_ent {
            let at = 8 + i * cb;
            let nid = le_u64(&b, at).unwrap_or(0) as u32;
            let first = le_u64(&b, at + 8).unwrap_or(0);
            if level == 0 {
                let bid_sub = le_u64(&b, at + 16).unwrap_or(0);
                out.insert(
                    nid,
                    Subnode {
                        bid_data: first,
                        bid_sub,
                    },
                );
            } else {
                self.subnodes_into(first, level, out, visited)?;
            }
        }
        Ok(())
    }
}

/// The leaves of one data tree as they are gathered.
struct DataTree {
    out: Vec<Vec<u8>>,
    total: usize,
    visited: HashSet<u64>,
}

#[cfg(test)]
mod tests {
    //! Synthetic stores, honest here because they pin only the bounds on the
    //! internal-block trees — a tree that names one block more than once, or
    //! states the wrong total — not the format, which is tested against the
    //! Data Leakage OST in `tests/ost4k_real_test.rs`.
    use super::super::block::BLOCK_TRAILER;
    use super::super::crc::{ndb_crc, ndb_sig};
    use super::*;

    #[derive(Default)]
    struct Store {
        data: Vec<u8>,
        blocks: Vec<BbtEntry>,
    }

    impl Store {
        /// Append one uncompressed block, sealed as Outlook would.
        fn add(&mut self, bid: u64, stored: &[u8]) -> &mut Self {
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
            d[t + 18..t + 20].copy_from_slice(&cb.to_le_bytes());
            self.data.extend_from_slice(&d);
            self.blocks.push(BbtEntry {
                bref: Bref { bid, ib },
                cb,
                cb_inflated: cb,
                c_ref: 1,
            });
            self
        }

        fn ndb(&self) -> Ndb<'_> {
            let header = Header4k {
                client: "test",
                version: 36,
                file_eof: self.data.len() as u64,
                nbt_root: Bref { bid: 0, ib: 0 },
                bbt_root: Bref { bid: 0, ib: 0 },
                crypt_method: 0,
            };
            let bbt = Walk {
                entries: self.blocks.clone(),
                ..Walk::default()
            };
            Ndb::assemble(&self.data, header, Walk::default(), bbt)
        }
    }

    /// An XBLOCK (level 1) or XXBLOCK (level 2).
    fn xblock(level: u8, lcb_total: u32, children: &[u64]) -> Vec<u8> {
        let mut b = vec![1, level];
        b.extend_from_slice(&(children.len() as u16).to_le_bytes());
        b.extend_from_slice(&lcb_total.to_le_bytes());
        for c in children {
            b.extend_from_slice(&c.to_le_bytes());
        }
        b
    }

    /// An SIBLOCK (level 1) whose entries each name `child`.
    fn siblock(entries: &[(u64, u64)]) -> Vec<u8> {
        let mut b = vec![2, 1];
        b.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        for (nid, bid) in entries {
            b.extend_from_slice(&nid.to_le_bytes());
            b.extend_from_slice(&bid.to_le_bytes());
        }
        b
    }

    fn slblock(entries: &[(u64, u64, u64)]) -> Vec<u8> {
        let mut b = vec![2, 0];
        b.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        for (nid, data, sub) in entries {
            b.extend_from_slice(&nid.to_le_bytes());
            b.extend_from_slice(&data.to_le_bytes());
            b.extend_from_slice(&sub.to_le_bytes());
        }
        b
    }

    const DATA_A: u64 = 0x404;
    const DATA_B: u64 = 0x408;
    const X_A: u64 = 0x406;
    const X_B: u64 = 0x40A;
    const XX: u64 = 0x40E;

    #[test]
    fn an_honest_xxblock_tree_reads_its_leaves_in_order() {
        let mut s = Store::default();
        s.add(DATA_A, &[0xA; 100])
            .add(DATA_B, &[0xB; 100])
            .add(X_A, &xblock(1, 100, &[DATA_A]))
            .add(X_B, &xblock(1, 100, &[DATA_B]))
            .add(XX, &xblock(2, 200, &[X_A, X_B]));
        let got = s.ndb().data_tree(XX).unwrap();
        assert_eq!(got, vec![vec![0xA; 100], vec![0xB; 100]]);
    }

    #[test]
    fn a_data_block_named_twice_in_one_tree_is_refused() {
        let mut s = Store::default();
        s.add(DATA_A, &[0xA; 100])
            .add(X_A, &xblock(1, 200, &[DATA_A, DATA_A]));
        let got = s.ndb().data_tree(X_A);
        assert!(
            matches!(&got, Err(NodeFault::Internal { detail, .. }) if detail.contains("more than once")),
            "{got:?}"
        );
    }

    #[test]
    fn an_xxblock_whose_lcb_total_disagrees_with_its_leaves_is_refused() {
        let mut s = Store::default();
        s.add(DATA_A, &[0xA; 100])
            .add(DATA_B, &[0xB; 100])
            .add(X_A, &xblock(1, 100, &[DATA_A]))
            .add(X_B, &xblock(1, 100, &[DATA_B]))
            .add(XX, &xblock(2, 999, &[X_A, X_B]));
        let got = s.ndb().data_tree(XX);
        assert!(
            matches!(&got, Err(NodeFault::Internal { bid: XX, detail }) if detail.contains("lcbTotal 999")),
            "{got:?}"
        );
    }

    /// The reviewer's amplification: one 8,000-byte block named 1,000 times
    /// by an XBLOCK, that XBLOCK named 20 times by an XXBLOCK — 28 KiB of
    /// input that used to assemble 160,000,000 bytes.
    #[test]
    fn one_block_named_by_every_entry_of_an_xxblock_is_refused_without_amplifying() {
        let mut s = Store::default();
        s.add(DATA_A, &[0x5A; 8000])
            .add(X_A, &xblock(1, 8_000_000, &[DATA_A; 1000]))
            .add(XX, &xblock(2, 160_000_000, &[X_A; 20]));
        let t = std::time::Instant::now();
        let got = s.ndb().data_tree(XX);
        assert!(got.is_err(), "assembled {:?} blocks", got.map(|v| v.len()));
        assert!(t.elapsed() < std::time::Duration::from_millis(500));
    }

    /// Many nodes that each name the same (well-formed) tree cannot make the
    /// store read more than a fixed multiple of what its block B-tree holds.
    #[test]
    fn the_store_wide_read_budget_stops_repeated_reads_of_one_tree() {
        let mut s = Store::default();
        s.add(DATA_A, &[0xA; 60_000])
            .add(DATA_B, &[0xB; 60_000])
            .add(X_A, &xblock(1, 120_000, &[DATA_A, DATA_B]));
        let ndb = s.ndb();
        let mut refused = None;
        for i in 0..1_000 {
            if let Err(e) = ndb.data_tree(X_A) {
                refused = Some((i, e));
                break;
            }
        }
        let (i, e) = refused.expect("1,000 reads of a 120 KB tree were all allowed");
        assert!(i > 1, "an honest first read was refused: {e}");
        assert!(e.to_string().contains("read budget"), "{e}");
    }

    #[test]
    fn an_siblock_naming_one_slblock_twice_is_refused() {
        let mut s = Store::default();
        s.add(0x410, &slblock(&[(0x25, DATA_A, 0)])).add(
            0x412 | BID_INTERNAL,
            &siblock(&[(0x25, 0x410), (0x25, 0x410)]),
        );
        let got = s.ndb().subnodes(0x412 | BID_INTERNAL);
        assert!(
            matches!(&got, Err(NodeFault::Internal { detail, .. }) if detail.contains("more than once")),
            "{got:?}"
        );
    }
}
