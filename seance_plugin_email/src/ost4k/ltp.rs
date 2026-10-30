//! The LTP layer over a version-36 NDB: heap-on-node, B-tree-on-heap and
//! property contexts.

/// One property value.
#[derive(Debug, Clone, PartialEq)]
pub enum PropValue {
    I16(i16),
    I32(i32),
    I64(i64),
    F64(f64),
    Bool(bool),
    /// A FILETIME: 100 ns ticks since 1601.
    Time(i64),
    Str(String),
    Bin(Vec<u8>),
    /// A type this reader keeps as bytes without interpreting.
    Other {
        ptype: u16,
        raw: Vec<u8>,
    },
}

use super::ndb::{Ndb, NodeFault, Subnode};
use super::{le_u16, le_u32};
use std::collections::BTreeMap;

/// `bSig` of a heap-on-node header.
const HN_SIG: u8 = 0xEC;
/// `bClientSig` of a property context.
pub const CLIENT_PC: u8 = 0xBC;
/// `bType` of a B-tree-on-heap header.
const BTH_TYPE: u8 = 0xB5;
/// A BTH deeper than this is not one Outlook writes.
const MAX_BTH_LEVELS: u8 = 8;
/// More allocations than fit a 64 KiB heap page are not real.
const MAX_BTH_RECORDS: usize = 1 << 16;

/// Why an LTP structure could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LtpFault {
    Node(NodeFault),
    Invalid(String),
}

impl std::fmt::Display for LtpFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Node(n) => write!(f, "{n}"),
            Self::Invalid(s) => write!(f, "{s}"),
        }
    }
}

impl From<NodeFault> for LtpFault {
    fn from(n: NodeFault) -> Self {
        Self::Node(n)
    }
}

fn invalid(s: impl Into<String>) -> LtpFault {
    LtpFault::Invalid(s.into())
}

/// A heap-on-node: the node's data blocks, each a heap page with its page
/// map, and the node's subnodes (where values too large for the heap live).
pub struct HeapNode {
    pages: Vec<Vec<u8>>,
    pub client_sig: u8,
    pub user_root: u32,
    pub subnodes: BTreeMap<u32, Subnode>,
}

impl HeapNode {
    pub fn open(ndb: &Ndb<'_>, bid_data: u64, bid_sub: u64) -> Result<Self, LtpFault> {
        let pages = ndb.data_tree(bid_data)?;
        let subnodes = ndb.subnodes(bid_sub)?;
        Self::from_pages(pages, subnodes)
    }

    /// A heap-on-node from data blocks and subnodes already assembled by a
    /// reader of some other store layout.
    pub fn from_pages(
        pages: Vec<Vec<u8>>,
        subnodes: BTreeMap<u32, Subnode>,
    ) -> Result<Self, LtpFault> {
        let first = pages
            .first()
            .ok_or_else(|| invalid("the node has no data"))?;
        if first.get(2) != Some(&HN_SIG) {
            return Err(invalid(format!(
                "heap signature {:?} where 0xEC belongs",
                first.get(2)
            )));
        }
        Ok(Self {
            client_sig: first.get(3).copied().unwrap_or(0),
            user_root: le_u32(first, 4).unwrap_or(0),
            pages,
            subnodes,
        })
    }

    /// Total bytes of every heap page. A property context never names more
    /// heap bytes than the heap holds, so this bounds what its values may copy.
    fn heap_len(&self) -> usize {
        self.pages.iter().map(Vec::len).sum()
    }

    /// The bytes of one heap allocation. A HID is `hidType` (5 bits, 0),
    /// `hidIndex` (11 bits, 1-based) and `hidBlockIndex` (16 bits).
    pub fn alloc(&self, hid: u32) -> Result<&[u8], LtpFault> {
        if hid & 0x1F != 0 {
            return Err(invalid(format!("{hid:#x} is a node id, not a heap id")));
        }
        let index = ((hid >> 5) & 0x7FF) as usize;
        let page = self
            .pages
            .get((hid >> 16) as usize)
            .ok_or_else(|| invalid(format!("heap id {hid:#x} names a page the node lacks")))?;
        let map = usize::from(le_u16(page, 0).unwrap_or(0));
        let c_alloc = usize::from(le_u16(page, map).unwrap_or(0));
        if index == 0 || index > c_alloc {
            return Err(invalid(format!(
                "heap id {hid:#x}: index {index} of {c_alloc} allocations"
            )));
        }
        let off = |i: usize| le_u16(page, map + 4 + 2 * i).map(usize::from);
        match (off(index - 1), off(index)) {
            (Some(a), Some(b)) if a <= b && b <= page.len() => Ok(&page[a..b]),
            _ => Err(invalid(format!(
                "heap id {hid:#x}: allocation out of bounds"
            ))),
        }
    }

    /// A value's bytes from an HNID: a heap id, or the NID of a subnode
    /// whose data holds it.
    pub fn hnid(&self, ndb: &Ndb<'_>, hnid: u32) -> Result<Vec<u8>, LtpFault> {
        self.hnid_with(&|sub| Ok(ndb.data(sub.bid_data)?), hnid)
    }

    /// [`Self::hnid`] with the subnode's bytes supplied by the caller.
    pub fn hnid_with(
        &self,
        subnode_data: &dyn Fn(&Subnode) -> Result<Vec<u8>, LtpFault>,
        hnid: u32,
    ) -> Result<Vec<u8>, LtpFault> {
        if hnid == 0 {
            return Ok(Vec::new());
        }
        if hnid & 0x1F == 0 {
            return self.alloc(hnid).map(<[u8]>::to_vec);
        }
        let sub = self.subnodes.get(&hnid).ok_or_else(|| {
            invalid(format!(
                "subnode {hnid:#x} is not in the node's subnode tree"
            ))
        })?;
        subnode_data(sub)
    }

    /// Every (key, data) record of the B-tree-on-heap whose header is `hid`.
    /// A tree that names one node twice (or names its own header) is
    /// refused, so the walk is bounded by the heap's allocations.
    pub fn bth(&self, hid: u32) -> Result<Vec<(Vec<u8>, Vec<u8>)>, LtpFault> {
        let h = self.alloc(hid)?;
        if h.len() < 8 || h[0] != BTH_TYPE {
            return Err(invalid(format!("BTH header {hid:#x} is not one")));
        }
        let (cb_key, cb_ent, levels) = (usize::from(h[1]), usize::from(h[2]), h[3]);
        let root = le_u32(h, 4).unwrap_or(0);
        if cb_key == 0 || levels > MAX_BTH_LEVELS {
            return Err(invalid(format!(
                "BTH {hid:#x}: key size {cb_key}, {levels} levels"
            )));
        }
        let mut out = Vec::new();
        // A node named twice is refused, so the walk visits each heap
        // allocation at most once whatever the records say.
        let mut visited = std::collections::HashSet::from([hid]);
        let mut stack = vec![(root, levels)];
        while let Some((node, level)) = stack.pop() {
            if node == 0 {
                continue;
            }
            if !visited.insert(node) {
                return Err(invalid(format!(
                    "BTH {hid:#x}: node {node:#x} is named more than once"
                )));
            }
            let x = self.alloc(node)?;
            let rec = if level == 0 {
                cb_key + cb_ent
            } else {
                cb_key + 4
            };
            if x.len() % rec != 0 {
                return Err(invalid(format!(
                    "BTH node {node:#x}: {} bytes is not a whole number of {rec}-byte records",
                    x.len()
                )));
            }
            for r in x.chunks_exact(rec).rev() {
                if level == 0 {
                    out.push((r[..cb_key].to_vec(), r[cb_key..].to_vec()));
                } else {
                    stack.push((le_u32(r, cb_key).unwrap_or(0), level - 1));
                }
            }
            if out.len() > MAX_BTH_RECORDS {
                return Err(invalid(format!(
                    "BTH {hid:#x} has more records than a heap can hold"
                )));
            }
        }
        // A key of up to eight bytes is a little-endian integer (a tag, a row id, a node id), and the
        // tree is in numeric order; comparing the bytes as a string misorders any id of 256 or more.
        if cb_key <= 8 {
            out.sort_by(|a, b| a.0.iter().rev().cmp(b.0.iter().rev()));
        } else {
            out.sort_by(|a, b| a.0.cmp(&b.0));
        }
        Ok(out)
    }
}

/// A property context read into values. A property whose value would not
/// read is listed in `unreadable`, never dropped in silence. So is a tag that
/// a second record names again: the first value is kept and the repeat is
/// listed, so a conflict is never settled by arrival order.
#[derive(Debug, Clone, Default)]
pub struct PropertyContext {
    pub props: BTreeMap<u16, PropValue>,
    pub unreadable: Vec<(u16, String)>,
    pub subnodes: BTreeMap<u32, Subnode>,
}

/// Read the property context stored in a node (or subnode).
pub fn read_pc(ndb: &Ndb<'_>, bid_data: u64, bid_sub: u64) -> Result<PropertyContext, LtpFault> {
    let hn = HeapNode::open(ndb, bid_data, bid_sub)?;
    read_pc_with(hn, &|sub| Ok(ndb.data(sub.bid_data)?))
}

/// [`read_pc`] for a node whose subnode tree may be gone (an old version of a
/// deleted message): the data tree is read once and a subnode tree that will
/// not read costs only the subnodes. Returns the property context and, when
/// the subnode tree failed, why. A data tree that will not read is an error.
pub fn read_pc_tolerating_subnodes(
    ndb: &Ndb<'_>,
    bid_data: u64,
    bid_sub: u64,
) -> Result<(PropertyContext, Option<NodeFault>), LtpFault> {
    let pages = ndb.data_tree(bid_data)?;
    let (subnodes, subnode_error) = match ndb.subnodes(bid_sub) {
        Ok(s) => (s, None),
        Err(e) => (BTreeMap::new(), Some(e)),
    };
    let hn = HeapNode::from_pages(pages, subnodes)?;
    let pc = read_pc_with(hn, &|sub| Ok(ndb.data(sub.bid_data)?))?;
    Ok((pc, subnode_error))
}

/// Read the property context of an opened heap. `subnode_data` gives the
/// bytes of a subnode, where a value too large for the heap is stored.
pub fn read_pc_with(
    hn: HeapNode,
    subnode_data: &dyn Fn(&Subnode) -> Result<Vec<u8>, LtpFault>,
) -> Result<PropertyContext, LtpFault> {
    if hn.client_sig != CLIENT_PC {
        return Err(invalid(format!(
            "client signature {:#04x} where a property context (0xBC) belongs",
            hn.client_sig
        )));
    }
    let mut pc = PropertyContext::default();
    // Values stored in the heap are copied out; many records may name one
    // large allocation, so the copies are charged to a budget of the heap's
    // own size and a value past it is listed as unreadable, never copied.
    let mut heap_budget = hn.heap_len();
    for (k, v) in hn.bth(hn.user_root)? {
        let (Some(tag), Some(ptype), Some(value)) = (le_u16(&k, 0), le_u16(&v, 0), le_u32(&v, 2))
        else {
            return Err(invalid("property record is not 2 + 6 bytes"));
        };
        if pc.props.contains_key(&tag) || pc.unreadable.iter().any(|(t, _)| *t == tag) {
            pc.unreadable
                .push((tag, "duplicate property record".to_string()));
            continue;
        }
        match decode(&hn, subnode_data, &mut heap_budget, ptype, value) {
            Ok(p) => {
                pc.props.insert(tag, p);
            }
            Err(e) => pc.unreadable.push((tag, e.to_string())),
        }
    }
    pc.subnodes = hn.subnodes;
    Ok(pc)
}

/// `bClientSig` of a table context.
pub const CLIENT_TC: u8 = 0x7C;

/// A table context read into rows. A row that would not read, or a cell that would not decode, is
/// listed in `unreadable` as (row, tag, why) with tag 0 for a whole row, never dropped in silence.
#[derive(Debug, Clone, Default)]
pub struct TableContext {
    pub rows: Vec<BTreeMap<u16, PropValue>>,
    pub unreadable: Vec<(usize, u16, String)>,
}

/// One column of a table context: `TCOLDESC`.
struct Column {
    tag: u16,
    ptype: u16,
    offset: usize,
    size: usize,
    bit: usize,
}

/// Read the table context held by node (or subnode) `bid_data` of a version 36 store, whose block size
/// is read from the matrix itself.
pub fn read_tc(ndb: &Ndb<'_>, bid_data: u64, bid_sub: u64) -> Result<TableContext, LtpFault> {
    let hn = HeapNode::open(ndb, bid_data, bid_sub)?;
    read_tc_with(
        hn,
        &|sub| Ok(ndb.data(sub.bid_data)?),
        &|sub| Ok(ndb.data_tree(sub.bid_data)?),
        0,
    )
}

/// Read the table context stored in a heap (the recipient table of a message, say).
///
/// `subnode_data` gives the bytes of a subnode (a value too large for the heap), and `subnode_blocks`
/// the separate blocks of one, because a row matrix too large for the heap lives in a subnode whose
/// blocks each hold a whole number of rows (`block_cap` bytes at most: 8,176 in a Unicode store, 8,180
/// in an ANSI one). Each row is read from the matrix at the position its row index names, and a cell
/// is present only if its bit in the row's existence bitmap is set.
pub fn read_tc_with(
    hn: HeapNode,
    subnode_data: &dyn Fn(&Subnode) -> Result<Vec<u8>, LtpFault>,
    subnode_blocks: &dyn Fn(&Subnode) -> Result<Vec<Vec<u8>>, LtpFault>,
    block_cap: usize,
) -> Result<TableContext, LtpFault> {
    if hn.client_sig != CLIENT_TC {
        return Err(invalid(format!(
            "client signature {:#04x} where a table context (0x7C) belongs",
            hn.client_sig
        )));
    }
    let info = hn.alloc(hn.user_root)?;
    if info.len() < 22 || info[0] != 0x7C {
        return Err(invalid("the table context header is not a TCINFO"));
    }
    let column_count = usize::from(info[1]);
    let end_of_columns = usize::from(le_u16(info, 6).unwrap_or(0));
    let row_size = usize::from(le_u16(info, 8).unwrap_or(0));
    let (hid_row_index, hnid_rows) = (le_u32(info, 10).unwrap_or(0), le_u32(info, 14).unwrap_or(0));
    let bitmap_len = column_count.div_ceil(8);
    if row_size == 0 || end_of_columns + bitmap_len > row_size {
        return Err(invalid(format!(
            "table context: rows of {row_size} bytes cannot hold {column_count} columns and their bitmap"
        )));
    }
    if info.len() < 22 + 8 * column_count {
        return Err(invalid(
            "table context: fewer column descriptors than columns",
        ));
    }
    let mut columns = Vec::with_capacity(column_count);
    for d in info[22..22 + 8 * column_count].as_chunks::<8>().0 {
        let column = Column {
            ptype: le_u16(d, 0).unwrap_or(0),
            tag: le_u16(d, 2).unwrap_or(0),
            offset: usize::from(le_u16(d, 4).unwrap_or(0)),
            size: usize::from(d[6]),
            bit: usize::from(d[7]),
        };
        if column.size == 0 || column.offset + column.size > end_of_columns {
            return Err(invalid(format!(
                "table context: column {:#06x} lies outside its row",
                column.tag
            )));
        }
        if column.bit / 8 >= bitmap_len {
            return Err(invalid(format!(
                "table context: column {:#06x} names bit {} of a {bitmap_len}-byte bitmap",
                column.tag, column.bit
            )));
        }
        columns.push(column);
    }

    let index = if hid_row_index == 0 {
        Vec::new()
    } else {
        hn.bth(hid_row_index)?
    };
    // Where the rows are: a run of bytes in the heap, or the blocks of a subnode.
    enum Matrix {
        Heap(Vec<u8>),
        Blocks(Vec<Vec<u8>>, usize),
    }
    let matrix = if hnid_rows == 0 {
        Matrix::Heap(Vec::new())
    } else if hnid_rows & 0x1F == 0 {
        Matrix::Heap(hn.alloc(hnid_rows)?.to_vec())
    } else {
        let sub = hn.subnodes.get(&hnid_rows).ok_or_else(|| {
            invalid(format!(
                "row matrix {hnid_rows:#x} is not in the node's subnode tree"
            ))
        })?;
        let blocks = subnode_blocks(sub)?;
        // `block_cap` 0 is a layout whose block size is not fixed here (version 36): a block of a
        // multi-block matrix then holds a whole number of rows, and the first one says how many.
        let per_block = match (block_cap, blocks.first()) {
            (0, Some(first)) => first.len() / row_size,
            (cap, _) => cap / row_size,
        };
        if per_block == 0 {
            return Err(invalid("table context: a row is larger than a block"));
        }
        Matrix::Blocks(blocks, per_block)
    };

    let mut table = TableContext::default();
    let mut heap_budget = hn.heap_len();
    for (n, (key, data)) in index.iter().enumerate() {
        // The row id is 4 bytes; the index of the row in the matrix is 4 bytes in a Unicode store and 2
        // in an ANSI one.
        let row_index = match (key.len(), data.len()) {
            (4, 4) => le_u32(data, 0).map(|n| n as usize),
            (4, 2) => le_u16(data, 0).map(usize::from),
            _ => None,
        }
        .ok_or_else(|| invalid("table context: a row index record is not 4 + 4 or 4 + 2 bytes"))?;
        let row = match &matrix {
            Matrix::Heap(bytes) => row_index
                .checked_mul(row_size)
                .and_then(|at| bytes.get(at..at + row_size)),
            Matrix::Blocks(blocks, per_block) => blocks.get(row_index / per_block).and_then(|b| {
                let at = (row_index % per_block) * row_size;
                b.get(at..at + row_size)
            }),
        };
        let Some(row) = row else {
            table.unreadable.push((
                n,
                0,
                format!("row {row_index} lies past the end of the row matrix"),
            ));
            continue;
        };
        let bitmap = &row[end_of_columns..end_of_columns + bitmap_len];
        let mut cells = BTreeMap::new();
        for column in &columns {
            if bitmap[column.bit / 8] & (0x80 >> (column.bit % 8)) == 0 {
                continue;
            }
            let raw = &row[column.offset..column.offset + column.size];
            let value = match (column.size, column.ptype) {
                (8, 0x0014) => Ok(PropValue::I64(i64::from_le_bytes(
                    raw.try_into().unwrap_or([0; 8]),
                ))),
                (8, 0x0040) => Ok(PropValue::Time(i64::from_le_bytes(
                    raw.try_into().unwrap_or([0; 8]),
                ))),
                (8, 0x0005) => Ok(PropValue::F64(f64::from_le_bytes(
                    raw.try_into().unwrap_or([0; 8]),
                ))),
                (8, ptype) => Ok(PropValue::Other {
                    ptype,
                    raw: raw.to_vec(),
                }),
                (1, _) => decode(
                    &hn,
                    subnode_data,
                    &mut heap_budget,
                    column.ptype,
                    u32::from(raw[0]),
                ),
                (2, _) => decode(
                    &hn,
                    subnode_data,
                    &mut heap_budget,
                    column.ptype,
                    u32::from(u16::from_le_bytes([raw[0], raw[1]])),
                ),
                (4, _) => decode(
                    &hn,
                    subnode_data,
                    &mut heap_budget,
                    column.ptype,
                    u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
                ),
                (size, _) => Err(invalid(format!("a {size}-byte cell"))),
            };
            match value {
                Ok(v) => {
                    cells.insert(column.tag, v);
                }
                Err(e) => table.unreadable.push((n, column.tag, e.to_string())),
            }
        }
        table.rows.push(cells);
    }
    Ok(table)
}

fn decode(
    hn: &HeapNode,
    subnode_data: &dyn Fn(&Subnode) -> Result<Vec<u8>, LtpFault>,
    heap_budget: &mut usize,
    ptype: u16,
    value: u32,
) -> Result<PropValue, LtpFault> {
    // Four bytes or fewer live in the record itself.
    Ok(match ptype {
        0x0002 => PropValue::I16(value as u16 as i16),
        0x0003 | 0x000A => PropValue::I32(value as i32),
        0x000B => PropValue::Bool(value & 0xFF != 0),
        0x0004 => PropValue::Other {
            ptype,
            raw: value.to_le_bytes().to_vec(),
        },
        _ => {
            if value != 0 && value & 0x1F == 0 {
                let len = hn.alloc(value)?.len();
                *heap_budget = heap_budget.checked_sub(len).ok_or_else(|| {
                    invalid("property byte budget exhausted (the values name more heap bytes than the heap holds)")
                })?;
            }
            let raw = hn.hnid_with(subnode_data, value)?;
            let eight = || -> Result<[u8; 8], LtpFault> {
                <[u8; 8]>::try_from(raw.as_slice()).map_err(|_| {
                    invalid(format!(
                        "type {ptype:#06x} value is {} bytes, not 8",
                        raw.len()
                    ))
                })
            };
            match ptype {
                0x0014 => PropValue::I64(i64::from_le_bytes(eight()?)),
                0x0040 => PropValue::Time(i64::from_le_bytes(eight()?)),
                0x0005 => PropValue::F64(f64::from_le_bytes(eight()?)),
                0x001F => {
                    if raw.len() % 2 != 0 {
                        return Err(invalid(format!(
                            "string value is {} bytes, not a whole number of UTF-16 units",
                            raw.len()
                        )));
                    }
                    let units: Vec<u16> = raw
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| u16::from_le_bytes(*c))
                        .collect();
                    let s = String::from_utf16_lossy(&units);
                    PropValue::Str(s.trim_end_matches('\0').to_string())
                }
                // An 8-bit string is in the message's own code page, which is not
                // known here. Valid UTF-8 (so ASCII) is a string; any other bytes
                // are kept exactly as stored, for the reader that knows the code
                // page, rather than altered or dropped.
                0x001E => match std::str::from_utf8(&raw) {
                    Ok(s) => PropValue::Str(s.trim_end_matches('\0').to_string()),
                    Err(_) => PropValue::Other { ptype, raw },
                },
                0x0102 => PropValue::Bin(raw),
                _ => PropValue::Other { ptype, raw },
            }
        }
    })
}

#[cfg(test)]
mod tests {
    //! A synthetic heap, honest here because it pins only the bound on the
    //! B-tree-on-heap walk (a record that names a node already walked), not
    //! the format, which is tested on the Data Leakage OST.
    use super::*;

    /// One heap page holding `allocs` in order: HID of allocation `i` (0-based)
    /// is `(i + 1) << 5`.
    fn heap(allocs: &[Vec<u8>]) -> HeapNode {
        let mut p = vec![0u8; 12];
        p[2] = HN_SIG;
        p[3] = CLIENT_PC;
        let mut offs = vec![12u16];
        for a in allocs {
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
        HeapNode {
            pages: vec![p],
            client_sig: CLIENT_PC,
            user_root: 1 << 5,
            subnodes: BTreeMap::new(),
        }
    }

    fn hid(i: u32) -> u32 {
        i << 5
    }

    fn bth_header(levels: u8, root: u32) -> Vec<u8> {
        let mut h = vec![BTH_TYPE, 2, 6, levels];
        h.extend_from_slice(&root.to_le_bytes());
        h
    }

    fn intermediate(children: &[u32]) -> Vec<u8> {
        let mut x = Vec::new();
        for (k, c) in children.iter().enumerate() {
            x.extend_from_slice(&(k as u16).to_le_bytes());
            x.extend_from_slice(&c.to_le_bytes());
        }
        x
    }

    /// A property context over `allocs` (allocation 1 is the BTH header,
    /// allocation 2 the leaf of `records`, the rest the caller's), read with
    /// no subnodes.
    fn read_records(records: &[(u16, u16, u32)], extra: &[Vec<u8>]) -> PropertyContext {
        let mut leaf = Vec::new();
        for (tag, ty, v) in records {
            leaf.extend_from_slice(&tag.to_le_bytes());
            leaf.extend_from_slice(&ty.to_le_bytes());
            leaf.extend_from_slice(&v.to_le_bytes());
        }
        let mut allocs = vec![bth_header(0, hid(2)), leaf];
        allocs.extend_from_slice(extra);
        read_pc_with(heap(&allocs), &|_| Err(invalid("no subnodes"))).unwrap()
    }

    /// 65,536 records may name one large allocation; each used to be copied.
    /// The copies are charged to a budget of the heap's own size.
    #[test]
    fn many_records_naming_one_large_allocation_are_not_all_copied() {
        let big = vec![0xAB; 10_000];
        let records: Vec<(u16, u16, u32)> =
            (0..100u16).map(|i| (0x6000 + i, 0x0102, hid(3))).collect();
        let pc = read_records(&records, &[big]);
        assert_eq!(pc.props.len() + pc.unreadable.len(), 100);
        assert!(pc.props.len() < 3, "{}", pc.props.len());
        assert!(
            pc.unreadable.iter().all(|(_, why)| why.contains("budget")),
            "{:?}",
            pc.unreadable
        );
    }

    #[test]
    fn a_fixed_width_value_of_the_wrong_length_is_unreadable() {
        let pc = read_records(
            &[(0x0E06, 0x0040, hid(3)), (0x0E07, 0x0040, hid(4))],
            &[vec![1; 12], vec![2; 8]],
        );
        assert!(pc.props.contains_key(&0x0E07));
        assert!(!pc.props.contains_key(&0x0E06));
        assert!(
            pc.unreadable[0].1.contains("12 bytes, not 8"),
            "{:?}",
            pc.unreadable
        );
    }

    #[test]
    fn an_odd_length_utf16_string_is_unreadable_not_shortened() {
        let pc = read_records(&[(0x0037, 0x001F, hid(3))], &[vec![b'a', 0, b'b', 0, b'c']]);
        assert!(pc.props.is_empty());
        assert!(pc.unreadable[0].1.contains("UTF-16"), "{:?}", pc.unreadable);
    }

    #[test]
    fn an_8_bit_string_that_is_not_utf8_keeps_its_bytes_untouched() {
        let pc = read_records(
            &[(0x0037, 0x001E, hid(3)), (0x001A, 0x001E, hid(4))],
            &[b"caf\xE9\0".to_vec(), b"IPM.Note\0".to_vec()],
        );
        assert_eq!(
            pc.props.get(&0x001A),
            Some(&PropValue::Str("IPM.Note".into()))
        );
        // The bytes are in the message's own code page, which this layer does
        // not know: they are kept exactly as stored, for the layer that does.
        assert_eq!(
            pc.props.get(&0x0037),
            Some(&PropValue::Other {
                ptype: 0x001E,
                raw: b"caf\xE9\0".to_vec()
            })
        );
        assert!(pc.unreadable.is_empty(), "{:?}", pc.unreadable);
    }

    /// A tag named twice is a conflict, not a last-writer-wins. Which record is
    /// met first is the BTH walk's order, so the test does not depend on it.
    #[test]
    fn a_tag_named_twice_keeps_the_first_value_and_lists_the_repeat() {
        let both = read_records(
            &[(0x0037, 0x001F, hid(3)), (0x0037, 0x001F, hid(4))],
            &[vec![b'a', 0, b'b', 0], vec![b'x', 0, b'y', 0]],
        );
        assert!(matches!(both.props.get(&0x0037), Some(PropValue::Str(_))));
        assert_eq!(
            both.unreadable,
            vec![(0x0037, "duplicate property record".to_string())]
        );

        // The first fails (odd length) and the second succeeds: whichever is met
        // second is listed as a duplicate, never silently merged.
        let split = read_records(
            &[(0x0037, 0x001F, hid(3)), (0x0037, 0x001F, hid(4))],
            &[vec![b'a', 0, b'b'], vec![b'x', 0, b'y', 0]],
        );
        assert_eq!(split.props.len() + split.unreadable.len(), 2);
        assert!(
            split
                .unreadable
                .iter()
                .any(|(_, why)| why == "duplicate property record"),
            "{:?}",
            split.unreadable
        );
    }

    #[test]
    fn an_honest_two_level_bth_reads_its_records() {
        let leaf_a = vec![1, 0, 3, 0, 7, 0, 0, 0];
        let leaf_b = vec![2, 0, 3, 0, 9, 0, 0, 0];
        let hn = heap(&[
            bth_header(1, hid(2)),
            intermediate(&[hid(3), hid(4)]),
            leaf_a.clone(),
            leaf_b.clone(),
        ]);
        let got = hn.bth(hid(1)).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, vec![1, 0]);
        assert_eq!(got[1].0, vec![2, 0]);
    }

    /// A table context's row index is keyed by 4-byte little-endian row ids, and the B-tree is in
    /// numeric order. Sorting the keys as byte strings put id 256 (`00 01 00 00`) before id 88
    /// (`58 00 00 00`), so a 144-recipient message listed its recipients out of order
    /// (`HUNT-280`, `PST-PUBLIC-4`: Enron mailbox, row ids 88 to 517).
    #[test]
    fn a_bth_with_four_byte_keys_is_in_numeric_order_not_byte_order() {
        let mut leaf = Vec::new();
        for id in [3u32, 88, 255, 256, 300, 517] {
            leaf.extend_from_slice(&id.to_le_bytes());
            leaf.extend_from_slice(&(id * 4).to_le_bytes());
        }
        let mut header = vec![BTH_TYPE, 4, 4, 0];
        header.extend_from_slice(&hid(2).to_le_bytes());
        let hn = heap(&[header, leaf]);
        let ids: Vec<u32> = hn
            .bth(hid(1))
            .unwrap()
            .iter()
            .map(|(k, _)| le_u32(k, 0).unwrap())
            .collect();
        assert_eq!(ids, vec![3, 88, 255, 256, 300, 517]);
    }

    #[test]
    fn a_bth_record_naming_a_node_already_walked_is_refused() {
        let leaf = vec![1, 0, 3, 0, 7, 0, 0, 0];
        let hn = heap(&[bth_header(1, hid(2)), intermediate(&[hid(3), hid(3)]), leaf]);
        let got = hn.bth(hid(1));
        assert!(
            matches!(&got, Err(LtpFault::Invalid(s)) if s.contains("more than once")),
            "{got:?}"
        );
    }

    /// Intermediate nodes that each name the next level's one node 300
    /// times, over an empty leaf, used to walk 300^levels nodes without ever
    /// tripping the record cap; the visited set refuses the first repeat.
    #[test]
    fn a_wide_repeating_bth_over_an_empty_leaf_terminates_at_once() {
        let hn = heap(&[
            bth_header(3, hid(2)),
            intermediate(&[hid(3); 300]),
            intermediate(&[hid(4); 300]),
            intermediate(&[hid(5); 300]),
            Vec::new(),
        ]);
        let t = std::time::Instant::now();
        let got = hn.bth(hid(1));
        let took = t.elapsed();
        assert!(got.is_err(), "{got:?}");
        assert!(took < std::time::Duration::from_millis(200), "{took:?}");
    }

    /// A table context over heap allocations: allocation 1 the TCINFO, 2 the row index BTH header, 3 its
    /// leaf (`indexed` rows), 4 the row matrix, then the caller's. `cols` are (tag, type, offset, size, bit).
    fn table(
        cols: &[(u16, u16, u16, u8, u8)],
        rows: &[Vec<u8>],
        indexed: usize,
        row_size: u16,
        ceb_at: u16,
        extra: &[Vec<u8>],
    ) -> Result<TableContext, LtpFault> {
        table_with_index_width(cols, rows, indexed, row_size, ceb_at, extra, 4)
    }

    /// [`table`] with the row index entry `width` bytes wide: 4 in a Unicode store, 2 in an ANSI one.
    fn table_with_index_width(
        cols: &[(u16, u16, u16, u8, u8)],
        rows: &[Vec<u8>],
        indexed: usize,
        row_size: u16,
        ceb_at: u16,
        extra: &[Vec<u8>],
        width: u8,
    ) -> Result<TableContext, LtpFault> {
        let mut info = vec![0x7C, cols.len() as u8];
        for end in [ceb_at, ceb_at, ceb_at, row_size] {
            info.extend_from_slice(&end.to_le_bytes());
        }
        info.extend_from_slice(&hid(2).to_le_bytes());
        info.extend_from_slice(&hid(4).to_le_bytes());
        info.extend_from_slice(&0u32.to_le_bytes());
        for &(tag, ty, ib, cb, bit) in cols {
            info.extend_from_slice(&ty.to_le_bytes());
            info.extend_from_slice(&tag.to_le_bytes());
            info.extend_from_slice(&ib.to_le_bytes());
            info.push(cb);
            info.push(bit);
        }
        let mut header = vec![BTH_TYPE, 4, width, 0];
        header.extend_from_slice(&hid(3).to_le_bytes());
        let mut leaf = Vec::new();
        for i in 0..indexed {
            leaf.extend_from_slice(&(100 + i as u32).to_le_bytes());
            leaf.extend_from_slice(&(i as u32).to_le_bytes()[..usize::from(width)]);
        }
        let mut allocs = vec![info, header, leaf, rows.concat()];
        allocs.extend_from_slice(extra);
        let mut hn = heap(&allocs);
        hn.client_sig = CLIENT_TC;
        hn.user_root = hid(1);
        let none = |_: &Subnode| Err(invalid("no subnodes"));
        let no_blocks = |_: &Subnode| Err(invalid("no subnodes"));
        read_tc_with(hn, &none, &no_blocks, 8176)
    }

    /// Row layout used below: 8-byte time at 0, 4-byte integer at 8, 4-byte string HNID at 12, a boolean at
    /// 16, the existence bitmap at 17 (bits are counted from the most significant).
    fn row(time: u64, int: u32, name: u32, flag: u8, exist: u8) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&time.to_le_bytes());
        r.extend_from_slice(&int.to_le_bytes());
        r.extend_from_slice(&name.to_le_bytes());
        r.push(flag);
        r.push(exist);
        r
    }

    const COLS: [(u16, u16, u16, u8, u8); 4] = [
        (0x0E06, 0x0040, 0, 8, 0),
        (0x0C15, 0x0003, 8, 4, 1),
        (0x3001, 0x001F, 12, 4, 2),
        (0x3A40, 0x000B, 16, 1, 3),
    ];

    /// Cells keep the tag they were declared with, an 8-byte value is read from the row itself, a string
    /// from the heap, and a cell whose existence bit is clear is absent, not zero.
    #[test]
    fn a_table_context_in_the_heap_is_read_row_by_row_and_an_absent_cell_stays_absent() {
        let rows = vec![
            row(7, 1, hid(5), 1, 0b1111_0000),
            row(9, 3, hid(6), 0, 0b1110_0000),
        ];
        let strings = [b"A\0l\0\0\0".to_vec(), b"B\0\0\0".to_vec()];
        let t = table(&COLS, &rows, 2, 18, 17, &strings).unwrap();
        assert_eq!(t.rows.len(), 2);
        assert_eq!(t.rows[0].get(&0x3001), Some(&PropValue::Str("Al".into())));
        assert_eq!(t.rows[0].get(&0x0C15), Some(&PropValue::I32(1)));
        assert_eq!(t.rows[0].get(&0x0E06), Some(&PropValue::Time(7)));
        assert_eq!(t.rows[0].get(&0x3A40), Some(&PropValue::Bool(true)));
        assert_eq!(t.rows[1].get(&0x3001), Some(&PropValue::Str("B".into())));
        assert_eq!(t.rows[1].get(&0x0C15), Some(&PropValue::I32(3)));
        assert_eq!(
            t.rows[1].get(&0x3A40),
            None,
            "bit clear: the cell is absent"
        );
        assert!(t.unreadable.is_empty(), "{:?}", t.unreadable);
    }

    /// A row index naming a row past the matrix is listed, not read as zeros.
    #[test]
    fn a_row_past_the_end_of_the_matrix_is_listed_unreadable_not_zero_filled() {
        let rows = vec![row(7, 1, hid(5), 1, 0b1111_0000)];
        let t = table(&COLS, &rows, 2, 18, 17, &[b"A\0\0\0".to_vec()]).unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(t.unreadable.len(), 1, "{:?}", t.unreadable);
        assert!(
            t.unreadable[0].2.contains("past the end"),
            "{:?}",
            t.unreadable
        );
    }

    /// A column that claims bytes outside its row, or a bitmap outside it, is not a table this reads.
    #[test]
    fn a_column_outside_its_row_is_refused() {
        let rows = vec![row(7, 1, hid(5), 1, 0b1111_0000)];
        let mut cols = COLS;
        cols[1].2 = 17;
        let e = table(&cols, &rows, 1, 18, 17, &[b"A\0\0\0".to_vec()]).unwrap_err();
        assert!(e.to_string().contains("outside"), "{e}");
    }

    /// A signature other than a table context's is refused by name.
    #[test]
    fn a_property_context_is_not_a_table_context() {
        let mut hn = heap(&[vec![0x7C, 0], vec![]]);
        hn.client_sig = CLIENT_PC;
        let none = |_: &Subnode| Err(invalid("no subnodes"));
        let no_blocks = |_: &Subnode| Err(invalid("no subnodes"));
        let e = read_tc_with(hn, &none, &no_blocks, 8176).unwrap_err();
        assert!(e.to_string().contains("table context"), "{e}");
    }
}
