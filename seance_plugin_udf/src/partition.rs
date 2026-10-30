//! Partition references resolved to places on the volume.
//!
//! A UDF address is a (partition reference, logical block) pair. The
//! reference indexes the Logical Volume Descriptor's partition maps, and each
//! kind of map translates its blocks differently:
//!
//! * **physical** (Type 1): partition start plus the block;
//! * **sparable** (`*UDF Sparable Partition`, rewritable media, UDF 2.2.9):
//!   as physical, except a packet the sparing table has relocated is read at
//!   the sector the table names;
//! * **virtual** (`*UDF Virtual Partition`, write-once media, UDF 2.2.8): the
//!   block indexes the Virtual Allocation Table, whose entry is a block of
//!   the underlying partition;
//! * **metadata** (`*UDF Metadata Partition`, UDF 2.50+, UDF 2.2.10): the
//!   block indexes the content of the metadata file, an Extended File Entry
//!   in the underlying partition (its mirror when the main copy is
//!   unreadable).
//!
//! Every translation ends in an absolute block of the volume.

use std::cell::Cell;
use std::collections::BTreeMap;

/// A run of absolute bytes, or of blocks that are not recorded anywhere.
pub type ByteRun = (Option<u64>, u64);

/// Budget of blocks translated one by one through virtual partitions, over
/// the whole volume: a crafted image cannot make every extent walk a large
/// table.
const MAX_TRANSLATED_BLOCKS: u64 = 1 << 26;

/// How deep one partition may sit on another.
const MAX_NESTING: usize = 4;

/// VAT entry meaning "this virtual block is not mapped" (UDF 2.2.8).
pub const VAT_UNUSED: u32 = 0xFFFF_FFFF;

/// One extent of the metadata file: `count` metadata-partition blocks from
/// `first`, recorded at absolute block `at` (or not recorded).
#[derive(Debug, Clone, Copy)]
pub struct MetaExtent {
    pub first: u32,
    pub count: u32,
    pub at: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum Partition {
    Physical {
        start: u32,
        length: u32,
    },
    Sparable {
        start: u32,
        length: u32,
        packet: u32,
        /// Packet start (partition block) -> absolute sector it was moved to.
        remap: BTreeMap<u32, u32>,
    },
    Virtual {
        /// The partition reference the VAT entries are blocks of.
        under: u16,
        table: Vec<u32>,
    },
    Metadata {
        extents: Vec<MetaExtent>,
        blocks: u32,
    },
}

impl Partition {
    pub fn kind(&self) -> &'static str {
        match self {
            Partition::Physical { .. } => "physical",
            Partition::Sparable { .. } => "sparable",
            Partition::Virtual { .. } => "virtual",
            Partition::Metadata { .. } => "metadata",
        }
    }

    /// Length in blocks.
    pub fn length(&self) -> u32 {
        match self {
            Partition::Physical { length, .. } | Partition::Sparable { length, .. } => *length,
            Partition::Virtual { table, .. } => table.len() as u32,
            Partition::Metadata { blocks, .. } => *blocks,
        }
    }
}

/// The resolved partition maps, indexed by partition reference.
#[derive(Debug)]
pub struct Partitions {
    pub parts: Vec<Partition>,
    pub block_size: u64,
    translated: Cell<u64>,
}

impl Partitions {
    pub fn new(parts: Vec<Partition>, block_size: u64) -> Self {
        Self {
            parts,
            block_size,
            translated: Cell::new(0),
        }
    }

    pub fn get(&self, part_ref: u16) -> Option<&Partition> {
        self.parts.get(part_ref as usize)
    }

    /// The absolute block that partition block `lbn` is recorded at.
    pub fn translate(&self, part_ref: u16, lbn: u32) -> Result<u64, &'static str> {
        self.translate_depth(part_ref, lbn, 0)
    }

    fn translate_depth(&self, part_ref: u16, lbn: u32, depth: usize) -> Result<u64, &'static str> {
        if depth > MAX_NESTING {
            return Err("partition_nesting_too_deep");
        }
        let p = self.get(part_ref).ok_or("partition_reference_invalid")?;
        if lbn >= p.length() {
            return Err("block_outside_partition");
        }
        match p {
            Partition::Physical { start, .. } => Ok(*start as u64 + lbn as u64),
            Partition::Sparable {
                start,
                packet,
                remap,
                ..
            } => {
                let base = lbn - lbn % packet;
                Ok(match remap.get(&base) {
                    Some(&moved) => moved as u64 + (lbn - base) as u64,
                    None => *start as u64 + lbn as u64,
                })
            }
            Partition::Virtual { under, table } => {
                let entry = table[lbn as usize];
                if entry == VAT_UNUSED {
                    return Err("virtual_block_not_mapped");
                }
                self.translate_depth(*under, entry, depth + 1)
            }
            Partition::Metadata { extents, .. } => {
                let e = find_extent(extents, lbn).ok_or("metadata_block_not_mapped")?;
                e.at.map(|at| at + (lbn - e.first) as u64)
                    .ok_or("metadata_block_not_recorded")
            }
        }
    }

    /// The absolute byte runs an extent of `bytes` from partition block
    /// `lbn` occupies, adjacent blocks merged. An extent that leaves its
    /// partition is an error, not a partial answer.
    pub fn map_extent(
        &self,
        part_ref: u16,
        lbn: u32,
        bytes: u64,
    ) -> Result<Vec<ByteRun>, &'static str> {
        let bs = self.block_size;
        let p = self.get(part_ref).ok_or("partition_reference_invalid")?;
        let blocks = bytes.div_ceil(bs);
        if lbn as u64 + blocks > p.length() as u64 {
            return Err("block_outside_partition");
        }
        if let Partition::Physical { start, .. } = p {
            return Ok(vec![(Some((*start as u64 + lbn as u64) * bs), bytes)]);
        }
        let mut runs: Vec<ByteRun> = Vec::new();
        let mut remaining = bytes;
        let mut b = lbn;
        while remaining > 0 {
            // How many blocks from `b` are known to be contiguous without
            // translating each: a sparing packet, a metadata extent.
            let (abs, span) = match p {
                Partition::Sparable { packet, .. } => {
                    (self.translate(part_ref, b)?, packet - b % packet)
                }
                Partition::Metadata { extents, .. } => {
                    let e = find_extent(extents, b).ok_or("metadata_block_not_mapped")?;
                    let span = e.first + e.count - b;
                    match e.at {
                        Some(at) => (at + (b - e.first) as u64, span),
                        None => {
                            let len = remaining.min(span as u64 * bs);
                            push_run(&mut runs, None, len);
                            remaining -= len;
                            b += span;
                            continue;
                        }
                    }
                }
                _ => {
                    let n = self.translated.get() + 1;
                    if n > MAX_TRANSLATED_BLOCKS {
                        return Err("translation_budget_exhausted");
                    }
                    self.translated.set(n);
                    (self.translate(part_ref, b)?, 1)
                }
            };
            let len = remaining.min(span as u64 * bs);
            push_run(&mut runs, Some(abs * bs), len);
            remaining -= len;
            b += span;
        }
        Ok(runs)
    }
}

fn find_extent(extents: &[MetaExtent], lbn: u32) -> Option<&MetaExtent> {
    let i = extents.partition_point(|e| e.first <= lbn).checked_sub(1)?;
    let e = &extents[i];
    (lbn - e.first < e.count).then_some(e)
}

fn push_run(runs: &mut Vec<ByteRun>, off: Option<u64>, len: u64) {
    if let Some(last) = runs.last_mut() {
        match (last.0, off) {
            (Some(a), Some(b)) if a + last.1 == b => {
                last.1 += len;
                return;
            }
            (None, None) => {
                last.1 += len;
                return;
            }
            _ => {}
        }
    }
    runs.push((off, len));
}

/// A sparable map's fields (UDF 2.2.9).
#[derive(Debug, Clone)]
pub struct SparableMap {
    pub partition_number: u16,
    pub packet: u16,
    pub table_size: u32,
    pub tables: Vec<u32>,
}

/// A metadata map's fields (UDF 2.2.10).
#[derive(Debug, Clone, Copy)]
pub struct MetadataMap {
    pub partition_number: u16,
    pub file: u32,
    pub mirror: u32,
    pub duplicate: bool,
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// The partition number every Type 2 map carries at byte 38.
pub fn type2_partition_number(raw: &[u8]) -> Option<u16> {
    (raw.len() >= 40).then(|| u16_at(raw, 38))
}

pub fn parse_sparable(raw: &[u8]) -> Option<SparableMap> {
    if raw.len() < 48 {
        return None;
    }
    let n = raw[42].min(4) as usize;
    let tables = (0..n)
        .filter_map(|i| raw.get(48 + 4 * i..52 + 4 * i).map(|b| u32_at(b, 0)))
        .collect();
    Some(SparableMap {
        partition_number: u16_at(raw, 38),
        packet: u16_at(raw, 40),
        table_size: u32_at(raw, 44),
        tables,
    })
}

pub fn parse_metadata(raw: &[u8]) -> Option<MetadataMap> {
    if raw.len() < 59 {
        return None;
    }
    Some(MetadataMap {
        partition_number: u16_at(raw, 38),
        file: u32_at(raw, 40),
        mirror: u32_at(raw, 44),
        duplicate: raw[58] & 1 != 0,
    })
}

/// A sparing table (UDF 2.2.12) that passed its tag checks.
#[derive(Debug, Clone)]
pub struct SparingTable {
    pub sequence: u32,
    /// (original packet start, absolute sector) for relocated packets only.
    pub entries: Vec<(u32, u32)>,
}

/// Parse a sparing table's body (the tag has already been verified).
pub fn parse_sparing_table(b: &[u8]) -> Option<SparingTable> {
    if b.len() < 56 || crate::descriptors::regid_identifier(&b[16..48]) != "*UDF Sparing Table" {
        return None;
    }
    let count = u16_at(b, 48) as usize;
    let entries = (0..count)
        .filter_map(|i| b.get(56 + 8 * i..64 + 8 * i))
        .map(|e| (u32_at(e, 0), u32_at(e, 4)))
        // 0xFFFFFFFF is an available spare, 0xFFFFFFF0 a defective one:
        // neither relocates anything.
        .filter(|&(orig, _)| orig < 0xFFFF_FFF0)
        .collect();
    Some(SparingTable {
        sequence: u32_at(b, 52),
        entries,
    })
}

/// A Virtual Allocation Table's content (UDF 2.2.11 for 2.00+, 2.2.10 of
/// UDF 1.50 for the older trailer form).
#[derive(Debug, Clone)]
pub struct Vat {
    pub table: Vec<u32>,
    /// The earlier VAT's ICB, a block of the underlying partition: the
    /// volume as it stood before the last write (an earlier session).
    pub previous: Option<u32>,
    pub number_of_files: Option<u32>,
    pub number_of_directories: Option<u32>,
    /// "2.00+" for the header form (file type 248), "1.50" for the trailer.
    pub form: &'static str,
}

/// The entity identifier that ends a UDF 1.50 VAT.
const VAT_150_REGID: &str = "*UDF Virtual Alloc Tbl";

/// Decode a VAT from the content of its File Entry. `file_type` 248 is the
/// UDF 2.00+ form; any other type is tried as the 1.50 form, which is
/// recognised only by its trailing entity identifier.
pub fn parse_vat(content: &[u8], file_type: u8) -> Result<Vat, &'static str> {
    let prev = |v: u32| (v != VAT_UNUSED).then_some(v);
    if file_type == 248 {
        if content.len() < 152 {
            return Err("vat_header_truncated");
        }
        let header = (u16_at(content, 0) as usize).max(152);
        let body = content.get(header..).ok_or("vat_header_truncated")?;
        Ok(Vat {
            table: body
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_le_bytes(*c))
                .collect(),
            previous: prev(u32_at(content, 132)),
            number_of_files: Some(u32_at(content, 136)),
            number_of_directories: Some(u32_at(content, 140)),
            form: "2.00+",
        })
    } else {
        let n = content.len();
        if n < 36 || crate::descriptors::regid_identifier(&content[n - 36..n - 4]) != VAT_150_REGID
        {
            return Err("not_a_virtual_allocation_table");
        }
        Ok(Vat {
            table: content[..n - 36]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_le_bytes(*c))
                .collect(),
            previous: prev(u32_at(content, n - 4)),
            number_of_files: None,
            number_of_directories: None,
            form: "1.50",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparable_packet_relocation_moves_the_whole_packet_only() {
        let p = Partitions::new(
            vec![Partition::Sparable {
                start: 100,
                length: 64,
                packet: 16,
                remap: BTreeMap::from([(16, 5000)]),
            }],
            2048,
        );
        assert_eq!(p.translate(0, 3), Ok(103));
        assert_eq!(p.translate(0, 16), Ok(5000));
        assert_eq!(p.translate(0, 31), Ok(5015));
        assert_eq!(p.translate(0, 32), Ok(132));
        // An extent across the relocated packet is split in three.
        let runs = p.map_extent(0, 14, 20 * 2048).unwrap();
        assert_eq!(
            runs,
            vec![
                (Some(114 * 2048), 2 * 2048),
                (Some(5000 * 2048), 16 * 2048),
                (Some(132 * 2048), 2 * 2048)
            ]
        );
    }

    #[test]
    fn virtual_blocks_go_through_the_vat_to_the_physical_partition() {
        let p = Partitions::new(
            vec![
                Partition::Physical {
                    start: 10,
                    length: 100,
                },
                Partition::Virtual {
                    under: 0,
                    table: vec![7, 8, VAT_UNUSED, 50],
                },
            ],
            2048,
        );
        assert_eq!(p.translate(1, 0), Ok(17));
        assert_eq!(p.translate(1, 2), Err("virtual_block_not_mapped"));
        assert_eq!(p.translate(1, 4), Err("block_outside_partition"));
        assert_eq!(
            p.map_extent(1, 0, 2 * 2048).unwrap(),
            vec![(Some(17 * 2048), 2 * 2048)]
        );
    }

    #[test]
    fn metadata_blocks_follow_the_metadata_file_extents() {
        let p = Partitions::new(
            vec![Partition::Metadata {
                extents: vec![
                    MetaExtent {
                        first: 0,
                        count: 4,
                        at: Some(200),
                    },
                    MetaExtent {
                        first: 4,
                        count: 4,
                        at: Some(900),
                    },
                ],
                blocks: 8,
            }],
            512,
        );
        assert_eq!(p.translate(0, 5), Ok(901));
        assert_eq!(
            p.map_extent(0, 2, 4 * 512).unwrap(),
            vec![(Some(202 * 512), 2 * 512), (Some(900 * 512), 2 * 512)]
        );
        assert_eq!(p.translate(0, 8), Err("block_outside_partition"));
    }

    #[test]
    fn vat_150_is_recognised_by_its_trailing_identifier_only() {
        let mut v = Vec::new();
        for e in [3u32, 4, VAT_UNUSED] {
            v.extend_from_slice(&e.to_le_bytes());
        }
        let mut regid = [0u8; 32];
        regid[1..1 + VAT_150_REGID.len()].copy_from_slice(VAT_150_REGID.as_bytes());
        v.extend_from_slice(&regid);
        v.extend_from_slice(&77u32.to_le_bytes());
        let vat = parse_vat(&v, 0).unwrap();
        assert_eq!(vat.table, vec![3, 4, VAT_UNUSED]);
        assert_eq!(vat.previous, Some(77));
        assert_eq!(vat.form, "1.50");
        v[20] ^= 1;
        assert_eq!(
            parse_vat(&v, 0).unwrap_err(),
            "not_a_virtual_allocation_table"
        );
    }
}
