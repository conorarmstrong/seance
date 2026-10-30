//! The volume-structure layer (ECMA-167 part 3): the Anchor Volume Descriptor
//! Pointer, the Volume Descriptor Sequence it points at, the partition maps,
//! and the File Set Descriptor that names the root directory.

use crate::cs0;
use crate::tag::{self, ident, TagError};
use crate::timestamp;
use seance_core::data_source::DataSource;
use seance_core::io::read_exact_or_fail;

/// The sector size tried first, and the one the anchor-search error names.
pub const SECTOR: u64 = 2048;

/// Every sector size the anchor is looked for at (ECMA-167 3/8.4.2.1 puts
/// it at sector 256 of whatever size the medium has): 2048 first, because
/// optical media and nearly every image use it.
pub const SECTOR_SIZES: [u64; 4] = [2048, 512, 1024, 4096];

/// The largest single descriptor the Volume Descriptor Sequence is read in
/// (a Logical Volume Descriptor with many maps may span sectors on media
/// with 512-byte sectors).
const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024;

/// Bounds on a crafted image's descriptor sequences.
const MAX_VDS_DESCRIPTORS: u32 = 256;
const MAX_VDS_POINTERS: u32 = 8;

/// An `extent_ad` (ECMA-167 3/7.1): a length in bytes and a start sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentAd {
    pub length: u32,
    pub location: u32,
}

impl ExtentAd {
    fn parse(b: &[u8]) -> Self {
        Self {
            length: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            location: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
}

/// A `long_ad` (ECMA-167 4/14.14.2): an extent in a given partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongAd {
    /// Extent length in bytes (the low 30 bits).
    pub length: u32,
    /// Extent type (the top 2 bits): 0 recorded, 1 allocated not recorded,
    /// 2 not allocated, 3 the next extent of allocation descriptors.
    pub ext_type: u8,
    pub lbn: u32,
    pub part_ref: u16,
}

impl LongAd {
    pub fn parse(b: &[u8]) -> Option<Self> {
        let b = b.get(..16)?;
        let raw = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        Some(Self {
            length: raw & 0x3FFF_FFFF,
            ext_type: (raw >> 30) as u8,
            lbn: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            part_ref: u16::from_le_bytes([b[8], b[9]]),
        })
    }
}

/// The anchor that was believed.
#[derive(Debug, Clone, Copy)]
pub struct Anchor {
    /// The sector size the anchor was found at.
    pub sector_size: u64,
    pub sector: u64,
    pub main: ExtentAd,
    pub reserve: ExtentAd,
}

/// A partition map from the Logical Volume Descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionMap {
    /// Type 1: a physical partition, by partition number.
    Type1 { partition_number: u16 },
    /// Type 2, named by its entity identifier (`*UDF Virtual Partition`,
    /// `*UDF Sparable Partition`, `*UDF Metadata Partition`), with the map's
    /// bytes for the fields each kind carries.
    Type2 { identifier: String, raw: Vec<u8> },
    /// A map type ECMA-167 does not define.
    Unknown { map_type: u8 },
}

/// A Partition Descriptor's placement.
#[derive(Debug, Clone)]
pub struct PartitionDesc {
    pub number: u16,
    pub contents: String,
    pub start: u32,
    pub length: u32,
    vds_number: u32,
}

/// What the Volume Descriptor Sequence said.
#[derive(Debug, Clone)]
pub struct Volume {
    pub volume_identifier: Option<String>,
    pub volume_set_identifier: Option<String>,
    pub recorded: Option<String>,
    pub logical_volume_identifier: String,
    pub block_size: u32,
    pub domain_identifier: String,
    /// The UDF revision from the domain identifier suffix (e.g. 0x0102).
    pub udf_revision: Option<u16>,
    pub fsd: LongAd,
    pub maps: Vec<PartitionMap>,
    pub partitions: Vec<PartitionDesc>,
}

/// The File Set Descriptor's content.
#[derive(Debug, Clone)]
pub struct FileSet {
    pub root: LongAd,
    pub file_set_identifier: String,
    pub logical_volume_identifier: String,
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Read one sector of `size` bytes.
fn read_sector(ds: &dyn DataSource, sector: u64, size: u64) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; size as usize];
    read_exact_or_fail(ds, sector * size, &mut buf, "UDF descriptor")
        .map_err(|_| format!("sector_{sector}_unreadable"))?;
    Ok(buf)
}

/// The descriptor at `sector`, read whole: when its tag says it is longer
/// than one sector, the sectors after it are read too (bounded). Returns the
/// bytes and how many sectors the descriptor occupies.
fn read_descriptor(ds: &dyn DataSource, sector: u64, size: u64) -> Result<(Vec<u8>, u64), String> {
    let mut buf = read_sector(ds, sector, size)?;
    let crc_len = u16_at(&buf, 10) as usize;
    let need = tag::TAG_LEN + crc_len;
    if need > buf.len() && need <= MAX_DESCRIPTOR_BYTES {
        let sectors = (need as u64).div_ceil(size);
        let mut whole = vec![0u8; (sectors * size) as usize];
        if read_exact_or_fail(ds, sector * size, &mut whole, "UDF descriptor").is_ok() {
            buf = whole;
        }
    }
    let span = (buf.len() as u64 / size).max(1);
    Ok((buf, span))
}

/// The identifier part of a `regid` (23 bytes after the flags byte),
/// trailing NULs dropped.
pub fn regid_identifier(r: &[u8]) -> String {
    let id = r.get(1..24).unwrap_or(&[]);
    let end = id.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
    String::from_utf8_lossy(&id[..end]).into_owned()
}

/// Find the Anchor Volume Descriptor Pointer: sector 256, then the last
/// sector (N-1), then N-257 (ECMA-167 3/8.4.2.1), at 2048-byte sectors and
/// then at 512, 1024 and 4096. On failure the error names what each
/// 2048-byte location held.
pub fn find_anchor(ds: &dyn DataSource) -> Result<Anchor, String> {
    let mut first_error = None;
    for size in SECTOR_SIZES {
        match find_anchor_at(ds, size) {
            Ok(a) => return Ok(a),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    Err(first_error.unwrap_or_default())
}

/// The anchor search at one sector size.
fn find_anchor_at(ds: &dyn DataSource, size: u64) -> Result<Anchor, String> {
    let n = ds.size() / size;
    let mut candidates = vec![256u64];
    if n > 0 {
        candidates.push(n - 1);
    }
    if n > 257 {
        candidates.push(n - 257);
    }
    candidates.dedup();
    let mut why = Vec::new();
    for s in candidates {
        let buf = match read_sector(ds, s, size) {
            Ok(b) => b,
            Err(e) => {
                why.push(format!("{s}:{e}"));
                continue;
            }
        };
        match tag::verify(&buf, Some(ident::AVDP), Some(s as u32)) {
            Ok(_) => {
                return Ok(Anchor {
                    sector_size: size,
                    sector: s,
                    main: ExtentAd::parse(&buf[16..24]),
                    reserve: ExtentAd::parse(&buf[24..32]),
                })
            }
            Err(e) => why.push(format!("{s}:{}", e.as_str())),
        }
    }
    Err(format!(
        "no_anchor_volume_descriptor_pointer ({})",
        why.join(", ")
    ))
}

/// Read one Volume Descriptor Sequence to its Terminating Descriptor,
/// following Volume Descriptor Pointers. A descriptor that fails its tag
/// checks fails the whole sequence, so the caller can fall back to the
/// reserve copy rather than believe half of a damaged one.
pub fn read_vds(ds: &dyn DataSource, extent: ExtentAd, size: u64) -> Result<Volume, String> {
    let mut pvd: Option<(u32, Vec<u8>)> = None;
    let mut lvd: Option<(u32, Vec<u8>)> = None;
    let mut partitions: Vec<PartitionDesc> = Vec::new();

    let mut current = extent;
    let mut pointers = 0u32;
    let mut read = 0u32;
    'sequence: loop {
        let sectors = (current.length as u64).div_ceil(size);
        let mut followed = false;
        let mut i = 0u64;
        while i < sectors {
            read += 1;
            if read > MAX_VDS_DESCRIPTORS {
                return Err("volume_descriptor_sequence_too_long".into());
            }
            let s = current.location as u64 + i;
            let (buf, span) = read_descriptor(ds, s, size)?;
            i += span;
            let t = tag::verify(&buf, None, Some(s as u32))
                .map_err(|e: TagError| format!("sector_{s}:{}", e.as_str()))?;
            let vds_number = u32_at(&buf, 16);
            match t.ident {
                ident::PVD => {
                    if pvd.as_ref().is_none_or(|(n, _)| vds_number >= *n) {
                        pvd = Some((vds_number, buf));
                    }
                }
                ident::LVD => {
                    if lvd.as_ref().is_none_or(|(n, _)| vds_number >= *n) {
                        lvd = Some((vds_number, buf));
                    }
                }
                ident::PD => {
                    let pd = PartitionDesc {
                        number: u16_at(&buf, 22),
                        contents: regid_identifier(&buf[24..56]),
                        start: u32_at(&buf, 188),
                        length: u32_at(&buf, 192),
                        vds_number,
                    };
                    match partitions.iter_mut().find(|p| p.number == pd.number) {
                        Some(p) if p.vds_number <= pd.vds_number => *p = pd,
                        Some(_) => {}
                        None => partitions.push(pd),
                    }
                }
                ident::VDP => {
                    pointers += 1;
                    if pointers > MAX_VDS_POINTERS {
                        return Err("volume_descriptor_pointer_chain_too_long".into());
                    }
                    current = ExtentAd::parse(&buf[20..28]);
                    followed = true;
                    break;
                }
                ident::TD => break 'sequence,
                _ => {}
            }
        }
        if !followed {
            // The extent ended without a Terminating Descriptor; what was
            // read is still the sequence (ECMA-167 3/8.4.2 allows it).
            break;
        }
    }

    let (_, lvd) = lvd.ok_or("no_logical_volume_descriptor")?;
    if partitions.is_empty() {
        return Err("no_partition_descriptor".into());
    }
    let block_size = u32_at(&lvd, 212);
    let domain = &lvd[216..248];
    let map_table_len = u32_at(&lvd, 264) as usize;
    let map_count = u32_at(&lvd, 268);
    let table = lvd
        .get(440..440 + map_table_len.min(lvd.len().saturating_sub(440)))
        .unwrap_or(&[]);
    let mut maps = Vec::new();
    let mut o = 0usize;
    for _ in 0..map_count.min(64) {
        let Some(&[map_type, map_len]) = table.get(o..o + 2) else {
            return Err("partition_map_table_truncated".into());
        };
        let map_len = map_len as usize;
        if map_len < 2 || o + map_len > table.len() {
            return Err("partition_map_table_truncated".into());
        }
        let m = &table[o..o + map_len];
        maps.push(match map_type {
            1 if map_len >= 6 => PartitionMap::Type1 {
                partition_number: u16_at(m, 4),
            },
            2 if map_len >= 36 => PartitionMap::Type2 {
                identifier: regid_identifier(&m[4..36]),
                raw: m.to_vec(),
            },
            t => PartitionMap::Unknown { map_type: t },
        });
        o += map_len;
    }

    let decode = |f: &[u8]| cs0::decode_dstring(f).ok();
    let pvd = pvd.map(|(_, b)| b);
    Ok(Volume {
        volume_identifier: pvd.as_ref().and_then(|b| decode(&b[24..56])),
        volume_set_identifier: pvd.as_ref().and_then(|b| decode(&b[72..200])),
        recorded: pvd
            .as_ref()
            .and_then(|b| timestamp::decode(&b[376..388]))
            .map(|d| d.text),
        logical_volume_identifier: decode(&lvd[84..212]).unwrap_or_default(),
        block_size,
        domain_identifier: regid_identifier(domain),
        udf_revision: Some(u16_at(domain, 24)).filter(|&r| r != 0),
        fsd: LongAd::parse(&lvd[248..264]).ok_or("lvd_truncated")?,
        maps,
        partitions,
    })
}
