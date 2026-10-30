//! Turning the Logical Volume Descriptor's partition maps into a
//! [`Partitions`] that translates every address: reading the sparing tables,
//! finding and decoding the Virtual Allocation Table, and reading the
//! metadata file's extents.

use crate::descriptors::{LongAd, PartitionMap, Volume};
use crate::partition::{self, MetaExtent, Partition, Partitions};
use crate::tag::{self, ident};
use crate::walk::Walker;
use seance_core::data_source::DataSource;
use seance_core::io::read_exact_or_fail;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

pub const SPARABLE: &str = "*UDF Sparable Partition";
pub const VIRTUAL: &str = "*UDF Virtual Partition";
pub const METADATA: &str = "*UDF Metadata Partition";

/// The largest VAT read whole (2^24 entries).
const MAX_VAT_BYTES: u64 = 64 * 1024 * 1024;
/// How far back from the end of the evidence trailing zeros are skipped when
/// looking for the last recorded block (an image padded past its VAT).
const MAX_TRAILING_ZERO_BYTES: u64 = 64 * 1024 * 1024;
/// Recorded blocks, counting back from the last one, tried as the VAT's ICB.
const VAT_SEARCH_BLOCKS: u64 = 16;
/// Earlier VATs followed through the previous-VAT pointers.
const MAX_EARLIER_VATS: usize = 64;
/// The largest sparing table read (65,535 entries).
const MAX_SPARING_TABLE_BYTES: usize = 56 + 8 * 65_535;

/// Why a partition map was not resolved.
#[derive(Debug)]
pub enum MapError {
    /// A map of a kind this reader does not read, by its name.
    Unsupported(String),
    /// A kind it reads whose structures could not be (no VAT found, no
    /// sparing table verified, neither metadata file readable, ...).
    Unresolved(String),
}

impl From<String> for MapError {
    fn from(s: String) -> Self {
        MapError::Unresolved(s)
    }
}

/// Resolve every partition map. What each map needed (the sparing table
/// believed, where the VAT was found, which metadata file copy was read) is
/// written into `vol`. The first map that cannot be resolved is the error,
/// by name.
pub fn resolve(
    ds: &Arc<dyn DataSource>,
    volume: &Volume,
    block_size: u64,
    vol: &mut Value,
) -> Result<Partitions, MapError> {
    let pd = |n: u16| {
        volume
            .partitions
            .iter()
            .find(|p| p.number == n)
            .ok_or_else(|| format!("no_partition_descriptor_for_{n}"))
    };
    // Pass 1: the maps that sit directly on a Partition Descriptor.
    let mut parts: Vec<Partition> = Vec::with_capacity(volume.maps.len());
    let mut numbers: Vec<Option<u16>> = Vec::with_capacity(volume.maps.len());
    let mut deferred: Vec<(usize, &str, &[u8])> = Vec::new();
    for (i, m) in volume.maps.iter().enumerate() {
        match m {
            PartitionMap::Type1 { partition_number } => {
                let p = pd(*partition_number)?;
                parts.push(Partition::Physical {
                    start: p.start,
                    length: p.length,
                });
                numbers.push(Some(*partition_number));
            }
            PartitionMap::Type2 { identifier, raw } if identifier == SPARABLE => {
                let map = partition::parse_sparable(raw)
                    .ok_or_else(|| format!("{SPARABLE} map truncated"))?;
                let p = pd(map.partition_number)?;
                if map.packet == 0 {
                    return Err(format!("{SPARABLE} packet length 0").into());
                }
                let remap = read_sparing(ds.as_ref(), &map, block_size, vol)?;
                parts.push(Partition::Sparable {
                    start: p.start,
                    length: p.length,
                    packet: map.packet as u32,
                    remap,
                });
                numbers.push(Some(map.partition_number));
            }
            PartitionMap::Type2 { identifier, raw }
                if identifier == VIRTUAL || identifier == METADATA =>
            {
                // Placeholder until pass 2 can read through pass 1's maps.
                parts.push(Partition::Physical {
                    start: 0,
                    length: 0,
                });
                numbers.push(None);
                deferred.push((i, identifier.as_str(), raw.as_slice()));
            }
            PartitionMap::Type2 { identifier, .. } => {
                return Err(MapError::Unsupported(identifier.clone()))
            }
            PartitionMap::Unknown { map_type } => {
                return Err(MapError::Unsupported(format!(
                    "partition map type {map_type}"
                )))
            }
        }
    }
    if parts.is_empty() {
        return Err(MapError::Unresolved("no partition maps".into()));
    }

    // Pass 2: the maps that are read through another map.
    for (i, identifier, raw) in deferred {
        let number = partition::type2_partition_number(raw)
            .ok_or_else(|| format!("{identifier} map truncated"))?;
        let under = numbers
            .iter()
            .position(|n| *n == Some(number))
            .ok_or_else(|| format!("{identifier}: no map for partition {number}"))?
            as u16;
        let base = Partitions::new(parts.clone(), block_size);
        let resolved = if identifier == VIRTUAL {
            virtual_partition(ds, &base, under, vol)?
        } else {
            let map = partition::parse_metadata(raw)
                .ok_or_else(|| format!("{METADATA} map truncated"))?;
            metadata_partition(ds, &base, under, &map, vol)?
        };
        parts[i] = resolved;
    }

    vol["partition_map_kinds"] = json!(parts.iter().map(Partition::kind).collect::<Vec<_>>());
    Ok(Partitions::new(parts, block_size))
}

/// Read the sparing tables and believe the verified one with the highest
/// sequence number. None verifying is a refusal: a relocated packet would
/// otherwise be read from where it no longer is.
fn read_sparing(
    ds: &dyn DataSource,
    map: &partition::SparableMap,
    block_size: u64,
    vol: &mut Value,
) -> Result<BTreeMap<u32, u32>, String> {
    let mut best: Option<partition::SparingTable> = None;
    let mut why = Vec::new();
    let mut verified = 0u32;
    for &loc in &map.tables {
        let mut head = vec![0u8; block_size as usize];
        if read_exact_or_fail(ds, loc as u64 * block_size, &mut head, "UDF sparing table").is_err()
        {
            why.push(format!("{loc}:unreadable"));
            continue;
        }
        // The table's own entry count sizes it, not the map's table-size
        // field: one writer records the whole sparing area there.
        let count = u16::from_le_bytes([head[48], head[49]]) as usize;
        let len = (56 + 8 * count).min(MAX_SPARING_TABLE_BYTES);
        let mut b = vec![0u8; len.max(block_size as usize)];
        if read_exact_or_fail(ds, loc as u64 * block_size, &mut b, "UDF sparing table").is_err() {
            why.push(format!("{loc}:unreadable"));
            continue;
        }
        match tag::verify(&b, Some(0), Some(loc)) {
            Ok(_) => {}
            Err(e) => {
                why.push(format!("{loc}:{}", e.as_str()));
                continue;
            }
        }
        let Some(t) = partition::parse_sparing_table(&b) else {
            why.push(format!("{loc}:not_a_sparing_table"));
            continue;
        };
        verified += 1;
        if best.as_ref().is_none_or(|b| t.sequence > b.sequence) {
            best = Some(t);
        }
    }
    let Some(t) = best else {
        return Err(format!("sparing_table_unreadable ({})", why.join(", ")));
    };
    vol["sparing_packet_length"] = json!(map.packet);
    vol["sparing_tables_recorded"] = json!(map.tables.len());
    vol["sparing_tables_verified"] = json!(verified);
    vol["sparing_table_sequence"] = json!(t.sequence);
    vol["sparing_relocated_packets"] = json!(t.entries.len());
    if !why.is_empty() {
        vol["sparing_tables_not_believed"] = json!(why);
    }
    Ok(t.entries.into_iter().collect())
}

fn walker<'a>(ds: &'a Arc<dyn DataSource>, parts: &'a Partitions) -> Walker<'a> {
    Walker::new(ds, parts.block_size, parts, Uuid::nil(), Uuid::nil())
}

/// The last block of the evidence that is not all zeros, looking back at
/// most [`MAX_TRAILING_ZERO_BYTES`].
fn last_recorded_block(ds: &dyn DataSource, block_size: u64) -> Option<u64> {
    let blocks = ds.size() / block_size;
    let chunk_blocks = (1u64 << 20) / block_size;
    let floor = blocks.saturating_sub(MAX_TRAILING_ZERO_BYTES / block_size);
    let mut end = blocks;
    while end > floor {
        let start = end.saturating_sub(chunk_blocks).max(floor);
        let mut buf = vec![0u8; ((end - start) * block_size) as usize];
        read_exact_or_fail(ds, start * block_size, &mut buf, "UDF VAT search").ok()?;
        if let Some(i) = buf.iter().rposition(|&b| b != 0) {
            return Some(start + i as u64 / block_size);
        }
        end = start;
    }
    None
}

/// Find the Virtual Allocation Table and build the virtual partition. The
/// VAT is the File Entry in the last recorded block (UDF 2.2.8): the newest
/// one describes the volume as last written, which on a multisession disc is
/// the last session. Earlier VATs, reachable through the previous-VAT
/// pointers, are the volume's earlier states; they are located and counted,
/// not walked.
fn virtual_partition(
    ds: &Arc<dyn DataSource>,
    base: &Partitions,
    under: u16,
    vol: &mut Value,
) -> Result<Partition, String> {
    let bs = base.block_size;
    let (start, length) = match base.get(under) {
        Some(Partition::Physical { start, length } | Partition::Sparable { start, length, .. }) => {
            (*start as u64, *length as u64)
        }
        _ => return Err(format!("{VIRTUAL}: underlying map is not physical")),
    };
    let last = last_recorded_block(ds.as_ref(), bs)
        .ok_or_else(|| format!("{VIRTUAL}: no recorded block found at the end of the evidence"))?;
    let w = walker(ds, base);
    let mut why = Vec::new();
    let mut found = None;
    for abs in (last.saturating_sub(VAT_SEARCH_BLOCKS - 1)..=last).rev() {
        if abs < start || abs - start >= length {
            continue;
        }
        let lbn = (abs - start) as u32;
        match read_vat(&w, under, lbn, bs) {
            Ok(v) => {
                found = Some((abs, lbn, v));
                break;
            }
            Err(e) => why.push(format!("{abs}:{e}")),
        }
    }
    let Some((abs, lbn, vat)) = found else {
        if why.is_empty() {
            why.push(format!(
                "last recorded block {last} is outside the partition"
            ));
        }
        return Err(format!(
            "virtual_allocation_table_not_found ({})",
            why.into_iter().take(4).collect::<Vec<_>>().join(", ")
        ));
    };
    vol["vat_block"] = json!(abs);
    vol["vat_icb_lbn"] = json!(lbn);
    vol["vat_form"] = json!(vat.form);
    vol["vat_entries"] = json!(vat.table.len());
    if let Some(n) = vat.number_of_files {
        vol["vat_number_of_files"] = json!(n);
    }
    if let Some(n) = vat.number_of_directories {
        vol["vat_number_of_directories"] = json!(n);
    }
    if last + 1 < ds.size() / bs {
        vol["vat_found_before_trailing_zeros"] = json!(true);
    }
    // On write-once media the partition spans the whole disc, and nothing
    // after the VAT has been written: the evidence ending there is not a
    // truncated acquisition, and the volume must not say it is.
    if let Some(m) = vol.as_object_mut() {
        if m.remove("partition_extends_past_evidence").is_some() {
            m.insert("partition_unrecorded_after_vat".into(), json!(true));
        }
    }
    // The earlier states of the volume.
    let mut earlier = Vec::new();
    let mut prev = vat.previous;
    let mut stop = None;
    while let Some(p) = prev {
        if earlier.len() >= MAX_EARLIER_VATS {
            stop = Some("earlier_vat_budget_exhausted".to_string());
            break;
        }
        if p == lbn || earlier.contains(&p) {
            stop = Some("earlier_vat_chain_loops".to_string());
            break;
        }
        match read_vat(&w, under, p, bs) {
            Ok(v) => {
                earlier.push(p);
                prev = v.previous;
            }
            Err(e) => {
                stop = Some(format!("earlier_vat_at_{p}_unreadable:{e}"));
                break;
            }
        }
    }
    if !earlier.is_empty() || stop.is_some() {
        vol["vat_earlier_icb_lbns"] = json!(earlier);
        vol["vat_earlier_states_not_walked"] = json!(true);
    }
    if let Some(s) = stop {
        vol["vat_earlier_chain_stopped"] = json!(s);
    }
    Ok(Partition::Virtual {
        under,
        table: vat.table,
    })
}

fn read_vat(w: &Walker, under: u16, lbn: u32, bs: u64) -> Result<partition::Vat, &'static str> {
    let icb = w.read_icb(LongAd {
        length: bs as u32,
        ext_type: 0,
        lbn,
        part_ref: under,
    })?;
    if let Some((why, _)) = icb.content_problem {
        return Err(why);
    }
    // Cheap rejection before reading: a 1.50 VAT is file type 0 (unspecified).
    if icb.file_type != 248 && icb.file_type != 0 {
        return Err("not_a_virtual_allocation_table");
    }
    let bytes = w.file_bytes(&icb, MAX_VAT_BYTES)?;
    partition::parse_vat(&bytes, icb.file_type)
}

/// Read the metadata file (its mirror if the main copy fails) into the
/// metadata partition's extents.
fn metadata_partition(
    ds: &Arc<dyn DataSource>,
    base: &Partitions,
    under: u16,
    map: &partition::MetadataMap,
    vol: &mut Value,
) -> Result<Partition, String> {
    let bs = base.block_size;
    let w = walker(ds, base);
    let read = |lbn: u32, want: u8| -> Result<Partition, &'static str> {
        let icb = w.read_icb(LongAd {
            length: bs as u32,
            ext_type: 0,
            lbn,
            part_ref: under,
        })?;
        if icb.file_type != want {
            return Err("unexpected_metadata_file_type");
        }
        if let Some((why, _)) = icb.content_problem {
            return Err(why);
        }
        let mut extents = Vec::new();
        let mut first = 0u32;
        for (off, len) in Walker::content_runs(&icb) {
            let count = len.div_ceil(bs) as u32;
            extents.push(MetaExtent {
                first,
                count,
                at: off.map(|o| o / bs),
            });
            first = first.checked_add(count).ok_or("metadata_file_too_large")?;
        }
        Ok(Partition::Metadata {
            extents,
            blocks: first,
        })
    };
    vol["metadata_duplicate_flag"] = json!(map.duplicate);
    match read(map.file, 250) {
        Ok(p) => {
            vol["metadata_file_read"] = json!("main");
            Ok(p)
        }
        Err(main) => {
            vol["metadata_main_file_error"] = json!(main);
            match read(map.mirror, 251) {
                Ok(p) => {
                    vol["metadata_file_read"] = json!("mirror");
                    Ok(p)
                }
                Err(mirror) => Err(format!(
                    "metadata_file_unreadable (main: {main}; mirror: {mirror})"
                )),
            }
        }
    }
}

/// Read the File Set Descriptor the Logical Volume Descriptor names.
pub fn read_file_set(
    ds: &dyn DataSource,
    parts: &Partitions,
    fsd: LongAd,
) -> Result<crate::descriptors::FileSet, String> {
    let abs = parts.translate(fsd.part_ref, fsd.lbn).map_err(|e| {
        if e == "block_outside_partition" {
            "file_set_descriptor_outside_partition".to_string()
        } else if e == "partition_reference_invalid" {
            "file_set_descriptor_partition_reference_invalid".to_string()
        } else {
            format!("file_set_descriptor:{e}")
        }
    })?;
    let mut buf = vec![0u8; parts.block_size as usize];
    read_exact_or_fail(
        ds,
        abs * parts.block_size,
        &mut buf,
        "UDF file set descriptor",
    )
    .map_err(|_| "file_set_descriptor_unreadable".to_string())?;
    tag::verify(&buf, Some(ident::FSD), Some(fsd.lbn))
        .map_err(|e| format!("file_set_descriptor:{}", e.as_str()))?;
    Ok(crate::descriptors::FileSet {
        root: LongAd::parse(&buf[400..416]).ok_or("fsd_truncated")?,
        file_set_identifier: crate::cs0::decode_dstring(&buf[304..336]).unwrap_or_default(),
        logical_volume_identifier: crate::cs0::decode_dstring(&buf[112..240]).unwrap_or_default(),
    })
}
