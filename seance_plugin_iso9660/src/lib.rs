#![forbid(unsafe_code)]
//! ISO9660 (ECMA-119) optical filesystem parser.
//!
//! Parses an ISO9660 volume presented as a whole-volume `DataSource` and emits one
//! `FileEntry` artifact per file/directory. Regular files carry an attached content
//! `DataSource` reconstructed from their (contiguous) extent.
//!
//! On-disk layout notes (multi-byte integers are stored in BOTH little- and
//! big-endian; we read the little-endian copy):
//! - Logical sector size is 2048. The System Area is the first 16 sectors.
//! - Volume descriptors begin at sector 16; the Primary Volume Descriptor (type 1)
//!   holds the logical block size and the 34-byte root directory record.
//!
//! References:
//! - ECMA-119 / ISO 9660 "Volume and File Structure of CDROM".

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{byte_runs_to_metadata, ByteSliceDataSource, DataSource},
    io::{read_exact_or_fail, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

mod rock_ridge;
use rock_ridge::RockRidgeVolume;

// --- Constants ---

// A logical sector is 2048 bytes; volume descriptors occupy one sector each.
const LOGICAL_SECTOR_SIZE: usize = 2048;
// The System Area occupies the first 16 sectors; descriptors start at sector 16.
const SYSTEM_AREA_SECTORS: u64 = 16;

// Volume descriptor types (byte 0 of each descriptor sector).
const VD_TYPE_PRIMARY: u8 = 1;
/// A Supplementary Volume Descriptor: same layout as the primary, describing a
/// second directory tree. Joliet (Microsoft's long-name extension) is an SVD
/// whose escape sequences name UCS-2 level 1, 2 or 3.
const VD_TYPE_SUPPLEMENTARY: u8 = 2;
const VD_TYPE_TERMINATOR: u8 = 255;
/// Escape-sequences field of a volume descriptor (32 bytes at +88).
const VD_ESCAPE_SEQUENCES_OFFSET: usize = 88;
const VD_ESCAPE_SEQUENCES_LEN: usize = 32;

// Field offsets within the Primary Volume Descriptor.
const PVD_VOLUME_SPACE_SIZE_OFFSET: usize = 80; // both-endian u32
const PVD_LOGICAL_BLOCK_SIZE_OFFSET: usize = 128; // both-endian u16
const PVD_ROOT_RECORD_OFFSET: usize = 156; // embedded 34-byte directory record

// Field offsets within a directory record.
const DR_EXTENT_LBA_OFFSET: usize = 2; // both-endian u32
const DR_DATA_LENGTH_OFFSET: usize = 10; // both-endian u32
const DR_RECORDING_DATETIME_OFFSET: usize = 18; // 7-byte recording date/time
const DR_FILE_FLAGS_OFFSET: usize = 25;
const DR_FILE_ID_LEN_OFFSET: usize = 32;
const DR_FILE_ID_OFFSET: usize = 33;
// The fixed portion of a directory record is 33 bytes; the shortest valid record
// carries a single-byte identifier, so 34 bytes.
const DR_MIN_LEN: usize = 34;
// File flag bit 1: this record describes a directory.
const DR_FLAG_DIRECTORY: u8 = 0x02;
// File flag bit 7 (ECMA-119 9.1.6): this is NOT the final directory record for
// the file — the file continues in the records that follow, each describing one
// more extent. A file larger than 4 GiB (or split by the mastering tool) is
// recorded this way, and treating each record as its own file both splits the
// inventory and truncates every part (BUG-240).
const DR_FLAG_MULTI_EXTENT: u8 = 0x80;

// Safety limits to bound work on corrupt/crafted images.
const MAX_VOLUME_DESCRIPTORS: u64 = 64;
const MAX_CONTENT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DIRECTORY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 200_000;
const MAX_DEPTH: usize = 64;

// --- Little-endian slice helpers (panic-free on short/corrupt input) ---

fn le_u16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn le_u32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

// Structural reads go through `seance_core::io::read_exact_or_fail` (BUG-104): a
// truncated/corrupt extent must surface as an error, never be silently
// zero-filled and served as legitimate directory/file content.

/// Parse a directory record's 7-byte recording date/time (ECMA-119 9.1.5):
///   0 years since 1900 (u8)   1 month   2 day   3 hour   4 minute
///   5 second   6 GMT offset in 15-minute intervals (signed i8)
/// Returns an absolute RFC 3339 timestamp (the stored offset is preserved).
/// Returns `None` for an all-zero / out-of-range "unset" record (BUG-105).
fn parse_recording_datetime(dt: &[u8]) -> Option<String> {
    if dt.len() < 7 {
        return None;
    }
    let year = 1900 + dt[0] as i32;
    let month = dt[1] as u32;
    let day = dt[2] as u32;
    let hour = dt[3] as u32;
    let minute = dt[4] as u32;
    let second = dt[5] as u32;
    let offset_secs = (dt[6] as i8) as i32 * 15 * 60;

    // An unset record (all zeros) has month/day 0; reject rather than fabricate.
    let naive_date = chrono::NaiveDate::from_ymd_opt(year, month, day)?;
    let naive_time = chrono::NaiveTime::from_hms_opt(hour, minute, second)?;
    let naive = chrono::NaiveDateTime::new(naive_date, naive_time);
    let tz = chrono::FixedOffset::east_opt(offset_secs)?;
    let dt = chrono::TimeZone::from_local_datetime(&tz, &naive).single()?;
    Some(dt.to_rfc3339())
}

// --- Data structures ---

/// The Primary Volume Descriptor fields we need to walk the tree.
struct PrimaryVolumeDescriptor {
    logical_block_size: u32,
    volume_space_size: u32,
    root_extent_lba: u32,
    root_data_length: u32,
}

/// The volume descriptors a walk can start from: the Primary Volume
/// Descriptor, and the Joliet Supplementary Volume Descriptor when the disc
/// carries one.
struct VolumeDescriptors {
    primary: Vec<u8>,
    /// The Joliet SVD sector, if any. Its directory tree names the same files
    /// as the primary tree in UCS-2, up to 64 characters, mixed case — the
    /// names a Windows author gave them, where the primary tree holds the
    /// ISO-9660 level-1 rendering (`LONGFI~1.TXT` or `LONG_FIL.TXT`).
    joliet: Option<Vec<u8>>,
}

/// Whether a Supplementary Volume Descriptor's escape sequences declare
/// Joliet: `%/@`, `%/C` or `%/E` (UCS-2 level 1, 2 or 3; ISO 2022 designation
/// of the 16-bit set), per the Joliet specification §4.1.1.
fn is_joliet_svd(vd: &[u8]) -> bool {
    let Some(esc) =
        vd.get(VD_ESCAPE_SEQUENCES_OFFSET..VD_ESCAPE_SEQUENCES_OFFSET + VD_ESCAPE_SEQUENCES_LEN)
    else {
        return false;
    };
    esc.windows(3)
        .any(|w| w == b"%/@" || w == b"%/C" || w == b"%/E")
}

/// Locate the Primary Volume Descriptor and, if present, the Joliet
/// Supplementary Volume Descriptor. The set is read to its terminator: the
/// SVD follows the PVD, and stopping at the first descriptor found is how the
/// Joliet tree was overlooked for as long as it was (`DOC-013`).
fn find_volume_descriptors(ds: &dyn DataSource) -> Result<VolumeDescriptors, ModuleError> {
    let mut primary: Option<Vec<u8>> = None;
    let mut joliet: Option<Vec<u8>> = None;
    for i in 0..MAX_VOLUME_DESCRIPTORS {
        let sector = SYSTEM_AREA_SECTORS + i;
        let offset = sector * LOGICAL_SECTOR_SIZE as u64;
        let mut buf = vec![0u8; LOGICAL_SECTOR_SIZE];
        read_exact_or_fail(ds, offset, &mut buf, "ISO9660 volume descriptor")?;

        // Every volume descriptor carries the "CD001" standard identifier at +1.
        if &buf[1..6] != b"CD001" {
            return Err(ModuleError::ParsingError(format!(
                "missing CD001 identifier at sector {}",
                sector
            )));
        }
        match buf[0] {
            VD_TYPE_PRIMARY => {
                if primary.is_none() {
                    primary = Some(buf);
                }
            }
            VD_TYPE_SUPPLEMENTARY => {
                if joliet.is_none() && is_joliet_svd(&buf) {
                    joliet = Some(buf);
                }
            }
            VD_TYPE_TERMINATOR => break,
            _ => {}
        }
    }
    match primary {
        Some(primary) => Ok(VolumeDescriptors { primary, joliet }),
        None => Err(ModuleError::ParsingError(
            "no Primary Volume Descriptor found".into(),
        )),
    }
}

/// Locate and return the 2048-byte Primary Volume Descriptor sector.
#[cfg(test)]
fn find_primary_volume_descriptor(ds: &dyn DataSource) -> Result<Vec<u8>, ModuleError> {
    find_volume_descriptors(ds).map(|v| v.primary)
}

/// Parse the fields we need from a Primary Volume Descriptor sector.
fn parse_pvd(pvd: &[u8]) -> Result<PrimaryVolumeDescriptor, ModuleError> {
    let logical_block_size = le_u16(pvd, PVD_LOGICAL_BLOCK_SIZE_OFFSET)
        .ok_or_else(|| ModuleError::ParsingError("missing logical block size".into()))?
        as u32;
    if logical_block_size == 0 {
        return Err(ModuleError::ParsingError("zero logical block size".into()));
    }
    let volume_space_size = le_u32(pvd, PVD_VOLUME_SPACE_SIZE_OFFSET).unwrap_or(0);
    // The root directory record is embedded at +156; read its extent and length.
    let root_extent_lba = le_u32(pvd, PVD_ROOT_RECORD_OFFSET + DR_EXTENT_LBA_OFFSET)
        .ok_or_else(|| ModuleError::ParsingError("missing root extent LBA".into()))?;
    let root_data_length = le_u32(pvd, PVD_ROOT_RECORD_OFFSET + DR_DATA_LENGTH_OFFSET)
        .ok_or_else(|| ModuleError::ParsingError("missing root data length".into()))?;

    Ok(PrimaryVolumeDescriptor {
        logical_block_size,
        volume_space_size,
        root_extent_lba,
        root_data_length,
    })
}

/// A single parsed directory record.
struct DirRecord {
    extent_lba: u32,
    data_length: u32,
    is_directory: bool,
    /// The multi-extent flag: this record is not the last one of its file.
    multi_extent: bool,
    /// Recording date/time as absolute RFC 3339, if present (BUG-105).
    recorded: Option<String>,
    /// Raw file identifier bytes (before version-suffix stripping).
    identifier: Vec<u8>,
    /// The System Use area: the bytes after the identifier (and its padding
    /// byte) to the end of the record, where SUSP / Rock Ridge live.
    system_use: Vec<u8>,
}

/// Parse one directory record from a slice whose byte 0 is the record length.
/// Returns `None` for records too short to be valid.
fn parse_dir_record(d: &[u8]) -> Option<DirRecord> {
    let record_len = *d.first()? as usize;
    if record_len < DR_MIN_LEN || d.len() < DR_MIN_LEN {
        return None;
    }
    let extent_lba = le_u32(d, DR_EXTENT_LBA_OFFSET)?;
    let data_length = le_u32(d, DR_DATA_LENGTH_OFFSET)?;
    let flags = *d.get(DR_FILE_FLAGS_OFFSET)?;
    let is_directory = flags & DR_FLAG_DIRECTORY != 0;
    let multi_extent = flags & DR_FLAG_MULTI_EXTENT != 0;

    let recorded = d
        .get(DR_RECORDING_DATETIME_OFFSET..DR_RECORDING_DATETIME_OFFSET + 7)
        .and_then(parse_recording_datetime);

    let id_len = *d.get(DR_FILE_ID_LEN_OFFSET)? as usize;
    // Clamp the identifier to what actually fits inside the record and slice.
    let id_end = (DR_FILE_ID_OFFSET + id_len).min(record_len).min(d.len());
    let identifier = if id_end > DR_FILE_ID_OFFSET {
        d[DR_FILE_ID_OFFSET..id_end].to_vec()
    } else {
        Vec::new()
    };

    // ECMA-119 9.1.12: a padding byte follows an even-length identifier.
    let su_start = DR_FILE_ID_OFFSET + id_len + usize::from(id_len.is_multiple_of(2));
    let system_use = d
        .get(su_start..record_len.min(d.len()))
        .map(<[u8]>::to_vec)
        .unwrap_or_default();

    Some(DirRecord {
        extent_lba,
        data_length,
        is_directory,
        multi_extent,
        recorded,
        identifier,
        system_use,
    })
}

/// The "." (self) and ".." (parent) entries have a single-byte identifier of
/// 0x00 or 0x01; they must never be emitted or recursed into.
fn is_special(rec: &DirRecord) -> bool {
    rec.identifier.len() == 1 && (rec.identifier[0] == 0x00 || rec.identifier[0] == 0x01)
}

/// Decode a record's display name. For files the ISO version suffix (`;1`) is
/// stripped; directory names are used verbatim. In a Joliet tree the identifier
/// is UCS-2 big-endian (a trailing odd byte, which a valid record never has, is
/// dropped rather than invented into a character).
fn record_name(rec: &DirRecord, joliet: bool) -> String {
    let raw = if joliet {
        let units: Vec<u16> = rec
            .identifier
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .collect();
        std::borrow::Cow::Owned(String::from_utf16_lossy(&units))
    } else {
        String::from_utf8_lossy(&rec.identifier)
    };
    if rec.is_directory {
        raw.into_owned()
    } else {
        // Strip the version suffix: everything from the last ';'.
        match raw.rsplit_once(';') {
            Some((base, _)) => base.to_string(),
            None => raw.into_owned(),
        }
    }
}

/// Walk a directory's data buffer, returning its records in order. Directory
/// records never cross a logical-block boundary: a zero record length means "no
/// more records in this block", so advance to the next block-aligned offset.
fn read_directory_records(dir_bytes: &[u8], block_size: usize) -> Vec<DirRecord> {
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < dir_bytes.len() {
        let rec_len = dir_bytes[offset] as usize;
        if rec_len == 0 {
            // Skip to the next block boundary and keep scanning.
            let next = ((offset / block_size) + 1) * block_size;
            if next <= offset {
                break;
            }
            offset = next;
            continue;
        }
        if offset + rec_len > dir_bytes.len() {
            break;
        }
        if let Some(rec) = parse_dir_record(&dir_bytes[offset..offset + rec_len]) {
            records.push(rec);
        }
        offset += rec_len;
    }
    records
}

// --- Module implementation ---

pub struct Iso9660Parser;

impl ForensicsModule for Iso9660Parser {
    fn id(&self) -> &str {
        "plugin.filesystem.iso9660"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileSystem]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Gate: only run on ISO9660 filesystem artifacts.
        let subtype = artifact.subtype();
        let fs_type = artifact
            .metadata
            .get("filesystem_type")
            .and_then(|v| v.as_str());
        let applies = subtype == Some("iso9660")
            || fs_type
                .map(|s| {
                    s.eq_ignore_ascii_case("ISO9660")
                        || s.eq_ignore_ascii_case("ISO 9660")
                        || s.eq_ignore_ascii_case("CD9660")
                })
                .unwrap_or(false);
        if !applies {
            return Ok(Vec::new());
        }

        info!(
            "ISO9660 parser processing filesystem artifact ID: {}",
            artifact.id
        );

        let ds = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("ISO9660 parser requires a data source".to_string())
        })?;

        let descriptors = find_volume_descriptors(ds.as_ref())?;
        // The Joliet tree is walked when there is one: it names the same
        // files as the primary tree, with the names their author gave them.
        // Which tree the names came from is stamped on every entry, because a
        // name on a court-facing screen has to be traceable to the structure
        // it was read from. A Joliet SVD that will not parse falls back to the
        // primary tree rather than failing the disc.
        // Rock Ridge rides on the primary tree. When the primary root's "."
        // record declares it, that tree is walked with the Rock Ridge names
        // even where a Joliet tree exists -- the POSIX names are the author's
        // own, unbounded by Joliet's 64 UCS-2 characters, and only that tree
        // carries ownership, modes and link targets. The Linux kernel makes
        // the same choice (HUNT-176).
        let primary = parse_pvd(&descriptors.primary)?;
        let rock_ridge = detect_rock_ridge(ds.as_ref(), &primary);
        if let Some(ref rr) = rock_ridge {
            info!(
                "ISO9660: Rock Ridge present (SUSP skip {}, extension {:?})",
                rr.skip, rr.extension_id
            );
        }
        let (vd, joliet) = match descriptors.joliet.as_deref().map(parse_pvd) {
            _ if rock_ridge.is_some() => (primary, false),
            Some(Ok(svd)) => (svd, true),
            Some(Err(e)) => {
                warn!(
                    "ISO9660: Joliet volume descriptor present but unusable ({}); \
                     walking the primary tree",
                    e
                );
                (primary, false)
            }
            None => (primary, false),
        };
        info!(
            "ISO9660: blockSize={}, volumeSpace={}, rootLba={}, rootLen={}, names={}",
            vd.logical_block_size,
            vd.volume_space_size,
            vd.root_extent_lba,
            vd.root_data_length,
            if rock_ridge.is_some() {
                "rock_ridge"
            } else if joliet {
                "joliet"
            } else {
                "iso9660"
            }
        );

        let mut walker = Walker {
            ds: ds.as_ref(),
            block_size: vd.logical_block_size,
            joliet,
            rock_ridge,
            case_id: artifact.case_id,
            root_id: artifact.id,
            produced: Vec::new(),
            records_seen: 0,
            visited_extents: HashSet::new(),
            any_incomplete: false,
        };
        let root_status = walker.walk(vd.root_extent_lba, vd.root_data_length, "/", 0);

        info!(
            "ISO9660 parser produced {} file entries",
            walker.produced.len()
        );

        // Somewhere in the tree the walk stopped short. The root directory has
        // no FileEntry of its own to carry the flag, so publish a volume-level
        // record: an inventory that silently ends at a budget looks exactly like
        // a disc that really held nothing more.
        if walker.any_incomplete {
            let mut meta = json!({
                "type": "iso9660_walk",
                "directory_parse_incomplete": true,
                "entries_emitted": walker.produced.len(),
                "records_seen": walker.records_seen,
            });
            if let Some(reason) = root_status {
                meta["directory_parse_incomplete_reason"] = json!(reason);
            }
            walker.produced.push(
                Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, meta)
                    .with_parent(artifact.id),
            );
        }
        Ok(walker.produced)
    }
}

/// Recursive directory-tree walker. Holds the invariant context so the recursion
/// carries only the per-directory parameters.
struct Walker<'a> {
    ds: &'a dyn DataSource,
    block_size: u32,
    /// Whether the tree being walked is the Joliet one (UCS-2 identifiers).
    joliet: bool,
    /// Set when the primary tree carries Rock Ridge and is being walked
    /// with it (HUNT-176).
    rock_ridge: Option<RockRidgeVolume>,
    case_id: Uuid,
    root_id: Uuid,
    produced: Vec<Artifact>,
    records_seen: usize,
    /// Directory extent LBAs already walked. In a valid ISO every directory
    /// occupies its own extent, so a repeat LBA means a crafted image whose
    /// records point back into an ancestor/sibling directory. Skipping repeats
    /// stops depth-first re-reads of the same extent (up to MAX_RECORDS deep)
    /// that would otherwise spam artifacts from a tiny image. MAX_DEPTH alone
    /// bounds recursion depth but not this fan-out amplification.
    visited_extents: HashSet<u32>,
    /// True once any directory anywhere in the tree stopped short, so the
    /// module can publish a volume-level incompleteness marker.
    any_incomplete: bool,
}

impl Walker<'_> {
    /// Walk one directory extent, emitting a `FileEntry` per record and
    /// recursing into subdirectories.
    ///
    /// Returns `None` when the directory was enumerated to its end, or
    /// `Some(reason)` when it was not: a depth or record budget, a cyclic
    /// extent, an oversized directory, or an extent the image cannot deliver.
    /// The caller stamps the reason onto the directory's own artifact, because
    /// a listing that stops early is indistinguishable from a directory that
    /// really is that short — and the second is what an examiner will believe.
    fn walk(
        &mut self,
        extent_lba: u32,
        data_length: u32,
        parent_path: &str,
        depth: usize,
    ) -> Option<&'static str> {
        if depth > MAX_DEPTH {
            warn!("ISO9660: max directory depth reached at {}", parent_path);
            return Some(self.mark("max_depth"));
        }
        // Cycle guard: a directory extent is only ever walked once. A repeat LBA
        // is a self-referential/cyclic image; recursing again would re-read the
        // same extent and re-emit its records, amplified by the fan-out.
        if !self.visited_extents.insert(extent_lba) {
            warn!(
                "ISO9660: skipping already-visited directory extent {} at {}",
                extent_lba, parent_path
            );
            return Some(self.mark("cyclic_extent"));
        }
        if data_length == 0 {
            return None;
        }
        if data_length as u64 > MAX_DIRECTORY_BYTES {
            warn!(
                "ISO9660: directory {} too large ({} bytes), skipping",
                parent_path, data_length
            );
            return Some(self.mark("directory_too_large"));
        }

        let byte_off = extent_lba as u64 * self.block_size as u64;
        let mut dir_bytes = vec![0u8; data_length as usize];
        if let Err(e) = read_exact_or_fail(
            self.ds,
            byte_off,
            &mut dir_bytes,
            "ISO9660 directory extent",
        ) {
            warn!(
                "ISO9660 directory read failed at offset {}: {}",
                byte_off, e
            );
            return Some(self.mark("extent_read_failed"));
        }

        let records = read_directory_records(&dir_bytes, self.block_size as usize);
        let mut index = 0usize;
        while index < records.len() {
            let rec = &records[index];
            if is_special(rec) {
                index += 1;
                continue;
            }
            self.records_seen += 1;
            if self.records_seen > MAX_RECORDS {
                warn!("ISO9660: record budget exhausted");
                return Some(self.mark("record_budget_exhausted"));
            }

            // Collect every extent of this file. A record with the multi-extent
            // flag set is continued by the record that follows it; the file ends
            // at the first record with the flag clear (ECMA-119 9.1.6).
            let mut extents: Vec<(u32, u32)> = vec![(rec.extent_lba, rec.data_length)];
            let mut last = index;
            let mut final_record_seen = rec.is_directory || !rec.multi_extent;
            while !final_record_seen {
                match records.get(last + 1) {
                    // ECMA-119 9.1.6: every Directory Record of a multi-extent
                    // file carries the SAME File Identifier. Without that check
                    // a stray multi-extent flag swallows the next file: its
                    // bytes get appended to this one, its size grows, and it
                    // vanishes from the inventory entirely.
                    Some(next)
                        if !next.is_directory
                            && !is_special(next)
                            && next.identifier == rec.identifier =>
                    {
                        extents.push((next.extent_lba, next.data_length));
                        last += 1;
                        final_record_seen = !next.multi_extent;
                    }
                    // The continuation record is missing or names a different
                    // file: the directory extent ended (or holds something else)
                    // before this file's final record. The reconstruction is
                    // short by an unknown amount.
                    _ => break,
                }
            }
            self.records_seen += last - index;
            index = last + 1;

            let rr = self
                .rock_ridge
                .as_ref()
                .map(|vol| rock_ridge::read(self.ds, self.block_size, &rec.system_use, vol));
            let iso_name = record_name(rec, self.joliet);
            let name = match rr.as_ref().and_then(|r| r.name.clone()) {
                Some(n) if !n.is_empty() => n,
                _ => iso_name.clone(),
            };
            if name.is_empty() {
                continue;
            }
            // Deep-directory relocation (RRIP 4.1.5): a record marked `RE` is
            // a directory moved into the relocation directory, and is listed
            // where its `CL` placeholder stands instead; the placeholder is a
            // zero-length file record naming the moved directory's extent.
            if rr.as_ref().is_some_and(|r| r.relocated) {
                continue;
            }
            let child_link = rr.as_ref().and_then(|r| r.child_link);
            let is_directory = rec.is_directory || child_link.is_some();
            // A `CL` target whose "." record will not read walks nothing; the
            // placeholder entry itself carries that, or it reads as an empty
            // directory (HUNT-211).
            let mut target_unreadable: Option<&'static str> = None;
            let dir_extent = match child_link {
                Some(lba) => match self.dot_length(lba) {
                    Ok(len) => (lba, len),
                    Err(reason) => {
                        target_unreadable = Some(reason);
                        (lba, 0)
                    }
                },
                None => (rec.extent_lba, rec.data_length),
            };
            let path = if parent_path == "/" {
                format!("/{}", name)
            } else {
                format!("{}/{}", parent_path, name)
            };
            let size: u64 = if is_directory {
                0
            } else {
                extents.iter().map(|&(_, len)| len as u64).sum()
            };

            let mut metadata = json!({
                "name": name,
                "path": path,
                "parent_path": parent_path,
                "is_directory": is_directory,
                "size": size,
                "extent_lba": rec.extent_lba,
                "filesystem_type": "ISO9660",
                // Which directory tree the name was read from: "joliet" (the
                // UCS-2 long-name tree) or "iso9660" (the level-1 primary
                // tree). The two trees share extents; only the names differ.
                "name_source": if rr.as_ref().is_some_and(|r| r.name.is_some()) {
                    "rock_ridge"
                } else if self.joliet {
                    "joliet"
                } else {
                    "iso9660"
                },
            });
            if extents.len() > 1 {
                metadata["extent_count"] = json!(extents.len());
            }
            if !final_record_seen {
                // Never let a half-assembled multi-extent file look whole.
                metadata["content_incomplete"] = json!(true);
                metadata["content_incomplete_reason"] =
                    json!(IncompleteReason::UnresolvedStructure.as_str());
                warn!(
                    "ISO9660: multi-extent file {} has no final directory record",
                    path
                );
            }

            // The record's recording date/time is the file's on-disc timestamp
            // (BUG-105). It is offset-aware/absolute, so it feeds the timeline and
            // sort-by-date directly; surfaced under both "modified" and "recorded".
            if let Some(ref t) = rec.recorded {
                metadata["modified"] = json!(t);
                metadata["recorded"] = json!(t);
            }
            if let Some(rr) = rr {
                apply_rock_ridge(&mut metadata, &rr, &iso_name);
            }

            // Attach content for regular files from their extent list.
            let content: Option<Arc<dyn DataSource>> = if is_directory {
                None
            } else {
                build_file_content(self.ds, self.block_size, &extents, &mut metadata)
            };

            if let Some(lba) = child_link {
                metadata["extent_lba"] = json!(lba);
                metadata["rock_ridge_relocated_from_lba"] = json!(rec.extent_lba);
            }

            let dir_artifact_index = self.produced.len();
            self.produced.push(
                Artifact::new(self.case_id, ArtifactType::FileEntry, content, metadata)
                    .with_parent(self.root_id),
            );

            if is_directory {
                let walked = self.walk(dir_extent.0, dir_extent.1, &path, depth + 1);
                if let Some(reason) = walked.or(target_unreadable) {
                    let meta = &mut self.produced[dir_artifact_index].metadata;
                    meta["directory_parse_incomplete"] = json!(true);
                    meta["directory_parse_incomplete_reason"] = json!(reason);
                }
            }
        }
        None
    }

    /// The data length a directory extent's own "." record gives, for a
    /// Rock Ridge `CL` placeholder, which names the extent but not its size.
    /// When the record will not read, the reason is returned (and the volume
    /// marked); the caller stamps it on the placeholder's own entry, which
    /// would otherwise read as an empty directory (HUNT-211).
    fn dot_length(&mut self, lba: u32) -> Result<u32, &'static str> {
        let mut first = [0u8; DR_MIN_LEN];
        let off = lba as u64 * self.block_size as u64;
        if read_exact_or_fail(self.ds, off, &mut first, "Rock Ridge CL target").is_ok() {
            if let Some(rec) = parse_dir_record(&first) {
                return Ok(rec.data_length);
            }
        }
        Err(self.mark("relocated_directory_unreadable"))
    }

    /// Record that the walk stopped short and hand the reason back to the
    /// caller. Every early return from [`Walker::walk`] goes through here so the
    /// volume-level marker can never fall out of step with a directory's own.
    fn mark(&mut self, reason: &'static str) -> &'static str {
        self.any_incomplete = true;
        reason
    }
}

/// Where the primary root's "." record declares Rock Ridge, the volume's
/// SUSP skip length and extension identifier.
fn detect_rock_ridge(
    ds: &dyn DataSource,
    pvd: &PrimaryVolumeDescriptor,
) -> Option<RockRidgeVolume> {
    let byte_off = pvd.root_extent_lba as u64 * pvd.logical_block_size as u64;
    let len = (pvd.root_data_length as usize).clamp(DR_MIN_LEN, 255);
    let mut first = vec![0u8; len];
    read_exact_or_fail(ds, byte_off, &mut first, "ISO9660 root directory").ok()?;
    let dot = parse_dir_record(first.get(..*first.first()? as usize)?)?;
    rock_ridge::detect(ds, pvd.logical_block_size, &dot.system_use)
}

/// Stamp what a record's Rock Ridge entries said onto its `FileEntry`.
fn apply_rock_ridge(metadata: &mut serde_json::Value, rr: &rock_ridge::RockRidge, iso_name: &str) {
    if rr.name.is_some() {
        // The level-1 name the same record carries, for traceability.
        metadata["iso9660_name"] = json!(iso_name);
    }
    if let Some(mode) = rr.mode {
        metadata["mode"] = json!(mode);
    }
    for (key, value) in [
        ("nlink", rr.nlink),
        ("uid", rr.uid),
        ("gid", rr.gid),
        ("inode", rr.serial),
    ] {
        if let Some(v) = value {
            metadata[key] = json!(v);
        }
    }
    // The TF modification time is the file's own mtime; the directory
    // record's recording time stays under `recorded`.
    for (key, value) in [
        ("created", &rr.created),
        ("modified", &rr.modified),
        ("accessed", &rr.accessed),
        ("changed", &rr.changed),
    ] {
        if let Some(t) = value {
            metadata[key] = json!(t);
        }
    }
    if let Some(ref target) = rr.symlink_target {
        metadata["is_symlink"] = json!(true);
        metadata["symlink_target"] = json!(target);
    }
    if !rr.unread.is_empty() {
        // Present on the disc, recognised, and not decoded by this reader.
        metadata["rock_ridge_entries_not_read"] = json!(rr.unread);
        // A zisofs file's extent holds compressed bytes, and a sparse file's
        // extent is not its whole logical content: neither may be served
        // and hashed as the file's bytes without the standard flag.
        let reason = if rr.unread.contains(&"ZF") {
            Some(IncompleteReason::Compressed)
        } else if rr.unread.contains(&"SF") {
            Some(IncompleteReason::UnresolvedStructure)
        } else {
            None
        };
        if let Some(reason) = reason {
            if metadata.get("content_incomplete").is_none() {
                metadata["content_incomplete"] = json!(true);
                metadata["content_incomplete_reason"] = json!(reason.as_str());
            }
        }
    }
    if rr.incomplete {
        metadata["rock_ridge_incomplete"] = json!(true);
    }
}

/// Materialize a regular file's bytes from its `(extent_lba, data_length)` list
/// and wrap them in an in-memory data source. Records the byte runs into
/// `metadata`. A multi-extent file (BUG-240) has more than one entry and its
/// content is the extents concatenated in record order. Very large files are
/// skipped (no content attached) and flagged.
fn build_file_content(
    ds: &dyn DataSource,
    block_size: u32,
    extents: &[(u32, u32)],
    metadata: &mut serde_json::Value,
) -> Option<Arc<dyn DataSource>> {
    let runs: Vec<(Option<u64>, u64)> = extents
        .iter()
        .map(|&(lba, len)| (Some(lba as u64 * block_size as u64), len as u64))
        .collect();
    let total: u64 = extents.iter().map(|&(_, len)| len as u64).sum();

    // Persist the filesystem-window byte runs so the content resolver can re-serve.
    let (runs_json, complete) = byte_runs_to_metadata(&runs);
    metadata["data_runs"] = runs_json;

    if total == 0 {
        metadata["data_runs_complete"] = json!(complete);
        return Some(Arc::new(ByteSliceDataSource::new(Vec::new())));
    }
    if total > MAX_CONTENT_BYTES {
        // Too large to materialize in memory; flag and skip content.
        metadata["data_runs_complete"] = json!(false);
        metadata["content_too_large"] = json!(true);
        return None;
    }

    let mut content = Vec::with_capacity(total as usize);
    for &(offset, len) in &runs {
        let Some(byte_off) = offset else { continue };
        let start = content.len();
        content.resize(start + len as usize, 0u8);
        if let Err(e) =
            read_exact_or_fail(ds, byte_off, &mut content[start..], "ISO9660 file extent")
        {
            // BUG-104: a truncated/out-of-range extent must not be reported complete.
            warn!("ISO9660 content read failed at offset {}: {}", byte_off, e);
            metadata["data_runs_complete"] = json!(false);
            metadata["content_truncated"] = json!(true);
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] = json!(IncompleteReason::ShortRead.as_str());
            return None;
        }
    }
    metadata["data_runs_complete"] = json!(complete);
    Some(Arc::new(ByteSliceDataSource::new(content)))
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;

    #[test]
    fn test_module_metadata() {
        let module = Iso9660Parser;
        assert_eq!(module.id(), "plugin.filesystem.iso9660");
        assert_eq!(module.version(), env!("CARGO_PKG_VERSION"));
        assert!(module.subscribes_to().contains(&ArtifactType::FileSystem));
        assert_eq!(module.input_capability(), InputCapability::RandomAccess);
    }

    #[test]
    fn test_gate_skips_non_iso() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileSystem,
            None,
            json!({ "filesystem_type": "NTFS" }),
        );
        assert!(Iso9660Parser.process(&art).unwrap().is_empty());
    }

    #[test]
    fn test_find_and_parse_pvd() {
        // Build a volume: 16 sectors of System Area, a PVD at sector 16, and a
        // terminator at sector 17.
        let mut vol = vec![0u8; LOGICAL_SECTOR_SIZE * 18];

        let p = 16 * LOGICAL_SECTOR_SIZE;
        vol[p] = VD_TYPE_PRIMARY;
        vol[p + 1..p + 6].copy_from_slice(b"CD001");
        vol[p + 6] = 1; // version
                        // Logical block size @128 (both-endian u16); write the LE copy.
        vol[p + PVD_LOGICAL_BLOCK_SIZE_OFFSET..p + PVD_LOGICAL_BLOCK_SIZE_OFFSET + 2]
            .copy_from_slice(&2048u16.to_le_bytes());
        // Volume space size @80 (both-endian u32); write the LE copy.
        vol[p + PVD_VOLUME_SPACE_SIZE_OFFSET..p + PVD_VOLUME_SPACE_SIZE_OFFSET + 4]
            .copy_from_slice(&1000u32.to_le_bytes());
        // Root directory record @156: extent LBA @+2, data length @+10.
        let r = p + PVD_ROOT_RECORD_OFFSET;
        vol[r + DR_EXTENT_LBA_OFFSET..r + DR_EXTENT_LBA_OFFSET + 4]
            .copy_from_slice(&28u32.to_le_bytes());
        vol[r + DR_DATA_LENGTH_OFFSET..r + DR_DATA_LENGTH_OFFSET + 4]
            .copy_from_slice(&2048u32.to_le_bytes());

        let t = 17 * LOGICAL_SECTOR_SIZE;
        vol[t] = VD_TYPE_TERMINATOR;
        vol[t + 1..t + 6].copy_from_slice(b"CD001");

        let ds = ByteSliceDataSource::new(vol);
        let pvd = find_primary_volume_descriptor(&ds).unwrap();
        let vd = parse_pvd(&pvd).unwrap();
        assert_eq!(vd.logical_block_size, 2048);
        assert_eq!(vd.volume_space_size, 1000);
        assert_eq!(vd.root_extent_lba, 28);
        assert_eq!(vd.root_data_length, 2048);
    }

    #[test]
    fn test_find_pvd_rejects_missing_cd001() {
        // A volume whose sector 16 lacks the CD001 identifier is not ISO9660.
        let vol = vec![0u8; LOGICAL_SECTOR_SIZE * 17];
        let ds = ByteSliceDataSource::new(vol);
        assert!(find_primary_volume_descriptor(&ds).is_err());
    }

    #[test]
    fn test_parse_dir_record_file() {
        // A file record for "FILE1.TXT;1" at LBA 28, 512 bytes long.
        let name = b"FILE1.TXT;1";
        let record_len = DR_FILE_ID_OFFSET + name.len(); // 33 + 11 = 44 (even)
        let mut rec = vec![0u8; record_len];
        rec[0] = record_len as u8;
        rec[DR_EXTENT_LBA_OFFSET..DR_EXTENT_LBA_OFFSET + 4].copy_from_slice(&28u32.to_le_bytes());
        rec[DR_DATA_LENGTH_OFFSET..DR_DATA_LENGTH_OFFSET + 4]
            .copy_from_slice(&512u32.to_le_bytes());
        rec[DR_FILE_FLAGS_OFFSET] = 0x00; // regular file
        rec[DR_FILE_ID_LEN_OFFSET] = name.len() as u8;
        rec[DR_FILE_ID_OFFSET..DR_FILE_ID_OFFSET + name.len()].copy_from_slice(name);

        let parsed = parse_dir_record(&rec).unwrap();
        assert_eq!(parsed.extent_lba, 28);
        assert_eq!(parsed.data_length, 512);
        assert!(!parsed.is_directory);
        assert!(!is_special(&parsed));
        // Version suffix ";1" stripped.
        assert_eq!(record_name(&parsed, false), "FILE1.TXT");
    }

    #[test]
    fn test_parse_dir_record_directory() {
        let name = b"SUBDIR";
        let record_len = DR_FILE_ID_OFFSET + name.len(); // 39
        let mut rec = vec![0u8; record_len];
        rec[0] = record_len as u8;
        rec[DR_EXTENT_LBA_OFFSET..DR_EXTENT_LBA_OFFSET + 4].copy_from_slice(&30u32.to_le_bytes());
        rec[DR_DATA_LENGTH_OFFSET..DR_DATA_LENGTH_OFFSET + 4]
            .copy_from_slice(&2048u32.to_le_bytes());
        rec[DR_FILE_FLAGS_OFFSET] = DR_FLAG_DIRECTORY;
        rec[DR_FILE_ID_LEN_OFFSET] = name.len() as u8;
        rec[DR_FILE_ID_OFFSET..DR_FILE_ID_OFFSET + name.len()].copy_from_slice(name);

        let parsed = parse_dir_record(&rec).unwrap();
        assert!(parsed.is_directory);
        assert_eq!(parsed.extent_lba, 30);
        // Directory names keep their identifier verbatim (no version stripping).
        assert_eq!(record_name(&parsed, false), "SUBDIR");
    }

    #[test]
    fn test_read_directory_records_skips_specials() {
        // Build a directory extent: "." , ".." , then one file record.
        let mut dir = Vec::new();

        // "." self entry: id length 1, byte 0x00, directory flag.
        let mut dot = vec![0u8; DR_MIN_LEN];
        dot[0] = DR_MIN_LEN as u8;
        dot[DR_FILE_FLAGS_OFFSET] = DR_FLAG_DIRECTORY;
        dot[DR_FILE_ID_LEN_OFFSET] = 1;
        dot[DR_FILE_ID_OFFSET] = 0x00;
        dir.extend_from_slice(&dot);

        // ".." parent entry: id length 1, byte 0x01, directory flag.
        let mut dotdot = vec![0u8; DR_MIN_LEN];
        dotdot[0] = DR_MIN_LEN as u8;
        dotdot[DR_FILE_FLAGS_OFFSET] = DR_FLAG_DIRECTORY;
        dotdot[DR_FILE_ID_LEN_OFFSET] = 1;
        dotdot[DR_FILE_ID_OFFSET] = 0x01;
        dir.extend_from_slice(&dotdot);

        // A file "A.TXT;1".
        let name = b"A.TXT;1";
        let rl = DR_FILE_ID_OFFSET + name.len(); // 40
        let mut f = vec![0u8; rl];
        f[0] = rl as u8;
        f[DR_EXTENT_LBA_OFFSET..DR_EXTENT_LBA_OFFSET + 4].copy_from_slice(&50u32.to_le_bytes());
        f[DR_DATA_LENGTH_OFFSET..DR_DATA_LENGTH_OFFSET + 4].copy_from_slice(&123u32.to_le_bytes());
        f[DR_FILE_ID_LEN_OFFSET] = name.len() as u8;
        f[DR_FILE_ID_OFFSET..DR_FILE_ID_OFFSET + name.len()].copy_from_slice(name);
        dir.extend_from_slice(&f);

        let records = read_directory_records(&dir, LOGICAL_SECTOR_SIZE);
        assert_eq!(records.len(), 3);
        let non_special: Vec<&DirRecord> = records.iter().filter(|r| !is_special(r)).collect();
        assert_eq!(non_special.len(), 1);
        assert_eq!(record_name(non_special[0], false), "A.TXT");
        assert_eq!(non_special[0].extent_lba, 50);
        assert_eq!(non_special[0].data_length, 123);
    }

    #[test]
    fn test_walk_skips_self_referential_directory() {
        // Crafted ISO: the root directory holds three subdirectory records that
        // each point back at the root's own extent. Without the cycle guard the
        // walker re-reads that extent for every child, fanning out (3^depth)
        // toward the record budget. With the guard, each child is emitted once
        // and the second walk of the extent returns immediately.
        const ROOT_LBA: u32 = 18;
        let mut vol = vec![0u8; LOGICAL_SECTOR_SIZE * (ROOT_LBA as usize + 1)];

        // PVD at sector 16.
        let p = 16 * LOGICAL_SECTOR_SIZE;
        vol[p] = VD_TYPE_PRIMARY;
        vol[p + 1..p + 6].copy_from_slice(b"CD001");
        vol[p + 6] = 1;
        vol[p + PVD_LOGICAL_BLOCK_SIZE_OFFSET..p + PVD_LOGICAL_BLOCK_SIZE_OFFSET + 2]
            .copy_from_slice(&2048u16.to_le_bytes());
        let r = p + PVD_ROOT_RECORD_OFFSET;
        vol[r + DR_EXTENT_LBA_OFFSET..r + DR_EXTENT_LBA_OFFSET + 4]
            .copy_from_slice(&ROOT_LBA.to_le_bytes());
        vol[r + DR_DATA_LENGTH_OFFSET..r + DR_DATA_LENGTH_OFFSET + 4]
            .copy_from_slice(&2048u32.to_le_bytes());

        // Terminator at sector 17.
        let t = 17 * LOGICAL_SECTOR_SIZE;
        vol[t] = VD_TYPE_TERMINATOR;
        vol[t + 1..t + 6].copy_from_slice(b"CD001");

        // Root extent: three subdirectory records, each pointing back at ROOT_LBA.
        let mut dir = Vec::new();
        for name in [
            b"EVIL1".as_slice(),
            b"EVIL2".as_slice(),
            b"EVIL3".as_slice(),
        ] {
            let rl = DR_FILE_ID_OFFSET + name.len();
            let mut rec = vec![0u8; rl];
            rec[0] = rl as u8;
            rec[DR_EXTENT_LBA_OFFSET..DR_EXTENT_LBA_OFFSET + 4]
                .copy_from_slice(&ROOT_LBA.to_le_bytes());
            rec[DR_DATA_LENGTH_OFFSET..DR_DATA_LENGTH_OFFSET + 4]
                .copy_from_slice(&2048u32.to_le_bytes());
            rec[DR_FILE_FLAGS_OFFSET] = DR_FLAG_DIRECTORY;
            rec[DR_FILE_ID_LEN_OFFSET] = name.len() as u8;
            rec[DR_FILE_ID_OFFSET..DR_FILE_ID_OFFSET + name.len()].copy_from_slice(name);
            dir.extend_from_slice(&rec);
        }
        let d = ROOT_LBA as usize * LOGICAL_SECTOR_SIZE;
        vol[d..d + dir.len()].copy_from_slice(&dir);

        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(Arc::new(ByteSliceDataSource::new(vol)) as Arc<dyn DataSource>),
            json!({ "filesystem_type": "ISO9660" }),
        );

        let produced = Iso9660Parser.process(&art).unwrap();
        // Exactly the three children, no cyclic amplification.
        let entries: Vec<&Artifact> = produced
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();
        assert_eq!(entries.len(), 3);
        // Each child's own listing was cut short by the cycle guard, and the
        // volume carries a walk-level marker: skipping a cyclic extent is a
        // decision not to enumerate, not proof the directory was empty.
        for e in &entries {
            assert_eq!(e.metadata["directory_parse_incomplete"], json!(true));
            assert_eq!(
                e.metadata["directory_parse_incomplete_reason"],
                json!("cyclic_extent")
            );
        }
        assert!(
            produced
                .iter()
                .any(|a| a.metadata.get("type").and_then(|t| t.as_str()) == Some("iso9660_walk")),
            "a truncated walk publishes a volume-level marker"
        );
    }

    #[test]
    fn test_parse_recording_datetime() {
        // BUG-105: 7-byte recording date/time -> absolute RFC 3339.
        // 1995-06-15 12:30:00, GMT offset 0.
        let dt = [95u8, 6, 15, 12, 30, 0, 0];
        let ts = parse_recording_datetime(&dt).unwrap();
        assert!(ts.starts_with("1995-06-15T12:30:00+00:00"), "got {}", ts);

        // GMT +2h == 8 fifteen-minute intervals; the offset must be preserved.
        let dt_off = [95u8, 6, 15, 12, 30, 0, 8];
        let ts_off = parse_recording_datetime(&dt_off).unwrap();
        assert!(ts_off.ends_with("+02:00"), "got {}", ts_off);

        // An all-zero (unset) record decodes to None, never a fabricated 1900.
        assert!(parse_recording_datetime(&[0u8; 7]).is_none());
    }

    #[test]
    fn test_parse_dir_record_carries_recording_time() {
        // A file record with a recording date/time must surface it (BUG-105).
        let name = b"A.TXT;1";
        let record_len = DR_FILE_ID_OFFSET + name.len();
        let mut rec = vec![0u8; record_len];
        rec[0] = record_len as u8;
        rec[DR_EXTENT_LBA_OFFSET..DR_EXTENT_LBA_OFFSET + 4].copy_from_slice(&40u32.to_le_bytes());
        rec[DR_DATA_LENGTH_OFFSET..DR_DATA_LENGTH_OFFSET + 4].copy_from_slice(&10u32.to_le_bytes());
        rec[DR_RECORDING_DATETIME_OFFSET..DR_RECORDING_DATETIME_OFFSET + 7]
            .copy_from_slice(&[121u8, 3, 1, 9, 0, 0, 0]); // 2021-03-01 09:00:00Z
        rec[DR_FILE_ID_LEN_OFFSET] = name.len() as u8;
        rec[DR_FILE_ID_OFFSET..DR_FILE_ID_OFFSET + name.len()].copy_from_slice(name);

        let parsed = parse_dir_record(&rec).unwrap();
        assert!(parsed
            .recorded
            .as_deref()
            .unwrap()
            .starts_with("2021-03-01T09:00:00"));
    }

    #[test]
    fn test_truncated_volume_descriptor_fails_closed() {
        // BUG-104: a volume that ends mid-descriptor must error rather than parse
        // a zero-padded sector. The fail-closed read itself lives in
        // seance_core::io; this pins the behaviour at the ISO9660 call site.
        let ds = ByteSliceDataSource::new(vec![0u8; LOGICAL_SECTOR_SIZE * 16 + 100]);
        assert!(find_primary_volume_descriptor(&ds).is_err());
    }

    #[test]
    fn test_truncated_file_extent_is_not_reported_complete() {
        // A file extent that runs past the end of the volume yields no content and
        // is flagged truncated, never a zero-padded "complete" file.
        let ds = ByteSliceDataSource::new(vec![0xAAu8; 2048]);
        let mut metadata = json!({});
        // extent starts at block 1 (byte 2048) — exactly at EOF, so nothing reads.
        let content = build_file_content(&ds, 2048, &[(1, 4096)], &mut metadata);
        assert!(
            content.is_none(),
            "a truncated extent must not yield content"
        );
        assert_eq!(metadata["data_runs_complete"], json!(false));
        assert_eq!(metadata["content_truncated"], json!(true));
    }

    /// Write a directory record into `dir`.
    fn push_record(dir: &mut Vec<u8>, name: &[u8], lba: u32, len: u32, flags: u8) {
        let rl = DR_FILE_ID_OFFSET + name.len();
        let mut rec = vec![0u8; rl];
        rec[0] = rl as u8;
        rec[DR_EXTENT_LBA_OFFSET..DR_EXTENT_LBA_OFFSET + 4].copy_from_slice(&lba.to_le_bytes());
        rec[DR_DATA_LENGTH_OFFSET..DR_DATA_LENGTH_OFFSET + 4].copy_from_slice(&len.to_le_bytes());
        rec[DR_FILE_FLAGS_OFFSET] = flags;
        rec[DR_FILE_ID_LEN_OFFSET] = name.len() as u8;
        rec[DR_FILE_ID_OFFSET..DR_FILE_ID_OFFSET + name.len()].copy_from_slice(name);
        dir.extend_from_slice(&rec);
    }

    /// Build a minimal volume: PVD at 16, terminator at 17, root extent at 18
    /// holding `dir`, and two data blocks at LBA 19 and 20.
    fn volume_with_root(dir: &[u8], data_blocks: &[(u32, u8)]) -> Vec<u8> {
        const ROOT_LBA: u32 = 18;
        let last_lba = data_blocks
            .iter()
            .map(|&(l, _)| l)
            .max()
            .unwrap_or(ROOT_LBA);
        let mut vol = vec![0u8; LOGICAL_SECTOR_SIZE * (last_lba as usize + 1)];

        let p = 16 * LOGICAL_SECTOR_SIZE;
        vol[p] = VD_TYPE_PRIMARY;
        vol[p + 1..p + 6].copy_from_slice(b"CD001");
        vol[p + 6] = 1;
        vol[p + PVD_LOGICAL_BLOCK_SIZE_OFFSET..p + PVD_LOGICAL_BLOCK_SIZE_OFFSET + 2]
            .copy_from_slice(&2048u16.to_le_bytes());
        let r = p + PVD_ROOT_RECORD_OFFSET;
        vol[r + DR_EXTENT_LBA_OFFSET..r + DR_EXTENT_LBA_OFFSET + 4]
            .copy_from_slice(&ROOT_LBA.to_le_bytes());
        vol[r + DR_DATA_LENGTH_OFFSET..r + DR_DATA_LENGTH_OFFSET + 4]
            .copy_from_slice(&2048u32.to_le_bytes());

        let t = 17 * LOGICAL_SECTOR_SIZE;
        vol[t] = VD_TYPE_TERMINATOR;
        vol[t + 1..t + 6].copy_from_slice(b"CD001");

        let d = ROOT_LBA as usize * LOGICAL_SECTOR_SIZE;
        vol[d..d + dir.len()].copy_from_slice(dir);

        for &(lba, fill) in data_blocks {
            let start = lba as usize * LOGICAL_SECTOR_SIZE;
            for b in &mut vol[start..start + LOGICAL_SECTOR_SIZE] {
                *b = fill;
            }
        }
        vol
    }

    /// Build a volume with a PVD at 16 whose root (LBA 21) holds `pvd_dir`, a
    /// Joliet SVD at 17 whose root (LBA 22) holds `joliet_dir`, a terminator at
    /// 18, and one data block at LBA 23.
    fn volume_with_joliet(pvd_dir: &[u8], joliet_dir: &[u8], escapes: &[u8]) -> Vec<u8> {
        let mut vol = vec![0u8; LOGICAL_SECTOR_SIZE * 24];
        let mut descriptor = |sector: usize, kind: u8, root_lba: u32| {
            let p = sector * LOGICAL_SECTOR_SIZE;
            vol[p] = kind;
            vol[p + 1..p + 6].copy_from_slice(b"CD001");
            vol[p + 6] = 1;
            vol[p + PVD_LOGICAL_BLOCK_SIZE_OFFSET..p + PVD_LOGICAL_BLOCK_SIZE_OFFSET + 2]
                .copy_from_slice(&2048u16.to_le_bytes());
            let r = p + PVD_ROOT_RECORD_OFFSET;
            vol[r + DR_EXTENT_LBA_OFFSET..r + DR_EXTENT_LBA_OFFSET + 4]
                .copy_from_slice(&root_lba.to_le_bytes());
            vol[r + DR_DATA_LENGTH_OFFSET..r + DR_DATA_LENGTH_OFFSET + 4]
                .copy_from_slice(&2048u32.to_le_bytes());
        };
        descriptor(16, VD_TYPE_PRIMARY, 21);
        descriptor(17, VD_TYPE_SUPPLEMENTARY, 22);
        let e = 17 * LOGICAL_SECTOR_SIZE + VD_ESCAPE_SEQUENCES_OFFSET;
        vol[e..e + escapes.len()].copy_from_slice(escapes);
        let t = 18 * LOGICAL_SECTOR_SIZE;
        vol[t] = VD_TYPE_TERMINATOR;
        vol[t + 1..t + 6].copy_from_slice(b"CD001");
        let d = 21 * LOGICAL_SECTOR_SIZE;
        vol[d..d + pvd_dir.len()].copy_from_slice(pvd_dir);
        let d = 22 * LOGICAL_SECTOR_SIZE;
        vol[d..d + joliet_dir.len()].copy_from_slice(joliet_dir);
        for b in &mut vol[23 * LOGICAL_SECTOR_SIZE..24 * LOGICAL_SECTOR_SIZE] {
            *b = 0x41;
        }
        vol
    }

    fn ucs2(name: &str) -> Vec<u8> {
        name.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
    }

    fn names_of(vol: Vec<u8>) -> Vec<(String, String)> {
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(Arc::new(ByteSliceDataSource::new(vol))),
            json!({ "filesystem_type": "ISO9660" }),
        );
        Iso9660Parser
            .process(&artifact)
            .unwrap()
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .map(|a| {
                (
                    a.metadata["name"].as_str().unwrap().to_string(),
                    a.metadata["name_source"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    /// A disc with a Joliet tree is named from it (DOC-013). The primary tree
    /// holds the ISO-9660 level-1 rendering an examiner would not recognise;
    /// the Joliet tree holds the name the author gave the file, in UCS-2. Every
    /// entry says which tree its name came from.
    #[test]
    fn a_joliet_tree_names_the_files_and_says_so() {
        let mut pvd_dir = Vec::new();
        push_record(&mut pvd_dir, b"LONG_FIL.TXT;1", 23, 2048, 0);
        let mut joliet_dir = Vec::new();
        push_record(
            &mut joliet_dir,
            &ucs2("Long file name — résumé.txt;1"),
            23,
            2048,
            0,
        );
        push_record(
            &mut joliet_dir,
            &ucs2("Photos"),
            22,
            2048,
            DR_FLAG_DIRECTORY,
        );

        let names = names_of(volume_with_joliet(&pvd_dir, &joliet_dir, b"%/E"));
        assert!(
            names.contains(&(
                "Long file name — résumé.txt".to_string(),
                "joliet".to_string()
            )),
            "{names:?}"
        );
        assert!(
            names.contains(&("Photos".to_string(), "joliet".to_string())),
            "a directory name is decoded the same way: {names:?}"
        );
        assert!(
            !names.iter().any(|(n, _)| n == "LONG_FIL.TXT"),
            "the level-1 rendering must not be listed beside the real name: {names:?}"
        );

        // An SVD whose escape sequences do not declare Joliet is not one: the
        // primary tree is walked and the entries say so.
        let names = names_of(volume_with_joliet(&pvd_dir, &joliet_dir, b"%/Z"));
        assert_eq!(
            names,
            vec![("LONG_FIL.TXT".to_string(), "iso9660".to_string())],
            "{names:?}"
        );
    }

    #[test]
    fn test_multi_extent_file_is_one_entry_with_all_extents() {
        // BUG-240: two consecutive records for BIG.DAT, the first carrying the
        // multi-extent flag. They describe ONE file of 3000 bytes, not two.
        let mut dir = Vec::new();
        push_record(&mut dir, b"BIG.DAT;1", 19, 2048, DR_FLAG_MULTI_EXTENT);
        push_record(&mut dir, b"BIG.DAT;1", 20, 952, 0);
        let vol = volume_with_root(&dir, &[(19, 0xAA), (20, 0xBB)]);

        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(Arc::new(ByteSliceDataSource::new(vol)) as Arc<dyn DataSource>),
            json!({ "filesystem_type": "ISO9660" }),
        );
        let produced = Iso9660Parser.process(&art).unwrap();

        assert_eq!(produced.len(), 1, "a multi-extent file is a single entry");
        let f = &produced[0];
        assert_eq!(f.metadata["name"], "BIG.DAT");
        assert_eq!(f.metadata["size"], json!(3000u64));
        assert_eq!(f.metadata["extent_count"], json!(2));
        assert_eq!(f.metadata["data_runs_complete"], json!(true));
        assert!(f.metadata.get("content_incomplete").is_none());

        // Content spans both extents, in record order.
        let data = f.data.as_ref().expect("content attached");
        assert_eq!(data.size(), 3000);
        let mut buf = vec![0u8; 3000];
        let n = data.read_at(0, &mut buf).unwrap();
        assert_eq!(n, 3000);
        assert!(buf[..2048].iter().all(|&b| b == 0xAA));
        assert!(buf[2048..].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn test_multi_extent_without_final_record_is_flagged_incomplete() {
        // The continuation record is missing (truncated/corrupt directory): the
        // file must not be published as if its extents were all present.
        let mut dir = Vec::new();
        push_record(&mut dir, b"BIG.DAT;1", 19, 2048, DR_FLAG_MULTI_EXTENT);
        let vol = volume_with_root(&dir, &[(19, 0xAA)]);

        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(Arc::new(ByteSliceDataSource::new(vol)) as Arc<dyn DataSource>),
            json!({ "filesystem_type": "ISO9660" }),
        );
        let produced = Iso9660Parser.process(&art).unwrap();
        assert_eq!(produced.len(), 1);
        assert_eq!(produced[0].metadata["content_incomplete"], json!(true));
        assert_eq!(
            produced[0].metadata["content_incomplete_reason"],
            json!("unresolved_structure")
        );
    }

    /// B2-071: a multi-extent continuation must carry the SAME File Identifier
    /// (ECMA-119 9.1.6). Taking the next record regardless of name lets a stray
    /// or crafted multi-extent flag swallow the following file: its bytes are
    /// appended to the previous one, its size is wrong, and it disappears from
    /// the inventory altogether.
    #[test]
    fn a_multi_extent_continuation_with_a_different_name_is_not_absorbed() {
        let mut dir = Vec::new();
        push_record(&mut dir, b"FIRST.DAT;1", 19, 2048, DR_FLAG_MULTI_EXTENT);
        push_record(&mut dir, b"SECOND.DAT;1", 20, 952, 0);
        let vol = volume_with_root(&dir, &[(19, 0xAA), (20, 0xBB)]);

        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(Arc::new(ByteSliceDataSource::new(vol)) as Arc<dyn DataSource>),
            json!({ "filesystem_type": "ISO9660" }),
        );
        let produced = Iso9660Parser.process(&art).unwrap();

        let names: Vec<String> = produced
            .iter()
            .filter_map(|a| a.metadata.get("name").and_then(|v| v.as_str()))
            .map(str::to_string)
            .collect();
        assert!(
            names.iter().any(|n| n == "SECOND.DAT"),
            "the following file must stay in the inventory: {names:?}"
        );

        let first = produced
            .iter()
            .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("FIRST.DAT"))
            .expect("the first file is emitted");
        assert_eq!(
            first.metadata["size"],
            json!(2048u64),
            "the first file keeps its own extent only"
        );
        assert_eq!(
            first.metadata["content_incomplete"],
            json!(true),
            "its declared continuation was never found"
        );
    }

    /// B2-072: the record budget stops the walk. Without a marker a partially
    /// enumerated disc is indistinguishable from a fully enumerated one, and the
    /// missing files read as files that were never burned.
    #[test]
    fn exhausting_the_record_budget_publishes_a_walk_incomplete_marker() {
        // A directory whose records exceed MAX_RECORDS is impractical to build,
        // so drive `walk` directly with an already-spent budget.
        let mut dir = Vec::new();
        push_record(&mut dir, b"A.TXT;1", 19, 10, 0);
        let vol = volume_with_root(&dir, &[(19, 0xAA)]);
        let ds = ByteSliceDataSource::new(vol);

        let mut walker = Walker {
            ds: &ds,
            block_size: 2048,
            joliet: false,
            rock_ridge: None,
            case_id: Uuid::new_v4(),
            root_id: Uuid::new_v4(),
            produced: Vec::new(),
            records_seen: MAX_RECORDS,
            visited_extents: HashSet::new(),
            any_incomplete: false,
        };
        let reason = walker.walk(18, 2048, "/", 0);

        assert_eq!(reason, Some("record_budget_exhausted"));
        assert!(walker.any_incomplete);
        assert!(
            walker.produced.is_empty(),
            "the budget was already spent, so nothing was enumerated"
        );
    }

    /// The success path: a directory walked to its end reports no reason and
    /// leaves the volume marker off, so the marker stays meaningful.
    #[test]
    fn a_fully_enumerated_directory_reports_no_incompleteness() {
        let mut dir = Vec::new();
        push_record(&mut dir, b"A.TXT;1", 19, 10, 0);
        let vol = volume_with_root(&dir, &[(19, 0xAA)]);

        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(Arc::new(ByteSliceDataSource::new(vol)) as Arc<dyn DataSource>),
            json!({ "filesystem_type": "ISO9660" }),
        );
        let produced = Iso9660Parser.process(&art).unwrap();
        assert_eq!(produced.len(), 1);
        assert!(produced[0]
            .metadata
            .get("directory_parse_incomplete")
            .is_none());
    }
}
