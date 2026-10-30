// these guards test a magic prefix, which is what identifies the format; the
// pattern form would inline byte literals into the match and lose the names.
#![allow(clippy::redundant_guards)]
#![forbid(unsafe_code)]
//! Windows Thumbcache (`thumbcache_*.db`) parser exposed as a [`ForensicsModule`].
//!
//! Windows stores rendered thumbnails in per-size cache databases
//! (`thumbcache_32.db`, `thumbcache_256.db`, `thumbcache_1600.db`, ...). Each
//! file starts with a `CMMM` header followed by a run of `CMMM` cache entries,
//! one per cached thumbnail. This module emits one `ThumbcacheEntry` record per
//! entry: its 64-bit cache identifier, the (optional) identifier string, the
//! thumbnail byte size, and the detected image format (JPEG/PNG/BMP).
//!
//! The parser self-selects purely on the `CMMM` content magic (a
//! `thumbcache_*` basename is only a soft hint). It never panics on malformed
//! input: every field read is bounds-checked and any inconsistent entry is
//! skipped, returning fewer records rather than failing.
//!
//! Whenever the walk stops before the end of the loaded bytes -- entry cap, a
//! torn final entry, an unexpected signature, or an impossible entry size --
//! or the bytes loaded fall short of the file (`short_read` when the source
//! answered short, `file_read_capped` when the file is over the load cap) --
//! or steps over an entry whose size fields contradict each other, the module
//! emits one extra `ThumbcacheParseStatus` record carrying the standard
//! `content_incomplete` / `content_incomplete_reason` pair plus
//! `inventory_incomplete`. Without it a short listing is indistinguishable
//! from a machine that simply never rendered those thumbnails.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Value};
use tracing::warn;
use uuid::Uuid;

/// Signature shared by the file header and every cache entry.
const SIGNATURE: &[u8; 4] = b"CMMM";
/// Bytes of the entry header we read directly: signature(4) + cache_entry_size(4)
/// + entry_hash(8) + identifier_string_size(4) + padding_size(4) + data_size(4).
const ENTRY_HEADER_MIN: usize = 28;
/// The file header is 24 bytes (Vista/7). We locate the first entry by scanning
/// for the next `CMMM` at/after this offset rather than trusting header offsets.
const HEADER_SCAN_START: usize = 24;
/// Sane upper bound on entries parsed from one cache, guarding against loops.
const MAX_ENTRIES: usize = 100_000;
/// Cap on how many bytes we load from a single file.
const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;

/// Parses Windows Thumbcache (`thumbcache_*.db`) files.
pub struct ThumbcacheParser;

impl ForensicsModule for ThumbcacheParser {
    fn id(&self) -> &str {
        "plugin.windows.thumbcache"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileEntry,
            ArtifactType::FileContent,
            // A shadow-copy prior version only (HUNT-277).
            ArtifactType::ParsedRecord,
        ]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        seance_core::shadow_copy::parse_with_shadow_copy(artifact, |a| {
            Ok::<_, ModuleError>(parse(a))
        })
    }
}

/// Gate on the `CMMM` content magic, then parse all cache entries.
fn parse(artifact: &Artifact) -> Vec<Artifact> {
    if artifact
        .metadata
        .get("is_directory")
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        return Vec::new();
    }
    let Some(ds) = artifact.data.as_ref() else {
        return Vec::new();
    };
    let ds = ds.as_ref();

    // Content magic is authoritative: cheaply gate on "CMMM" before loading the
    // whole file (a "thumbcache_" basename is only a hint, not required here).
    let mut sig = [0u8; 4];
    if read_at_full(ds, 0, &mut sig) < 4 || &sig != SIGNATURE {
        return Vec::new();
    }

    let buf = read_all(ds);
    let mut scan = parse_entries(&buf, artifact.case_id, artifact.id);
    if let Some(shortfall) = load_shortfall(ds.size(), buf.len() as u64) {
        // The cache was larger than the load cap, or the source stopped early;
        // either way entries past that point were never examined, and the
        // record says which. A walk that stopped on a torn final entry at the
        // end of a short read stopped BECAUSE of the read: the torn entry is
        // not a fact about the file, so the read is the reason given.
        if scan.stopped.is_none()
            || (shortfall == "short_read" && scan.stopped == Some("truncated_final_entry"))
        {
            // A torn entry keeps the offset the walk gave up at (the entry's
            // start, where hand carving would begin).
            if scan.stopped.is_none() {
                scan.stopped_at_offset = Some(buf.len() as u64);
            }
            scan.stopped = Some(shortfall);
        }
    }

    let mut out = scan.entries;
    // Either the walk stopped short, or it stepped over entries it could not
    // make sense of. Both leave the inventory shorter than the cache.
    let reason = scan
        .stopped
        .or((scan.skipped > 0).then_some("inconsistent_entry_fields"));
    if let Some(reason) = reason {
        let entries_parsed = out.len();
        // A thumbcache shows which images existed on the machine, including
        // ones since deleted. A silently short walk turns "no thumbnail for
        // that picture" into an apparent fact; state the shortfall instead.
        warn!(
            "Thumbcache parse incomplete ({}): {} entries recovered, {} skipped",
            reason,
            out.len(),
            scan.skipped
        );
        out.push(
            Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "ThumbcacheParseStatus",
                    "record_type": "thumbcache_parse_status",
                    "name": "thumbcache (partially parsed)",
                    "content_incomplete": true,
                    "content_incomplete_reason": reason,
                    "inventory_incomplete": true,
                    "entries_parsed": entries_parsed,
                    "entries_skipped": scan.skipped,
                    "stopped_at_offset": scan.stopped_at_offset,
                    "max_entries": MAX_ENTRIES,
                    "message": "Thumbcache parsing stopped before the end of the cache: \
                                thumbnails past that point are absent from this case",
                }),
            )
            .with_parent(artifact.id),
        );
    }
    out
}

/// Result of walking a thumbcache: the entry records, plus why the walk
/// stopped early if it did and where.
///
/// Forensic meaning: a thumbnail proves an image was present on the machine
/// even after the image itself is gone. If the walk stops at a cap, a torn
/// entry, an unexpected signature or an impossible entry size and says
/// nothing, the missing thumbnails read as thumbnails that never existed.
/// `stopped_at_offset` is the byte offset within the loaded buffer at which
/// the walk gave up, so an examiner can carve the remainder by hand.
struct EntryScan {
    entries: Vec<Artifact>,
    stopped: Option<&'static str>,
    stopped_at_offset: Option<u64>,
    /// Entries the walk stepped over because their size fields contradict each
    /// other. The walk continues (the stride is still known), but each one is a
    /// thumbnail the cache holds and the case does not.
    skipped: usize,
}

/// True when every byte from `pos` to the end of `buf` is zero.
///
/// A thumbcache is grown in place, so the region after the last written entry
/// is normally zero fill. Zero fill is unambiguous free space and is NOT an
/// incomplete parse; anything else sitting where an entry header should be is
/// data this parser did not decode and must be reported as such.
fn rest_is_zero_fill(buf: &[u8], pos: usize) -> bool {
    buf.get(pos..)
        .is_none_or(|rest| rest.iter().all(|&b| b == 0))
}

/// Walk the `CMMM` entries, advancing by each entry's `cache_entry_size`.
fn parse_entries(buf: &[u8], case_id: Uuid, parent_id: Uuid) -> EntryScan {
    let Some(mut pos) = find_first_entry(buf) else {
        return EntryScan {
            entries: Vec::new(),
            stopped: None,
            stopped_at_offset: None,
            skipped: 0,
        };
    };

    let mut out = Vec::new();
    let mut stopped: Option<&'static str> = None;
    let mut stopped_at: Option<u64> = None;
    let mut skipped = 0usize;
    let mut count = 0usize;
    loop {
        // Enough bytes for the fixed header we read?
        match pos.checked_add(ENTRY_HEADER_MIN) {
            Some(end) if end <= buf.len() => {}
            _ => {
                // Fewer than a header's worth of bytes remain. Zero fill is the
                // cache's normal free space; a non-zero stub is the head of an
                // entry whose body never made it into the evidence.
                if !rest_is_zero_fill(buf, pos) {
                    stopped = Some("truncated_final_entry");
                    stopped_at = Some(pos as u64);
                }
                break;
            }
        }
        if &buf[pos..pos + 4] != SIGNATURE {
            // Not the entry signature. Later bytes may still hold entries this
            // walk will never reach (one corrupt entry, or a cache version
            // whose entry stride this parser computes differently), so the
            // shortfall has to be stated rather than read as "no more
            // thumbnails". Zero fill alone is free space, not a shortfall.
            if !rest_is_zero_fill(buf, pos) {
                stopped = Some("entry_signature_mismatch");
                stopped_at = Some(pos as u64);
            }
            break;
        }
        // Another entry was waiting when the cap was reached.
        if count >= MAX_ENTRIES {
            stopped = Some("entry_cap");
            stopped_at = Some(pos as u64);
            break;
        }

        let Some(cache_entry_size) = read_u32(buf, pos + 4).map(|v| v as usize) else {
            // Unreachable given the header bounds check above, but a silent
            // break here would be the same undetectable short walk.
            stopped = Some("entry_header_unreadable");
            stopped_at = Some(pos as u64);
            break;
        };
        if cache_entry_size < ENTRY_HEADER_MIN {
            // The entry declares a size smaller than its own header: the stride
            // to the next entry is unknowable, so the rest of the cache is
            // unreachable from here.
            stopped = Some("invalid_entry_size");
            stopped_at = Some(pos as u64);
            break;
        }
        let Some(entry_end) = pos.checked_add(cache_entry_size) else {
            stopped = Some("invalid_entry_size");
            stopped_at = Some(pos as u64);
            break;
        };
        if entry_end > buf.len() {
            // Truncated final entry: stop rather than read past the buffer, and
            // record that the cache did not end cleanly.
            stopped = Some("truncated_final_entry");
            stopped_at = Some(pos as u64);
            break;
        }

        let entry_hash = read_u64(buf, pos + 8).unwrap_or(0);
        let id_size = read_u32(buf, pos + 16).unwrap_or(0) as usize;
        let pad_size = read_u32(buf, pos + 20).unwrap_or(0) as usize;
        let data_size = read_u32(buf, pos + 24).unwrap_or(0) as usize;

        // Locate the identifier and data via the size fields (version-robust:
        // works regardless of how many fixed header fields a given Windows
        // version inserts before the identifier). `None` == inconsistent entry.
        let record = (|| -> Option<Artifact> {
            let sub_total = id_size.checked_add(pad_size)?.checked_add(data_size)?;
            // The three variable regions plus the fixed header must fit inside
            // the entry; otherwise the size fields are inconsistent.
            if sub_total.checked_add(ENTRY_HEADER_MIN)? > cache_entry_size {
                return None;
            }
            let data_start = entry_end.checked_sub(data_size)?;
            let id_start = entry_end.checked_sub(sub_total)?;

            let identifier = if id_size > 0 {
                slice(buf, id_start, id_size).and_then(decode_utf16le)
            } else {
                None
            };
            let image_format = detect_format(slice(buf, data_start, data_size));
            let hash_hex = format!("{entry_hash:016x}");

            let mut m = serde_json::Map::new();
            m.insert("type".into(), json!("ThumbcacheEntry"));
            m.insert("subtype".into(), json!("thumbcache"));
            m.insert("entry_hash".into(), json!(hash_hex));
            if let Some(id) = identifier {
                m.insert("identifier".into(), json!(id));
            }
            m.insert("data_size".into(), json!(data_size as u64));
            m.insert("image_format".into(), json!(image_format));
            m.insert("name".into(), json!(format!("thumbcache {hash_hex}")));

            Some(
                Artifact::new(case_id, ArtifactType::ParsedRecord, None, Value::Object(m))
                    .with_parent(parent_id),
            )
        })();

        match record {
            Some(r) => out.push(r),
            // The stride to the next entry is still known, so the walk goes on,
            // but this thumbnail is one the cache holds and the case will not.
            None => skipped += 1,
        }

        // `cache_entry_size >= ENTRY_HEADER_MIN > 0`, so this always advances.
        pos = entry_end;
        count += 1;
    }
    EntryScan {
        entries: out,
        stopped,
        stopped_at_offset: stopped_at,
        skipped,
    }
}

/// Scan for the first `CMMM` entry signature at/after the file header.
fn find_first_entry(buf: &[u8]) -> Option<usize> {
    let mut i = HEADER_SCAN_START;
    while i + 4 <= buf.len() {
        if &buf[i..i + 4] == SIGNATURE {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Classify thumbnail bytes by their leading magic.
fn detect_format(data: Option<&[u8]>) -> &'static str {
    match data {
        Some(d) if d.starts_with(&[0xFF, 0xD8, 0xFF]) => "jpeg",
        Some(d) if d.starts_with(&[0x89, 0x50, 0x4E, 0x47]) => "png",
        Some(d) if d.starts_with(&[0x42, 0x4D]) => "bmp",
        _ => "unknown",
    }
}

/// Decode a UTF-16LE identifier, trimming trailing NULs. Returns `None` when
/// empty after trimming.
fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    if units.is_empty() {
        return None;
    }
    let s = String::from_utf16_lossy(&units);
    let trimmed = s.trim_end_matches('\u{0}');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Bounds-checked `[start, start + len)` sub-slice (no overflow, no panic).
fn slice(buf: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    let end = start.checked_add(len)?;
    buf.get(start..end)
}

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let b = slice(buf, off, 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(buf: &[u8], off: usize) -> Option<u64> {
    let b = slice(buf, off, 8)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// Fill `buf` from `offset`, tolerating short reads; returns bytes filled.
fn read_at_full(ds: &dyn DataSource, offset: u64, buf: &mut [u8]) -> usize {
    let mut filled = 0usize;
    while filled < buf.len() {
        match ds.read_at(offset + filled as u64, &mut buf[filled..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => filled += n,
        }
    }
    filled
}

/// Read the whole source into memory (capped at [`MAX_FILE_BYTES`]).
fn read_all(ds: &dyn DataSource) -> Vec<u8> {
    let size = ds.size().min(MAX_FILE_BYTES);
    let mut buf = vec![0u8; size as usize];
    let filled = read_at_full(ds, 0, &mut buf);
    buf.truncate(filled);
    buf
}

/// Why fewer bytes were loaded than the file declares, if they were.
///
/// Two different facts (HUNT-197): `file_read_capped` means the file is larger
/// than [`MAX_FILE_BYTES`] and every byte up to the cap arrived, so the rest
/// was not read by this build's choice; `short_read` means the source handed
/// over fewer bytes than were asked for, so the rest could not be read.
fn load_shortfall(size: u64, loaded: u64) -> Option<&'static str> {
    let asked = size.min(MAX_FILE_BYTES);
    if loaded < asked {
        Some("short_read")
    } else if loaded < size {
        Some("file_read_capped")
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
