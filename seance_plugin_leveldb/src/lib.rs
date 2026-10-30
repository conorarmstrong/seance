#![forbid(unsafe_code)]
//! Chrome/Edge LevelDB **Local/Session Storage** `.log` parser.
//!
//! Chromium stores `localStorage` / `sessionStorage` in a LevelDB, whose write-
//! ahead `.log` holds the most recent writes. [`LevelDbStorageParser`] parses the
//! `.log` framing and its `WriteBatch` records with pure byte operations (no
//! external LevelDB dependency), decodes the Chromium DOM-Storage key/value
//! schema, and emits one `LocalStorageItem`
//! [`ParsedRecord`](ArtifactType::ParsedRecord) per stored entry.
//!
//! # Formats (all little-endian)
//!
//! - **Log record**: 32 KiB blocks of `[u32 crc][u16 length][u8 type][data]`;
//!   a logical record is `FULL` or `FIRST (+MIDDLE)* +LAST` (types 1/2/3/4).
//! - **WriteBatch**: `[u64 sequence][u32 count]` then `count` × `[u8 tag]
//!   [varint32 klen][key] (put: [varint32 vlen][value])` (tag 1 = put, 0 = delete).
//! - **DOM-Storage key**: `_<origin>\x00<storage key>` for values, `META:<origin>`
//!   for per-origin metadata. Value bytes are prefixed with an encoding marker
//!   (`0x00` = UTF-16LE, `0x01` = Latin-1/UTF-8).
//!
//! Both LevelDB file types are handled: the write-ahead `.log` (live/recent
//! writes) and the compacted `.ldb`/`.sst` SSTables (the bulk/older data,
//! Snappy-decompressed via `snap`).
//!
//! # Scope & honesty
//!
//! The origin and value decoding follow the documented schema; the per-entry
//! storage-key sub-encoding is surfaced best-effort. Only records whose keys
//! match the DOM-Storage schema are emitted, so a non-storage file yields
//! nothing. Nothing panics.
//!
//! Every way this parser can stop short of the whole file — the [`MAX_LOG_BYTES`]
//! byte cap, a source that delivers fewer bytes than it declares, log framing or
//! SSTable structure that stops making sense partway through — is carried onto
//! the emitted records as `content_incomplete` and summarised in one
//! `LevelDbParseStatus` artifact. Without that, a prefix of a Local Storage
//! database yields a tidy list of keys and an examiner concludes the origins
//! past it never stored anything.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{read_capped, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::debug;
use uuid::Uuid;

const BLOCK_SIZE: usize = 32 * 1024;
const HEADER_SIZE: usize = 7;
/// Cap on how many bytes of the log to read (256 MiB).
const MAX_LOG_BYTES: u64 = 256 * 1024 * 1024;

pub struct LevelDbStorageParser;

impl ForensicsModule for LevelDbStorageParser {
    fn id(&self) -> &str {
        "plugin.browsers.leveldb_storage"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let Some(kind) = storage_file_kind(name, path) else {
            return Ok(Vec::new());
        };
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        // The bytes we actually got, and why they might not be all of them. A
        // 300 MiB Local Storage database read to 256 MiB parses perfectly and
        // silently omits everything after that point.
        let declared = data.size();
        let bytes = read_capped(data.as_ref(), MAX_LOG_BYTES);
        let mut incomplete: Option<IncompleteReason> = if (bytes.len() as u64) >= declared {
            None
        } else if declared > MAX_LOG_BYTES {
            Some(IncompleteReason::CapReached)
        } else {
            Some(IncompleteReason::ShortRead)
        };

        let entries: Vec<(Vec<u8>, Option<Vec<u8>>)> = match kind {
            // Write-ahead log: the recent writes.
            StorageKind::Log => {
                let (records, framing_ok) = read_log_records(&bytes);
                let mut batches_ok = true;
                let pairs: Vec<(Vec<u8>, Option<Vec<u8>>)> = records
                    .iter()
                    .flat_map(|r| {
                        let (pairs, ok) = parse_write_batch(r);
                        batches_ok &= ok;
                        pairs
                    })
                    .collect();
                if !(framing_ok && batches_ok) {
                    incomplete.get_or_insert(IncompleteReason::UnresolvedStructure);
                }
                pairs
            }
            // Compacted SSTable: the bulk / older data.
            StorageKind::Ldb => {
                let (pairs, structure_ok) = sstable_key_values(&bytes);
                if !structure_ok {
                    incomplete.get_or_insert(IncompleteReason::UnresolvedStructure);
                }
                pairs
            }
        };

        let mut out = Vec::new();
        for (key, value) in entries {
            if let Some(item) = decode_storage_entry(&key, value.as_deref()) {
                out.push(build_record(artifact.case_id, artifact.id, item));
            }
        }
        debug!(
            "LevelDbStorageParser: {} storage items from {}",
            out.len(),
            name
        );

        if let Some(reason) = incomplete {
            // Stamp the shortfall on every record so it travels with the data
            // wherever it is exported, then say it once at the file level. The
            // marker is the only thing standing between "this origin stored
            // nothing" and "we stopped reading before we got there" when the
            // truncation was deep enough to recover no records at all.
            // The sentence travels with the stamp, on the key the
            // examiner-facing reader displays
            // (`frontend/src/lib/incompleteness.ts` takes it from
            // `content_incomplete_detail` and reads nothing named `detail`).
            // A storage item marked "cap_reached" and nothing else leaves the
            // examiner to guess whether this value is partial or the list
            // around it is.
            let detail = incomplete_detail(reason, bytes.len() as u64, declared);
            for record in out.iter_mut() {
                if let Some(map) = record.metadata.as_object_mut() {
                    map.insert("content_incomplete".into(), json!(true));
                    map.insert("content_incomplete_reason".into(), json!(reason.as_str()));
                    map.insert("content_incomplete_detail".into(), json!(detail));
                }
            }
            out.push(incomplete_marker(
                artifact,
                name,
                reason,
                out.len(),
                bytes.len() as u64,
                declared,
            ));
        }

        Ok(out)
    }
}

/// The one sentence describing what was not read, written once so the per-record
/// stamp and the file-level marker cannot drift apart.
fn incomplete_detail(reason: IncompleteReason, bytes_read: u64, declared_size: u64) -> String {
    match reason {
        IncompleteReason::CapReached => format!(
            "the file is {declared_size} bytes, over the {MAX_LOG_BYTES}-byte parser cap; \
             only the first {bytes_read} bytes were parsed"
        ),
        IncompleteReason::ShortRead => format!(
            "the source declared {declared_size} bytes but delivered {bytes_read}; \
             the remainder could not be read"
        ),
        _ => format!(
            "the LevelDB framing stopped being parseable partway through \
             {bytes_read} bytes; entries after that point were not extracted"
        ),
    }
}

/// A record stating that a LevelDB storage file was only partly recovered.
///
/// What an examiner learns: how many items came out, how much of the file was
/// read, and why the rest was not. What a wrong answer would look like without
/// it: a complete-looking inventory of `localStorage` origins that stops at
/// 256 MiB, or at the first byte of damaged framing, with nothing to say so.
fn incomplete_marker(
    artifact: &Artifact,
    file_name: &str,
    reason: IncompleteReason,
    items_emitted: usize,
    bytes_read: u64,
    declared_size: u64,
) -> Artifact {
    let detail = incomplete_detail(reason, bytes_read, declared_size);
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("LevelDbParseStatus"));
    m.insert("subtype".into(), json!("local_storage_incomplete"));
    m.insert("browser".into(), json!("Chrome/Edge"));
    m.insert("file_name".into(), json!(file_name));
    m.insert("content_incomplete".into(), json!(true));
    m.insert("content_incomplete_reason".into(), json!(reason.as_str()));
    m.insert("items_emitted".into(), json!(items_emitted));
    m.insert("bytes_read".into(), json!(bytes_read));
    m.insert("declared_size".into(), json!(declared_size));
    m.insert("max_log_bytes".into(), json!(MAX_LOG_BYTES));
    // `content_incomplete_detail` is the key the examiner-facing reader shows;
    // `detail` is kept beside it for the consumers already on it.
    m.insert("content_incomplete_detail".into(), json!(detail.clone()));
    m.insert("detail".into(), json!(detail.clone()));
    m.insert(
        "name".into(),
        json!(format!(
            "LevelDB storage (partially parsed): {file_name} — {detail}"
        )),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(m),
    )
    .with_parent(artifact.id)
    .with_subtype("local_storage_incomplete")
}

/// A decoded DOM-Storage entry.
struct StorageItem {
    origin: String,
    key: String,
    value: Option<String>,
    deleted: bool,
}

/// Which LevelDB file this is: the write-ahead `.log` or a compacted `.ldb`.
enum StorageKind {
    Log,
    Ldb,
}

/// Gate: a `.log` / `.ldb` under a LevelDB / Local-Storage / Session-Storage
/// path. The path marker keeps the parser off unrelated `.log` files.
fn storage_file_kind(name: &str, path: &str) -> Option<StorageKind> {
    let p = path.to_ascii_lowercase();
    if !(p.contains("leveldb") || p.contains("local storage") || p.contains("session storage")) {
        return None;
    }
    let n = name.to_ascii_lowercase();
    if n.ends_with(".log") {
        Some(StorageKind::Log)
    } else if n.ends_with(".ldb") || n.ends_with(".sst") {
        Some(StorageKind::Ldb)
    } else {
        None
    }
}

/// Reassemble logical records from the LevelDB log's physical, block-framed
/// records. CRCs are not verified (extraction, not integrity checking).
///
/// Returns `(records, framing_intact)`. `framing_intact` is false when the walk
/// stopped on a record header that could not be believed, or ended holding an
/// unterminated FIRST/MIDDLE fragment: in both cases the entries in the rest of
/// the file were not read, and the caller must not present what came back as
/// the whole log.
fn read_log_records(data: &[u8]) -> (Vec<Vec<u8>>, bool) {
    let mut records = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    while pos + HEADER_SIZE <= data.len() {
        // Less than a header left in this block => block trailer padding.
        let block_off = pos % BLOCK_SIZE;
        if BLOCK_SIZE - block_off < HEADER_SIZE {
            pos += BLOCK_SIZE - block_off;
            continue;
        }
        let length = u16::from_le_bytes([data[pos + 4], data[pos + 5]]) as usize;
        let rtype = data[pos + 6];
        pos += HEADER_SIZE;
        if rtype == 0 {
            // Zero/padding record: skip to the next block.
            let bo = pos % BLOCK_SIZE;
            if bo != 0 {
                pos += BLOCK_SIZE - bo;
            }
            pending.clear();
            continue;
        }
        if length > BLOCK_SIZE || pos + length > data.len() {
            // Corrupt or truncated: whatever follows is unreachable.
            return (records, false);
        }
        let payload = &data[pos..pos + length];
        pos += length;
        match rtype {
            1 => {
                records.push(payload.to_vec());
                pending.clear();
            } // FULL
            2 => {
                pending.clear();
                pending.extend_from_slice(payload);
            } // FIRST
            3 => pending.extend_from_slice(payload), // MIDDLE
            4 => {
                pending.extend_from_slice(payload);
                records.push(std::mem::take(&mut pending));
            } // LAST
            // An undefined record type means the framing is no longer trusted.
            _ => return (records, false),
        }
    }
    // A FIRST/MIDDLE fragment with no LAST is a logical record the file was cut
    // in the middle of; its entries are lost.
    let intact = pending.is_empty();
    (records, intact)
}

/// Parse a WriteBatch into `(key, Some(value)|None)` pairs (None = deletion).
///
/// Returns `(pairs, complete)`. The batch header declares how many operations it
/// contains; `complete` is false when fewer than that were decoded, which means
/// the batch was cut short or malformed and the operations after the break —
/// stored keys, or the deletions that would show a key was removed — are absent.
/// A decoded write batch: each `(key, value)` with `None` for a deletion, and
/// whether the batch ended cleanly.
///
/// The flag is not decoration -- a batch that ran out mid-record yields the
/// entries it did decode, and a caller that ignored the flag would publish a
/// truncated batch as a complete one.
type WriteBatch = (Vec<(Vec<u8>, Option<Vec<u8>>)>, bool);

fn parse_write_batch(rec: &[u8]) -> WriteBatch {
    let mut out = Vec::new();
    if rec.len() < 12 {
        // Too short to even hold a batch header: nothing decodable here.
        return (out, false);
    }
    let count = u32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]) as usize;
    let mut pos = 12usize;
    for _ in 0..count {
        if pos >= rec.len() {
            break;
        }
        let tag = rec[pos];
        pos += 1;
        let Some((klen, np)) = read_varint32(rec, pos) else {
            break;
        };
        pos = np;
        if pos + klen > rec.len() {
            break;
        }
        let key = rec[pos..pos + klen].to_vec();
        pos += klen;
        match tag {
            1 => {
                // put
                let Some((vlen, np)) = read_varint32(rec, pos) else {
                    break;
                };
                pos = np;
                if pos + vlen > rec.len() {
                    break;
                }
                let value = rec[pos..pos + vlen].to_vec();
                pos += vlen;
                out.push((key, Some(value)));
            }
            0 => out.push((key, None)), // deletion
            _ => break,                 // unknown tag: stop this batch
        }
    }
    let complete = out.len() == count;
    (out, complete)
}

/// Read a LevelDB varint32 (LEB128). Returns `(value, new_pos)` or None.
///
/// A value too wide for 32 bits is **refused**, not truncated. The loop ran
/// `while shift < 32` and took a fifth byte at `shift = 28`, where
/// `(b & 0x7f) << 28` silently drops that byte's top three bits — so a length
/// of 2^32 read back as a small number, and the reader went on to use it as if
/// the file had said so.
fn read_varint32(data: &[u8], mut pos: usize) -> Option<(usize, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0u32;
    while shift < 32 {
        let b = *data.get(pos)?;
        pos += 1;
        let payload = (b & 0x7f) as u32;
        // The last byte that fits carries only `32 - shift` significant bits.
        if payload.checked_shl(shift).map(|v| v >> shift) != Some(payload) {
            return None;
        }
        result |= payload << shift;
        if b & 0x80 == 0 {
            return Some((result as usize, pos));
        }
        shift += 7;
    }
    None
}

/// The same, one byte wider, and refusing an over-wide value for the same
/// reason: at `shift = 63` a byte carries one significant bit and six that
/// would be dropped.
fn read_varint64(data: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    while shift < 64 {
        let b = *data.get(pos)?;
        pos += 1;
        let payload = (b & 0x7f) as u64;
        if payload.checked_shl(shift).map(|v| v >> shift) != Some(payload) {
            return None;
        }
        result |= payload << shift;
        if b & 0x80 == 0 {
            return Some((result, pos));
        }
        shift += 7;
    }
    None
}

// ── SSTable (.ldb) parsing ───────────────────────────────────────────────────
//
// A LevelDB SSTable ends with a 48-byte footer: two BlockHandles (metaindex,
// index) as varint (offset, size) pairs padded to 40 bytes, then an 8-byte
// magic. The index block points at data blocks; each data block holds
// prefix-compressed `InternalKey`/value entries followed by a restart array,
// then a 1-byte compression tag (0 = none, 1 = Snappy) and a 4-byte CRC.

const SSTABLE_MAGIC: u64 = 0xdb47_7524_8b80_fb57;
const FOOTER_LEN: usize = 48;

/// Extract `(user_key, Some(value)|None)` pairs from an SSTable. `None` marks a
/// deletion (the `InternalKey` type byte is 0).
///
/// Returns `(pairs, structure_intact)`. Every early exit here returns the same
/// empty vector — no footer magic, an unreadable index block, a data block that
/// will not decompress — and an empty SSTable returns it too. `structure_intact`
/// is what separates the two: false means "we could not read this table", which
/// must never be presented as "this table held no storage entries".
fn sstable_key_values(data: &[u8]) -> WriteBatch {
    if data.len() < FOOTER_LEN {
        return (Vec::new(), false);
    }
    let footer = &data[data.len() - FOOTER_LEN..];
    if u64::from_le_bytes(footer[40..48].try_into().unwrap()) != SSTABLE_MAGIC {
        return (Vec::new(), false);
    }
    // metaindex handle (skipped) then the index handle.
    let Some((_mi_off, _mi_size, np)) = read_block_handle(footer, 0) else {
        return (Vec::new(), false);
    };
    let Some((idx_off, idx_size, _)) = read_block_handle(footer, np) else {
        return (Vec::new(), false);
    };
    let Some(index_block) = read_block(data, idx_off, idx_size) else {
        return (Vec::new(), false);
    };

    let mut out = Vec::new();
    let (index_entries, mut intact) = parse_block(&index_block);
    for (_ikey, handle) in index_entries {
        let Some((doff, dsize, _)) = read_block_handle(&handle, 0) else {
            // A data block we cannot even locate: its keys are lost.
            intact = false;
            continue;
        };
        let Some(block) = read_block(data, doff, dsize) else {
            // Out of range, or Snappy that will not decompress.
            intact = false;
            continue;
        };
        let (entries, block_intact) = parse_block(&block);
        intact &= block_intact;
        for (key, value) in entries {
            if key.len() < 8 {
                // An InternalKey shorter than its own 8-byte trailer: the entry
                // cannot be attributed to a user key at all.
                intact = false;
                continue;
            }
            let user_key = key[..key.len() - 8].to_vec();
            // InternalKey trailer = (sequence << 8) | type, little-endian, so the
            // type byte is the first of the 8-byte trailer. 0 = deletion.
            let vtype = key[key.len() - 8];
            if vtype == 0 {
                out.push((user_key, None));
            } else {
                out.push((user_key, Some(value)));
            }
        }
    }
    (out, intact)
}

/// Parse a BlockHandle `(offset, size)` pair of varint64s.
fn read_block_handle(buf: &[u8], pos: usize) -> Option<(usize, usize, usize)> {
    let (off, p1) = read_varint64(buf, pos)?;
    let (size, p2) = read_varint64(buf, p1)?;
    Some((off as usize, size as usize, p2))
}

/// Read a block's contents (excluding its 5-byte trailer), decompressing Snappy.
fn read_block(data: &[u8], offset: usize, size: usize) -> Option<Vec<u8>> {
    let end = offset.checked_add(size)?;
    if end >= data.len() {
        return None; // need the trailer's compression byte
    }
    let raw = &data[offset..end];
    match data[end] {
        0 => Some(raw.to_vec()),
        1 => snap::raw::Decoder::new().decompress_vec(raw).ok(),
        _ => None,
    }
}

/// Parse a LevelDB block's prefix-compressed key/value entries.
///
/// Returns `(entries, intact)`. Entries are prefix-compressed against their
/// predecessor, so the first unreadable varint makes every entry after it
/// undecodable as well — `intact` is false whenever the walk did not reach the
/// end of the entry region, and the caller must not report the prefix it did
/// decode as the block's whole contents.
/// A decoded block: its `(key, value)` entries and whether it ended cleanly.
type BlockEntries = (Vec<(Vec<u8>, Vec<u8>)>, bool);

fn parse_block(block: &[u8]) -> BlockEntries {
    if block.len() < 4 {
        return (Vec::new(), false);
    }
    let num_restarts = u32::from_le_bytes(block[block.len() - 4..].try_into().unwrap()) as usize;
    let Some(restart_bytes) = num_restarts.checked_mul(4) else {
        return (Vec::new(), false);
    };
    if block.len() < 4 + restart_bytes {
        return (Vec::new(), false);
    }
    let entries_end = block.len() - 4 - restart_bytes;

    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut prev_key: Vec<u8> = Vec::new();
    while pos < entries_end {
        let Some((shared, p1)) = read_varint32(block, pos) else {
            return (out, false);
        };
        let Some((non_shared, p2)) = read_varint32(block, p1) else {
            return (out, false);
        };
        let Some((vlen, p3)) = read_varint32(block, p2) else {
            return (out, false);
        };
        pos = p3;
        if shared > prev_key.len() || pos + non_shared + vlen > entries_end {
            return (out, false);
        }
        let mut key = prev_key[..shared].to_vec();
        key.extend_from_slice(&block[pos..pos + non_shared]);
        pos += non_shared;
        let value = block[pos..pos + vlen].to_vec();
        pos += vlen;
        prev_key = key.clone();
        out.push((key, value));
    }
    (out, true)
}

/// Decode a Chromium DOM-Storage key/value into a [`StorageItem`], or `None` if
/// the key isn't a storage value entry (`_<origin>\0<key>`).
fn decode_storage_entry(key: &[u8], value: Option<&[u8]>) -> Option<StorageItem> {
    // Data keys start with '_' (0x5f); META:/VERSION keys carry no user value.
    if key.first() != Some(&b'_') {
        return None;
    }
    let nul = key.iter().position(|&b| b == 0)?;
    let origin = String::from_utf8_lossy(&key[1..nul]).into_owned();
    if origin.is_empty() {
        return None;
    }
    let storage_key = String::from_utf8_lossy(&key[nul + 1..]).into_owned();
    Some(StorageItem {
        origin,
        key: storage_key,
        value: value.map(decode_value),
        deleted: value.is_none(),
    })
}

/// Decode a DOM-Storage value: byte 0 is the encoding marker.
fn decode_value(v: &[u8]) -> String {
    match v.first() {
        Some(0) => {
            let u16s: Vec<u16> = v[1..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&u16s)
        }
        Some(1) => String::from_utf8_lossy(&v[1..]).into_owned(),
        Some(_) => String::from_utf8_lossy(v).into_owned(),
        None => String::new(),
    }
}

fn build_record(case_id: Uuid, parent_id: Uuid, item: StorageItem) -> Artifact {
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("LocalStorageItem"));
    m.insert("subtype".into(), json!("local_storage"));
    m.insert("browser".into(), json!("Chrome/Edge"));
    m.insert("origin".into(), json!(item.origin));
    m.insert("storage_key".into(), json!(item.key));
    m.insert("deleted".into(), json!(item.deleted));
    if let Some(v) = item.value {
        m.insert("value".into(), json!(v));
    }
    m.insert(
        "name".into(),
        json!(format!("localStorage {} [{}]", item.origin, item.key)),
    );
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(m),
    )
    .with_parent(parent_id)
    .with_subtype("local_storage")
}

#[cfg(test)]
mod tests;
