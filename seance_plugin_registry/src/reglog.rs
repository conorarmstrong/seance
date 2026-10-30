//! Registry transaction-log replay (`.LOG1` / `.LOG2`).
//!
//! A Windows registry hive acquired from a live or improperly-unmounted system is
//! frequently **dirty**: its most recent changes live only in the transaction logs
//! and have not yet been flushed into the primary file. This module detects that
//! condition (base-block sequence numbers + checksum) and, when valid logs are
//! reachable, replays the pending dirty pages into an in-memory copy of the hive
//! **before** the parser runs, so downstream extraction reflects the recovered
//! state rather than stale on-disk bytes.
//!
//! Both log formats are supported: the new-format `HvLE` logs (Windows 8.1+) and
//! the legacy `DIRT` logs (Vista .. Windows 8.0).
//!
//! # Forensic invariants
//!
//! - **Fail closed / never fabricate.** Every offset and length is bounds-checked.
//!   A bad Marvin32 hash, a page reference outside the hive, a sequence gap, or a
//!   grow past the cap stops the replay at that point; whatever was validly applied
//!   is kept, and the reason is recorded in [`ReplayProvenance`]. No byte is ever
//!   invented.
//! - **Honest provenance.** The result always records whether the hive was dirty,
//!   whether replay was attempted, whether it succeeded, and why / why not.

use std::borrow::Cow;
use std::collections::BTreeMap;

/// Start of the hive bins data in a primary hive; on-disk cell offsets are
/// relative to this position and log page references are rebased onto it.
const HBIN_BASE: usize = 0x1000;
/// Size of the base-block header region we read (signature .. checksum).
const BASE_BLOCK_MIN: usize = 0x200;
/// New-format (`HvLE`) log entries begin here, immediately after the 512-byte
/// log base block.
const LOG_ENTRY_START: usize = 0x200;
/// Fixed `HvLE` entry header length: signature, size, flags, sequence,
/// hive-bins-data size, dirty-page count, Hash-1, Hash-2.
const HVLE_HEADER_LEN: usize = 0x28; // 40
/// Offset of the checksum field inside the base block (XOR-32 of bytes 0..0x1FC).
const CHECKSUM_OFFSET: usize = 0x1FC;
/// The fixed Marvin32 seed Windows uses for registry log-entry hashing.
const MARVIN32_SEED: u64 = 0x82EF_4D88_7A4E_55C5;
/// Cap on the recovered hive buffer; a growing-hive log entry may not push the
/// buffer past this (mirrors the plugin's `MAX_HIVE_BYTES`).
const MAX_HIVE_BYTES: usize = 512 * 1024 * 1024;

/// Parsed registry base-block header (hive OR log). Only the fields we use.
#[derive(Debug, Clone)]
pub struct BaseBlock {
    pub primary_seq: u32,
    pub secondary_seq: u32,
    pub last_written: u64,
    pub file_type: u32, // 0 = primary hive, 1 = legacy log, 6 = new-format log
    pub hbins_size: u32,
    pub checksum_ok: bool,
}

impl BaseBlock {
    /// True when the primary hive is dirty and needs recovery: mismatched
    /// sequence numbers OR an invalid base-block checksum.
    fn dirty(&self) -> bool {
        self.primary_seq != self.secondary_seq || !self.checksum_ok
    }
}

/// One dirty-page reference inside an `HvLE` entry.
#[derive(Debug, Clone, Copy)]
struct DirtyPageRef {
    rel_offset: u32,
    size: u32,
}

/// One fully-parsed new-format (`HvLE`) log entry.
struct LogEntry {
    sequence: u32,
    hbins_size: u32,
    pages: Vec<DirtyPageRef>,
    /// Byte range, into the owning log buffer, of the concatenated page bodies.
    data_range: std::ops::Range<usize>,
    hash1_ok: bool,
    /// Which discovered log this entry came from (index into the logs vec), used
    /// to source the post-replay last-written timestamp.
    log_index: usize,
}

/// The outcome of a replay attempt — mirrored into the artifact's provenance
/// metadata by the caller. `log_files` is filled in by the caller (the byte-only
/// `recover_hive` API cannot know the on-disk names).
#[derive(Debug, Clone)]
pub struct ReplayProvenance {
    pub dirty: bool,
    pub attempted: bool,
    pub replayed: bool,
    pub reason: &'static str,
    pub log_format: &'static str,
    pub log_files: Vec<String>,
    pub primary_seq: u32,
    pub secondary_seq: u32,
    pub applied_start_seq: Option<u32>,
    pub applied_end_seq: Option<u32>,
    pub entries_applied: u32,
    pub pages_applied: u32,
    pub bytes_applied: u64,
    pub last_written_before: Option<String>,
    pub last_written_after: Option<String>,
    pub changed_key_paths: Vec<String>,
}

impl ReplayProvenance {
    fn base(reason: &'static str) -> Self {
        Self {
            dirty: false,
            attempted: false,
            replayed: false,
            reason,
            log_format: "none",
            log_files: Vec::new(),
            primary_seq: 0,
            secondary_seq: 0,
            applied_start_seq: None,
            applied_end_seq: None,
            entries_applied: 0,
            pages_applied: 0,
            bytes_applied: 0,
            last_written_before: None,
            last_written_after: None,
            changed_key_paths: Vec::new(),
        }
    }
}

/// Little-endian u32 read, `None` if out of range.
fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Little-endian u64 read, `None` if out of range.
fn rd_u64(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// XOR-32 base-block checksum over bytes `[0, 0x1FC)` (127 little-endian u32s).
/// Windows special-cases an all-zero result to `1` and an all-ones result to
/// `0xFFFFFFFE`; we reproduce that so a recomputed checksum matches Windows.
fn checksum_xor32(base_block: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut off = 0;
    while off + 4 <= CHECKSUM_OFFSET {
        // Bounds guaranteed by the loop condition; default 0 keeps it total.
        let word = rd_u32(base_block, off).unwrap_or(0);
        sum ^= word;
        off += 4;
    }
    match sum {
        0 => 1,
        0xFFFF_FFFF => 0xFFFF_FFFE,
        other => other,
    }
}

/// Parse a base-block header. Returns `None` if the buffer is too short or lacks
/// the `regf` signature.
pub fn parse_base_block(buf: &[u8]) -> Option<BaseBlock> {
    if buf.len() < BASE_BLOCK_MIN || &buf[0..4] != b"regf" {
        return None;
    }
    let primary_seq = rd_u32(buf, 0x04)?;
    let secondary_seq = rd_u32(buf, 0x08)?;
    let last_written = rd_u64(buf, 0x0C)?;
    let file_type = rd_u32(buf, 0x1C)?;
    let hbins_size = rd_u32(buf, 0x28)?;
    let stored_checksum = rd_u32(buf, CHECKSUM_OFFSET)?;
    let checksum_ok = checksum_xor32(buf) == stored_checksum;
    Some(BaseBlock {
        primary_seq,
        secondary_seq,
        last_written,
        file_type,
        hbins_size,
        checksum_ok,
    })
}

/// The `file_type` field (0x1C) of a `regf` buffer, if it parses. Used by the
/// plugin to suppress standalone parsing of `.LOG1`/`.LOG2` files, which share
/// the `regf` magic and would otherwise be mis-parsed as hives.
pub fn hive_file_type(buf: &[u8]) -> Option<u32> {
    parse_base_block(buf).map(|bb| bb.file_type)
}

/// True when a base-block `file_type` identifies a transaction log rather than a
/// primary hive (`0`).
///
/// `1` and `2` are both legacy (`DIRT`) logs — `2` is the very old variant seen
/// on pre-Vista hives — and `6` is the new-format (`HvLE`) log. Type `2` is
/// classified here rather than ignored so it is (a) suppressed as a standalone
/// "hive" record and (b) offered to the legacy replay path, which independently
/// requires a `DIRT` structure before it applies a single byte.
pub fn is_log_file_type(file_type: u32) -> bool {
    matches!(file_type, 1 | 2 | 6)
}

/// True when this log's base block declares the legacy (`DIRT`) format.
fn is_legacy_log(bb: &BaseBlock) -> bool {
    matches!(bb.file_type, 1 | 2)
}

/// Marvin32 hash with the given seed, returning the full 64-bit digest. Windows
/// registry log entries store this as two little-endian u64 hashes.
fn marvin32(data: &[u8], seed: u64) -> u64 {
    #[inline]
    fn rotl(v: u32, n: u32) -> u32 {
        v.rotate_left(n)
    }
    #[inline]
    fn mix(mut s0: u32, mut s1: u32) -> (u32, u32) {
        s1 ^= s0;
        s0 = rotl(s0, 20);
        s0 = s0.wrapping_add(s1);
        s1 = rotl(s1, 9);
        s1 ^= s0;
        s0 = rotl(s0, 27);
        s0 = s0.wrapping_add(s1);
        s1 = rotl(s1, 19);
        (s0, s1)
    }

    let mut lo = (seed & 0xFFFF_FFFF) as u32;
    let mut hi = (seed >> 32) as u32;

    // `as_chunks` gives the whole words and the tail in one split, which is
    // what this hash needs: every word is folded in, then the 0..3 leftover
    // bytes below carry the terminator.
    let (words, rem) = data.as_chunks::<4>();
    for &c in words {
        let val = u32::from_le_bytes(c);
        lo = lo.wrapping_add(val);
        let (a, b) = mix(lo, hi);
        lo = a;
        hi = b;
    }

    // Tail: 0..3 remaining bytes plus the 0x80 terminator.
    let mut fin: u32 = 0x80;
    if rem.len() == 3 {
        fin = (fin << 8) | rem[2] as u32;
    }
    if rem.len() >= 2 {
        fin = (fin << 8) | rem[1] as u32;
    }
    if !rem.is_empty() {
        fin = (fin << 8) | rem[0] as u32;
    }
    lo = lo.wrapping_add(fin);
    let (a, b) = mix(lo, hi);
    lo = a;
    hi = b;
    let (a, b) = mix(lo, hi);
    lo = a;
    hi = b;

    ((hi as u64) << 32) | lo as u64
}

/// Parse every `HvLE` entry from a new-format log, in file order. Parsing stops
/// at the first structurally-invalid entry or the first entry whose Hash-2 is
/// wrong (Hash-2 covering the header means a bad Hash-2 is not a valid entry at
/// all). Entries with a bad Hash-1 are still returned but flagged, so the apply
/// stage can stop *before* applying them (fail closed).
fn parse_hvle_entries(log: &[u8], log_index: usize) -> Vec<LogEntry> {
    let mut entries = Vec::new();
    let mut cur = LOG_ENTRY_START;

    while cur + HVLE_HEADER_LEN <= log.len() {
        if &log[cur..cur + 4] != b"HvLE" {
            break;
        }
        let size = match rd_u32(log, cur + 0x04) {
            Some(s) => s as usize,
            None => break,
        };
        // Size must be a positive multiple of 512 that stays inside the buffer.
        if size < HVLE_HEADER_LEN || size % 512 != 0 || cur + size > log.len() {
            break;
        }
        let sequence = rd_u32(log, cur + 0x0C).unwrap_or(0);
        let hbins_size = rd_u32(log, cur + 0x10).unwrap_or(0);
        let count = rd_u32(log, cur + 0x14).unwrap_or(0) as usize;
        let stored_hash1 = rd_u64(log, cur + 0x18).unwrap_or(0);
        let stored_hash2 = rd_u64(log, cur + 0x20).unwrap_or(0);

        // The page-reference table must fit within the entry.
        let refs_bytes = match count.checked_mul(8) {
            Some(b) => b,
            None => break,
        };
        if HVLE_HEADER_LEN + refs_bytes > size {
            break;
        }

        // Hash-2 covers bytes [0, 0x20) of the entry (header through Hash-1).
        let hash2 = marvin32(&log[cur..cur + 0x20], MARVIN32_SEED);
        if hash2 != stored_hash2 {
            // Not a valid entry: stop here (fail closed).
            break;
        }
        // Hash-1 covers everything from the first page reference to the end.
        let hash1 = marvin32(&log[cur + HVLE_HEADER_LEN..cur + size], MARVIN32_SEED);
        let hash1_ok = hash1 == stored_hash1;

        let mut pages = Vec::with_capacity(count);
        let mut ok = true;
        for i in 0..count {
            let ro = cur + HVLE_HEADER_LEN + i * 8;
            let rel_offset = rd_u32(log, ro).unwrap_or(0);
            let psize = rd_u32(log, ro + 4).unwrap_or(0);
            pages.push(DirtyPageRef {
                rel_offset,
                size: psize,
            });
        }
        // Page bodies occupy [header+refs, size); their total must equal Σ sizes.
        let body_start = cur + HVLE_HEADER_LEN + refs_bytes;
        let body_end = cur + size;
        let total: u64 = pages.iter().map(|p| p.size as u64).sum();
        if total > (body_end - body_start) as u64 {
            ok = false;
        }

        entries.push(LogEntry {
            sequence,
            hbins_size,
            pages,
            data_range: body_start..body_end,
            // A page table that overruns the body is a corrupt entry: treat like
            // a Hash-1 failure so the apply stage refuses it.
            hash1_ok: hash1_ok && ok,
            log_index,
        });

        cur += size;
    }

    entries
}

/// Grow `buf` (zero-filled) so it can address at least `needed` bytes, capped at
/// [`MAX_HIVE_BYTES`]. Returns `false` if the grow would exceed the cap (abort).
/// The newly-addressed bytes are immediately overwritten by a validated page, so
/// this is a region-grow, not fabrication.
fn ensure_capacity(buf: &mut Vec<u8>, needed: usize) -> bool {
    if needed > MAX_HIVE_BYTES {
        return false;
    }
    if needed > buf.len() {
        buf.resize(needed, 0);
    }
    true
}

/// Overwrite the base block's sequence numbers, hive-bins-data size, and checksum
/// so the recovered hive is internally consistent (matching what Windows writes
/// after its own replay).
fn patch_base_block(buf: &mut [u8], new_seq: u32, hbins_size: u32) {
    if buf.len() < BASE_BLOCK_MIN {
        return;
    }
    buf[0x04..0x08].copy_from_slice(&new_seq.to_le_bytes());
    buf[0x08..0x0C].copy_from_slice(&new_seq.to_le_bytes());
    buf[0x28..0x2C].copy_from_slice(&hbins_size.to_le_bytes());
    let checksum = checksum_xor32(buf);
    buf[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());
}

/// Windows FILETIME to RFC3339 via the canonical helper (rejects the 1601/unset
/// sentinel so a corrupt field never yields a fabricated timestamp).
fn ft(filetime: u64) -> Option<String> {
    seance_core::time::filetime_to_rfc3339(filetime)
}

/// Recover a possibly-dirty hive by replaying its transaction logs.
///
/// Returns the (possibly patched) hive bytes and a full provenance record. A
/// clean or no-op hive returns [`Cow::Borrowed`] (zero copy); a replayed hive
/// returns [`Cow::Owned`]. `log_files` on the provenance is left empty for the
/// caller to fill with on-disk names.
pub fn recover_hive<'a>(
    hive: &'a [u8],
    log1: Option<&[u8]>,
    log2: Option<&[u8]>,
) -> (Cow<'a, [u8]>, ReplayProvenance) {
    let bb = match parse_base_block(hive) {
        Some(bb) => bb,
        // Not a parseable base block; nothing to say, parse raw.
        None => return (Cow::Borrowed(hive), ReplayProvenance::base("clean")),
    };

    // A log file fed directly as a hive is not a primary hive; never replay.
    if bb.file_type != 0 {
        let mut prov = ReplayProvenance::base("not_a_primary_hive");
        prov.primary_seq = bb.primary_seq;
        prov.secondary_seq = bb.secondary_seq;
        return (Cow::Borrowed(hive), prov);
    }

    let mut prov = ReplayProvenance::base("clean");
    prov.primary_seq = bb.primary_seq;
    prov.secondary_seq = bb.secondary_seq;
    prov.dirty = bb.dirty();
    prov.last_written_before = ft(bb.last_written);

    // Collect valid logs (base block parses AND declares a log file type).
    let mut logs: Vec<(&[u8], BaseBlock)> = Vec::new();
    for l in [log1, log2].into_iter().flatten() {
        if let Some(lbb) = parse_base_block(l) {
            if is_log_file_type(lbb.file_type) {
                logs.push((l, lbb));
            }
        }
    }

    if logs.is_empty() {
        prov.reason = if prov.dirty { "no_logs_found" } else { "clean" };
        return (Cow::Borrowed(hive), prov);
    }

    prov.attempted = true;

    // The format is a property of each log, not of the pair: a hive carried
    // across a Windows upgrade can have a stale legacy `.LOG1` beside a live
    // new-format `.LOG2` (or the reverse). Split by declared type and run the
    // matching path; the `HvLE` logs take precedence because their sequence
    // chain is the stronger evidence, and the legacy logs are only consulted
    // when the new-format path applied nothing.
    let new_logs: Vec<(&[u8], BaseBlock)> = logs
        .iter()
        .filter(|(_, b)| b.file_type == 6)
        .cloned()
        .collect();
    let legacy_logs: Vec<(&[u8], BaseBlock)> = logs
        .iter()
        .filter(|(_, b)| is_legacy_log(b))
        .cloned()
        .collect();

    if !new_logs.is_empty() {
        let mut np = prov.clone();
        np.log_format = "new_hvle";
        let (out, np) = recover_new_format(hive, &bb, &new_logs, np);
        if np.replayed || legacy_logs.is_empty() {
            return (out, np);
        }
        // Nothing applied from the HvLE logs; the legacy leftovers still deserve
        // a look rather than being silently dropped.
    }

    prov.log_format = "legacy_dirt";
    recover_legacy_format(hive, &bb, &legacy_logs, prov)
}

/// New-format (`HvLE`) replay: collect entries across both logs, apply the
/// longest contiguous run beginning at `secondary_seq + 1`.
fn recover_new_format<'a>(
    hive: &'a [u8],
    bb: &BaseBlock,
    logs: &[(&[u8], BaseBlock)],
    mut prov: ReplayProvenance,
) -> (Cow<'a, [u8]>, ReplayProvenance) {
    // Gather candidate entries (seq strictly newer than the last committed one),
    // keyed by sequence. A BTreeMap keeps them sorted and dedups on tie (first
    // log wins, matching the discovery order).
    let mut by_seq: BTreeMap<u32, LogEntry> = BTreeMap::new();
    for (idx, (log, _)) in logs.iter().enumerate() {
        for e in parse_hvle_entries(log, idx) {
            if e.sequence <= bb.secondary_seq {
                continue; // already committed
            }
            by_seq.entry(e.sequence).or_insert(e);
        }
    }

    if by_seq.is_empty() {
        // Logs present but nothing newer than the hive: cannot resolve dirtiness.
        prov.reason = if prov.dirty { "logs_invalid" } else { "clean" };
        return (Cow::Borrowed(hive), prov);
    }

    let mut buf = hive.to_vec();
    let mut expected: u64 = bb.secondary_seq as u64 + 1;
    let mut last_applied: Option<u32> = None;
    let mut last_hbins = bb.hbins_size;
    let mut last_log_index = 0usize;

    #[derive(PartialEq)]
    enum Stop {
        End,
        Gap,
        HashMismatch,
        PageOutOfRange,
    }
    // Always assigned before it is read: every exit path from the loop below
    // sets the reason it stopped.
    let stop;

    loop {
        let seq = expected as u32;
        let entry = match by_seq.get(&seq) {
            Some(e) => e,
            None => {
                // No entry at the next expected sequence: gap if a higher one
                // exists, otherwise a clean end of chain.
                stop = if by_seq.keys().any(|&s| (s as u64) > expected) {
                    Stop::Gap
                } else {
                    Stop::End
                };
                break;
            }
        };
        if !entry.hash1_ok {
            stop = Stop::HashMismatch;
            break;
        }

        // Pre-validate the whole entry before touching the buffer, so a bad page
        // never leaves a partially-applied entry behind.
        let needed = HBIN_BASE + entry.hbins_size as usize;
        let mut cursor = entry.data_range.start;
        let mut ranges: Vec<(usize, usize, usize)> = Vec::with_capacity(entry.pages.len());
        let mut page_ok = true;
        for p in &entry.pages {
            let psize = p.size as usize;
            let file_off = HBIN_BASE + p.rel_offset as usize;
            let body_end = cursor + psize;
            if body_end > entry.data_range.end
                || file_off + psize > needed
                || needed > MAX_HIVE_BYTES
            {
                page_ok = false;
                break;
            }
            ranges.push((file_off, cursor, psize));
            cursor = body_end;
        }
        if !page_ok {
            stop = Stop::PageOutOfRange;
            break;
        }

        let log_bytes = logs[entry.log_index].0;
        if !ensure_capacity(&mut buf, needed) {
            stop = Stop::PageOutOfRange;
            break;
        }
        for (file_off, body_off, psize) in ranges {
            buf[file_off..file_off + psize].copy_from_slice(&log_bytes[body_off..body_off + psize]);
            prov.pages_applied += 1;
            prov.bytes_applied += psize as u64;
        }

        prov.entries_applied += 1;
        last_applied = Some(seq);
        last_hbins = entry.hbins_size;
        last_log_index = entry.log_index;
        expected += 1;
    }

    match last_applied {
        Some(seq) => {
            prov.replayed = true;
            prov.applied_start_seq = Some(bb.secondary_seq + 1);
            prov.applied_end_seq = Some(seq);
            patch_base_block(&mut buf, seq, last_hbins);
            prov.last_written_after = ft(logs[last_log_index].1.last_written);
            prov.reason = match stop {
                Stop::End => "recovered",
                Stop::Gap => "sequence_gap",
                Stop::HashMismatch => "hash_mismatch",
                Stop::PageOutOfRange => "page_out_of_range",
            };
            (Cow::Owned(buf), prov)
        }
        None => {
            prov.reason = match stop {
                Stop::Gap | Stop::End => "sequence_gap",
                Stop::HashMismatch => "hash_mismatch",
                Stop::PageOutOfRange => "page_out_of_range",
            };
            (Cow::Borrowed(hive), prov)
        }
    }
}

/// Legacy (`DIRT`) replay across every discovered legacy log.
///
/// A legacy log carries no sequence chain: it is a single snapshot of the pages
/// that were dirty during one (interrupted) sync, so nothing inside it limits
/// what gets applied the way the new-format path's `secondary_seq + 1` chain
/// does. The log's *eligibility* therefore has to be established up front, or an
/// older `.LOG` sitting beside a newer primary would silently revert pages and
/// still be stamped `recovered` — a hybrid state that never existed live.
///
/// Candidates are tried newest-first (by base-block `last_written`, the same key
/// yarp orders on), so a Vista..Win8 `.LOG1`/`.LOG2` pair replays the newer log
/// and falls back to the older one only when the newer is unusable.
fn recover_legacy_format<'a>(
    hive: &'a [u8],
    bb: &BaseBlock,
    logs: &[(&[u8], BaseBlock)],
    mut prov: ReplayProvenance,
) -> (Cow<'a, [u8]>, ReplayProvenance) {
    // A clean primary is already complete on disk; replaying a DIRT snapshot
    // over it can only take it backwards. (The new-format path needs no
    // equivalent gate: it applies entries strictly newer than the committed
    // sequence and is self-limiting.)
    if !bb.dirty() {
        prov.reason = "clean";
        return (Cow::Borrowed(hive), prov);
    }

    // Newest-first. `sort_by` is stable, so equal timestamps keep discovery
    // order (`.LOG1` before `.LOG2`).
    let mut order: Vec<usize> = (0..logs.len()).collect();
    order.sort_by(|&a, &b| logs[b].1.last_written.cmp(&logs[a].1.last_written));

    // Reported reason comes from the best (newest) candidate that was rejected.
    let mut first_reason: Option<&'static str> = None;
    for idx in order {
        let (log, lbb) = (logs[idx].0, &logs[idx].1);
        match apply_legacy_log(hive, bb, log, lbb, prov.clone()) {
            Ok(result) => return result,
            Err(reason) => {
                if first_reason.is_none() {
                    first_reason = Some(reason);
                }
            }
        }
    }

    prov.reason = first_reason.unwrap_or("no_logs_found");
    (Cow::Borrowed(hive), prov)
}

/// Try one legacy (`DIRT`) log against a dirty hive: read the dirty-page bitmap
/// and apply each set page (512 bytes) at `0x1000 + 512 * page_index`.
///
/// `Err(reason)` means the log was ineligible or unusable and **nothing** was
/// applied, so the caller may fall back to the other log. `Ok` carries the
/// patched buffer, including the partial-apply case (`page_out_of_range`).
fn apply_legacy_log<'a>(
    hive: &'a [u8],
    bb: &BaseBlock,
    log: &[u8],
    lbb: &BaseBlock,
    mut prov: ReplayProvenance,
) -> Result<(Cow<'a, [u8]>, ReplayProvenance), &'static str> {
    // The log's own base block must be intact. A failed checksum means the log
    // header was torn mid-write, so nothing behind it can be trusted. (Mismatched
    // sequence numbers inside a legacy log are *expected* — the base block is a
    // copy of the primary's, taken while the primary was mid-sync — so they are
    // not disqualifying on their own.)
    if !lbb.checksum_ok {
        return Err("log_base_block_invalid");
    }

    // Never apply a log that predates the primary. `last_written` is the primary
    // signal; the sequence number catches a leftover log from an earlier sync
    // whose timestamp is unset or equal. Replaying either would overwrite live
    // pages with stale ones.
    if lbb.last_written < bb.last_written || lbb.primary_seq < bb.secondary_seq {
        return Err("log_older_than_hive");
    }

    // "DIRT" signature at the start of sector 1 (0x200), then the bitmap.
    let dirt_off = LOG_ENTRY_START;
    if log.get(dirt_off..dirt_off + 4) != Some(b"DIRT") {
        return Err("logs_invalid");
    }

    // One bit per 512-byte page of hive bins data.
    let page_count = (lbb.hbins_size as usize) / 512;
    let bitmap_bytes = page_count.div_ceil(8);
    let bitmap_start = dirt_off + 4;
    let bitmap = match log.get(bitmap_start..bitmap_start + bitmap_bytes) {
        Some(b) => b,
        None => return Err("logs_invalid"),
    };

    // Dirty page bodies begin at the next 512-aligned offset after the bitmap.
    let mut body = (bitmap_start + bitmap_bytes).next_multiple_of(512);

    let mut buf = hive.to_vec();
    let mut ok = true;
    for p in 0..page_count {
        let byte = bitmap[p / 8];
        if byte & (1 << (p % 8)) == 0 {
            continue;
        }
        let file_off = HBIN_BASE + 512 * p;
        // Bounds-check the source page and grow the destination if the hive grew.
        if body + 512 > log.len() {
            ok = false;
            break;
        }
        if !ensure_capacity(&mut buf, file_off + 512) {
            ok = false;
            break;
        }
        buf[file_off..file_off + 512].copy_from_slice(&log[body..body + 512]);
        prov.pages_applied += 1;
        prov.bytes_applied += 512;
        body += 512;
    }

    if prov.pages_applied == 0 {
        // Nothing usable in this log: let the caller try the other one.
        return Err("logs_invalid");
    }

    prov.replayed = true;
    prov.entries_applied = 1;
    prov.applied_start_seq = Some(lbb.primary_seq);
    prov.applied_end_seq = Some(lbb.primary_seq);
    let new_hbins = lbb.hbins_size.max(bb.hbins_size);
    patch_base_block(&mut buf, lbb.primary_seq, new_hbins);
    prov.last_written_after = ft(lbb.last_written);
    // A truncated body mid-run is a partial recovery; keep what applied.
    prov.reason = if ok { "recovered" } else { "page_out_of_range" };
    Ok((Cow::Owned(buf), prov))
}

#[cfg(test)]
mod tests;
