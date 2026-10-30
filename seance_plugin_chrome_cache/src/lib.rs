#![forbid(unsafe_code)]
//! Chrome/Edge disk-cache parser ("Simple" and legacy "blockfile" formats).
//!
//! [`ChromeCacheParser`] recovers the **cached URL** of each entry — the
//! primary forensic value: what the browser fetched — content-gated on the
//! header magic so it self-selects regardless of the hash-based filenames.
//! **It recovers no cached content.** Nothing here reads a Simple Cache
//! entry past its key, and the blockfile path reads neither
//! `data_stream_sizes` nor `data_stream_addresses`, so the response body a
//! browser stored is not produced by this module.
//!
//! # Simple Cache (modern default: Android/Linux, newer desktop)
//!
//! Each cached resource is its own file `<hash>_0`, opening with a fixed
//! `SimpleFileHeader` (little-endian, from Chromium `simple_entry_format.h`):
//!
//! ```text
//! u64 initial_magic_number (0xfcfb6d1ba7725c30); u32 version; u32 key_length;
//! u32 key_hash;   // 20 bytes, then `key_length` bytes of key (the URL)
//! ```
//!
//! # Blockfile cache (legacy: older Chrome, IE/Edge disk cache)
//!
//! `data_#` files start with an 8 KiB `BlockFileHeader` (magic `0xC104CAC3`,
//! the file's own index at offset 8, its block size at 12, its allocation count
//! at 16 and its allocation bitmap from 80) followed by the blocks. Chromium
//! allocates every `EntryStore` from a 256-byte block file, so only a file whose
//! header declares 256-byte blocks is walked for entries — `data_0` (rankings)
//! and the 1 KiB / 4 KiB files hold rankings, long keys and stream data and
//! yield nothing of their own, and a block size no block file has is reported,
//! not walked at a guessed stride. In an `EntryStore` the key hash is at offset
//! 0, the creation time at 24, the key length at 32 and the key at 96.
//!
//! A block is taken as an entry when its key **hashes** (SuperFastHash,
//! `disk_cache::Hash`) to the value at offset 0 and carries the NUL Chromium
//! writes after it (HUNT-145); every record says `key_hash_verified`. A key
//! that does not verify is still read when it is NUL-terminated and has a form
//! Chromium writes — a damaged entry is still evidence of a fetch — and is
//! stamped as unverified. Each record also says whether the allocation bitmap
//! marks its blocks `allocated`, `free` (an evicted or deleted entry whose bytes
//! survive) or `partly_free`.
//!
//! # Key forms (HUNT-185)
//!
//! The key is the URL in older caches. A network-isolation-keyed ("split")
//! cache writes `1/0/_dk_<top-frame site> <frame site> <url>` (`_dk_s_` for a
//! subframe document resource), and a sparse entry's children are
//! `Range_<key>:<signature>:<child>`. These are taken apart: the record
//! carries the URL, `top_frame_site`, `frame_site`, the key as stored
//! (`cache_key`) and its form (`cache_key_form`). A key that verifies by its
//! hash but is in a form this module does not recognise is published without
//! a URL, showing the key as stored, and counted
//! (`entries_key_form_not_recognised`) — never guessed at, never dropped.
//!
//! A key of 160 bytes or more does not fit the first block. Up to
//! [`MAX_INTERNAL_KEY_LEN`] Chromium continues it into the following blocks of
//! the same file, which this scan reads (see [`blocks_for_key`]) — long URLs
//! are exactly the ones carrying query strings and tracking parameters. Beyond
//! that the key moves to the block the `long_key` cache address at offset 36
//! names. That address carries the file it lives in, and it is very often *this*
//! file — Chromium sizes the key's own allocation from its length, so a key of
//! 928..1023 bytes is written back into the same 256-byte block file the entry
//! itself came from. [`locate_long_key`] resolves those and recovers the URL.
//! The rest name another `data_#` — a 1 KiB or 4 KiB block file for keys of
//! 1,023 bytes and over — or an external `f_` file. For a sibling `data_#` the
//! parser asks the [`DataSource`] it was handed for that file by name
//! ([`DataSource::open_relative`]), checks the file's own header says it is
//! the block file the address names, and reads the key from there; the record
//! then says which file and block the URL came from. Where the source cannot
//! look beside itself, the sibling is not there, or its bytes do not hold the
//! key, the entry is still published — without a URL, and naming the file,
//! block and byte offset where the key is — so an examiner can go and read it.
//! An external `f_` file is never opened by this module; the entry names it
//! the same way.
//!
//! # Honesty & robustness
//!
//! A file whose magic does not match either cache format yields an empty result
//! and nothing else — it is not a cache. A file that *is* a cache and was read
//! short, or read under a cap, is a different answer and gets a
//! `BrowserCacheParseStatus` record saying so. **One case is not
//! distinguishable from the first:** a recognised `data_#` read whole whose
//! blocks hold no entry — an all-free cache file among them — yields an empty
//! result only when its header declares no allocations; one that declares
//! allocations and yields nothing gets a record saying so. The records it does
//! emit cover: the [`MAX_CACHE_BYTES`] scan cap,
//! a source that delivers fewer bytes than it declares, a Simple Cache entry
//! cut off inside its own header or whose declared key runs past the end of the
//! file, or blockfile entries whose
//! URL is stored outside the file and could not be reached
//! (`long_key_entries_unresolved`) or cut off by
//! the end of the scan (`spanning_key_entries_truncated`). Key lengths are
//! bounds-checked against the file. Nothing panics.
//!
//! A key whose bytes are not valid UTF-8 is damaged, not absent: in either
//! format its URL is recovered with the invalid bytes substituted and the
//! record carries `url_encoding_lossy` alongside the incompleteness pair, so
//! the substituted characters are never read as ones the browser requested.
//!
//! What a wrong answer would look like without that record: a 700 MiB `data_1`
//! scanned to 512 MiB, presenting a clean list of cached URLs from which an
//! examiner concludes a site was never fetched.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
    time::webkit_us_to_unix_secs,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;
use uuid::Uuid;

/// `SimpleFileHeader::initial_magic_number`.
const SIMPLE_MAGIC: u64 = 0xfcfb_6d1b_a772_5c30;
/// Header is 20 bytes; the key follows.
const HEADER_LEN: usize = 20;
/// Reject absurd key lengths (a cache key is a URL).
const MAX_KEY_LEN: usize = 64 * 1024;

/// `BlockFileHeader::magic` for the older multi-file "blockfile" cache:
/// Chromium's `disk_cache::kBlockMagic`, and the `signature` the dtFabric
/// specification for `chrome_cache_data_block_file_header` pins at the same
/// value (`reference/plaso/plaso/parsers/chrome_cache.yaml`).
///
/// This was `0xC0F0`, which is not a value Chromium has ever written. No real
/// `data_#` file matched it, so the whole blockfile branch below was unreachable
/// on evidence and every legacy Chrome / EdgeHTML cache fell through to the
/// "this is not a cache" empty result — the one answer this parser must never
/// give to a file it cannot read. The crate's own tests built their fixtures
/// from this constant, so they passed either way; the test that pins it now
/// spells the value out.
const BLOCK_MAGIC: u32 = 0xC104_CAC3;
/// The `BlockFileHeader` occupies the first 8 KiB of a `data_#` file.
const BLOCK_HEADER_SIZE: usize = 8192;
/// `BlockFileHeader::this_file`: the index of this block file, so `data_3` says
/// 3. [`locate_long_key`] compares a cache address's file selector against it to
/// tell "the key is in the file we were handed" from "the key is in another
/// one".
const BFH_THIS_FILE: usize = 8;
/// `BlockFileHeader::entry_size`: the byte size of one block in this file
/// (256, 1024 or 4096). Read from a sibling's header before a key is taken from
/// it, so a file that is not the block file the address names is not read.
const BFH_ENTRY_SIZE: usize = 12;
/// `BlockFileHeader::allocation_map`: one bit per block, block `i` at bit
/// `i % 32` of little-endian word `i / 32` — equivalently bit `i % 8` of byte
/// `i / 8` — set while the block is allocated. It runs to the end of the
/// 8 KiB header.
const BFH_ALLOCATION_MAP: usize = 80;
/// `EntryStore::hash`: `disk_cache::Hash(key)`, SuperFastHash of the key.
const ES_HASH: usize = 0;
/// `disk_cache::Addr::kFileNameMask`: the low 28 bits of an external-file
/// address are the number in its `f_%06x` name.
const ADDR_FILE_NAME: u32 = 0x0fff_ffff;
/// One `EntryStore` record is 256 bytes; the inline key starts at offset 96.
const ENTRY_STORE_SIZE: usize = 256;
const ES_CREATION_TIME: usize = 24; // u64 microseconds since 1601
const ES_KEY_LEN: usize = 32; // i32
const ES_LONG_KEY: usize = 36; // CacheAddr of a key held outside the entry
const ES_KEY: usize = 96; // key bytes start here
const ES_KEY_MAX_INLINE: usize = ENTRY_STORE_SIZE - ES_KEY; // 160
/// Chromium `kMaxInternalKeyLength`: `4 * sizeof(EntryStore) - offsetof(key) - 1`.
/// The longest key still stored in the entry's own (up to four) blocks; a longer
/// one is written at the `long_key` cache address instead.
const MAX_INTERNAL_KEY_LEN: usize = 4 * ENTRY_STORE_SIZE - ES_KEY - 1; // 927
/// `disk_cache::Addr::kInitializedMask`. An address without it points nowhere.
const ADDR_INITIALIZED: u32 = 0x8000_0000;
/// `disk_cache::Addr` file-type field (bits 28-30): 0 is an external `f_` file,
/// 1-4 are the `data_#` block files (rankings / 256 / 1K / 4K blocks).
const ADDR_FILE_TYPE: u32 = 0x7000_0000;
/// The highest defined file type (`FILE_TYPE_BLOCK_4096`).
const ADDR_FILE_TYPE_MAX: u32 = 4;
/// `disk_cache::Addr` file-selector field (bits 16-23): which `data_#` file a
/// block-file address lives in.
const ADDR_FILE_SELECTOR: u32 = 0x00ff_0000;
/// `disk_cache::Addr` block-count field (bits 24-25), holding `n - 1`.
const ADDR_NUM_BLOCKS: u32 = 0x0300_0000;
/// `disk_cache::Addr` start-block field (bits 0-15).
const ADDR_START_BLOCK: u32 = 0x0000_ffff;
/// Bits 26-27 belong to no field of a block-file address and are zero in one
/// Chromium wrote (`Addr::SanityCheck` rejects a non-zero value there).
const ADDR_RESERVED: u32 = 0x0C00_0000;
/// Cap on how many bytes of a block file to scan (512 MiB).
const MAX_CACHE_BYTES: u64 = 512 * 1024 * 1024;

pub struct ChromeCacheParser;

impl ForensicsModule for ChromeCacheParser {
    fn id(&self) -> &str {
        "plugin.browsers.chrome_cache"
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
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(Vec::new());
        }
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        let file_name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Read enough to identify the cache format by its header magic.
        let mut head = [0u8; HEADER_LEN];
        let n = read_at_full(data.as_ref(), 0, &mut head);
        if n < 4 {
            return Ok(Vec::new());
        }

        // Simple Cache: each entry is its own file, keyed by its URL.
        if n >= 8 && u64::from_le_bytes(head[0..8].try_into().unwrap()) == SIMPLE_MAGIC {
            if n < HEADER_LEN {
                // The magic matched, so this IS a cache entry, and it stops
                // inside its own 20-byte header: the URL cannot be recovered.
                // That is a finding, not the empty result a non-cache gets.
                return Ok(vec![parse_status(
                    artifact.case_id,
                    artifact.id,
                    file_name,
                    "simple",
                    IncompleteReason::ShortRead,
                    0,
                    n as u64,
                    data.size(),
                    format!(
                        "the Simple Cache magic matched but only {n} of the {HEADER_LEN} \
                         header bytes could be read; the cached URL is not recoverable"
                    ),
                )]);
            }
            return Ok(parse_simple_entry(
                data.as_ref(),
                &head,
                artifact.case_id,
                artifact.id,
                file_name,
            ));
        }

        // Blockfile cache: a data_# file starts with the block-file magic.
        if u32::from_le_bytes(head[0..4].try_into().unwrap()) == BLOCK_MAGIC {
            return Ok(parse_blockfile(
                data.as_ref(),
                artifact.case_id,
                artifact.id,
                file_name,
            ));
        }

        Ok(Vec::new())
    }
}

/// The record that says a file which IS a Chrome cache was not recovered whole.
///
/// What an examiner learns: which cache format, how many URLs came out, how much
/// of the file was read and why the rest was not. It is emitted only after the
/// format magic has matched, so an unrelated file never produces one. The
/// converse does not hold: an empty result means either "not a cache" or "a
/// cache read whole in which no entry's key could be read", and this module
/// cannot always tell those apart: the header's allocation count (offset 16)
/// counts stream data as well as entries, so it separates them only when it is
/// zero.
#[allow(clippy::too_many_arguments)]
fn parse_status(
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
    cache_format: &str,
    reason: IncompleteReason,
    entries_recovered: usize,
    bytes_read: u64,
    declared_size: u64,
    detail: String,
) -> Artifact {
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("BrowserCacheParseStatus"));
    m.insert("subtype".into(), json!("browser_cache_incomplete"));
    m.insert("browser".into(), json!("Chrome/Edge"));
    m.insert("cache_format".into(), json!(cache_format));
    m.insert("file_name".into(), json!(file_name));
    m.insert("content_incomplete".into(), json!(true));
    m.insert("content_incomplete_reason".into(), json!(reason.as_str()));
    m.insert("entries_recovered".into(), json!(entries_recovered));
    m.insert("bytes_read".into(), json!(bytes_read));
    m.insert("declared_size".into(), json!(declared_size));
    m.insert("max_cache_bytes".into(), json!(MAX_CACHE_BYTES));
    // The sentence has to land on the key the examiner-facing reader shows.
    // `frontend/src/lib/incompleteness.ts` takes it from
    // `content_incomplete_detail` and reads nothing named `detail`, so a status
    // record carrying only the latter reached the examiner as the bare token
    // "cap_reached" — never which file, how much of it was read, or what is
    // therefore missing from the URL listing. `detail` stays beside it for the
    // consumers already on it.
    m.insert("content_incomplete_detail".into(), json!(detail.clone()));
    m.insert("detail".into(), json!(detail.clone()));
    m.insert(
        "name".into(),
        json!(format!(
            "Browser cache (partially parsed): {file_name} — {detail}"
        )),
    );
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(m),
    )
    .with_parent(parent_id)
    .with_subtype("browser_cache_incomplete")
}

/// Build the record for one Simple Cache entry (`head` starts with the magic).
///
/// The magic has already matched, so this file IS a cache entry. Every way of
/// failing to recover its URL therefore returns a status record rather than an
/// empty vector: "this entry's URL could not be read" and "there was no cached
/// entry here" are different findings and must not render the same.
fn parse_simple_entry(
    data: &dyn DataSource,
    head: &[u8; HEADER_LEN],
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
) -> Vec<Artifact> {
    let version = u32::from_le_bytes(head[8..12].try_into().unwrap());
    let key_length = u32::from_le_bytes(head[12..16].try_into().unwrap()) as usize;
    let key_hash = u32::from_le_bytes(head[16..20].try_into().unwrap());
    let declared = data.size();
    let unreadable = |reason: IncompleteReason, detail: String| {
        vec![parse_status(
            case_id,
            parent_id,
            file_name,
            "simple",
            reason,
            0,
            declared.min(HEADER_LEN as u64),
            declared,
            detail,
        )]
    };
    if key_length == 0 || key_length > MAX_KEY_LEN {
        return unreadable(
            IncompleteReason::UnresolvedStructure,
            format!(
                "the Simple Cache header declares a {key_length}-byte key, which is not a \
                 plausible URL length; the cached URL could not be recovered"
            ),
        );
    }
    if (HEADER_LEN + key_length) as u64 > declared {
        return unreadable(
            IncompleteReason::ShortRead,
            format!(
                "the Simple Cache header declares a {key_length}-byte key but the file is \
                 only {declared} bytes; the cached URL is not present"
            ),
        );
    }
    let mut key = vec![0u8; key_length];
    let got = read_at_full(data, HEADER_LEN as u64, &mut key);
    if got < key_length {
        return unreadable(
            IncompleteReason::ShortRead,
            format!(
                "the source supplied {got} of the {key_length} key bytes; the cached URL \
                 could not be recovered"
            ),
        );
    }
    let (url, lossy) = decode_key(&key);
    debug!("ChromeCacheParser: simple-cache URL {url}");
    let metadata = json!({
        "type": "BrowserCacheEntry",
        "subtype": "browser_cache_entry",
        "browser": "Chrome/Edge",
        "cache_format": "simple",
        "version": version,
        "key_hash": format!("{key_hash:08x}"),
        "url": url,
        "name": format!("Cached URL: {url}"),
    });
    let mut record = Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
        .with_parent(parent_id)
        .with_subtype("browser_cache_entry");
    if lossy {
        stamp_lossy(&mut record);
    }
    vec![record]
}

/// Decode a cache key to a URL, reporting whether bytes had to be substituted.
///
/// Cache keys are URLs and so are ASCII; bytes that are not valid UTF-8 mean the
/// key is damaged. The lossy conversion puts U+FFFD where those bytes were, so
/// the string that comes out is **not** the URL the browser fetched. Returning
/// it is right — a damaged URL is still evidence of a fetch — but presenting it
/// as an exact one is not, hence the flag.
fn decode_key(key: &[u8]) -> (String, bool) {
    match std::str::from_utf8(key) {
        Ok(s) => (s.to_owned(), false),
        Err(_) => (String::from_utf8_lossy(key).into_owned(), true),
    }
}

/// Mark a recovered entry whose URL contains substituted bytes.
///
/// The sentence goes on `content_incomplete_detail`, the key the
/// examiner-facing reader displays: "unresolved structure" on a URL record does
/// not tell anyone that the URL in front of them has characters in it the
/// browser never asked for.
fn stamp_lossy(record: &mut Artifact) {
    if let Some(map) = record.metadata.as_object_mut() {
        map.insert("url_encoding_lossy".into(), json!(true));
        map.insert("content_incomplete".into(), json!(true));
        map.insert(
            "content_incomplete_reason".into(),
            json!(IncompleteReason::UnresolvedStructure.as_str()),
        );
        map.insert(
            "content_incomplete_detail".into(),
            json!(
                "the stored cache key holds bytes that are not valid UTF-8; the URL shown \
                 carries a replacement character where each of them was, so it is not exactly \
                 the URL the browser requested"
            ),
        );
    }
}

/// Scan a blockfile `data_#` file for `EntryStore` records and recover the URL
/// key of each: keys held inside the entry, keys that continue past the first
/// 256-byte block into the entry's following blocks, and keys written to the
/// separate `long_key` address when that address names this same file (see
/// [`locate_long_key`]).
///
/// A key in another `data_#` is read from that file when the source can open
/// it by name beside this one (see [`SiblingBlockFiles`]); the record then
/// names the file, block and byte offset it came from.
///
/// Three things make the resulting listing shorter than the file's real entry
/// set, and each of them is reported rather than left to look like absence:
/// the [`MAX_CACHE_BYTES`] scan cap, a source that delivers fewer bytes than it
/// declares, and entries whose `long_key` address names a file this module
/// could not reach — a `data_#` the source cannot open, or an external `f_`.
/// Every recovered record is stamped `content_incomplete`, each unreached entry
/// is published without a URL and with the place its key is, and a status
/// record carries the counts. Without that a `data_#` over the cap — or one
/// full of long tracking URLs — yields a tidy, complete-looking list from which
/// an examiner concludes a site was never fetched.
fn parse_blockfile(
    ds: &dyn DataSource,
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
) -> Vec<Artifact> {
    let declared = ds.size();
    let mut siblings = SiblingBlockFiles::new(ds);
    let size = declared.min(MAX_CACHE_BYTES);
    if size < (BLOCK_HEADER_SIZE + ENTRY_STORE_SIZE) as u64 {
        // The block-file magic matched but there is not even one EntryStore
        // after the 8 KiB header: the file was cut inside its own header.
        return vec![parse_status(
            case_id,
            parent_id,
            file_name,
            "blockfile",
            IncompleteReason::ShortRead,
            0,
            size,
            declared,
            format!(
                "the block-file header claims a cache but the file is {declared} bytes, \
                 shorter than the {BLOCK_HEADER_SIZE}-byte header plus one entry"
            ),
        )];
    }
    let mut buf = vec![0u8; size as usize];
    let read = read_at_full(ds, 0, &mut buf);
    buf.truncate(read);

    // Which `data_#` file this is, from its own header. `None` when the header
    // was not delivered whole, and then no key is ever claimed to be in this
    // file: a scan that cannot say which file it holds must not answer that
    // question at all.
    let this_file: Option<u32> = buf
        .get(BFH_THIS_FILE..BFH_THIS_FILE + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]) as u32);

    // HUNT-145: the header's own count of allocated entries, read so an
    // empty scan result can say WHY it is empty. `number_of_entries` sits at
    // offset 16, `maximum_number_of_entries` at offset 20
    // (chrome_cache_data_block_file_header in the plaso reference format),
    // right after the four u16 fields and the u32 block_size that precede it.
    // Both require the header to have been delivered whole.
    const BFH_NUMBER_OF_ENTRIES: usize = 16;
    let declared_entries: Option<u32> = buf
        .get(BFH_NUMBER_OF_ENTRIES..BFH_NUMBER_OF_ENTRIES + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));

    // HUNT-145: the header's own block size. Chromium allocates every
    // EntryStore from a 256-byte block file; `data_0` (rankings, 36-byte
    // blocks) and the 1 KiB / 4 KiB files hold rankings, long keys and stream
    // data, which are reached through the addresses in `data_1`. Walking one of
    // those at 256 bytes read stream data as entries. A size no block file has
    // is damage, and is said rather than walked at a guessed stride.
    let block_size: Option<u32> = buf
        .get(BFH_ENTRY_SIZE..BFH_ENTRY_SIZE + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    match block_size {
        Some(256) | None => {}
        Some(36 | 1024 | 4096) => return Vec::new(),
        Some(other) => {
            let mut record = parse_status(
                case_id,
                parent_id,
                file_name,
                "blockfile",
                IncompleteReason::UnresolvedStructure,
                0,
                read as u64,
                declared,
                format!(
                    "the block-file header declares a block size of {other} bytes, which no \
                     Chromium block file has (36, 256, 1024 or 4096); the header is damaged, \
                     and the file was not walked at a guessed stride, so any entries it holds \
                     are not listed"
                ),
            );
            if let Some(map) = record.metadata.as_object_mut() {
                map.insert("declared_block_size".into(), json!(other));
            }
            return vec![record];
        }
    }
    // The allocation bitmap, when the header was delivered whole.
    let bitmap: Option<&[u8]> = buf.get(BFH_ALLOCATION_MAP..BLOCK_HEADER_SIZE);

    // Same precedence as `TempDb::spill`: an over-cap file is reported as
    // capped even though the read also stops short of the declared size,
    // because the cap is why we never tried to read the rest.
    let incomplete = if (read as u64) >= declared {
        None
    } else if declared > MAX_CACHE_BYTES {
        Some(IncompleteReason::CapReached)
    } else {
        Some(IncompleteReason::ShortRead)
    };

    let mut out = Vec::new();
    // Entries this scan can see but cannot read the URL of. Counted apart from
    // the blocks that are not entries at all: an examiner has to be able to
    // tell "no such cached URL" from "a cached URL we could not produce".
    let mut long_key_elsewhere = 0usize;
    let mut long_key_here_unreadable = 0usize;
    let mut spanning_key_cut = 0usize;
    // Long keys read out of this same file, and out of a sibling block file.
    // Reported alongside the losses so the recovered figure is never mistaken
    // for the whole set.
    let mut long_key_recovered = 0usize;
    let mut long_key_from_sibling = 0usize;
    // HUNT-185: keys that are this entry's by their hash but whose form this
    // module does not know. Published without a URL, and counted.
    let mut key_form_unrecognised = 0usize;
    // Entries whose key is in a file this scan could not read: published
    // without a URL, after the listing stamp, so each says where its key is.
    let mut unread = Vec::new();

    let mut off = BLOCK_HEADER_SIZE;
    while off + ENTRY_STORE_SIZE <= buf.len() {
        let entry = off;
        let block = &buf[entry..entry + ENTRY_STORE_SIZE];
        off += ENTRY_STORE_SIZE;

        let key_len = i32::from_le_bytes(block[ES_KEY_LEN..ES_KEY_LEN + 4].try_into().unwrap());
        // Zero is a free block and a negative or absurd length is not a record:
        // neither is a cached URL that went missing, so neither is counted.
        if key_len <= 0 || key_len as usize > MAX_KEY_LEN {
            continue;
        }
        let key_len = key_len as usize;
        let block_index = (entry - BLOCK_HEADER_SIZE) / ENTRY_STORE_SIZE;
        let stored_hash = u32::from_le_bytes(block[ES_HASH..ES_HASH + 4].try_into().unwrap());
        let created = u64::from_le_bytes(
            block[ES_CREATION_TIME..ES_CREATION_TIME + 8]
                .try_into()
                .unwrap(),
        );
        // A u64 too large to be an i64 is not a plausible timestamp; `ok()`
        // drops it exactly as the shared pre-epoch guard drops an unset 0.
        let created = i64::try_from(created).ok().and_then(webkit_us_to_unix_secs);
        let entry_blocks = if key_len > MAX_INTERNAL_KEY_LEN {
            1
        } else {
            blocks_for_key(key_len)
        };
        let facts = EntryFacts {
            block: block_index,
            stored_hash,
            allocation: allocation_of(bitmap, block_index, entry_blocks),
        };

        if key_len > MAX_INTERNAL_KEY_LEN {
            // The key was written at the `long_key` cache address. That address
            // names the file it went to, and Chromium picks that file from the
            // key's LENGTH — so a key just over the 927-byte inline limit is
            // allocated from the same 256-byte block file the entry itself lives
            // in, and is sitting in the bytes already in hand. Read it when the
            // address says it is here; count it when it says it is somewhere
            // this module was not handed. Either way the entry never vanishes.
            let long_key =
                u32::from_le_bytes(block[ES_LONG_KEY..ES_LONG_KEY + 4].try_into().unwrap());
            match locate_long_key(long_key, this_file, key_len) {
                LongKey::NotAnAddress => continue,
                LongKey::OtherFile(remote) => {
                    let read = siblings.read_key(&remote, key_len).and_then(|key| {
                        if superfast_hash(&key) == stored_hash {
                            Ok(key)
                        } else {
                            Err(SiblingMiss {
                                token: "sibling_key_hash_mismatch",
                                why: format!(
                                    "{} beside this file was opened and holds a NUL-terminated \
                                     key of {key_len} bytes at that offset, but it does not hash \
                                     to {stored_hash:08x}, the hash this entry carries, so it is \
                                     not this entry's key",
                                    remote.file_name()
                                ),
                            })
                        }
                    });
                    match read {
                        Ok(key) => {
                            let Some(parsed) = parse_cache_key(&key) else {
                                out.push(build_unrecognised_key_record(
                                    case_id,
                                    parent_id,
                                    created,
                                    &key,
                                    &facts,
                                    Some(&remote),
                                ));
                                key_form_unrecognised += 1;
                                continue;
                            };
                            let mut record = build_entry_record(
                                case_id, parent_id, &parsed, created, &facts, true,
                            );
                            if let Some(map) = record.metadata.as_object_mut() {
                                map.insert("key_source".into(), json!("long_key_other_file"));
                                map.insert("key_length".into(), json!(key_len));
                                map.insert("key_file".into(), json!(remote.file_name()));
                                if let Some(block) = remote.block() {
                                    map.insert("key_block".into(), json!(block));
                                }
                                map.insert("key_offset".into(), json!(remote.offset()));
                            }
                            out.push(record);
                            long_key_from_sibling += 1;
                        }
                        Err(miss) => {
                            unread.push(build_unread_long_key_record(
                                case_id, parent_id, created, key_len, &remote, &miss, &facts,
                            ));
                            long_key_elsewhere += 1;
                        }
                    }
                    continue;
                }
                LongKey::ThisFile(offset) => {
                    // The address says the key is in this file. The bytes must
                    // be there (not cut off by the scan cap or a source that
                    // stopped delivering), carry the NUL where the length puts
                    // it, and hash to the value the entry holds; otherwise they
                    // are not this entry's key. Refuse to guess; count the loss.
                    let Some(key) = read_long_key(&buf, offset, key_len)
                        .filter(|key| superfast_hash(key) == stored_hash)
                    else {
                        long_key_here_unreadable += 1;
                        continue;
                    };
                    let Some(parsed) = parse_cache_key(key) else {
                        out.push(build_unrecognised_key_record(
                            case_id, parent_id, created, key, &facts, None,
                        ));
                        key_form_unrecognised += 1;
                        continue;
                    };
                    let mut record =
                        build_entry_record(case_id, parent_id, &parsed, created, &facts, true);
                    if let Some(map) = record.metadata.as_object_mut() {
                        // Where the URL came from, because it is not the entry's
                        // own block: an examiner reading a 1 KiB tracking URL
                        // should be able to see it was assembled from a second
                        // location in the same file.
                        map.insert("key_source".into(), json!("long_key_same_file"));
                        map.insert("key_length".into(), json!(key_len));
                    }
                    out.push(record);
                    long_key_recovered += 1;
                    continue;
                }
            }
        }

        // A key of 160 bytes or more runs on into the entry's following blocks.
        let Some(key) = buf.get(entry + ES_KEY..entry + ES_KEY + key_len) else {
            // Cut off by the scan cap or by a source that stopped delivering.
            if starts_like_cache_key(&buf[entry + ES_KEY..]) {
                spanning_key_cut += 1;
            }
            continue;
        };
        // HUNT-145: the key is this entry's when it hashes to the value the
        // entry carries and the NUL Chromium writes after it is where the
        // length puts it. A key that does not verify is still read when it has
        // a form Chromium writes and its terminator — a damaged entry is still
        // evidence of a fetch — and the record says the hash did not match.
        // Anything else is a block that is not an entry.
        let terminated = buf.get(entry + ES_KEY + key_len) == Some(&0);
        let verified = terminated && superfast_hash(key) == stored_hash;
        match (verified, parse_cache_key(key)) {
            (true, Some(parsed)) => {
                out.push(build_entry_record(
                    case_id, parent_id, &parsed, created, &facts, true,
                ));
            }
            (true, None) => {
                out.push(build_unrecognised_key_record(
                    case_id, parent_id, created, key, &facts, None,
                ));
                key_form_unrecognised += 1;
            }
            (false, Some(parsed)) if terminated => {
                out.push(build_entry_record(
                    case_id, parent_id, &parsed, created, &facts, false,
                ));
            }
            _ => continue,
        }
        // The entry owns every block its key runs through; those are key bytes,
        // not further entries, so do not rescan them.
        if entry_blocks > 1 {
            off = entry + entry_blocks * ENTRY_STORE_SIZE;
        }
    }

    // Entries whose URL is in the listing; a verified key of an unknown form
    // is published too, without a URL, and is not a recovered URL.
    let recovered = out.len() - key_form_unrecognised;

    // HUNT-145: an empty vector from this function has always meant two
    // different things — "these bytes are not a cache" (the caller's magic
    // check already ruled that out by this point) and "this recognised cache
    // holds no keys this scan could read" — and the two were indistinguishable
    // on the case. Where the header itself declares allocated entries but
    // nothing was recovered, that ambiguity is resolved with a record; a
    // header declaring zero entries stays silent, because that is a
    // genuinely empty cache and a record over every unopened `data_#` file on
    // a disk would be noise the crate's own design deliberately avoids.
    let unreadable =
        long_key_elsewhere + long_key_here_unreadable + spanning_key_cut + key_form_unrecognised;
    // Only when nothing else explains the empty listing: an entry whose key
    // was addressed and could not be read is counted below, and returning here
    // dropped that count.
    if recovered == 0
        && unread.is_empty()
        && unreadable == 0
        && declared_entries.is_some_and(|n| n > 0)
    {
        let n = declared_entries.unwrap();
        let mut record = parse_status(
            case_id,
            parent_id,
            file_name,
            "blockfile",
            IncompleteReason::UnresolvedStructure,
            0,
            read as u64,
            declared,
            format!(
                concat!(
                    "the block-file header declares {} allocations (entries, and the small ",
                    "stream data Chromium keeps in the same file), and this scan could not ",
                    "recover a URL from any of them; this is not the same as a cache that ",
                    "holds no entries"
                ),
                n
            ),
        );
        if let Some(map) = record.metadata.as_object_mut() {
            map.insert("declared_entries".into(), json!(n));
        }
        return vec![record];
    }
    // The listing is short either because the scan stopped early or because
    // entries inside it could not be read. Both leave it incomplete, and the
    // reason for stopping early is the more specific of the two.
    let listing_reason = incomplete.or(if unreadable > 0 {
        Some(IncompleteReason::UnresolvedStructure)
    } else {
        None
    });
    if let Some(reason) = listing_reason {
        // The sentence travels with the stamp, on the key the examiner-facing
        // reader shows. A record marked "cap_reached" and nothing else leaves
        // the person reading it to guess whether the URL itself is partial (it
        // is not) or the list around it is (it is).
        let cause = match reason {
            IncompleteReason::CapReached => format!(
                "the {declared}-byte cache file was scanned only to the \
                 {MAX_CACHE_BYTES}-byte cap"
            ),
            IncompleteReason::ShortRead => {
                format!("the source delivered {read} of the {declared} bytes it declared")
            }
            _ => format!(
                "{unreadable} entry(s) in this cache file hold a URL that could not be produced"
            ),
        };
        // Two framings of the same cause, because the claim "this URL is whole"
        // is only true of a record that did not already say its own key bytes
        // were substituted. Saying it anyway put "recovered whole" beside
        // "not valid UTF-8" on one record.
        let whole_detail = format!(
            "this URL was recovered whole, but {cause}, so the listing it belongs to is short"
        );
        let short_detail = format!("the listing this URL belongs to is short: {cause}");
        for record in out.iter_mut() {
            if let Some(map) = record.metadata.as_object_mut() {
                map.insert("content_incomplete".into(), json!(true));
                map.insert("content_incomplete_reason".into(), json!(reason.as_str()));
                // A key whose own bytes were substituted has already said so,
                // and that is the more specific statement about THIS record —
                // but it is not the only one true of it, and the reason token
                // this loop writes describes the LISTING. Dropping the listing
                // sentence left "cap_reached" beside a sentence about UTF-8,
                // which reads as the cap having damaged the URL. Both facts are
                // kept, in the order of how specific they are to this record.
                let detail = match map
                    .get("content_incomplete_detail")
                    .and_then(|v| v.as_str())
                {
                    Some(own) => format!("{own}; {short_detail}"),
                    None => whole_detail.clone(),
                };
                map.insert("content_incomplete_detail".into(), json!(detail));
            }
        }
    }
    // Each of these already carries its own sentence — where its key is and
    // why it was not read — which is the whole of what is incomplete about it.
    out.extend(unread);

    if let Some(reason) = incomplete {
        let detail = if reason == IncompleteReason::CapReached {
            format!(
                "the file is {declared} bytes, over the {MAX_CACHE_BYTES}-byte scan cap; \
                 entries past the first {read} bytes were not recovered"
            )
        } else {
            format!(
                "the source declared {declared} bytes but delivered {read}; entries past \
                 that point were not recovered"
            )
        };
        out.push(parse_status(
            case_id,
            parent_id,
            file_name,
            "blockfile",
            reason,
            recovered,
            read as u64,
            declared,
            detail,
        ));
    }

    if unreadable > 0 {
        let detail = format!(
            "{unreadable} cache entries hold a URL this scan could not produce \
             ({long_key_elsewhere} whose key is stored at a cache address in another data_# \
             or f_ file this scan could not read, each published without its URL and naming \
             where the key is; {long_key_here_unreadable} whose key is addressed inside this \
             file at bytes that were not read or do not hold it; {spanning_key_cut} whose key \
             runs past the {read} bytes read; {key_form_unrecognised} whose key is this entry's \
             by its hash but is in a form this module does not recognise, each published with \
             the key as stored and no URL); those URLs are missing from this listing"
        );
        let mut record = parse_status(
            case_id,
            parent_id,
            file_name,
            "blockfile",
            IncompleteReason::UnresolvedStructure,
            recovered,
            read as u64,
            declared,
            detail,
        );
        if let Some(map) = record.metadata.as_object_mut() {
            map.insert("entries_unreadable".into(), json!(unreadable));
            // Every long-key entry whose URL is still missing, whichever of the
            // two reasons applies. The examiner's question is "how many cached
            // URLs are absent", not "which sub-case".
            map.insert(
                "long_key_entries_unresolved".into(),
                json!(long_key_elsewhere + long_key_here_unreadable),
            );
            map.insert(
                "long_key_entries_in_other_file".into(),
                json!(long_key_elsewhere),
            );
            map.insert(
                "long_key_entries_unread_here".into(),
                json!(long_key_here_unreadable),
            );
            map.insert(
                "long_key_entries_recovered".into(),
                json!(long_key_recovered),
            );
            map.insert(
                "long_key_entries_recovered_from_other_file".into(),
                json!(long_key_from_sibling),
            );
            map.insert(
                "spanning_key_entries_truncated".into(),
                json!(spanning_key_cut),
            );
            map.insert(
                "entries_key_form_not_recognised".into(),
                json!(key_form_unrecognised),
            );
        }
        out.push(record);
    }
    out
}

/// Where an entry's `long_key` cache address says its URL was written.
#[derive(Debug, PartialEq, Eq)]
enum LongKey {
    /// In the block file this module was handed, at this byte offset.
    ThisFile(usize),
    /// In another `data_#` file, or in an external `f_` file: reached through
    /// the source's own notion of the files beside it, or else published as an
    /// entry whose key is at a named place this module could not read.
    OtherFile(RemoteKey),
    /// Not an address Chromium wrote for a key of this length. The scan is a
    /// heuristic over 256-byte blocks and meets many that are not entries at
    /// all; this one is not an entry whose URL went missing, and counting it as
    /// one would put a fetch that never happened in front of an examiner.
    NotAnAddress,
}

/// Resolve the `long_key` address of an entry whose key did not fit inside it.
///
/// Field layout per `disk_cache::Addr` and plaso's `CacheAddress`
/// (`reference/plaso/plaso/parsers/chrome_cache.py`): bit 31 initialized, bits
/// 28-30 file type, bits 24-25 the block count less one, bits 16-23 which
/// `data_#` file, bits 0-15 the first block. The bytes of a block-file address
/// start at `8192 + start_block * block_size`.
///
/// `this_file` is the index this block file's own header declares, or `None`
/// when the header was not read whole. The two checks past the address's own
/// sanity are what keep a garbage word from producing a URL:
///
/// * the allocation the address describes has to be big enough for the key and
///   its trailing NUL — Chromium sizes it from exactly that;
/// * the file type has to be the one Chromium picks for a key this long
///   (`Addr::RequiredFileType`), which has been `<1024 → 256-byte blocks,
///   <4096 → 1 KiB, <=16384 → 4 KiB` since the format was written.
///
/// A key big enough to need an external file is never in this one.
fn locate_long_key(addr: u32, this_file: Option<u32>, key_len: usize) -> LongKey {
    if !is_cache_addr(addr) {
        return LongKey::NotAnAddress;
    }
    let file_type = (addr & ADDR_FILE_TYPE) >> ADDR_FILE_TYPE.trailing_zeros();
    // Chromium stores a key of `key_len` bytes plus a trailing NUL.
    let stored = key_len + 1;
    let Some(block_size) = block_size_for_file_type(file_type) else {
        // File type 0 is an external `f_` file and 1 is the rankings file,
        // which never holds a key. Neither is reachable from here; only the
        // first is a real loss, and `is_cache_addr` has already ruled out the
        // undefined types.
        return if file_type == 0 {
            LongKey::OtherFile(RemoteKey::External {
                number: addr & ADDR_FILE_NAME,
            })
        } else {
            LongKey::NotAnAddress
        };
    };
    if required_file_type(stored) != Some(file_type) {
        return LongKey::NotAnAddress;
    }
    let num_blocks = ((addr & ADDR_NUM_BLOCKS) >> ADDR_NUM_BLOCKS.trailing_zeros()) as usize + 1;
    if num_blocks * block_size < stored {
        return LongKey::NotAnAddress;
    }
    let file = (addr & ADDR_FILE_SELECTOR) >> ADDR_FILE_SELECTOR.trailing_zeros();
    let start_block = addr & ADDR_START_BLOCK;
    if this_file != Some(file) {
        return LongKey::OtherFile(RemoteKey::BlockFile {
            file,
            block: start_block,
            block_size,
        });
    }
    LongKey::ThisFile(BLOCK_HEADER_SIZE + start_block as usize * block_size)
}

/// A key's place in a file other than the one in hand, decoded from its
/// `long_key` address so the record can name it whether or not it was read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RemoteKey {
    /// Block `block` of `data_{file}`, a file of `block_size`-byte blocks.
    BlockFile {
        file: u32,
        block: u32,
        block_size: usize,
    },
    /// The first bytes of `f_{number:06x}` (Chromium names external files from
    /// the low 28 bits of the address, `Addr::FileNumber`).
    External { number: u32 },
}

impl RemoteKey {
    fn file_name(&self) -> String {
        match self {
            RemoteKey::BlockFile { file, .. } => format!("data_{file}"),
            RemoteKey::External { number } => format!("f_{number:06x}"),
        }
    }

    /// Byte offset of the key inside that file: `8192 + block * block_size`
    /// in a block file, the start of an external one.
    fn offset(&self) -> u64 {
        match self {
            RemoteKey::BlockFile {
                block, block_size, ..
            } => BLOCK_HEADER_SIZE as u64 + *block as u64 * *block_size as u64,
            RemoteKey::External { .. } => 0,
        }
    }

    fn block(&self) -> Option<u32> {
        match self {
            RemoteKey::BlockFile { block, .. } => Some(*block),
            RemoteKey::External { .. } => None,
        }
    }

    /// The place as an examiner would write it down: `data_2 block 7`, or
    /// `f_00000b`.
    fn place(&self) -> String {
        match self {
            RemoteKey::BlockFile { file, block, .. } => format!("data_{file} block {block}"),
            RemoteKey::External { number } => format!("f_{number:06x}"),
        }
    }
}

/// Why a key in another file was not read from it. The token goes on the
/// record as `url_unrecoverable_reason`; the sentence says the same in words.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SiblingMiss {
    token: &'static str,
    why: String,
}

/// The `data_#` files beside the one in hand, opened by name on first use and
/// checked against their own headers before a key is read out of them.
///
/// "Could not look" and "looked and it is not there" are different findings
/// (HUNT-101, on SQLite's `-wal`): a source that cannot enumerate its
/// neighbours — a bare byte buffer, an entry a filesystem parser produced from
/// a disk image — answers the first, and the record says so rather than
/// claiming the file is absent. A file that is there is read only if its
/// header carries the block-file magic and names itself as the block file the
/// address wanted, with the block size the address implies: `data_2` beside
/// `data_1` is otherwise just a name, and a key read from the wrong file would
/// be attributed to this entry's timestamp.
struct SiblingBlockFiles<'a> {
    ds: &'a dyn DataSource,
    /// Keyed by file index and the block size the address implied, since a
    /// file checked good for 1 KiB blocks says nothing about a 4 KiB address
    /// that happens to name the same index.
    opened: HashMap<(u32, usize), Result<Arc<dyn DataSource>, SiblingMiss>>,
}

impl<'a> SiblingBlockFiles<'a> {
    fn new(ds: &'a dyn DataSource) -> Self {
        Self {
            ds,
            opened: HashMap::new(),
        }
    }

    /// The key bytes at `remote`, or the reason they were not read.
    fn read_key(&mut self, remote: &RemoteKey, key_len: usize) -> Result<Vec<u8>, SiblingMiss> {
        let (file, block_size) = match remote {
            RemoteKey::BlockFile {
                file, block_size, ..
            } => (*file, *block_size),
            RemoteKey::External { .. } => {
                return Err(SiblingMiss {
                    token: "external_file_not_opened",
                    why: format!(
                        "this module does not open external f_ files, so {} was not read",
                        remote.file_name()
                    ),
                });
            }
        };
        let sibling = self.open(file, block_size)?;
        let mut stored = vec![0u8; key_len + 1];
        let got = read_at_full(sibling.as_ref(), remote.offset(), &mut stored);
        let name = remote.file_name();
        if got < stored.len() {
            return Err(SiblingMiss {
                token: "sibling_short_read",
                why: format!(
                    "{name} beside this file was opened but holds only {got} of the {} bytes \
                     the key and its terminator need at that offset",
                    stored.len()
                ),
            });
        }
        // The NUL check `read_long_key` makes on the file in hand, for the
        // same reason: publishing whatever lies at the offset would put some
        // other cached URL under this entry's timestamp. The caller then checks
        // the key's hash against the entry's and its form; each refusal carries
        // its own token.
        if stored[key_len] != 0 {
            return Err(SiblingMiss {
                token: "sibling_key_not_terminated_at_length",
                why: format!(
                    "{name} beside this file was opened, but the byte {key_len} bytes past \
                     that offset is not the NUL Chromium writes after a key, so the bytes \
                     there are not this entry's key"
                ),
            });
        }
        stored.truncate(key_len);
        Ok(stored)
    }

    fn open(&mut self, file: u32, block_size: usize) -> Result<Arc<dyn DataSource>, SiblingMiss> {
        if let Some(known) = self.opened.get(&(file, block_size)) {
            return known.clone();
        }
        let opened = self.open_uncached(file, block_size);
        self.opened.insert((file, block_size), opened.clone());
        opened
    }

    fn open_uncached(
        &self,
        file: u32,
        block_size: usize,
    ) -> Result<Arc<dyn DataSource>, SiblingMiss> {
        let name = format!("data_{file}");
        if !self.ds.supports_siblings() {
            return Err(SiblingMiss {
                token: "sibling_lookup_unsupported",
                why: format!(
                    "not reachable from this file: the source it was read from cannot look \
                     for files beside it, so {name} was not looked for"
                ),
            });
        }
        let Some(sibling) = self.ds.open_relative(&name) else {
            return Err(SiblingMiss {
                token: "sibling_not_present",
                why: format!("not reachable from this file: {name} is not present beside it"),
            });
        };
        let mut head = [0u8; BFH_ENTRY_SIZE + 4];
        let got = read_at_full(sibling.as_ref(), 0, &mut head);
        if got < head.len() {
            return Err(SiblingMiss {
                token: "sibling_header_mismatch",
                why: format!(
                    "{name} beside this file is not read: only {got} of its first {} header \
                     bytes could be read, so it cannot say which block file it is",
                    head.len()
                ),
            });
        }
        let magic = u32::from_le_bytes(head[0..4].try_into().unwrap());
        let this_file = u16::from_le_bytes([head[BFH_THIS_FILE], head[BFH_THIS_FILE + 1]]) as u32;
        let entry_size =
            u32::from_le_bytes(head[BFH_ENTRY_SIZE..BFH_ENTRY_SIZE + 4].try_into().unwrap());
        if magic != BLOCK_MAGIC {
            return Err(SiblingMiss {
                token: "sibling_header_mismatch",
                why: format!(
                    "{name} beside this file is not read: it does not open with the block-file \
                     magic, so it is not a cache block file"
                ),
            });
        }
        if this_file != file || entry_size as usize != block_size {
            return Err(SiblingMiss {
                token: "sibling_header_mismatch",
                why: format!(
                    "{name} beside this file is not read: its header says it is block file \
                     {this_file} with {entry_size}-byte blocks, not block file {file} with \
                     {block_size}-byte blocks"
                ),
            });
        }
        Ok(sibling)
    }
}

/// The record for an entry whose key is in another file this scan did not
/// read. It carries no `url` — none of the key is in the entry — and instead
/// says exactly where the key is, so an examiner can open that file at that
/// offset, and why it was not read here.
fn build_unread_long_key_record(
    case_id: Uuid,
    parent_id: Uuid,
    created: Option<i64>,
    key_len: usize,
    remote: &RemoteKey,
    miss: &SiblingMiss,
    facts: &EntryFacts,
) -> Artifact {
    let place = remote.place();
    let detail = format!(
        "the key is {key_len} bytes, over the {MAX_INTERNAL_KEY_LEN}-byte limit an entry holds \
         inline, so none of it is in this entry; the full key is at {place} (byte offset {} of \
         that file), {}",
        remote.offset(),
        miss.why
    );
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("BrowserCacheEntry"));
    m.insert("subtype".into(), json!("browser_cache_entry"));
    m.insert("browser".into(), json!("Chrome/Edge"));
    m.insert("cache_format".into(), json!("blockfile"));
    if let Some(c) = created {
        m.insert("creation_time".into(), json!(c));
    }
    m.insert("key_source".into(), json!("long_key_other_file"));
    m.insert("key_length".into(), json!(key_len));
    m.insert("key_file".into(), json!(remote.file_name()));
    if let Some(block) = remote.block() {
        m.insert("key_block".into(), json!(block));
    }
    m.insert("key_offset".into(), json!(remote.offset()));
    m.insert("url_unrecoverable_reason".into(), json!(miss.token));
    facts.stamp(&mut m, None);
    m.insert("content_incomplete".into(), json!(true));
    m.insert(
        "content_incomplete_reason".into(),
        json!(IncompleteReason::UnresolvedStructure.as_str()),
    );
    m.insert("content_incomplete_detail".into(), json!(detail));
    m.insert(
        "name".into(),
        json!(format!(
            "Cached URL not read from this file: {key_len}-byte key at {place}"
        )),
    );
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(m),
    )
    .with_parent(parent_id)
    .with_subtype("browser_cache_entry")
}

/// Byte size of one block in a `data_#` file of this type, or `None` for the
/// types that hold no cache key (0 is an external file, 1 the rankings file).
fn block_size_for_file_type(file_type: u32) -> Option<usize> {
    match file_type {
        2 => Some(256),
        3 => Some(1024),
        4 => Some(4096),
        _ => None,
    }
}

/// `disk_cache::Addr::RequiredFileType`: the block file Chromium allocates a
/// buffer of `size` bytes from. `None` when the size needs an external file.
fn required_file_type(size: usize) -> Option<u32> {
    if size < 1024 {
        Some(2)
    } else if size < 4096 {
        Some(3)
    } else if size <= 4096 * 4 {
        Some(4)
    } else {
        None
    }
}

/// The key bytes at `offset`, or `None` if this is not the key the entry named.
///
/// The NUL Chromium writes after the key has to be exactly where `key_len` puts
/// it; the caller then checks the key's hash against the entry's. Both exist
/// for the same reason: the alternative to refusing an unconvincing match is
/// publishing some other cached URL under this entry's timestamp, which is a
/// fabricated fetch. A refusal costs the entry its URL and says so.
fn read_long_key(buf: &[u8], offset: usize, key_len: usize) -> Option<&[u8]> {
    let stored = buf.get(offset..offset.checked_add(key_len)?.checked_add(1)?)?;
    (stored[key_len] == 0).then(|| &stored[..key_len])
}

/// True if `addr` could be a `disk_cache::Addr` Chromium wrote, per the field
/// layout in `reference/plaso/plaso/parsers/chrome_cache.py` (`CacheAddress`)
/// and Chromium's own `Addr::SanityCheck`: initialized, a defined file type,
/// and — for the block files, where every remaining bit belongs to a field —
/// no reserved bit set.
///
/// This gates the `long_key_entries_unresolved` count, and the reason it has to
/// be strict is the mirror of the reason the count exists. The scan is a
/// heuristic over 256-byte blocks and meets plenty that are not entries at all;
/// counting one of those as an entry whose URL could not be produced puts a
/// missing fetch in front of an examiner that never happened. A false "evidence
/// was lost" is as wrong as a silent drop, in the other direction.
fn is_cache_addr(addr: u32) -> bool {
    if addr & ADDR_INITIALIZED == 0 {
        return false;
    }
    let file_type = (addr & ADDR_FILE_TYPE) >> ADDR_FILE_TYPE.trailing_zeros();
    if file_type > ADDR_FILE_TYPE_MAX {
        return false;
    }
    // A separate `f_` file puts its whole selector in the low 28 bits, so the
    // reserved bits only mean anything for the block files.
    file_type == 0 || addr & ADDR_RESERVED == 0
}

/// Chromium `EntryImpl::NumBlocksForEntry`: how many consecutive 256-byte
/// blocks an entry with this key length occupies. A key of [`ES_KEY_MAX_INLINE`]
/// bytes or more continues past the first block into the following ones.
fn blocks_for_key(key_len: usize) -> usize {
    if key_len < ES_KEY_MAX_INLINE {
        1
    } else {
        (key_len - ES_KEY_MAX_INLINE) / ENTRY_STORE_SIZE + 2
    }
}

/// True if these bytes open with a URL scheme this cache would store. Checked on
/// raw bytes so a key that is not valid UTF-8 can still be identified as one.
fn starts_like_url(b: &[u8]) -> bool {
    [
        b"http://".as_ref(),
        b"https://",
        b"ftp://",
        b"ws://",
        b"wss://",
    ]
    .iter()
    .any(|p| b.starts_with(p))
}

// `base::Time` (microseconds since 1601-01-01) is the same base WebKit/Chrome
// history uses; conversion lives in `seance_core::time::webkit_us_to_unix_secs`.

/// True if these bytes could open a cache key: a URL, a sparse child's
/// `Range_`, or the `<n>/<n>/` prefix of the key forms Chromium writes. Used
/// only to decide whether a key cut off by the end of the scan was an entry's.
fn starts_like_cache_key(b: &[u8]) -> bool {
    starts_like_url(b) || b.starts_with(b"Range_") || split_numeric_prefix(b).is_some()
}

/// `<digits>/<digits>/` at the start of `b`: the credential flag and upload
/// identifier `HttpCache::GenerateCacheKey` writes. Returns the rest.
fn split_numeric_prefix(b: &[u8]) -> Option<&[u8]> {
    let mut rest = b;
    for _ in 0..2 {
        let digits = rest.iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 || digits > 20 || rest.get(digits) != Some(&b'/') {
            return None;
        }
        rest = &rest[digits + 1..];
    }
    Some(rest)
}

/// How a cache key was written (HUNT-185).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyForm {
    /// The key is the URL.
    Url,
    /// `<credential>/<upload id>/<url>`.
    Prefixed,
    /// Split cache: `<credential>/<upload id>/_dk_[s_]<top-frame site>
    /// [<frame site> ]<url>`.
    DoubleKeyed,
}

impl KeyForm {
    fn as_str(self) -> &'static str {
        match self {
            KeyForm::Url => "url",
            KeyForm::Prefixed => "prefixed",
            KeyForm::DoubleKeyed => "double_keyed",
        }
    }
}

/// A cache key taken apart into what it says.
#[derive(Debug)]
struct CacheKey<'a> {
    raw: &'a [u8],
    url: &'a [u8],
    form: KeyForm,
    top_frame_site: Option<&'a [u8]>,
    frame_site: Option<&'a [u8]>,
    /// The `s_` marker Chromium writes for a subframe document resource.
    subframe_document_resource: bool,
    /// `Range_<key>:<signature>:<child>`: a child of a sparse entry.
    sparse: Option<(&'a [u8], &'a [u8])>,
}

/// Take a cache key apart, or `None` for a form this module does not
/// recognise.
///
/// The forms are the ones `HttpCache::GenerateCacheKey` writes and the ones
/// measured on the plaso corpora: a bare URL; `<n>/<n>/<url>`;
/// `<n>/<n>/_dk_[s_]<top-frame site> [<frame site> ]<url>` (the network
/// isolation key, with a space — which a URL cannot contain — separating
/// each part); and any of those as a sparse child
/// `Range_<key>:<hex signature>:<hex child id>`. The URL must open with a
/// scheme this module publishes. Anything else — a newer prefix such as
/// `_cn_`, say — is `None`, and the caller publishes the key as stored rather
/// than guess which part is the URL.
fn parse_cache_key(raw: &[u8]) -> Option<CacheKey<'_>> {
    let is_hex = |b: &[u8]| !b.is_empty() && b.iter().all(u8::is_ascii_hexdigit);
    let (mut rest, sparse) = match raw.strip_prefix(b"Range_") {
        Some(body) => {
            let mut parts = body.rsplitn(3, |&c| c == b':');
            let child = parts.next()?;
            let signature = parts.next()?;
            let base = parts.next()?;
            if !is_hex(child) || !is_hex(signature) {
                return None;
            }
            (base, Some((signature, child)))
        }
        None => (raw, None),
    };
    let prefixed = split_numeric_prefix(rest);
    if let Some(after) = prefixed {
        rest = after;
    }
    let mut key = CacheKey {
        raw,
        url: rest,
        form: if prefixed.is_some() {
            KeyForm::Prefixed
        } else {
            KeyForm::Url
        },
        top_frame_site: None,
        frame_site: None,
        subframe_document_resource: false,
        sparse,
    };
    if let Some(isolated) = rest.strip_prefix(b"_dk_") {
        let (isolated, subframe) = match isolated.strip_prefix(b"s_") {
            Some(r) => (r, true),
            None => (isolated, false),
        };
        let parts: Vec<&[u8]> = isolated.split(|&c| c == b' ').collect();
        let (top, frame, url) = match parts.as_slice() {
            [top, url] => (*top, None, *url),
            [top, frame, url] => (*top, Some(*frame), *url),
            _ => return None,
        };
        if top.is_empty() || frame.is_some_and(<[u8]>::is_empty) {
            return None;
        }
        key.form = KeyForm::DoubleKeyed;
        key.url = url;
        key.top_frame_site = Some(top);
        key.frame_site = frame;
        key.subframe_document_resource = subframe;
    }
    (starts_like_url(key.url) && !key.url.contains(&b' ')).then_some(key)
}

/// `disk_cache::Hash`: Paul Hsieh's SuperFastHash, as Chromium's
/// `base/third_party/superfasthash` computes it — 16-bit little-endian
/// reads, and the trailing bytes read as `signed char`. The entry header's
/// `hash` is this over the whole key.
fn superfast_hash(data: &[u8]) -> u32 {
    if data.is_empty() {
        return 0;
    }
    let get16 = |i: usize| u32::from(u16::from_le_bytes([data[i], data[i + 1]]));
    let signed = |b: u8| b as i8 as i32 as u32;
    let mut hash = data.len() as u32;
    let rem = data.len() & 3;
    let mut i = 0;
    for _ in 0..data.len() / 4 {
        hash = hash.wrapping_add(get16(i));
        let tmp = (get16(i + 2) << 11) ^ hash;
        hash = (hash << 16) ^ tmp;
        i += 4;
        hash = hash.wrapping_add(hash >> 11);
    }
    match rem {
        3 => {
            hash = hash.wrapping_add(get16(i));
            hash ^= hash << 16;
            hash ^= signed(data[i + 2]) << 18;
            hash = hash.wrapping_add(hash >> 11);
        }
        2 => {
            hash = hash.wrapping_add(get16(i));
            hash ^= hash << 11;
            hash = hash.wrapping_add(hash >> 17);
        }
        1 => {
            hash = hash.wrapping_add(signed(data[i]));
            hash ^= hash << 10;
            hash = hash.wrapping_add(hash >> 1);
        }
        _ => {}
    }
    hash ^= hash << 3;
    hash = hash.wrapping_add(hash >> 5);
    hash ^= hash << 4;
    hash = hash.wrapping_add(hash >> 17);
    hash ^= hash << 25;
    hash = hash.wrapping_add(hash >> 6);
    hash
}

/// Whether the blocks an entry occupies are allocated, by the header's
/// allocation bitmap: `"allocated"`, `"free"` (Chromium released them — the
/// entry was evicted or deleted and its bytes survive until reused), or
/// `"partly_free"`. `None` when the bitmap was not read.
fn allocation_of(bitmap: Option<&[u8]>, first: usize, blocks: usize) -> Option<&'static str> {
    let bitmap = bitmap?;
    let bit = |i: usize| bitmap.get(i / 8).map(|b| b >> (i % 8) & 1 == 1);
    let mut set = 0;
    for i in first..first + blocks {
        if bit(i)? {
            set += 1;
        }
    }
    Some(match set {
        0 => "free",
        n if n == blocks => "allocated",
        _ => "partly_free",
    })
}

/// What the scan knows about the entry a record comes from, independent of
/// its key.
struct EntryFacts {
    /// The entry's first block in this file.
    block: usize,
    /// `EntryStore::hash` as stored.
    stored_hash: u32,
    allocation: Option<&'static str>,
}

impl EntryFacts {
    /// Put the entry's own facts on a record. `verified` is whether the key
    /// the record carries hashes to `stored_hash` (`None` when no key was
    /// read).
    fn stamp(&self, m: &mut serde_json::Map<String, serde_json::Value>, verified: Option<bool>) {
        m.insert("key_block_in_file".into(), json!(self.block));
        m.insert(
            "key_hash".into(),
            json!(format!("{:08x}", self.stored_hash)),
        );
        if let Some(v) = verified {
            m.insert("key_hash_verified".into(), json!(v));
        }
        if let Some(a) = self.allocation {
            m.insert("allocation".into(), json!(a));
            if a != "allocated" {
                m.insert(
                    "allocation_detail".into(),
                    json!(format!(
                        "this entry's block(s) are marked {} in the file's allocation bitmap: \
                         Chromium released them, so the entry was evicted or deleted, and what \
                         is read here is what survived in the block(s) until they are reused",
                        if a == "free" { "free" } else { "partly free" }
                    )),
                );
            }
        }
    }
}

/// The record for one entry whose key was read and recognised.
fn build_entry_record(
    case_id: Uuid,
    parent_id: Uuid,
    key: &CacheKey<'_>,
    created: Option<i64>,
    facts: &EntryFacts,
    hash_verified: bool,
) -> Artifact {
    let (url, lossy) = decode_key(key.url);
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("BrowserCacheEntry"));
    m.insert("subtype".into(), json!("browser_cache_entry"));
    m.insert("browser".into(), json!("Chrome/Edge"));
    m.insert("cache_format".into(), json!("blockfile"));
    m.insert("url".into(), json!(url));
    if let Some(c) = created {
        m.insert("creation_time".into(), json!(c));
    }
    m.insert("cache_key_form".into(), json!(key.form.as_str()));
    if key.raw != key.url {
        m.insert("cache_key".into(), json!(decode_key(key.raw).0));
    }
    if let Some(site) = key.top_frame_site {
        m.insert("top_frame_site".into(), json!(decode_key(site).0));
    }
    if let Some(site) = key.frame_site {
        m.insert("frame_site".into(), json!(decode_key(site).0));
    }
    if key.subframe_document_resource {
        m.insert("subframe_document_resource".into(), json!(true));
    }
    if let Some((signature, child)) = key.sparse {
        m.insert("sparse_signature".into(), json!(decode_key(signature).0));
        m.insert("sparse_child_id".into(), json!(decode_key(child).0));
    }
    facts.stamp(&mut m, Some(hash_verified));
    let freed = facts.allocation.is_some_and(|a| a != "allocated");
    m.insert(
        "name".into(),
        json!(if freed {
            format!("Cached URL (freed entry): {url}")
        } else {
            format!("Cached URL: {url}")
        }),
    );
    let mut record = Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(m),
    )
    .with_parent(parent_id)
    .with_subtype("browser_cache_entry");
    if lossy {
        stamp_lossy(&mut record);
    }
    if !hash_verified {
        if let Some(map) = record.metadata.as_object_mut() {
            let own = format!(
                "the key does not hash to {:08x}, the hash this entry's header carries, so it \
                 is not established that the bytes read as this URL are the key this entry was \
                 written with (a block freed and partly reused, or damaged, reads this way)",
                facts.stored_hash
            );
            let detail = match map
                .get("content_incomplete_detail")
                .and_then(|v| v.as_str())
            {
                Some(prior) => format!("{prior}; {own}"),
                None => own,
            };
            map.insert("content_incomplete".into(), json!(true));
            map.insert(
                "content_incomplete_reason".into(),
                json!(IncompleteReason::UnresolvedStructure.as_str()),
            );
            map.insert("content_incomplete_detail".into(), json!(detail));
        }
    }
    record
}

/// The record for an entry whose key is its own by its hash but is in a form
/// this module does not recognise: no URL is claimed, and the key is shown as
/// stored so an examiner can read it.
fn build_unrecognised_key_record(
    case_id: Uuid,
    parent_id: Uuid,
    created: Option<i64>,
    key: &[u8],
    facts: &EntryFacts,
    remote: Option<&RemoteKey>,
) -> Artifact {
    let (shown, _) = decode_key(key);
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("BrowserCacheEntry"));
    m.insert("subtype".into(), json!("browser_cache_entry"));
    m.insert("browser".into(), json!("Chrome/Edge"));
    m.insert("cache_format".into(), json!("blockfile"));
    if let Some(c) = created {
        m.insert("creation_time".into(), json!(c));
    }
    m.insert("cache_key".into(), json!(shown));
    m.insert("key_length".into(), json!(key.len()));
    if let Some(remote) = remote {
        m.insert("key_source".into(), json!("long_key_other_file"));
        m.insert("key_file".into(), json!(remote.file_name()));
        if let Some(block) = remote.block() {
            m.insert("key_block".into(), json!(block));
        }
        m.insert("key_offset".into(), json!(remote.offset()));
    }
    m.insert(
        "url_unrecoverable_reason".into(),
        json!("cache_key_form_not_recognised"),
    );
    facts.stamp(&mut m, Some(true));
    m.insert("content_incomplete".into(), json!(true));
    m.insert(
        "content_incomplete_reason".into(),
        json!(IncompleteReason::UnresolvedStructure.as_str()),
    );
    m.insert(
        "content_incomplete_detail".into(),
        json!(
            "the stored key is this entry's — it hashes to the value the entry carries — but it \
             is not in a form this module recognises (a URL, <n>/<n>/<url>, \
             <n>/<n>/_dk_[s_]<top-frame site> [<frame site> ]<url>, or a Range_ child of one), \
             so no URL is claimed from it; the key is shown as stored"
        ),
    );
    let head: String = shown.chars().take(80).collect();
    m.insert(
        "name".into(),
        json!(format!("Cache entry, key form not recognised: {head}")),
    );
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(m),
    )
    .with_parent(parent_id)
    .with_subtype("browser_cache_entry")
}

/// Read exactly `buf.len()` bytes from `offset`, tolerating short reads; returns
/// how many bytes were actually read.
fn read_at_full(ds: &dyn DataSource, offset: u64, buf: &mut [u8]) -> usize {
    let mut off = 0usize;
    while off < buf.len() {
        match ds.read_at(offset + off as u64, &mut buf[off..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => off += n,
        }
    }
    off
}

#[cfg(test)]
mod tests;
