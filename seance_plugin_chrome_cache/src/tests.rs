use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;
use uuid::Uuid;

/// Build a Chrome Simple Cache entry file for `url`, with trailing stream bytes.
fn simple_cache_entry(url: &str, version: u32) -> Vec<u8> {
    let key = url.as_bytes();
    let mut v = Vec::new();
    v.extend_from_slice(&SIMPLE_MAGIC.to_le_bytes());
    v.extend_from_slice(&version.to_le_bytes());
    v.extend_from_slice(&(key.len() as u32).to_le_bytes());
    v.extend_from_slice(&0xdead_beefu32.to_le_bytes()); // key_hash
    v.extend_from_slice(key);
    v.extend_from_slice(b"...cached response body and EOF records...");
    v
}

fn run(bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "f9a1c3d4e5f6a7b8_0" }),
    );
    ChromeCacheParser.process(&art).unwrap()
}

#[test]
fn extracts_cached_url() {
    let out = run(simple_cache_entry("https://example.com/app.js?v=3", 5));
    assert_eq!(out.len(), 1);
    let rec = &out[0];
    assert_eq!(rec.metadata["type"], "BrowserCacheEntry");
    assert_eq!(rec.metadata["cache_format"], "simple");
    assert_eq!(rec.metadata["url"], "https://example.com/app.js?v=3");
    assert_eq!(rec.metadata["version"], 5);
    assert_eq!(rec.metadata["key_hash"], "deadbeef");
    assert_eq!(
        rec.metadata["name"],
        "Cached URL: https://example.com/app.js?v=3"
    );
}

#[test]
fn ignores_non_cache_file() {
    // Wrong magic.
    assert!(run(b"not a chrome cache file at all........".to_vec()).is_empty());
    // Too short for a header.
    assert!(run(vec![0x30, 0x5c, 0x72]).is_empty());
}

#[test]
fn a_key_length_past_end_of_file_is_reported_not_dropped() {
    // Valid magic, but key_length claims more than the file holds. The magic
    // says this IS a Simple Cache entry, so recovering no URL from it is a
    // finding — it must not render as "no cache entry here" (B2-163).
    let mut v = Vec::new();
    v.extend_from_slice(&SIMPLE_MAGIC.to_le_bytes());
    v.extend_from_slice(&5u32.to_le_bytes());
    v.extend_from_slice(&10_000u32.to_le_bytes()); // key_length >> file
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(b"short");
    let out = run(v);

    assert!(
        out.iter()
            .all(|a| a.metadata["type"] != "BrowserCacheEntry"),
        "no URL can be claimed from a key that is not in the file"
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["type"], "BrowserCacheParseStatus");
    assert_eq!(out[0].metadata["cache_format"], "simple");
    assert_eq!(out[0].metadata["content_incomplete"], true);
    assert_eq!(out[0].metadata["content_incomplete_reason"], "short_read");
    assert_eq!(out[0].metadata["entries_recovered"], 0);
}

#[test]
fn a_simple_entry_cut_inside_its_header_is_reported_not_dropped() {
    // 12 bytes: the magic identifies a Simple Cache entry, but the header stops
    // before the key length. The unfixed crate required all 20 header bytes and
    // fell through to "not a cache", losing the entry without a word.
    let mut v = Vec::new();
    v.extend_from_slice(&SIMPLE_MAGIC.to_le_bytes());
    v.extend_from_slice(&5u32.to_le_bytes());
    let out = run(v);

    assert!(cache_entries(&out).is_empty());
    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].metadata["cache_format"], "simple");
    assert_eq!(status[0].metadata["content_incomplete"], true);
    assert_eq!(
        status[0].metadata["content_incomplete_reason"],
        "short_read"
    );
    assert_eq!(status[0].metadata["bytes_read"], 12);
    assert_eq!(status[0].metadata["entries_recovered"], 0);
}

#[test]
fn a_simple_cache_key_that_is_not_utf8_says_the_url_was_substituted() {
    // `parse_simple_entry` ran the key through `from_utf8_lossy` and published
    // the result as the URL. U+FFFD then reads as a character the browser
    // asked for: the record claims a fetch of a URL that was never requested,
    // with nothing to say a byte was replaced. The blockfile path was given
    // `url_encoding_lossy` and this one was left as it was.
    let key = b"https://evidence.test/\xff\xfea";
    let mut v = Vec::new();
    v.extend_from_slice(&SIMPLE_MAGIC.to_le_bytes());
    v.extend_from_slice(&5u32.to_le_bytes());
    v.extend_from_slice(&(key.len() as u32).to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(key);
    let out = run(v);

    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 1, "the fetch is still evidence");
    assert_eq!(entries[0].metadata["cache_format"], "simple");
    assert_eq!(entries[0].metadata["url_encoding_lossy"], true);
    assert_eq!(entries[0].metadata["content_incomplete"], true);
    assert_eq!(
        entries[0].metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
}

#[test]
fn a_clean_simple_cache_key_is_not_marked_lossy() {
    // The counterweight: if every URL were flagged, the flag on the damaged
    // one would tell an examiner nothing.
    let out = run(simple_cache_entry("https://example.com/app.js?v=3", 5));
    assert_eq!(out.len(), 1);
    assert!(out[0].metadata.get("url_encoding_lossy").is_none());
    assert!(out[0].metadata.get("content_incomplete").is_none());
}

#[test]
fn module_metadata() {
    let p = ChromeCacheParser;
    assert_eq!(p.id(), "plugin.browsers.chrome_cache");
    assert!(p.subscribes_to().contains(&ArtifactType::FileEntry));
}

// ── Blockfile cache (data_# files) ───────────────────────────────────────────

/// Build a 256-byte EntryStore with an inline URL key, carrying the key hash
/// Chromium writes at offset 0 (`disk_cache::Hash`, SuperFastHash).
fn entry_store(url: &str, creation_us_since_1601: u64) -> Vec<u8> {
    let mut b = entry_store_raw_key(url.as_bytes());
    b[ES_CREATION_TIME..ES_CREATION_TIME + 8]
        .copy_from_slice(&creation_us_since_1601.to_le_bytes());
    b
}

/// An 8 KiB block-file header the way Chromium writes one: magic, version
/// 2.0, this file's index, its block size, the allocation count, and the
/// allocation bitmap with a bit set for each block in `allocated`.
fn block_file_header(this_file: u16, block_size: u32, allocated: &[usize]) -> Vec<u8> {
    let mut f = vec![0u8; BLOCK_HEADER_SIZE];
    f[0..4].copy_from_slice(&BLOCK_MAGIC.to_le_bytes());
    f[4..8].copy_from_slice(&0x0002_0000u32.to_le_bytes());
    f[BFH_THIS_FILE..BFH_THIS_FILE + 2].copy_from_slice(&this_file.to_le_bytes());
    f[BFH_ENTRY_SIZE..BFH_ENTRY_SIZE + 4].copy_from_slice(&block_size.to_le_bytes());
    f[16..20].copy_from_slice(&(allocated.len() as u32).to_le_bytes());
    f[20..24].copy_from_slice(&1024u32.to_le_bytes());
    for &b in allocated {
        f[80 + b / 8] |= 1 << (b % 8);
    }
    f
}

/// Build a `data_1`-shaped block file: the header (256-byte blocks, file 1)
/// and the given EntryStore records, each record's blocks marked allocated
/// unless the record is all zero (a free block). The header's allocation
/// count is the number of records carrying a key hash — the entries — so a
/// fixture of junk blocks declares none, as the tests of the declared-count
/// record intend.
fn blockfile(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut allocated = Vec::new();
    let mut block = 0usize;
    for e in entries {
        let blocks = e.len().div_ceil(ENTRY_STORE_SIZE);
        if e.iter().any(|&b| b != 0) {
            allocated.extend(block..block + blocks);
        }
        block += blocks;
    }
    let declared = entries
        .iter()
        .filter(|e| e.len() >= 4 && e[0..4] != [0, 0, 0, 0] && e[0..4] != [0xAA; 4])
        .count() as u32;
    let mut f = block_file_header(1, 256, &allocated);
    f[16..20].copy_from_slice(&declared.to_le_bytes());
    for e in entries {
        f.extend_from_slice(e);
    }
    f
}

#[test]
fn extracts_blockfile_entry_urls() {
    // 2013-01-06T12:00:00Z == 1357473600 Unix; microseconds since 1601:
    let ct = (1_357_473_600u64 + 11_644_473_600) * 1_000_000;
    let entries = vec![
        entry_store("https://cached.example/a.png", ct),
        entry_store("http://evidence.test/tracker", 0), // no creation time
        vec![0xAAu8; ENTRY_STORE_SIZE],                 // non-entry block: skipped
    ];
    let out = run(blockfile(&entries));
    assert_eq!(out.len(), 2, "two URL entries; garbage block skipped");

    let a = out
        .iter()
        .find(|x| x.metadata["url"] == "https://cached.example/a.png")
        .unwrap();
    assert_eq!(a.metadata["cache_format"], "blockfile");
    assert_eq!(a.metadata["creation_time"].as_i64(), Some(1_357_473_600));

    let b = out
        .iter()
        .find(|x| x.metadata["url"] == "http://evidence.test/tracker")
        .unwrap();
    assert!(b.metadata.get("creation_time").is_none()); // ct = 0 -> omitted
}

// --- B2-163: a capped or short-read cache is not a complete one -------------
//
// `parse_blockfile` scanned `size.min(MAX_CACHE_BYTES)` and then truncated the
// buffer to whatever the source actually delivered, with no marker either way.
// A 700 MiB `data_1`, or one whose backing extents run out, produced a clean
// list of cached URLs and nothing to say the rest of the file was never looked
// at. Against the unfixed crate these tests fail: no `content_incomplete` and
// no `BrowserCacheParseStatus` existed in it.

use seance_core::test_support::TruncatedSource;

fn run_ds(ds: Arc<dyn DataSource>) -> Vec<Artifact> {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "data_1" }),
    );
    ChromeCacheParser.process(&art).unwrap()
}

fn status_records(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.metadata["type"] == "BrowserCacheParseStatus")
        .collect()
}

fn cache_entries(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.metadata["type"] == "BrowserCacheEntry")
        .collect()
}

fn sample_blockfile() -> Vec<u8> {
    blockfile(&[
        entry_store("https://cached.example/a.png", 0),
        entry_store("http://evidence.test/tracker", 0),
    ])
}

#[test]
fn a_whole_blockfile_carries_no_incompleteness() {
    // The counterweight: if a complete scan were marked, the marks on the
    // truncated ones would mean nothing.
    let out = run(sample_blockfile());
    assert_eq!(cache_entries(&out).len(), 2);
    assert!(status_records(&out).is_empty());
    for a in &out {
        assert!(a.metadata.get("content_incomplete").is_none());
    }
}

#[test]
fn a_blockfile_that_under_delivers_marks_every_entry_and_says_so() {
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::halved(sample_blockfile()));
    let out = run_ds(ds);

    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 2, "the readable prefix must still parse");
    for e in &entries {
        assert_eq!(e.metadata["content_incomplete"], true);
        assert_eq!(e.metadata["content_incomplete_reason"], "short_read");
    }

    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].metadata["cache_format"], "blockfile");
    assert_eq!(
        status[0].metadata["content_incomplete_reason"],
        "short_read"
    );
    assert_eq!(status[0].metadata["entries_recovered"], 2);
    assert_eq!(status[0].metadata["file_name"], "data_1");
}

#[test]
fn a_blockfile_over_the_scan_cap_reports_cap_reached() {
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(
        sample_blockfile(),
        MAX_CACHE_BYTES + 1,
    ));
    let out = run_ds(ds);

    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    assert_eq!(
        status[0].metadata["content_incomplete_reason"],
        "cap_reached"
    );
    assert_eq!(status[0].metadata["declared_size"], MAX_CACHE_BYTES + 1);
    assert_eq!(status[0].metadata["max_cache_bytes"], MAX_CACHE_BYTES);
    for e in cache_entries(&out) {
        assert_eq!(e.metadata["content_incomplete_reason"], "cap_reached");
    }
}

#[test]
fn a_blockfile_cut_inside_its_own_header_is_not_an_empty_cache() {
    // The magic matched, so this is a cache; a file too short to hold even one
    // EntryStore must report that, not return the empty vector a cache with no
    // entries returns.
    let mut f = vec![0u8; 64];
    f[0..4].copy_from_slice(&BLOCK_MAGIC.to_le_bytes());
    let out = run(f);

    assert!(cache_entries(&out).is_empty());
    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    assert_eq!(
        status[0].metadata["content_incomplete_reason"],
        "short_read"
    );
    assert_eq!(status[0].metadata["entries_recovered"], 0);
}

// --- B2-163 residual: a long key is not a reason for an entry to disappear ---
//
// `parse_blockfile` skipped every EntryStore whose key_len exceeded the 160
// bytes that fit the first block, with a bare `continue`: no record, no counter,
// no flag. Long URLs are the ones carrying query strings and tracking
// parameters, and they left no trace at all in the listing.

/// The blocks of an EntryStore whose key runs past the first one, laid out the
/// way Chromium does it: `blocks_for_key` consecutive 256-byte blocks with the
/// key starting at offset 96 of the first.
fn entry_store_spanning(url: &str) -> Vec<u8> {
    let key = url.as_bytes();
    let mut b = vec![0u8; blocks_for_key(key.len()) * ENTRY_STORE_SIZE];
    b[0..4].copy_from_slice(&superfast_hash(key).to_le_bytes());
    b[ES_KEY_LEN..ES_KEY_LEN + 4].copy_from_slice(&(key.len() as i32).to_le_bytes());
    b[ES_KEY..ES_KEY + key.len()].copy_from_slice(key);
    b
}

/// An EntryStore whose key was too long to live in the entry at all: `key_len`
/// bytes held at the `long_key` cache address, key area left zeroed.
fn entry_store_long_key(key_len: usize, long_key_addr: u32) -> Vec<u8> {
    let mut b = vec![0u8; ENTRY_STORE_SIZE];
    b[ES_KEY_LEN..ES_KEY_LEN + 4].copy_from_slice(&(key_len as i32).to_le_bytes());
    b[ES_LONG_KEY..ES_LONG_KEY + 4].copy_from_slice(&long_key_addr.to_le_bytes());
    b
}

/// An EntryStore with an arbitrary byte string as its key, and that key's
/// hash in the header, as Chromium writes it.
fn entry_store_raw_key(key: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; ENTRY_STORE_SIZE];
    b[0..4].copy_from_slice(&superfast_hash(key).to_le_bytes());
    b[ES_KEY_LEN..ES_KEY_LEN + 4].copy_from_slice(&(key.len() as i32).to_le_bytes());
    b[ES_KEY..ES_KEY + key.len()].copy_from_slice(key);
    b
}

/// A long-key EntryStore whose header carries the hash of `key`, which lives
/// at `long_key_addr`.
fn entry_store_long_key_for(key: &[u8], long_key_addr: u32) -> Vec<u8> {
    let mut b = entry_store_long_key(key.len(), long_key_addr);
    b[0..4].copy_from_slice(&superfast_hash(key).to_le_bytes());
    b
}

/// 306 bytes: too long for one block, short enough to stay inside the entry.
fn long_tracking_url() -> String {
    format!("https://ads.example/track?{}", "p=1&".repeat(70))
}

#[test]
fn a_key_spanning_into_the_next_block_is_recovered() {
    let url = long_tracking_url();
    assert!(url.len() > ES_KEY_MAX_INLINE && url.len() <= MAX_INTERNAL_KEY_LEN);

    let out = run(blockfile(&[
        entry_store_spanning(&url),
        entry_store("http://evidence.test/tracker", 0),
    ]));

    let entries = cache_entries(&out);
    assert_eq!(
        entries.len(),
        2,
        "the spanning URL, and the entry that follows the blocks it occupies"
    );
    assert!(entries.iter().any(|e| e.metadata["url"] == url.as_str()));
    assert!(entries
        .iter()
        .any(|e| e.metadata["url"] == "http://evidence.test/tracker"));
    // Nothing was missed, so nothing may claim it was.
    assert!(status_records(&out).is_empty());
    for e in &entries {
        assert!(e.metadata.get("content_incomplete").is_none());
    }
}

#[test]
fn an_entry_whose_key_lives_outside_the_file_is_counted_not_dropped() {
    // key_len past kMaxInternalKeyLength: Chromium wrote the URL at the
    // long_key address, in a different data_# file a bare byte buffer cannot
    // reach. Recovering it here is impossible; hiding the entry is not
    // allowed, and nor is letting the entry that WAS read pass as a whole
    // listing.
    let addr = 0x8000_0000u32 | (3 << 28) | (1 << 24) | (2 << 16) | 7; // BLOCK_1K, data_2
    let out = run(blockfile(&[
        entry_store("https://cached.example/a.png", 0),
        entry_store_long_key(1200, addr),
    ]));

    let entries = cache_entries(&out);
    assert_eq!(
        entries.len(),
        2,
        "the unread entry is published too: {out:#?}"
    );
    let read = entries
        .iter()
        .find(|e| e.metadata["url"] == "https://cached.example/a.png")
        .unwrap();
    assert_eq!(read.metadata["content_incomplete"], true);
    assert_eq!(
        read.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );

    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].metadata["content_incomplete"], true);
    assert_eq!(
        status[0].metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(status[0].metadata["long_key_entries_unresolved"], 1);
    assert_eq!(status[0].metadata["spanning_key_entries_truncated"], 0);
    assert_eq!(status[0].metadata["entries_unreadable"], 1);
    assert_eq!(status[0].metadata["entries_recovered"], 1);
}

#[test]
fn a_spanning_key_cut_off_by_the_end_of_the_scan_is_counted() {
    // The entry declares 306 key bytes but only its first block is present:
    // the URL cannot be produced, and "no entry here" would be a lie.
    let mut blocks = entry_store_spanning(&long_tracking_url());
    blocks.truncate(ENTRY_STORE_SIZE);
    let out = run(blockfile(&[blocks]));

    assert!(cache_entries(&out).is_empty());
    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    assert_eq!(
        status[0].metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(status[0].metadata["spanning_key_entries_truncated"], 1);
    assert_eq!(status[0].metadata["long_key_entries_unresolved"], 0);
    assert_eq!(status[0].metadata["entries_recovered"], 0);
}

#[test]
fn a_key_with_bytes_that_are_not_utf8_is_reported_lossily_not_dropped() {
    // A damaged URL is still evidence of a fetch. It was dropped by another
    // bare `continue`; now it comes out marked as damaged.
    let out = run(blockfile(&[entry_store_raw_key(
        b"https://evidence.test/\xff\xfea",
    )]));

    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].metadata["url_encoding_lossy"], true);
    assert_eq!(entries[0].metadata["content_incomplete"], true);
    assert_eq!(
        entries[0].metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert!(entries[0].metadata["url"]
        .as_str()
        .unwrap()
        .starts_with("https://evidence.test/"));
}

/// A `data_#` file that holds its 8 KiB header and then stops inside its first
/// 256-byte record used to return an **empty vector** — the answer reserved
/// for "these bytes are not a cache at all". The guard tested `size <= 8192`
/// while its own message spoke of the header plus one entry, so a file of
/// 8,193 to 8,447 bytes fell through it, its record loop never ran, and the
/// module's stated invariant — a file that is a cache and could not be read in
/// full gets a record saying so — was broken for exactly that range.
/// HUNT-145: a `data_#` whose header declares allocated entries but whose
/// scan recovered none must not read the same as an empty cache. The header's
/// `number_of_entries` (offset 16) was unread, so both cases produced the
/// identical empty vector.
#[test]
fn a_nonempty_header_with_nothing_recovered_says_so() {
    // Header declares 3 entries, but the blocks that follow are junk the scan
    // cannot read a key out of (key_len 0, then negative) — a real-world shape
    // for a `data_#` whose entries were allocated but corrupted or unreadable.
    let mut f = block_file_header(1, 256, &[]);
    f[16..20].copy_from_slice(&3u32.to_le_bytes()); // number_of_entries
    f[20..24].copy_from_slice(&4u32.to_le_bytes()); // maximum_number_of_entries
    f.extend_from_slice(&vec![0u8; ENTRY_STORE_SIZE]); // free block: key_len 0
    f.extend_from_slice(&vec![0xAAu8; ENTRY_STORE_SIZE]); // key_len negative

    let out = run(f);
    assert!(
        out.iter()
            .any(|a| a.metadata["type"] == "BrowserCacheParseStatus"),
        "a header declaring entries with nothing recovered must leave a record: {out:?}"
    );
    let status = out
        .iter()
        .find(|a| a.metadata["type"] == "BrowserCacheParseStatus")
        .unwrap();
    assert_eq!(status.metadata["content_incomplete"], json!(true));
    assert_eq!(status.metadata["declared_entries"], json!(3));
    let detail = status.metadata["content_incomplete_detail"]
        .as_str()
        .unwrap_or_default();
    assert!(
        detail.contains('3'),
        "the declared count belongs in the sentence an examiner reads: {detail}"
    );
}

/// The counterweight, unchanged: a header that itself declares zero entries
/// stays a silent empty result — this is a genuinely empty cache, not a
/// cache whose declared entries could not be recovered.
#[test]
fn a_genuinely_empty_header_stays_silent() {
    let mut f = block_file_header(1, 256, &[]);
    f.extend_from_slice(&[0u8; ENTRY_STORE_SIZE]);
    f.extend_from_slice(&[0xAAu8; ENTRY_STORE_SIZE]);
    let out = run(f);
    assert!(
        out.is_empty(),
        "a genuinely empty cache must not gain a record: {out:?}"
    );
}

#[test]
fn a_block_file_cut_inside_its_first_record_says_so_rather_than_reading_as_empty() {
    let mut f = blockfile(&[]);
    f.extend_from_slice(&[0u8; 100]); // 8,292 bytes: header whole, record cut
    assert!(f.len() > BLOCK_HEADER_SIZE && f.len() < BLOCK_HEADER_SIZE + ENTRY_STORE_SIZE);

    let out = run(f);
    assert_eq!(out.len(), 1, "a cache that was cut must leave a record");
    let m = &out[0].metadata;
    assert_eq!(m["type"], "BrowserCacheParseStatus");
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], "short_read");
}

#[test]
fn blocks_that_are_not_entries_are_not_counted_as_unreadable_ones() {
    // The counterweight: free blocks and cached data must not inflate the
    // "could not read" number, or it stops meaning anything.
    let out = run(blockfile(&[
        vec![0u8; ENTRY_STORE_SIZE],    // free block: key_len 0
        vec![0xAAu8; ENTRY_STORE_SIZE], // data: key_len is negative
        entry_store_long_key(2000, 0),  // long key_len, but no address to it
    ]));
    assert!(out.is_empty(), "got {out:?}");
}

#[test]
fn a_long_key_pointer_that_chromium_could_not_have_written_is_not_counted() {
    // The other half of the counterweight. The scan is a heuristic over
    // 256-byte blocks, so it meets blocks that are not entries; counting one of
    // those as an entry whose URL went missing puts a fetch that never happened
    // in front of an examiner. Only the initialized bit was checked, which half
    // of all garbage words satisfy.
    let out = run(blockfile(&[
        // File type 7: there is no such block file (0..=4 are defined).
        entry_store_long_key(1200, 0xF000_0007),
        // File type 2 (data_#) with a reserved bit set: Addr::SanityCheck
        // rejects it.
        entry_store_long_key(1200, 0xA400_0007),
    ]));
    assert!(out.is_empty(), "got {out:?}");

    // ...and an address Chromium could have written is still counted, so the
    // guard cannot be passing by refusing everything.
    let out = run(blockfile(&[entry_store_long_key(1200, 0x8C00_1234)]));
    let status = status_records(&out);
    assert_eq!(status.len(), 1, "an external f_ file address is a real one");
    assert_eq!(status[0].metadata["long_key_entries_unresolved"], 1);
}

/// The block-file magic has to be the one Chromium writes, or the whole
/// blockfile branch is unreachable on evidence.
///
/// `BLOCK_MAGIC` was `0xC0F0`, a value no `data_#` file carries. Every legacy
/// Chrome / EdgeHTML disk cache therefore missed both format gates and returned
/// the empty result reserved for "this file is not a cache" — the one answer
/// this parser must never give to a cache it did not read. The crate's own
/// fixtures were built from the constant, so they agreed with it whatever it
/// was; this test spells the value out instead, and fails against the unfixed
/// crate on the first assertion.
#[test]
fn the_block_file_magic_is_the_one_chromium_writes() {
    // disk_cache::kBlockMagic, and the `signature` pinned by the dtFabric
    // spec for chrome_cache_data_block_file_header.
    assert_eq!(BLOCK_MAGIC, 0xC104_CAC3);

    let mut f = block_file_header(1, 256, &[0]);
    f[0..4].copy_from_slice(&0xC104_CAC3u32.to_le_bytes());
    f.extend_from_slice(&entry_store("https://cached.example/a.png", 0));
    let out = run(f);
    assert_eq!(
        cache_entries(&out).len(),
        1,
        "a real data_# file must parse: {out:?}"
    );

    // And the value it used to hold is not a cache at all.
    let mut wrong = block_file_header(1, 256, &[0]);
    wrong[0..4].copy_from_slice(&0xC0F0u32.to_le_bytes());
    wrong.extend_from_slice(&entry_store("https://cached.example/a.png", 0));
    assert!(run(wrong).is_empty());
}

// --- The long key, when it is in the file we were handed ---------------------
//
// A key past kMaxInternalKeyLength is written at the `long_key` cache address.
// That address names the file, and Chromium picks the file from the key's
// LENGTH: 928..1023 bytes is allocated out of the 256-byte block file, which is
// the same file the EntryStore itself came from. Those URLs are in the bytes
// already in hand and were being counted as unreachable.

/// A 1000-byte URL: past the 927 that fit inside the entry, short enough that
/// Chromium allocates its key out of a 256-byte block file.
fn long_key_url() -> String {
    format!("https://ads.example/track?q={}", "a".repeat(972))
}

/// A `data_1` holding one long-key entry in block 0 whose key bytes live in
/// block 4 of the same file, laid out the way Chromium writes them: the key,
/// then the trailing NUL, inside an allocation of `ceil((key_len + 1) / 256)`
/// blocks.
fn blockfile_with_same_file_long_key(url: &str) -> Vec<u8> {
    let key = url.as_bytes();
    let key_len = key.len();
    let start_block = 4usize;
    let num_blocks = (key_len + 1).div_ceil(ENTRY_STORE_SIZE);
    // initialized | file type 2 (256-byte blocks) | blocks - 1 | data_1 | block 4
    let addr = 0x8000_0000u32
        | (2 << 28)
        | ((num_blocks as u32 - 1) << 24)
        | (1 << 16)
        | start_block as u32;

    let mut allocated = vec![0usize];
    allocated.extend(start_block..start_block + num_blocks);
    let mut f = block_file_header(1, 256, &allocated);
    f.extend_from_slice(&entry_store_long_key_for(key, addr));
    // Blocks 1..4 are free.
    f.resize(BLOCK_HEADER_SIZE + start_block * ENTRY_STORE_SIZE, 0);
    f.extend_from_slice(key);
    f.push(0);
    f.resize(
        BLOCK_HEADER_SIZE + (start_block + num_blocks) * ENTRY_STORE_SIZE,
        0,
    );
    f
}

#[test]
fn a_long_key_written_back_into_this_same_file_is_recovered() {
    let url = long_key_url();
    assert!(url.len() > MAX_INTERNAL_KEY_LEN);
    let out = run(blockfile_with_same_file_long_key(&url));

    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 1, "got {out:?}");
    assert_eq!(entries[0].metadata["url"], url.as_str());
    // The URL did not come from the entry's own block, and the record says so.
    assert_eq!(entries[0].metadata["key_source"], "long_key_same_file");
    assert_eq!(entries[0].metadata["key_length"], json!(url.len()));
    assert!(
        status_records(&out).is_empty(),
        "nothing was missed, so nothing may claim it was: {out:?}"
    );
}

#[test]
fn a_long_key_addressed_in_this_file_whose_bytes_are_gone_is_counted_not_invented() {
    // The address says the key is here and the blocks holding it were never
    // read. Publishing whatever is at that offset would attribute some other
    // cached URL to this entry's timestamp; the loss is counted instead.
    let mut f = blockfile_with_same_file_long_key(&long_key_url());
    f.truncate(BLOCK_HEADER_SIZE + ENTRY_STORE_SIZE);
    let out = run(f);

    assert!(cache_entries(&out).is_empty());
    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].metadata["long_key_entries_unresolved"], 1);
    assert_eq!(status[0].metadata["long_key_entries_unread_here"], 1);
    assert_eq!(status[0].metadata["long_key_entries_in_other_file"], 0);
    assert_eq!(status[0].metadata["long_key_entries_recovered"], 0);
    assert_eq!(status[0].metadata["entries_recovered"], 0);
}

/// Every stamp this parser writes has to carry its sentence on the key the
/// examiner-facing reader displays.
///
/// `frontend/src/lib/incompleteness.ts` is the one place the incompleteness
/// pair is read, and it takes the parser's sentence from
/// `content_incomplete_detail`. This crate wrote it to a bare `detail` that
/// nothing on that path shows, and stamped the cache entries themselves with no
/// sentence at all — so an examiner met "short_read" on a URL record with
/// nothing to say whether the URL was partial or the list around it was. Each
/// assertion here fails against the unfixed crate.
#[test]
fn every_cache_stamp_carries_its_sentence_where_the_reader_looks() {
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::halved(sample_blockfile()));
    let out = run_ds(ds);

    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    let detail = status[0].metadata["detail"].as_str().unwrap();
    assert_eq!(
        status[0].metadata["content_incomplete_detail"],
        json!(detail)
    );

    for e in cache_entries(&out) {
        let said = e.metadata["content_incomplete_detail"]
            .as_str()
            .expect("a stamped entry must say what is incomplete about it");
        assert!(
            said.contains("recovered whole") && said.contains("listing"),
            "the URL is whole and the listing is short; say which: {said}"
        );
    }

    // A key whose own bytes were substituted makes the more specific
    // statement, and keeps it.
    let lossy = run(blockfile(&[entry_store_raw_key(
        b"https://evidence.test/\xff\xfea",
    )]));
    let entries = cache_entries(&lossy);
    assert_eq!(entries.len(), 1);
    assert!(entries[0].metadata["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("not valid UTF-8"));
}

/// A record can be short in two ways at once, and the reason token names only
/// one of them.
///
/// A cache key with substituted bytes, in a file the source under-delivered,
/// carries `content_incomplete_reason: "short_read"` — the loop that stamps the
/// listing shortfall writes that on every record. When the sentence beside it
/// was left as the key's own "not valid UTF-8", the pair read as "the short read
/// damaged this URL", which is a cause this parser never established; and the
/// listing shortfall, which the token does name, went unexplained. Both facts
/// belong on the record. Against the version that skipped the listing sentence
/// for lossy records the second assertion fails.
#[test]
fn a_lossy_key_in_a_short_read_file_says_both_things_and_contradicts_neither() {
    let bytes = blockfile(&[entry_store_raw_key(b"https://evidence.test/\xff\xfea")]);
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::halved(bytes));
    let out = run_ds(ds);

    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 1, "got {out:?}");
    assert_eq!(
        entries[0].metadata["content_incomplete_reason"],
        "short_read"
    );
    let said = entries[0].metadata["content_incomplete_detail"]
        .as_str()
        .unwrap();
    assert!(said.contains("not valid UTF-8"), "{said}");
    assert!(
        said.contains("the listing this URL belongs to is short"),
        "the reason token is about the listing; the sentence has to explain it: {said}"
    );
    // ...and it must not also claim this URL came out whole, because it did not.
    assert!(!said.contains("recovered whole"), "{said}");
}

#[test]
fn a_long_key_address_is_read_the_way_chromium_wrote_it() {
    let key_len = 1000usize; // 1001 stored bytes -> 4 blocks of 256
    let addr = 0x8000_0000u32 | (2 << 28) | (3 << 24) | (1 << 16) | 4;
    assert_eq!(
        locate_long_key(addr, Some(1), key_len),
        LongKey::ThisFile(BLOCK_HEADER_SIZE + 4 * 256)
    );
    // Same address, a file this module was not handed: decoded to the place
    // the key is, so the sibling can be opened by name or the record can say
    // where to look.
    let in_data_1 = LongKey::OtherFile(RemoteKey::BlockFile {
        file: 1,
        block: 4,
        block_size: 256,
    });
    assert_eq!(locate_long_key(addr, Some(2), key_len), in_data_1);
    // A header that was never read cannot be used to claim the key is here.
    assert_eq!(locate_long_key(addr, None, key_len), in_data_1);
    // An external f_ file: real, named from the low 28 bits of the address.
    assert_eq!(
        locate_long_key(0x8C00_1234, Some(1), 20_000),
        LongKey::OtherFile(RemoteKey::External { number: 0xC00_1234 })
    );
    // A block file too small to have held this key is not the allocation
    // Chromium made for it, so it is not an entry's key address at all.
    assert_eq!(locate_long_key(addr, Some(1), 3_000), LongKey::NotAnAddress);
    assert_eq!(
        locate_long_key(0x8000_0000 | (2 << 28) | (1 << 16) | 4, Some(1), key_len),
        LongKey::NotAnAddress,
        "one 256-byte block cannot hold a 1000-byte key"
    );
}

#[test]
fn a_file_that_is_not_a_cache_still_yields_nothing_at_all() {
    // The status record must never fire on a file this parser does not own,
    // or every unrelated file in the image gains a spurious finding.
    assert!(run(b"not a chrome cache file at all........".to_vec()).is_empty());
    assert!(run(vec![0u8; 4096]).is_empty());
}

// ── Long keys in a sibling block file (ROADMAP §5.7) ─────────────────────────

/// Chromium's own `Cache` directory from the plaso corpus: `data_1` holds two
/// entries whose 1,339- and 1,335-byte keys were written to 1 KiB blocks 20
/// and 38 of `data_2` beside it (`long_key` words `0xb1020014` and
/// `0xb1020026`, checked by hand against the bytes of that file).
fn plaso_chrome_cache_dir() -> Option<std::path::PathBuf> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../reference/plaso/test_data/chrome_cache");
    dir.join("data_1").is_file().then_some(dir)
}

fn run_file(path: &std::path::Path) -> Vec<Artifact> {
    let ds = seance_core::data_source::FileDataSource::new(path.to_path_buf()).unwrap();
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(ds)),
        json!({ "name": path.file_name().unwrap().to_str().unwrap() }),
    );
    ChromeCacheParser.process(&art).unwrap()
}

#[test]
fn a_long_key_in_a_sibling_block_file_is_recovered_from_it_and_says_where_from() {
    let Some(dir) = plaso_chrome_cache_dir() else {
        eprintln!("Skipping test: reference/plaso/test_data/chrome_cache not found");
        return;
    };
    let out = run_file(&dir.join("data_1"));

    let from_sibling: Vec<&Artifact> = cache_entries(&out)
        .into_iter()
        .filter(|e| e.metadata["key_source"] == "long_key_other_file")
        .collect();
    assert_eq!(from_sibling.len(), 2, "{out:#?}");
    for (block, key_len) in [(20, 1339), (38, 1335)] {
        let rec = from_sibling
            .iter()
            .find(|e| e.metadata["key_block"] == block)
            .unwrap_or_else(|| {
                panic!("no entry resolved from data_2 block {block}: {from_sibling:#?}")
            });
        let url = rec.metadata["url"].as_str().unwrap();
        assert_eq!(url.len(), key_len);
        assert!(url.starts_with("https://www.google.ch/gen_204?v=3&s=web&e=17259,"));
        assert_eq!(rec.metadata["key_file"], "data_2");
        assert_eq!(rec.metadata["key_length"], key_len);
        assert_eq!(rec.metadata["key_offset"], 8192 + block * 1024);
        assert!(
            rec.metadata.get("creation_time").is_some(),
            "the entry's own timestamp travels with the URL"
        );
        assert!(
            rec.metadata.get("url_unrecoverable_reason").is_none(),
            "a recovered URL carries no reason for not recovering it"
        );
    }
    for s in status_records(&out) {
        assert_eq!(
            s.metadata["long_key_entries_in_other_file"], 0,
            "both sibling keys were reached, so none is a loss: {s:#?}"
        );
    }
}

#[test]
fn a_long_key_in_a_sibling_the_source_cannot_reach_names_the_file_and_block() {
    // A bare byte buffer cannot look beside itself. The entry must not vanish,
    // must not be given a short or invented URL, and must say exactly where
    // the key is so an examiner can go and read it.
    let addr = 0x8000_0000u32 | (3 << 28) | (1 << 24) | (2 << 16) | 7;
    let ct = (1_357_473_600u64 + 11_644_473_600) * 1_000_000;
    let mut entry = entry_store_long_key(1200, addr);
    entry[ES_CREATION_TIME..ES_CREATION_TIME + 8].copy_from_slice(&ct.to_le_bytes());
    let out = run(blockfile(&[
        entry_store("https://cached.example/a.png", 0),
        entry,
    ]));

    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 2, "{out:#?}");
    let unread = entries
        .iter()
        .find(|e| e.metadata.get("url").is_none())
        .expect("the entry whose key is elsewhere is published without a URL");
    assert_eq!(unread.metadata["key_file"], "data_2");
    assert_eq!(unread.metadata["key_block"], 7);
    assert_eq!(unread.metadata["key_offset"], 8192 + 7 * 1024);
    assert_eq!(unread.metadata["key_length"], 1200);
    assert_eq!(unread.metadata["creation_time"], 1_357_473_600);
    assert_eq!(unread.metadata["content_incomplete"], true);
    assert_eq!(
        unread.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    let detail = unread.metadata["content_incomplete_detail"]
        .as_str()
        .unwrap();
    assert!(detail.contains("1200"), "{detail}");
    assert!(detail.contains("927"), "{detail}");
    assert!(detail.contains("data_2 block 7"), "{detail}");
    assert!(detail.contains("not reachable from this file"), "{detail}");
    assert_eq!(
        unread.metadata["url_unrecoverable_reason"],
        "sibling_lookup_unsupported"
    );
    let name = unread.metadata["name"].as_str().unwrap();
    assert!(name.contains("data_2 block 7"), "{name}");

    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].metadata["long_key_entries_in_other_file"], 1);
    assert_eq!(
        status[0].metadata["entries_recovered"], 1,
        "a URL-less entry is not a recovered URL"
    );
}

/// A `data_1` in its own directory, with or without a `data_2` beside it.
fn cache_dir_with(data_1: &[u8], data_2: Option<&[u8]>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("data_1"), data_1).unwrap();
    if let Some(bytes) = data_2 {
        std::fs::write(dir.path().join("data_2"), bytes).unwrap();
    }
    dir
}

/// A `data_1` whose one entry names `data_2` block 7 (1 KiB blocks) for
/// `key`, and carries `key`'s hash.
fn data_1_pointing_at_data_2(key: &[u8]) -> Vec<u8> {
    let num_blocks = (key.len() + 1).div_ceil(1024) as u32;
    let addr = 0x8000_0000u32 | (3 << 28) | ((num_blocks - 1) << 24) | (2 << 16) | 7;
    blockfile(&[entry_store_long_key_for(key, addr)])
}

/// A `data_2` (1 KiB blocks) holding `key` and its NUL at block 7.
fn data_2_holding(key: &[u8], this_file: u16) -> Vec<u8> {
    let mut f = block_file_header(this_file, 1024, &[7, 8]);
    f.resize(BLOCK_HEADER_SIZE + 7 * 1024, 0);
    f.extend_from_slice(key);
    f.push(0);
    f.resize(BLOCK_HEADER_SIZE + 9 * 1024, 0);
    f
}

#[test]
fn a_long_key_in_a_sibling_that_is_not_beside_this_file_says_so() {
    let dir = cache_dir_with(&data_1_pointing_at_data_2(&[b'x'; 1200]), None);
    let out = run_file(&dir.path().join("data_1"));

    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 1, "{out:#?}");
    assert!(entries[0].metadata.get("url").is_none());
    assert_eq!(entries[0].metadata["key_file"], "data_2");
    assert_eq!(entries[0].metadata["key_block"], 7);
    assert_eq!(
        entries[0].metadata["url_unrecoverable_reason"],
        "sibling_not_present"
    );
    let detail = entries[0].metadata["content_incomplete_detail"]
        .as_str()
        .unwrap();
    assert!(detail.contains("data_2 block 7"), "{detail}");
    assert!(detail.contains("not present beside"), "{detail}");
}

#[test]
fn a_long_key_in_a_sibling_beside_this_file_is_read_from_it() {
    let url = format!("https://ads.example/track?q={}", "b".repeat(1172));
    let dir = cache_dir_with(
        &data_1_pointing_at_data_2(url.as_bytes()),
        Some(&data_2_holding(url.as_bytes(), 2)),
    );
    let out = run_file(&dir.path().join("data_1"));

    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 1, "{out:#?}");
    assert_eq!(entries[0].metadata["url"], url.as_str());
    assert_eq!(entries[0].metadata["key_source"], "long_key_other_file");
    assert_eq!(entries[0].metadata["key_file"], "data_2");
    assert_eq!(entries[0].metadata["key_block"], 7);
    assert!(entries[0].metadata.get("content_incomplete").is_none());
    assert!(
        status_records(&out).is_empty(),
        "nothing was missed, so nothing may claim it was: {out:#?}"
    );
}

#[test]
fn a_sibling_that_is_not_the_block_file_the_address_names_is_not_read() {
    // The file beside data_1 is called data_2 but its own header says it is
    // block file 3: reading a key out of it would attribute bytes from the
    // wrong file to this entry. Refuse, and say why.
    let url = format!("https://ads.example/track?q={}", "c".repeat(1172));
    let dir = cache_dir_with(
        &data_1_pointing_at_data_2(url.as_bytes()),
        Some(&data_2_holding(url.as_bytes(), 3)),
    );
    let out = run_file(&dir.path().join("data_1"));

    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 1, "{out:#?}");
    assert!(entries[0].metadata.get("url").is_none());
    assert_eq!(
        entries[0].metadata["url_unrecoverable_reason"],
        "sibling_header_mismatch"
    );
    let detail = entries[0].metadata["content_incomplete_detail"]
        .as_str()
        .unwrap();
    assert!(detail.contains("block file 3"), "{detail}");
    assert_eq!(
        status_records(&out)[0].metadata["long_key_entries_in_other_file"],
        1
    );
}

/// The two gates a sibling key passes through are different findings and
/// carry different tokens. Here data_2 is the right file, but block 7 does
/// not hold a NUL exactly `key_len` bytes in: the bytes there are not this
/// entry's key at all.
#[test]
fn a_sibling_whose_block_is_not_terminated_at_the_key_length_is_counted_not_invented() {
    // 1201 non-NUL bytes: the byte 1200 in is a letter, not the terminator.
    let dir = cache_dir_with(
        &data_1_pointing_at_data_2(&[b'x'; 1200]),
        Some(&data_2_holding(&[b'x'; 1201], 2)),
    );
    let out = run_file(&dir.path().join("data_1"));

    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 1, "{out:#?}");
    assert!(entries[0].metadata.get("url").is_none());
    assert_eq!(
        entries[0].metadata["url_unrecoverable_reason"],
        "sibling_key_not_terminated_at_length"
    );
    let detail = entries[0].metadata["content_incomplete_detail"]
        .as_str()
        .unwrap();
    assert!(detail.contains("NUL"), "{detail}");
    assert_eq!(
        status_records(&out)[0].metadata["long_key_entries_in_other_file"],
        1
    );
}

/// HUNT-185. A NUL-terminated key of exactly the declared length, whose hash
/// is the one the entry carries, in Chromium's split-cache form
/// (`1/0/_dk_<top-frame site> <frame site> <url>`). It was refused at the
/// scheme gate; it is this entry's key, and its URL and both sites are
/// published.
#[test]
fn a_split_cache_long_key_in_a_sibling_is_recovered_with_its_sites() {
    let key_len = 1200;
    let mut key =
        b"1/0/_dk_https://example.test https://frame.test https://example.test/a?q=".to_vec();
    key.resize(key_len, b'a');
    let dir = cache_dir_with(
        &data_1_pointing_at_data_2(&key),
        Some(&data_2_holding(&key, 2)),
    );
    let out = run_file(&dir.path().join("data_1"));

    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 1, "{out:#?}");
    let m = &entries[0].metadata;
    let url =
        std::str::from_utf8(&key[b"1/0/_dk_https://example.test https://frame.test ".len()..])
            .unwrap();
    assert_eq!(m["url"], url);
    assert_eq!(m["top_frame_site"], "https://example.test");
    assert_eq!(m["frame_site"], "https://frame.test");
    assert_eq!(m["cache_key_form"], "double_keyed");
    assert_eq!(m["cache_key"], std::str::from_utf8(&key).unwrap());
    assert_eq!(m["key_hash_verified"], true);
    assert_eq!(m["key_file"], "data_2");
    assert!(status_records(&out).is_empty(), "{out:#?}");
}

/// A key that is this entry's (its hash matches, its NUL is where the length
/// says) but whose form this build does not know is not dropped and not
/// guessed at: it is published without a URL, showing the key as stored, and
/// counted — the gate's refusals are no longer silent.
#[test]
fn a_verified_key_of_a_form_not_recognised_is_published_raw_and_counted() {
    let key_len = 1200;
    let mut key = b"1/0/_zz_https://example.test https://example.test/x".to_vec();
    key.resize(key_len, b'a');
    let dir = cache_dir_with(
        &data_1_pointing_at_data_2(&key),
        Some(&data_2_holding(&key, 2)),
    );
    let out = run_file(&dir.path().join("data_1"));

    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 1, "{out:#?}");
    let m = &entries[0].metadata;
    assert!(m.get("url").is_none());
    assert_eq!(
        m["url_unrecoverable_reason"],
        "cache_key_form_not_recognised"
    );
    assert!(m["cache_key"].as_str().unwrap().starts_with("1/0/_zz_"));
    assert_eq!(m["key_hash_verified"], true);
    let status = status_records(&out);
    assert_eq!(status.len(), 1, "{out:#?}");
    assert_eq!(status[0].metadata["entries_key_form_not_recognised"], 1);
    assert_eq!(status[0].metadata["entries_unreadable"], 1);
}

/// The key at the sibling offset is NUL-terminated at the right length and
/// has a recognised form, but it does not hash to the value this entry's
/// header carries: it is some other entry's key, and attributing it to this
/// entry's timestamp would be a fabricated fetch.
#[test]
fn a_sibling_key_that_is_not_this_entrys_by_its_hash_is_refused() {
    let url = format!("https://ads.example/track?q={}", "d".repeat(1172));
    let other = format!("https://ads.example/track?q={}", "e".repeat(1172));
    let dir = cache_dir_with(
        &data_1_pointing_at_data_2(url.as_bytes()),
        Some(&data_2_holding(other.as_bytes(), 2)),
    );
    let out = run_file(&dir.path().join("data_1"));
    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 1, "{out:#?}");
    assert!(entries[0].metadata.get("url").is_none());
    assert_eq!(
        entries[0].metadata["url_unrecoverable_reason"],
        "sibling_key_hash_mismatch"
    );
}

/// The plaso `chrome_cache_v3` corpus (HUNT-185, HUNT-145), counted
/// independently over `data_1` (532,480 bytes, 2,048 blocks of 256) with a
/// separate Python reading of the format: 826 inline keys whose SuperFastHash
/// equals the hash their entry carries — 816 `1/0/_dk_<site> <site> <url>`,
/// 6 `1/0/_dk_s_…` (subframe document resources) and 4 `Range_1/0/_dk_…:<sig>:<n>`
/// sparse children — plus 36 long keys that also verify: 2 in `data_1` itself,
/// 33 in `data_2`, 1 in `data_3`. 12 more blocks declare a long key with no
/// initialised address and are not entries. Every one of the 862 entry blocks
/// is marked allocated in the file's bitmap. Before HUNT-185 this file yielded
/// **0 URLs**: every key was refused at the scheme gate.
#[test]
fn the_v3_corpus_recovers_every_split_cache_key_with_its_sites() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../reference/plaso/test_data/chrome_cache_v3");
    if !dir.join("data_1").is_file() {
        eprintln!("Skipping test: reference/plaso/test_data/chrome_cache_v3 not found");
        return;
    }
    let out = run_file(&dir.join("data_1"));

    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 862, "{:#?}", status_records(&out));
    assert!(
        status_records(&out).is_empty(),
        "{:#?}",
        status_records(&out)
    );
    for e in &entries {
        let m = &e.metadata;
        assert!(m["url"].as_str().unwrap().starts_with("http"), "{m}");
        assert_eq!(m["key_hash_verified"], true, "{m}");
        assert_eq!(m["cache_key_form"], "double_keyed", "{m}");
        assert!(m["top_frame_site"].as_str().is_some(), "{m}");
        assert!(m["frame_site"].as_str().is_some(), "{m}");
        assert_eq!(m["allocation"], "allocated", "{m}");
        assert!(m.get("content_incomplete").is_none(), "{m}");
    }
    let count = |f: &dyn Fn(&&&Artifact) -> bool| entries.iter().filter(f).count();
    assert_eq!(count(&|e| e.metadata.get("key_source").is_none()), 826);
    assert_eq!(
        count(&|e| e.metadata["key_source"] == "long_key_same_file"),
        2
    );
    assert_eq!(count(&|e| e.metadata["key_file"] == "data_2"), 33);
    assert_eq!(count(&|e| e.metadata["key_file"] == "data_3"), 1);
    assert_eq!(
        count(&|e| e.metadata["subframe_document_resource"] == true),
        6
    );
    assert_eq!(count(&|e| e.metadata.get("sparse_child_id").is_some()), 4);

    // One entry, checked field by field: block 23.
    let e = entries
        .iter()
        .find(|e| e.metadata["key_block_in_file"] == 23)
        .expect("block 23 holds an entry");
    assert_eq!(
        e.metadata["url"],
        "https://fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu4mxK.woff2"
    );
    assert_eq!(e.metadata["top_frame_site"], "https://google.com");
    assert_eq!(e.metadata["frame_site"], "https://google.com");
    assert_eq!(e.metadata["key_hash"], "3ecdbace");

    // A sparse child (block 349): the URL is the parent's, without the
    // `:<signature>:<child>` suffix, which is published beside it.
    let r = entries
        .iter()
        .find(|e| e.metadata["key_block_in_file"] == 349)
        .unwrap();
    assert_eq!(
        r.metadata["url"],
        "https://www.youtube.com/s/search/audio/failure.mp3"
    );
    assert_eq!(r.metadata["sparse_signature"], "2f5d2d93d442c8");
    assert_eq!(r.metadata["sparse_child_id"], "0");
    assert_eq!(r.metadata["top_frame_site"], "https://youtube.com");
}

/// The first plaso corpus: 215 inline keys and the 2 sibling keys, every one
/// verified against its entry's hash.
#[test]
fn the_v1_corpus_keys_all_verify_against_their_entry_hash() {
    let Some(dir) = plaso_chrome_cache_dir() else {
        eprintln!("Skipping test: reference/plaso/test_data/chrome_cache not found");
        return;
    };
    let out = run_file(&dir.join("data_1"));
    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 217, "{:#?}", status_records(&out));
    assert!(entries
        .iter()
        .all(|e| e.metadata["key_hash_verified"] == true));
    assert!(entries
        .iter()
        .all(|e| e.metadata["cache_key_form"] == "url"));
    assert!(entries
        .iter()
        .all(|e| e.metadata["allocation"] == "allocated"));
    assert!(
        status_records(&out).is_empty(),
        "{:#?}",
        status_records(&out)
    );
}

/// `data_0` (rankings, 36-byte blocks), `data_2` and `data_3` (1 KiB and 4 KiB
/// blocks holding long keys and stream data) hold no EntryStore: Chromium
/// allocates every entry from a 256-byte block file. Walking them at 256
/// bytes read stream data as entries, and a header declaring allocations with
/// nothing recovered said "entries could not be read" about a file that holds
/// none by design.
#[test]
fn the_block_files_that_hold_no_entries_yield_nothing() {
    for corpus in ["chrome_cache", "chrome_cache_v3"] {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../reference/plaso/test_data")
            .join(corpus);
        if !dir.join("data_1").is_file() {
            eprintln!("Skipping test: {corpus} not found");
            continue;
        }
        for f in ["data_0", "data_2", "data_3"] {
            let out = run_file(&dir.join(f));
            assert!(out.is_empty(), "{corpus}/{f}: {out:#?}");
        }
    }
}

/// HUNT-184: the same real cache, as a filesystem parser inside a disk image
/// publishes it — sources with no path, bundled by `attach_sibling_bundles` —
/// reaches its sibling long keys exactly as the loose directory does.
#[test]
fn a_sibling_long_key_is_reached_from_inside_a_disk_image() {
    let Some(dir) = plaso_chrome_cache_dir() else {
        eprintln!("Skipping test: reference/plaso/test_data/chrome_cache not found");
        return;
    };
    let case = Uuid::new_v4();
    let mut listing: Vec<Artifact> = ["data_0", "data_1", "data_2", "data_3", "index"]
        .iter()
        .map(|name| {
            let bytes = std::fs::read(dir.join(name)).unwrap();
            let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
            Artifact::new(
                case,
                ArtifactType::FileEntry,
                Some(ds),
                json!({ "name": name, "path": format!("/Users/u/AppData/Local/Google/Chrome/User Data/Default/Cache/{name}") }),
            )
        })
        .collect();
    seance_core::data_source::attach_sibling_bundles(&mut listing);
    let out = ChromeCacheParser.process(&listing[1]).unwrap();

    let from_sibling: Vec<&Artifact> = cache_entries(&out)
        .into_iter()
        .filter(|e| e.metadata["key_source"] == "long_key_other_file")
        .collect();
    assert_eq!(from_sibling.len(), 2, "{out:#?}");
    for e in &from_sibling {
        assert_eq!(e.metadata["key_file"], "data_2");
        assert!(e.metadata["url"]
            .as_str()
            .unwrap()
            .starts_with("https://www.google.ch/gen_204"));
        assert!(e.metadata.get("url_unrecoverable_reason").is_none());
    }
    assert_eq!(cache_entries(&out).len(), 217);
}

#[test]
fn a_long_key_in_an_external_file_names_it_and_is_not_opened() {
    // File type 0: the key is the first bytes of `f_00000b`. This module
    // opens no external file, and says which one it would have been.
    let addr = 0x8000_0000u32 | 0x0b;
    let out = run(blockfile(&[entry_store_long_key(20_000, addr)]));

    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 1, "{out:#?}");
    assert!(entries[0].metadata.get("url").is_none());
    assert_eq!(entries[0].metadata["key_file"], "f_00000b");
    assert!(entries[0].metadata.get("key_block").is_none());
    assert_eq!(entries[0].metadata["key_offset"], 0);
    assert_eq!(
        entries[0].metadata["url_unrecoverable_reason"],
        "external_file_not_opened"
    );
    let detail = entries[0].metadata["content_incomplete_detail"]
        .as_str()
        .unwrap();
    assert!(detail.contains("f_00000b"), "{detail}");
}

// ── HUNT-145: the header's bitmap and block size, and the entry's key hash ──

/// `disk_cache::Hash` is SuperFastHash. Known answers taken from the entry
/// headers Chromium wrote in the plaso corpora (block, key, stored hash).
#[test]
fn superfast_hash_matches_the_hashes_chromium_wrote() {
    for (key, hash) in [
        (
            &b"http://tools.google.com/chrome/intl/en/welcome.html"[..],
            0xb71a_616a,
        ),
        (
            b"https://www.google.com/intl/en/chrome/browser/welcome.html",
            0xe98f_5932,
        ),
        (
            b"1/0/_dk_https://google.com https://google.com https://fonts.gstatic.com/s/roboto/v18/KFOmCnqEu92Fr1Mu4mxK.woff2",
            0x3ecd_bace,
        ),
        (
            b"1/0/_dk_https://google.com https://google.com https://fonts.gstatic.com/s/roboto/v18/KFOlCnqEu92Fr1MmWUlfBBc4.woff2",
            0xa5e4_a7af,
        ),
    ] {
        assert_eq!(superfast_hash(key), hash, "{}", String::from_utf8_lossy(key));
    }
    assert_eq!(superfast_hash(b""), 0);
}

#[test]
fn an_inline_key_that_does_not_hash_to_its_entry_is_published_but_says_so() {
    let mut e = entry_store("https://cached.example/a.png", 0);
    e[0..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let out = run(blockfile(&[e]));
    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 1, "{out:#?}");
    let m = &entries[0].metadata;
    assert_eq!(m["url"], "https://cached.example/a.png");
    assert_eq!(m["key_hash"], "12345678");
    assert_eq!(m["key_hash_verified"], false);
    assert_eq!(m["content_incomplete"], true);
    let detail = m["content_incomplete_detail"].as_str().unwrap();
    assert!(detail.contains("hash"), "{detail}");
    assert!(detail.contains("12345678"), "{detail}");

    // The clean case says it verified.
    let out = run(blockfile(&[entry_store("https://cached.example/a.png", 0)]));
    assert_eq!(cache_entries(&out)[0].metadata["key_hash_verified"], true);
    assert!(cache_entries(&out)[0]
        .metadata
        .get("content_incomplete")
        .is_none());
}

/// An inline key was believed on its length and a scheme prefix alone: a
/// URL-looking run of bytes with no NUL where the length ends, and no hash to
/// back it, is not an entry's key.
#[test]
fn an_unverified_inline_key_without_its_terminator_is_not_an_entry() {
    let mut e = entry_store("https://cached.example/a.png", 0);
    e[0..4].copy_from_slice(&0u32.to_le_bytes());
    let len = "https://cached.example/a.png".len();
    e[ES_KEY + len] = b'X';
    let out = run(blockfile(&[e]));
    assert!(cache_entries(&out).is_empty(), "{out:#?}");
}

#[test]
fn an_entry_in_a_block_the_bitmap_marks_free_is_published_as_freed() {
    let mut f = block_file_header(1, 256, &[1]);
    f.extend_from_slice(&entry_store("https://evicted.example/", 0)); // block 0: free
    f.extend_from_slice(&entry_store("https://live.example/", 0)); // block 1
    let out = run(f);
    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 2, "{out:#?}");
    let freed = entries
        .iter()
        .find(|e| e.metadata["url"] == "https://evicted.example/")
        .unwrap();
    assert_eq!(freed.metadata["allocation"], "free");
    assert!(freed.metadata["name"].as_str().unwrap().contains("freed"));
    assert!(freed.metadata["allocation_detail"]
        .as_str()
        .unwrap()
        .contains("allocation bitmap"));
    let live = entries
        .iter()
        .find(|e| e.metadata["url"] == "https://live.example/")
        .unwrap();
    assert_eq!(live.metadata["allocation"], "allocated");
}

/// The header's `block_size` is read and honoured: a 1 KiB block file is not
/// read as 256-byte EntryStores, even when its bytes would pass for one.
#[test]
fn a_block_file_of_larger_blocks_is_not_walked_for_entries() {
    let mut f = block_file_header(2, 1024, &[0]);
    f.extend_from_slice(&entry_store("https://looks.like/an-entry", 0));
    f.resize(BLOCK_HEADER_SIZE + 1024, 0);
    assert!(run(f).is_empty());
}

/// A block size no Chromium block file has is damage, and the file is not
/// walked at a guessed stride; that is said, not left as an empty result.
#[test]
fn a_block_size_no_block_file_has_is_reported_not_guessed() {
    let mut f = block_file_header(1, 0, &[0]);
    f.extend_from_slice(&entry_store("https://cached.example/a.png", 0));
    let out = run(f);
    assert!(cache_entries(&out).is_empty(), "{out:#?}");
    let status = status_records(&out);
    assert_eq!(status.len(), 1, "{out:#?}");
    assert_eq!(
        status[0].metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert_eq!(status[0].metadata["declared_block_size"], 0);
    assert!(status[0].metadata["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("block size"));
}

// ── HUNT-185: the split-cache key form, inline ──────────────────────────────

#[test]
fn an_inline_split_cache_key_publishes_its_url_and_sites() {
    let key = "1/0/_dk_https://top.test https://frame.test https://cdn.test/app.js";
    let out = run(blockfile(&[entry_store(key, 0)]));
    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 1, "{out:#?}");
    let m = &entries[0].metadata;
    assert_eq!(m["url"], "https://cdn.test/app.js");
    assert_eq!(m["top_frame_site"], "https://top.test");
    assert_eq!(m["frame_site"], "https://frame.test");
    assert_eq!(m["cache_key"], key);
    assert_eq!(m["cache_key_form"], "double_keyed");
    assert!(m.get("subframe_document_resource").is_none());
    assert_eq!(m["name"], "Cached URL: https://cdn.test/app.js");
}

#[test]
fn a_subframe_document_resource_key_says_so() {
    let key = "1/0/_dk_s_https://top.test https://top.test https://top.test/frame.html";
    let out = run(blockfile(&[entry_store(key, 0)]));
    let m = &cache_entries(&out)[0].metadata;
    assert_eq!(m["url"], "https://top.test/frame.html");
    assert_eq!(m["top_frame_site"], "https://top.test");
    assert_eq!(m["subframe_document_resource"], true);
}

#[test]
fn a_sparse_child_key_publishes_the_parent_url() {
    let key =
        "Range_1/0/_dk_https://yt.test https://yt.test https://www.yt.test/a.mp3:2f5d2d93d442c8:1a";
    let out = run(blockfile(&[entry_store(key, 0)]));
    let m = &cache_entries(&out)[0].metadata;
    assert_eq!(m["url"], "https://www.yt.test/a.mp3");
    assert_eq!(m["sparse_signature"], "2f5d2d93d442c8");
    assert_eq!(m["sparse_child_id"], "1a");
    // A plain, single-keyed URL carries none of the split-cache fields.
    let out = run(blockfile(&[entry_store("https://plain.test/x", 0)]));
    let m = &cache_entries(&out)[0].metadata;
    assert_eq!(m["cache_key_form"], "url");
    assert!(m.get("top_frame_site").is_none());
    assert!(
        m.get("cache_key").is_none(),
        "the key IS the URL; not repeated"
    );
}

#[test]
fn a_verified_inline_key_of_an_unknown_form_is_counted_not_dropped() {
    let key = "1/0/_cn_https://top.test https://cdn.test/app.js";
    let out = run(blockfile(&[
        entry_store(key, 0),
        entry_store("https://cached.example/a.png", 0),
    ]));
    let entries = cache_entries(&out);
    assert_eq!(entries.len(), 2, "{out:#?}");
    let raw = entries
        .iter()
        .find(|e| e.metadata.get("url").is_none())
        .expect("the unknown form is published without a URL");
    assert_eq!(raw.metadata["cache_key"], key);
    assert_eq!(
        raw.metadata["url_unrecoverable_reason"],
        "cache_key_form_not_recognised"
    );
    let status = status_records(&out);
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].metadata["entries_key_form_not_recognised"], 1);
}
