//! Panic-safety net for the forensic SQLite parser.
//!
//! The parser's contract is to *degrade*, never panic, on hostile, truncated, or
//! fragment-sized input -- because the orchestrator runs every module under
//! `catch_unwind`, a panic is silently converted to a logged error and never
//! fails ingestion or any integration test. That made a real off-by-one (an
//! unguarded `data[HEADER_LEN]` on a len-100 carved fragment) invisible to the
//! whole suite until it showed up as thousands of runtime "module panicked" logs
//! on a real image.
//!
//! This test throws a broad band of small buffers -- every length across the
//! header boundary, several fill patterns, with and without a (partial) magic --
//! at the public `extract()` entry point and asserts it never panics. It would
//! have failed on the len-100 garbage-magic fragment that motivated it.

use seance_core::data_source::ByteSliceDataSource;
use seance_plugin_sqlite::sqlite_forensic::{extract, ForensicOptions};

const MAGIC: &[u8; 16] = b"SQLite format 3\x00";

fn opts() -> ForensicOptions {
    ForensicOptions {
        enable_carving: true,
        max_records: 1000,
        wal_bytes: None,
        journal_bytes: None,
    }
}

#[test]
fn extract_never_panics_on_small_or_hostile_buffers() {
    // Cover well past the 100-byte header and one full page so page-level and
    // carving paths are exercised, not just header parsing.
    for len in 0usize..=600 {
        for &fill in &[0x00u8, 0xAB, 0xFF, 0x0D, 0x05, 0x53] {
            // (a) pure garbage of this length (no magic): drives the
            //     zeroed/fuzzy/structural recovery branches. fill=0xAB len=100
            //     is the exact fragment that reproduced the original panic.
            let garbage = ByteSliceDataSource::new(vec![fill; len]);
            let _ = extract(&garbage, &opts());

            // (b) same buffer but seeded with as much of the magic as fits, so
            //     the clean-magic and partial-magic paths are covered at every
            //     length too.
            let mut with_magic = vec![fill; len];
            let m = MAGIC.len().min(len);
            with_magic[..m].copy_from_slice(&MAGIC[..m]);
            let seeded = ByteSliceDataSource::new(with_magic);
            let _ = extract(&seeded, &opts());
        }
    }
}
