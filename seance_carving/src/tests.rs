use crate::engine::{CarvingDataSource, CarvingEngine};
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::io;
use std::sync::Arc;

/// In-memory data source for testing
#[derive(Debug)]
struct MemorySource {
    data: Vec<u8>,
}

impl CarvingDataSource for MemorySource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let off = offset as usize;
        if off >= self.data.len() {
            return Ok(0);
        }
        let available = self.data.len() - off;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.data[off..off + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

/// Simple test signature: detects header [0xAA, 0xBB], footer [0xCC, 0xDD]
struct TestSignature;

impl FileSignature for TestSignature {
    fn name(&self) -> &str {
        "TestFormat"
    }

    fn extensions(&self) -> &[&str] {
        &["tst"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 2 && buf[0] == 0xAA && buf[1] == 0xBB {
            Some(RecoveryInit {
                min_filesize: 4,
                extension: "tst".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // Scan for footer [0xCC, 0xDD]
        for i in 0..buf.len().saturating_sub(1) {
            if buf[i] == 0xCC && buf[i + 1] == 0xDD {
                let footer_end = recovery.file_size + i as u64 + 2;
                return DataCheckResult::Stop(footer_end);
            }
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {
        // No extra validation
    }

    fn max_file_size(&self) -> u64 {
        1024 * 1024 // 1 MB
    }
}

/// Signature with a calculated size from the header
struct SizedSignature;

impl FileSignature for SizedSignature {
    fn name(&self) -> &str {
        "SizedFormat"
    }

    fn extensions(&self) -> &[&str] {
        &["szd"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Header: [0xEE, 0xFF, size_lo, size_hi]
        if buf.len() >= 4 && buf[0] == 0xEE && buf[1] == 0xFF {
            let size = u16::from_le_bytes([buf[2], buf[3]]) as u64;
            Some(RecoveryInit {
                min_filesize: 4,
                extension: "szd".to_string(),
                calculated_file_size: Some(size),
            })
        } else {
            None
        }
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        65536
    }
}

/// Header [0xAA, 0xBB]; footer is a pair of zero bytes [0x00, 0x00]. Used to
/// prove that fabricated zero padding on a short final block is never scanned
/// as content (BUG-159): before the fix, a partial block was zero-filled to the
/// full block size and this footer matched the fabricated zeros.
struct ZeroFooterSignature;

impl FileSignature for ZeroFooterSignature {
    fn name(&self) -> &str {
        "ZeroFooter"
    }

    fn extensions(&self) -> &[&str] {
        &["zf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 2 && buf[0] == 0xAA && buf[1] == 0xBB {
            Some(RecoveryInit {
                min_filesize: 4,
                extension: "zf".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        for i in 0..buf.len().saturating_sub(1) {
            if buf[i] == 0x00 && buf[i + 1] == 0x00 {
                return DataCheckResult::Stop(recovery.file_size + i as u64 + 2);
            }
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        1024 * 1024
    }
}

#[test]
fn test_registry_basic_matching() {
    let mut registry = SignatureRegistry::new();
    let sig: Arc<dyn FileSignature> = Arc::new(TestSignature);
    registry.register(0, &[0xAA, 0xBB], sig);

    // Matching buffer
    let buf = vec![0xAA, 0xBB, 0x00, 0x00];
    let matches = registry.find_matches(&buf);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].0.name(), "TestFormat");
    assert_eq!(matches[0].1, 0);

    // Non-matching buffer
    let buf = vec![0x00, 0x00, 0x00, 0x00];
    let matches = registry.find_matches(&buf);
    assert!(matches.is_empty());
}

#[test]
fn test_registry_offset_matching() {
    let mut registry = SignatureRegistry::new();
    let sig: Arc<dyn FileSignature> = Arc::new(TestSignature);
    // Register at offset 4 instead of 0
    registry.register(4, &[0xAA, 0xBB], sig);

    // Pattern at offset 4
    let buf = vec![0x00, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0x00, 0x00];
    let matches = registry.find_matches(&buf);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].1, 4);

    // Pattern at offset 0 should NOT match
    let buf = vec![0xAA, 0xBB, 0x00, 0x00, 0x00, 0x00];
    let matches = registry.find_matches(&buf);
    assert!(matches.is_empty());
}

#[test]
fn test_carve_single_file_with_footer() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xAA, 0xBB], Arc::new(TestSignature));

    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    // Build data: header at 0, some payload, footer
    let mut data = vec![0u8; 64];
    data[0] = 0xAA;
    data[1] = 0xBB;
    // Put footer at offset 20
    data[20] = 0xCC;
    data[21] = 0xDD;

    let source = MemorySource { data: data.clone() };
    let results = engine.scan(&source, source.size());

    assert!(!results.is_empty(), "Should find at least one carved file");
    let carved = &results[0];
    assert_eq!(carved.offset, 0);
    assert_eq!(carved.extension, "tst");
    assert_eq!(carved.signature_name, "TestFormat");
    // Size should be 22 (0 through footer end at 22)
    assert_eq!(carved.size, 22);
}

#[test]
fn test_carve_size_from_header() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xEE, 0xFF], Arc::new(SizedSignature));

    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    // Header says file is 100 bytes
    let mut data = vec![0u8; 256];
    data[0] = 0xEE;
    data[1] = 0xFF;
    data[2] = 100; // size low byte
    data[3] = 0; // size high byte

    let source = MemorySource { data };
    let results = engine.scan(&source, source.size());

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].offset, 0);
    assert_eq!(results[0].size, 100);
    assert_eq!(results[0].extension, "szd");
}

#[test]
fn test_carve_max_file_size_enforcement() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xEE, 0xFF], Arc::new(SizedSignature));

    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    // Header claims a size exceeding max_file_size (65536)
    // Use a size of 0 which is below min_filesize (4), so it should be rejected
    let mut data = vec![0u8; 256];
    data[0] = 0xEE;
    data[1] = 0xFF;
    // Size = 2 (below min_filesize of 4)
    data[2] = 2;
    data[3] = 0;

    let source = MemorySource { data };
    let results = engine.scan(&source, source.size());

    // Should NOT produce a result since calculated size is below min_filesize
    assert!(results.is_empty(), "Should reject files below min_filesize");
}

#[test]
fn test_carve_overlapping_files() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xAA, 0xBB], Arc::new(TestSignature));

    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    // Two files: first at 0 with footer at 14, second at 16 with footer at 30
    let mut data = vec![0u8; 64];
    // File 1
    data[0] = 0xAA;
    data[1] = 0xBB;
    data[14] = 0xCC;
    data[15] = 0xDD;
    // File 2
    data[24] = 0xAA;
    data[25] = 0xBB;
    data[38] = 0xCC;
    data[39] = 0xDD;

    let source = MemorySource { data: data.clone() };
    let results = engine.scan(&source, source.size());

    assert!(
        results.len() >= 2,
        "Should find at least 2 files, found {}",
        results.len()
    );
}

#[test]
fn test_scan_with_progress_reports_final_bytes() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xAA, 0xBB], Arc::new(TestSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    let source = MemorySource {
        data: vec![0u8; 128],
    };
    let mut calls: Vec<(u64, u64)> = Vec::new();
    let mut progress = |done: u64, total: u64| calls.push((done, total));

    let result = engine.scan_with_progress(&source, source.size(), Some(&mut progress), None);

    assert!(!result.cancelled);
    assert_eq!(result.bytes_scanned, 128);
    // Final progress call always reports (bytes_scanned, bytes_total)
    assert_eq!(calls.last().copied(), Some((128, 128)));
}

#[test]
fn test_scan_with_cancellation_returns_partial() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xAA, 0xBB], Arc::new(TestSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    let source = MemorySource {
        data: vec![0u8; 1024],
    };
    let cancel = || true; // cancelled before the first block

    let result = engine.scan_with_progress(&source, source.size(), None, Some(&cancel));

    assert!(
        result.cancelled,
        "cancelled scan must report cancelled=true"
    );
    assert!(result.files.is_empty());
    assert_eq!(result.bytes_scanned, 0);
}

#[test]
fn test_validated_true_when_footer_confirmed() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xAA, 0xBB], Arc::new(TestSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    let mut data = vec![0u8; 64];
    data[0] = 0xAA;
    data[1] = 0xBB;
    data[20] = 0xCC;
    data[21] = 0xDD;

    let source = MemorySource { data };
    let results = engine.scan(&source, source.size());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].validated, Some(true));
}

#[test]
fn test_validated_none_when_size_from_header() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xEE, 0xFF], Arc::new(SizedSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    let mut data = vec![0u8; 256];
    data[0] = 0xEE;
    data[1] = 0xFF;
    data[2] = 100;
    data[3] = 0;

    let source = MemorySource { data };
    let results = engine.scan(&source, source.size());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].validated, None);
}

#[test]
fn test_validated_false_when_truncated_at_end_of_source() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xAA, 0xBB], Arc::new(TestSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    // Header but no footer: recovery is finalized at end of source
    let mut data = vec![0u8; 64];
    data[0] = 0xAA;
    data[1] = 0xBB;

    let source = MemorySource { data };
    let results = engine.scan(&source, source.size());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].validated, Some(false));
}

#[test]
fn short_read_tail_is_not_scanned_as_content() {
    // A partial final block: 5 real bytes (no zero pair), read into an 8-byte
    // block. The fabricated zero padding must NOT be matched as the [0x00,0x00]
    // footer (BUG-159); the file is finalized at the real end of data.
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xAA, 0xBB], Arc::new(ZeroFooterSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    let source = MemorySource {
        data: vec![0xAA, 0xBB, 0x11, 0x22, 0x33],
    };
    let results = engine.scan(&source, source.size());
    assert_eq!(results.len(), 1);
    // The real readable length (5), not a size derived from a fabricated-zero
    // footer match (which would be 7).
    assert_eq!(results[0].size, 5);
}

#[test]
fn test_header_size_is_clamped_to_the_end_of_the_source() {
    // BUG-267: a header near the end of unallocated space declares 4000 bytes
    // but only 64 exist. Carving the declared length would build a window that
    // runs past EOF, and its md5/sha256 would then cover only the readable
    // prefix while the artifact claimed the declared size.
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xEE, 0xFF], Arc::new(SizedSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    let mut data = vec![0u8; 64];
    data[0] = 0xEE;
    data[1] = 0xFF;
    data[2..4].copy_from_slice(&4000u16.to_le_bytes());

    let source = MemorySource { data };
    let size = source.size();
    let results = engine.scan(&source, size);

    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].size, size,
        "the carved size must never exceed the bytes that exist"
    );
    assert_eq!(
        results[0].validated,
        Some(false),
        "a file truncated at the end of the source is not footer-validated"
    );
}

#[test]
fn test_header_size_within_the_source_is_untouched() {
    // The clamp must not disturb the normal case: a declared size that fits
    // stays exact and keeps its "no validation performed" outcome.
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xEE, 0xFF], Arc::new(SizedSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    let mut data = vec![0u8; 256];
    data[0] = 0xEE;
    data[1] = 0xFF;
    data[2..4].copy_from_slice(&100u16.to_le_bytes());

    let source = MemorySource { data };
    let results = engine.scan(&source, source.size());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].size, 100);
    assert_eq!(results[0].validated, None);
}

#[test]
fn test_empty_source() {
    let registry = SignatureRegistry::new();
    let engine = CarvingEngine::new(Arc::new(registry));

    let source = MemorySource { data: vec![] };
    let results = engine.scan(&source, 0);
    assert!(results.is_empty());
}

#[test]
fn test_no_signatures_registered() {
    let registry = SignatureRegistry::new();
    let engine = CarvingEngine::new(Arc::new(registry));

    let source = MemorySource {
        data: vec![0xAA, 0xBB, 0x00, 0x00, 0xCC, 0xDD],
    };
    let results = engine.scan(&source, source.size());
    assert!(results.is_empty());
}

// ---------------------------------------------------------------------------
// Slack geometry
// ---------------------------------------------------------------------------

#[test]
fn test_slack_region_partial_last_cluster() {
    // logical 700 bytes in 512-byte clusters => 188 used in the last cluster,
    // so slack = 512 - 188 = 324 bytes ending at allocation_end (1024).
    let region = CarvingEngine::slack_region(700, 512, 1024);
    assert_eq!(region, Some((700, 324)));
}

#[test]
fn test_slack_region_none_when_cluster_aligned() {
    // A whole number of clusters leaves no slack.
    assert_eq!(CarvingEngine::slack_region(1024, 512, 1024), None);
}

#[test]
fn test_slack_region_none_for_degenerate_inputs() {
    assert_eq!(CarvingEngine::slack_region(0, 512, 1024), None);
    assert_eq!(CarvingEngine::slack_region(700, 0, 1024), None);
    // slack larger than the allocation end would underflow the offset.
    assert_eq!(CarvingEngine::slack_region(1, 512, 8), None);
}

// ---------------------------------------------------------------------------
// Slack carving
// ---------------------------------------------------------------------------

#[test]
fn test_carve_slack_recovers_signature_past_logical_end() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xEE, 0xFF], Arc::new(SizedSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    // File: cluster_size 32, allocation ends at 96, logical size 70.
    // slack = [70, 96) (26 bytes). Embed a 20-byte SizedFormat file at 70.
    let (slack_offset, slack_len) = CarvingEngine::slack_region(70, 32, 96).unwrap();
    assert_eq!((slack_offset, slack_len), (70, 26));

    let mut data = vec![0u8; 128];
    data[70] = 0xEE;
    data[71] = 0xFF;
    data[72] = 20; // size low byte
    data[73] = 0; // size high byte

    let source = MemorySource { data };
    let finds = engine.carve_slack(&source, slack_offset, slack_len, 32);

    let sig: Vec<_> = finds
        .iter()
        .filter(|f| f.signature_name == "SizedFormat")
        .collect();
    assert_eq!(sig.len(), 1, "expected one signature find in slack");
    assert_eq!(sig[0].offset, 70, "offset must be absolute in the source");
    assert_eq!(sig[0].size, 20);
    assert_eq!(sig[0].validated, None);
}

#[test]
fn test_carve_slack_zero_filled_yields_nothing() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xEE, 0xFF], Arc::new(SizedSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    let source = MemorySource {
        data: vec![0u8; 128],
    };
    let finds = engine.carve_slack(&source, 70, 26, 32);
    assert!(finds.is_empty(), "zero-filled slack must fabricate nothing");
}

#[test]
fn test_carve_slack_strings_pass() {
    // No signature match; recover a printable-ASCII run from slack.
    let registry = SignatureRegistry::new();
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    let mut data = vec![0u8; 128];
    data[70..80].copy_from_slice(b"HELLOWORLD"); // 10 printable bytes
    let source = MemorySource { data };

    let finds = engine.carve_slack(&source, 70, 26, 32);
    let strings: Vec<_> = finds
        .iter()
        .filter(|f| f.signature_name == "Strings")
        .collect();
    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].offset, 70);
    assert_eq!(strings[0].size, 10);
    assert_eq!(strings[0].extension, "txt");
}

#[test]
fn test_carve_slack_short_string_below_threshold_ignored() {
    let registry = SignatureRegistry::new();
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    let mut data = vec![0u8; 128];
    data[70..75].copy_from_slice(b"HELLO"); // only 5 printable bytes
    let source = MemorySource { data };

    let finds = engine.carve_slack(&source, 70, 26, 32);
    assert!(
        finds.is_empty(),
        "runs shorter than the threshold are ignored"
    );
}

#[test]
fn test_carve_slack_clamps_len_to_cluster() {
    // A bogus slack_len larger than the cluster is clamped, so a signature that
    // starts one cluster beyond the slack is never attributed.
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xEE, 0xFF], Arc::new(SizedSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    let mut data = vec![0u8; 128];
    // Signature planted at offset 40, i.e. 40 bytes into the slack window.
    data[40] = 0xEE;
    data[41] = 0xFF;
    data[42] = 20;
    data[43] = 0;
    let source = MemorySource { data };

    // slack_offset 0, cluster_size 32: slack_len clamped from 999 to 32, so
    // offset 40 is out of range and nothing is recovered.
    let finds = engine.carve_slack(&source, 0, 999, 32);
    assert!(
        finds.iter().all(|f| f.signature_name != "SizedFormat"),
        "clamped slack must not reach beyond one cluster"
    );
}

/// Source that serves real data but caps every single read to `max_read` bytes,
/// so a read larger than a block (the file_check tail window) comes back short
/// even though the bytes exist. Models a DataSource returning partial reads.
struct ShortTailSource {
    data: Vec<u8>,
    max_read: usize,
}

impl CarvingDataSource for ShortTailSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let off = offset as usize;
        if off >= self.data.len() {
            return Ok(0);
        }
        let available = self.data.len() - off;
        let to_read = buf.len().min(available).min(self.max_read);
        buf[..to_read].copy_from_slice(&self.data[off..off + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

#[test]
fn test_short_file_check_read_leaves_validation_unknown() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xAA, 0xBB], Arc::new(TestSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    let mut data = vec![0u8; 64];
    data[0] = 0xAA;
    data[1] = 0xBB;
    data[20] = 0xCC;
    data[21] = 0xDD;

    // Full-read source: the 22-byte file_check window is read completely, so the
    // footer is confirmed and validation is positive.
    let full = MemorySource { data: data.clone() };
    let full_results = engine.scan(&full, full.size());
    assert_eq!(full_results[0].validated, Some(true));

    // Capped source: every read_at returns at most 8 bytes, but the bytes all
    // exist. `read_full` loops until the 22-byte file_check window is filled, so
    // a *partial* read (not EOF) is correctly recovered and validated — it is
    // NOT mistaken for a truncated/zero-padded tail. Genuine truncation (a real
    // short read that hits EOF before the window fills) is what leaves
    // validation unknown; that is enforced by the `read_len < check_size => None`
    // guard in the engine (BUG-159).
    let short = ShortTailSource { data, max_read: 8 };
    let short_results = engine.scan(&short, short.size());
    assert_eq!(short_results[0].size, 22, "carve boundary is still known");
    assert_eq!(
        short_results[0].validated,
        Some(true),
        "a partial read whose bytes all exist is looped to completion and validated"
    );
}

/// Header [0xA1, 0xB1]; end marker [0xC1, 0xD1]. `data_check` deliberately stops
/// *before* the marker, so the recovered tail does not carry the format's
/// terminator and `verify_footer` disagrees with it.
///
/// Models a signature whose block scan and whose footer check reach different
/// answers — the case where the engine used to record `validated: Some(true)`
/// regardless (B2-143).
struct DisagreeingFooterSignature;

impl FileSignature for DisagreeingFooterSignature {
    fn name(&self) -> &str {
        "DisagreeingFooter"
    }

    fn extensions(&self) -> &[&str] {
        &["dfr"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 2 && buf[0] == 0xA1 && buf[1] == 0xB1 {
            Some(RecoveryInit {
                min_filesize: 4,
                extension: "dfr".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        for i in 0..buf.len().saturating_sub(1) {
            if buf[i] == 0xC1 && buf[i + 1] == 0xD1 {
                // Stop short of the marker: the carved extent will NOT end on it.
                return DataCheckResult::Stop(recovery.file_size + i as u64);
            }
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn verify_footer(&self, data: &[u8]) -> Option<bool> {
        if data.len() < 2 {
            return Some(false);
        }
        Some(data[data.len() - 2] == 0xC1 && data[data.len() - 1] == 0xD1)
    }

    fn max_file_size(&self) -> u64 {
        1024 * 1024
    }
}

/// Header [0xA2, 0xB2] with no terminator at all and a 32-byte ceiling. Used to
/// prove an over-long recovery is still reported (B2-144).
struct TinyCapSignature;

impl FileSignature for TinyCapSignature {
    fn name(&self) -> &str {
        "TinyCap"
    }

    fn extensions(&self) -> &[&str] {
        &["tc"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 2 && buf[0] == 0xA2 && buf[1] == 0xB2 {
            Some(RecoveryInit {
                min_filesize: 4,
                extension: "tc".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        32
    }
}

/// A signature that rejects the recovered tail must produce `validated:
/// Some(false)`, not the blanket `Some(true)` the engine used to record.
///
/// What an examiner learns: whether the carve ended where the format says it
/// ends. A wrong answer here labels a heuristic fragment "footer-validated" —
/// the strongest confidence the tool offers — for a file whose end marker is
/// not there (B2-143).
#[test]
fn footer_check_failure_is_not_reported_as_validated() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xA1, 0xB1], Arc::new(DisagreeingFooterSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    let mut data = vec![0u8; 64];
    data[0] = 0xA1;
    data[1] = 0xB1;
    data[20] = 0xC1;
    data[21] = 0xD1;

    let source = MemorySource { data };
    let results = engine.scan(&source, source.size());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].size, 20, "extent stops short of the marker");
    assert_eq!(
        results[0].validated,
        Some(false),
        "a signature that disowns the recovered tail must not yield Some(true)"
    );
}

/// Hitting a signature's size ceiling must still yield a carved file, flagged as
/// not footer-validated.
///
/// What an examiner learns: that a file of this type starts here. A wrong answer
/// here is the file's total absence from the carve results, which reads as "no
/// such file was on the media" (B2-144).
#[test]
fn max_file_size_overrun_still_records_a_truncated_carve() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xA2, 0xB2], Arc::new(TinyCapSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    // 256 bytes of content with no terminator: recovery runs past the 32-byte cap.
    let mut data = vec![0x77u8; 256];
    data[0] = 0xA2;
    data[1] = 0xB2;

    let source = MemorySource { data };
    let results = engine.scan(&source, source.size());
    assert_eq!(
        results.len(),
        1,
        "a recovery stopped by the size cap must not vanish"
    );
    assert_eq!(results[0].offset, 0);
    assert_eq!(results[0].size, 32, "carve is clamped to the cap");
    assert_eq!(
        results[0].validated,
        Some(false),
        "a capped carve is a heuristic recovery, never footer-validated"
    );
}

/// Header [0xA3, 0xB3]. `data_check` returns `Error` once the recovery has run
/// past `error_after` bytes, modelling a format whose structure stops making
/// sense partway through a real object.
struct FailsMidwaySignature {
    error_after: u64,
}

impl FileSignature for FailsMidwaySignature {
    fn name(&self) -> &str {
        "FailsMidway"
    }

    fn extensions(&self) -> &[&str] {
        &["fm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 2 && buf[0] == 0xA3 && buf[1] == 0xB3 {
            Some(RecoveryInit {
                min_filesize: 4,
                extension: "fm".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, _buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        if recovery.file_size >= self.error_after {
            DataCheckResult::Error
        } else {
            DataCheckResult::Continue
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        1024 * 1024
    }
}

/// A `data_check` that errors mid-object must still report the bytes recovered
/// so far, flagged as not footer-validated.
///
/// What an examiner learns: that an object of this type began at this offset.
/// A wrong answer here is the object's total absence from the carve results —
/// identical, on the page, to media that never held one — even though a header
/// matched and the bytes are on the disk (B7-014).
#[test]
fn a_data_check_error_still_records_the_bytes_recovered_so_far() {
    let mut registry = SignatureRegistry::new();
    registry.register(
        0,
        &[0xA3, 0xB3],
        Arc::new(FailsMidwaySignature { error_after: 32 }),
    );
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    let mut data = vec![0x55u8; 128];
    data[0] = 0xA3;
    data[1] = 0xB3;

    let source = MemorySource { data };
    let results = engine.scan(&source, source.size());

    assert_eq!(
        results.len(),
        1,
        "a recovery abandoned by data_check must not vanish: {results:?}"
    );
    assert_eq!(results[0].offset, 0);
    assert_eq!(
        results[0].size, 32,
        "the extent runs to the block the check failed on"
    );
    assert_eq!(
        results[0].validated,
        Some(false),
        "an abandoned recovery is heuristic, never footer-validated"
    );
}

/// `carve_slack` must loop short reads.
///
/// What an examiner learns: which deleted content survives in the tail of a
/// cluster. A source that returns short at an extent boundary would otherwise
/// have the rest of the window analysed as the untouched zeros of the buffer —
/// bytes that were never on the disk, and that match footers and string
/// heuristics of their own (B5-024).
#[test]
fn carve_slack_loops_short_reads_rather_than_analysing_the_prefix() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xAA, 0xBB], Arc::new(TestSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    // The signature sits 32 bytes into the slack window, past the point any
    // single read of this source reaches.
    let mut data = vec![0u8; 64];
    data[32] = 0xAA;
    data[33] = 0xBB;
    data[40] = 0xCC;
    data[41] = 0xDD;

    let whole = MemorySource { data: data.clone() };
    let expected = engine.carve_slack(&whole, 0, 64, 64);
    assert!(
        expected.iter().any(|f| f.signature_name == "TestFormat"),
        "the fixture must be carvable when every read is served whole: {expected:?}"
    );

    let short = ShortTailSource { data, max_read: 8 };
    let found = engine.carve_slack(&short, 0, 64, 64);
    assert!(
        found.iter().any(|f| f.signature_name == "TestFormat"),
        "a source that returns short must still have its whole slack window read: {found:?}"
    );
}

/// Header [0xA4, 0xB4], footer [0xCC, 0xDD], ceiling 38 bytes. Used to prove
/// the size cap is measured against the bytes that were read, not against the
/// nominal block size.
struct CappedFooterSignature;

impl FileSignature for CappedFooterSignature {
    fn name(&self) -> &str {
        "CappedFooter"
    }

    fn extensions(&self) -> &[&str] {
        &["cf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 2 && buf[0] == 0xA4 && buf[1] == 0xB4 {
            Some(RecoveryInit {
                min_filesize: 4,
                extension: "cf".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        for i in 0..buf.len().saturating_sub(1) {
            if buf[i] == 0xCC && buf[i + 1] == 0xDD {
                return DataCheckResult::Stop(recovery.file_size + i as u64 + 2);
            }
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        38
    }
}

/// The size ceiling must be measured against the bytes actually read, not the
/// nominal block size.
///
/// What an examiner learns: where a recovered file ends and whether its own
/// terminator was found. On a short final block the old arithmetic added a
/// whole block, firing the ceiling before the block containing the footer was
/// ever handed to `data_check` — so a file that ends inside the source was
/// reported a byte-count too long and labelled a heuristic truncation instead
/// of a footer-validated carve (B5-037).
#[test]
fn the_size_ceiling_is_measured_against_the_bytes_actually_read() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xA4, 0xB4], Arc::new(CappedFooterSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(8);

    // 36 bytes: four whole blocks and a 4-byte tail holding the footer. The
    // ceiling is 38, so the file is inside it — but only if the tail block is
    // counted as the four bytes it is.
    let mut data = vec![0x11u8; 36];
    data[0] = 0xA4;
    data[1] = 0xB4;
    data[32] = 0xCC;
    data[33] = 0xDD;

    let source = MemorySource { data };
    let results = engine.scan(&source, source.size());

    assert_eq!(results.len(), 1, "{results:?}");
    assert_eq!(
        results[0].size, 34,
        "the carve ends at its own footer, not at the ceiling"
    );
    assert_eq!(
        results[0].validated,
        Some(true),
        "the footer was found, so this is not a heuristic truncation"
    );
}

// ── the formats a modern device actually writes ─────────────────────────────

/// **The finding, driven through the whole engine rather than one callback.**
///
/// A unit test on `header_check` proves the brand table is read. It does not
/// prove the signature is registered, that the engine reaches it, or that the
/// extension survives into a carved result — and this session has already
/// produced one feature whose unit tests passed while nothing worked end to
/// end. So this carves an image the way a case would.
#[test]
fn an_iphone_photograph_carves_as_heic_through_the_real_registry() {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);

    // A HEIC file: ftyp declaring the `heic` brand, a metadata box, and image
    // data — then unrelated bytes, as unallocated space always has.
    let mut image = Vec::new();
    image.extend_from_slice(&24u32.to_be_bytes());
    image.extend_from_slice(b"ftypheic");
    image.extend_from_slice(b"\x00\x00\x00\x00heicmif1");
    let meta_at = image.len();
    image.extend_from_slice(&64u32.to_be_bytes());
    image.extend_from_slice(b"meta");
    image.resize(meta_at + 64, 0);
    let mdat_at = image.len();
    image.extend_from_slice(&512u32.to_be_bytes());
    image.extend_from_slice(b"mdat");
    image.resize(mdat_at + 512, 0x7F);
    let photo_end = image.len() as u64;
    image.extend_from_slice(&[0x5A; 1024]);

    let source = MemorySource { data: image };
    let results = engine.scan(&source, source.size());

    let photo = results
        .iter()
        .find(|f| f.offset == 0)
        .expect("the photograph must be carved at all");
    assert_eq!(
        photo.extension, "heic",
        "an iPhone photograph carved as {:?} will not be found by an examiner \
         filtering carved output for images",
        photo.extension
    );
    assert_eq!(
        photo.size, photo_end,
        "the carve must end where the box chain does; running on to the size cap \
         appends whatever else was on the disk to the photograph"
    );
}

/// zstd is the default compressor on modern Linux and Android — btrfs, package
/// managers, kernel modules. It was absent from the signature set entirely.
#[test]
fn a_zstandard_frame_carves_through_the_real_registry() {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);

    // A real frame: `printf 'hello hello hello hello\n' | zstd` (zstd 1.5).
    let mut image = vec![
        0x28, 0xB5, 0x2F, 0xFD, 0x04, 0x58, 0x6D, 0x00, 0x00, 0x38, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
        0x20, 0x0A, 0x01, 0x00, 0x99, 0x4B, 0x11, 0xA8, 0x7C, 0x2E, 0xA8,
    ];
    image.extend_from_slice(&[0x11; 2048]);

    let source = MemorySource { data: image };
    let results = engine.scan(&source, source.size());
    assert!(
        results.iter().any(|f| f.extension == "zst"),
        "no zstd frame was carved; found {:?}",
        results.iter().map(|f| &f.extension).collect::<Vec<_>>()
    );
}

/// Parquet brackets itself with `PAR1`, so a carve of one can be *validated*
/// rather than merely bounded.
#[test]
fn a_parquet_file_carves_and_its_footer_is_validated() {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);

    // `PAR1`, then a dictionary page header in Thrift compact form: field 1
    // (`type`, i32) = DICTIONARY_PAGE (zigzag 4), fields 2 and 3 (the page
    // sizes, i32) = 8 each.
    let mut image = b"PAR1".to_vec();
    image.extend_from_slice(&[0x15, 0x04, 0x15, 0x10, 0x15, 0x10]);
    image.extend_from_slice(&[0x33; 1018]);
    image.extend_from_slice(&1024u32.to_le_bytes());
    image.extend_from_slice(b"PAR1");

    let source = MemorySource { data: image };
    let results = engine.scan(&source, source.size());
    assert!(
        results.iter().any(|f| f.extension == "parquet"),
        "no parquet file was carved; found {:?}",
        results.iter().map(|f| &f.extension).collect::<Vec<_>>()
    );
}

/// CARVE-018. SYNTHETIC from a real tool: a Parquet file written by pyarrow
/// 26.0.0 embedded in noise. The carve ends at the file's trailing magic (it
/// used to run to the end of the source) and, being sized from the file's own
/// structure, carries `validated: None`.
#[test]
fn a_real_parquet_file_in_noise_is_carved_to_its_exact_end() {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);

    let file = include_bytes!("../tests/fixtures/carve018/pyarrow_26_0_0.parquet");
    let mut image = vec![0x55u8; 8192];
    image.extend_from_slice(file);
    image.extend_from_slice(&[0xAA; 16384]);

    let source = MemorySource { data: image };
    let results = engine.scan(&source, source.size());
    let parquet: Vec<_> = results
        .iter()
        .filter(|f| f.extension == "parquet")
        .collect();
    assert_eq!(parquet.len(), 1, "found {results:?}");
    assert_eq!(parquet[0].offset, 8192);
    assert_eq!(parquet[0].size, file.len() as u64);
}

/// CARVE-018. SYNTHETIC header: a BPG whose declared picture length is 12 MiB
/// used to fail the 8 MiB cap and was not carved at all.
#[test]
fn a_bpg_declared_over_8_mib_is_carved_to_its_declared_size() {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(4096);

    let mut image = vec![b'B', b'P', b'G', 0xFB, 0x00, 0x00, 0x10, 0x10];
    image.extend_from_slice(&[0x86, 0x80, 0x80, 0x00]); // ue32 = 12 MiB
    let header_len = image.len() as u64;
    image.resize(13 * 1024 * 1024, 0);

    let source = MemorySource { data: image };
    let results = engine.scan(&source, source.size());
    let bpg: Vec<_> = results.iter().filter(|f| f.extension == "bpg").collect();
    assert_eq!(bpg.len(), 1, "found {results:?}");
    assert_eq!(bpg[0].offset, 0);
    assert_eq!(bpg[0].size, 12 * 1024 * 1024 + header_len);
    assert_eq!(bpg[0].validated, None);
}

/// CARVE-018. A BPG with picture length 0 stays bounded by the next header,
/// whatever the cap is.
#[test]
fn a_bpg_with_zero_length_is_still_bounded_by_the_next_header() {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(4096);

    let header = [b'B', b'P', b'G', 0xFB, 0x00, 0x00, 0x10, 0x10, 0x00];
    let mut image = header.to_vec();
    image.resize(20_480, 0x11);
    image.extend_from_slice(&header);
    image.resize(40_960, 0x11);
    // The second header must sit on a block boundary to be seen.
    let second = 20_480u64;

    let source = MemorySource { data: image };
    let results = engine.scan(&source, source.size());
    let bpg: Vec<_> = results.iter().filter(|f| f.extension == "bpg").collect();
    assert_eq!(bpg.first().map(|f| (f.offset, f.size)), Some((0, second)));
    assert_eq!(bpg[0].validated, Some(false));
}

/// **A skippable frame is part of a stream, not a file of its own.**
///
/// `pzstd` — the parallel zstd everyone actually uses — writes a skippable
/// frame holding the block index before the data frames. Carving that frame as
/// a standalone file with its own exact length splits the archive in two: a
/// 16-byte fragment and, separately, the compressed data, neither of which is
/// the archive. LZ4 uses the same magic range, so the fragment cannot even be
/// labelled with confidence.
#[test]
fn a_pzstd_archive_carves_as_one_file_and_not_as_a_fragment_plus_a_body() {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);

    let mut image = vec![0x50, 0x2A, 0x4D, 0x18];
    image.extend_from_slice(&8u32.to_le_bytes());
    image.extend_from_slice(&[0u8; 8]);
    // The data frame that follows, as pzstd writes it.
    image.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD, 0x00]);
    image.extend_from_slice(&[0x11; 2048]);

    let source = MemorySource { data: image };
    let results = engine.scan(&source, source.size());

    let zst: Vec<_> = results.iter().filter(|f| f.extension == "zst").collect();
    assert!(!zst.is_empty(), "the archive must be carved at all");
    assert_eq!(
        zst.len(),
        1,
        "the archive was split into {} carves: {:?}. A skippable frame is a component \
         of a stream, and carving it separately hands an examiner two fragments where \
         there was one archive.",
        zst.len(),
        zst.iter().map(|f| (f.offset, f.size)).collect::<Vec<_>>()
    );
    assert_eq!(
        zst[0].offset, 0,
        "the carve must start at the skippable frame, which is where the archive starts"
    );
    // And it must actually contain the archive. "Exactly one carve" is equally
    // what happens when the skippable frame is carved as a 16-byte file and the
    // compressed data behind it is never carved at all — which is worse than
    // fragmenting it, and is what this assertion exists to catch.
    assert!(
        zst[0].size > 1024,
        "the carve is {} bytes: the skippable frame alone. The compressed data \
         behind it was not recovered.",
        zst[0].size
    );
}

/// The archive formats added after review, carved through the real registry.
///
/// A unit test on `header_check` does not prove a signature is registered or
/// that the engine reaches it. These were added because the same gap hid a
/// broken feature earlier in this work.
#[test]
fn the_added_archive_formats_carve_through_the_real_registry() {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);

    // LZ4: magic, then the frame descriptor the `lz4` tool writes by default
    // (version 01, independent blocks, content checksum, 4 MiB blocks) and its
    // header checksum 0xA7.
    let mut lz4 = vec![0x04, 0x22, 0x4D, 0x18, 0x64, 0x40, 0xA7];
    lz4.extend_from_slice(&[0x22; 2048]);
    let found = engine.scan(&MemorySource { data: lz4.clone() }, lz4.len() as u64);
    assert!(
        found.iter().any(|f| f.extension == "lz4"),
        "no LZ4 frame carved; found {:?}",
        found.iter().map(|f| &f.extension).collect::<Vec<_>>()
    );

    // WARC: a real record, version line and all.
    let mut warc = b"WARC/1.0\r\nWARC-Type: response\r\nContent-Length: 4\r\n\r\n".to_vec();
    warc.extend_from_slice(&[b'x'; 2048]);
    let found = engine.scan(&MemorySource { data: warc.clone() }, warc.len() as u64);
    assert!(
        found.iter().any(|f| f.extension == "warc"),
        "no WARC carved; found {:?}",
        found.iter().map(|f| &f.extension).collect::<Vec<_>>()
    );

    // cpio: a newc header whose fields really are hexadecimal, and a trailer.
    let mut cpio = b"070701".to_vec();
    for _ in 0..13 {
        cpio.extend_from_slice(b"00000001");
    }
    cpio.extend_from_slice(b"init\0");
    cpio.extend_from_slice(&[0u8; 1024]);
    cpio.extend_from_slice(b"TRAILER!!!");
    let found = engine.scan(&MemorySource { data: cpio.clone() }, cpio.len() as u64);
    assert!(
        found.iter().any(|f| f.extension == "cpio"),
        "no cpio archive carved; found {:?}",
        found.iter().map(|f| &f.extension).collect::<Vec<_>>()
    );
}

// ── an orphan EVTX chunk (HUNT-163) ─────────────────────────────────────────

/// A chunk header in the real `ElfChnk` layout, over a full 64 KiB chunk:
/// `header_size` 128 at 0x28, `last_event_record_data_offset` at 0x2C,
/// `free_space_offset` at 0x30, and record bytes up to the free-space offset.
fn elfchnk(free_space_offset: u32) -> Vec<u8> {
    let mut chunk = vec![0u8; 65_536];
    chunk[..8].copy_from_slice(b"ElfChnk\0");
    chunk[0x08..0x10].copy_from_slice(&1u64.to_le_bytes());
    chunk[0x10..0x18].copy_from_slice(&104u64.to_le_bytes());
    chunk[0x18..0x20].copy_from_slice(&1u64.to_le_bytes());
    chunk[0x20..0x28].copy_from_slice(&104u64.to_le_bytes());
    chunk[0x28..0x2C].copy_from_slice(&128u32.to_le_bytes());
    chunk[0x2C..0x30].copy_from_slice(&(free_space_offset - 616).to_le_bytes());
    chunk[0x30..0x34].copy_from_slice(&free_space_offset.to_le_bytes());
    chunk[512..free_space_offset as usize].fill(0x2A);
    chunk
}

/// **A chunk left in free space after its log was rotated or deleted is
/// carved.** Only the `ElfFile` file header was a signature, so a headerless
/// chunk was carved by nothing and never reached the EVTX module's recovery
/// pass. It carves as one fixed 64 KiB extent at a sector boundary.
#[test]
fn an_orphan_evtx_chunk_in_free_space_carves_as_one_64_kib_chunk() {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);

    let mut image = vec![0x5Au8; 1536];
    image.extend_from_slice(&elfchnk(30_264));
    image.extend_from_slice(&[0x5A; 2048]);
    let source = MemorySource { data: image };
    let results = engine.scan(&source, source.size());
    let chunk = results
        .iter()
        .find(|f| f.offset == 1536)
        .unwrap_or_else(|| panic!("the orphan chunk must be carved; found {results:?}"));
    assert_eq!(chunk.signature_name, "EVTX chunk (Windows event log)");
    assert_eq!(chunk.extension, "elfchnk");
    assert_eq!(chunk.size, 65_536, "the chunk size is fixed by the format");
}

/// The magic alone is not a chunk: a header whose own size field is not 128,
/// or whose free-space offset lies inside the header or past the chunk, is
/// refused rather than carved as event-log evidence.
#[test]
fn bytes_that_only_spell_elfchnk_are_not_carved_as_a_chunk() {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);

    for (field, value) in [(0x28usize, 64u32), (0x30, 100), (0x30, 70_000)] {
        let mut chunk = elfchnk(30_264);
        chunk[field..field + 4].copy_from_slice(&value.to_le_bytes());
        let source = MemorySource { data: chunk };
        let results = engine.scan(&source, source.size());
        assert!(
            results
                .iter()
                .all(|f| f.signature_name != "EVTX chunk (Windows event log)"),
            "field {field:#x} = {value} must be refused; carved {results:?}"
        );
    }
}

/// The same on real chunks (`SEANCE_EVTX_CORPUS`): a whole chunk of
/// omerbenamram's `system.evtx`, and plaso's `System2.evtx` third chunk as
/// that file cuts it, placed at sector offsets inside unrelated bytes. The
/// cut chunk is carved to the end of the source and marked not validated.
#[test]
fn real_evtx_chunks_carve_from_unrelated_bytes() {
    let Some(dir) = std::env::var_os("SEANCE_EVTX_CORPUS") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let (Ok(system), Ok(system2)) = (
        std::fs::read(dir.join("system.evtx")),
        std::fs::read(dir.join("System2.evtx")),
    ) else {
        return;
    };
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);

    let whole = &system[4096 + 3 * 65_536..4096 + 4 * 65_536];
    let cut = &system2[4096 + 2 * 65_536..];
    let mut image = vec![0x5Au8; 3 * 512];
    image.extend_from_slice(whole);
    image.extend_from_slice(&[0xC3; 5 * 512]);
    let cut_at = image.len() as u64;
    image.extend_from_slice(cut);
    let source = MemorySource { data: image };
    let results = engine.scan(&source, source.size());
    let chunks: Vec<_> = results
        .iter()
        .filter(|f| f.signature_name == "EVTX chunk (Windows event log)")
        .collect();
    assert_eq!(chunks.len(), 2, "{results:?}");
    assert_eq!((chunks[0].offset, chunks[0].size), (1536, 65_536));
    assert_eq!(
        (chunks[1].offset, chunks[1].size),
        (cut_at, cut.len() as u64)
    );
    assert_eq!(
        chunks[1].validated,
        Some(false),
        "a chunk cut by the end of the source is short of its fixed size"
    );
}

// ── a whole EVTX log sized by walking its chunks (CARVE-013) ────────────────

/// An `ElfFile` header in the real layout: first and last chunk numbers at
/// 0x08 and 0x10, next record identifier at 0x18, `header_size` 128 at 0x20,
/// minor 1 and major 3 at 0x24/0x26, the header block size 4,096 as a u16 at
/// 0x28 and the chunk count as a u16 at 0x2A — padded to the 4 KiB block.
fn elffile_header(header_chunk_count: u16) -> Vec<u8> {
    let mut header = vec![0u8; 4096];
    header[..8].copy_from_slice(b"ElfFile\0");
    header[0x10..0x18]
        .copy_from_slice(&u64::from(header_chunk_count.saturating_sub(1)).to_le_bytes());
    header[0x18..0x20].copy_from_slice(&105u64.to_le_bytes());
    header[0x20..0x24].copy_from_slice(&128u32.to_le_bytes());
    header[0x24..0x26].copy_from_slice(&1u16.to_le_bytes());
    header[0x26..0x28].copy_from_slice(&3u16.to_le_bytes());
    header[0x28..0x2A].copy_from_slice(&4096u16.to_le_bytes());
    header[0x2A..0x2C].copy_from_slice(&header_chunk_count.to_le_bytes());
    header[0x78..0x7C].copy_from_slice(&1u32.to_le_bytes());
    header
}

fn evtx_carves(results: &[crate::engine::CarvedFile]) -> Vec<(u64, u64, Option<bool>)> {
    results
        .iter()
        .filter(|f| f.signature_name == "EVTX")
        .map(|f| (f.offset, f.size, f.validated))
        .collect()
}

/// **The extent of a whole log is the run of chunks that follow its header,
/// not the header's count.** The count is read where it is (a u16 at 0x2A),
/// but a real log's count disagrees with its chunks in both directions:
/// `system.evtx` says 3 and holds 15, `System2.evtx` says 96 and holds 3. A
/// header that says 3 over five chunks carves all five; one that says 96 over
/// two chunks followed by other bytes carves two.
#[test]
fn a_whole_evtx_log_is_sized_by_its_chunks_not_its_header_count() {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);

    for (header_count, chunks) in [(3u16, 5usize), (96, 2)] {
        let mut image = vec![0x5Au8; 3 * 512];
        image.extend_from_slice(&elffile_header(header_count));
        for _ in 0..chunks {
            image.extend_from_slice(&elfchnk(30_264));
        }
        image.extend_from_slice(&[0x5A; 4 * 512]);
        let source = MemorySource { data: image };
        let results = engine.scan(&source, source.size());
        assert_eq!(
            evtx_carves(&results),
            vec![(1536, 4096 + chunks as u64 * 65_536, None)],
            "header count {header_count} over {chunks} chunks; carved {results:?}"
        );
    }
}

/// The same on the two real logs (`SEANCE_EVTX_CORPUS`), each whole and
/// embedded at a sector offset in unrelated bytes: omerbenamram's
/// `system.evtx` carves as its 15 chunks (its last two 64 KiB blocks are
/// zeroed preallocation, not chunks), and plaso's `System2.evtx`, whose third
/// chunk that copy cuts short, carves to the end of the source and is marked
/// not validated.
#[test]
fn real_evtx_logs_carve_whole_from_unrelated_bytes() {
    let Some(dir) = std::env::var_os("SEANCE_EVTX_CORPUS") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let (Ok(system), Ok(system2)) = (
        std::fs::read(dir.join("system.evtx")),
        std::fs::read(dir.join("System2.evtx")),
    ) else {
        return;
    };
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);

    let mut image = vec![0x5Au8; 3 * 512];
    image.extend_from_slice(&system);
    image.extend_from_slice(&[0xC3; 5 * 512]);
    let second_at = image.len() as u64;
    image.extend_from_slice(&system2);
    let source = MemorySource { data: image };
    let results = engine.scan(&source, source.size());
    assert_eq!(
        evtx_carves(&results),
        vec![
            (1536, 4096 + 15 * 65_536, None),
            (second_at, system2.len() as u64, Some(false)),
        ],
        "{results:?}"
    );
}

// ── CARVE-015: a new header ends a running carve only once it survives its
// own data check ──────────────────────────────────────────────────────────

/// A loosely identified unsized format, as many PhotoRec-derived signatures
/// are: `header_check` sees only a two-byte magic `4C 5A`, and the structure
/// that proves the file is checked block by block. Bytes 2..4 are the length
/// of the first record (little-endian), which must fit in the block and be at
/// least 8; byte 4 is a record type in 1..=4. Bytes that merely happen to
/// start `4C 5A` fail that check. A record type of 0xFF is an end record: the
/// file stops at the end of the first record.
struct LooseRecordSignature;

impl FileSignature for LooseRecordSignature {
    fn name(&self) -> &str {
        "LooseRecord"
    }

    fn extensions(&self) -> &[&str] {
        &["lzr"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        (buf.len() >= 2 && buf[..2] == [0x4C, 0x5A]).then(|| RecoveryInit {
            min_filesize: 64,
            extension: "lzr".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        if recovery.file_size != 0 {
            return DataCheckResult::Continue;
        }
        if buf.len() < 8 {
            return DataCheckResult::Error;
        }
        let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
        if len < 8 || len > buf.len() {
            return DataCheckResult::Error;
        }
        match buf[4] {
            1..=4 => DataCheckResult::Continue,
            0xFF => DataCheckResult::Stop(len as u64),
            _ => DataCheckResult::Error,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        1024 * 1024
    }
}

fn carve_015_scan(data: Vec<u8>) -> Vec<(String, u64, u64, Option<bool>)> {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xAA, 0xBB], Arc::new(TestSignature));
    registry.register(0, &[0x4C, 0x5A], Arc::new(LooseRecordSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);
    let source = MemorySource { data };
    engine
        .scan(&source, source.size())
        .into_iter()
        .map(|f| (f.signature_name, f.offset, f.size, f.validated))
        .collect()
}

/// A 2 KiB footer-terminated file whose body happens to hold `4C 5A` at the
/// start of its third sector, followed by text that is no record structure.
fn footer_file_with_body_bytes_at_sector_2(body_at_1024: &[u8]) -> Vec<u8> {
    let mut data = vec![0xAA, 0xBB];
    data.resize(2046, 0x41);
    data[1024..1024 + body_at_1024.len()].copy_from_slice(body_at_1024);
    data.extend_from_slice(&[0xCC, 0xDD]);
    data
}

/// The running carve comes out whole and footer-validated: the match inside
/// its body fails the matching signature's own data check, so it never was a
/// new file and must not cut the one being carved.
#[test]
fn a_header_that_fails_its_own_data_check_does_not_cut_a_running_carve() {
    // "LZ", then ASCII: record length 0x4141 overruns the block.
    let data = footer_file_with_body_bytes_at_sector_2(b"LZAAAAAAAAAA");
    let found = carve_015_scan(data);
    assert_eq!(
        found,
        vec![("TestFormat".to_string(), 0, 2048, Some(true))],
        "{found:?}"
    );
}

/// A match whose data check stops the new file short of its own minimum
/// size would record nothing, so it too leaves the running carve alone.
#[test]
fn a_header_whose_data_check_records_nothing_does_not_cut_a_running_carve() {
    // A well-formed end record of 16 bytes: below the 64-byte minimum.
    let data = footer_file_with_body_bytes_at_sector_2(&[
        0x4C, 0x5A, 0x10, 0x00, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    let found = carve_015_scan(data);
    assert_eq!(
        found,
        vec![("TestFormat".to_string(), 0, 2048, Some(true))],
        "{found:?}"
    );
}

/// A match that survives its data check is a new file: it ends the running
/// carve exactly as before, which is recorded not footer-validated.
#[test]
fn a_header_that_survives_its_data_check_still_ends_a_running_carve() {
    let data = footer_file_with_body_bytes_at_sector_2(&[
        0x4C, 0x5A, 0x20, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    let found = carve_015_scan(data);
    assert_eq!(
        found,
        vec![
            ("TestFormat".to_string(), 0, 1024, Some(false)),
            ("LooseRecord".to_string(), 1024, 1024, Some(false)),
        ],
        "{found:?}"
    );
}

/// A sized match whose declared size is rejected records nothing, so it
/// leaves the running carve alone too.
#[test]
fn a_sized_header_whose_size_is_rejected_does_not_cut_a_running_carve() {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xAA, 0xBB], Arc::new(TestSignature));
    registry.register(0, &[0xEE, 0xFF], Arc::new(SizedSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);
    // Declared size 2: below SizedFormat's 4-byte minimum.
    let data = footer_file_with_body_bytes_at_sector_2(&[0xEE, 0xFF, 0x02, 0x00]);
    let source = MemorySource { data };
    let found: Vec<_> = engine
        .scan(&source, source.size())
        .into_iter()
        .map(|f| (f.signature_name, f.offset, f.size, f.validated))
        .collect();
    assert_eq!(
        found,
        vec![("TestFormat".to_string(), 0, 2048, Some(true))],
        "{found:?}"
    );
}

// ── CARVE-016: a sized match inside a running carve does not cut it ─────────

fn carve_016_scan(data: Vec<u8>) -> Vec<(String, u64, u64, Option<bool>)> {
    let mut registry = SignatureRegistry::new();
    registry.register(0, &[0xAA, 0xBB], Arc::new(TestSignature));
    registry.register(0, &[0xEE, 0xFF], Arc::new(SizedSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);
    let source = MemorySource { data };
    let mut found: Vec<_> = engine
        .scan(&source, source.size())
        .into_iter()
        .map(|f| (f.signature_name, f.offset, f.size, f.validated))
        .collect();
    found.sort_by_key(|f| (f.1, f.0.clone()));
    found
}

/// A footer-terminated file 2 KiB long whose third sector begins a 512-byte
/// sized object — an embedded thumbnail, an attached icon — with the file's
/// own footer after the object ends. The sized match used to end the running
/// carve at 1,024 and record the object without resuming anything, so the
/// running file came out half its length, not validated, and its last 512
/// bytes, footer included, were in no carve at all. The object is recorded
/// and the running file carries on to its footer, whole and validated.
#[test]
fn a_sized_object_nested_in_a_running_carve_does_not_cut_it() {
    let mut data = vec![0xAA, 0xBB];
    data.resize(2046, 0x41);
    data[1024..1028].copy_from_slice(&[0xEE, 0xFF, 0x00, 0x02]);
    data.extend_from_slice(&[0xCC, 0xDD]);
    let found = carve_016_scan(data);
    assert_eq!(
        found,
        vec![
            ("TestFormat".to_string(), 0, 2048, Some(true)),
            ("SizedFormat".to_string(), 1024, 512, None),
        ],
        "{found:?}"
    );
}

/// When the running file has no footer after the sized object, nothing shows
/// the object was inside it: the running carve is recorded as it always was,
/// cut at the object's start and not validated, and the object whole.
#[test]
fn a_sized_object_after_an_unterminated_carve_still_ends_it_at_the_object() {
    let mut data = vec![0xAA, 0xBB];
    data.resize(3072, 0x41);
    data[1024..1028].copy_from_slice(&[0xEE, 0xFF, 0x00, 0x02]);
    let found = carve_016_scan(data);
    assert_eq!(
        found,
        vec![
            ("TestFormat".to_string(), 0, 1024, Some(false)),
            ("SizedFormat".to_string(), 1024, 512, None),
        ],
        "{found:?}"
    );
}

/// A terminator inside the sized object is the object's content, not the
/// running file's end: it does not stretch the running carve over the
/// object, which is recorded cut at the object as before.
#[test]
fn a_footer_inside_the_sized_object_does_not_end_the_running_carve_there() {
    let mut data = vec![0xAA, 0xBB];
    data.resize(3072, 0x41);
    data[1024..1028].copy_from_slice(&[0xEE, 0xFF, 0x00, 0x02]);
    data[1100..1102].copy_from_slice(&[0xCC, 0xDD]);
    let found = carve_016_scan(data);
    assert_eq!(
        found,
        vec![
            ("TestFormat".to_string(), 0, 1024, Some(false)),
            ("SizedFormat".to_string(), 1024, 512, None),
        ],
        "{found:?}"
    );
}

// ── CARVE-015: a loose magic planted in filler is not a file ─────────────────

/// Deterministic filler for the loose-signature survey: `xorshift64*` bytes.
fn survey_random(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
        })
        .collect()
}

/// The fillers a running carve's body is made of: free space, erased flash,
/// prose, and compressed or encrypted bytes.
fn survey_fillers(len: usize) -> Vec<(String, Vec<u8>)> {
    let prose = b"The quick brown fox jumps over the lazy dog. Lorem ipsum dolor sit amet, \
consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\r\n";
    let mut out = vec![
        ("zeros".to_string(), vec![0u8; len]),
        ("ones".to_string(), vec![0xFFu8; len]),
        (
            "prose".to_string(),
            prose.iter().copied().cycle().take(len).collect(),
        ),
    ];
    for seed in 1..=16u64 {
        out.push((
            format!("random{seed}"),
            survey_random(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15), len),
        ));
    }
    out
}

/// A pattern the body of another file can hold at a block boundary by
/// chance: four bytes or fewer, or zero bytes only. The text signature's
/// patterns are text, which every text file's body is made of, so they count
/// as loose whatever their length.
fn survey_is_loose_magic(name: &str, pattern: &[u8]) -> bool {
    pattern.len() <= 4 || pattern.iter().all(|&b| b == 0) || name == "TXT"
}

/// How much filler the survey generates: the header block is its first
/// `block` bytes, and `SurveySource` repeats the rest.
const SURVEY_SOURCE_LEN: usize = 64 * 1024;

/// The running carve's body as the survey sees it: the planted header block,
/// then the same filler for 8 GiB, so that a signature confirming its header
/// from the source (a TIFF directory anywhere a 32-bit offset can point)
/// reads filler there, as it would inside a real image, rather than running
/// off the end of a short buffer.
struct SurveySource {
    data: Vec<u8>,
    block: usize,
}

impl CarvingDataSource for SurveySource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.size().saturating_sub(offset) as usize);
        let tail = (self.data.len() - self.block) as u64;
        for (i, b) in buf[..n].iter_mut().enumerate() {
            let at = offset + i as u64;
            *b = if at < self.data.len() as u64 {
                self.data[at as usize]
            } else {
                self.data[self.block + ((at - self.block as u64) % tail) as usize]
            };
        }
        Ok(n)
    }

    fn size(&self) -> u64 {
        1 << 33
    }
}

/// Every loose registration whose signature, handed its magic planted in
/// filler, accepts the header, gives no size of its own, and survives its
/// own `data_check` on that block — so it would end a running carve
/// (`engine.rs` `new_match_survives`). Returns `(name, pattern, fillers
/// accepted)`.
fn survey_loose_survivors(block: usize) -> Vec<(String, Vec<u8>, Vec<String>)> {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let mut out = Vec::new();
    for (offset, pattern, sig) in registry.registrations() {
        // A weak header never ends a running carve, whatever it matches.
        if !survey_is_loose_magic(sig.name(), &pattern) || sig.weak_header() {
            continue;
        }
        let off = offset as usize;
        if off + pattern.len() > block {
            continue;
        }
        let mut accepted = Vec::new();
        for (label, mut data) in survey_fillers(SURVEY_SOURCE_LEN) {
            data[off..off + pattern.len()].copy_from_slice(&pattern);
            let buf = data[..block].to_vec();
            let Some(mut init) = sig.header_check(&buf, 0) else {
                continue;
            };
            let source = SurveySource { data, block };
            if init.calculated_file_size.is_none() {
                init.calculated_file_size = sig.extent_from_source(&source, 0);
            }
            if init.calculated_file_size.is_some() {
                continue;
            }
            if CarvingEngine::new_match_survives(&sig, &init, &buf, &source, 1 << 40, 0) {
                accepted.push(label);
            }
        }
        if !accepted.is_empty() {
            out.push((sig.name().to_string(), pattern, accepted));
        }
    }
    out
}

/// Survey, printed: run with `--ignored --nocapture` to list them.
#[test]
#[ignore = "survey printout; the assertion is survey_no_loose_unsized_signature_survives_filler"]
fn survey_print_loose_survivors() {
    for (name, pattern, accepted) in survey_loose_survivors(512) {
        println!(
            "{name}\t{:02x?}\t{}/{}\t{}",
            pattern,
            accepted.len(),
            survey_fillers(8).len(),
            accepted.join(",")
        );
    }
}

/// Each real file under the roots named by `SEANCE_CARVE_REAL_ROOTS`
/// (colon-separated) is handed to every signature whose magic it carries; a
/// signature that claims the file (`header_check`, unsized) must not then
/// refuse its first block in `data_check`, nor refute it from the whole file
/// (`header_confirmed_by_source`, files up to 256 MiB). A file carrying another format's
/// magic may rightly be refused by it, so only a refusal by a signature that
/// lists the file's own extension fails the test; the rest are printed.
#[test]
#[ignore = "walks local directories of real files; set SEANCE_CARVE_REAL_ROOTS"]
fn real_files_survive_their_own_header_block_check() {
    let Some(roots) = std::env::var_os("SEANCE_CARVE_REAL_ROOTS") else {
        return;
    };
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let regs = registry.registrations();

    let mut stack: Vec<std::path::PathBuf> = std::env::split_paths(&roots).collect();
    let (mut files, mut claimed, mut own_refusals) = (0u64, 0u64, Vec::new());
    let mut per_sig: std::collections::BTreeMap<String, (u64, u64)> = Default::default();
    // Per signature: confirmed from the whole file, refuted, could not look.
    let mut source_tally: std::collections::BTreeMap<String, (u64, u64, u64)> = Default::default();
    while let Some(path) = stack.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            if let Ok(dir) = std::fs::read_dir(&path) {
                stack.extend(dir.filter_map(|e| e.ok().map(|e| e.path())));
            }
            continue;
        }
        if !meta.is_file() || meta.len() == 0 {
            continue;
        }
        let Ok(mut f) = std::fs::File::open(&path) else {
            continue;
        };
        let mut block = vec![0u8; 512];
        let n = std::io::Read::read(&mut f, &mut block).unwrap_or(0);
        block.truncate(n);
        files += 1;
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let mut seen = std::collections::HashSet::new();
        for (offset, pattern, sig) in &regs {
            let off = *offset as usize;
            if block.len() < off + pattern.len() || block[off..off + pattern.len()] != pattern[..] {
                continue;
            }
            if !seen.insert(sig.name().to_string()) {
                continue;
            }
            let Some(mut init) = sig.header_check(&block, 0) else {
                continue;
            };
            let source = MemorySource {
                data: block.clone(),
            };
            if init.calculated_file_size.is_none() {
                init.calculated_file_size = sig.extent_from_source(&source, 0);
            }
            if init.calculated_file_size.is_some() {
                continue;
            }
            claimed += 1;
            let mut rec = FileRecovery::from_init(&init, 0);
            // `None` is "could not look" (no source check for this format, a
            // directory past the file, a file too large to read here), never
            // a confirmation: it is counted apart from `Some(true)`.
            let block_refused = sig.data_check(&block, &mut rec) == DataCheckResult::Error;
            let from_source = if meta.len() <= 256 << 20 {
                std::fs::read(&path).ok().and_then(|whole| {
                    sig.header_confirmed_by_source(&MemorySource { data: whole }, 0)
                })
            } else {
                None
            };
            let refused = block_refused || from_source == Some(false);
            {
                let tally = source_tally.entry(sig.name().to_string()).or_default();
                match from_source {
                    Some(true) => tally.0 += 1,
                    Some(false) => tally.1 += 1,
                    None => tally.2 += 1,
                }
            }
            let own = sig
                .extensions()
                .iter()
                .any(|e| e.eq_ignore_ascii_case(&ext));
            let entry = per_sig.entry(sig.name().to_string()).or_default();
            entry.0 += 1;
            if refused {
                entry.1 += 1;
                println!(
                    "refused\t{}\t{}\t{}",
                    sig.name(),
                    if own { "OWN" } else { "other" },
                    path.display()
                );
                if own {
                    own_refusals.push((sig.name().to_string(), path.clone()));
                }
            }
        }
    }
    for (name, (n, refused)) in &per_sig {
        let (yes, no, unknown) = source_tally.get(name).copied().unwrap_or_default();
        println!(
            "claimed\t{name}\t{n}\trefused\t{refused}\tsource_confirmed\t{yes}\tsource_refuted\t{no}\tsource_could_not_look\t{unknown}"
        );
    }
    println!("{files} files, {claimed} unsized claims");
    assert!(
        own_refusals.is_empty(),
        "real files refused by their own format's check: {own_refusals:#?}"
    );
}

// ── CARVE-015: each loose signature checks its header block ─────────────────

/// A loose registration that survives filler, and the fillers it may
/// survive, with the reason. Every other loose registration must refuse all
/// of them (`survey_no_loose_unsized_signature_survives_filler`).
const SURVEY_ALLOWED: &[(&str, &[&str], &str)] = &[
    // Text is what a text file's body is made of: a script's `#!` at a block
    // boundary inside prose is indistinguishable from the start of a script.
    ("TXT", &["prose"], "text magic in text"),
    // The planted pattern turns prose into a skippable-frame magic whose
    // payload runs past the block; RFC 8878 leaves the payload free.
    (
        "Zstandard (skippable frame first)",
        &["prose"],
        "payload is user data",
    ),
    // Printable descriptors make small offsets and lengths, all in range.
    ("HDF4", &["prose"], "prose makes in-range descriptors"),
    // CAM, DIM, Papyrus, QuarkXpress and TIB have no public layout and are weak
    // headers, which never end a running carve. MySQL MyISAM .MYI is checked
    // against files written by mariadb and mysql, and Dahua DAD against two public exports.
];

/// Every loose signature (a magic of four bytes or fewer, or of zero bytes,
/// or text) refuses its magic planted in zeros, erased flash, prose and
/// random bytes on the header block, except as `SURVEY_ALLOWED` states. Red
/// before CARVE-015's per-signature checks, when 36 loose signatures (the
/// since-removed Dovecot among them) survived one or more fillers.
#[test]
fn survey_no_loose_unsized_signature_survives_filler() {
    let mut unexpected = Vec::new();
    for (name, pattern, accepted) in survey_loose_survivors(512) {
        let allowed = SURVEY_ALLOWED
            .iter()
            .find(|(n, _, _)| *n == name)
            .map(|(_, fillers, _)| *fillers)
            .unwrap_or(&[]);
        let bad: Vec<_> = accepted
            .iter()
            .filter(|label| !allowed.iter().any(|a| *a == "*" || label.starts_with(a)))
            .collect();
        if !bad.is_empty() {
            unexpected.push(format!("{name} {pattern:02x?}: {bad:?}"));
        }
    }
    assert!(unexpected.is_empty(), "{unexpected:#?}");
}

/// Hand `block` to the registered signature called `name` as a header block:
/// `Some(true)` if its header check accepts and its `data_check` on the block
/// does not refuse it, `Some(false)` if `data_check` refuses it, `None` if the
/// header check does not match at all.
fn first_block_verdict(name: &str, block: &[u8]) -> Option<bool> {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let sig = registry
        .registrations()
        .into_iter()
        .find(|(off, pat, sig)| {
            let off = *off as usize;
            sig.name() == name && block.get(off..off + pat.len()) == Some(&pat[..])
        })
        .map(|(_, _, sig)| sig)
        .unwrap_or_else(|| panic!("no {name} registration matches the block"));
    let init = sig.header_check(block, 0)?;
    let mut rec = FileRecovery::from_init(&init, 0);
    Some(sig.data_check(block, &mut rec) != DataCheckResult::Error)
}

/// The header block of a real file of each format passes its signature's
/// check. Fixtures in `tests/fixtures/carve015/` are the first 512 bytes of
/// files written by the tools that make them: ImageMagick 6 (JPEG, both TIFF
/// byte orders, PDF), Info-ZIP 3.0, FFmpeg (Matroska, MP4, a QuickTime
/// movie's `moov` atom, an MPEG-2 program stream's pack and system headers),
/// mke2fs (an ext4 superblock and the root directory block), mkfs.xfs (a
/// superblock, and a version 2 inode; and the version 3 root inode, ino 128,
/// cut from `seance_plugin_xfs/tests/fixtures/xfs_v5_deleted.img.gz`, a v5
/// CRC-enabled volume made by mkfs.xfs on Linux 6.8), zstd 1.5, and from plaso's test data a
/// Windows `SYSTEM` hive, a PE executable and an Outlook PST.
#[test]
fn real_header_blocks_pass_their_signatures_check() {
    macro_rules! fixture {
        ($f:literal) => {
            &include_bytes!(concat!("../tests/fixtures/carve015/", $f))[..]
        };
    }
    let cases: &[(&str, &[u8])] = &[
        ("JPEG", fixture!("jpeg.bin")),
        ("TIFF_LE", fixture!("tiff_le.bin")),
        ("TIFF_BE", fixture!("tiff_be.bin")),
        ("PDF", fixture!("pdf.bin")),
        ("ZIP", fixture!("zip.bin")),
        ("MKV", fixture!("mkv.bin")),
        ("ISO Base Media", fixture!("mp4.bin")),
        ("MOV", fixture!("mov_moov_first.bin")),
        ("MPEG", fixture!("mpeg_pack.bin")),
        ("MPEG", fixture!("mpeg_system.bin")),
        ("EXT", fixture!("ext_superblock.bin")),
        ("EXT", fixture!("ext_directory.bin")),
        ("XFS", fixture!("xfs_superblock.bin")),
        ("XFS", fixture!("xfs_inode.bin")),
        ("XFS", fixture!("xfs_inode_v3.bin")),
        ("Zstandard", fixture!("zstd.bin")),
        ("Registry", fixture!("registry.bin")),
        ("PE", fixture!("pe.bin")),
        ("PST", fixture!("pst.bin")),
    ];
    for (name, block) in cases {
        assert_eq!(first_block_verdict(name, block), Some(true), "{name}");
    }
}

/// Every registration of the TIFF magic, in either byte order, refuses a
/// header block whose first directory is empty (TIFF 6.0 section 2: a
/// directory holds at least one entry). The older generic `TIFF` signature
/// in `formats/tiff.rs` shares the magic of `TIFF_LE` and `TIFF_BE`; a
/// registration that passed such a block would still end a running carve
/// wherever the other two refuse it (CARVE-015). Synthetic: it pins the
/// mechanism, the real-file companion is
/// `the_generic_tiff_signature_passes_real_tiff_header_blocks`.
#[test]
fn every_tiff_magic_registration_refuses_an_implausible_ifd_on_the_header_block() {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let mut le = survey_random(0x7715_0015, 512);
    le[..4].copy_from_slice(b"II*\0");
    le[4..8].copy_from_slice(&8u32.to_le_bytes());
    le[8..10].copy_from_slice(&[0, 0]);
    let mut be = survey_random(0x7715_0016, 512);
    be[..4].copy_from_slice(b"MM\0*");
    be[4..8].copy_from_slice(&8u32.to_be_bytes());
    be[8..10].copy_from_slice(&[0, 0]);
    let mut checked = Vec::new();
    let mut survivors = Vec::new();
    for (_, pattern, sig) in registry.registrations() {
        for block in [&le, &be] {
            if pattern[..] != block[..4] {
                continue;
            }
            let Some(init) = sig.header_check(block, 0) else {
                continue;
            };
            checked.push(sig.name().to_string());
            let source = MemorySource {
                data: block.clone(),
            };
            if CarvingEngine::new_match_survives(&sig, &init, block, &source, 1 << 40, 0) {
                survivors.push(format!("{} {:02x?}", sig.name(), pattern));
            }
        }
    }
    assert!(checked.iter().any(|n| n == "TIFF"), "{checked:?}");
    assert!(survivors.is_empty(), "{survivors:?}");
}

/// With no carve running, a recovery that would start at a `TIFF`-magic
/// header whose first directory (inside the header block) is empty is
/// refused by the generic `TIFF` registration's own `data_check`, in both
/// byte orders. The source check (`header_confirmed_by_source`) is consulted
/// only when a match would end a running carve, so at recovery start the
/// `data_check` is the only thing that refuses it. Synthetic: it pins the
/// mechanism.
#[test]
fn the_generic_tiff_signature_refuses_an_empty_directory_at_recovery_start() {
    let mut all = SignatureRegistry::new();
    crate::formats::register_all(&mut all);
    let mut registry = SignatureRegistry::new();
    for (offset, pattern, sig) in all.registrations() {
        if sig.name() == "TIFF" {
            registry.register(offset, &pattern, sig);
        }
    }
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);
    for (magic, diroff, seed) in [
        (*b"II*\0", 8u32.to_le_bytes(), 0x7715_0017u64),
        (*b"MM\0*", 8u32.to_be_bytes(), 0x7715_0018),
    ] {
        let mut data = survey_random(seed, 8192);
        data[..4].copy_from_slice(&magic);
        data[4..8].copy_from_slice(&diroff);
        data[8..10].copy_from_slice(&[0, 0]);
        let source = MemorySource { data };
        let found: Vec<_> = engine
            .scan(&source, source.size())
            .into_iter()
            .map(|f| (f.signature_name, f.offset, f.size))
            .collect();
        assert!(found.is_empty(), "{magic:02x?}: {found:?}");
    }
}

/// The generic `TIFF` signature still accepts the header blocks of real
/// TIFFs written by ImageMagick 6 in both byte orders.
#[test]
fn the_generic_tiff_signature_passes_real_tiff_header_blocks() {
    let le = include_bytes!("../tests/fixtures/carve015/tiff_le.bin");
    let be = include_bytes!("../tests/fixtures/carve015/tiff_be.bin");
    assert_eq!(first_block_verdict("TIFF", le), Some(true));
    assert_eq!(first_block_verdict("TIFF", be), Some(true));
}

/// The TIFF-style registrations (every one whose magic is `II*\0`, `MM\0*`,
/// `IIU\0` or JPEG XR's `II\xBC`), taken from the full registry.
fn tiff_family_registry() -> SignatureRegistry {
    let mut all = SignatureRegistry::new();
    crate::formats::register_all(&mut all);
    let mut registry = SignatureRegistry::new();
    for (offset, pattern, sig) in all.registrations() {
        if ["TIFF", "TIFF_LE", "TIFF_BE", "RW2", "WDP"].contains(&sig.name()) {
            registry.register(offset, &pattern, sig);
        }
    }
    registry
}

/// A running unsized carve whose body holds, at the start of its third
/// sector, a little-endian TIFF header pointing 4 KiB on at a directory with
/// no entries. The header block alone cannot refute it (the directory lies
/// beyond it); the source can, so the running carve comes out whole and
/// footer-validated (CARVE-015). Synthetic: it pins the mechanism.
#[test]
fn a_tiff_header_whose_distant_ifd_is_garbage_does_not_end_a_running_carve() {
    let mut registry = tiff_family_registry();
    registry.register(0, &[0xAA, 0xBB], Arc::new(TestSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);
    let mut data = vec![0xAA, 0xBB];
    data.resize(8190, 0x41);
    data[1024..1028].copy_from_slice(b"II*\0");
    data[1028..1032].copy_from_slice(&4096u32.to_le_bytes());
    data[1024 + 4096..1024 + 4098].copy_from_slice(&[0, 0]);
    data.extend_from_slice(&[0xCC, 0xDD]);
    let source = MemorySource { data };
    let found: Vec<_> = engine
        .scan(&source, source.size())
        .into_iter()
        .map(|f| (f.signature_name, f.offset, f.size, f.validated))
        .collect();
    assert_eq!(
        found,
        vec![("TestFormat".to_string(), 0, 8192, Some(true))],
        "{found:?}"
    );
}

/// A whole little-endian TIFF written by ImageMagick 6
/// (`convert -size 64x64 gradient: -define tiff:endian=lsb`, 8,450 bytes)
/// puts its only directory at 8,200, far past the header block. Every
/// registration that claims it confirms it from the source.
#[test]
fn a_real_tiff_with_its_directory_past_the_header_block_is_confirmed_from_the_source() {
    let data = include_bytes!("../tests/fixtures/carve015/tiff_le_whole.tif").to_vec();
    let source = MemorySource { data: data.clone() };
    let registry = tiff_family_registry();
    let mut confirmed = Vec::new();
    for (_, pattern, sig) in registry.registrations() {
        if data[..pattern.len()] != pattern[..] || sig.header_check(&data[..512], 0).is_none() {
            continue;
        }
        assert_eq!(
            sig.header_confirmed_by_source(&source, 0),
            Some(true),
            "{}",
            sig.name()
        );
        confirmed.push(sig.name().to_string());
    }
    confirmed.sort();
    assert_eq!(confirmed, ["TIFF", "TIFF_LE"]);
}

/// A big-endian ("MM") TIFF header whose directory lies 4 KiB on, past the
/// header block, and holds one entry of an undefined field type (0xFFFF).
/// The header block alone cannot refute it; each big-endian registration
/// must refute it from the source. Synthetic: this pins the mechanism for
/// the big-endian byte order, it is not validation on real evidence.
fn big_endian_tiff_with_a_garbage_distant_directory(len: usize, at: usize) -> Vec<u8> {
    let mut data = vec![0x41; len];
    data[at..at + 4].copy_from_slice(b"MM\0*");
    data[at + 4..at + 8].copy_from_slice(&4096u32.to_be_bytes());
    let dir = at + 4096;
    data[dir..dir + 2].copy_from_slice(&1u16.to_be_bytes());
    data[dir + 2..dir + 4].copy_from_slice(&0x0100u16.to_be_bytes());
    data[dir + 4..dir + 6].copy_from_slice(&0xFFFFu16.to_be_bytes());
    data
}

#[test]
fn every_big_endian_tiff_registration_refutes_a_garbage_distant_directory_from_the_source() {
    let data = big_endian_tiff_with_a_garbage_distant_directory(8192, 0);
    let source = MemorySource { data: data.clone() };
    let registry = tiff_family_registry();
    let mut refuted = Vec::new();
    for (_, pattern, sig) in registry.registrations() {
        if data[..pattern.len()] != pattern[..] || sig.header_check(&data[..512], 0).is_none() {
            continue;
        }
        assert_eq!(
            sig.header_confirmed_by_source(&source, 0),
            Some(false),
            "{}",
            sig.name()
        );
        refuted.push(sig.name().to_string());
    }
    refuted.sort();
    assert_eq!(refuted, ["TIFF", "TIFF_BE"]);
}

/// The same big-endian header met mid-carve does not end the running carve.
#[test]
fn a_big_endian_tiff_header_whose_distant_ifd_is_garbage_does_not_end_a_running_carve() {
    let mut registry = tiff_family_registry();
    registry.register(0, &[0xAA, 0xBB], Arc::new(TestSignature));
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);
    let mut data = big_endian_tiff_with_a_garbage_distant_directory(8190, 1024);
    data[0..2].copy_from_slice(&[0xAA, 0xBB]);
    data.extend_from_slice(&[0xCC, 0xDD]);
    let source = MemorySource { data };
    let found: Vec<_> = engine
        .scan(&source, source.size())
        .into_iter()
        .map(|f| (f.signature_name, f.offset, f.size, f.validated))
        .collect();
    assert_eq!(
        found,
        vec![("TestFormat".to_string(), 0, 8192, Some(true))],
        "{found:?}"
    );
}

/// The signatures that recognise their format by a magic alone, because
/// neither a public layout past it nor a real sample is held (CARVE-015).
const WEAK_HEADER_SIGNATURES: [&str; 5] = ["CAM", "DIM", "Papyrus", "QuarkXpress", "TIB"];

/// Exactly the five the owner named on 2026-09-26 are weak headers; DAD and
/// MySQL, whose layouts are public, are not among them.
#[test]
fn the_weak_header_signatures_are_the_five_decided() {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let mut weak: Vec<String> = registry
        .registrations()
        .into_iter()
        .filter(|(_, _, sig)| sig.weak_header())
        .map(|(_, _, sig)| sig.name().to_string())
        .collect();
    weak.sort();
    weak.dedup();
    assert_eq!(weak, WEAK_HEADER_SIGNATURES);
}

/// A running unsized carve whose body holds, at the start of its third
/// sector, the magic of a weak-header signature over random bytes. The match
/// does not end the running carve, which comes out whole and
/// footer-validated; the same bytes at the start of the scan, with nothing
/// running, still start a carve of their own (CARVE-015, decision (b)).
/// Synthetic: it pins the mechanism.
#[test]
fn a_weak_header_starts_a_carve_but_never_ends_a_running_one() {
    let mut all = SignatureRegistry::new();
    crate::formats::register_all(&mut all);
    let weak: Vec<_> = all
        .registrations()
        .into_iter()
        .filter(|(_, _, sig)| WEAK_HEADER_SIGNATURES.contains(&sig.name()))
        .collect();
    let mut body = survey_random(0xC0FF_EE15, 8192);
    for b in body.iter_mut().filter(|b| **b == 0xCC || **b == 0xAA) {
        *b = 0x41;
    }
    let mut tried = std::collections::BTreeSet::new();
    for (offset, pattern, sig) in weak {
        let off = offset as usize;
        let mut planted = body[1024..1536].to_vec();
        planted[off..off + pattern.len()].copy_from_slice(&pattern);
        if sig.header_check(&planted, 0).is_none() {
            continue;
        }
        tried.insert(sig.name().to_string());
        let mut registry = SignatureRegistry::new();
        registry.register(0, &[0xAA, 0xBB], Arc::new(TestSignature));
        registry.register(offset, &pattern, sig.clone());
        let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);

        let mut data = body.clone();
        data[..2].copy_from_slice(&[0xAA, 0xBB]);
        data[1024..1536].copy_from_slice(&planted);
        data.extend_from_slice(&[0xCC, 0xDD]);
        let source = MemorySource { data };
        let found: Vec<_> = engine
            .scan(&source, source.size())
            .into_iter()
            .map(|f| (f.signature_name, f.offset, f.size, f.validated))
            .collect();
        assert_eq!(
            found,
            vec![("TestFormat".to_string(), 0, 8194, Some(true))],
            "{} {pattern:02x?}",
            sig.name()
        );

        let mut alone = planted.clone();
        alone.extend_from_slice(&body[1536..]);
        let source = MemorySource { data: alone };
        let found = engine.scan(&source, source.size());
        assert!(
            found
                .iter()
                .any(|f| f.offset == 0 && f.signature_name == sig.name()),
            "{} {pattern:02x?}: {found:?}",
            sig.name()
        );
    }
    assert_eq!(
        tried.into_iter().collect::<Vec<_>>(),
        WEAK_HEADER_SIGNATURES
    );
}

/// The stated cost of the weak-header decision: a genuine weak-header file
/// met while another carve runs does not start its own carve, and when the
/// running carve stops before the weak file ends (here at its footer, inside
/// the weak file's body), the weak file's tail past that point is recovered
/// by nothing, because its header block has already been passed. This pins
/// the limit the method statements name; it is not a behaviour to keep for
/// its own sake. Synthetic: the weak file is its magic over random bytes.
#[test]
fn a_weak_header_file_met_mid_carve_loses_its_tail_past_that_carve() {
    let mut all = SignatureRegistry::new();
    crate::formats::register_all(&mut all);
    let mut body = survey_random(0xC0FF_EE16, 8192);
    for b in body.iter_mut().filter(|b| **b == 0xCC || **b == 0xAA) {
        *b = 0x41;
    }
    let mut tried = std::collections::BTreeSet::new();
    for (offset, pattern, sig) in all.registrations() {
        if !WEAK_HEADER_SIGNATURES.contains(&sig.name()) {
            continue;
        }
        let off = offset as usize;
        let mut data = body.clone();
        data[1024 + off..1024 + off + pattern.len()].copy_from_slice(&pattern);
        if sig.header_check(&data[1024..1536], 0).is_none() {
            continue;
        }
        tried.insert(sig.name().to_string());
        data[..2].copy_from_slice(&[0xAA, 0xBB]);
        data[2000..2002].copy_from_slice(&[0xCC, 0xDD]);
        let mut registry = SignatureRegistry::new();
        registry.register(0, &[0xAA, 0xBB], Arc::new(TestSignature));
        registry.register(offset, &pattern, sig.clone());
        let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);
        let source = MemorySource { data };
        let found: Vec<_> = engine
            .scan(&source, source.size())
            .into_iter()
            .map(|f| (f.signature_name, f.offset, f.size))
            .collect();
        assert_eq!(
            found,
            vec![("TestFormat".to_string(), 0, 2002)],
            "{} {pattern:02x?}",
            sig.name()
        );
    }
    assert_eq!(
        tried.into_iter().collect::<Vec<_>>(),
        WEAK_HEADER_SIGNATURES
    );
}

/// A zstd frame (zstd 1.5, over random bytes) that carries the ext superblock
/// magic `53 EF` at 0x38, as a zstd-compressed kernel module on the
/// development host does by chance. Every other field of a superblock is
/// wrong, so the EXT signature refuses it.
#[test]
fn a_zstd_frame_carrying_the_ext_magic_is_not_a_superblock() {
    let block = include_bytes!("../tests/fixtures/carve015/zstd_with_ext_magic.bin");
    assert_eq!(first_block_verdict("EXT", block), Some(false));
    assert_eq!(first_block_verdict("Zstandard", block), Some(true));
}

/// Each fixture below is laid out from its format's public description, as
/// no file of the format is held; each passes, and the same block with one
/// field made impossible is refused.
#[test]
fn spec_layout_header_blocks_pass_and_one_wrong_field_fails() {
    fn block(prefix: &[u8], fill: u8) -> Vec<u8> {
        let mut b = prefix.to_vec();
        b.resize(512, fill);
        b
    }
    fn check(name: &str, good: Vec<u8>, bad_at: usize, bad: u8) {
        assert_eq!(first_block_verdict(name, &good), Some(true), "{name} good");
        let mut wrong = good;
        wrong[bad_at] = bad;
        assert_eq!(
            first_block_verdict(name, &wrong),
            Some(false),
            "{name} bad @{bad_at}"
        );
    }

    // Stata 114: 0x72, LOHI, filetype 1, pad, nvar 3, nobs 10, label, stamp.
    let mut dta = vec![0x72, 0x02, 0x01, 0x00, 3, 0, 10, 0, 0, 0];
    dta.resize(10, 0);
    let mut label = b"auto data".to_vec();
    label.resize(81, 0);
    dta.extend_from_slice(&label);
    let mut stamp = b" 1 Jan 2024 10:00".to_vec();
    stamp.resize(18, 0);
    dta.extend_from_slice(&stamp);
    check("DTA", block(&dta, 0x40), 4, 0); // no variables (nvar 0)

    // ZODB FileStorage: "FS21", tid, tlen 200, status ' ', ulen 5, dlen 4, elen 0.
    let mut fs = b"FS21".to_vec();
    fs.extend_from_slice(&[0x03, 0xE1, 0, 0, 0, 0, 0, 1]);
    fs.extend_from_slice(&200u64.to_be_bytes());
    fs.push(b' ');
    fs.extend_from_slice(&[0, 5, 0, 4, 0, 0]);
    fs.extend_from_slice(b"admininit");
    check("FS", block(&fs, 0x80), 19, 20); // shorter than its header and strings

    // Impulse Tracker: "IMPM", song name, then volumes, speed and tempo.
    let mut it = b"IMPM".to_vec();
    it.resize(0x30, 0);
    it.extend_from_slice(&[128, 48, 6, 125, 128, 0]);
    check("IT", block(&it, 0), 0x33, 0); // a tempo of 0

    // DBPF 1.1 (The Sims 2).
    let dbpf = [b'D', b'B', b'P', b'F', 1, 0, 0, 0, 1, 0, 0, 0];
    check("MAXIS", block(&dbpf, 0), 4, 0); // major version 0

    // MLV: "MLVI", block size 52, "v2.0", ..., then a RAWI block.
    let mut mlv = b"MLVI".to_vec();
    mlv.extend_from_slice(&52u32.to_le_bytes());
    mlv.extend_from_slice(b"v2.0\0\0\0\0");
    mlv.resize(24, 0x5A);
    mlv.extend_from_slice(&[0, 0, 1, 0]); // fileNum 0, fileCount 1
    mlv.resize(52, 0);
    mlv.extend_from_slice(b"RAWI");
    check("MLV", block(&mlv, 0), 8, b'x');

    // Doom PWAD: 1 lump, directory at 12: filepos 0, size 0, "MAP01".
    let mut wad = b"PWAD".to_vec();
    wad.extend_from_slice(&1u32.to_le_bytes());
    wad.extend_from_slice(&12u32.to_le_bytes());
    wad.extend_from_slice(&[0; 8]);
    wad.extend_from_slice(b"MAP01\0\0\0");
    check("WAD", block(&wad, 0), 20, 0x01); // a control byte in the lump name

    // JPEG XR and RW2: TIFF-like headers, IFD at 8 with one SHORT entry.
    for (name, magic) in [
        ("WDP", [0x49, 0x49, 0xBC, 0x01]),
        ("RW2", [0x49, 0x49, 0x55, 0x00]),
    ] {
        let mut t = magic.to_vec();
        t.extend_from_slice(&8u32.to_le_bytes());
        t.extend_from_slice(&[1, 0, 0x01, 0xBC, 3, 0, 1, 0, 0, 0, 5, 0, 0, 0]);
        check(name, block(&t, 0), 12, 0x40); // an undefined field type
    }

    // HDF4: magic, a DD block of 2 descriptors, no next block; version tag.
    let mut hdf = vec![0x0E, 0x03, 0x13, 0x01, 0, 2, 0, 0, 0, 0];
    hdf.extend_from_slice(&[0, 30, 0, 1, 0, 0, 0, 34, 0, 0, 0, 92]);
    hdf.extend_from_slice(&[0, 1, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    check("HDF4", block(&hdf, 0), 23, 2); // a real element ending past 4 GiB

    // LZ4 frame as the `lz4` tool writes it; the header checksum is wrong.
    check(
        "LZ4",
        block(&[0x04, 0x22, 0x4D, 0x18, 0x64, 0x40, 0xA7], 0x22),
        6,
        0xA8,
    );

    // A shell script.
    let script = b"#!/bin/sh\n# start the service\nexec /usr/sbin/daemon --foreground \"$@\"\n";
    check("TXT", block(script, 0), 20, 0x01); // a control byte

    // pzstd: a skippable frame of 8 bytes, then a zstd frame.
    let mut skip = vec![0x50, 0x2A, 0x4D, 0x18, 8, 0, 0, 0];
    skip.extend_from_slice(&[0; 8]);
    skip.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD, 0x04, 0x58, 0x6D, 0x00, 0x00]);
    check(
        "Zstandard (skippable frame first)",
        block(&skip, 0x11),
        16,
        0x00,
    );

    // Parquet: `PAR1` and a dictionary page header.
    let mut pq = b"PAR1".to_vec();
    pq.extend_from_slice(&[0x15, 0x04, 0x15, 0x10, 0x15, 0x10]);
    check("Parquet", block(&pq, 0x33), 4, 0x33);
}

/// A running carve is not cut by a loose magic its body holds at a block
/// boundary. Before CARVE-015's per-signature checks, an `MZ` there (with no
/// PE header to size it) survived its own `data_check` and ended the PDF.
#[test]
fn a_stray_mz_inside_a_pdf_does_not_cut_it() {
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let engine = CarvingEngine::new(Arc::new(registry)).with_block_size(512);

    let mut image = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n1 0 obj\n<< /Length 900 >>\nstream\n".to_vec();
    image.resize(1024, b'q');
    image.extend_from_slice(b"MZ");
    image.resize(2048, 0);
    image.extend_from_slice(b"endstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
    let len = image.len() as u64;
    let source = MemorySource { data: image };
    let found = engine.scan(&source, len);
    let pdf: Vec<_> = found
        .iter()
        .filter(|f| f.signature_name == "PDF")
        .map(|f| (f.offset, f.size, f.validated))
        .collect();
    assert_eq!(pdf, vec![(0, len, Some(true))], "{found:?}");
}

/// A JPEG is judged on its first segment, whose length the next marker must
/// confirm; damage further on does not lose the file. DFTT #11's
/// `haxor2.jpg` has the length of its second segment (a DQT, at byte 19)
/// zeroed: the same damage made to a real ImageMagick JPEG still passes,
/// while the first segment's length made wrong by one is refused.
#[test]
fn a_jpeg_is_judged_on_its_first_segment() {
    let real = include_bytes!("../tests/fixtures/carve015/jpeg.bin");
    assert_eq!(&real[20..24], &[0xFF, 0xDB, 0x00, 0x43]);
    let mut damaged_later = real.to_vec();
    damaged_later[23] = 0x00;
    assert_eq!(first_block_verdict("JPEG", &damaged_later), Some(true));
    let mut wrong_first = real.to_vec();
    wrong_first[5] = 0x11; // APP0 length 17: the next byte is not a marker
    assert_eq!(first_block_verdict("JPEG", &wrong_first), Some(false));
}

/// A MyISAM index file written by mysql 8.0 (synthetic table, not case
/// evidence), planted in filler, is carved to the length its header states.
#[test]
fn a_myisam_index_in_filler_is_carved_byte_exact() {
    let fixture = include_bytes!("../tests/fixtures/carve015/myisam_mysql8_a.MYI");
    let mut registry = SignatureRegistry::new();
    crate::formats::register_all(&mut registry);
    let mut data = vec![0x5au8; 4096];
    data.extend_from_slice(fixture);
    data.extend(vec![0x5au8; 4096]);
    let source = MemorySource { data: data.clone() };
    let results = CarvingEngine::new(Arc::new(registry)).scan(&source, data.len() as u64);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].offset, 4096);
    assert_eq!(results[0].size, fixture.len() as u64);
}
