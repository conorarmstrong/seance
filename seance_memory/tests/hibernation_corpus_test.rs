//! The hibernation reconstruction against the two real captures this machine
//! holds, and the ground truth each was built with (MEM-026).
//!
//! Both files are several GiB and live outside the repository:
//!
//! * `SEANCE_WIN_HIBERFIL` — Windows 11 build 26200, 8 GiB guest, full
//!   hibernation, 8,499,130,368 bytes, NT10 layout. Before hibernating, the
//!   guest ran `marker.ps1` (`~/win11-lab/vm/marker.ps1`), which
//!   commits a 256 MiB buffer and writes, in each of its 65,536 pages,
//!   `"HIBRMARK"` at offset 0, `le64(i)` at offset 8 and `le64(i)` at offset
//!   2048 — nothing else. The rest of each page is what a freshly committed
//!   page holds, zero; the tests below measure that rather than assume it.
//! * `SEANCE_WIN_HUFFMAN_HIBERFIL` — Windows Server 2012 R2, NT6.2/6.3 layout,
//!   the capture that carries real Xpress-Huffman tables under that layout.
//!
//! Absent, each test skips.
//!
//! # What was found, with the offsets
//!
//! Until this was written the walk of the 26200 file stopped at byte
//! 31,361,217 (boot) and 35,713,049 (kernel) — 163 MiB restored, 7 marker
//! strings. The boot stop is the *end of the boot set*: its 2,501 tables
//! describe 40,004 pages, which is `NumPagesForLoader` at header offset 0x58.
//! The kernel stop was a misread: table 116 at byte 33,609,845 has header
//! `0x60179002`, bit 29 set, and a 22-bit size field made that 2,103,184 bytes.
//! The size is 21 bits (6,032 here) and the next table sits exactly at
//! 33,615,897. With that, the kernel set walks 31,969 tables to byte
//! 543,228,141 and describes 511,499 pages — the u64 at header offset 0x238.
//!
//! A restore set has no terminator, so the walk always ends on bytes that are
//! not a table header, and that alone cannot tell a finished set from a
//! broken one. **The only ground for calling both sets complete is that each
//! set's described page count equals the count its header states.** The bytes
//! after the kernel set's end say nothing either way, and are not a zero run:
//! of the 16,147 bytes from 543,228,141 to 543,244,288 (page 0x20614, the u64
//! at 0x78), 16,025 are non-zero, starting `8e 4d 01 04 0e b6 65 fc`, at 7.98
//! bits per byte; the file is then zero for 1,344 bytes from 543,244,288, and
//! five 1 MiB windows sampled at equal steps from 543,245,632 to the end of
//! the file each measure 8.00 bits per byte. The bytes at 543,228,141 do not
//! parse as a table header, which is how the walk ends. What that tail is —
//! the unwritten remainder of a preallocated file on a decrypted BitLocker
//! volume is one reading — was not established and is not asserted.
//!
//! Of the kernel tables, 30,479 carry bit 30. None decodes as plain Xpress and
//! all that are not stored decode as Xpress-Huffman: on this layout bit 30 is
//! the Huffman flag. The 2012 R2 file says the opposite of the same bit (103
//! bit-30 tables, all plain; 131 bit-31 tables, all Huffman), so the flag is
//! read per layout. The earlier reconstruction fed those 26200 blocks to the
//! plain decoder and placed what came out.
//!
//! # The marker count
//!
//! The complete reconstruction holds **all 65,536 marker pages**, each
//! byte-exact: `"HIBRMARK"` + `le64(i)` at 0, `le64(i)` at 2048, zero
//! elsewhere. `GROUND-TRUTH.txt` (`~/win11-lab/hiber/`) states
//! the three fields — "Page i (4096 bytes) contains: bytes[0:8]="HIBRMARK",
//! bytes[8:16]=le64(i), bytes[2048:2056]=le64(i)" and "a correct
//! decompression of physical RAM must contain 65536 pages each holding
//! "HIBRMARK"+le64(i)" — and says nothing about the other bytes; that they
//! are zero is measured here, not quoted. Before: 7 marker *strings*, none of
//! them a marker page, and 170,520,576 bytes restored. After: 65,536 marker
//! pages and 2,258,956,288 bytes — the 551,503 pages the header counts, every
//! one of them, no page number named twice by either set.
//!
//! A search for the *string* counts more than 65,536, and the difference is
//! measured, not guessed: the reconstruction holds **131,110** occurrences of
//! `"HIBRMARK"`. 131,072 of them begin a byte-exact marker page — every index
//! 0..65,535 is present at exactly **two** physical addresses, with no
//! constant displacement between the pair (10,811 distinct differences) — and
//! the other 38 sit inside pages at offsets other than 0. All 38 were read
//! (the accounting test prints each one with its surrounding bytes): 33 are
//! the script's own source text in memory — 19 copies of
//! `Encoding.ASCII.GetBytes("HIBRMARK")` and 14 of the comment `page i holds
//! "HIBRMARK" + le64(i)` — and 5 are the string inside binary structures
//! (two next to a UTF-16 `HIBRMARK`, two next to a fragment of the comment,
//! one between `NTNA` and `ECTI`) that were not identified further.
//!
//! An independent walk of the file's table entries (Python, page numbers
//! only, no decoding) finds the boot set naming 40,004 distinct page numbers
//! and the kernel set 511,499, none named twice in or across the sets, 551,503
//! in all — so the reconstruction's 551,503 pages are exactly the pages the
//! file names, each once. The 131,072 marker-page addresses are 131,072
//! distinct page numbers, none of them in the boot set: every one is named
//! once, by the kernel set. The doubling is therefore the file's account of
//! the machine, not the reader's placement. Why the machine held two copies
//! of a buffer the script wrote once is not established here.

use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::io::IncompleteReason;
use seance_memory::formats::hibernation::open;
use seance_memory::layer::MemoryLayer;
use std::sync::Arc;

const PAGE: u64 = 4096;

fn corpus(var: &str) -> Option<Arc<dyn DataSource>> {
    let p = std::env::var(var).ok()?;
    let src = FileDataSource::new(std::path::PathBuf::from(p)).ok()?;
    Some(Arc::new(src))
}

fn set_record<'a>(
    layer: &'a seance_memory::segmented::SegmentedLayer,
    set: &str,
) -> &'a serde_json::Value {
    layer
        .layer_meta()
        .note("hibernation_restore_sets")
        .and_then(|v| v.as_array())
        .and_then(|sets| sets.iter().find(|s| s["set"] == set))
        .unwrap_or_else(|| panic!("no record for the {set} set"))
}

fn incompletes(
    layer: &seance_memory::segmented::SegmentedLayer,
    reason: IncompleteReason,
) -> Vec<String> {
    layer
        .layer_meta()
        .incomplete()
        .iter()
        .filter(|i| i.reason == reason)
        .map(|i| i.detail.clone())
        .collect()
}

#[test]
fn the_win11_corpus_restores_both_sets_to_the_page_counts_its_header_states() {
    let Some(src) = corpus("SEANCE_WIN_HIBERFIL") else {
        eprintln!("skipping: set SEANCE_WIN_HIBERFIL");
        return;
    };
    let layer = open(src).expect("the corpus reconstructs");

    let boot = set_record(&layer, "boot");
    assert_eq!(boot["pages"], 40_004, "{boot}");
    assert_eq!(boot["header_count"], 40_004, "{boot}");
    assert_eq!(boot["tables"], 2_501, "{boot}");
    assert_eq!(boot["ended_at"], 31_361_217, "{boot}");
    assert_eq!(boot["complete"], true, "{boot}");

    let kernel = set_record(&layer, "kernel");
    assert_eq!(kernel["pages"], 511_499, "{kernel}");
    assert_eq!(kernel["header_count"], 511_499, "{kernel}");
    assert_eq!(kernel["tables"], 31_969, "{kernel}");
    assert_eq!(kernel["ended_at"], 543_228_141, "{kernel}");
    assert_eq!(
        kernel["tables_with_uninterpreted_bit_29"], 15_326,
        "{kernel}"
    );
    assert_eq!(kernel["complete"], true, "{kernel}");

    let stops = incompletes(&layer, IncompleteReason::UnresolvedStructure);
    assert!(stops.is_empty(), "both sets are complete: {stops:?}");
    let gaps = incompletes(&layer, IncompleteReason::Compressed);
    assert!(gaps.is_empty(), "every block decodes: {gaps:?}");

    // 40,004 + 511,499: every page the two sets describe is a distinct page
    // slot in the reconstruction, so neither set names a page the other has.
    let restored = layer
        .layer_meta()
        .note("hibernation_pages_restored")
        .and_then(|v| v.as_u64())
        .expect("restored page count");
    assert_eq!(restored, 551_503, "restored {restored} pages");
    assert_eq!(
        layer
            .layer_meta()
            .note("hibernation_restored_bytes")
            .and_then(|v| v.as_u64()),
        Some(restored * PAGE)
    );
    eprintln!(
        "win11 26200: {restored} pages restored ({} MiB)",
        restored * PAGE / (1024 * 1024)
    );
}

#[test]
fn the_win11_corpus_marker_pages_are_byte_exact_and_their_number_is_stated() {
    let Some(src) = corpus("SEANCE_WIN_HIBERFIL") else {
        eprintln!("skipping: set SEANCE_WIN_HIBERFIL");
        return;
    };
    let layer = open(src).expect("the corpus reconstructs");

    let mut markers: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut inexact = 0u64;
    let mut buf = vec![0u8; PAGE as usize];
    for segment in layer.segments() {
        let mut addr = segment.memory_offset;
        let end = addr + segment.length;
        while addr < end {
            let n = layer.read_at(addr, &mut buf).expect("a mapped page reads");
            assert_eq!(n, PAGE as usize, "page at {addr:#x}");
            if &buf[..8] == b"HIBRMARK" {
                let i = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                let j = u64::from_le_bytes(buf[2048..2056].try_into().unwrap());
                let zeros =
                    buf[16..2048].iter().all(|&b| b == 0) && buf[2056..].iter().all(|&b| b == 0);
                if i == j && i < 65_536 && zeros {
                    markers.insert(i);
                } else {
                    inexact += 1;
                }
            }
            addr += PAGE;
        }
    }
    eprintln!(
        "win11 26200: {} distinct marker pages of 65,536 ({} not byte-exact)",
        markers.len(),
        inexact
    );
    assert_eq!(inexact, 0, "every marker page present is byte-exact");
    assert_eq!(
        markers.len(),
        65_536,
        "every page the workload wrote is in the reconstruction, byte-exact"
    );
    assert_eq!(markers.iter().next_back(), Some(&65_535));
}

#[test]
fn the_2012r2_corpus_restores_both_sets_to_the_page_counts_its_header_states() {
    let Some(src) = corpus("SEANCE_WIN_HUFFMAN_HIBERFIL") else {
        eprintln!("skipping: set SEANCE_WIN_HUFFMAN_HIBERFIL");
        return;
    };
    let layer = open(src).expect("the corpus reconstructs");

    let boot = set_record(&layer, "boot");
    assert_eq!(boot["pages"], 16_664, "{boot}");
    assert_eq!(boot["header_count"], 16_664, "{boot}");
    assert_eq!(boot["complete"], true, "{boot}");
    let kernel = set_record(&layer, "kernel");
    assert_eq!(kernel["pages"], 113_548, "{kernel}");
    assert_eq!(kernel["header_count"], 113_548, "{kernel}");
    assert_eq!(kernel["tables"], 7_097, "{kernel}");
    assert_eq!(kernel["tables_with_uninterpreted_bit_29"], 0, "{kernel}");
    assert_eq!(kernel["complete"], true, "{kernel}");

    let stops = incompletes(&layer, IncompleteReason::UnresolvedStructure);
    assert!(stops.is_empty(), "{stops:?}");
    let gaps = incompletes(&layer, IncompleteReason::Compressed);
    assert!(
        gaps.is_empty(),
        "every block decodes under the NT6.2 flag reading: {gaps:?}"
    );
}

/// The count a search for the marker *string* gets, and what every occurrence
/// beyond the 65,536 marked pages is. This is the test that lets
/// `seance_plugin_memory_windows`'s rules-search test pin its string count as
/// a known answer rather than a guess at what the excess is.
#[test]
fn the_win11_corpus_holds_each_marker_page_twice_and_the_string_count_is_accounted_for() {
    let Some(src) = corpus("SEANCE_WIN_HIBERFIL") else {
        eprintln!("skipping: set SEANCE_WIN_HIBERFIL");
        return;
    };
    let layer = open(src).expect("the corpus reconstructs");

    let mut buf = vec![0u8; PAGE as usize];
    let mut occurrences = 0u64;
    let mut inside_a_page = 0u64;
    let mut inside_script_source = 0u64;
    let mut inexact_at_offset_0 = 0u64;
    let mut copies: std::collections::BTreeMap<u64, Vec<u64>> = Default::default();
    for segment in layer.segments() {
        let mut addr = segment.memory_offset;
        let end = addr + segment.length;
        while addr < end {
            layer.read_at(addr, &mut buf).expect("a mapped page reads");
            let mut pos = 0usize;
            while let Some(k) = buf[pos..].windows(8).position(|w| w == b"HIBRMARK") {
                let off = pos + k;
                occurrences += 1;
                if off == 0 {
                    let i = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                    let j = u64::from_le_bytes(buf[2048..2056].try_into().unwrap());
                    let zeros = buf[16..2048].iter().all(|&b| b == 0)
                        && buf[2056..].iter().all(|&b| b == 0);
                    if i == j && i < 65_536 && zeros {
                        copies.entry(i).or_default().push(addr);
                    } else {
                        inexact_at_offset_0 += 1;
                    }
                } else {
                    inside_a_page += 1;
                    // What each occurrence that is not a marker page sits in,
                    // printed so that a changed count can be read, not guessed.
                    let lo = off.saturating_sub(48);
                    let hi = (off + 56).min(buf.len());
                    let context: String = buf[lo..hi]
                        .iter()
                        .map(|&b| {
                            if (0x20..0x7f).contains(&b) {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    eprintln!("  string inside page {addr:#x} at +{off:#x}: {context}");
                    // The two lines of `marker.ps1` that carry the string.
                    if context.contains("GetBytes(\"HIBRMARK\")")
                        || context.contains("holds \"HIBRMARK\" + le64(i)")
                    {
                        inside_script_source += 1;
                    }
                }
                pos = off + 8;
            }
            addr += PAGE;
        }
    }
    let displacements: std::collections::BTreeSet<i64> = copies
        .values()
        .filter(|a| a.len() == 2)
        .map(|a| a[1] as i64 - a[0] as i64)
        .collect();
    eprintln!(
        "win11 26200: {occurrences} \"HIBRMARK\" strings; {} distinct marker pages, each at {} \
         address(es); {inside_a_page} inside pages at other offsets; {} distinct displacements \
         between the two copies",
        copies.len(),
        copies.values().map(Vec::len).min().unwrap_or(0),
        displacements.len()
    );

    assert_eq!(occurrences, 131_110, "the measured string count");
    assert_eq!(inexact_at_offset_0, 0);
    assert_eq!(copies.len(), 65_536);
    assert!(
        copies.values().all(|a| a.len() == 2),
        "every marked page is at exactly two physical addresses"
    );
    assert_eq!(
        inside_a_page, 38,
        "occurrences that are not at a page's start"
    );
    assert_eq!(
        inside_script_source, 33,
        "of those, the ones that are the script's own source text; the other \
         five sit in binary structures and are printed above"
    );
    assert_eq!(occurrences, 2 * 65_536 + 38);
    // Not one displaced placement of the whole buffer: the pairs are not a
    // constant distance apart.
    assert_eq!(displacements.len(), 10_811);
}
