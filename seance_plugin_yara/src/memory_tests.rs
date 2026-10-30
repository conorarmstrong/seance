//! The memory scanner: what a hit is, and the three things a chunk-local
//! evaluation cannot claim.

use super::memory::*;
use crate::YaraScanner;
use seance_memory::scan::{Hit, ScanControl, Scanner};
use std::io::Write;

/// Compile a rule set from source text, through the same loader the product
/// uses — a `tempfile` rather than a constructor, so the test exercises the
/// path that fails closed on a bad rule.
fn scanner(rules: &str) -> MemoryYaraScanner {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("rules.yar");
    let mut file = std::fs::File::create(&path).expect("write rules");
    file.write_all(rules.as_bytes()).expect("write");
    drop(file);
    let inner = YaraScanner::from_rule_path(dir.path()).expect("the rules compile");
    MemoryYaraScanner::new("yara_memory", std::sync::Arc::new(inner))
}

/// Collect every hit a chunk produces.
fn hits(scanner: &MemoryYaraScanner, chunk: &[u8], base: u64) -> Vec<Hit> {
    let mut out = Vec::new();
    scanner.scan_chunk(chunk, base, &mut |hit| {
        out.push(hit);
        ScanControl::Continue
    });
    out
}

const ONE_STRING: &str = r#"
rule finds_marker {
  strings: $a = "FORENSIC-W11"
  condition: $a
}
"#;

/// **A hit's address is the chunk's base plus the match offset**, which is what
/// makes it an address in the image rather than an offset in a buffer.
#[test]
fn a_hit_carries_the_address_of_its_first_byte_in_the_layer() {
    let scanner = scanner(ONE_STRING);
    let mut chunk = vec![0u8; 64];
    chunk[16..28].copy_from_slice(b"FORENSIC-W11");
    let found = hits(&scanner, &chunk, 0x7FF8_0000_0000);

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].address, 0x7FF8_0000_0000 + 16);
    assert_eq!(found[0].length, 12);
    assert_eq!(
        scanner.rule_name(found[0].pattern_id),
        Some("finds_marker"),
        "the pattern id names the rule"
    );
}

/// Two matches of the same string are two hits, each at its own address.
#[test]
fn every_match_is_its_own_hit() {
    let scanner = scanner(ONE_STRING);
    let mut chunk = vec![b'.'; 128];
    chunk[0..12].copy_from_slice(b"FORENSIC-W11");
    chunk[100..112].copy_from_slice(b"FORENSIC-W11");
    let found = hits(&scanner, &chunk, 0x1000);
    let addresses: Vec<u64> = found.iter().map(|h| h.address).collect();
    assert_eq!(addresses, vec![0x1000, 0x1064]);
}

/// A chunk with nothing in it produces nothing — and that is a clean answer,
/// as distinct from the engine having refused it.
#[test]
fn a_chunk_with_no_match_produces_no_hit_and_no_failure() {
    let scanner = scanner(ONE_STRING);
    assert!(hits(&scanner, &vec![0u8; 4096], 0).is_empty());
    assert!(
        scanner.failures().is_empty(),
        "nothing went wrong, so nothing is recorded as having gone wrong"
    );
}

/// The sink can stop the scanner mid-chunk, which is how a hit cap bounds a
/// scan without materialising every match first.
#[test]
fn the_sink_can_stop_the_scan() {
    let scanner = scanner(ONE_STRING);
    let mut chunk = vec![b'.'; 256];
    for start in [0usize, 64, 128, 192] {
        chunk[start..start + 12].copy_from_slice(b"FORENSIC-W11");
    }
    let mut seen = 0;
    scanner.scan_chunk(&chunk, 0, &mut |_| {
        seen += 1;
        if seen == 2 {
            ScanControl::Stop
        } else {
            ScanControl::Continue
        }
    });
    assert_eq!(seen, 2, "the scanner stopped when it was told to");
}

/// **The match length is unbounded and the scanner says so**, which is what
/// makes the driver publish its chunk-boundary limitation rather than hide it.
#[test]
fn the_match_length_is_declared_unbounded() {
    let scanner = scanner(ONE_STRING);
    assert_eq!(
        scanner.max_match_len(),
        None,
        "a YARA string can be a regex or a hex pattern with jumps, so no bound is knowable"
    );
    assert_eq!(scanner.name(), "yara_memory");
    assert_eq!(scanner.rule_count(), 1);
    assert_eq!(scanner.rule_names(), ["finds_marker"]);
}

/// **A two-string condition fires only where both strings are in one chunk**,
/// and the scope statement says exactly that. This is the limitation a rule set
/// written for whole-file scanning must be read with.
#[test]
fn a_condition_joining_two_strings_is_evaluated_within_one_chunk() {
    let scanner = scanner(
        r#"
rule needs_both {
  strings:
    $a = "ALPHA-MARKER"
    $b = "OMEGA-MARKER"
  condition: $a and $b
}
"#,
    );
    // Both in one chunk: it fires.
    let mut together = vec![b'.'; 256];
    together[0..12].copy_from_slice(b"ALPHA-MARKER");
    together[128..140].copy_from_slice(b"OMEGA-MARKER");
    assert!(
        !hits(&scanner, &together, 0).is_empty(),
        "both strings in one chunk satisfy the condition"
    );

    // One each side of a boundary: neither chunk satisfies it, and the two are
    // never considered together.
    let mut first = vec![b'.'; 256];
    first[0..12].copy_from_slice(b"ALPHA-MARKER");
    let mut second = vec![b'.'; 256];
    second[0..12].copy_from_slice(b"OMEGA-MARKER");
    assert!(hits(&scanner, &first, 0).is_empty());
    assert!(hits(&scanner, &second, 256).is_empty());

    // And the scanner states it rather than leaving it to be discovered.
    let scope = scanner.condition_scope();
    assert!(scope.contains("same chunk"), "got {scope}");
    assert!(scope.contains("filesize"), "got {scope}");
    assert!(
        scope.contains("larger chunk moves these"),
        "a bigger chunk is not a fix, and the statement says so: {scope}"
    );
}

/// **`filesize` is meaningless over an address space**, and the chunk's length
/// is not substituted for it.
#[test]
fn filesize_is_not_the_chunk_length() {
    let scanner = scanner(
        r#"
rule tiny_file {
  strings: $a = "FORENSIC-W11"
  condition: $a and filesize < 100
}
"#,
    );
    let mut chunk = vec![b'.'; 4096];
    chunk[0..12].copy_from_slice(b"FORENSIC-W11");
    // Whatever the engine makes of `filesize` over a 4 KiB buffer, the
    // documented position is that this scanner does not claim a file's length
    // exists. The test pins the statement, not the engine's arithmetic.
    let _ = hits(&scanner, &chunk, 0);
    assert!(scanner.condition_scope().contains("there is no file"));
}

/// A rule set with two rules keeps their ids apart, so a hit names the rule
/// that produced it and not the first one in the file.
#[test]
fn a_hit_names_the_rule_that_matched_and_not_the_first_rule() {
    let scanner = scanner(
        r#"
rule first_rule {
  strings: $a = "NOT-IN-THIS-CHUNK"
  condition: $a
}
rule second_rule {
  strings: $b = "FORENSIC-W11"
  condition: $b
}
"#,
    );
    let mut chunk = vec![b'.'; 64];
    chunk[8..20].copy_from_slice(b"FORENSIC-W11");
    let found = hits(&scanner, &chunk, 0);
    assert_eq!(found.len(), 1);
    assert_eq!(scanner.rule_name(found[0].pattern_id), Some("second_rule"));
    assert_eq!(scanner.rule_names().len(), 2);
}

/// **A rule can be true with no string of its own found**, and there is no
/// address to report for it. It is named rather than dropped.
///
/// `condition: true` is the clearest form, but a condition resting on
/// `filesize` alone has the same shape — and over a chunk of an address space
/// `filesize` means nothing, so a rule written that way firing is exactly what
/// an examiner needs to be told about rather than have quietly produce nothing.
#[test]
fn a_rule_that_matches_without_a_string_is_named_because_it_has_no_address() {
    let scanner = scanner(
        r#"
rule conditionless {
  condition: true
}
rule needs_a_string {
  strings: $a = "FORENSIC-W11"
  condition: $a
}
"#,
    );
    let mut chunk = vec![b'.'; 64];
    chunk[8..20].copy_from_slice(b"FORENSIC-W11");
    let found = hits(&scanner, &chunk, 0x2000);

    // One hit, from the rule that found a string. The conditionless rule
    // produced no hit -- there is no address it could carry.
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].address, 0x2008);
    assert_eq!(
        scanner.rule_name(found[0].pattern_id),
        Some("needs_a_string")
    );
    // And it is on the record.
    assert_eq!(
        scanner.rules_matched_without_pattern(),
        vec!["conditionless".to_string()],
        "a rule that fired with no string match must be named, not dropped"
    );
}

/// A rule whose strings all matched is NOT listed as matching without a
/// string — the list would be meaningless if every match appeared in it.
#[test]
fn a_rule_whose_string_matched_is_not_named_as_conditionless() {
    let scanner = scanner(ONE_STRING);
    let mut chunk = vec![b'.'; 64];
    chunk[0..12].copy_from_slice(b"FORENSIC-W11");
    let _ = hits(&scanner, &chunk, 0);
    assert!(scanner.rules_matched_without_pattern().is_empty());
}

/// **A fault belongs to the scan that met it, and to no later one.** One
/// compiled rule set drives every process of an image and then the next image
/// in the case, so faults that accumulated would be published again on every
/// record after the one they happened in — a refusal in process 4 reported
/// against process 900.
#[test]
fn taking_the_diagnostics_clears_them_so_a_later_record_does_not_repeat_them() {
    use seance_memory::scan::ScannerDiagnostics;

    let scanner = scanner(
        r#"
rule conditionless {
  condition: true
}
"#,
    );
    let mut chunk = vec![b'.'; 64];
    chunk[0..8].copy_from_slice(b"anything");
    let _ = hits(&scanner, &chunk, 0);

    // The first taker gets it...
    let first = scanner.take_matched_without_address();
    assert_eq!(first, vec!["conditionless".to_string()]);
    // ...and the second gets nothing, because nothing has happened since.
    assert!(scanner.take_matched_without_address().is_empty());
    // A second scan produces it again, on its own record.
    let _ = hits(&scanner, &chunk, 0x1000);
    assert_eq!(
        scanner.take_matched_without_address(),
        vec!["conditionless".to_string()]
    );

    // The same for refused chunks, which this engine cannot be made to produce
    // on demand: an empty take is an empty take, and the point is that it does
    // not grow across scans.
    assert!(scanner.take_refused_chunks().is_empty());
}
