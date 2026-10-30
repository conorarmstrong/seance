//! The case-wide byte sweep against NIST CFTT's Forensic String Search
//! federated test image, checked against the published answer key.
//!
//! The image is `ss-win-07-25-18.dd` (2,098,028,544 bytes, SHA-256
//! `1574185b8dedc343ceb7dd306099a7bd41ceb77730b52c8d97181aeb792b6eb9`) from
//! the "String Search Federated Testing Data Set, version 1.1, revised
//! September 27 2019", held at `~/forensic_corpora/cftt_string_search/`. The
//! key is `win_string_doc.txt` beside it: one row per planted string, as
//! `id:term:byte offset:sector:file:filesystem:encoding`.
//!
//! The rows are the published offsets of real bytes in a real image — the
//! `cities` UTF-16LE row at byte 9,684,344 is `63 00 69 00 74 00 ...` when
//! read with `dd` — so a sweep that reports an offset the key does not hold,
//! or an encoding the key contradicts, is wrong about the evidence, not about
//! a fixture written from the same description as the code.
//!
//! Some UTF-16 rows in the key have their opposite-endian twin one byte
//! away in the image (where a planted string is followed or preceded by
//! another Latin-1 code unit, the `00` high bytes line up under either
//! reading); the sweep folds each such twin into the hit one byte before it.
//! For the four swept terms the key holds 43 UTF-16 rows, and 29 of them
//! have a twin — the other 14 stand alone, and the sweep pins those to the
//! key's encoding. Both counts are asserted below, not only printed. A
//! published UTF-16 offset is therefore found either as a hit's own offset
//! or as the `endian_aliases` offset of the hit one byte earlier, whose
//! `encodings` name both endiannesses; the checks below accept exactly those
//! two forms and nothing looser.
//!
//! When the corpus is not on the machine the tests say so and pass, because
//! a 2 GB image cannot be checked in; the honest reading of a pass on a
//! machine without the corpus is "not run here", which is what is printed.
//! That is only the default: with `SEANCE_REQUIRE_CORPUS` set (to anything but
//! empty or `0`, as for every other corpus gate) an absent corpus panics, so a
//! job that demands the corpus cannot go green having checked nothing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use seance_core::data_source::{DataSource, FileDataSource, WindowSource};
use seance_search::sweep::{
    sweep, PatternSet, PatternSpec, RegionKind, SearchScope, SweepBounds, SweepHit, SweepRequest,
    SweepTarget,
};
use uuid::Uuid;

const IMAGE_BYTES: u64 = 2_098_028_544;

fn corpus_dir() -> Option<PathBuf> {
    let dir = if let Ok(dir) = std::env::var("SEANCE_CFTT_STRING_SEARCH") {
        PathBuf::from(dir)
    } else {
        let home = std::env::var("HOME").ok()?;
        PathBuf::from(home)
            .join("forensic_corpora/cftt_string_search")
            .join("string-search-federated-testing-data-set-version-1-1-revised-september-27-2019")
    };
    if dir
        .join("copy-to-test-computer/ss-win-07-25-18.dd")
        .is_file()
        && dir.join("win_string_doc.txt").is_file()
    {
        Some(dir)
    } else {
        // The same switch `seance_core::test_support::corpus` honours: CI sets
        // it to demand proof that the comparison ran, so an absent corpus is a
        // failure there rather than a pass that checked nothing.
        assert!(
            !corpus_required(),
            "the NIST CFTT string-search corpus is not at {}, but SEANCE_REQUIRE_CORPUS demands \
             it. This run would have reported a pass having compared nothing.",
            dir.display()
        );
        eprintln!(
            "NOT RUN: the NIST CFTT string-search corpus is not at {} \
             (set SEANCE_CFTT_STRING_SEARCH to its directory)",
            dir.display()
        );
        None
    }
}

/// Whether the caller has demanded that corpora be present
/// (`SEANCE_REQUIRE_CORPUS` set to anything but empty or `0`).
fn corpus_required() -> bool {
    std::env::var("SEANCE_REQUIRE_CORPUS").is_ok_and(|v| v != "0" && !v.is_empty())
}

/// One row of the published key.
#[derive(Debug, Clone)]
struct KeyRow {
    term: String,
    offset: u64,
    file: String,
    filesystem: String,
    encoding: String,
}

fn key_rows(dir: &Path) -> Vec<KeyRow> {
    let text = std::fs::read_to_string(dir.join("win_string_doc.txt")).expect("key is readable");
    text.lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split(':').collect();
            if cols.len() < 7 {
                return None;
            }
            // The four `zipped` rows point into a docx, not at an offset.
            let offset = cols[2].trim().parse::<u64>().ok()?;
            Some(KeyRow {
                term: cols[1].trim().to_string(),
                offset,
                file: cols[4].to_string(),
                filesystem: cols[5].to_string(),
                encoding: match cols[6].trim() {
                    "utf-16-le" => "utf-16le",
                    "utf-16-be" => "utf-16be",
                    other => other,
                }
                .to_string(),
            })
        })
        .collect()
}

/// The key's region for a row, from the file name it plants the string in.
fn region_of(row: &KeyRow) -> RegionKind {
    if row.filesystem == "unalloc" {
        RegionKind::Unallocated
    } else if row.file.starts_with("DELETED-") {
        RegionKind::Recovered
    } else {
        RegionKind::Live
    }
}

/// The terms these tests sweep for: an ASCII word planted in every encoding
/// and region; the same accented word in its precomposed (NFC) and decomposed
/// (NFD) forms, which are different bytes and different key rows; and the
/// hidden-MFT key string.
fn terms() -> Vec<&'static str> {
    vec!["cities", "ma\u{f1}ana", "man\u{303}ana", "SecretKey"]
}

/// Whether a hit accounts for a key row at `offset` (an absolute image
/// offset; `base` is where the hit's object starts in the image): the row's
/// bytes are the hit's own, or the folded opposite-endian reading one byte
/// after it.
fn hit_accounts_for(hit: &SweepHit, base: u64, row: &KeyRow) -> bool {
    if hit.pattern_value != row.term {
        return false;
    }
    let own = base + hit.offset == row.offset && hit.encodings.iter().any(|e| e == &row.encoding);
    let folded = hit
        .endian_aliases
        .iter()
        .any(|a| a.folded && base + a.offset == row.offset && a.encoding == row.encoding);
    own || folded
}

fn open_image(dir: &Path) -> Arc<dyn DataSource> {
    let image = FileDataSource::new(dir.join("copy-to-test-computer/ss-win-07-25-18.dd"))
        .expect("image opens");
    assert_eq!(image.size(), IMAGE_BYTES, "the image is the published size");
    Arc::new(image)
}

#[test]
fn every_published_offset_of_the_swept_terms_is_found_in_a_window_of_the_real_image_with_its_encoding_and_region(
) {
    let Some(dir) = corpus_dir() else { return };
    let image = open_image(&dir);
    let terms = terms();
    let rows: Vec<KeyRow> = key_rows(&dir)
        .into_iter()
        .filter(|r| terms.contains(&r.term.as_str()))
        .collect();
    assert_eq!(
        rows.len(),
        28 + 21 + 21 + 2,
        "the key holds 28 cities, 21 NFC and 21 NFD mañana, and 2 SecretKey rows with offsets"
    );

    // One object per key row: a 4 KiB window of the image around the
    // published offset, labelled with the region the key places it in.
    const HALF: u64 = 2048;
    let mut ids: BTreeMap<Uuid, (u64, KeyRow)> = BTreeMap::new();
    let targets: Vec<SweepTarget> = rows
        .iter()
        .map(|row| {
            let start = row.offset.saturating_sub(HALF);
            let id = Uuid::new_v4();
            ids.insert(id, (start, row.clone()));
            SweepTarget {
                artifact_id: id,
                artifact_type: "FileContent".to_string(),
                name: Some(row.file.clone()),
                path: Some(format!("{}/{}", row.filesystem, row.file)),
                region: region_of(row),
                declared_size: HALF * 2,
                content_hash: None,
                source: Arc::new(WindowSource::new(Arc::clone(&image), start, HALF * 2)),
            }
        })
        .collect();

    let specs: Vec<PatternSpec> = terms.iter().map(|t| PatternSpec::text(*t)).collect();
    let patterns = PatternSet::compile(&specs, &["windows-1252".to_string()]).expect("compiles");
    let response = sweep(
        targets,
        &patterns,
        &SweepRequest {
            scope: SearchScope::default(),
            bounds: SweepBounds::default(),
            resume: None,
        },
    )
    .expect("sweep runs");
    assert!(response.complete, "{}", response.coverage_statement);
    assert_eq!(response.objects_searched, rows.len());

    let mut missing = Vec::new();
    let mut utf16_rows = 0;
    let mut utf16_rows_with_twin = 0;
    for (id, (start, row)) in &ids {
        let found = response
            .hits
            .iter()
            .find(|h| h.artifact_id == *id && hit_accounts_for(h, *start, row));
        match found {
            Some(hit) => {
                assert_eq!(hit.region, region_of(row));
                if row.encoding == "utf-8" && row.term.is_ascii() {
                    assert_eq!(
                        hit.encodings,
                        vec!["utf-8".to_string(), "windows-1252".to_string()],
                        "ASCII bytes are consistent with both encodings and the hit says so"
                    );
                } else if row.encoding == "utf-8" {
                    assert_eq!(
                        hit.encodings,
                        vec!["utf-8".to_string()],
                        "the UTF-8 bytes of a non-ASCII word are not any other searched encoding"
                    );
                } else {
                    utf16_rows += 1;
                    if hit.endian_ambiguous() {
                        utf16_rows_with_twin += 1;
                        assert_eq!(
                            hit.encodings,
                            vec!["utf-16be".to_string(), "utf-16le".to_string()],
                            "a folded pair names both endiannesses"
                        );
                    } else {
                        assert_eq!(hit.encodings, vec![row.encoding.clone()]);
                    }
                }
            }
            None => missing.push(format!(
                "{} {} at {} ({}, {})",
                row.term, row.encoding, row.offset, row.file, row.filesystem
            )),
        }
    }
    assert!(
        missing.is_empty(),
        "{} of {} published offsets not found:\n{}",
        missing.len(),
        rows.len(),
        missing.join("\n")
    );
    eprintln!(
        "windowed sweep: {} hits for {} key rows; {} of {} UTF-16 rows have an opposite-endian \
         twin one byte away; {} twins folded",
        response.hits.len(),
        rows.len(),
        utf16_rows_with_twin,
        utf16_rows,
        response.endian_aliases_folded
    );
    // The counts the module doc and `seance_search::sweep` quote: for the
    // four swept terms the key holds 43 UTF-16 rows, 29 of which have an
    // opposite-endian twin one byte away (each folded, none reported as a
    // hit of its own) and 14 of which stand alone.
    assert_eq!(utf16_rows, 43, "UTF-16 key rows for the swept terms");
    assert_eq!(
        utf16_rows_with_twin, 29,
        "UTF-16 key rows for the swept terms with an opposite-endian twin one byte away"
    );
    assert_eq!(
        response.endian_aliases_folded, 29,
        "every twin is folded into the hit one byte before it"
    );
    // Every hit is a key row: the windows hold nothing the key does not
    // list, and no UTF-16 twin is reported as a hit of its own.
    let unlisted: Vec<String> = response
        .hits
        .iter()
        .filter(|h| {
            let (start, _) = ids[&h.artifact_id];
            !rows.iter().any(|row| hit_accounts_for(h, start, row))
        })
        .map(|h| format!("{} {:?} at {}", h.pattern_value, h.encodings, h.offset))
        .collect();
    assert!(
        unlisted.is_empty(),
        "{} hit(s) the key does not list:\n{}",
        unlisted.len(),
        unlisted.join("\n")
    );
    assert_eq!(
        response.hits.len(),
        rows.len(),
        "one hit per key row, with every opposite-endian twin folded"
    );
    assert!(
        response
            .hits
            .iter()
            .any(|h| h.region == RegionKind::Unallocated),
        "the key plants strings in unallocated space and the sweep must label them so"
    );
    assert!(
        response
            .hits
            .iter()
            .any(|h| h.region == RegionKind::Recovered),
        "the key plants strings in deleted files and the sweep must label them so"
    );
}

/// The whole image as one object. This is the sweep an examiner runs when
/// the file system has not been parsed, or when they want slack and
/// unallocated space that no object covers. It reads all 2 GB and takes a
/// few seconds, so it runs only when asked.
#[test]
#[ignore = "reads the whole 2 GB image; run with --ignored when the corpus is present"]
fn a_sweep_of_the_whole_real_image_finds_every_published_offset_of_the_swept_terms() {
    let Some(dir) = corpus_dir() else { return };
    let image = open_image(&dir);
    let terms = terms();
    let rows: Vec<KeyRow> = key_rows(&dir)
        .into_iter()
        .filter(|r| terms.contains(&r.term.as_str()))
        .collect();

    let id = Uuid::new_v4();
    let target = SweepTarget {
        artifact_id: id,
        artifact_type: "RawEvidence".to_string(),
        name: Some("ss-win-07-25-18.dd".to_string()),
        path: None,
        region: RegionKind::Raw,
        declared_size: IMAGE_BYTES,
        // The published hash, so the sweep does not spend the run hashing.
        content_hash: Some(
            "1574185b8dedc343ceb7dd306099a7bd41ceb77730b52c8d97181aeb792b6eb9".to_string(),
        ),
        source: image,
    };
    let specs: Vec<PatternSpec> = terms.iter().map(|t| PatternSpec::text(*t)).collect();
    let patterns = PatternSet::compile(&specs, &[]).expect("compiles");
    let started = std::time::Instant::now();
    let response = sweep(
        vec![target],
        &patterns,
        &SweepRequest {
            scope: SearchScope::default(),
            bounds: SweepBounds {
                max_hits: 100_000,
                max_bytes: u64::MAX,
                chunk_bytes: 8 << 20,
            },
            resume: None,
        },
    )
    .expect("sweep runs");
    eprintln!(
        "whole-image sweep: {} hits in {:?}; {}",
        response.hits.len(),
        started.elapsed(),
        response.coverage_statement
    );
    assert!(response.complete, "{}", response.coverage_statement);
    assert_eq!(response.bytes_scanned, IMAGE_BYTES);

    let missing: Vec<String> = rows
        .iter()
        .filter(|row| !response.hits.iter().any(|h| hit_accounts_for(h, 0, row)))
        .map(|row| format!("{} {} at {}", row.term, row.encoding, row.offset))
        .collect();
    assert!(
        missing.is_empty(),
        "{} of {} published offsets not found:\n{}",
        missing.len(),
        rows.len(),
        missing.join("\n")
    );
    // Every hit in the whole image is a key row, own reading or folded
    // twin: a hit the key does not list would be a hit the sweep is wrong
    // about, and an unfolded twin would be a second hit for one string.
    let unlisted: Vec<String> = response
        .hits
        .iter()
        .filter(|h| !rows.iter().any(|row| hit_accounts_for(h, 0, row)))
        .map(|h| {
            format!(
                "{} {:?} at {} aliases {:?}",
                h.pattern_value, h.encodings, h.offset, h.endian_aliases
            )
        })
        .collect();
    assert!(
        unlisted.is_empty(),
        "{} hit(s) the key does not list:\n{}",
        unlisted.len(),
        unlisted.join("\n")
    );
    assert_eq!(response.hits.len(), rows.len(), "one hit per key row");
    assert!(response.hits.iter().all(|h| h.region == RegionKind::Raw));
}
