//! The case-wide byte sweep against the NIST CFTT string-search federated test image for **unix**
//! (`ss-unix-07-25-18.dd`: HFS+, ext4, HFSX and APFS partitions), checked against the published key
//! `unix_string_doc.txt` (`VAL-005`).
//!
//! The question the structural readers could not answer: the key's 492 `DELETED-*` rows live in
//! unallocated blocks, so no file system reader names them. The sweep searches the raw bytes, so
//! the test asks, for every key row that states a byte offset, whether the sweep reports a hit at
//! that offset in the key's encoding (as its own hit, or as the folded opposite-endian reading one
//! byte after an earlier hit). Rows are counted by file system and by live or deleted.
//!
//! The image is 2 GB and is not in the repository: with the corpus absent the test says so and
//! passes, as `byte_sweep_cftt_test` does, and `SEANCE_REQUIRE_CORPUS` turns that into a failure.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use seance_core::data_source::{DataSource, FileDataSource};
use seance_search::sweep::{
    sweep, PatternSet, PatternSpec, RegionKind, SearchScope, SweepBounds, SweepRequest, SweepTarget,
};
use uuid::Uuid;

const IMAGE_BYTES: u64 = 2_098_028_544;

fn corpus_dir() -> Option<PathBuf> {
    let dir = if let Ok(dir) = std::env::var("SEANCE_CFTT_STRING_SEARCH") {
        PathBuf::from(dir)
    } else {
        PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/cftt_string_search")
            .join("string-search-federated-testing-data-set-version-1-1-revised-september-27-2019")
    };
    if dir
        .join("copy-to-test-computer/ss-unix-07-25-18.dd")
        .is_file()
        && dir.join("unix_string_doc.txt").is_file()
    {
        return Some(dir);
    }
    assert!(
        !std::env::var("SEANCE_REQUIRE_CORPUS").is_ok_and(|v| v != "0" && !v.is_empty()),
        "the NIST CFTT string-search corpus is not at {}, but SEANCE_REQUIRE_CORPUS demands it",
        dir.display()
    );
    eprintln!(
        "NOT RUN: the NIST CFTT string-search corpus is not at {}",
        dir.display()
    );
    None
}

#[derive(Debug, Clone)]
struct KeyRow {
    term: String,
    offset: u64,
    file: String,
    filesystem: String,
    encoding: String,
}

fn key_rows(dir: &std::path::Path) -> Vec<KeyRow> {
    let text = std::fs::read_to_string(dir.join("unix_string_doc.txt")).expect("key is readable");
    text.lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split(':').collect();
            if cols.len() < 7 {
                return None;
            }
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

#[test]
#[ignore = "reads the whole 2 GB image; run with --ignored when the corpus is present"]
fn a_sweep_of_the_whole_unix_image_is_measured_against_every_published_offset() {
    let Some(dir) = corpus_dir() else { return };
    let image = FileDataSource::new(dir.join("copy-to-test-computer/ss-unix-07-25-18.dd"))
        .expect("image opens");
    assert_eq!(image.size(), IMAGE_BYTES, "the image is the published size");
    let rows = key_rows(&dir);
    let terms: BTreeSet<&str> = rows.iter().map(|r| r.term.as_str()).collect();
    let target = SweepTarget {
        artifact_id: Uuid::new_v4(),
        artifact_type: "RawEvidence".to_string(),
        name: Some("ss-unix-07-25-18.dd".to_string()),
        path: None,
        region: RegionKind::Raw,
        declared_size: IMAGE_BYTES,
        content_hash: None,
        source: Arc::new(image),
    };
    let specs: Vec<PatternSpec> = terms.iter().map(|t| PatternSpec::text(*t)).collect();
    let patterns = PatternSet::compile(&specs, &["windows-1252".to_string()]).expect("compiles");
    let started = std::time::Instant::now();
    let response = sweep(
        vec![target],
        &patterns,
        &SweepRequest {
            scope: SearchScope::default(),
            bounds: SweepBounds {
                max_hits: 5_000_000,
                max_bytes: u64::MAX,
                chunk_bytes: 8 << 20,
            },
            resume: None,
        },
    )
    .expect("sweep runs");
    eprintln!(
        "unix sweep: {} terms, {} hits in {:?}; {}",
        terms.len(),
        response.hits.len(),
        started.elapsed(),
        response.coverage_statement
    );
    assert!(response.complete, "{}", response.coverage_statement);

    // Index the hits by (term, offset) with their encodings, folded twins included.
    let mut at: BTreeMap<(String, u64), BTreeSet<String>> = BTreeMap::new();
    for h in &response.hits {
        let e = at.entry((h.pattern_value.clone(), h.offset)).or_default();
        e.extend(h.encodings.iter().cloned());
        for a in &h.endian_aliases {
            if a.folded {
                at.entry((h.pattern_value.clone(), a.offset))
                    .or_default()
                    .insert(a.encoding.clone());
            }
        }
    }
    // Rows the key places exactly where the sweep reports the term, by file system and by live or
    // deleted; the rest are listed with the nearest hit of the same term.
    let mut tally: BTreeMap<(String, bool), (u32, u32)> = BTreeMap::new();
    let mut missing: Vec<(String, i64)> = Vec::new();
    for row in &rows {
        let found = at
            .get(&(row.term.clone(), row.offset))
            .is_some_and(|encs| encs.contains(&row.encoding));
        let deleted = row.file.starts_with("DELETED-");
        let t = tally.entry((row.filesystem.clone(), deleted)).or_default();
        if found {
            t.0 += 1;
        } else {
            t.1 += 1;
            let nearest = at
                .keys()
                .filter(|(t, _)| *t == row.term)
                .map(|(_, o)| *o as i64 - row.offset as i64)
                .min_by_key(|d| d.abs())
                .expect("the term is found somewhere in the image");
            missing.push((format!("{} {}", row.term, row.file), nearest));
        }
    }
    for ((fs, deleted), (f, m)) in &tally {
        eprintln!(
            "MEASURE {fs:6} {:8} found {f:4} missing {m:4}",
            if *deleted { "deleted" } else { "live" }
        );
    }
    eprintln!(
        "MEASURE total rows {} missing {}",
        rows.len(),
        missing.len()
    );

    assert_eq!(rows.len(), 1049, "key rows that state a byte offset");
    // Every `DELETED-*` row of the key, on all four file systems, is found at its published
    // offset (452 of 456), with the key's encoding, in a raw sweep that parsed no file system.
    // The four it is not are `Wolf` rows, below.
    let deleted_found: u32 = tally
        .iter()
        .filter(|((_, d), _)| *d)
        .map(|(_, (f, _))| f)
        .sum();
    let deleted_missing: u32 = tally
        .iter()
        .filter(|((_, d), _)| *d)
        .map(|(_, (_, m))| m)
        .sum();
    assert_eq!((deleted_found, deleted_missing), (452, 4));
    // The 14 rows not found at the key's offset. Eight are `Wolf` (live and deleted on each of the
    // four file systems): the term is there, one byte after the key's offset on every one, so the
    // key points at the byte before it. Six are in document formats: `rifle`, `flintlock`,
    // `longbow`, `revolver` and `shotgun` are found 6, 10, 8, 17 and 15 bytes before the key's
    // offset, which sits inside the line the term opens; `crossbow` is split by markup in the html
    // (`</u>bow`), so no contiguous `crossbow` sits there and the nearest is 5,893 bytes away.
    // None is a term the sweep missed in bytes that spell it.
    let wolf: Vec<i64> = missing
        .iter()
        .filter(|(n, _)| n.starts_with("Wolf "))
        .map(|(_, d)| *d)
        .collect();
    assert_eq!(wolf, vec![1; 8], "{missing:?}");
    let mut others: Vec<(&str, i64)> = missing
        .iter()
        .filter(|(n, _)| !n.starts_with("Wolf "))
        .map(|(n, d)| (n.split(' ').next().unwrap(), *d))
        .collect();
    others.sort();
    assert_eq!(
        others,
        vec![
            ("crossbow", 5893),
            ("flintlock", -10),
            ("longbow", -8),
            ("revolver", -17),
            ("rifle", -6),
            ("shotgun", -15),
        ]
    );
}
