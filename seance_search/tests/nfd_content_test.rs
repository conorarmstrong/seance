//! A decomposed (NFD) term in a file's bytes is found by a keyword search
//! (`VAL-001`).
//!
//! NIST CFTT's Forensic String Search key holds 18 rows whose target files are
//! written in decomposed UTF-8 -- `man` + U+0303 + `ana`, `liberta` + U+0300,
//! `Ma` + U+0308 + `use`. The files were recovered and indexed and the rows
//! still failed, because the content extractor treated a combining mark as a
//! separator and indexed `man ana`.
//!
//! The bytes here come from the artifact's DATA SOURCE, a file on disk, never
//! its metadata: `serde_json` keeps a combining mark intact, so text placed in
//! the metadata would have been found all along and hidden the defect. The
//! sector text is the published CFTT target line (`==> mañana 3153`, NFD)
//! written into a synthetic file -- it pins the mechanism, it is not a
//! validation on the image; that is the CFTT re-run in `VALIDATION.md`.

use std::io::Write;
use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::FileDataSource;
use seance_search::{SearchOptions, SearchService};
use serde_json::json;
use uuid::Uuid;

fn opts(query: &str) -> SearchOptions {
    SearchOptions {
        query: query.to_string(),
        limit: 50,
        artifact_types: None,
        use_regex: false,
        file_extensions: None,
        fuzzy: None,
    }
}

#[tokio::test]
async fn a_decomposed_term_in_a_files_bytes_is_found_by_a_keyword_search() {
    let dir = tempfile::tempdir().expect("temp dir");
    let svc = SearchService::new(&dir.path().join("index")).expect("search service");
    let case_id = Uuid::new_v4();

    let mut body = vec![0u8; 64];
    body.extend_from_slice("==> man\u{303}ana 3153 <==\n".as_bytes());
    body.extend_from_slice("==> liberta\u{300} 3217 <==\n".as_bytes());
    body.extend_from_slice("==> Ma\u{308}use 3281 <==\n".as_bytes());
    body.extend_from_slice(&[0u8; 64]);
    let path = dir.path().join("LIVE-NFD-tomorrow-fat-utf-8.txt");
    std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(&body))
        .expect("write the file");

    let art = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(Arc::new(FileDataSource::new(path).expect("open"))),
        json!({ "name": "opaque.bin", "path": "/evidence/opaque.bin" }),
    );
    svc.add_artifact_to_index(&art).await.expect("index");
    svc.commit().await.expect("commit");

    for term in ["man\u{303}ana", "liberta\u{300}", "Ma\u{308}use"] {
        let response = svc
            .search_with_options(case_id, opts(term))
            .await
            .expect("search");
        assert!(
            response.results.iter().any(|r| r.artifact_id == art.id),
            "{term:?} is in the file's bytes and must be found: {response:?}"
        );
    }

    // Exact-form matching (owner decision, 2026-09-26): the precomposed (NFC)
    // spelling is different bytes and is not claimed to match decomposed text.
    // Pinned so a change to canonical-equivalence matching is a decision, not
    // an accident.
    let nfc = svc
        .search_with_options(case_id, opts("ma\u{f1}ana"))
        .await
        .expect("search");
    assert!(
        !nfc.results.iter().any(|r| r.artifact_id == art.id),
        "NFC mañana is not NFD mañana under exact-form matching: {nfc:?}"
    );
}
