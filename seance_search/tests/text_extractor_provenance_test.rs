//! The search-universe statement is about the INDEX that answered, not only
//! about the running build (`SEARCH-002`, review of 2026-09-27).
//!
//! A case ingested before the 2026-09-26 UTF-16 widening holds text read as
//! ASCII-only UTF-16. Opened on a later build, its search must not claim the
//! widened coverage: `Россия` in UTF-16 is still not in that index. The
//! service records, per case, which extractor version built its file
//! documents, and a case with file documents and no record is one an earlier
//! build made.
//!
//! "An earlier build" is simulated by removing the record file after
//! indexing: builds before this one never wrote it, so the on-disk state is
//! the same. These pin the mechanism on synthetic artifacts; they are not a
//! validation on real evidence.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::FileDataSource;
use seance_search::{
    IndexTextExtractor, MatchMode, SearchService, TEXT_EXTRACTOR_RECORD_FILE,
    TEXT_EXTRACTOR_VERSION,
};
use serde_json::json;
use uuid::Uuid;

fn file_artifact(dir: &Path, case_id: Uuid, name: &str) -> Artifact {
    let path = dir.join(name);
    std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(b"some plain text in a file"))
        .expect("write the file");
    Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(Arc::new(FileDataSource::new(path).expect("open"))),
        json!({ "name": name }),
    )
}

#[tokio::test]
async fn a_case_this_build_indexed_is_recorded_as_current_and_survives_a_restart() {
    let dir = tempfile::tempdir().expect("temp dir");
    let index = dir.path().join("index");
    let case_id = Uuid::new_v4();
    {
        let svc = SearchService::new(&index).expect("search service");
        svc.add_artifact_to_index(&file_artifact(dir.path(), case_id, "a.txt"))
            .await
            .expect("index");
        svc.commit().await.expect("commit");
        let p = svc.text_extractor_provenance(case_id);
        assert_eq!(p.status, IndexTextExtractor::Current, "{p:?}");
        assert_eq!(p.recorded_versions, vec![TEXT_EXTRACTOR_VERSION]);
    }
    let svc = SearchService::new(&index).expect("reopen");
    let p = svc.text_extractor_provenance(case_id);
    assert_eq!(
        p.status,
        IndexTextExtractor::Current,
        "after a restart: {p:?}"
    );
    let u = svc.search_universe_for_case(case_id, MatchMode::Exact);
    assert!(!u.statement.contains("earlier build"), "{}", u.statement);
}

/// The reviewer's case: a v1.0.x case opened on this build.
#[tokio::test]
async fn a_case_an_earlier_build_indexed_is_not_described_with_this_builds_coverage() {
    let dir = tempfile::tempdir().expect("temp dir");
    let index = dir.path().join("index");
    let case_id = Uuid::new_v4();
    {
        let svc = SearchService::new(&index).expect("search service");
        svc.add_artifact_to_index(&file_artifact(dir.path(), case_id, "old.txt"))
            .await
            .expect("index");
        svc.commit().await.expect("commit");
    }
    // What a build before the record existed leaves on disk.
    let _ = std::fs::remove_file(index.join(TEXT_EXTRACTOR_RECORD_FILE));

    let svc = SearchService::new(&index).expect("reopen");
    let p = svc.text_extractor_provenance(case_id);
    assert_eq!(p.status, IndexTextExtractor::Earlier, "{p:?}");
    assert!(p.recorded_versions.is_empty(), "{p:?}");
    let u = svc.search_universe_for_case(case_id, MatchMode::Exact);
    assert_eq!(u.index_text_extractor, IndexTextExtractor::Earlier);
    assert!(u.statement.contains("re-ingest"), "{}", u.statement);

    // Evidence added to the same case on this build does not make the old
    // documents current: the case stays "earlier", now with this version
    // recorded beside it.
    svc.add_artifact_to_index(&file_artifact(dir.path(), case_id, "new.txt"))
        .await
        .expect("index");
    svc.commit().await.expect("commit");
    let p = svc.text_extractor_provenance(case_id);
    assert_eq!(p.status, IndexTextExtractor::Earlier, "mixed case: {p:?}");
    assert_eq!(p.recorded_versions, vec![TEXT_EXTRACTOR_VERSION]);
}

/// A fresh ingest indexes directories (file entries with no bytes) before
/// files, and commits on a cadence. Those must not be mistaken for documents
/// an earlier build left behind.
#[tokio::test]
async fn a_fresh_case_whose_directories_are_committed_first_is_still_current() {
    let dir = tempfile::tempdir().expect("temp dir");
    let svc = SearchService::new(&dir.path().join("index")).expect("search service");
    let case_id = Uuid::new_v4();
    for n in 0..3 {
        let d = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({ "name": format!("dir{n}"), "is_directory": true }),
        );
        svc.add_artifact_to_index(&d).await.expect("index");
    }
    svc.commit().await.expect("commit");
    svc.add_artifact_to_index(&file_artifact(dir.path(), case_id, "f.txt"))
        .await
        .expect("index");
    svc.commit().await.expect("commit");
    let p = svc.text_extractor_provenance(case_id);
    assert_eq!(p.status, IndexTextExtractor::Current, "{p:?}");
}

#[tokio::test]
async fn a_case_with_no_file_documents_says_no_file_text_was_searched() {
    let dir = tempfile::tempdir().expect("temp dir");
    let svc = SearchService::new(&dir.path().join("index")).expect("search service");
    let case_id = Uuid::new_v4();
    let rec = Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({ "type": "BrowserHistory", "url": "https://example.org" }),
    );
    svc.add_artifact_to_index(&rec).await.expect("index");
    svc.commit().await.expect("commit");
    let p = svc.text_extractor_provenance(case_id);
    assert_eq!(p.status, IndexTextExtractor::NoFileDocuments, "{p:?}");
}

/// A purged case forgets its record, so a later ingest under the same id is
/// judged on what is in the index then.
#[tokio::test]
async fn deleting_a_case_forgets_its_record() {
    let dir = tempfile::tempdir().expect("temp dir");
    let index = dir.path().join("index");
    let case_id = Uuid::new_v4();
    {
        let svc = SearchService::new(&index).expect("search service");
        svc.add_artifact_to_index(&file_artifact(dir.path(), case_id, "old.txt"))
            .await
            .expect("index");
        svc.commit().await.expect("commit");
    }
    let _ = std::fs::remove_file(index.join(TEXT_EXTRACTOR_RECORD_FILE));
    let svc = SearchService::new(&index).expect("reopen");
    svc.add_artifact_to_index(&file_artifact(dir.path(), case_id, "new.txt"))
        .await
        .expect("index");
    svc.commit().await.expect("commit");
    assert_eq!(
        svc.text_extractor_provenance(case_id).status,
        IndexTextExtractor::Earlier
    );

    svc.delete_case(case_id).await.expect("delete case");
    assert_eq!(
        svc.text_extractor_provenance(case_id).status,
        IndexTextExtractor::NoFileDocuments
    );
    svc.add_artifact_to_index(&file_artifact(dir.path(), case_id, "again.txt"))
        .await
        .expect("index");
    svc.commit().await.expect("commit");
    assert_eq!(
        svc.text_extractor_provenance(case_id).status,
        IndexTextExtractor::Current
    );
}
