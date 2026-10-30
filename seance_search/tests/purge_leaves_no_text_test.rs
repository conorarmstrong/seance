//! A purged case must leave no readable text behind in the index directory.
//!
//! A tantivy delete is a mark: the document stops answering queries and its
//! text stays in the segment file until something merges that segment away.
//! Deleting a case is how an examiner removes an exhibit from a workspace, and
//! after a purge the names, paths and message bodies of the deleted case — and,
//! by the decision recorded as `SEC-004`, any recovered credential value — were
//! still readable with `grep` in `workspace/search_index`, indefinitely
//! (HUNT-092). The documents were gone from every query, which is exactly what
//! made it invisible.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_search::SearchService;
use serde_json::json;
use uuid::Uuid;

/// Does any file in the index directory contain this byte string?
fn text_on_disk(dir: &std::path::Path, needle: &str) -> bool {
    let needle = needle.as_bytes();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        if !entry.path().is_file() {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        if bytes.windows(needle.len()).any(|w| w == needle) {
            return true;
        }
    }
    false
}

fn seed(svc: &SearchService, case_id: Uuid, marker: &str, docs: usize) {
    for i in 0..docs {
        let art = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({
                "name": format!("{marker}_{i:03}.txt"),
                "content": format!("{marker} record {i}"),
            }),
        );
        svc.add_artifact_to_index_sync(&art).expect("index");
        if i % 7 == 6 {
            svc.commit_sync().expect("commit");
        }
    }
    svc.commit_sync().expect("commit");
}

#[tokio::test]
async fn deleting_a_case_takes_its_text_off_disk() {
    // Two markers that cannot occur in tantivy's own metadata.
    const DOOMED: &str = "zorbulaxdoomed";
    const KEPT: &str = "zorbulaxkept";

    let dir = tempfile::tempdir().expect("temp dir");
    let svc = SearchService::new(dir.path()).expect("search service");
    let doomed = Uuid::new_v4();
    let kept = Uuid::new_v4();
    seed(&svc, doomed, DOOMED, 30);
    seed(&svc, kept, KEPT, 30);

    assert!(
        text_on_disk(dir.path(), DOOMED),
        "the seeded text should be in the index to begin with"
    );

    svc.delete_case(doomed).await.expect("purge");

    assert!(
        !text_on_disk(dir.path(), DOOMED),
        "a purged case's text is still readable in the index directory"
    );

    // The other case is untouched: still on disk and still answering.
    assert!(text_on_disk(dir.path(), KEPT));
    let hits = svc.search(kept, KEPT, 10).await.expect("search");
    assert!(
        !hits.is_empty(),
        "the surviving case must still be findable"
    );
}

/// HUNT-093. Deleting one artifact marks its document and leaves its text in
/// the segment file, exactly as a case purge did before HUNT-092. Rewriting
/// every segment on each delete would cost the whole index per file, so the
/// rewrite is owed and paid at the writer's next idle moment — which must
/// actually happen, or "deleted" means "hidden from search" and nothing more.
#[tokio::test]
async fn deleting_one_artifact_takes_its_text_off_disk_at_the_next_quiet_moment() {
    const DOOMED: &str = "zorbulaxsingle";
    const KEPT: &str = "zorbulaxneighbour";

    let dir = tempfile::tempdir().expect("temp dir");
    let svc = SearchService::new(dir.path()).expect("search service");
    let case_id = Uuid::new_v4();

    seed(&svc, case_id, KEPT, 30);
    let doomed = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": format!("{DOOMED}.txt"), "content": format!("{DOOMED} the only one")}),
    );
    svc.add_artifact_to_index_sync(&doomed).expect("index");
    svc.commit_sync().expect("commit");
    assert!(text_on_disk(dir.path(), DOOMED));

    svc.delete_artifact(doomed.id).await.expect("delete");

    // The writer's idle tick is 500ms; allow generously for a slow machine.
    let mut gone = false;
    for _ in 0..40 {
        if !text_on_disk(dir.path(), DOOMED) {
            gone = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    assert!(
        gone,
        "the deleted artifact's text is still readable in the index directory"
    );
    assert!(
        text_on_disk(dir.path(), KEPT),
        "the rest of the case must survive the rewrite"
    );
}
