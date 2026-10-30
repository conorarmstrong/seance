//! HUNT-161: a stream read from a bare `$MFT` is not served from the `$MFT`.
//!
//! Its run list addresses clusters of a volume that was not supplied. Applied
//! to the `$MFT` file the same offsets land on other MFT records, so a preview,
//! a download or a re-hash would present MFT records as the stream's content.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
};
use seance_db::SqliteConnection;
use serde_json::json;

#[tokio::test]
async fn a_stream_whose_volume_is_not_in_evidence_is_refused_not_served_from_the_mft() {
    let dir = tempfile::tempdir().unwrap();
    let mft = dir.path().join("$MFT");
    std::fs::write(&mft, vec![0x46u8; 64 * 1024]).unwrap();

    let db = SqliteConnection::new("sqlite::memory:").await.unwrap();
    db.initialize().await.unwrap();
    let case_id = db.create_case("Bare $MFT", "Examiner").await.unwrap();

    let evidence = Artifact::new(
        case_id,
        ArtifactType::RawEvidence,
        None,
        json!({
            "name": "$MFT",
            "path": mft.to_string_lossy(),
            "source_path": mft.to_string_lossy(),
        }),
    );
    db.record_artifact(&evidence).await.unwrap();

    // The shape the MFT parser publishes for `$Secure:$SDS` from a bare `$MFT`.
    let stream = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({
            "name": "$Secure:$SDS",
            "size": 8192,
            "data_runs": [[4096, 8192]],
            "data_runs_complete": true,
            "content_incomplete": true,
            "content_incomplete_reason": "unresolved_structure",
            "volume_not_in_evidence": true,
        }),
    )
    .with_parent(evidence.id);
    db.record_artifact(&stream).await.unwrap();

    let resolved = seance_api::content_resolver::resolve_artifact_content(
        &db,
        &seance_api::EvidenceRootPolicy::unrestricted(),
        case_id,
        stream.id,
    )
    .await;
    let Err(err) = resolved else {
        panic!("the $MFT's own bytes at the stream's offsets were served as the stream");
    };
    assert!(
        err.to_string().contains("not in evidence"),
        "the refusal names why: {err}"
    );
}
