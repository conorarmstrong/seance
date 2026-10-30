//! Tests for per-file hash storage: metadata md5/sha1/sha256 populate the
//! indexed hash columns on insert, apply_file_hash updates both the columns
//! and metadata, and hash-set matching reads the columns.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use uuid::Uuid;

// "hello" digests.
const MD5: &str = "5d41402abc4b2a76b9719d911017c592";
const SHA1: &str = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
const SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

async fn setup() -> (SqliteConnection, Uuid) {
    let db = SqliteConnection::new("sqlite::memory:").await.unwrap();
    db.initialize().await.unwrap();
    let case_id = db.create_case("File Hash Test", "Examiner").await.unwrap();
    (db, case_id)
}

fn file_entry(case_id: Uuid, metadata: serde_json::Value) -> Artifact {
    Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::FileEntry,
        data: None,
        metadata,
    }
}

/// A record_artifact insert with an `md5` metadata key must populate the
/// md5_hash column, making the file matchable against a hash set.
#[tokio::test]
async fn insert_with_md5_metadata_populates_column() {
    let (db, case_id) = setup().await;

    let artifact = file_entry(case_id, serde_json::json!({ "name": "a.bin", "md5": MD5 }));
    db.record_artifact(&artifact).await.unwrap();

    let set_id = db
        .create_hash_set(case_id, "known", None, "known", "md5")
        .await
        .unwrap();
    db.import_hash_set_entries(set_id, &[(MD5.to_string(), None)])
        .await
        .unwrap();

    let (hits, total) = db.list_hash_hits(case_id, None, 1, 100).await.unwrap();
    assert_eq!(total, 1, "column must be populated from md5 metadata key");
    assert_eq!(hits[0].artifact_id, artifact.id);
    assert_eq!(hits[0].algorithm, "md5");
}

/// A batch insert must also populate the hash columns.
#[tokio::test]
async fn batch_insert_populates_hash_columns() {
    let (db, case_id) = setup().await;

    let artifact = file_entry(
        case_id,
        serde_json::json!({ "name": "b.bin", "sha256": SHA256 }),
    );
    db.record_artifacts_batch(std::slice::from_ref(&artifact))
        .await
        .unwrap();

    let set_id = db
        .create_hash_set(case_id, "known", None, "known", "sha256")
        .await
        .unwrap();
    db.import_hash_set_entries(set_id, &[(SHA256.to_string(), None)])
        .await
        .unwrap();

    let (hits, total) = db.list_hash_hits(case_id, None, 1, 100).await.unwrap();
    assert_eq!(total, 1, "batch insert must populate the sha256 column");
    assert_eq!(hits[0].artifact_id, artifact.id);
    assert_eq!(hits[0].algorithm, "sha256");
}

/// apply_file_hash updates the columns AND merges md5/sha1/sha256 into the
/// artifact metadata so the Overview and export read them directly.
#[tokio::test]
async fn apply_file_hash_updates_column_and_metadata() {
    let (db, case_id) = setup().await;

    // File entry with no hashes yet (metadata-only, as a filesystem parser emits).
    let artifact = file_entry(case_id, serde_json::json!({ "name": "hello.txt" }));
    db.record_artifact(&artifact).await.unwrap();

    db.apply_file_hash(case_id, artifact.id, MD5, SHA1, SHA256)
        .await
        .unwrap();

    // Metadata now carries the hashes.
    let stored = db.get_artifact(artifact.id).await.unwrap().unwrap();
    assert_eq!(
        stored.metadata.get("md5").and_then(|v| v.as_str()),
        Some(MD5)
    );
    assert_eq!(
        stored.metadata.get("sha1").and_then(|v| v.as_str()),
        Some(SHA1)
    );
    assert_eq!(
        stored.metadata.get("sha256").and_then(|v| v.as_str()),
        Some(SHA256)
    );
    // Existing metadata is preserved.
    assert_eq!(
        stored.metadata.get("name").and_then(|v| v.as_str()),
        Some("hello.txt")
    );

    // Columns are populated: hash-set matching finds it after apply.
    let set_id = db
        .create_hash_set(case_id, "notable", None, "notable", "sha1")
        .await
        .unwrap();
    db.import_hash_set_entries(set_id, &[(SHA1.to_string(), Some("Known Bad".to_string()))])
        .await
        .unwrap();

    let (hits, total) = db.list_hash_hits(case_id, None, 1, 100).await.unwrap();
    assert_eq!(total, 1, "apply_file_hash must populate the sha1 column");
    assert_eq!(hits[0].artifact_id, artifact.id);
    assert_eq!(hits[0].algorithm, "sha1");
}

/// count_hash_matches_for_case counts distinct matching artifacts (not one
/// row per hash set) across a case.
#[tokio::test]
async fn count_hash_matches_counts_distinct_artifacts() {
    let (db, case_id) = setup().await;

    let a = file_entry(case_id, serde_json::json!({ "name": "a.bin", "md5": MD5 }));
    let b = file_entry(case_id, serde_json::json!({ "name": "b.bin", "md5": MD5 }));
    let clean = file_entry(case_id, serde_json::json!({ "name": "clean.bin" }));
    db.record_artifact(&a).await.unwrap();
    db.record_artifact(&b).await.unwrap();
    db.record_artifact(&clean).await.unwrap();

    // Two hash sets both containing MD5: a and b each match twice, but the
    // distinct-artifact count is 2.
    let s1 = db
        .create_hash_set(case_id, "one", None, "known", "md5")
        .await
        .unwrap();
    let s2 = db
        .create_hash_set(case_id, "two", None, "known", "md5")
        .await
        .unwrap();
    db.import_hash_set_entries(s1, &[(MD5.to_string(), None)])
        .await
        .unwrap();
    db.import_hash_set_entries(s2, &[(MD5.to_string(), None)])
        .await
        .unwrap();

    assert_eq!(db.count_hash_matches_for_case(case_id).await.unwrap(), 2);
}

/// apply_file_hash on a missing artifact is a tolerated no-op (returns Ok).
#[tokio::test]
async fn apply_file_hash_missing_artifact_is_noop() {
    let (db, case_id) = setup().await;
    db.apply_file_hash(case_id, Uuid::new_v4(), MD5, SHA1, SHA256)
        .await
        .unwrap();
}
