//! apply_file_hashes_batch persists each file's hashes in ONE transaction
//! instead of one autocommit UPDATE per file, and reports the parents that
//! aren't persisted yet (for retry). Guards both the metadata merge (json_set)
//! and the hash-column write (surfaced via hash-set matching).

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::json;
use uuid::Uuid;

const MD5: &str = "0123456789abcdef0123456789abcdef";
const SHA1: &str = "0123456789abcdef0123456789abcdef01234567";
const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn batch_applies_hashes_to_columns_and_metadata_and_reports_misses() -> Result<()> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case = db.create_case("HashBatch", "Examiner").await?;

    let a = Artifact::new(
        case,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "a.bin" }),
    );
    let b = Artifact::new(
        case,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "b.bin" }),
    );
    db.record_artifacts_batch(&[a.clone(), b.clone()]).await?;

    // Two real parents plus one that isn't persisted, in a single call.
    let missing = Uuid::new_v4();
    let missed = db
        .apply_file_hashes_batch(&[
            (
                case,
                a.id,
                MD5.to_string(),
                SHA1.to_string(),
                SHA256.to_string(),
            ),
            (
                case,
                b.id,
                MD5.to_string(),
                SHA1.to_string(),
                SHA256.to_string(),
            ),
            (
                case,
                missing,
                MD5.to_string(),
                SHA1.to_string(),
                SHA256.to_string(),
            ),
        ])
        .await?;

    // Only the non-existent parent is returned for retry.
    assert_eq!(missed, vec![missing]);

    // The merged hashes land in metadata (the json_set path).
    let got = db.get_artifact(a.id).await?.expect("artifact a persisted");
    assert_eq!(got.metadata.get("md5").and_then(|v| v.as_str()), Some(MD5));
    assert_eq!(
        got.metadata.get("sha1").and_then(|v| v.as_str()),
        Some(SHA1)
    );
    assert_eq!(
        got.metadata.get("sha256").and_then(|v| v.as_str()),
        Some(SHA256)
    );

    // And the hash COLUMNS are written: a hash set matching MD5 finds both files.
    let hs = db
        .create_hash_set(case, "known", None, "known", "md5")
        .await?;
    db.import_hash_set_entries(hs, &[(MD5.to_string(), Some("test".to_string()))])
        .await?;
    assert_eq!(db.count_hash_matches_for_case(case).await?, 2);

    Ok(())
}

#[tokio::test]
async fn empty_batch_is_a_noop() -> Result<()> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    assert!(db.apply_file_hashes_batch(&[]).await?.is_empty());
    assert!(db.mark_file_hashes_skipped_batch(&[]).await?.is_empty());
    Ok(())
}

/// B4-030: the UPDATE was `WHERE id = ?` with no case. Ids arrive from the
/// worker pipeline, so a corrupt or cross-case `parent_id` could write digests
/// onto another case's evidence.
#[tokio::test]
async fn a_hash_for_the_wrong_case_never_touches_another_cases_artifact() -> Result<()> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_a = db.create_case("A", "Examiner").await?;
    let case_b = db.create_case("B", "Examiner").await?;

    let victim = Artifact::new(
        case_b,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "b_evidence.bin" }),
    );
    db.record_artifact(&victim).await?;

    // Case A's pipeline offers a hash for an artifact that belongs to case B.
    let missed = db
        .apply_file_hashes_batch(&[(
            case_a,
            victim.id,
            MD5.to_string(),
            SHA1.to_string(),
            SHA256.to_string(),
        )])
        .await?;
    assert_eq!(
        missed,
        vec![victim.id],
        "a cross-case hash must match no row"
    );

    let got = db.get_artifact(victim.id).await?.expect("victim persisted");
    assert!(
        got.metadata.get("md5").is_none(),
        "case A must not be able to write digests onto case B's evidence"
    );

    // The same reasoning for the skip stamp.
    let missed = db
        .mark_file_hashes_skipped_batch(&[(case_a, victim.id, "size".to_string())])
        .await?;
    assert_eq!(missed, vec![victim.id]);
    let got = db.get_artifact(victim.id).await?.expect("victim persisted");
    assert!(got.metadata.get("content_incomplete").is_none());

    Ok(())
}

/// B6-005: a `file_hash` record that carries only `hash_skipped` must leave the
/// parent marked, not blank. A file too large or too broken to hash otherwise
/// looks exactly like one that was hashed and matched nothing.
#[tokio::test]
async fn a_skipped_hash_stamps_the_standard_incompleteness_pair() -> Result<()> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case = db.create_case("Skip", "Examiner").await?;

    let big = Artifact::new(
        case,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "huge.bin" }),
    );
    db.record_artifact(&big).await?;

    let missing = Uuid::new_v4();
    let missed = db
        .mark_file_hashes_skipped_batch(&[
            (case, big.id, "size".to_string()),
            (case, missing, "short_read".to_string()),
        ])
        .await?;
    assert_eq!(
        missed,
        vec![missing],
        "an unpersisted parent must be reported for retry, not silently accepted"
    );

    let got = db.get_artifact(big.id).await?.expect("artifact persisted");
    assert_eq!(
        got.metadata
            .get("content_incomplete")
            .and_then(|v| v.as_bool()),
        Some(true),
        "the flag must be a JSON boolean, not the string \"true\""
    );
    assert_eq!(
        got.metadata
            .get("content_incomplete_reason")
            .and_then(|v| v.as_str()),
        Some("hash_skipped_size")
    );
    assert_eq!(
        got.metadata.get("hash_skipped").and_then(|v| v.as_str()),
        Some("size")
    );
    assert!(
        got.metadata.get("md5").is_none(),
        "a skipped hash must never fabricate a digest"
    );

    Ok(())
}
