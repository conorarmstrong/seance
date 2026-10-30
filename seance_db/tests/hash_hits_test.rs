use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use uuid::Uuid;

const MD5_A: &str = "5d41402abc4b2a76b9719d911017c592";
const SHA256_B: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

async fn setup() -> (SqliteConnection, Uuid) {
    let db = SqliteConnection::new("sqlite::memory:").await.unwrap();
    db.initialize().await.unwrap();
    let case_id = db.create_case("Hash Hits Test", "Examiner").await.unwrap();
    (db, case_id)
}

async fn insert_artifact(
    db: &SqliteConnection,
    case_id: Uuid,
    metadata: serde_json::Value,
) -> Uuid {
    let artifact = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::FileEntry,
        data: None,
        metadata,
    };
    db.record_artifact(&artifact).await.unwrap();
    artifact.id
}

#[tokio::test]
async fn list_hash_hits_matches_md5_and_sha256() {
    let (db, case_id) = setup().await;

    let md5_artifact = insert_artifact(
        &db,
        case_id,
        serde_json::json!({
            "name": "evil.exe",
            "path": "/malware/evil.exe",
            "md5": MD5_A.to_uppercase(), // case-insensitive match
        }),
    )
    .await;
    let sha_artifact = insert_artifact(
        &db,
        case_id,
        serde_json::json!({
            "name": "hello.txt",
            "sha256": SHA256_B,
        }),
    )
    .await;
    // No hashes: never a hit
    insert_artifact(&db, case_id, serde_json::json!({ "name": "clean.txt" })).await;

    let set_id = db
        .create_hash_set(case_id, "notable", None, "notable", "md5")
        .await
        .unwrap();
    db.import_hash_set_entries(
        set_id,
        &[
            (MD5_A.to_string(), Some("Known Bad".to_string())),
            (SHA256_B.to_string(), None),
            ("ffffffffffffffffffffffffffffffff".to_string(), None),
        ],
    )
    .await
    .unwrap();

    let (hits, total) = db.list_hash_hits(case_id, None, 1, 100).await.unwrap();
    assert_eq!(total, 2);
    assert_eq!(hits.len(), 2);

    let md5_hit = hits.iter().find(|h| h.artifact_id == md5_artifact).unwrap();
    assert_eq!(md5_hit.algorithm, "md5");
    assert_eq!(md5_hit.matched_hash, MD5_A);
    assert_eq!(md5_hit.name.as_deref(), Some("evil.exe"));
    assert_eq!(md5_hit.path.as_deref(), Some("/malware/evil.exe"));
    assert_eq!(md5_hit.hash_set_id, set_id);
    assert_eq!(md5_hit.hash_set_name, "notable");

    let sha_hit = hits.iter().find(|h| h.artifact_id == sha_artifact).unwrap();
    assert_eq!(sha_hit.algorithm, "sha256");
    assert_eq!(sha_hit.matched_hash, SHA256_B);
}

#[tokio::test]
async fn list_hash_hits_filters_by_set_and_paginates() {
    let (db, case_id) = setup().await;

    insert_artifact(
        &db,
        case_id,
        serde_json::json!({
            "name": "a.bin", "md5": MD5_A,
        }),
    )
    .await;
    insert_artifact(
        &db,
        case_id,
        serde_json::json!({
            "name": "b.bin", "md5": MD5_A,
        }),
    )
    .await;

    let set_one = db
        .create_hash_set(case_id, "one", None, "known", "md5")
        .await
        .unwrap();
    let set_two = db
        .create_hash_set(case_id, "two", None, "known", "md5")
        .await
        .unwrap();
    db.import_hash_set_entries(set_one, &[(MD5_A.to_string(), None)])
        .await
        .unwrap();
    db.import_hash_set_entries(set_two, &[(MD5_A.to_string(), None)])
        .await
        .unwrap();

    // Unfiltered: 2 artifacts x 2 sets = 4 hits
    let (_, total) = db.list_hash_hits(case_id, None, 1, 100).await.unwrap();
    assert_eq!(total, 4);

    // Filtered to one set: 2 hits
    let (hits, total) = db
        .list_hash_hits(case_id, Some(set_one), 1, 100)
        .await
        .unwrap();
    assert_eq!(total, 2);
    assert!(hits.iter().all(|h| h.hash_set_id == set_one));

    // Pagination: page size 1 yields one row but the full total
    let (page1, total) = db
        .list_hash_hits(case_id, Some(set_one), 1, 1)
        .await
        .unwrap();
    assert_eq!(total, 2);
    assert_eq!(page1.len(), 1);
    let (page2, _) = db
        .list_hash_hits(case_id, Some(set_one), 2, 1)
        .await
        .unwrap();
    assert_eq!(page2.len(), 1);
    assert_ne!(page1[0].artifact_id, page2[0].artifact_id);
}

#[tokio::test]
async fn list_hash_hits_is_case_scoped() {
    let (db, case_a) = setup().await;
    let case_b = db.create_case("Other Case", "Examiner").await.unwrap();

    // Artifact in case A, hash set in case B: no cross-case hits
    insert_artifact(
        &db,
        case_a,
        serde_json::json!({
            "name": "a.bin", "md5": MD5_A,
        }),
    )
    .await;
    let set_b = db
        .create_hash_set(case_b, "b-set", None, "known", "md5")
        .await
        .unwrap();
    db.import_hash_set_entries(set_b, &[(MD5_A.to_string(), None)])
        .await
        .unwrap();

    let (hits, total) = db.list_hash_hits(case_a, None, 1, 100).await.unwrap();
    assert_eq!(total, 0);
    assert!(hits.is_empty());
    let (hits, total) = db.list_hash_hits(case_b, None, 1, 100).await.unwrap();
    assert_eq!(total, 0);
    assert!(hits.is_empty());
}
