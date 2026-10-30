//! duplicate_hash_groups groups artifacts by SHA-256, largest first, and never
//! groups distinct-hash or unhashed artifacts.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::json;

const DUP: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const UNIQUE: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const MD5: &str = "0123456789abcdef0123456789abcdef";
const SHA1: &str = "0123456789abcdef0123456789abcdef01234567";

#[tokio::test]
async fn groups_matching_sha256_largest_first() -> Result<()> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case = db.create_case("Dedup", "Examiner").await?;

    // a + b share DUP; c is unique; d has no hash at all.
    let a = Artifact::new(
        case,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "photo.jpg", "path": "/DCIM/photo.jpg" }),
    );
    let b = Artifact::new(
        case,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "photo_copy.jpg", "path": "/tmp/photo_copy.jpg" }),
    );
    let c = Artifact::new(
        case,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "unique.bin" }),
    );
    let d = Artifact::new(
        case,
        ArtifactType::FileEntry,
        None,
        json!({ "name": "nohash.bin" }),
    );
    db.record_artifacts_batch(&[a.clone(), b.clone(), c.clone(), d.clone()])
        .await?;

    db.apply_file_hashes_batch(&[
        (
            case,
            a.id,
            MD5.to_string(),
            SHA1.to_string(),
            DUP.to_string(),
        ),
        (
            case,
            b.id,
            MD5.to_string(),
            SHA1.to_string(),
            DUP.to_string(),
        ),
        (
            case,
            c.id,
            MD5.to_string(),
            SHA1.to_string(),
            UNIQUE.to_string(),
        ),
    ])
    .await?;

    let groups = db.duplicate_hash_groups(case, 100, 100).await?;

    // Only the shared hash forms a group; unique and unhashed are excluded.
    assert_eq!(groups.len(), 1, "exactly one duplicate group");
    let g = &groups[0];
    assert_eq!(g.hash, DUP);
    assert_eq!(g.count, 2);
    let names: Vec<&str> = g.members.iter().filter_map(|m| m.name.as_deref()).collect();
    assert!(names.contains(&"photo.jpg"));
    assert!(names.contains(&"photo_copy.jpg"));
    assert!(!names.contains(&"unique.bin"));
    assert!(!names.contains(&"nohash.bin"));
    // Path is surfaced from metadata.
    assert!(g
        .members
        .iter()
        .any(|m| m.path.as_deref() == Some("/DCIM/photo.jpg")));
    Ok(())
}

#[tokio::test]
async fn member_cap_keeps_true_count() -> Result<()> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case = db.create_case("Dedup", "Examiner").await?;

    let mut arts = Vec::new();
    for i in 0..5 {
        arts.push(Artifact::new(
            case,
            ArtifactType::FileEntry,
            None,
            json!({ "name": format!("copy_{i}.bin") }),
        ));
    }
    db.record_artifacts_batch(&arts).await?;
    let hashes: Vec<_> = arts
        .iter()
        .map(|a| {
            (
                case,
                a.id,
                MD5.to_string(),
                SHA1.to_string(),
                DUP.to_string(),
            )
        })
        .collect();
    db.apply_file_hashes_batch(&hashes).await?;

    // Cap members at 2, but the true count must still be 5.
    let groups = db.duplicate_hash_groups(case, 100, 2).await?;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].count, 5);
    assert_eq!(groups[0].members.len(), 2);
    Ok(())
}
