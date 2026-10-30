use seance_core::{
    artifact::{Artifact, ArtifactType},
    db::DatabaseConnection,
};
use seance_db::SqliteConnection;
use serde_json::json;
use sqlx::SqlitePool;
use uuid::Uuid;

async fn setup_db() -> (SqliteConnection, String) {
    // Under the system temp dir, not the working directory: these files used
    // to land in the repository root, and the WAL-mode sidecars (`-wal`,
    // `-shm`) outlived the main file that teardown removed (HUNT-039).
    let db_name = std::env::temp_dir()
        .join(format!("test_seance_{}.sqlite", Uuid::new_v4()))
        .to_string_lossy()
        .into_owned();
    let db_url = format!("sqlite:{}?mode=rwc", db_name);

    // Ensure file doesn't exist
    if std::path::Path::new(&db_name).exists() {
        let _ = std::fs::remove_file(&db_name);
    }

    let conn = SqliteConnection::new(&db_url)
        .await
        .expect("Failed to create DB connection");
    conn.initialize().await.expect("Failed to initialize DB");

    (conn, db_name)
}

async fn teardown_db(path: &str) {
    // Best effort cleanup
    // The main file and both WAL-mode sidecars; SQLite leaves the sidecars
    // behind when the last connection was not closed cleanly.
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{path}{suffix}"));
    }
}

#[tokio::test]
async fn test_create_case() {
    let (db, path) = setup_db().await;
    let case_name = "Integration Test Case";
    let examiner = "Integration Tester";

    let case_id = db
        .create_case(case_name, examiner)
        .await
        .expect("Failed to create case");

    // Verify with direct SQL
    let pool = SqlitePool::connect(&format!("sqlite:{}", path))
        .await
        .expect("Failed to connect for verification");
    let row: (String, String) = sqlx::query_as("SELECT name, status FROM cases WHERE id = ?")
        .bind(case_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch case");

    assert_eq!(row.0, case_name);
    assert_eq!(row.1, "active");

    pool.close().await;
    teardown_db(&path).await;
}

#[tokio::test]
async fn test_record_artifact_and_timeline() {
    let (db, path) = setup_db().await;
    let case_id = db.create_case("Artifact Test", "Tester").await.unwrap();

    // 1. Record Standard Artifact
    let file_artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "suspect.txt", "size": 1024}),
    );
    db.record_artifact(&file_artifact)
        .await
        .expect("Failed to record file artifact");

    // Verify Artifact
    let pool = SqlitePool::connect(&format!("sqlite:{}", path))
        .await
        .unwrap();
    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM artifacts WHERE id = ?")
        .bind(file_artifact.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 1);

    // 2. Record Timeline Event
    let ts = 1700000000;
    let event_artifact = Artifact::new(
        case_id,
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": ts,
            "timestamp_desc": "Modified",
            "source_module": "test",
            "short_desc": "File Modified",
            "full_details": "{\"filename\": \"suspect.txt\", \"info\": \"Details\"}"
        }),
    )
    .with_parent(file_artifact.id);

    db.record_artifact(&event_artifact)
        .await
        .expect("Failed to record timeline artifact");

    // Verify Timeline Table
    let row: (i64, String) =
        sqlx::query_as("SELECT timestamp, short_desc FROM timeline_events WHERE artifact_id = ?")
            .bind(event_artifact.id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(row.0, ts);
    assert_eq!(row.1, "File Modified");

    pool.close().await;
    teardown_db(&path).await;
}
