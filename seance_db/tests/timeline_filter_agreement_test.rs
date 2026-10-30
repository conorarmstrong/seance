//! The timeline page, its count and its export all build their WHERE clause
//! from `build_timeline_where`. This pins that they return the same events for
//! the same filter, across each kind of predicate (maintainability guard: the
//! predicates used to be written out four times).

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use serde_json::json;
use uuid::Uuid;

async fn seed(db: &SqliteConnection, case_id: Uuid) -> Result<Vec<Uuid>> {
    let rows = [
        (100_i64, "Created", "mft", "report_final.docx", "alpha"),
        (200, "Modified", "mft", "reportxfinal.docx", "beta"),
        (300, "Executed", "prefetch", "mimikatz.exe", "gamma"),
        (400, "Created", "evtx", "logon 4624", "delta"),
    ];
    let mut ids = Vec::new();
    for (ts, desc, module, short, name) in rows {
        let a = Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": ts,
                "timestamp_desc": desc,
                "source_module": module,
                "short_desc": short,
                "full_details": json!({"filename": name}).to_string(),
            }),
        );
        ids.push(a.id);
        db.record_artifact(&a).await?;
    }
    Ok(ids)
}

#[tokio::test]
async fn page_count_and_export_agree_on_every_filter_kind() -> Result<()> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Agree", "Examiner").await?;
    let ids = seed(&db, case_id).await?;

    let modules = vec!["mft".to_string()];
    let tagged: Vec<Vec<u8>> = vec![ids[0].as_bytes().to_vec(), ids[2].as_bytes().to_vec()];
    let none: Vec<Vec<u8>> = vec![];

    // (from, to, modules, search, filename, event_type, event_ids)
    #[allow(clippy::type_complexity)]
    let cases: Vec<(
        Option<i64>,
        Option<i64>,
        Option<&[String]>,
        Option<&str>,
        Option<&str>,
        Option<&str>,
        Option<&[Vec<u8>]>,
    )> = vec![
        (None, None, None, None, None, None, None),
        (Some(150), None, None, None, None, None, None),
        (None, Some(250), None, None, None, None, None),
        (None, None, Some(&modules), None, None, None, None),
        (None, None, None, Some("report_final"), None, None, None),
        (
            None,
            None,
            None,
            Some("+mimikatz -notepad"),
            None,
            None,
            None,
        ),
        (None, None, None, Some("source:evtx"), None, None, None),
        // Parse failure and empty-predicate fallbacks.
        (None, None, None, Some(r#""""#), None, None, None),
        (None, None, None, Some("-"), None, None, None),
        (None, None, None, None, Some("alpha"), None, None),
        (None, None, None, None, None, Some("Created"), None),
        (None, None, None, None, None, None, Some(&tagged)),
        (None, None, None, None, None, None, Some(&none)),
        (
            Some(50),
            Some(350),
            Some(&modules),
            Some("report"),
            None,
            Some("Created"),
            Some(&tagged),
        ),
    ];

    for (i, (from, to, mods, search, filename, etype, evids)) in cases.into_iter().enumerate() {
        let page = db
            .get_timeline_events_filtered(
                case_id, from, to, mods, search, filename, etype, None, None, None, None, None,
                evids,
            )
            .await?;
        let count = db
            .get_timeline_events_count(case_id, from, to, mods, search, filename, etype, evids)
            .await?;

        let mut rx = db.stream_export_timeline(
            case_id,
            from,
            to,
            mods.map(|m| m.to_vec()),
            search.map(String::from),
            filename.map(String::from),
            etype.map(String::from),
            evids.map(|e| e.to_vec()),
        );
        let mut exported = Vec::new();
        while let Some(row) = rx.recv().await {
            exported.push(row.map_err(anyhow::Error::msg)?.id);
        }

        let mut page_ids: Vec<Uuid> = page.iter().map(|e| e.id).collect();
        // Page and export share the ordering; compare as ordered lists.
        assert_eq!(page_ids, exported, "case {i}: page and export differ");
        page_ids.sort();
        assert_eq!(
            page_ids.len() as i64,
            count,
            "case {i}: page and count differ"
        );
    }
    Ok(())
}
