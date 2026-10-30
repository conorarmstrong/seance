//! Filtering and sorting a parsed-record listing SERVER-SIDE.
//!
//! A record table could previously only filter the rows it had already fetched,
//! so on any set larger than one page the filter searched a slice and a term
//! missing from the slice looked like a term missing from the case. The screen
//! said so, honestly, but the caveat existed only because the query could not do
//! the work.
//!
//! The load-bearing assertion here is [`the_total_counts_the_filtered_set`]. The
//! "N of T" line above every record table reads T straight off this number; if T
//! stays the TYPE's count while the rows are filtered, that line becomes a false
//! statement about the evidence the moment anybody types in the box.
//!
//! The second is [`a_record_whose_metadata_will_not_parse_is_counted_not_hidden`].
//! `json_extract` over malformed JSON aborts the whole statement, so every
//! extraction has to sit behind `json_valid`; the cost of that guard is that an
//! unparseable record can never match a search term. It must not therefore
//! vanish without trace — the listing counts those rows and says how many.

mod common;

use anyhow::Result;
use common::file_db;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::{RecordListingQuery, RecordOrder, RecordSort, RecordTextFilter, SqliteConnection};
use serde_json::json;
use uuid::Uuid;

async fn setup() -> Result<(SqliteConnection, Uuid)> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Records", "examiner").await?;

    let rows = vec![
        json!({"type": "WhatsApp", "body": "Meet me at the DOCK", "sender": "alice", "seq": 3}),
        json!({"type": "WhatsApp", "body": "dock is closed", "sender": "bob", "seq": 1}),
        json!({"type": "WhatsApp", "body": "nothing here", "sender": "dockside ltd", "seq": 2}),
        json!({"type": "WhatsApp", "body": "unrelated", "sender": "carol", "seq": 4}),
        // A different type entirely: it must never be counted by a WhatsApp
        // listing, filtered or not.
        json!({"type": "Skype", "body": "dock dock dock", "sender": "dave"}),
    ];
    let artifacts: Vec<Artifact> = rows
        .into_iter()
        .map(|metadata| Artifact {
            id: Uuid::new_v4(),
            case_id,
            parent_id: None,
            artifact_type: ArtifactType::ParsedRecord,
            metadata,
            data: None,
        })
        .collect();
    db.record_artifacts_batch(&artifacts).await?;
    Ok((db, case_id))
}

fn query<'a>(record_type: &'a str) -> RecordListingQuery<'a> {
    RecordListingQuery {
        record_type,
        source_id: None,
        search: None,
        sort: None,
        order: RecordOrder::OldestIngestedFirst,
        page: 1,
        page_size: 100,
        include_superseded: false,
    }
}

fn bodies(records: &[Artifact]) -> Vec<String> {
    records
        .iter()
        .map(|r| {
            r.metadata
                .get("body")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string()
        })
        .collect()
}

#[tokio::test]
async fn the_total_counts_the_filtered_set() -> Result<()> {
    let (db, case_id) = setup().await?;
    let keys = vec!["body".to_string()];

    let unfiltered = db
        .list_records_filtered(case_id, &query("WhatsApp"))
        .await?;
    assert_eq!(unfiltered.total, 4);
    assert_eq!(unfiltered.type_total, 4);

    let mut q = query("WhatsApp");
    q.search = Some(RecordTextFilter {
        needle: "dock",
        keys: &keys,
    });
    let filtered = db.list_records_filtered(case_id, &q).await?;

    assert_eq!(
        filtered.total, 2,
        "the total above a filtered table must count the FILTERED rows, or the \
         'N of T' line is a lie the moment the filter is used"
    );
    assert_eq!(
        filtered.type_total, 4,
        "and the type's own population must still be sayable alongside it"
    );
    assert_eq!(filtered.records.len(), 2);
    Ok(())
}

#[tokio::test]
async fn the_search_is_case_insensitive_and_ors_across_the_named_keys() -> Result<()> {
    let (db, case_id) = setup().await?;

    // `body` alone: "Meet me at the DOCK" (upper case) and "dock is closed".
    let body_only = vec!["body".to_string()];
    let mut q = query("WhatsApp");
    q.search = Some(RecordTextFilter {
        needle: "DoCk",
        keys: &body_only,
    });
    let page = db.list_records_filtered(case_id, &q).await?;
    assert_eq!(page.total, 2);

    // Adding `sender` ORs in "dockside ltd", whose body says nothing.
    let both = vec!["body".to_string(), "sender".to_string()];
    let mut q = query("WhatsApp");
    q.search = Some(RecordTextFilter {
        needle: "dock",
        keys: &both,
    });
    let page = db.list_records_filtered(case_id, &q).await?;
    assert_eq!(page.total, 3);
    Ok(())
}

#[tokio::test]
async fn a_search_never_reaches_into_another_record_type() -> Result<()> {
    let (db, case_id) = setup().await?;
    let keys = vec!["body".to_string()];
    let mut q = query("WhatsApp");
    q.search = Some(RecordTextFilter {
        needle: "dock",
        keys: &keys,
    });
    let page = db.list_records_filtered(case_id, &q).await?;
    assert!(
        !bodies(&page.records)
            .iter()
            .any(|b| b.contains("dock dock")),
        "the Skype record matches the term but is not in this type's population"
    );
    Ok(())
}

#[tokio::test]
async fn like_metacharacters_in_the_term_match_literally() -> Result<()> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Escaping", "examiner").await?;
    let artifacts: Vec<Artifact> = ["report_final", "reportXfinal"]
        .iter()
        .map(|body| Artifact {
            id: Uuid::new_v4(),
            case_id,
            parent_id: None,
            artifact_type: ArtifactType::ParsedRecord,
            metadata: json!({"type": "Doc", "body": body}),
            data: None,
        })
        .collect();
    db.record_artifacts_batch(&artifacts).await?;

    let keys = vec!["body".to_string()];
    let mut q = query("Doc");
    q.search = Some(RecordTextFilter {
        needle: "report_final",
        keys: &keys,
    });
    let page = db.list_records_filtered(case_id, &q).await?;
    assert_eq!(
        page.total, 1,
        "'_' is a LIKE wildcard; unescaped it silently over-matches, which in a \
         record listing is an extra row of somebody else's evidence"
    );
    Ok(())
}

#[tokio::test]
async fn sorting_by_a_metadata_key_orders_by_that_key() -> Result<()> {
    let (db, case_id) = setup().await?;

    let mut q = query("WhatsApp");
    q.sort = Some(RecordSort {
        key: "seq",
        descending: false,
    });
    let asc = db.list_records_filtered(case_id, &q).await?;
    let seqs: Vec<i64> = asc
        .records
        .iter()
        .map(|r| r.metadata["seq"].as_i64().unwrap())
        .collect();
    assert_eq!(seqs, vec![1, 2, 3, 4]);

    q.sort = Some(RecordSort {
        key: "seq",
        descending: true,
    });
    let desc = db.list_records_filtered(case_id, &q).await?;
    let seqs: Vec<i64> = desc
        .records
        .iter()
        .map(|r| r.metadata["seq"].as_i64().unwrap())
        .collect();
    assert_eq!(seqs, vec![4, 3, 2, 1]);
    Ok(())
}

#[tokio::test]
async fn a_sorted_listing_pages_without_dropping_or_repeating_a_row() -> Result<()> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Paging", "examiner").await?;

    // Every record shares one sort value, so the tie-break is the only thing
    // that makes the order total. Without it a page boundary reshuffles and a
    // row appears twice, or never.
    let artifacts: Vec<Artifact> = (0..20)
        .map(|i| Artifact {
            id: Uuid::new_v4(),
            case_id,
            parent_id: None,
            artifact_type: ArtifactType::ParsedRecord,
            metadata: json!({"type": "Doc", "rank": 1, "n": i}),
            data: None,
        })
        .collect();
    db.record_artifacts_batch(&artifacts).await?;

    let mut seen = std::collections::HashSet::new();
    for page in 1..=4u32 {
        let mut q = query("Doc");
        q.sort = Some(RecordSort {
            key: "rank",
            descending: false,
        });
        q.page = page;
        q.page_size = 5;
        let got = db.list_records_filtered(case_id, &q).await?;
        for r in &got.records {
            assert!(seen.insert(r.id), "record {} appeared on two pages", r.id);
        }
    }
    assert_eq!(
        seen.len(),
        20,
        "every record must appear on exactly one page"
    );
    Ok(())
}

#[tokio::test]
async fn a_record_whose_metadata_will_not_parse_is_counted_not_hidden() -> Result<()> {
    // Corrupted in the file, byte for byte, exactly as
    // `comms_histogram_test::one_unreadable_record_costs_one_record_not_the_whole_chart`
    // does it: nothing in this crate can write invalid JSON, because every write
    // path serialises `metadata_json` from a `serde_json::Value`, and an UPDATE
    // that tried would be refused by the record-type expression index. This is
    // the shape corruption AFTER write leaves behind, where the row is still
    // reachable through an index key computed while the JSON still parsed.
    let (db, path) = file_db().await?;
    let case_id = db.create_case("Corrupt", "examiner").await?;

    let good: Vec<Artifact> = ["dock one", "dock two", "elsewhere"]
        .iter()
        .map(|body| Artifact {
            id: Uuid::new_v4(),
            case_id,
            parent_id: None,
            artifact_type: ArtifactType::ParsedRecord,
            metadata: json!({"type": "Doc", "body": body}),
            data: None,
        })
        .collect();
    db.record_artifacts_batch(&good).await?;
    drop(db);

    {
        let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path)).await?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&pool)
            .await?;
        drop(pool);
    }
    let mut bytes = std::fs::read(path.path())?;
    let needle = br#""body":"elsewhere""#;
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("the record's metadata_json is stored verbatim in the file");
    // `"body":"elsewhere"` -> ` body":"elsewhere"`: same length, same page
    // layout, same stored index key, no longer valid JSON.
    bytes[at] = b' ';
    std::fs::write(path.path(), &bytes)?;
    let db = SqliteConnection::new(&format!("sqlite:{}", path)).await?;

    let keys = vec!["body".to_string()];
    let mut q = query("Doc");
    q.search = Some(RecordTextFilter {
        needle: "dock",
        keys: &keys,
    });
    let page = db.list_records_filtered(case_id, &q).await?;

    assert_eq!(page.total, 2, "the two readable matches");
    assert_eq!(
        page.type_total, 3,
        "the corrupt row is still one of the type's records"
    );
    assert_eq!(
        page.unfilterable_metadata,
        Some(1),
        "the corrupt row could not be tested against the term, and the listing \
         must say so rather than letting it disappear from the count"
    );
    Ok(())
}

#[tokio::test]
async fn an_unfiltered_listing_does_not_claim_zero_unreadable_rows() -> Result<()> {
    let (db, case_id) = setup().await?;
    let page = db
        .list_records_filtered(case_id, &query("WhatsApp"))
        .await?;
    assert_eq!(
        page.unfilterable_metadata, None,
        "with no search term nothing was tested for readability; None is 'not \
         looked up', and reporting 0 would assert a check that never ran"
    );
    Ok(())
}

#[tokio::test]
async fn a_source_scoped_listing_searches_and_counts_within_the_scope() -> Result<()> {
    // The scoped statements carry a subtree CTE whose placeholders come BEFORE
    // the search term's in the count statement and AFTER the type's in the page
    // statement. Two statements, two bind orders, one fixture: a mistake in
    // either would show one population and count another.
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Scoped", "examiner").await?;

    let source = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::RawEvidence,
        metadata: json!({"name": "phone.tar"}),
        data: None,
    };
    db.record_artifact(&source).await?;

    let inside: Vec<Artifact> = ["dock alpha", "dock bravo", "elsewhere"]
        .iter()
        .map(|body| Artifact {
            id: Uuid::new_v4(),
            case_id,
            parent_id: Some(source.id),
            artifact_type: ArtifactType::ParsedRecord,
            metadata: json!({"type": "Doc", "body": body}),
            data: None,
        })
        .collect();
    db.record_artifacts_batch(&inside).await?;

    // Same type, same term, but outside the source's subtree.
    let outside = Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::ParsedRecord,
        metadata: json!({"type": "Doc", "body": "dock charlie"}),
        data: None,
    };
    db.record_artifact(&outside).await?;

    let keys = vec!["body".to_string()];
    let mut q = query("Doc");
    q.source_id = Some(source.id);
    q.search = Some(RecordTextFilter {
        needle: "dock",
        keys: &keys,
    });
    let page = db.list_records_filtered(case_id, &q).await?;

    assert_eq!(page.total, 2, "only the two inside the scope");
    assert_eq!(page.type_total, 3, "the scope holds three Doc records");
    assert_eq!(page.records.len(), 2);
    assert!(
        !bodies(&page.records).iter().any(|b| b == "dock charlie"),
        "a record outside the source subtree matched the term but is not in the \
         population the caller asked about"
    );
    Ok(())
}
