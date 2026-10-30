/// Search integration tests: index artifacts → query → verify results.
///
/// Tests the full Tantivy indexing and search pipeline:
/// 1. Creates a SearchService with a temp directory
/// 2. Indexes synthetic artifacts with known content
/// 3. Searches and verifies results match expectations
/// 4. Tests filtering, regex, and edge cases
use seance_core::artifact::{Artifact, ArtifactType};
use seance_search::{SearchOptions, SearchService};
use serde_json::json;
use uuid::Uuid;

/// Sanity test using raw Tantivy to confirm the library works
#[tokio::test]
async fn test_raw_tantivy_sanity() {
    use tantivy::{
        collector::TopDocs,
        doc,
        query::QueryParser,
        schema::{Schema, STORED, TEXT},
        Index,
    };
    let dir = temp_search_dir();

    let mut schema_builder = Schema::builder();
    let title = schema_builder.add_text_field("title", TEXT | STORED);
    let body = schema_builder.add_text_field("body", TEXT);
    let schema = schema_builder.build();

    let index = Index::create_in_dir(dir.path(), schema.clone()).unwrap();
    let mut writer = index.writer(15_000_000).unwrap();
    writer
        .add_document(doc!(title => "hello world", body => "test content"))
        .unwrap();
    writer.commit().unwrap();

    let reader = index.reader().unwrap();
    let searcher = reader.searcher();
    let query_parser = QueryParser::for_index(&index, vec![title, body]);
    let query = query_parser.parse_query("hello").unwrap();
    let top_docs = searcher
        .search(&query, &TopDocs::with_limit(10).order_by_score())
        .unwrap();

    eprintln!("Raw Tantivy: {} results", top_docs.len());
    assert_eq!(top_docs.len(), 1, "Raw Tantivy should find 1 result");
}

fn temp_search_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("Failed to create temp dir")
}

fn make_artifact(
    case_id: Uuid,
    artifact_type: ArtifactType,
    metadata: serde_json::Value,
) -> Artifact {
    Artifact::new(case_id, artifact_type, None, metadata)
}

// --- File-content indexing ---

#[tokio::test]
async fn indexes_file_content_for_keyword_search() {
    use seance_core::data_source::ByteSliceDataSource;
    use std::sync::Arc;

    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).expect("service");
    let case_id = Uuid::new_v4();

    // A file whose name reveals nothing, but whose bytes contain a keyword and
    // an ASCII string embedded in binary. Both must be searchable.
    let content = b"\x00\x01preamble the-secret-marker trailing\x00\xffZZembeddedZZ\x00".to_vec();
    let art = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(Arc::new(ByteSliceDataSource::new(content))),
        json!({ "name": "opaque.bin", "size": 40 }),
    );
    svc.add_artifact_to_index(&art).await.unwrap();
    svc.commit().await.unwrap();

    let by_content = svc.search(case_id, "the-secret-marker", 10).await.unwrap();
    assert!(!by_content.is_empty(), "content keyword must match");
    assert_eq!(by_content[0].artifact_id, art.id);

    let by_string = svc.search(case_id, "ZZembeddedZZ", 10).await.unwrap();
    assert!(!by_string.is_empty(), "embedded ASCII string must match");
}

// --- Threaded writer: high-volume indexing crosses the auto-commit boundary ---

/// The writer thread commits every 1000 docs. Indexing well past that boundary
/// and then committing must leave every document searchable (nothing lost at a
/// periodic commit). Guards the move of the writer into a dedicated thread.
#[tokio::test]
async fn indexes_many_docs_across_commit_boundary() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).expect("service");
    let case_id = Uuid::new_v4();

    // 2500 docs > 2x the 1000-doc auto-commit threshold.
    for i in 0..2500u32 {
        let art = make_artifact(
            case_id,
            ArtifactType::ParsedRecord,
            json!({ "name": format!("record_{i}"), "marker": "commonmarker" }),
        );
        svc.add_artifact_to_index(&art).await.unwrap();
    }
    svc.commit().await.unwrap();

    // All 2500 share the marker; ask for more than that and expect all back.
    let results = svc.search(case_id, "commonmarker", 5000).await.unwrap();
    assert_eq!(results.len(), 2500, "every indexed doc must be searchable");
}

// --- Batch delete: a recursive artifact delete purges the whole subtree ---

/// delete_artifacts removes many documents (a deleted subtree) in one commit, so
/// they don't linger as stale search hits.
#[tokio::test]
async fn delete_artifacts_removes_the_whole_set() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).expect("service");
    let case_id = Uuid::new_v4();

    let mut arts = Vec::new();
    for i in 0..3 {
        let art = make_artifact(
            case_id,
            ArtifactType::ParsedRecord,
            json!({ "name": format!("doc_{i}"), "marker": "sharedmarker" }),
        );
        svc.add_artifact_to_index(&art).await.unwrap();
        arts.push(art);
    }
    svc.commit().await.unwrap();
    assert_eq!(
        svc.search(case_id, "sharedmarker", 10).await.unwrap().len(),
        3,
        "all three indexed"
    );

    // Delete two of the three in one batch.
    svc.delete_artifacts(vec![arts[0].id, arts[1].id])
        .await
        .unwrap();

    let remaining = svc.search(case_id, "sharedmarker", 10).await.unwrap();
    assert_eq!(remaining.len(), 1, "only the undeleted doc remains");
    assert_eq!(remaining[0].artifact_id, arts[2].id);

    // Empty batch is a no-op (must not error or wipe anything).
    svc.delete_artifacts(vec![]).await.unwrap();
    assert_eq!(
        svc.search(case_id, "sharedmarker", 10).await.unwrap().len(),
        1,
    );
}

// --- Basic indexing and search ---

#[tokio::test]
async fn test_index_and_search_basic() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).expect("Failed to create SearchService");
    let case_id = Uuid::new_v4();

    let art = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({
            "name": "important_document.docx",
            "size": 4096,
            "path": "/Users/evidence/Documents/important_document.docx",
        }),
    );

    svc.add_artifact_to_index(&art).await.unwrap();
    svc.commit().await.unwrap();

    let results = svc.search(case_id, "important", 10).await.unwrap();
    assert!(!results.is_empty(), "Should find the indexed artifact");
    assert_eq!(results[0].artifact_id, art.id);
    assert_eq!(results[0].name, "important_document.docx");
}

#[tokio::test]
async fn test_search_by_metadata_content() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    let art = make_artifact(
        case_id,
        ArtifactType::ParsedRecord,
        json!({
            "name": "email_message",
            "subtype": "email_message",
            "from": "alice@example.com",
            "to": ["bob@example.com"],
            "subject": "Quarterly financial report Q3 2024",
            "body_text": "Please find attached the quarterly financial summary.",
        }),
    );

    svc.add_artifact_to_index(&art).await.unwrap();
    svc.commit().await.unwrap();

    // Search by email address in metadata
    let results = svc.search(case_id, "alice@example.com", 10).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].artifact_id, art.id);

    // Search by subject content
    let results = svc
        .search(case_id, "quarterly financial", 10)
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
}

#[tokio::test]
async fn test_search_no_results() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    let art = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({
            "name": "readme.txt",
            "size": 100,
        }),
    );

    svc.add_artifact_to_index(&art).await.unwrap();
    svc.commit().await.unwrap();

    let results = svc
        .search(case_id, "nonexistent_term_xyz", 10)
        .await
        .unwrap();
    assert!(results.is_empty());
}

#[tokio::test]
async fn test_search_empty_index() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    svc.commit().await.unwrap();

    let results = svc.search(case_id, "anything", 10).await.unwrap();
    assert!(results.is_empty());
}

// --- Case isolation ---

#[tokio::test]
async fn test_search_case_isolation() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_a = Uuid::new_v4();
    let case_b = Uuid::new_v4();

    let art_a = make_artifact(
        case_a,
        ArtifactType::FileEntry,
        json!({
            "name": "secret_file.txt",
            "content": "case A only",
        }),
    );
    let art_b = make_artifact(
        case_b,
        ArtifactType::FileEntry,
        json!({
            "name": "secret_file.txt",
            "content": "case B only",
        }),
    );

    svc.add_artifact_to_index(&art_a).await.unwrap();
    svc.add_artifact_to_index(&art_b).await.unwrap();
    svc.commit().await.unwrap();

    let results_a = svc.search(case_a, "secret_file", 10).await.unwrap();
    assert_eq!(results_a.len(), 1);
    assert_eq!(results_a[0].artifact_id, art_a.id);

    let results_b = svc.search(case_b, "secret_file", 10).await.unwrap();
    assert_eq!(results_b.len(), 1);
    assert_eq!(results_b[0].artifact_id, art_b.id);
}

// --- Artifact type filtering ---

#[tokio::test]
async fn test_search_artifact_type_filter() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    let file_entry = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({
            "name": "malware.exe",
            "size": 65536,
        }),
    );
    let timeline = make_artifact(
        case_id,
        ArtifactType::TimelineEvent,
        json!({
            "name": "malware execution",
            "timestamp": "2024-03-15T14:30:00Z",
            "short_desc": "malware.exe executed",
        }),
    );
    let parsed = make_artifact(
        case_id,
        ArtifactType::ParsedRecord,
        json!({
            "name": "registry_entry",
            "subtype": "registry_value",
            "key": "HKLM\\Software\\malware",
        }),
    );

    for art in [&file_entry, &timeline, &parsed] {
        svc.add_artifact_to_index(art).await.unwrap();
    }
    svc.commit().await.unwrap();

    // Search all types — should find all 3
    let results = svc.search(case_id, "malware", 10).await.unwrap();
    assert_eq!(results.len(), 3);

    // Filter to TimelineEvent only
    let response = svc
        .search_with_options(
            case_id,
            SearchOptions {
                query: "malware".to_string(),
                limit: 10,
                artifact_types: Some(vec!["TimelineEvent".to_string()]),
                use_regex: false,
                file_extensions: None,
                fuzzy: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(response.results.len(), 1);
    assert_eq!(response.results[0].artifact_type, "TimelineEvent");

    // Filter to FileEntry only
    let response = svc
        .search_with_options(
            case_id,
            SearchOptions {
                query: "malware".to_string(),
                limit: 10,
                artifact_types: Some(vec!["FileEntry".to_string()]),
                use_regex: false,
                file_extensions: None,
                fuzzy: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(response.results.len(), 1);
    assert_eq!(response.results[0].artifact_type, "FileEntry");
}

// --- Regex search ---

#[tokio::test]
async fn test_search_regex_mode() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    let art1 = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({
            "name": "report_2024_Q1.pdf",
        }),
    );
    let art2 = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({
            "name": "report_2024_Q2.pdf",
        }),
    );
    let art3 = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({
            "name": "invoice_2023.pdf",
        }),
    );

    for art in [&art1, &art2, &art3] {
        svc.add_artifact_to_index(art).await.unwrap();
    }
    svc.commit().await.unwrap();

    // Regex matching report_2024_Q[12]
    let response = svc
        .search_with_options(
            case_id,
            SearchOptions {
                query: "report_2024_Q[12]".to_string(),
                limit: 10,
                artifact_types: None,
                use_regex: true,
                file_extensions: None,
                fuzzy: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(
        response.results.len(),
        2,
        "Regex should match both Q1 and Q2 reports"
    );

    // Verify snippets carry highlight ranges into the snippet text
    for result in &response.results {
        assert!(
            result.snippet.is_some(),
            "Regex results should have snippets"
        );
        let snippet = result.snippet.as_ref().unwrap();
        assert!(
            !result.highlights.is_empty(),
            "Result should have highlight ranges"
        );
        for &(start, end) in &result.highlights {
            assert!(
                snippet.get(start..end).is_some(),
                "Highlight range must index into the snippet"
            );
        }
    }
}

// --- File extension filtering ---

#[tokio::test]
async fn test_search_file_extension_filter() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    let pdf = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({
            "name": "document.pdf",
        }),
    );
    let docx = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({
            "name": "document.docx",
        }),
    );
    let txt = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({
            "name": "document.txt",
        }),
    );

    for art in [&pdf, &docx, &txt] {
        svc.add_artifact_to_index(art).await.unwrap();
    }
    svc.commit().await.unwrap();

    // Filter to .pdf only
    let response = svc
        .search_with_options(
            case_id,
            SearchOptions {
                query: "document".to_string(),
                limit: 10,
                artifact_types: None,
                use_regex: false,
                file_extensions: Some(vec!["pdf".to_string()]),
                fuzzy: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(response.results.len(), 1);
    assert_eq!(response.results[0].name, "document.pdf");

    // Filter to multiple extensions
    let response = svc
        .search_with_options(
            case_id,
            SearchOptions {
                query: "document".to_string(),
                limit: 10,
                artifact_types: None,
                use_regex: false,
                file_extensions: Some(vec!["pdf".to_string(), "txt".to_string()]),
                fuzzy: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(response.results.len(), 2);
}

// --- Limit and pagination ---

#[tokio::test]
async fn test_search_respects_limit() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    // Index 20 artifacts with "testfile" in the name
    for i in 0..20 {
        let art = make_artifact(
            case_id,
            ArtifactType::FileEntry,
            json!({
                "name": format!("testfile_{:03}.dat", i),
            }),
        );
        svc.add_artifact_to_index(&art).await.unwrap();
    }
    svc.commit().await.unwrap();

    let results = svc.search(case_id, "testfile", 5).await.unwrap();
    assert_eq!(results.len(), 5, "Should respect limit of 5");
}

// --- Delete case ---

#[tokio::test]
async fn test_delete_case() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    for i in 0..5 {
        let art = make_artifact(
            case_id,
            ArtifactType::FileEntry,
            json!({
                "name": format!("evidence_{}.bin", i),
            }),
        );
        svc.add_artifact_to_index(&art).await.unwrap();
    }
    svc.commit().await.unwrap();

    let results = svc.search(case_id, "evidence", 10).await.unwrap();
    assert_eq!(results.len(), 5);

    svc.delete_case(case_id).await.unwrap();

    let results = svc.search(case_id, "evidence", 10).await.unwrap();
    assert!(
        results.is_empty(),
        "All documents should be deleted after delete_case"
    );
}

// --- SearchResponse metadata ---

#[tokio::test]
async fn test_search_response_metadata() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    let art = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({
            "name": "metadata_test.log",
        }),
    );
    svc.add_artifact_to_index(&art).await.unwrap();
    svc.commit().await.unwrap();

    let response = svc
        .search_with_options(
            case_id,
            SearchOptions {
                query: "metadata_test".to_string(),
                limit: 10,
                artifact_types: None,
                use_regex: false,
                file_extensions: None,
                fuzzy: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(response.query, "metadata_test");
    assert_eq!(response.total_count, 1);
    assert!(response.elapsed_ms < 5000, "Search should complete quickly");
}

/// A structured (non-substring) query whose match count exceeds `limit` must
/// report `truncated`, with or without an extension post-filter.
///
/// What an examiner learns: whether the rows on screen are every match in the
/// evidence or only the first page. A wrong answer here reads as "this term
/// appears exactly N times" when it appears many more — the basis for an
/// absence conclusion that the evidence does not support.
#[tokio::test]
async fn test_fulltext_search_flags_truncation_without_extension_filter() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    for i in 0..12 {
        let art = make_artifact(
            case_id,
            ArtifactType::FileEntry,
            json!({ "name": format!("capped_hit_{i}.log") }),
        );
        svc.add_artifact_to_index(&art).await.unwrap();
    }
    svc.commit().await.unwrap();

    // `OR` keeps the query off the plain-substring path and on the tokenized
    // full-text path, which is where the cap was reported as completeness.
    let opts = |limit: usize, exts: Option<Vec<String>>| SearchOptions {
        query: "capped OR absent_term".to_string(),
        limit,
        artifact_types: None,
        use_regex: false,
        file_extensions: exts,
        fuzzy: None,
    };

    let capped = svc
        .search_with_options(case_id, opts(5, None))
        .await
        .unwrap();
    assert_eq!(capped.results.len(), 5, "limit must be honoured");
    assert!(
        capped.truncated,
        "5 of 12 matches returned must be reported as truncated"
    );

    // The whole match set fits: complete, and must not claim otherwise.
    let complete = svc
        .search_with_options(case_id, opts(50, None))
        .await
        .unwrap();
    assert_eq!(complete.results.len(), 12);
    assert!(
        !complete.truncated,
        "a result set containing every match must not be flagged truncated"
    );

    // Extension post-filter path keeps its own capped-window signal.
    let filtered = svc
        .search_with_options(case_id, opts(50, Some(vec!["log".to_string()])))
        .await
        .unwrap();
    assert_eq!(filtered.results.len(), 12);
    assert!(!filtered.truncated);
}

/// `total_count` is prevalence, not page size.
///
/// What an examiner learns: how often a keyword occurs in the evidence. The
/// triage flow asks for one row per term and prints this number, so a
/// `total_count` that echoed `results.len()` would report every term in the
/// case as a single hit, and a triage note built on it would understate the
/// evidence by orders of magnitude.
#[tokio::test]
async fn test_total_count_is_match_count_not_page_size() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    for i in 0..12 {
        let art = make_artifact(
            case_id,
            ArtifactType::FileEntry,
            json!({ "name": format!("prevalent_hit_{i}.log") }),
        );
        svc.add_artifact_to_index(&art).await.unwrap();
    }
    svc.commit().await.unwrap();

    let triage = |query: &str, use_regex: bool| SearchOptions {
        query: query.to_string(),
        // What the keyword-triage flow sends.
        limit: 1,
        artifact_types: None,
        use_regex,
        file_extensions: None,
        fuzzy: None,
    };

    // Default (plain keyword) route: the substring scan.
    let substring = svc
        .search_with_options(case_id, triage("prevalent", false))
        .await
        .unwrap();
    assert_eq!(substring.results.len(), 1, "limit must be honoured");
    assert_eq!(
        substring.total_count, 12,
        "substring scan must count all 12"
    );
    assert!(!substring.count_is_lower_bound);
    assert!(substring.truncated);

    // Structured query route: the tokenized full-text search.
    let fulltext = svc
        .search_with_options(case_id, triage("prevalent OR absent_term", false))
        .await
        .unwrap();
    assert_eq!(fulltext.results.len(), 1);
    assert_eq!(
        fulltext.total_count, 12,
        "full-text must report Count, not 1"
    );
    assert!(!fulltext.count_is_lower_bound);
    assert!(fulltext.truncated);

    // Regex route.
    let regex = svc
        .search_with_options(case_id, triage("prevalent_hit_[0-9]", true))
        .await
        .unwrap();
    assert_eq!(regex.results.len(), 1);
    assert_eq!(regex.total_count, 12, "regex scan must count all 12");
    assert!(!regex.count_is_lower_bound);
    assert!(regex.truncated);
}

/// On the full-text path the exact count is taken before the extension
/// post-filter, so once the candidate window fills, the filtered figure is a
/// floor. It must be published as one.
#[tokio::test]
async fn test_extension_post_filter_over_capped_window_marks_lower_bound() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    for i in 0..12 {
        let art = make_artifact(
            case_id,
            ArtifactType::FileEntry,
            json!({ "name": format!("windowed_hit_{i}.log") }),
        );
        svc.add_artifact_to_index(&art).await.unwrap();
    }
    svc.commit().await.unwrap();

    // limit 1 => a 5-document candidate window, which 12 matches exhaust.
    let response = svc
        .search_with_options(
            case_id,
            SearchOptions {
                query: "windowed OR absent_term".to_string(),
                limit: 1,
                artifact_types: None,
                use_regex: false,
                file_extensions: Some(vec!["log".to_string()]),
                fuzzy: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(response.results.len(), 1);
    assert!(
        response.count_is_lower_bound,
        "matches past the candidate window were never filtered or counted"
    );
    assert!(
        response.total_count <= 12 && response.total_count >= 1,
        "the count must be a floor of the real 12, got {}",
        response.total_count
    );
    assert!(response.truncated);
}

// --- Snippet highlighting ---

#[tokio::test]
async fn test_search_snippets() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    let art = make_artifact(
        case_id,
        ArtifactType::ParsedRecord,
        json!({
            "name": "browser_history",
            "subtype": "browser_history",
            "url": "https://suspicious-domain.com/malware/payload",
            "title": "Download page for suspicious payload executable",
        }),
    );
    svc.add_artifact_to_index(&art).await.unwrap();
    svc.commit().await.unwrap();

    let results = svc.search(case_id, "suspicious", 10).await.unwrap();
    assert_eq!(results.len(), 1);

    // Full-text search should produce snippets
    let snippet = results[0]
        .snippet
        .as_ref()
        .expect("a full-text hit must carry a snippet");
    assert!(
        snippet.contains("suspicious"),
        "Snippet should contain the search term: {snippet}"
    );
    let &(start, end) = results[0]
        .highlights
        .first()
        .expect("a full-text hit must carry a highlight");
    assert!(
        snippet[start..end].eq_ignore_ascii_case("suspicious"),
        "the first highlight must slice out the term: {:?}",
        &snippet[start..end]
    );
}

// --- An added document is invisible until it is committed ---

#[tokio::test]
async fn test_an_added_document_is_not_visible_until_committed() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    // Add a single artifact (an enqueue, which does not commit)
    let art = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({
            "name": "autocommit_test.bin",
        }),
    );
    svc.add_artifact_to_index(&art).await.unwrap();

    // Not yet committed — search should find nothing
    let results = svc.search(case_id, "autocommit_test", 10).await.unwrap();
    assert!(
        results.is_empty(),
        "Uncommitted documents should not be visible"
    );

    // Manually commit
    svc.commit().await.unwrap();

    let results = svc.search(case_id, "autocommit_test", 10).await.unwrap();
    assert_eq!(results.len(), 1, "Should find document after manual commit");
}

// --- Indexer module: no lost documents (H13a) ---

#[tokio::test]
async fn test_indexer_process_then_commit_loses_nothing() {
    use seance_core::module::ForensicsModule;
    use seance_search::SearchIndexer;
    use std::sync::Arc;

    let dir = temp_search_dir();
    let svc = Arc::new(SearchService::new(dir.path()).unwrap());
    let indexer = SearchIndexer::new(svc.clone());
    let case_id = Uuid::new_v4();

    // Index via the module interface, exactly as the orchestrator does
    for i in 0..10 {
        let art = make_artifact(
            case_id,
            ArtifactType::FileEntry,
            json!({
                "name": format!("ingest_tail_{}.bin", i),
            }),
        );
        indexer.process(&art).expect("process should succeed");
    }

    // Commit immediately after the last process() returns. Every document
    // handed to process() must be visible after this commit.
    svc.commit().await.unwrap();

    let results = svc.search(case_id, "ingest_tail", 20).await.unwrap();
    assert_eq!(
        results.len(),
        10,
        "No documents may be lost between process() and commit()"
    );
}

// --- Index recovery must not destroy data on unrelated errors (H13b) ---

#[tokio::test]
async fn test_new_propagates_corruption_instead_of_wiping() {
    let dir = temp_search_dir();

    // Simulate index corruption: meta.json exists but is garbage
    let meta_path = dir.path().join("meta.json");
    std::fs::write(&meta_path, b"this is not valid json {{{").unwrap();

    let result = SearchService::new(dir.path());
    assert!(
        result.is_err(),
        "Corrupted index must be a hard error, not a silent wipe"
    );

    // The directory contents must be untouched
    let meta = std::fs::read(&meta_path).expect("meta.json must still exist after failed open");
    assert_eq!(meta, b"this is not valid json {{{");
}

#[tokio::test]
async fn test_new_recovers_from_schema_mismatch() {
    use tantivy::{
        schema::{Schema, STORED, TEXT},
        Index,
    };

    let dir = temp_search_dir();

    // Create an index with an incompatible schema
    let mut schema_builder = Schema::builder();
    schema_builder.add_text_field("totally_different_field", TEXT | STORED);
    let old_schema = schema_builder.build();
    Index::create_in_dir(dir.path(), old_schema).unwrap();

    // SearchService::new should detect the schema mismatch and rebuild
    let svc = SearchService::new(dir.path()).expect("Schema mismatch should auto-recover");

    let case_id = Uuid::new_v4();
    let art = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({"name": "rebuilt.txt"}),
    );
    svc.add_artifact_to_index(&art).await.unwrap();
    svc.commit().await.unwrap();
    let results = svc.search(case_id, "rebuilt", 10).await.unwrap();
    assert_eq!(results.len(), 1);
}

// --- delete_artifact ---

#[tokio::test]
async fn test_delete_artifact() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    let keep = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({"name": "evidence_keep.bin"}),
    );
    let remove = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({"name": "evidence_remove.bin"}),
    );
    svc.add_artifact_to_index(&keep).await.unwrap();
    svc.add_artifact_to_index(&remove).await.unwrap();
    svc.commit().await.unwrap();

    let results = svc.search(case_id, "evidence", 10).await.unwrap();
    assert_eq!(results.len(), 2);

    svc.delete_artifact(remove.id).await.unwrap();

    let results = svc.search(case_id, "evidence", 10).await.unwrap();
    assert_eq!(results.len(), 1, "Deleted artifact must stop matching");
    assert_eq!(results[0].artifact_id, keep.id);
}

// --- rebuild_index ---

#[tokio::test]
async fn test_rebuild_index_empties_index() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    for i in 0..3 {
        let art = make_artifact(
            case_id,
            ArtifactType::FileEntry,
            json!({
                "name": format!("wipeme_{}.dat", i),
            }),
        );
        svc.add_artifact_to_index(&art).await.unwrap();
    }
    svc.commit().await.unwrap();
    assert_eq!(svc.search(case_id, "wipeme", 10).await.unwrap().len(), 3);

    svc.rebuild_index().await.unwrap();

    assert!(svc.search(case_id, "wipeme", 10).await.unwrap().is_empty());

    // Index must remain usable after rebuild
    let art = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({"name": "after_rebuild.dat"}),
    );
    svc.add_artifact_to_index(&art).await.unwrap();
    svc.commit().await.unwrap();
    assert_eq!(
        svc.search(case_id, "after_rebuild", 10)
            .await
            .unwrap()
            .len(),
        1
    );
}

// --- truncated flag ---

#[tokio::test]
async fn test_truncated_flag_default_false() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    let art = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        json!({"name": "plain.txt"}),
    );
    svc.add_artifact_to_index(&art).await.unwrap();
    svc.commit().await.unwrap();

    let response = svc
        .search_with_options(
            case_id,
            SearchOptions {
                query: "plain".to_string(),
                limit: 10,
                artifact_types: None,
                use_regex: false,
                file_extensions: None,
                fuzzy: None,
            },
        )
        .await
        .unwrap();
    assert!(!response.truncated);
    assert_eq!(response.total_count, response.results.len());
}

#[tokio::test]
async fn test_extension_filter_sets_truncated_when_over_limit() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    // 30 matching .pdf files, limit 5: post-filter yields more than limit
    for i in 0..30 {
        let art = make_artifact(
            case_id,
            ArtifactType::FileEntry,
            json!({
                "name": format!("document_{:03}.pdf", i),
            }),
        );
        svc.add_artifact_to_index(&art).await.unwrap();
    }
    svc.commit().await.unwrap();

    let response = svc
        .search_with_options(
            case_id,
            SearchOptions {
                query: "document".to_string(),
                limit: 5,
                artifact_types: None,
                use_regex: false,
                file_extensions: Some(vec!["pdf".to_string()]),
                fuzzy: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(response.results.len(), 5, "Must respect limit");
    assert_eq!(
        response.total_count, 30,
        "total_count is how many artifacts match, not how many rows came back"
    );
    assert!(
        !response.count_is_lower_bound,
        "the scan covered the whole case, so the count is exact"
    );
    assert!(
        response.truncated,
        "Must flag incompleteness when post-filter exceeds limit"
    );

    // Same query with a generous limit: everything fits, not truncated
    let response = svc
        .search_with_options(
            case_id,
            SearchOptions {
                query: "document".to_string(),
                limit: 100,
                artifact_types: None,
                use_regex: false,
                file_extensions: Some(vec!["pdf".to_string()]),
                fuzzy: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(response.results.len(), 30);
    assert!(!response.truncated);
}

#[tokio::test]
async fn test_regex_search_sets_truncated_when_over_limit() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    for i in 0..10 {
        let art = make_artifact(
            case_id,
            ArtifactType::FileEntry,
            json!({
                "name": format!("regex_target_{}.log", i),
            }),
        );
        svc.add_artifact_to_index(&art).await.unwrap();
    }
    svc.commit().await.unwrap();

    // Limit below the match count: truncated
    let response = svc
        .search_with_options(
            case_id,
            SearchOptions {
                query: "regex_target_[0-9]".to_string(),
                limit: 3,
                artifact_types: None,
                use_regex: true,
                file_extensions: None,
                fuzzy: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(response.results.len(), 3);
    assert!(
        response.truncated,
        "Regex search must flag results beyond the limit"
    );

    // Limit above the match count: complete
    let response = svc
        .search_with_options(
            case_id,
            SearchOptions {
                query: "regex_target_[0-9]".to_string(),
                limit: 50,
                artifact_types: None,
                use_regex: true,
                file_extensions: None,
                fuzzy: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(response.results.len(), 10);
    assert!(!response.truncated);
}

#[tokio::test]
async fn test_regex_search_with_extension_filter_truncated() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    for i in 0..8 {
        let art = make_artifact(
            case_id,
            ArtifactType::FileEntry,
            json!({
                "name": format!("mixed_{}.pdf", i),
            }),
        );
        svc.add_artifact_to_index(&art).await.unwrap();
    }
    for i in 0..8 {
        let art = make_artifact(
            case_id,
            ArtifactType::FileEntry,
            json!({
                "name": format!("mixed_{}.txt", i),
            }),
        );
        svc.add_artifact_to_index(&art).await.unwrap();
    }
    svc.commit().await.unwrap();

    // Extension filter applies before the limit is counted
    let response = svc
        .search_with_options(
            case_id,
            SearchOptions {
                query: "mixed_[0-9]".to_string(),
                limit: 20,
                artifact_types: None,
                use_regex: true,
                file_extensions: Some(vec!["pdf".to_string()]),
                fuzzy: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        response.results.len(),
        8,
        "All 8 pdf matches should be returned"
    );
    assert!(!response.truncated);
    for r in &response.results {
        assert!(r.name.ends_with(".pdf"));
    }
}

// --- Multiple artifact types indexed ---

#[tokio::test]
async fn test_index_multiple_artifact_types() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    let types_and_meta = vec![
        (
            ArtifactType::FileEntry,
            json!({"name": "system32.dll", "path": "C:\\Windows\\System32"}),
        ),
        (
            ArtifactType::SystemArtifact,
            json!({"name": "SAM", "subtype": "registry_hive"}),
        ),
        (
            ArtifactType::ParsedRecord,
            json!({"name": "user_account", "subtype": "sam_user", "username": "Administrator"}),
        ),
        (
            ArtifactType::TimelineEvent,
            json!({"name": "login_event", "timestamp": "2024-06-01T08:00:00Z", "short_desc": "Administrator login"}),
        ),
        (
            ArtifactType::RawEvidence,
            json!({"name": "disk_image.E01", "size": 1073741824}),
        ),
    ];

    for (atype, meta) in &types_and_meta {
        let art = make_artifact(case_id, atype.clone(), meta.clone());
        svc.add_artifact_to_index(&art).await.unwrap();
    }
    svc.commit().await.unwrap();

    // Search for Administrator should find ParsedRecord and TimelineEvent
    let results = svc.search(case_id, "Administrator", 10).await.unwrap();
    assert!(
        results.len() >= 2,
        "Should find Administrator in multiple artifacts"
    );
}

// --- Fuzzy, boolean, and proximity (QueryParser features) ---

#[tokio::test]
async fn test_fuzzy_boolean_and_proximity() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    let art = make_artifact(
        case_id,
        ArtifactType::FileEntry,
        serde_json::json!({ "name": "forensics report about malware analysis" }),
    );
    svc.add_artifact_to_index(&art).await.unwrap();
    svc.commit().await.unwrap();

    let opts = |q: &str, fuzzy: Option<u8>| SearchOptions {
        query: q.to_string(),
        limit: 10,
        artifact_types: None,
        use_regex: false,
        file_extensions: None,
        fuzzy,
    };

    // A typo does not match with exact term search...
    let r = svc
        .search_with_options(case_id, opts("forensik", None))
        .await
        .unwrap();
    assert_eq!(r.results.len(), 0, "typo must not match without fuzzy");

    // ...but does with fuzzy (edit distance 2: 'k'->'c' + insert 's').
    let r = svc
        .search_with_options(case_id, opts("forensik", Some(2)))
        .await
        .unwrap();
    assert_eq!(
        r.results.len(),
        1,
        "fuzzy should match forensik -> forensics"
    );

    // Boolean AND: both terms present.
    let r = svc
        .search_with_options(case_id, opts("forensics AND malware", None))
        .await
        .unwrap();
    assert_eq!(r.results.len(), 1);

    // Boolean NOT: excludes the doc.
    let r = svc
        .search_with_options(case_id, opts("malware AND NOT forensics", None))
        .await
        .unwrap();
    assert_eq!(r.results.len(), 0);

    // Phrase proximity/slop: "report analysis" are 3 tokens apart.
    let r = svc
        .search_with_options(case_id, opts("\"report analysis\"~3", None))
        .await
        .unwrap();
    assert_eq!(r.results.len(), 1, "phrase slop should match nearby words");
}

// --- Substring (grep-like) keyword matching ---

/// A plain keyword search matches substrings, so a shorter query is a superset
/// of a longer one: searching "feel" finds every record "feeling" finds. This is
/// the exact inconsistency reported against 2.db.
#[tokio::test]
async fn plain_keyword_matches_substrings_feel_is_superset_of_feeling() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    // Two records contain "feeling"; one more contains "unfeeling" (the term in
    // the middle of a word); an unrelated record must never match.
    for (i, body) in [
        "I have a strange feeling about this",
        "that feeling again",
        "an unfeeling response",
        "completely unrelated text",
    ]
    .iter()
    .enumerate()
    {
        let art = make_artifact(
            case_id,
            ArtifactType::ParsedRecord,
            json!({ "name": format!("msg_{i}"), "text": body }),
        );
        svc.add_artifact_to_index(&art).await.unwrap();
    }
    svc.commit().await.unwrap();

    // "feeling" matches the two records that contain the whole word plus the one
    // containing "unfeeling".
    let feeling = svc.search(case_id, "feeling", 10).await.unwrap();
    assert_eq!(
        feeling.len(),
        3,
        "feeling matches 'feeling' and 'unfeeling'"
    );

    // "feel" must be a superset: same three, since each contains "feel".
    let feel = svc.search(case_id, "feel", 10).await.unwrap();
    assert_eq!(feel.len(), 3, "feel is a superset of feeling");

    let feeling_ids: std::collections::HashSet<_> = feeling.iter().map(|r| r.artifact_id).collect();
    let feel_ids: std::collections::HashSet<_> = feel.iter().map(|r| r.artifact_id).collect();
    assert!(
        feeling_ids.is_subset(&feel_ids),
        "every 'feeling' hit must also be a 'feel' hit",
    );
}

/// Multiple plain words are an AND of substrings: each word must appear
/// somewhere in the record (name or content), not necessarily adjacent.
#[tokio::test]
async fn plain_multiword_query_is_and_of_substrings() {
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    let both = make_artifact(
        case_id,
        ArtifactType::ParsedRecord,
        json!({ "name": "a", "text": "I feel really good today" }),
    );
    let only_feel = make_artifact(
        case_id,
        ArtifactType::ParsedRecord,
        json!({ "name": "b", "text": "I feel tired" }),
    );
    svc.add_artifact_to_index(&both).await.unwrap();
    svc.add_artifact_to_index(&only_feel).await.unwrap();
    svc.commit().await.unwrap();

    let r = svc.search(case_id, "feel good", 10).await.unwrap();
    assert_eq!(r.len(), 1, "only the record with both words matches");
    assert_eq!(r[0].artifact_id, both.id);
}

// --- per-case display-name repair ---

/// A FileEntry whose keyword lives ONLY in its bytes, never in its metadata.
fn body_keyword_artifact(case_id: Uuid, name: &str, body: &str) -> Artifact {
    Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(std::sync::Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(body.as_bytes().to_vec()),
        )),
        json!({ "name": name, "path": format!("/evidence/{}", name) }),
    )
}

#[tokio::test]
async fn reindexing_a_case_keeps_file_body_text_searchable() {
    // The repair walks the documents already in the index. Rebuilding from the
    // database instead would look equivalent and is not: DB-loaded artifacts
    // carry no data source, so every keyword that exists only inside a file's
    // bytes would stop matching and read to an examiner as "not in evidence".
    // This is the test that fails if anyone reaches for that variant.
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let case_id = Uuid::new_v4();

    let art = body_keyword_artifact(
        case_id,
        "notes.txt",
        "ransom note: zebracrossing at midnight",
    );
    svc.add_artifact_to_index(&art).await.unwrap();
    svc.commit().await.unwrap();
    assert_eq!(
        svc.search(case_id, "zebracrossing", 10)
            .await
            .unwrap()
            .len(),
        1
    );

    let outcome = svc.refresh_case_display_names(case_id).await.unwrap();
    assert_eq!(
        outcome.documents, 1,
        "the repair must have visited the case's document"
    );

    let after = svc.search(case_id, "zebracrossing", 10).await.unwrap();
    assert_eq!(
        after.len(),
        1,
        "a body-only keyword must still match after a reindex"
    );
    assert_eq!(after[0].artifact_id, art.id);
    assert_eq!(after[0].name, "notes.txt");
}

#[tokio::test]
async fn reindexing_one_case_leaves_another_cases_documents_alone() {
    // `rebuild_index` sends DeleteAll, which is global across every case and
    // re-adds nothing. Routing it as a per-case reindex would empty the search
    // index for every other case on the server. This pins the scope.
    let dir = temp_search_dir();
    let svc = SearchService::new(dir.path()).unwrap();
    let target = Uuid::new_v4();
    let bystander = Uuid::new_v4();

    for (case_id, name) in [
        (target, "target_evidence.dat"),
        (bystander, "bystander_evidence.dat"),
    ] {
        let art = make_artifact(case_id, ArtifactType::FileEntry, json!({ "name": name }));
        svc.add_artifact_to_index(&art).await.unwrap();
    }
    svc.commit().await.unwrap();

    let outcome = svc.refresh_case_display_names(target).await.unwrap();
    assert_eq!(
        outcome.documents, 1,
        "the repair must see only the case it was asked about"
    );

    assert_eq!(
        svc.search(bystander, "bystander_evidence", 10)
            .await
            .unwrap()
            .len(),
        1,
        "reindexing one case must not touch another case's documents"
    );
    assert_eq!(
        svc.search(target, "target_evidence", 10)
            .await
            .unwrap()
            .len(),
        1,
        "and must leave the reindexed case searchable"
    );
}
