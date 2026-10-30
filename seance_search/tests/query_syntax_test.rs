//! A plain string an examiner would type must not answer with an error.
//!
//! Found by running NIST CFTT's Forensic String Search methodology
//! (`ROADMAP` §5.2) against `ss-win-07-25-18.dd`. One of the published target
//! strings is `(901)555-1111` — a phone number in the form anybody would type
//! — and searching for it produced:
//!
//! ```text
//! ERROR seance_api: Search failed: Failed to parse search query: '(901)555-1111'
//! ERROR seance_api: Internal server error [7ac1c748…]
//! ```
//!
//! Tantivy's query syntax claims `(`, `)`, `:`, `+`, `-`, `[`, `]`, `^`, `"`,
//! `~` and `*`, so the parentheses made the query a syntax error and the API
//! returned a 500. A forensic search must not answer a plain string with an
//! internal server error — and must not silently reinterpret one either, since
//! an examiner whose structured query was quietly changed would be reading the
//! answer to a different question. So the query is retried literally and the
//! response says it was.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_search::{SearchOptions, SearchService};
use serde_json::json;
use uuid::Uuid;

/// An index holding one document per awkward string.
fn seeded() -> (tempfile::TempDir, SearchService, Uuid) {
    let dir = tempfile::tempdir().expect("temp dir");
    let svc = SearchService::new(dir.path()).expect("search service");
    let case_id = Uuid::new_v4();
    for (i, content) in [
        // The CFTT target that caused the 500.
        "call (901)555-1111 for details",
        "ssn 987-65-4321 on file",
        "mail berlin@deutchland.net today",
        "a plain sentence about a kestrel",
    ]
    .iter()
    .enumerate()
    {
        let art = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            json!({ "name": format!("doc_{i}.txt"), "content": content }),
        );
        svc.add_artifact_to_index_sync(&art).expect("index");
    }
    svc.commit_sync().expect("commit");
    (dir, svc, case_id)
}

fn opts(query: &str) -> SearchOptions {
    SearchOptions {
        query: query.to_string(),
        limit: 50,
        artifact_types: None,
        use_regex: false,
        file_extensions: None,
        fuzzy: None,
    }
}

/// **The query that used to return a 500.**
#[tokio::test]
async fn a_phone_number_in_parentheses_is_searched_rather_than_refused() {
    let (_dir, svc, case_id) = seeded();
    let response = svc
        .search_page(case_id, opts("(901)555-1111"), 0)
        .await
        .expect("a plain string must not answer with an error");
    assert!(
        response.total_count >= 1,
        "the document holding it should match: {response:?}"
    );
    // And the response says the query was not read as syntax, so nobody reads
    // the answer as an answer to a structured query.
    let said = response
        .query_taken_literally
        .as_deref()
        .expect("the reinterpretation is stated, not silent");
    assert!(
        said.contains("LITERALLY") && said.contains("query syntax"),
        "got {said}"
    );
}

/// Every character tantivy claims as syntax, in the shapes evidence carries
/// them. None may produce an error.
#[tokio::test]
async fn a_query_of_punctuation_an_examiner_would_type_never_errors() {
    let (_dir, svc, case_id) = seeded();
    for query in [
        "(901)555-1111",
        "987-65-4321",
        "berlin@deutchland.net",
        "C:\\Windows\\System32",
        "a:b",
        "[bracketed]",
        "half\"quoted",
        "trailing~",
        "plus+minus-",
        "^caret",
        "star*",
    ] {
        let result = svc.search_page(case_id, opts(query), 0).await;
        assert!(
            result.is_ok(),
            "{query:?} produced an error rather than a result: {:?}",
            result.err()
        );
    }
}

/// **A query that DOES parse is not reinterpreted**, and says nothing about
/// having been. Otherwise the field would appear on every response and mean
/// nothing.
#[tokio::test]
async fn a_well_formed_query_is_not_reported_as_taken_literally() {
    let (_dir, svc, case_id) = seeded();
    for query in ["kestrel", "kestrel sentence", "\"a plain sentence\""] {
        let response = svc
            .search_page(case_id, opts(query), 0)
            .await
            .expect("search");
        assert!(
            response.query_taken_literally.is_none(),
            "{query:?} parses as a structured query and must not be reported as literal: {:?}",
            response.query_taken_literally
        );
    }
}

/// The literal retry finds the text, not a neighbouring document: taking a
/// query literally must not widen it.
#[tokio::test]
async fn taking_a_query_literally_does_not_widen_it() {
    let (_dir, svc, case_id) = seeded();
    let response = svc
        .search_page(case_id, opts("(901)555-1111"), 0)
        .await
        .expect("search");
    // One document holds that number; the other three do not.
    assert_eq!(
        response.total_count,
        1,
        "a literal search for one document's text must not match the others: {:?}",
        response
            .results
            .iter()
            .map(|r| r.name.clone())
            .collect::<Vec<_>>()
    );
}
