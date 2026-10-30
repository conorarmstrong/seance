//! The review ledger, as a fact about the CASE rather than about a browser.
//!
//! The ledger used to live in browser-local storage, which meant the answer to
//! "what has anybody looked at?" was scoped to one person on one machine. The
//! handover scenario — examiner B inherits examiner A's case — is the whole
//! reason the ledger exists, and B saw an empty one.
//!
//! These tests pin the three claims the ledger makes, because each of them is a
//! claim an examiner could be cross-examined on:
//!
//!   * OPENED and REVIEWED are separate assertions. Scrolling past a row is not
//!     examining it, and no arithmetic here may turn one into the other.
//!   * `opened_at` is the FIRST opening and is never rewritten. Marking a row
//!     reviewed records the opening at the instant it happened rather than
//!     inventing an earlier one.
//!   * Withdrawing a review leaves the opening standing AND leaves a record that
//!     the review was made and retracted. An erased review and a review that was
//!     never made must not read alike.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::{ReviewIdState, ReviewMark, SqliteConnection};
use serde_json::json;
use uuid::Uuid;

async fn setup() -> Result<(SqliteConnection, Uuid, Vec<Uuid>)> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Handover", "alice").await?;

    let artifacts: Vec<Artifact> = (0..5)
        .map(|i| Artifact {
            id: Uuid::new_v4(),
            case_id,
            parent_id: None,
            artifact_type: ArtifactType::FileEntry,
            metadata: json!({"name": format!("file{i}.txt")}),
            data: None,
        })
        .collect();
    let ids: Vec<Uuid> = artifacts.iter().map(|a| a.id).collect();
    db.record_artifacts_batch(&artifacts).await?;
    Ok((db, case_id, ids))
}

#[tokio::test]
async fn an_opening_is_not_a_review() -> Result<()> {
    let (db, case_id, ids) = setup().await?;

    db.record_artifact_reviews_at(
        case_id,
        "alice",
        &[(ids[0], ReviewMark::Opened), (ids[1], ReviewMark::Opened)],
        1_000,
    )
    .await?;

    let opened = db
        .artifact_review_ids(case_id, ReviewIdState::Opened, None, 100)
        .await?;
    assert_eq!(opened.total, 2, "two artifacts were opened");

    let reviewed = db
        .artifact_review_ids(case_id, ReviewIdState::Reviewed, None, 100)
        .await?;
    assert_eq!(
        reviewed.total, 0,
        "opening a row must never register as having reviewed it"
    );
    assert!(
        reviewed.ids.is_empty(),
        "the reviewed id list must be empty, not merely counted as zero"
    );
    Ok(())
}

#[tokio::test]
async fn marking_reviewed_records_the_opening_at_the_instant_it_happened() -> Result<()> {
    let (db, case_id, ids) = setup().await?;

    // No prior opening: the artifact goes straight from unseen to reviewed.
    db.record_artifact_reviews_at(case_id, "alice", &[(ids[0], ReviewMark::Reviewed)], 5_000)
        .await?;

    let row = db
        .get_artifact_review(case_id, ids[0], "alice")
        .await?
        .expect("a review row");
    assert_eq!(
        row.opened_at, 5_000,
        "the opening must be stamped when it happened, not backdated"
    );
    assert_eq!(row.reviewed_at, Some(5_000));
    Ok(())
}

#[tokio::test]
async fn a_second_opening_never_rewrites_the_first() -> Result<()> {
    let (db, case_id, ids) = setup().await?;

    db.record_artifact_reviews_at(case_id, "alice", &[(ids[0], ReviewMark::Opened)], 1_000)
        .await?;
    let again = db
        .record_artifact_reviews_at(case_id, "alice", &[(ids[0], ReviewMark::Opened)], 9_000)
        .await?;

    let row = db
        .get_artifact_review(case_id, ids[0], "alice")
        .await?
        .expect("a review row");
    assert_eq!(
        row.opened_at, 1_000,
        "'when did this examiner first look at it' is the recorded fact; a later \
         scroll past the same row must not overwrite it"
    );
    assert_eq!(
        again.unchanged, 1,
        "the repeat opening changed nothing and must say so"
    );
    assert_eq!(again.openings_recorded, 0);
    Ok(())
}

#[tokio::test]
async fn withdrawing_a_review_leaves_the_opening_and_leaves_a_record() -> Result<()> {
    let (db, case_id, ids) = setup().await?;

    db.record_artifact_reviews_at(case_id, "alice", &[(ids[0], ReviewMark::Opened)], 1_000)
        .await?;
    db.record_artifact_reviews_at(case_id, "alice", &[(ids[0], ReviewMark::Reviewed)], 2_000)
        .await?;
    let withdrawal = db
        .record_artifact_reviews_at(case_id, "alice", &[(ids[0], ReviewMark::Unreviewed)], 3_000)
        .await?;

    assert_eq!(withdrawal.reviews_withdrawn, 1);

    let row = db
        .get_artifact_review(case_id, ids[0], "alice")
        .await?
        .expect("the row survives the withdrawal");
    assert_eq!(
        row.opened_at, 1_000,
        "withdrawing a review must not withdraw the opening"
    );
    assert_eq!(row.reviewed_at, None);

    // The append-only half: a review that was made and retracted must not read
    // like a review that was never made.
    let history = db
        .artifact_review_history(case_id, Some(ids[0]), None, 100)
        .await?;
    let actions: Vec<&str> = history.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(
        actions,
        vec!["opened", "reviewed", "review_withdrawn"],
        "the ledger must keep the whole transition history, in order"
    );
    Ok(())
}

#[tokio::test]
async fn withdrawing_a_review_that_was_never_made_invents_nothing() -> Result<()> {
    let (db, case_id, ids) = setup().await?;

    let outcome = db
        .record_artifact_reviews_at(case_id, "alice", &[(ids[0], ReviewMark::Unreviewed)], 1_000)
        .await?;

    assert_eq!(outcome.reviews_withdrawn, 0);
    assert_eq!(
        outcome.openings_recorded, 0,
        "withdrawing a review nobody made must not manufacture an opening"
    );
    assert!(
        db.get_artifact_review(case_id, ids[0], "alice")
            .await?
            .is_none(),
        "no row should exist at all"
    );
    assert!(db
        .artifact_review_history(case_id, Some(ids[0]), None, 100)
        .await?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn two_examiners_hold_two_independent_ledgers_over_one_case() -> Result<()> {
    let (db, case_id, ids) = setup().await?;

    db.record_artifact_reviews_at(
        case_id,
        "alice",
        &[(ids[0], ReviewMark::Reviewed), (ids[1], ReviewMark::Opened)],
        1_000,
    )
    .await?;
    db.record_artifact_reviews_at(case_id, "bob", &[(ids[0], ReviewMark::Opened)], 2_000)
        .await?;

    let stats = db.artifact_review_stats(case_id).await?;
    let alice = stats
        .per_examiner
        .iter()
        .find(|e| e.examiner == "alice")
        .expect("alice");
    let bob = stats
        .per_examiner
        .iter()
        .find(|e| e.examiner == "bob")
        .expect("bob");

    assert_eq!(alice.opened, 2);
    assert_eq!(alice.reviewed, 1);
    assert_eq!(bob.opened, 1);
    assert_eq!(
        bob.reviewed, 0,
        "bob opened the artifact alice reviewed; that is not bob having reviewed it"
    );

    // The case-wide roll-up counts ARTIFACTS, not ledger rows: ids[0] was opened
    // by two people and is one artifact that has been looked at.
    assert_eq!(stats.distinct_opened, 2);
    assert_eq!(stats.distinct_reviewed, 1);
    assert_eq!(
        stats.case_artifact_total, 5,
        "the denominator is the case's artifact population"
    );
    Ok(())
}

#[tokio::test]
async fn an_artifact_from_another_case_is_refused_rather_than_filed() -> Result<()> {
    let (db, case_id, ids) = setup().await?;
    let other_case = db.create_case("Somebody else's case", "mallory").await?;
    let intruder = Artifact {
        id: Uuid::new_v4(),
        case_id: other_case,
        parent_id: None,
        artifact_type: ArtifactType::FileEntry,
        metadata: json!({"name": "not-yours.txt"}),
        data: None,
    };
    db.record_artifact(&intruder).await?;

    let outcome = db
        .record_artifact_reviews_at(
            case_id,
            "mallory",
            &[
                (ids[0], ReviewMark::Opened),
                (intruder.id, ReviewMark::Reviewed),
            ],
            1_000,
        )
        .await?;

    assert_eq!(outcome.openings_recorded, 1, "only the in-case artifact");
    assert_eq!(
        outcome.rejected,
        vec![intruder.id],
        "the out-of-case id must be named in the response, not dropped"
    );
    assert!(db
        .get_artifact_review(case_id, intruder.id, "mallory")
        .await?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn the_id_listing_states_its_own_ceiling() -> Result<()> {
    let (db, case_id, ids) = setup().await?;

    let marks: Vec<(Uuid, ReviewMark)> = ids.iter().map(|id| (*id, ReviewMark::Reviewed)).collect();
    db.record_artifact_reviews_at(case_id, "alice", &marks, 1_000)
        .await?;

    let page = db
        .artifact_review_ids(case_id, ReviewIdState::Reviewed, None, 2)
        .await?;
    assert_eq!(page.ids.len(), 2);
    assert!(
        page.capped,
        "a listing that returned fewer ids than exist must say so"
    );
    assert_eq!(
        page.total, 5,
        "and it must still state how many there really are"
    );

    let whole = db
        .artifact_review_ids(case_id, ReviewIdState::Reviewed, None, 100)
        .await?;
    assert!(!whole.capped);
    assert_eq!(whole.ids.len(), 5);
    Ok(())
}

#[tokio::test]
async fn the_id_listing_can_be_scoped_to_one_examiner_or_to_everybody() -> Result<()> {
    let (db, case_id, ids) = setup().await?;

    db.record_artifact_reviews_at(case_id, "alice", &[(ids[0], ReviewMark::Reviewed)], 1_000)
        .await?;
    db.record_artifact_reviews_at(case_id, "bob", &[(ids[1], ReviewMark::Reviewed)], 1_000)
        .await?;

    let everyone = db
        .artifact_review_ids(case_id, ReviewIdState::Reviewed, None, 100)
        .await?;
    assert_eq!(everyone.total, 2);

    let just_alice = db
        .artifact_review_ids(case_id, ReviewIdState::Reviewed, Some("alice"), 100)
        .await?;
    assert_eq!(just_alice.ids, vec![ids[0]]);
    Ok(())
}

#[tokio::test]
async fn reviewing_twice_keeps_the_first_review_instant() -> Result<()> {
    let (db, case_id, ids) = setup().await?;

    db.record_artifact_reviews_at(case_id, "alice", &[(ids[0], ReviewMark::Reviewed)], 1_000)
        .await?;
    let second = db
        .record_artifact_reviews_at(case_id, "alice", &[(ids[0], ReviewMark::Reviewed)], 8_000)
        .await?;

    let row = db
        .get_artifact_review(case_id, ids[0], "alice")
        .await?
        .expect("a review row");
    assert_eq!(
        row.reviewed_at,
        Some(1_000),
        "when the artifact was cleared is a fact about the examination; re-asserting \
         it later must not move it"
    );
    assert_eq!(second.unchanged, 1);
    assert_eq!(second.reviews_recorded, 0);
    Ok(())
}
