//! Deleted-message recovery (ROADMAP §3.10) graded on the one real version-36
//! store this project holds: the suspect's OST from the NIST CFReDS Data
//! Leakage case, cut at its NTFS initialised length. Provenance and NIST's
//! answer key are in `tests/fixtures/ost_v36/README.md`.
//!
//! NIST's key (question 21) lists twelve messages. Eleven are in the live
//! B-trees; the twelfth, "It's me" (2015-03-23 16:38:47 local, UTC-4), is
//! marked "Recovered Item from unused area of OST file". That message is the
//! known answer here: it is graded against the key, not against this reader.

use seance_plugin_email::ost4k::{
    ltp::PropValue,
    mailbox::read_mailbox,
    ndb::Ndb,
    recover::{recover, Completeness, Source},
};

const FIXTURE: &str = "tests/fixtures/ost_v36/iaman.informant_initialised_prefix.ost";

fn fixture() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{} is tracked: {e}", path.display()))
}

fn s(p: &std::collections::BTreeMap<u16, PropValue>, tag: u16) -> String {
    match p.get(&tag) {
        Some(PropValue::Str(s)) => s.clone(),
        _ => String::new(),
    }
}

fn subject(p: &std::collections::BTreeMap<u16, PropValue>) -> String {
    // Outlook's two-character prefix marker (U+0001 and a length character).
    let raw = s(p, 0x0037);
    match raw.strip_prefix('\u{1}') {
        Some(rest) => rest.chars().skip(1).collect(),
        None => raw,
    }
}

/// FILETIME ticks to Unix seconds.
fn unix(p: &std::collections::BTreeMap<u16, PropValue>, tag: u16) -> Option<i64> {
    match p.get(&tag) {
        Some(PropValue::Time(t)) => Some(t / 10_000_000 - 11_644_473_600),
        _ => None,
    }
}

/// NIST's twelfth message is recovered from the store's unreferenced pages
/// and blocks, whole, at its keyed time, and nothing the live store holds is
/// reported again as recovered.
#[test]
fn nists_recovered_item_its_me_is_recovered_from_the_unused_area() {
    let data = fixture();
    let ndb = Ndb::open(&data).unwrap();
    let mb = read_mailbox(&ndb);
    assert_eq!(mb.messages.len(), 14, "the live mailbox is unchanged");
    let r = recover(&ndb, &mb);

    let hits: Vec<_> = r
        .messages
        .iter()
        .filter(|m| subject(&m.props) == "It's me")
        .collect();
    assert_eq!(hits.len(), 1, "{:?}", r.messages);
    let m = hits[0];
    // Key: 2015-03-23 16:38:47 local (UTC-4) = 20:38:47 UTC.
    assert_eq!(unix(&m.props, 0x0039), Some(1_427_143_127));
    // The message read whole, but it is an earlier state: the entry's newest
    // version (data BID 0x7830) is in no block that could be found, so the
    // recovery is graded partial and says so rather than claiming the last
    // state of the message.
    assert_eq!(m.completeness, Completeness::Partial, "{:?}", m.gaps);
    assert!(
        m.gaps
            .iter()
            .any(|g| g.contains("0x7830") && g.contains("earlier state")),
        "{:?}",
        m.gaps
    );
    assert!(m.props_unreadable.is_empty() && m.attachments_unreadable == 0);
    assert!(m
        .other_versions
        .iter()
        .any(|v| v.newer && v.bid_data == 0x7830));
    assert_eq!(m.nid, 0x0020_15E4);
    // Its parent is Sent Items, a live folder.
    let sent = mb
        .folders
        .iter()
        .find(|f| f.nid == m.parent_nid)
        .expect("the parent is a live folder");
    assert!(sent.path.ends_with("/Sent Items"), "{}", sent.path);
    assert_eq!(m.data_block_offset, Some(0x61000));
    assert_eq!(m.subnode_block_offset, Some(0x55400));
    match &m.source {
        Source::StaleNodeEntry { page_offsets } => {
            assert_eq!(page_offsets.len(), 5, "{page_offsets:x?}")
        }
        other => panic!("{other:?}"),
    }

    // None of the eleven live keyed messages (or the three sync logs) comes
    // back as a recovery.
    let live: std::collections::HashSet<(String, Option<i64>)> = mb
        .messages
        .iter()
        .map(|m| (subject(&m.props), unix(&m.props, 0x0039)))
        .collect();
    for m in r.messages.iter().chain(&r.fragments) {
        assert!(
            !live.contains(&(subject(&m.props), unix(&m.props, 0x0039))),
            "{} was reported again",
            subject(&m.props)
        );
    }
}

/// What else the walk finds on this file, measured here and pinned so a
/// change in it is seen. These are not in NIST's key and are not graded
/// against it: four deleted message nodes in Deleted Items whose content does
/// not match any live message (three read whole or in part, one whose data
/// block was not found), 37 valid B-tree pages and 101 blocks no live tree
/// references, and no property context with no node entry.
#[test]
fn the_rest_of_the_unused_area_is_reported_with_its_completeness() {
    let data = fixture();
    let ndb = Ndb::open(&data).unwrap();
    let mb = read_mailbox(&ndb);
    let r = recover(&ndb, &mb);
    assert_eq!(r.unreferenced_pages.len(), 37);
    assert_eq!(r.blocks_found, 482);
    assert_eq!(r.unreferenced_blocks, 101);
    assert_eq!(r.messages.len(), 5);
    assert!(r.fragments.is_empty());
    assert!(r.copies_of_live.is_empty());
    assert!(!r.capped);
    let grade: Vec<(String, &str)> = r
        .messages
        .iter()
        .map(|m| (subject(&m.props), m.completeness.as_str()))
        .collect();
    assert_eq!(
        grade,
        vec![
            ("RE: Good job, buddy.".to_string(), "partial"),
            ("It's me".to_string(), "partial"),
            ("RE: Last request".to_string(), "complete"),
            (String::new(), "entry_only"),
            ("Watch out!".to_string(), "complete"),
        ]
    );
    let gone = &r.messages[3];
    assert!(gone.gaps[0].contains("0x7278"), "{:?}", gone.gaps);
}

/// The parser publishes each recovery as a message record marked recovered
/// from unallocated space, with its offsets and completeness, and the summary
/// counts them and names the entry whose data was not found.
#[test]
fn parse_pst_marks_recovered_messages_as_recovered_from_unallocated_space() {
    let out: Vec<serde_json::Value> = seance_plugin_email::parse_pst(
        &fixture(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        "iaman.informant@nist.gov.ost",
    )
    .into_iter()
    .map(|a| a.metadata)
    .collect();
    let recovered: Vec<_> = out
        .iter()
        .filter(|m| m["subtype"] == "email_message" && m["recovered"] == true)
        .collect();
    assert_eq!(recovered.len(), 4);
    let its_me = recovered
        .iter()
        .find(|m| m["subject"] == "It's me")
        .expect("It's me is published");
    assert_eq!(its_me["allocation"], "unallocated");
    assert_eq!(its_me["recovery_source"], "stale_node_entry");
    // Read whole, but from an earlier version of its entry (a newer one's
    // data block was not found), so it is graded partial.
    assert_eq!(its_me["recovery_completeness"], "partial");
    assert_eq!(its_me["recovery_offsets"]["data_block"], 0x61000);
    assert_eq!(
        its_me["folder_path"],
        "Root - Mailbox/IPM_SUBTREE/Sent Items"
    );
    assert!(its_me["date"]
        .as_str()
        .unwrap()
        .starts_with("2015-03-23T20:38:47"));
    assert_eq!(its_me["content_incomplete"], true);

    let partial = recovered
        .iter()
        .find(|m| m["recovery_completeness"] == "partial")
        .unwrap();
    assert_eq!(partial["content_incomplete"], true);
    assert!(!partial["recovery_gaps"].as_array().unwrap().is_empty());

    // The timeline event of a recovered message says so too.
    assert!(out
        .iter()
        .any(|m| m["event_type"] == "email_message" && m["recovered"] == true));

    let s = out.iter().find(|m| m["subtype"] == "pst_summary").unwrap();
    assert_eq!(s["message_count"], 14, "the live count is unchanged");
    assert_eq!(s["recovered_messages"], 4);
    assert_eq!(s["recovered_fragments"], 0);
    assert_eq!(s["unreferenced_pages"], 37);
    assert_eq!(s["unreferenced_blocks"], 101);
    let e = s["recovered_entries_without_data"].as_array().unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0]["node_id"], "0x201c44");
    let note = s["store_note"].as_str().unwrap();
    assert!(note.contains("allocation map ignored"), "{note}");
}
