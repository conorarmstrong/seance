//! The version 14 reader and recovery on the one large real store this project
//! has: Jean's Outlook mailbox from the NPS M57-Jean scenario (2,326,528 bytes,
//! 258 messages, SHA-256 `e17b8c39…1119`, see `tests/fixtures/pst_old/`).
//!
//! The store is not in the repository. `SEANCE_PST14_CORPUS` names a directory
//! holding it as `m57_jean_outlook.pst`; without the variable these skip, and a
//! named directory missing the file panics (`documentation/TESTING.md`).
//!
//! The answer is libpff's, not this reader's: `m57_jean_outlook_libpff_oracle.tsv`
//! lists every message libpff reads, with its folder, subject and attachment count.

use super::*;
use std::collections::BTreeMap as Map;

const ORACLE: &str = include_str!("../tests/fixtures/pst_old/m57_jean_outlook_libpff_oracle.tsv");

fn store_bytes() -> Option<Vec<u8>> {
    let path =
        seance_core::test_support::corpus::file("SEANCE_PST14_CORPUS", "m57_jean_outlook.pst")?;
    Some(std::fs::read(path).expect("read the store"))
}

/// (attachments, folder, subject) by node id, from libpff.
fn oracle() -> Map<u32, (usize, String, String)> {
    ORACLE
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let mut f = l.splitn(4, '\t');
            let nid = u32::from_str_radix(f.next().unwrap().trim_start_matches("0x"), 16).unwrap();
            let att = f.next().unwrap().parse().unwrap();
            (
                nid,
                (
                    att,
                    f.next().unwrap().to_string(),
                    f.next().unwrap_or("").to_string(),
                ),
            )
        })
        .collect()
}

pub(super) fn subject(props: &Map<u16, PropValue>) -> String {
    match props.get(&0x0037) {
        Some(PropValue::Str(s)) => crate::pst::normalise_subject(s),
        _ => String::new(),
    }
}

#[test]
fn every_live_message_reads_as_libpff_reads_it() {
    let Some(data) = store_bytes() else { return };
    let s = Store::open(&data).expect("the real store opens");
    assert_eq!(s.layout(), Layout::Ansi);
    assert!(s.faults().is_empty(), "{:?}", s.faults());
    let want = oracle();
    assert_eq!(want.len(), 258);
    assert_eq!(
        s.live_message_nodes(),
        want.keys().copied().collect::<Vec<_>>(),
        "the live node B-tree names the messages libpff lists, and no others"
    );
    for (nid, (att, _, subj)) in &want {
        let pc = s
            .read_live_pc(*nid)
            .unwrap_or_else(|e| panic!("{nid:#x}: {e}"));
        assert_eq!(&subject(&pc.props), subj, "{nid:#x}");
        let got = pc
            .subnodes
            .keys()
            .filter(|n| *n & 0x1F == NID_TYPE_ATTACHMENT)
            .count();
        assert_eq!(got, *att, "{nid:#x}: attachments");
    }
}

#[test]
fn an_untouched_real_mailbox_reports_no_deleted_message() {
    let Some(data) = store_bytes() else { return };
    let r = recover(&data).unwrap();
    assert!(
        r.messages.is_empty(),
        "every stale node entry names a message that is still live: {:?}",
        r.messages.iter().map(|m| m.nid).collect::<Vec<_>>()
    );
    // The stale pages and the unreferenced blocks are real and are counted.
    assert_eq!(r.unreferenced_pages.len(), 21);
    assert_eq!(r.unreferenced_blocks, 29);
}

/// The 62 live messages whose node entry also sits in a stale page (found
/// by walking the file's pages independently of this module).
pub(super) fn nodes_with_a_stale_entry(data: &[u8]) -> Vec<u32> {
    let s = Store::open(data).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for p in s.scan_pages().found {
        if p.ptype != PTYPE_NBT || p.level != 0 || s.live_pages.contains(&p.ib) {
            continue;
        }
        let page = s.page_at(p.ib, Some(PTYPE_NBT), None).unwrap();
        for i in 0..page.c_ent {
            if let Some(n) = page.entry(i).and_then(|e| s.nbt_entry(e)) {
                let nid = n.nid as u32;
                if nid & 0x1F == NID_TYPE_NORMAL_MESSAGE && s.nodes.contains_key(&nid) {
                    seen.insert(nid);
                }
            }
        }
    }
    seen.into_iter().collect()
}

#[test]
fn messages_deleted_from_a_real_mailbox_are_recovered_as_libpff_read_them() {
    let Some(data) = store_bytes() else { return };
    let want = oracle();
    // The one with eight attachments, the one with one, one from Deleted
    // Items and one sent.
    for nid in [0x0020_0024u32, 0x0020_2184, 0x0020_1CC4, 0x0020_00A4] {
        let (att, _, subj) = &want[&nid];
        let cut = without_live_node(&data, nid);
        assert!(!Store::open(&cut)
            .unwrap()
            .live_message_nodes()
            .contains(&nid));
        let r = recover(&cut).unwrap();
        let m = r
            .messages
            .iter()
            .find(|m| m.nid == nid)
            .unwrap_or_else(|| panic!("{nid:#x} was not recovered"));
        assert_eq!(&subject(&m.props), subj, "{nid:#x}");
        assert_eq!(m.attachments.len(), *att, "{nid:#x}");
        assert_eq!(
            m.completeness,
            Completeness::Complete,
            "{nid:#x}: {:?}",
            m.gaps
        );
        assert_eq!(r.messages.len(), 1, "only the message cut out comes back");
    }
}

#[test]
fn all_62_messages_with_a_stale_entry_come_back_when_deleted_together() {
    let Some(data) = store_bytes() else { return };
    let want = oracle();
    let nodes = nodes_with_a_stale_entry(&data);
    assert_eq!(nodes.len(), 62);
    let cut = nodes
        .iter()
        .fold(data.clone(), |d, n| without_live_node(&d, *n));
    let r = recover(&cut).unwrap();
    let got: Vec<u32> = r.messages.iter().map(|m| m.nid).collect();
    assert_eq!(got, nodes, "exactly those, each once");
    // 0x2021E4's three stale entries name data blocks that were overwritten
    // (found by an independent walk of the file): its content is gone, and the
    // record says so instead of inventing any.
    const DATA_OVERWRITTEN: u32 = 0x0020_21E4;
    let paths = Store::open(&cut).unwrap().folder_paths();
    for m in &r.messages {
        assert_eq!(
            paths.get(&m.parent_nid).map(|p| format!("/{p}")),
            Some(want[&m.nid].1.clone()),
            "{:#x}: the folder libpff files it in",
            m.nid
        );
        if m.nid == DATA_OVERWRITTEN {
            assert_eq!(m.completeness, Completeness::EntryOnly);
            assert!(m.props.is_empty() && !m.gaps.is_empty());
            // Every version was tried and none read: each one carries its own
            // error, and the gaps name each version, not only the newest.
            assert!(!m.other_versions.is_empty());
            assert!(
                m.other_versions.iter().all(|v| v.read_error.is_some()),
                "{:?}",
                m.other_versions
            );
            assert_eq!(m.gaps.len(), m.other_versions.len() + 1, "{:?}", m.gaps);
            continue;
        }
        let (att, _, subj) = &want[&m.nid];
        assert_eq!(&subject(&m.props), subj, "{:#x}", m.nid);
        assert_eq!(m.attachments.len(), *att, "{:#x}", m.nid);
        assert_eq!(m.completeness, Completeness::Complete, "{:#x}", m.nid);
    }
    assert_eq!(
        r.messages
            .iter()
            .filter(|m| m.completeness == Completeness::Complete)
            .count(),
        61
    );
}

/// The limit of the method, pinned: a node whose entry was only ever in a live
/// page, and whose block the live block tree still names, leaves nothing
/// unreferenced to find.
#[test]
fn a_deletion_that_left_no_stale_entry_is_not_recovered_and_that_is_the_limit() {
    let Some(data) = store_bytes() else { return };
    let nid = 0x0020_16E4u32;
    assert!(!nodes_with_a_stale_entry(&data).contains(&nid));
    let r = recover(&without_live_node(&data, nid)).unwrap();
    assert!(r.messages.iter().all(|m| m.nid != nid));
}

/// The same through the plugin: what an examiner is given for the real
/// mailbox with its 62 recoverable messages deleted.
#[test]
fn the_plugin_publishes_the_real_mailbox_recoveries_and_says_what_it_scanned() {
    let Some(data) = store_bytes() else { return };
    let nodes = nodes_with_a_stale_entry(&data);
    let cut = nodes
        .iter()
        .fold(data.clone(), |d, n| without_live_node(&d, *n));
    let arts = crate::pst::parse_pst(&cut, uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), "o.pst");
    let recovered = arts
        .iter()
        .filter(|a| a.metadata.get("recovered") == Some(&serde_json::json!(true)))
        .filter(|a| a.metadata["subtype"] == "email_message")
        .count();
    // 61 messages and the one fragment; the 62nd node lost its data and is
    // named in the summary, not invented.
    assert_eq!(recovered, 62);
    let summary = arts.last().unwrap();
    assert_eq!(summary.metadata["recovered_messages"], 61);
    assert_eq!(summary.metadata["recovered_fragments"], 1);
    assert_eq!(
        summary.metadata["recovered_entries_without_data"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(summary.metadata["recovery_scanned_version"], 14);
    // 196 live messages remain in the live walk.
    assert_eq!(summary.metadata["message_count"], 258 - 62);
}

/// The one fragment in the real mailbox is not a separate deleted message: it
/// is an earlier draft of live Sent Items message 0x2027C4 (no sender, no body,
/// a submit time seven seconds before the sent copy's, the same subject and
/// delivery time). The identity rule shared with the version 36 recovery cannot
/// link the two, so the record has to say it may be one.
#[test]
fn a_fragment_that_may_be_an_earlier_state_of_a_live_message_says_so() {
    let Some(data) = store_bytes() else { return };
    let r = recover(&data).unwrap();
    assert_eq!(r.fragments.len(), 1);
    let f = &r.fragments[0];
    assert_eq!(subject(&f.props), "RE: Hi Jean");
    assert!(
        f.gaps
            .iter()
            .any(|g| g.contains("0x2027c4") && g.contains("earlier state")),
        "{:?}",
        f.gaps
    );
}

/// A fragment that matches no live message makes no such claim.
#[test]
fn a_fragment_matching_no_live_message_makes_no_earlier_state_claim() {
    let Some(data) = store_bytes() else { return };
    // Cut the sent message out of the live tree: nothing live shares the
    // fragment's subject and delivery time any more.
    let cut = without_live_node(&data, 0x0020_27C4);
    let r = recover(&cut).unwrap();
    let frag = r
        .fragments
        .iter()
        .find(|f| subject(&f.props) == "RE: Hi Jean")
        .expect("the fragment is still found");
    assert!(
        frag.gaps.iter().all(|g| !g.contains("earlier state")),
        "{:?}",
        frag.gaps
    );
}
