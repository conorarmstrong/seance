//! The version 23 (Unicode) reader and recovery on a real mailbox with
//! messages: the Outlook data file of the "Natasha Romanoff" scenario that
//! ships as public test data with plaso (Apache-2.0), 59,442,176 bytes,
//! SHA-256 `bab64f35…d6013`, see `tests/fixtures/pst_old/PROVENANCE.txt`.
//!
//! The store is not in the repository. `SEANCE_PST23_CORPUS` names a directory
//! holding it as `nromanoff_stark_research_labs.pst`; without the variable
//! these skip, and a named directory missing the file panics
//! (`documentation/TESTING.md`).
//!
//! The answer is libpff's, not this reader's:
//! `nromanoff_v23_libpff_oracle.tsv` lists every mail and contact item
//! pffexport (libpff 20231205) exports, with its node id, folder, subject and
//! attachment count.

use super::corpus_tests::{nodes_with_a_stale_entry, subject};
use super::*;
use std::collections::BTreeMap as Map;

/// The free/busy message pffexport skips, live in "Freebusy Data".
const FREEBUSY: u32 = 0x0020_0044;

const ORACLE: &str = include_str!("../tests/fixtures/pst_old/nromanoff_v23_libpff_oracle.tsv");

fn store_bytes() -> Option<Vec<u8>> {
    let path = seance_core::test_support::corpus::file(
        "SEANCE_PST23_CORPUS",
        "nromanoff_stark_research_labs.pst",
    )?;
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
            let folder = f.next().unwrap().to_string();
            let subj = crate::pst::normalise_subject(f.next().unwrap_or(""));
            (nid, (att, folder, subj))
        })
        .collect()
}

#[test]
fn every_live_message_in_a_real_unicode_store_reads_as_libpff_reads_it() {
    let Some(data) = store_bytes() else { return };
    check_every_live_message(&data);
}

/// The same store re-encoded with the cyclic algorithm by `scripts/synth/pst_to_cyclic.py`
/// (`nromanoff_stark_research_labs.cyclic.pst` beside the original, made from it; `PST-CYCLIC-1`): every one of
/// the 543 messages reads as libpff read the original, so every block of the tree decodes with the right key.
#[test]
fn every_live_message_in_a_cyclic_copy_reads_as_libpff_reads_the_original() {
    let Some(path) = seance_core::test_support::corpus::file(
        "SEANCE_PST23_CORPUS",
        "nromanoff_stark_research_labs.cyclic.pst",
    ) else {
        return;
    };
    check_every_live_message(&std::fs::read(path).expect("read the store"));
}

fn check_every_live_message(data: &[u8]) {
    let s = Store::open(data).expect("the real store opens");
    assert_eq!(s.layout(), Layout::Unicode);
    assert!(s.faults().is_empty(), "{:?}", s.faults());
    let want = oracle();
    assert_eq!(want.len(), 543);
    let live = s.live_message_nodes();
    let missing: Vec<_> = want.keys().filter(|n| !live.contains(n)).collect();
    let extra: Vec<_> = live.iter().filter(|n| !want.contains_key(n)).collect();
    assert!(
        missing.is_empty() && extra == [&FREEBUSY],
        "libpff lists, this reader does not: {missing:x?}; this reader lists, libpff does not: {extra:x?}"
    );
    // The one item pffexport does not export (it logs "Skipped ... of type
    // IPM.Microsoft.ScheduleData.FreeBusy"): the free/busy message in the
    // "Freebusy Data" folder, outside the mail tree.
    let paths = s.folder_paths();
    let fb = s
        .read_live_pc(FREEBUSY)
        .expect("the free/busy message reads");
    assert_eq!(
        fb.props.get(&0x001A),
        Some(&PropValue::Str(
            "IPM.Microsoft.ScheduleData.FreeBusy".into()
        ))
    );
    assert_eq!(
        paths
            .get(&s.nodes[&FREEBUSY].nid_parent)
            .map(String::as_str),
        Some("Freebusy Data")
    );
    let mut bad = Vec::new();
    for (nid, (att, folder, subj)) in &want {
        let pc = s
            .read_live_pc(*nid)
            .unwrap_or_else(|e| panic!("{nid:#x}: {e}"));
        let got_att = pc
            .subnodes
            .keys()
            .filter(|n| *n & 0x1F == NID_TYPE_ATTACHMENT)
            .count();
        let got_folder = s
            .nodes
            .get(nid)
            .and_then(|n| paths.get(&n.nid_parent))
            .map(|p| format!("/{p}"));
        let got_subj = subject(&pc.props);
        if &got_subj != subj || got_att != *att || got_folder.as_deref() != Some(folder.as_str()) {
            bad.push(format!(
                "{nid:#x}: subject {got_subj:?} want {subj:?}; attachments {got_att} want {att}; folder {got_folder:?} want {folder:?}"
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "{} differ:\n{}",
        bad.len(),
        bad[..bad.len().min(10)].join("\n")
    );
}

/// Three messages in Deleted Items (node 0x8062) have a stale node entry and no
/// live one: libpff lists Deleted Items as empty. This is this reader's
/// reading, not libpff's: libpff's own recovery (`pffexport -m recovered`)
/// fails on this file ("unable to recover index node at offset: 356864"), so
/// the existence of these three is not corroborated by libpff.
#[test]
fn an_untouched_real_unicode_mailbox_recovers_the_three_messages_deleted_from_it() {
    let Some(data) = store_bytes() else { return };
    let want = oracle();
    assert!(want
        .values()
        .all(|(_, f, _)| !f.ends_with("/Deleted Items")));
    let r = recover(&data).unwrap();
    let got: Vec<(u32, u32, String)> = r
        .messages
        .iter()
        .map(|m| (m.nid, m.parent_nid, subject(&m.props)))
        .collect();
    const DELETED_ITEMS: u32 = 0x8062;
    assert_eq!(
        got,
        vec![
            (
                0x204124,
                DELETED_ITEMS,
                "Undeliverable: RE: Agent List - Sensitive".to_string()
            ),
            (
                0x204164,
                DELETED_ITEMS,
                "Undeliverable: RE: Backstopped Accounts".to_string()
            ),
            (
                0x204184,
                DELETED_ITEMS,
                "Undeliverable: RE: Backstopped Accounts".to_string()
            ),
        ]
    );
    assert!(r
        .messages
        .iter()
        .all(|m| m.completeness == Completeness::Complete && m.gaps.is_empty()));
    let s = Store::open(&data).unwrap();
    assert!(r.messages.iter().all(|m| !s.nodes.contains_key(&m.nid)));
}

/// Real bytes, mutated: a live node's entry is cut from the live tree of the
/// real store and the page CRC rewritten. It is graded only on messages whose
/// original store holds a stale node entry; whether any do is read from the
/// file by `nodes_with_a_stale_entry`, not assumed.
#[test]
fn a_message_cut_from_the_live_tree_of_a_real_unicode_store_is_recovered_as_libpff_read_it() {
    let Some(data) = store_bytes() else { return };
    let want = oracle();
    let stale: Vec<u32> = nodes_with_a_stale_entry(&data)
        .into_iter()
        .filter(|n| want.contains_key(n))
        .collect();
    eprintln!("v23: {} live messages have a stale node entry", stale.len());
    assert!(!stale.is_empty(), "no stale entry to recover from");
    for nid in stale.iter().take(8) {
        let (att, folder, subj) = &want[nid];
        let cut = without_live_node(&data, *nid);
        let r = recover(&cut).unwrap();
        let m = r
            .messages
            .iter()
            .find(|m| m.nid == *nid)
            .unwrap_or_else(|| panic!("{nid:#x} was not recovered"));
        assert_eq!(&subject(&m.props), subj, "{nid:#x}");
        assert_eq!(m.attachments.len(), *att, "{nid:#x}");
        let paths = Store::open(&cut).unwrap().folder_paths();
        assert_eq!(
            paths.get(&m.parent_nid).map(|p| format!("/{p}")).as_ref(),
            Some(folder),
            "{nid:#x}"
        );
    }
}

/// The limit of the method on a Unicode store: a node with no stale entry
/// leaves nothing unreferenced to find.
#[test]
fn a_deletion_that_left_no_stale_entry_is_not_recovered_in_a_real_unicode_store() {
    let Some(data) = store_bytes() else { return };
    let stale = nodes_with_a_stale_entry(&data);
    let nid = *oracle()
        .keys()
        .find(|n| !stale.contains(n))
        .expect("some message has no stale entry");
    let r = recover(&without_live_node(&data, nid)).unwrap();
    assert!(r.messages.iter().all(|m| m.nid != nid));
}
