//! The Outlook 2013 OST reader (format version 36) against the one real file
//! this project holds: the suspect's mailbox from the NIST CFReDS Data Leakage
//! case, cut at its NTFS initialised length. Provenance, hashes and the NIST
//! known answers are in `tests/fixtures/ost_v36/README.md`.
//!
//! The fixture is tracked in the repository, so its absence is a failure, not
//! a skip.

use seance_plugin_email::ost4k::{Bref, Header4k, Ost4kError};

const FIXTURE: &str = "tests/fixtures/ost_v36/iaman.informant_initialised_prefix.ost";

fn fixture() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{} is tracked in the repository and could not be read ({e}); see \
             tests/fixtures/ost_v36/README.md",
            path.display()
        )
    })
}

#[test]
fn the_data_leakage_ost_header_names_its_two_btree_roots() {
    let data = fixture();
    assert_eq!(
        data.len(),
        3_360_768,
        "the fixture is the initialised prefix"
    );

    let h = Header4k::read(&data).expect("the real header reads and its CRCs match");
    assert_eq!(h.client, "OST");
    assert_eq!(h.version, 36);
    assert_eq!(
        h.file_eof, 16_818_176,
        "ibFileEof is the whole file, not the prefix"
    );
    assert_eq!(
        h.nbt_root,
        Bref {
            bid: 0x36EB,
            ib: 0x90000
        }
    );
    assert_eq!(
        h.bbt_root,
        Bref {
            bid: 0x36F0,
            ib: 0x91000
        }
    );
    assert_eq!(h.crypt_method, 0, "this store is not encoded");

    // The version is part of what the CRC covers, so a store claiming 35 fails
    // the version gate before the CRC is consulted, and names the number.
    let mut v35 = data[..4096].to_vec();
    v35[10] = 35;
    assert_eq!(Header4k::read(&v35), Err(Ost4kError::Version(35)));

    // One flipped bit inside the CRC's span is caught.
    let mut bent = data[..4096].to_vec();
    bent[0xD8] ^= 1;
    assert!(
        matches!(Header4k::read(&bent), Err(Ost4kError::Crc { .. })),
        "{:?}",
        Header4k::read(&bent)
    );

    // Too short to hold a header is a named truncation.
    assert!(matches!(
        Header4k::read(&data[..100]),
        Err(Ost4kError::Truncated { .. })
    ));
}

#[test]
fn the_data_leakage_ost_walks_351_nodes_and_381_blocks_with_no_unreadable_page() {
    use seance_plugin_email::ost4k::btree::{walk_bbt, walk_nbt};
    let data = fixture();
    let h = Header4k::read(&data).unwrap();

    let nbt = walk_nbt(&data, h.nbt_root);
    assert!(nbt.faults.is_empty(), "{:?}", nbt.faults);
    assert_eq!(nbt.entries.len(), 351);
    // The root and its three leaves.
    assert_eq!(nbt.pages_walked, 4);
    // Node ids are the B-tree's keys, so a walk in order is sorted and unique.
    assert!(nbt.entries.windows(2).all(|w| w[0].nid < w[1].nid));
    // NID_MESSAGE_STORE (0x21) and the root folder (0x122) are there.
    assert!(nbt.entries.iter().any(|e| e.nid == 0x21));
    assert!(nbt
        .entries
        .iter()
        .any(|e| e.nid == 0x122 && e.nid_parent == 0x122));

    let bbt = walk_bbt(&data, h.bbt_root);
    assert!(bbt.faults.is_empty(), "{:?}", bbt.faults);
    assert_eq!(bbt.entries.len(), 381);
    assert_eq!(bbt.pages_walked, 5);
    assert!(bbt
        .entries
        .windows(2)
        .all(|w| w[0].bref.bid < w[1].bref.bid));
    // No block lies past the initialised length.
    assert!(bbt
        .entries
        .iter()
        .all(|e| e.bref.ib + u64::from(e.cb) <= data.len() as u64));
    // 123 are stored compressed.
    assert_eq!(
        bbt.entries.iter().filter(|e| e.cb != e.cb_inflated).count(),
        123
    );
}

#[test]
fn every_block_the_bbt_names_reads_and_inflates_to_its_stated_size() {
    use seance_plugin_email::ost4k::block::read_block;
    use seance_plugin_email::ost4k::btree::walk_bbt;
    let data = fixture();
    let h = Header4k::read(&data).unwrap();
    let bbt = walk_bbt(&data, h.bbt_root);
    assert_eq!(bbt.entries.len(), 381);

    let mut failures = Vec::new();
    let mut inflated = 0;
    for e in &bbt.entries {
        match read_block(&data, e) {
            Ok(bytes) => {
                assert_eq!(bytes.len(), usize::from(e.cb_inflated), "{e:?}");
                if e.cb != e.cb_inflated {
                    inflated += 1;
                }
            }
            Err(f) => failures.push((e.bref.bid, f)),
        }
    }
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(inflated, 123);
}

/// The messages NIST's answer key lists for question 21 (see the fixture
/// README), with the key's local times converted to the UTC the store holds
/// (UTC−4 in March 2015). Taken from the key before this reader existed, not
/// from its output.
const KNOWN: &[(&str, &str, &str, &str)] = &[
    // (folder, subject, sender, submit time UTC to the second). The sender is
    // the SMTP address where the store holds one (mail received from
    // Exchange); the informant's own sent mail carries only his display name
    // and an Exchange X.500 address, so for those the key's address is
    // checked against the display name the store does hold.
    (
        "Inbox",
        "Hello, Iaman",
        "spy.conspirator@nist.gov",
        "2015-03-23T17:29:27",
    ),
    (
        "Sent Items",
        "RE: Hello, Iaman",
        "iaman.informant@nist.gov",
        "2015-03-23T18:44:31",
    ),
    (
        "Inbox",
        "Good job, buddy.",
        "spy.conspirator@nist.gov",
        "2015-03-23T19:14:58",
    ),
    (
        "Inbox",
        "RE: Good job, buddy.",
        "spy.conspirator@nist.gov",
        "2015-03-23T19:20:41",
    ),
    (
        "Inbox",
        "Important request",
        "spy.conspirator@nist.gov",
        "2015-03-23T19:26:22",
    ),
    (
        "Sent Items",
        "RE: Important request",
        "iaman.informant@nist.gov",
        "2015-03-23T19:27:05",
    ),
    (
        "Deleted Items",
        "RE: It's me",
        "spy.conspirator@nist.gov",
        "2015-03-23T20:41:19",
    ),
    (
        "Inbox",
        "Last request",
        "spy.conspirator@nist.gov",
        "2015-03-24T13:25:57",
    ),
    (
        "Deleted Items",
        "RE: Last request",
        "iaman.informant@nist.gov",
        "2015-03-24T13:35:10",
    ),
    (
        "Deleted Items",
        "RE: Watch out!",
        "iaman.informant@nist.gov",
        "2015-03-24T19:34:02",
    ),
    (
        "Deleted Items",
        "Done",
        "iaman.informant@nist.gov",
        "2015-03-24T21:05:09",
    ),
];

#[test]
fn the_informant_mailbox_lists_its_folders_and_messages() {
    use seance_plugin_email::ost4k::ltp::PropValue;
    use seance_plugin_email::ost4k::mailbox::read_mailbox;
    use seance_plugin_email::ost4k::ndb::Ndb;

    let data = fixture();
    let ndb = Ndb::open(&data).unwrap();
    let mb = read_mailbox(&ndb);
    assert!(mb.nodes_unreadable.is_empty(), "{:?}", mb.nodes_unreadable);

    let folder = |name: &str| {
        mb.folders
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("no folder {name}: {:?}", mb.folders))
    };
    for name in [
        "Inbox",
        "Sent Items",
        "Deleted Items",
        "Outbox",
        "Drafts",
        "Calendar",
        "Contacts",
    ] {
        let f = folder(name);
        assert_eq!(f.path, format!("Root - Mailbox/IPM_SUBTREE/{name}"));
    }
    assert_eq!(folder("Inbox").content_count, Some(5));
    assert_eq!(folder("Sent Items").content_count, Some(2));
    assert_eq!(folder("Deleted Items").content_count, Some(4));

    // Eleven the key lists, and three Outlook synchronisation logs it does not.
    assert_eq!(mb.messages.len(), 14);
    let text = |m: &seance_plugin_email::ost4k::mailbox::Message, tag: u16| match m.props.get(&tag)
    {
        Some(PropValue::Str(s)) => s.clone(),
        other => panic!("{tag:#06x}: {other:?}"),
    };
    let folder_of = |m: &seance_plugin_email::ost4k::mailbox::Message| {
        mb.folders
            .iter()
            .find(|f| f.nid == m.folder_nid)
            .map(|f| f.name.clone())
            .unwrap()
    };
    let mut by_display_name = 0;
    for (fname, subject, from, when) in KNOWN {
        let m = mb
            .messages
            .iter()
            .find(|m| {
                text(m, 0x0037)
                    .trim_start_matches('\u{1}')
                    .ends_with(subject)
                    && folder_of(m) == *fname
            })
            .unwrap_or_else(|| panic!("{fname}/{subject} not found"));
        match m.props.get(&0x5D01) {
            Some(PropValue::Str(smtp)) => assert_eq!(smtp, from, "{subject}"),
            None => {
                // Only the informant's own mail may lack an SMTP address; for
                // it, the sender is matched by display name and X.500 DN, not
                // by the key's address, which the store does not hold.
                assert_eq!(*from, "iaman.informant@nist.gov", "{subject}");
                by_display_name += 1;
                assert_eq!(text(m, 0x0C1A), "iaman", "{subject}");
                assert!(text(m, 0x0C1F).ends_with("-iaman"), "{subject}");
            }
            other => panic!("{subject}: {other:?}"),
        }
        let Some(PropValue::Time(ft)) = m.props.get(&0x0039) else {
            panic!("{subject}: no submit time")
        };
        let secs = (ft - 116_444_736_000_000_000) / 10_000_000;
        let got = chrono::DateTime::from_timestamp(secs, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        assert_eq!(&got, when, "{subject}");
        assert!(
            m.props_unreadable.is_empty(),
            "{subject}: {:?}",
            m.props_unreadable
        );
    }
    assert_eq!(by_display_name, 5);

    // Reading the whole mailbox touches each block about once: well inside
    // the store-wide read budget that bounds hostile trees.
    let (read, budget) = ndb.bytes_read();
    let held: u64 = ndb
        .bbt
        .entries
        .iter()
        .map(|e| u64::from(e.cb_inflated))
        .sum();
    eprintln!("read {read} of {held} held (budget {budget})");
    assert!(read <= 2 * held, "read {read}, held {held}");
    assert!(read < budget);

    let sync = mb
        .messages
        .iter()
        .filter(|m| folder_of(m) == "Sync Issues")
        .count();
    assert_eq!(sync, 3);

    // A body the key quotes, from the HTML body (this store holds no plain
    // text body for it).
    let good_job = mb
        .messages
        .iter()
        .find(|m| text(m, 0x0037) == "\u{1}\u{1}Good job, buddy.")
        .unwrap();
    let Some(PropValue::Bin(html)) = good_job.props.get(&0x1013) else {
        panic!("no HTML body")
    };
    let html = String::from_utf8_lossy(html);
    assert!(html.contains("I need a more detailed data about this business."));
}

fn run_parse(data: &[u8]) -> Vec<serde_json::Value> {
    seance_plugin_email::parse_pst(
        data,
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        "iaman.informant@nist.gov.ost",
    )
    .into_iter()
    .map(|a| a.metadata)
    .collect()
}

#[test]
fn parse_pst_on_the_data_leakage_ost_emits_email_artifacts_and_a_summary_naming_the_ost_layout() {
    let out = run_parse(&fixture());
    // The live mailbox; messages recovered from unallocated space (§3.10) are
    // graded in `ost4k_recover_real_test.rs`.
    let messages: Vec<_> = out
        .iter()
        .filter(|m| m["subtype"] == "email_message" && m.get("recovered").is_none())
        .collect();
    assert_eq!(messages.len(), 14);

    let mut informant = 0;
    for (folder, subject, from, when) in KNOWN {
        let m = messages
            .iter()
            .find(|m| {
                m["subject"] == *subject && m["folder_path"].as_str().unwrap().ends_with(folder)
            })
            .unwrap_or_else(|| panic!("{folder}/{subject} not emitted"));
        assert!(
            m["date"].as_str().unwrap().starts_with(when),
            "{subject}: {}",
            m["date"]
        );
        assert_eq!(m["store_version"], 36);
        if *from == "iaman.informant@nist.gov" {
            // The informant's own sent mail holds no SMTP address, so the
            // key's address is not what is published: `from` is the Exchange
            // X.500 DN and only the display name matches the key (EMAIL-001).
            assert_eq!(m["from_name"], "iaman", "{subject}");
            assert!(
                m["from"].as_str().unwrap().ends_with("-iaman"),
                "{subject}: {}",
                m["from"]
            );
            informant += 1;
        } else {
            assert_eq!(m["from"], *from, "{subject}");
        }
    }
    assert_eq!(informant, 5, "the informant's own messages in the key");
    let hello = messages
        .iter()
        .find(|m| m["subject"] == "Hello, Iaman")
        .unwrap();
    assert_eq!(hello["from"], "spy.conspirator@nist.gov");
    assert_eq!(hello["from_name"], "spy");
    assert_eq!(hello["to"], serde_json::json!(["iaman"]));
    assert_eq!(hello["folder_path"], "Root - Mailbox/IPM_SUBTREE/Inbox");
    assert!(hello["message_id"]
        .as_str()
        .unwrap()
        .contains("BN1PR09MB0156"));
    // The key's body, from the HTML body, and the record says so.
    assert!(
        hello["body_text"]
            .as_str()
            .unwrap()
            .contains("How are you doing?"),
        "{}",
        hello["body_text"]
    );
    assert_eq!(hello["body_source"], "html");
    assert!(hello["body_html"].as_str().unwrap().starts_with("<html"));
    assert!(hello.get("content_incomplete").is_none());

    let watch = messages
        .iter()
        .find(|m| m["subject"] == "RE: Watch out!")
        .unwrap();
    // This keyed message does hold a plain body (and no HTML body), so not
    // every keyed message's body comes from HTML.
    assert!(watch["body_text"]
        .as_str()
        .unwrap()
        .contains("I am trying."));
    assert_eq!(watch["body_source"], "text");

    // The three Sync Issues messages hold only a compressed-RTF body
    // (PidTagRtfCompressed, 0x1009), which this build does not decode. The
    // record must say the body was present and not read, not that there was
    // none.
    let sync: Vec<_> = messages
        .iter()
        .filter(|m| {
            m["folder_path"]
                .as_str()
                .unwrap_or_default()
                .ends_with("/Sync Issues")
        })
        .collect();
    assert_eq!(sync.len(), 3);
    for m in sync {
        assert_eq!(m["body_source"], "rtf_not_decoded", "{m}");
        assert_eq!(m["body_text"], "", "{m}");
        assert_eq!(m["content_incomplete"], true, "{m}");
        assert_eq!(m["content_incomplete_reason"], "compressed", "{m}");
    }

    let s: Vec<_> = out
        .iter()
        .filter(|m| m["subtype"] == "pst_summary")
        .collect();
    assert_eq!(s.len(), 1);
    let s = s[0];
    assert_eq!(s["pst_variant"], "ost_v36");
    assert_eq!(s["store_version"], 36);
    assert_eq!(s["message_count"], 14);
    assert_eq!(s["btree_pages_walked"], 9);
    assert_eq!(s["blocks_in_bbt"], 381);
    assert_eq!(s["blocks_verified"], 381);
    assert_eq!(s["blocks_inflated"], 123);
    assert_eq!(s["page_faults"], serde_json::json!([]));
    assert_eq!(s["block_faults"], serde_json::json!([]));
    assert_eq!(s["bytes_supplied"], 3_360_768);
    assert_eq!(s["header_file_eof"], 16_818_176);
    assert_eq!(s["folder_count_mismatches"], serde_json::json!([]));
    assert!(s.get("content_incomplete").is_none(), "{s}");
    assert!(
        s["name"]
            .as_str()
            .unwrap()
            .starts_with("OST (version 36): 14 messages"),
        "{}",
        s["name"]
    );
    // The prefix is shorter than the header says the file is; the summary
    // says so without claiming anything referenced is missing.
    let note = s["store_note"].as_str().unwrap();
    assert!(note.contains("shorter than"), "{note}");
    // What neither tree references (where NIST's twelfth message lies) is
    // walked within the bytes supplied (§3.10); past them it could not be,
    // and the note says so.
    assert!(
        note.contains("neither B-tree references") && note.contains("not examined"),
        "{note}"
    );
}

/// The real file cut short, as a disk image cuts a file at its initialised
/// length. In this file every page and block the B-trees reference lies
/// between 0x23000 and 0x98000 (the non-zero data above that, up to
/// 0x334000, is referenced by neither tree), with the two roots at the top of
/// that range. So:
///
/// * cut at 0x92000, both trees are whole and one block (at 0x97000) is past
///   the cut;
/// * cut at 0x80000, both roots are past the cut and nothing can be walked;
/// * with 0x60000..0x76000 zeroed — what an image reads where a file was not
///   initialised; a mechanism test on real bytes, not a second real file —
///   the trees are whole and the message nodes whose data lay there are
///   named as unreadable.
///
/// Each time the summary names what it could not reach and marks the mailbox
/// incomplete; it never presents what it did read as the whole.
#[test]
fn a_truncated_v36_store_reports_the_uninitialised_extent() {
    let data = fixture();
    let summary = |out: &[serde_json::Value]| {
        out.iter()
            .find(|m| m["subtype"] == "pst_summary")
            .cloned()
            .expect("a summary")
    };

    let s = summary(&run_parse(&data[..0x92000]));
    assert_eq!(s["content_incomplete"], true, "{s}");
    assert_eq!(s["content_incomplete_reason"], "short_read");
    assert_eq!(s["page_faults"], serde_json::json!([]));
    assert_eq!(s["btree_pages_walked"], 9);
    assert_eq!(s["blocks_unwritten"], 1);
    assert_eq!(s["blocks_verified"], 380);
    assert!(s["block_faults"][0]
        .as_str()
        .unwrap()
        .contains("at 0x97000 lies past the bytes supplied"));
    assert_eq!(s["bytes_supplied"], 0x92000);
    assert!(s["message"]
        .as_str()
        .unwrap()
        .contains("not initialised on the image"));

    let s = summary(&run_parse(&data[..0x80000]));
    assert_eq!(s["content_incomplete"], true, "{s}");
    let faults = s["page_faults"].as_array().unwrap();
    assert_eq!(faults.len(), 2, "{faults:?}");
    assert!(
        faults
            .iter()
            .all(|f| f.as_str().unwrap().contains("past the")),
        "{faults:?}"
    );
    assert_eq!(s["pages_unwritten"], 2);
    assert_eq!(s["message_count"], 0);
    assert!(s["name"].as_str().unwrap().contains("0 messages"));

    let mut holed = data.clone();
    holed[0x60000..0x76000].fill(0);
    let out = run_parse(&holed);
    let s = summary(&out);
    assert_eq!(s["content_incomplete"], true, "{s}");
    assert_eq!(s["page_faults"], serde_json::json!([]));
    assert!(s["blocks_unwritten"].as_u64().unwrap() > 0);
    let lost = s["messages_unreadable"].as_u64().unwrap();
    assert!(lost > 0, "{s}");
    assert_eq!(s["message_count"].as_u64().unwrap() + lost, 14, "{s}");
    assert!(
        s["message"].as_str().unwrap().contains("reads as zeros"),
        "{}",
        s["message"]
    );
}

/// What the image itself hands over: the whole 16,818,176-byte file, whose
/// bytes past the initialised length read as zeros. Verified on extraction —
/// the Sleuth Kit copy of the whole file is this fixture followed by nothing
/// but zeros (README) — so padding the fixture rebuilds it exactly. Nothing
/// the trees reference is in the zeros, so the mailbox is whole and the
/// summary does not call it short.
#[test]
fn the_whole_file_as_the_image_reads_it_gives_the_same_mailbox() {
    let mut whole = fixture();
    whole.resize(16_818_176, 0);
    let out = run_parse(&whole);
    let s = out.iter().find(|m| m["subtype"] == "pst_summary").unwrap();
    assert_eq!(s["message_count"], 14);
    assert_eq!(s["bytes_supplied"], 16_818_176);
    assert!(s.get("content_incomplete").is_none(), "{s}");
    let note = s["store_note"].as_str().unwrap();
    assert!(!note.contains("shorter than"));
    // Nothing is missing from what the trees reference, but the space they do
    // not reference was not looked at, and the note says so.
    assert!(
        note.contains("neither B-tree references") && note.contains("not examined"),
        "{note}"
    );
}

/// The `ost4k_parser` fuzz seed (`fuzz/gen_seeds.py`): the file cut at
/// 0x98000 with the roots given directly. It must reach the whole mailbox, or
/// the fuzzer's mutations never reach the XBLOCK, heap and property-context
/// readers.
#[test]
fn the_fuzz_seed_extent_reaches_every_message() {
    use seance_plugin_email::ost4k::mailbox::read_mailbox;
    use seance_plugin_email::ost4k::ndb::Ndb;
    use seance_plugin_email::ost4k::Bref;

    let data = fixture();
    let cut = &data[..0x98000];
    let ndb = Ndb::from_roots(
        cut,
        Bref {
            bid: 0x36EB,
            ib: 0x90000,
        },
        Bref {
            bid: 0x36F0,
            ib: 0x91000,
        },
    );
    assert!(ndb.nbt.faults.is_empty() && ndb.bbt.faults.is_empty());
    let mb = read_mailbox(&ndb);
    assert!(mb.nodes_unreadable.is_empty(), "{:?}", mb.nodes_unreadable);
    assert_eq!(mb.messages.len(), 14);
}
