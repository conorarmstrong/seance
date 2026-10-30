//! The recipient tables of four public PST stores read by this crate's own reader and compared with libpff
//! (`HUNT-280`). One ANSI store (`pstsdk-sample2`, version 14) and three Unicode ones (version 23).
//!
//! The answer is libpff's, `tests/fixtures/pst_public/<store>.recipients.tsv`, written by
//! `scripts/oracle/pst_recipients.py` (pypff): one line per recipient, every cell as `tag:type=value`
//! (strings and integers as read, binary as its length). The stores are the published test data of other
//! projects, held at `~/forensic_corpora/public_pst/stores/` (`SEANCE_PUBLIC_PST_CORPUS`); they are not in
//! this repository. Without the variable these skip.

use std::collections::BTreeSet;

use seance_plugin_email::ost4k::ltp::PropValue;
use seance_plugin_email::pst512::Store;

fn cell(tag: u16, v: &PropValue) -> String {
    match v {
        // Unicode strings are type 001f and 8-bit ones (ANSI stores) 001e; both are text here.
        PropValue::Str(s) => format!(
            "{tag:04x}:S={}",
            s.replace('\t', "\\t").replace('\n', "\\n")
        ),
        PropValue::I32(n) => format!("{tag:04x}:0003={n}"),
        PropValue::Bool(b) => format!("{tag:04x}:000b={}", u8::from(*b)),
        PropValue::Bin(b) => format!("{tag:04x}:0102=len{}", b.len()),
        other => format!("{tag:04x}:?={other:?}"),
    }
}

/// libpff lists a cell with no data (existence bit clear, or a value of zero bytes) as an entry with an empty
/// value (`None` for a string, `len0` for binary); this reader does not list a cell whose bit is clear and
/// lists a present empty one as empty. Both sides are compared without the empty cells, which say nothing.
///
/// libpff also answers `0` for an integer or boolean cell whose existence bit is clear (the Enron stores' recipient
/// rows clear the bits of `0ff9`, `0ffe`, `3900`, `39ff`, `3a40` and `0e0f`, read from the row bitmaps `df 80`), and
/// the binding gives no way to tell that from a stored zero. Zero integers and booleans are dropped from both sides
/// for that reason: a present cell holding 0 that this reader omitted would not be seen by this comparison.
fn has_data(c: &str) -> bool {
    !(c.ends_with("=None")
        || c.ends_with("=len0")
        || c.ends_with(":S=")
        || c.ends_with(":0003=0")
        || c.ends_with(":000b=0"))
}

fn grade(store: &str, tsv: &str) {
    let Some(path) = seance_core::test_support::corpus::file("SEANCE_PUBLIC_PST_CORPUS", store)
    else {
        return;
    };
    let data = std::fs::read(path).unwrap();
    let store_reader = Store::open(&data).expect("the store opens");
    let mut checked = 0;
    for line in tsv.lines().filter(|l| !l.starts_with('#')) {
        let mut fields = line.split('\t');
        let nid = u32::from_str_radix(fields.next().unwrap().trim_start_matches("0x"), 16).unwrap();
        let row: usize = fields.next().unwrap().parse().unwrap();
        let want: BTreeSet<String> = fields
            .map(|c| c.replace(":001f=", ":S=").replace(":001e=", ":S="))
            .filter(|c| has_data(c))
            .collect();
        let m = store_reader
            .read_live_message(nid)
            .expect("the message reads");
        let rows = m
            .recipients
            .as_ref()
            .unwrap_or_else(|| panic!("{store} {nid:#x}: no recipient table read; {:?}", m.gaps));
        let got: BTreeSet<String> = rows[row]
            .iter()
            .map(|(t, v)| cell(*t, v))
            .filter(|c| has_data(c))
            .collect();
        assert_eq!(got, want, "{store} message {nid:#x} recipient {row}");
        checked += 1;
    }
    assert!(checked > 0, "{store}: the oracle lists no recipient");
}

macro_rules! store {
    ($name:ident, $file:literal) => {
        store!($name, $file, $file);
    };
    ($name:ident, $file:literal, $answers:literal) => {
        #[test]
        fn $name() {
            grade(
                concat!($file, ".pst"),
                include_str!(concat!("fixtures/pst_public/", $answers, ".recipients.tsv")),
            );
        }
    };
}

store!(ansi_pstsdk_sample2_recipient_table, "pstsdk-sample2");
store!(unicode_pstsdk_sample1_recipient_table, "pstsdk-sample1");
store!(
    unicode_pstsdk_submessage_recipient_table,
    "pstsdk-submessage"
);
store!(unicode_tika_four_recipient_tables, "tika-variousBodyTypes");
// A Unicode store of an Enron mailbox (EDRM v2, CC BY 3.0 US): four messages with 82 to 144 recipients, whose
// row matrix no longer fits one 8,176-byte heap allocation (`HUNT-280`, `PST-PUBLIC-4`).
store!(unicode_enron_many_recipient_tables, "enron-bailey-s");
// Messages of 338, 356 and 384 recipients: a row matrix of some 20 KB, held in a subnode of several blocks.
store!(unicode_enron_subnode_matrix_dean, "enron-dean-c2");
store!(unicode_enron_subnode_matrix_harris, "enron-harris-s");

// Cyclic ("high") encryption (bCryptMethod 2), which no public store uses: three of the stores above re-encoded by
// `scripts/synth/pst_to_cyclic.py` (written from MS-PST 5.1 and 5.2) and read by libpff identically to their originals
// (`PST-CYCLIC-1`). The recipient rows are the originals' answers, so a wrong key anywhere breaks a cell.
store!(
    cyclic_pstsdk_sample1_recipient_table,
    "pstsdk-sample1.cyclic",
    "pstsdk-sample1"
);
store!(
    cyclic_ansi_pstsdk_sample2_recipient_table,
    "pstsdk-sample2.cyclic",
    "pstsdk-sample2"
);
store!(
    cyclic_tika_four_recipient_tables,
    "tika-variousBodyTypes.cyclic",
    "tika-variousBodyTypes"
);

/// Version 36 (an Outlook 2013 OST), end to end: the three messages of `javalibpst-example-2013.ost`
/// each publish the recipient libpff lists, with its type, name, address type and address.
#[test]
fn version_36_ost_messages_publish_their_recipient_tables() {
    use seance_core::artifact::{Artifact, ArtifactType};
    use seance_core::data_source::{DataSource, FileDataSource};
    use seance_core::module::ForensicsModule;
    let Some(path) = seance_core::test_support::corpus::file(
        "SEANCE_PUBLIC_PST_CORPUS",
        "javalibpst-example-2013.ost",
    ) else {
        return;
    };
    let ds: std::sync::Arc<dyn DataSource> =
        std::sync::Arc::new(FileDataSource::new(path).expect("open"));
    let a = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": "example-2013.ost" }),
    );
    let out = seance_plugin_email::EmailParser
        .process(&a)
        .expect("parses");
    let tsv = include_str!("fixtures/pst_public/javalibpst-example-2013.recipients.tsv");
    let mut checked = 0;
    for line in tsv.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split('\t').collect();
        let cells: std::collections::BTreeMap<&str, &str> = f[2..]
            .iter()
            .filter_map(|c| c.split_once('='))
            .map(|(k, v)| (k.split(':').next().unwrap(), v))
            .collect();
        let msg = out
            .iter()
            .find(|o| o.metadata["subtype"] == "email_message" && o.metadata["node_id"] == f[0])
            .unwrap_or_else(|| panic!("no message {}", f[0]));
        assert_eq!(
            msg.metadata["recipients_read"],
            serde_json::json!(true),
            "{}",
            f[0]
        );
        let r = &msg.metadata["recipients"][f[1].parse::<usize>().unwrap()];
        let kind = match cells["0c15"] {
            "1" => "to",
            "2" => "cc",
            "3" => "bcc",
            _ => "other",
        };
        assert_eq!(r["type"], kind);
        assert_eq!(r["name"], cells["3001"]);
        assert_eq!(r["address_type"], cells["3002"]);
        assert_eq!(r["address"], cells["3003"]);
        checked += 1;
    }
    assert_eq!(checked, 3);
}
