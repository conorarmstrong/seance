//! Six public PST stores read end to end and compared with libpff (`HUNT-281`, `HUNT-280`).
//!
//! The stores are published test data of other projects (pstsdk, Apache Tika), held at
//! `~/forensic_corpora/public_pst/stores/` and named by `SEANCE_PUBLIC_PST_CORPUS`; they are pinned by
//! SHA-256 in that corpus's `PROVENANCE.md` and are not in this repository. The answer is libpff's:
//! `tests/fixtures/pst_public/<store>.libpff.tsv`, written by `scripts/oracle/pst_list.py` (pypff),
//! one row per message with its folder, subject and attachment count.
//!
//! What this grades, with two ANSI (version 14) stores and four Unicode (version 23) ones: every message
//! libpff lists is published, in the folder libpff places it in, with its subject and attachment count,
//! and no message libpff does not list is invented. `pstsdk-test_ansi` and `pstsdk-test_unicode` hold
//! messages the linked reader refuses (no recipient table); this crate's own reader publishes them and
//! says so. Without the variable these skip; a named directory missing a store panics.

use std::collections::BTreeMap;
use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_email::EmailParser;
use uuid::Uuid;

/// (folder, subject, attachments) -> how many messages.
type Listing = BTreeMap<(String, String, usize), usize>;

fn libpff(tsv: &str) -> Listing {
    let mut out = Listing::new();
    for line in tsv.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.splitn(5, '\t').collect();
        *out.entry((f[2].to_string(), f[3].to_string(), f[1].parse().unwrap()))
            .or_default() += 1;
    }
    out
}

fn ours(path: &std::path::Path) -> (Listing, Artifact, usize) {
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.to_path_buf()).expect("open"));
    let a = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": name }),
    );
    let out = EmailParser.process(&a).expect("the store parses");
    let mut listing = Listing::new();
    let mut own = 0;
    for m in out
        .iter()
        .filter(|o| o.metadata["subtype"] == "email_message")
    {
        assert!(m.metadata.get("recovered").is_none(), "{}", m.metadata);
        if m.metadata.get("read_by") == Some(&serde_json::json!("own_reader")) {
            own += 1;
        }
        let key = (
            m.metadata["folder_path"].as_str().unwrap().to_string(),
            m.metadata["subject"].as_str().unwrap().to_string(),
            m.metadata["attachment_count"].as_u64().unwrap() as usize,
        );
        *listing.entry(key).or_default() += 1;
    }
    let summary = out.last().unwrap().clone();
    (listing, summary, own)
}

fn grade(store: &str, tsv: &str, version: u64, own_reader: usize) {
    let Some(path) = seance_core::test_support::corpus::file("SEANCE_PUBLIC_PST_CORPUS", store)
    else {
        return;
    };
    let (got, summary, own) = ours(&path);
    assert_eq!(got, libpff(tsv), "{store}: the messages libpff lists");
    assert_eq!(summary.metadata["subtype"], "pst_summary");
    assert_eq!(summary.metadata["messages_unreadable"], 0, "{store}");
    assert!(summary.metadata.get("truncated").is_none(), "{store}");
    assert_eq!(
        summary.metadata["recovery_scanned_version"], version,
        "{store}"
    );
    assert_eq!(
        own, own_reader,
        "{store}: messages read by this crate's own reader"
    );
}

macro_rules! store {
    ($name:ident, $file:literal, $version:literal, $own:literal) => {
        #[test]
        fn $name() {
            grade(
                concat!($file, ".pst"),
                include_str!(concat!("fixtures/pst_public/", $file, ".libpff.tsv")),
                $version,
                $own,
            );
        }
    };
}

store!(
    ansi_pstsdk_sample2_one_message_with_an_attachment,
    "pstsdk-sample2",
    14,
    0
);
store!(
    ansi_pstsdk_test_ansi_message_the_linked_reader_refuses,
    "pstsdk-test_ansi",
    14,
    1
);
store!(unicode_pstsdk_sample1, "pstsdk-sample1", 23, 0);
store!(
    unicode_pstsdk_test_unicode_two_messages_the_linked_reader_refuses,
    "pstsdk-test_unicode",
    23,
    2
);
store!(
    unicode_pstsdk_submessage_embedded_message,
    "pstsdk-submessage",
    23,
    0
);
store!(
    unicode_tika_four_messages_in_html_and_rtf,
    "tika-variousBodyTypes",
    23,
    0
);
