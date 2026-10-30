//! An Outlook 97-2002 (ANSI) store with Japanese text, graded against its Unicode twin (`HUNT-281`).
//!
//! `pst-extractor-contacts97-2002.pst` and `pst-extractor-contacts.pst` hold the same contact whose name is
//! Japanese (test data of the pst-extractor project, MIT; `tests/fixtures/pst_public/PROVENANCE.md`). The
//! Unicode store keeps the text as UTF-16, so it is the answer for the ANSI store, which keeps Shift-JIS bytes
//! and declares no code page: its message carries a locale (1041, Japanese) and an Internet code page (50220,
//! ISO-2022-JP). The stores are held at `~/forensic_corpora/public_pst/stores/` (`SEANCE_PUBLIC_PST_CORPUS`)
//! and are not in this repository. Without the variable these skip.

use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_email::EmailParser;
use uuid::Uuid;

fn read(store: &str) -> Option<Vec<Artifact>> {
    let path = seance_core::test_support::corpus::file("SEANCE_PUBLIC_PST_CORPUS", store)?;
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).expect("open"));
    let a = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": store }),
    );
    Some(EmailParser.process(&a).expect("the store parses"))
}

fn message(out: &[Artifact]) -> &Artifact {
    let mut messages = out
        .iter()
        .filter(|o| o.metadata["subtype"] == "email_message");
    let m = messages.next().expect("one message");
    assert!(messages.next().is_none());
    m
}

fn summary(out: &[Artifact]) -> &Artifact {
    out.iter()
        .find(|o| o.metadata["subtype"] == "pst_summary")
        .expect("a summary")
}

/// The contact's subject and its folder path read from the ANSI store are the Unicode store's, character for
/// character, and the record says the code page was inferred from the message's locale, not declared.
#[test]
fn the_ansi_japanese_contact_reads_as_its_unicode_twin_and_says_how_the_code_page_was_chosen() {
    let (Some(ansi), Some(twin)) = (
        read("pst-extractor-contacts97-2002.pst"),
        read("pst-extractor-contacts.pst"),
    ) else {
        return;
    };
    let (a, u) = (message(&ansi), message(&twin));
    assert_eq!(a.metadata["subject"], u.metadata["subject"]);
    assert_eq!(a.metadata["subject"], "コム ドット イグザンプル 殿");
    assert_eq!(a.metadata["folder_path"], u.metadata["folder_path"]);
    assert_eq!(a.metadata["message_class"], u.metadata["message_class"]);
    let legacy = &a.metadata["legacy_8bit_text"];
    assert_eq!(legacy["codepage"], "shift_jis");
    assert_eq!(legacy["codepage_declared"], false);
    assert_eq!(legacy["codepage_basis"], "message_locale_id");
    assert_eq!(legacy["decoding_lossy"], false);
    assert!(
        u.metadata.get("legacy_8bit_text").is_none(),
        "the Unicode store holds no 8-bit text"
    );
}

/// The ANSI store's folder names are decoded in the page its messages imply, so the summary lists the
/// names the Unicode store spells.
#[test]
fn the_ansi_stores_folder_names_are_the_unicode_stores() {
    let (Some(ansi), Some(twin)) = (
        read("pst-extractor-contacts97-2002.pst"),
        read("pst-extractor-contacts.pst"),
    ) else {
        return;
    };
    let names = summary(&ansi).metadata["folders_8bit_names"].clone();
    assert_eq!(
        names,
        serde_json::json!([
            "Outlook データ ファイルのトップ",
            "削除済みアイテム",
            "連絡先 (Contact dedicated)"
        ])
    );
    let folder = message(&twin).metadata["folder_path"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        folder.starts_with("Outlook データ ファイルのトップ/"),
        "{folder}"
    );
}
