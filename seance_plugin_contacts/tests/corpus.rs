//! The corpus-diff half of ROADMAP §1.4a for this crate: the real address books
//! the validated ranges were read from, parsed through the product path, so a
//! parser that falls behind their schema fails here rather than going quiet.
//!
//! Gates (each skips loudly when unset and panics when it names a missing path):
//!
//! * `SEANCE_ANDROID2022_TREE` — the `data/` directory extracted from the Magnet
//!   2022 Android CTF image (`~/ctf-evidence/android2022/android.tar`).
//! * `SEANCE_IOS2022_TREE` — the root of the Magnet 2022 iOS full-file-system
//!   extraction (`~/ctf-evidence/ios2022ffs/.../*_files_full.zip`), with the
//!   `-wal` sidecars beside each database: the AddressBook's main file is a
//!   single empty page and its whole schema lives in the WAL.
//!
//! Both real address books hold zero contacts. That is the evidence, not a
//! shortfall, and the expectation is written as such: the version resolves,
//! every required column resolves, no stale marker is owed, and the summary says
//! zero.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
    test_support::corpus,
};
use seance_plugin_contacts::ContactsParser;
use std::sync::Arc;

fn parse(path: &std::path::Path) -> Vec<Artifact> {
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.to_path_buf()).unwrap());
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": name, "path": path.display().to_string() }),
    );
    ContactsParser.process(&artifact).unwrap()
}

fn stale_messages(out: &[Artifact]) -> Vec<String> {
    out.iter()
        .filter(|a| a.metadata["type"] == "ParserStaleWarning")
        .map(|a| a.metadata["message"].to_string())
        .collect()
}

fn summary(out: &[Artifact]) -> &Artifact {
    out.iter()
        .find(|a| a.metadata["subtype"] == "summary")
        .expect("an address book yields a summary")
}

/// `contacts2.db`: `PRAGMA user_version` 1300, `raw_contacts` / `data` /
/// `mimetypes` with every column this parser reads, zero contacts.
#[test]
fn the_android2022_contacts_store_parses_inside_its_validated_range() {
    let Some(path) = corpus::file(
        "SEANCE_ANDROID2022_TREE",
        "data/com.android.providers.contacts/databases/contacts2.db",
    ) else {
        return;
    };
    let out = parse(&path);
    assert!(
        stale_messages(&out).is_empty(),
        "{:?}",
        stale_messages(&out)
    );
    let s = summary(&out);
    assert_eq!(s.metadata["platform"], "Android");
    assert_eq!(s.metadata["contact_count"], 0);
    assert!(s.metadata.get("content_incomplete").is_none());
}

/// `AddressBook.sqlitedb`: `_SqliteDatabaseProperties._ClientVersion` 83 (its
/// `user_version` is 0), `ABPerson` / `ABMultiValue` with every column this
/// parser reads, zero people.
#[test]
fn the_ios2022_address_book_parses_inside_its_validated_range() {
    let Some(path) = corpus::file(
        "SEANCE_IOS2022_TREE",
        "private/var/mobile/Library/AddressBook/AddressBook.sqlitedb",
    ) else {
        return;
    };
    assert!(
        path.with_extension("sqlitedb-wal").is_file(),
        "the AddressBook's schema lives in its WAL; the corpus must carry the sidecar"
    );
    let out = parse(&path);
    assert!(
        stale_messages(&out).is_empty(),
        "{:?}",
        stale_messages(&out)
    );
    let s = summary(&out);
    assert_eq!(s.metadata["platform"], "iOS");
    assert_eq!(s.metadata["contact_count"], 0);
    assert!(s.metadata.get("content_incomplete").is_none());
}
