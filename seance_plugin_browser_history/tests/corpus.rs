//! The corpus-diff half of ROADMAP §1.4a for this crate: every real browser
//! store a validated range endpoint was read from, parsed through the product
//! path, with the version, the required columns and a record floor asserted —
//! so a parser that falls behind one of these schemas fails here rather than
//! going quiet.
//!
//! Gates, each skipping loudly when unset and panicking when it names a missing
//! path (`seance_core::test_support::corpus`):
//!
//! * `SEANCE_PLASO_TEST_DATA` — `reference/plaso/test_data` (plaso's own
//!   fixtures: Chrome History at meta.version 20/32/33/36, `cookies.db` at 5,
//!   `Cookies-68.0.3440.106` at 10, `Web Data` at 77, Firefox `places.sqlite`
//!   at user_version 10/23/75, Firefox cookies at 5/12, Safari `History.db`
//!   at 13).
//! * `SEANCE_CHROMEBOOK_TREE` — the Magnet 2021 Chromebook `decrypted/` tree
//!   (History 41, Cookies 11, Web Data 81, Login Data 24).
//! * `SEANCE_ANDROID2022_TREE` — the Magnet 2022 Android `data/` tree (Chrome
//!   History 51, Cookies 16, Web Data 98, Login Data 31).
//! * `SEANCE_MACOS2021_TREE` — the Magnet 2021 macOS tree (Safari History.db
//!   user_version 15).
//! * `SEANCE_IOS2022_TREE` — the Magnet 2022 iOS FFS root (Safari History.db
//!   user_version 16, with its `-wal` beside it).
//!
//! The floors are the counts measured when the ranges were declared; a parse
//! that recovers fewer has broken against that schema.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
    test_support::corpus,
};
use seance_plugin_browser_history::BrowserHistoryParser;
use seance_sqlite_util::{check_corpus, CorpusExpectation};
use std::path::Path;
use std::sync::Arc;

/// One real store: where it is, the name the parser self-selects on, the
/// record subtype it must yield and how many at least.
struct Expectation {
    var: &'static str,
    member: &'static str,
    gate_name: &'static str,
    subtype: &'static str,
    min_records: usize,
}

fn parse(path: &Path, gate_name: &str) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.to_path_buf()).unwrap());
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": gate_name, "path": path.display().to_string() }),
    );
    BrowserHistoryParser.process(&artifact).unwrap()
}

fn check(e: &Expectation) {
    let Some(path) = corpus::file(e.var, e.member) else {
        return;
    };
    let out = parse(&path, e.gate_name);
    let label = format!("{} ({})", e.member, e.var);
    let stale: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["type"] == "ParserStaleWarning")
        .map(|a| a.metadata["message"].to_string())
        .collect();
    assert!(stale.is_empty(), "{label}: {stale:?}");
    let failed: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["status"] == "ParseFailed")
        .map(|a| a.metadata["error"].to_string())
        .collect();
    assert!(failed.is_empty(), "{label}: {failed:?}");
    let records = out
        .iter()
        .filter(|a| a.metadata["subtype"] == e.subtype)
        .count();
    check_corpus(
        &CorpusExpectation {
            label,
            min_records: e.min_records,
        },
        records,
    )
    .unwrap();
}

const PLASO: &str = "SEANCE_PLASO_TEST_DATA";
const CHROMEBOOK: &str = "SEANCE_CHROMEBOOK_TREE";
const ANDROID: &str = "SEANCE_ANDROID2022_TREE";
const MACOS: &str = "SEANCE_MACOS2021_TREE";
const IOS: &str = "SEANCE_IOS2022_TREE";

#[test]
fn every_real_chrome_history_parses_inside_the_validated_range() {
    for (var, member, visits) in [
        (PLASO, "chrome_history/History", 69),
        (PLASO, "chrome_history/History-57.0.2987.133", 1),
        (PLASO, "chrome_history/History-58.0.3029.96", 1),
        (PLASO, "chrome_history/History-59.0.3071.86", 1),
        (CHROMEBOOK, "mount/user/History", 447),
        (
            ANDROID,
            "data/com.android.chrome/app_chrome/Default/History",
            57,
        ),
    ] {
        check(&Expectation {
            var,
            member,
            gate_name: "History",
            subtype: "browser_visit",
            min_records: visits,
        });
    }
}

/// The meta.version 20 store keeps its download path in `full_path` and its
/// URL in `url`; both are recovered, through the candidate lists.
#[test]
fn every_real_chrome_downloads_table_parses_inside_the_validated_range() {
    for (var, member, downloads) in [
        (PLASO, "chrome_history/History", 2),
        (PLASO, "chrome_history/History-57.0.2987.133", 1),
        (PLASO, "chrome_history/History-59.0.3071.86", 1),
        (CHROMEBOOK, "mount/user/History", 2),
        (
            ANDROID,
            "data/com.android.chrome/app_chrome/Default/History",
            2,
        ),
    ] {
        check(&Expectation {
            var,
            member,
            gate_name: "History",
            subtype: "browser_download",
            min_records: downloads,
        });
    }
    if let Some(path) = corpus::file(PLASO, "chrome_history/History") {
        let out = parse(&path, "History");
        let dl = out
            .iter()
            .filter(|a| a.metadata["subtype"] == "browser_download")
            .collect::<Vec<_>>();
        assert!(dl
            .iter()
            .all(|d| d.metadata["source_url_origin"] == "downloads_url"));
        assert!(dl
            .iter()
            .all(|d| !d.metadata["target_path"].as_str().unwrap().is_empty()));
    }
}

/// `cookies.db` (meta.version 5) names its flags `secure` / `httponly` and has
/// no `encrypted_value`; the candidate lists resolve it.
#[test]
fn every_real_chrome_cookie_jar_parses_inside_the_validated_range() {
    for (var, member, cookies) in [
        (PLASO, "cookies.db", 560),
        (PLASO, "Cookies-68.0.3440.106", 5),
        (CHROMEBOOK, "mount/user/Cookies", 996),
        (
            ANDROID,
            "data/com.android.chrome/app_chrome/Default/Cookies",
            144,
        ),
    ] {
        check(&Expectation {
            var,
            member,
            gate_name: "Cookies",
            subtype: "browser_cookie",
            min_records: cookies,
        });
    }
}

#[test]
fn every_real_chrome_web_data_parses_inside_the_validated_range() {
    for (var, member, rows) in [
        (PLASO, "Web Data", 3),
        (CHROMEBOOK, "mount/user/Web Data", 3),
        (
            ANDROID,
            "data/com.android.chrome/app_chrome/Default/Web Data",
            2,
        ),
    ] {
        check(&Expectation {
            var,
            member,
            gate_name: "Web Data",
            subtype: "browser_autofill",
            min_records: rows,
        });
    }
}

/// The chromebook store (meta.version 24) predates `date_last_used`; the
/// android2022 store (31) holds no logins, which is the evidence.
#[test]
fn every_real_chrome_login_store_parses_inside_the_validated_range() {
    for (var, member, logins) in [
        (CHROMEBOOK, "mount/user/Login Data", 1),
        (
            ANDROID,
            "data/com.android.chrome/app_chrome/Default/Login Data",
            0,
        ),
    ] {
        check(&Expectation {
            var,
            member,
            gate_name: "Login Data",
            subtype: "browser_login",
            min_records: logins,
        });
    }
}

#[test]
fn every_real_firefox_places_parses_inside_the_validated_range() {
    for (member, visits, bookmarks) in [
        ("firefox_history/places.sqlite", 1, 91),
        ("firefox_history/places_new.sqlite", 34, 14),
        ("places118.sqlite", 89, 5),
    ] {
        check(&Expectation {
            var: PLASO,
            member,
            gate_name: "places.sqlite",
            subtype: "browser_visit",
            min_records: visits,
        });
        check(&Expectation {
            var: PLASO,
            member,
            gate_name: "places.sqlite",
            subtype: "browser_bookmark",
            min_records: bookmarks,
        });
    }
}

#[test]
fn every_real_firefox_cookie_jar_parses_inside_the_validated_range() {
    for (member, cookies) in [
        ("firefox_cookies/firefox_10_cookies.sqlite", 13),
        ("firefox_cookies/firefox_2_cookies.sqlite", 90),
    ] {
        check(&Expectation {
            var: PLASO,
            member,
            gate_name: "cookies.sqlite",
            subtype: "browser_cookie",
            min_records: cookies,
        });
    }
}

#[test]
fn every_real_safari_history_parses_inside_the_validated_range() {
    for (var, member, visits) in [
        (PLASO, "History.db", 25),
        (MACOS, "Users/eliflatt/Library/Safari/History.db", 203),
        (IOS, "private/var/mobile/Library/Safari/History.db", 44),
    ] {
        check(&Expectation {
            var,
            member,
            gate_name: "History.db",
            subtype: "browser_visit",
            min_records: visits,
        });
    }
}
