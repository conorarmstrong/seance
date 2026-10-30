//! The corpus-diff half of ROADMAP §1.4a for this crate: the real stores the
//! validated ranges were read from, parsed through the product path, with the
//! version and the required columns asserted so a parser that falls behind
//! fails here rather than going quiet.
//!
//! Gated on `SEANCE_ANDROID2022_TREE`, the `data/` directory extracted from the
//! Magnet 2022 Android CTF image (`~/ctf-evidence/android2022/android.tar`).
//! The gate skips loudly when the variable is unset and panics when it names a
//! path that is not there, so a green run never means "compared nothing".

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
    test_support::corpus,
};
use seance_plugin_mobile_device::{AndroidAccountsParser, AndroidTelephonyParser};
use seance_sqlite_util::{check_corpus, CorpusExpectation};
use std::sync::Arc;

fn artifact_for(path: &std::path::Path) -> Artifact {
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.to_path_buf()).unwrap());
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": name, "path": path.display().to_string() }),
    )
}

fn stale_markers(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.metadata["type"] == "ParserStaleWarning")
        .collect()
}

/// `accounts_de.db` carries `user_version` 3 and seven accounts; `accounts_ce.db`
/// carries 10 and the same seven. Both are inside their declared range and
/// every required column resolves, so no stale marker is owed.
#[test]
fn the_android2022_account_stores_parse_inside_their_validated_range() {
    let Some(de) = corpus::file("SEANCE_ANDROID2022_TREE", "system_de/0/accounts_de.db") else {
        return;
    };
    let ce = corpus::file("SEANCE_ANDROID2022_TREE", "system_ce/0/accounts_ce.db").unwrap();
    for (path, label) in [(de, "accounts_de.db v3"), (ce, "accounts_ce.db v10")] {
        let out = AndroidAccountsParser::new()
            .process(&artifact_for(&path))
            .unwrap();
        assert!(
            stale_markers(&out).is_empty(),
            "{label}: {:?}",
            stale_markers(&out)
                .iter()
                .map(|m| &m.metadata["message"])
                .collect::<Vec<_>>()
        );
        let record = out
            .iter()
            .find(|a| a.metadata["source_kind"] == "android_accounts")
            .expect("accounts record");
        let read = record.metadata["accounts_read"].as_u64().unwrap() as usize;
        check_corpus(
            &CorpusExpectation {
                label: label.into(),
                min_records: 7,
            },
            read,
        )
        .unwrap();
        assert_eq!(
            record.metadata["facts"]["google_account"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
}

/// `telephony.db` carries `user_version` 1703944 and one SIM whose `number` is
/// empty and whose ICCID is 20 digits. `imsi` is not a column in this store, and
/// its absence is not drift.
#[test]
fn the_android2022_telephony_store_parses_inside_its_validated_range() {
    let Some(path) = corpus::file(
        "SEANCE_ANDROID2022_TREE",
        "user_de/0/com.android.providers.telephony/databases/telephony.db",
    ) else {
        return;
    };
    let out = AndroidTelephonyParser::new()
        .process(&artifact_for(&path))
        .unwrap();
    assert!(stale_markers(&out).is_empty(), "{out:?}");
    let record = out
        .iter()
        .find(|a| a.metadata["source_kind"] == "android_telephony")
        .expect("telephony record");
    assert_eq!(record.metadata["sims_read"], 1);
    assert_eq!(
        record.metadata["facts"]["iccid"][0].as_str().unwrap().len(),
        20
    );
    assert_eq!(record.metadata["facts"]["carrier"][0], "Tracfone");
    assert!(record.metadata["facts"].get("imsi").is_none());
}

/// `bt_config.conf` (HUNT-188): the file is read whole through the looped read,
/// so all three remembered devices are listed, the Moto 360 first (the answer
/// the CTF key gives for "the first IoT device connected"), and no record
/// carries a shortfall.
#[test]
fn the_android2022_bt_config_lists_every_pairing_and_claims_no_shortfall() {
    let Some(path) = corpus::file("SEANCE_ANDROID2022_TREE", "misc/bluedroid/bt_config.conf")
    else {
        return;
    };
    let out = seance_plugin_mobile_device::AndroidBluetoothParser::new()
        .process(&artifact_for(&path))
        .unwrap();
    let pairings: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["type"] == "BluetoothPairing")
        .collect();
    assert_eq!(pairings.len(), 3);
    assert_eq!(pairings[0].metadata["address"], "d0:5f:b8:33:df:00");
    assert!(out
        .iter()
        .all(|a| a.metadata.get("content_incomplete").is_none()));
}
