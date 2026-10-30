//! `System.keychain` revealed with the Mac's `/var/db/SystemKey` instead of a password (`HUNT-111`,
//! `VALIDATION.md` `KEYCHAIN-3`). Same audited per-record reveal as `macos_keychain_reveal_test.rs`; the
//! request carries `{"system_key": "<hex of the 48 bytes>"}` and keeps nothing.
//!
//! The evidence is the macOS 11.2.1 `System.keychain` and `SystemKey` of Josh Hickman's Big Sur image,
//! held at `~/forensic_corpora/found_macos_bigsur/extract/`. The guest-account password is the one
//! chainbreaker prints for the same pair. Without the corpus the tests say so and pass;
//! `SEANCE_REQUIRE_CORPUS` makes that a failure.

#[path = "support/ios_backup_harness.rs"]
mod support;

use axum::http::StatusCode;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_core::module::ForensicsModule;
use seance_plugin_macos_artifacts::KeychainParser;
use serde_json::json;
use support::*;
use uuid::Uuid;

const SECRET: &str = "AlSPT2l:1VMGGtTI";

fn evidence() -> Option<(std::path::PathBuf, String)> {
    let root = std::path::PathBuf::from(std::env::var("HOME").ok()?)
        .join("forensic_corpora/found_macos_bigsur/extract");
    let kc = root.join("Library/Keychains/System.keychain");
    let sk = root.join("private/var/db/SystemKey");
    match (kc.is_file(), std::fs::read(&sk)) {
        (true, Ok(key)) => Some((
            kc,
            key.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        )),
        _ => {
            assert!(
                !std::env::var("SEANCE_REQUIRE_CORPUS").is_ok_and(|v| v != "0" && !v.is_empty()),
                "{} is absent but SEANCE_REQUIRE_CORPUS demands it",
                root.display()
            );
            eprintln!("KEYCHAIN-3 could not look: {} is absent", root.display());
            None
        }
    }
}

/// Ingest `System.keychain` with no credential; returns the guest-account generic password's id.
async fn ingested(h: &Harness, path: &std::path::Path) -> Uuid {
    let copy = h._dir.path().join("System.keychain");
    std::fs::copy(path, &copy).unwrap();
    let file = Artifact::new(
        h.case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "System.keychain", "source_path": copy.to_string_lossy(), "path": copy.to_string_lossy(), "size": std::fs::metadata(&copy).unwrap().len()}),
    );
    h.db.record_artifact(&file).await.unwrap();
    let data: std::sync::Arc<dyn seance_core::data_source::DataSource> =
        std::sync::Arc::new(seance_core::data_source::FileDataSource::new(copy.clone()).unwrap());
    let mut parse_input = file.clone();
    parse_input.data = Some(data);
    parse_input.metadata["path"] = json!("/Library/Keychains/System.keychain");
    let mut guest = None;
    for a in KeychainParser.process(&parse_input).unwrap() {
        if a.metadata["item_kind"] == "generic_password" && a.metadata["account"] == "Guest" {
            guest = Some(a.id);
        }
        h.db.record_artifact(&a).await.unwrap();
    }
    guest.expect("the guest-account generic password")
}

fn reveal_uri(h: &Harness, record: Uuid) -> String {
    format!("/api/v1/cases/{}/keychain/{record}/reveal", h.case_id)
}

async fn audit_log(h: &Harness) -> Vec<serde_json::Value> {
    h.db.get_audit_log(h.case_id, 500, 0).await.unwrap()
}

fn actions(log: &[serde_json::Value]) -> Vec<String> {
    log.iter()
        .filter_map(|e| e["action"].as_str().map(str::to_string))
        .filter(|a| a.starts_with("macos_keychain"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_system_key_reveals_the_secret_after_the_audit_row_and_is_not_logged() {
    let Some((path, key_hex)) = evidence() else {
        return;
    };
    let h = harness().await;
    let item = ingested(&h, &path).await;
    let (status, body) = call(
        &h,
        "POST",
        reveal_uri(&h, item),
        Some(json!({"system_key": key_hex})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let v = body_json(&body);
    assert_eq!(v["value"], json!(SECRET));
    let log = audit_log(&h).await;
    assert!(actions(&log).contains(&"macos_keychain_secret_revealed".to_string()));
    let text = serde_json::to_string(&log).unwrap();
    assert!(text.contains("kind=macos_system_key"), "{text}");
    assert!(!text.contains(&key_hex) && !text.contains(&key_hex[16..64]) && !text.contains(SECRET));
    h.runner.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_system_key_a_malformed_one_and_both_credentials_reveal_nothing() {
    let Some((path, key_hex)) = evidence() else {
        return;
    };
    let h = harness().await;
    let item = ingested(&h, &path).await;
    // Byte 20 is inside the key window; 0x80 is not the DES parity bit.
    let mut wrong = key_hex.clone();
    wrong.replace_range(
        40..42,
        &format!(
            "{:02x}",
            u8::from_str_radix(&key_hex[40..42], 16).unwrap() ^ 0x80
        ),
    );
    for body_json_in in [
        json!({"system_key": wrong}),
        json!({"system_key": "zz"}),
        json!({"system_key": key_hex, "password": "x"}),
        json!({}),
    ] {
        let (status, body) = call(&h, "POST", reveal_uri(&h, item), Some(body_json_in)).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert!(!contains(&body, SECRET));
    }
    let acts = actions(&audit_log(&h).await);
    assert!(
        acts.contains(&"macos_keychain_reveal_refused".to_string()),
        "{acts:?}"
    );
    assert!(!acts.contains(&"macos_keychain_secret_revealed".to_string()));
    h.runner.abort();
}
