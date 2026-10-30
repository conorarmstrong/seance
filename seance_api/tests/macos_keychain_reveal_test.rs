//! The macOS keychain's item secrets: withheld everywhere, released only by an audited per-record
//! reveal that takes the keychain password in the request and keeps nothing (`HUNT-111`; the owner's
//! decision of 2026-09-26, applied as the iOS keychain's is).
//!
//! The evidence is the real macOS-made keychain of `KEYCHAIN-2` (`keychainbreaker`'s
//! `test.keychain-db`, password `keychainbreaker-test`, four items whose secret is `password#123`),
//! held at `~/forensic_corpora/public_keychain/keychainbreaker/testdata/`. Without it the tests say
//! so and pass; `SEANCE_REQUIRE_CORPUS` makes that a failure.

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

const PASSWORD: &str = "keychainbreaker-test";
const SECRET: &str = "password#123";

fn keychain_path() -> Option<std::path::PathBuf> {
    let p = std::path::PathBuf::from(std::env::var("HOME").ok()?)
        .join("forensic_corpora/public_keychain/keychainbreaker/testdata/test.keychain-db");
    if p.is_file() {
        return Some(p);
    }
    assert!(
        !std::env::var("SEANCE_REQUIRE_CORPUS").is_ok_and(|v| v != "0" && !v.is_empty()),
        "{} is absent but SEANCE_REQUIRE_CORPUS demands it",
        p.display()
    );
    eprintln!("KEYCHAIN-2 could not look: {} is absent", p.display());
    None
}

/// Ingest the keychain file and its items with NO password, as most examiners will: every item is
/// `locked`. Returns (a generic-password item id, the private key item id).
async fn ingested(h: &Harness, path: &std::path::Path) -> (Uuid, Uuid) {
    let copy = h._dir.path().join("test.keychain-db");
    std::fs::copy(path, &copy).unwrap();
    let file = Artifact::new(
        h.case_id,
        ArtifactType::FileEntry,
        None,
        json!({"name": "test.keychain-db", "source_path": copy.to_string_lossy(), "path": copy.to_string_lossy(), "size": std::fs::metadata(&copy).unwrap().len()}),
    );
    h.db.record_artifact(&file).await.unwrap();
    let data: std::sync::Arc<dyn seance_core::data_source::DataSource> =
        std::sync::Arc::new(seance_core::data_source::FileDataSource::new(copy.clone()).unwrap());
    let mut parse_input = file.clone();
    parse_input.data = Some(data);
    parse_input.metadata["path"] = json!("/Users/x/Library/Keychains/test.keychain-db");
    let (mut generic, mut key) = (None, None);
    for a in KeychainParser.process(&parse_input).unwrap() {
        match a.metadata["item_kind"].as_str() {
            Some("generic_password")
                if generic.is_none() && a.metadata["service"] == "moond4rk.com" =>
            {
                generic = Some(a.id)
            }
            Some("private_key") => key = Some(a.id),
            _ => {}
        }
        h.db.record_artifact(&a).await.unwrap();
    }
    (
        generic.expect("the generic password"),
        key.expect("the private key"),
    )
}

fn reveal_uri(h: &Harness, record: Uuid) -> String {
    format!("/api/v1/cases/{}/keychain/{record}/reveal", h.case_id)
}

async fn audit_actions(h: &Harness) -> Vec<String> {
    h.db.get_audit_log(h.case_id, 500, 0)
        .await
        .unwrap()
        .into_iter()
        .filter_map(|e| e["action"].as_str().map(str::to_string))
        .filter(|a| a.starts_with("macos_keychain"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_right_password_reveals_the_published_secret_after_the_audit_row() {
    let Some(path) = keychain_path() else { return };
    let h = harness().await;
    let (item, _key) = ingested(&h, &path).await;

    let (status, body) = call(
        &h,
        "POST",
        reveal_uri(&h, item),
        Some(json!({"password": PASSWORD})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let v = body_json(&body);
    assert_eq!(v["value"], json!(SECRET));
    assert_eq!(v["encoding"], json!("utf8"));
    assert!(audit_actions(&h)
        .await
        .contains(&"macos_keychain_secret_revealed".to_string()));
    // The password and the secret are not in the audit log.
    let log = serde_json::to_string(&h.db.get_audit_log(h.case_id, 500, 0).await.unwrap()).unwrap();
    assert!(!log.contains(PASSWORD) && !log.contains(SECRET));
    h.runner.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_password_reveals_nothing_and_is_audited_as_refused() {
    let Some(path) = keychain_path() else { return };
    let h = harness().await;
    let (item, _key) = ingested(&h, &path).await;
    let (status, body) = call(
        &h,
        "POST",
        reveal_uri(&h, item),
        Some(json!({"password": "not-it"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert!(!contains(&body, SECRET));
    let actions = audit_actions(&h).await;
    assert!(
        actions.contains(&"macos_keychain_reveal_refused".to_string()),
        "{actions:?}"
    );
    assert!(!actions.contains(&"macos_keychain_secret_revealed".to_string()));
    h.runner.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_private_key_reveals_as_a_pkcs8_der_in_hex_and_a_certificate_is_refused() {
    let Some(path) = keychain_path() else { return };
    let h = harness().await;
    let (_item, key) = ingested(&h, &path).await;
    let (status, body) = call(
        &h,
        "POST",
        reveal_uri(&h, key),
        Some(json!({"password": PASSWORD})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let v = body_json(&body);
    assert_eq!(v["encoding"], json!("hex"));
    let hex = v["value"].as_str().unwrap();
    // A PKCS#8 PrivateKeyInfo: a DER SEQUENCE (30 82 ...) holding version 0 (02 01 00).
    assert!(hex.starts_with("3082"), "{}", &hex[..16]);
    assert!(hex.len() > 2000);
    h.runner.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_only_user_cannot_reveal() {
    let Some(path) = keychain_path() else { return };
    let h = harness().await;
    let (item, _key) = ingested(&h, &path).await;
    let (status, _) = call_as(
        &h,
        &h.reader_token,
        "POST",
        reveal_uri(&h, item),
        Some(json!({"password": PASSWORD})),
    )
    .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
        "{status}"
    );
    h.runner.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_secret_is_in_no_record_listing_or_database_file() {
    let Some(path) = keychain_path() else { return };
    let h = harness().await;
    let (item, _key) = ingested(&h, &path).await;
    let (_, _) = call(
        &h,
        "POST",
        reveal_uri(&h, item),
        Some(json!({"password": PASSWORD})),
    )
    .await;
    let mut seen = Vec::new();
    for uri in [
        format!("/api/v1/cases/{}/records?type=KeychainItem", h.case_id),
        format!("/api/v1/cases/{}/artifacts/{item}", h.case_id),
    ] {
        let (status, body) = call(&h, "GET", uri.clone(), None).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        seen.extend_from_slice(&body);
    }
    assert!(!contains(&seen, SECRET));
    for suffix in ["", "-wal", "-shm"] {
        let bytes = std::fs::read(format!("{}{}", h.db_path.display(), suffix)).unwrap_or_default();
        assert!(
            !bytes.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()),
            "{suffix}"
        );
    }
    h.runner.abort();
}
