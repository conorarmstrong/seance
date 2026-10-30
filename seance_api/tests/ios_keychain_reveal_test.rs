//! The iOS backup keychain's secrets: withheld everywhere, released only by an
//! audited per-record reveal (HUNT-111; the owner's decision of 2026-09-26).
//!
//! A keychain item read from an encrypted backup's `keychain-backup.plist`
//! carries its attributes in the clear, but its secret (`v_Data` — a saved
//! password, a token, a key) is never stored: not in the record, the database,
//! a listing, an export. The reveal re-derives it from the backup while the
//! backup is unlocked for reading in this case, writes the audit row first, and
//! refuses if that write fails.
//!
//! The backup is **synthetic** (`seance_plugin_ios_backup::test_support`): it
//! pins the mechanism — the route, the audit order, where the secret must not
//! land — and is not validation of decryption against a real device's backup
//! (that is `IOS-KEYCHAIN-1`, which withholds and so reveals nothing).

#[path = "support/ios_backup_harness.rs"]
mod support;

use axum::http::StatusCode;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_core::module::ForensicsModule;
use seance_plugin_ios_backup::test_support::build_keychain_backup;
use seance_plugin_ios_backup::IosBackupParser;
use serde_json::{json, Value};
use support::*;
use uuid::Uuid;

const SECRET: &str = "Kc-s3cret-9f41d7-wifi-passphrase";

/// Ingest the synthetic keychain backup with its password, as the credential
/// route leaves it. Returns (backup dir, password, readable item, device-bound
/// item).
async fn ingested_keychain(h: &Harness) -> (std::path::PathBuf, String, Uuid, Uuid) {
    let (backup, password) = build_keychain_backup(SECRET.as_bytes());
    let folder = Artifact::new(
        h.case_id,
        ArtifactType::RawEvidence,
        None,
        json!({
            "name": "00008030-00AA11BB22CC33DD",
            "path": backup.to_string_lossy(),
            "is_directory": true,
        }),
    );
    h.db.record_artifact(&folder).await.unwrap();
    let (mut readable, mut bound) = (None, None);
    for a in IosBackupParser::with_password(password.clone())
        .process(&folder)
        .unwrap()
    {
        if a.metadata["type"] == "IosKeychainItem" {
            match a.metadata["state"].as_str() {
                Some("read") => readable = Some(a.id),
                Some("device_bound") => bound = Some(a.id),
                _ => {}
            }
        }
        h.db.record_artifact(&a).await.unwrap();
    }
    (
        backup,
        password,
        readable.expect("the readable item"),
        bound.expect("the device-bound item"),
    )
}

fn reveal_uri(h: &Harness, record: Uuid) -> String {
    format!("/api/v1/cases/{}/keychain/{record}/reveal", h.case_id)
}

fn db_files_hold(h: &Harness, needle: &str) -> bool {
    ["", "-wal", "-shm"].iter().any(|suffix| {
        std::fs::read(format!("{}{}", h.db_path.display(), suffix))
            .map(|bytes| contains(&bytes, needle))
            .unwrap_or(false)
    })
}

async fn reveal_rows(h: &Harness) -> Vec<Value> {
    h.db.get_audit_log(h.case_id, 500, 0)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e["action"] == json!("ios_keychain_secret_revealed"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ios_keychain_secret_absent_from_records_listing_export_and_search() {
    let h = harness().await;
    let (backup, _password, item, _bound) = ingested_keychain(&h).await;

    let mut seen = Vec::new();
    for uri in [
        format!("/api/v1/cases/{}/records?type=IosKeychainItem", h.case_id),
        format!(
            "/api/v1/cases/{}/records/export/csv?type=IosKeychainItem",
            h.case_id
        ),
        format!("/api/v1/cases/{}/artifacts/{item}", h.case_id),
    ] {
        let (status, body) = call(&h, "GET", uri.clone(), None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{uri}: {}",
            String::from_utf8_lossy(&body)
        );
        seen.extend_from_slice(&body);
    }
    // The listing is live — the account is there — and the secret is not.
    assert!(contains(&seen, "HomeNetwork"));
    assert!(contains(&seen, "withheld"));
    assert!(!contains(&seen, SECRET));
    let secret_hex: String = SECRET.bytes().map(|b| format!("{b:02x}")).collect();
    assert!(!contains(&seen, &secret_hex));
    // Not at rest either: nothing the case database holds (which is what the
    // search index and every export are built from) carries it.
    assert!(
        !db_files_hold(&h, SECRET),
        "the secret reached the case database"
    );

    h.runner.abort();
    let _ = std::fs::remove_dir_all(&backup);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ios_keychain_reveal_writes_audit_before_value() {
    let h = harness().await;
    let (backup, password, item, bound) = ingested_keychain(&h).await;

    // Locked: refused, the refusal names the unlock route, nothing audited
    // as revealed.
    let (status, body) = call(&h, "POST", reveal_uri(&h, item), None).await;
    assert_ne!(status, StatusCode::OK);
    let text = String::from_utf8_lossy(&body).to_string();
    assert!(text.contains("/unlock"), "{text}");
    assert!(!text.contains(SECRET));
    assert!(reveal_rows(&h).await.is_empty());

    // Unlock through the keychain record itself.
    let (status, body) = call(
        &h,
        "POST",
        unlock_uri(&h, item),
        Some(json!({ "kind": "ios_backup_password", "secret": password })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

    // A read-only grant cannot reveal.
    let (status, _) = call_as(
        &h,
        &h.reader_token.clone(),
        "POST",
        reveal_uri(&h, item),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(reveal_rows(&h).await.is_empty());

    // Revealed: the value, and one audit row naming who and which record —
    // never the value.
    let (status, body) = call(&h, "POST", reveal_uri(&h, item), None).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let v = body_json(&body);
    assert_eq!(v["value"], SECRET, "{v}");
    assert_eq!(v["encoding"], "utf8", "{v}");
    let rows = reveal_rows(&h).await;
    assert_eq!(rows.len(), 1, "{rows:#?}");
    assert_eq!(rows[0]["user_id"], "erin");
    assert_eq!(rows[0]["resource_id"], json!(item.to_string()));
    assert!(!serde_json::to_string(&rows).unwrap().contains(SECRET));

    // A device-bound item has no secret the backup can give: refused, and no
    // row says it was revealed.
    let (status, body) = call(&h, "POST", reveal_uri(&h, bound), None).await;
    assert_ne!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("device"));
    assert_eq!(reveal_rows(&h).await.len(), 1);

    // The audit write fails: the reveal does not happen.
    {
        let conn = rusqlite::Connection::open(&h.db_path).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER refuse_reveal_audit BEFORE INSERT ON audit_log \
             WHEN NEW.action = 'ios_keychain_secret_revealed' \
             BEGIN SELECT RAISE(ABORT, 'audit log unavailable'); END;",
        )
        .unwrap();
    }
    let (status, body) = call(&h, "POST", reveal_uri(&h, item), None).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert!(
        !contains(&body, SECRET),
        "the value left without its audit row"
    );

    // Still nothing at rest.
    assert!(!db_files_hold(&h, SECRET));
    h.runner.abort();
    let log_bytes = logs().0.lock().unwrap().clone();
    assert!(!contains(&log_bytes, SECRET), "the secret reached the log");
    let _ = std::fs::remove_dir_all(&backup);
}
