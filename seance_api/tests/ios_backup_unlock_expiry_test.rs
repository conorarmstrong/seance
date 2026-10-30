//! Unlock-to-read (`BUG-026`): keys are forgotten when the TTL runs out even
//! if nothing reads the backup again, and the forget is audited.
//!
//! Its own test binary, because the TTL is read once per process from
//! `SEANCE_UNLOCK_TTL_SECS`. The backup is **synthetic**
//! (`seance_plugin_ios_backup::test_support`): it pins the mechanism only.

#[path = "support/ios_backup_harness.rs"]
mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unlock_is_forgotten_and_audited_at_expiry_without_any_further_read() {
    // Set before anything touches the keyring, which reads it once.
    std::env::set_var(seance_api::backup_keyring::TTL_ENV, "1");
    let h = harness().await;
    let (backup, password, folder, _sms) = ingested_backup(&h).await;
    let ring = seance_api::backup_keyring::ios_backups();
    assert_eq!(ring.ttl().as_secs(), 1);

    let (status, body) = call(
        &h,
        "POST",
        unlock_uri(&h, folder),
        Some(json!({ "kind": "ios_backup_password", "secret": password })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(ring.len(), 1);

    // No read, no lock, no lookup: only the sweep can forget it.
    let mut expired_rows = Vec::new();
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let audit = h.db.get_audit_log(h.case_id, 200, 0).await.unwrap();
        expired_rows = audit
            .into_iter()
            .filter(|e| {
                e["action"] == json!("unlock_forgotten")
                    && e["details"]
                        .as_str()
                        .is_some_and(|d| d.contains("reason=expired"))
            })
            .collect();
        if ring.is_empty() && !expired_rows.is_empty() {
            break;
        }
    }
    assert!(ring.is_empty(), "the expired keys are no longer held");
    assert_eq!(expired_rows.len(), 1, "one forget, audited once");
    let row = &expired_rows[0];
    assert_eq!(row["user_id"], json!("system"), "{row}");
    let details = row["details"].as_str().unwrap();
    assert!(details.contains("kind=ios_backup_password"), "{details}");
    assert!(!details.contains(&password), "{details}");

    h.runner.abort();
    let _ = std::fs::remove_dir_all(&backup);
}
