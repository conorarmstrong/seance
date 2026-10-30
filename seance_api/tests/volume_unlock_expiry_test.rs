//! Unlock-to-read for a volume (`HUNT-254`): the decrypting view is forgotten
//! when the TTL runs out even if nothing reads the volume again, the forget is
//! audited, and the refusal returns.
//!
//! Its own test binary, because the TTL is read once per process from
//! `SEANCE_UNLOCK_TTL_SECS`. The volume is the real BitLocker To Go image
//! `test_data/bdetogo.raw` (password `bde-TEST`).

#[path = "support/volume_unlock_harness.rs"]
mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_volume_unlock_is_forgotten_and_audited_at_expiry_without_any_further_read() {
    let Some(image) = bdetogo() else {
        eprintln!("skipping: test_data/bdetogo.raw is not present");
        return;
    };
    // Set before anything touches a keyring, which reads it once.
    std::env::set_var(seance_api::backup_keyring::TTL_ENV, "1");
    let h = harness("read_write").await;
    let (volume, _decrypted, window) = decrypt_once(&h, &image).await;
    let ring = seance_api::unlocked_volumes::volumes();
    assert_eq!(ring.ttl().as_secs(), 1);

    let (status, body) = post_json(
        &h,
        unlock_uri(&h, window),
        json!({ "kind": "bitlocker_password", "secret": RIGHT }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // No read, no lock: only the sweep can forget it.
    let mut expired_rows = Vec::new();
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let audit = h.db.get_audit_log(h.case_id, 500, 0).await.unwrap();
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
    assert!(ring.is_empty(), "the expired view is no longer held");
    assert_eq!(expired_rows.len(), 1, "one forget, audited once");
    let row = &expired_rows[0];
    assert_eq!(row["user_id"], json!("system"), "{row}");
    let details = row["details"].as_str().unwrap();
    assert!(details.contains("kind=volume"), "{details}");
    assert!(details.contains(&volume.to_string()), "{details}");
    assert!(!details.contains(RIGHT), "{details}");

    let (status, body) = call(&h, "GET", content_uri(&h, window), None).await;
    assert_ne!(status, StatusCode::OK, "served after expiry: {body}");
    assert!(body.contains("/unlock"), "{body}");
    h.runner.abort();
}
