//! Unlock-to-read for an encrypted iOS backup (`BUG-026`), end to end.
//!
//! After ingest the password is gone, so the files of an encrypted backup
//! cannot be streamed, hex-viewed, exported or re-hashed: the only bytes on
//! disk are ciphertext and the resolver refuses them (`HUNT-004`). The owner
//! decision of 2026-09-26 is an explicit, audited unlock: `POST
//! …/artifacts/{id}/unlock` checks the password against the keybag and keeps
//! the unwrapped class keys in process memory for this case, with a TTL;
//! `DELETE` on the same route forgets them.
//!
//! The backup is **synthetic** (`seance_plugin_ios_backup::test_support`): it
//! pins the mechanism — the route, the audit, the scoping, where the password
//! must not land — and is not validation of decryption against a real
//! device's backup.

#[path = "support/ios_backup_harness.rs"]
mod support;

use axum::http::StatusCode;
use seance_core::db::DatabaseConnection;
use serde_json::{json, Value};
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_of_an_encrypted_backup_file_is_refused_before_unlock_and_served_after() {
    let h = harness().await;
    let (backup, password, folder, sms) = ingested_backup(&h).await;

    // Locked: refused, and the refusal names the unlock route.
    let (status, body) = call(&h, "GET", content_uri(&h, sms), None).await;
    assert_ne!(status, StatusCode::OK);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("/unlock"), "{text}");
    assert!(!contains(
        &body,
        std::str::from_utf8(SMS_PLAINTEXT).unwrap()
    ));

    // Unlock through the backup folder.
    let (status, body) = call(
        &h,
        "POST",
        unlock_uri(&h, folder),
        Some(json!({ "kind": "ios_backup_password", "secret": password })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let v = body_json(&body);
    assert_eq!(v["status"], "unlocked", "{v}");
    assert_eq!(v["kind"], "ios_backup_password", "{v}");
    assert!(v["expires_in_secs"].as_u64().unwrap() > 0, "{v}");

    // Served: the plaintext, byte for byte.
    let (status, body) = call(&h, "GET", content_uri(&h, sms), None).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(body, SMS_PLAINTEXT);

    // Locked again (through the file itself): refused again.
    let (status, body) = call(&h, "DELETE", unlock_uri(&h, sms), None).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(body_json(&body)["status"], "locked");
    let (status, body) = call(&h, "GET", content_uri(&h, sms), None).await;
    assert_ne!(status, StatusCode::OK, "locked again must refuse");
    assert!(!contains(
        &body,
        std::str::from_utf8(SMS_PLAINTEXT).unwrap()
    ));

    h.runner.abort();
    let _ = std::fs::remove_dir_all(&backup);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_backup_password_records_rejected_and_serves_nothing() {
    let h = harness().await;
    let (backup, _password, _folder, sms) = ingested_backup(&h).await;

    let (status, body) = call(
        &h,
        "POST",
        unlock_uri(&h, sms),
        Some(json!({ "kind": "ios_backup_password", "secret": WRONG })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("refused"), "{text}");
    assert!(!text.contains(WRONG), "{text}");

    let (status, _) = call(&h, "GET", content_uri(&h, sms), None).await;
    assert_ne!(status, StatusCode::OK);

    let audit = h.db.get_audit_log(h.case_id, 200, 0).await.unwrap();
    let outcome: Vec<&Value> = audit
        .iter()
        .filter(|e| e["action"] == json!("unlock_outcome"))
        .collect();
    assert_eq!(outcome.len(), 1, "{audit:#?}");
    assert!(outcome[0]["details"]
        .as_str()
        .unwrap()
        .contains("outcome=rejected"));

    h.runner.abort();
    let _ = std::fs::remove_dir_all(&backup);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_audit_row_names_the_kind_and_never_the_password() {
    let h = harness().await;
    let (backup, password, folder, sms) = ingested_backup(&h).await;
    let mut responses = Vec::new();

    for (method, target, secret) in [
        ("POST", folder, Some(WRONG)),
        ("POST", folder, Some(password.as_str())),
        ("DELETE", sms, None),
    ] {
        let body = secret.map(|s| json!({ "kind": "ios_backup_password", "secret": s }));
        let (_, bytes) = call(&h, method, unlock_uri(&h, target), body).await;
        responses.extend_from_slice(&bytes);
    }

    let audit = h.db.get_audit_log(h.case_id, 200, 0).await.unwrap();
    let rows = |action: &str| -> Vec<&Value> {
        audit
            .iter()
            .filter(|e| e["action"] == json!(action))
            .collect()
    };
    assert_eq!(rows("unlock_supplied").len(), 2, "{audit:#?}");
    let outcomes = rows("unlock_outcome");
    assert_eq!(outcomes.len(), 2, "{audit:#?}");
    let forgotten = rows("unlock_forgotten");
    assert_eq!(forgotten.len(), 1, "{audit:#?}");
    for row in rows("unlock_supplied")
        .iter()
        .chain(outcomes.iter())
        .chain(forgotten.iter())
    {
        assert_eq!(row["user_id"], json!("erin"));
        assert!(
            row["details"]
                .as_str()
                .unwrap()
                .contains("kind=ios_backup_password"),
            "{row}"
        );
    }
    let details: String = outcomes
        .iter()
        .map(|r| r["details"].as_str().unwrap().to_string())
        .collect();
    assert!(details.contains("outcome=rejected"), "{details}");
    assert!(details.contains("outcome=accepted"), "{details}");

    let audit_text = serde_json::to_string(&audit).unwrap();
    let jobs_text = format!("{:?}", h.db.list_jobs(h.case_id).await.unwrap());
    h.runner.abort();
    let log_bytes = logs().0.lock().unwrap().clone();
    assert!(contains(&log_bytes, "unlock"), "the log capture is live");
    for secret in [password.as_str(), WRONG] {
        assert!(!audit_text.contains(secret), "{secret} reached the audit");
        assert!(!jobs_text.contains(secret), "{secret} reached a job row");
        assert!(!contains(&responses, secret), "{secret} reached a response");
        assert!(!contains(&log_bytes, secret), "{secret} reached the log");
        for suffix in ["", "-wal", "-shm"] {
            let path = format!("{}{}", h.db_path.display(), suffix);
            if let Ok(bytes) = std::fs::read(&path) {
                assert!(!contains(&bytes, secret), "{secret} was written to {path}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&backup);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_only_grant_cannot_unlock() {
    let h = harness().await;
    let (backup, password, folder, sms) = ingested_backup(&h).await;

    let (status, _) = call_as(
        &h,
        &h.reader_token.clone(),
        "POST",
        unlock_uri(&h, folder),
        Some(json!({ "kind": "ios_backup_password", "secret": password })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call_as(
        &h,
        &h.reader_token.clone(),
        "GET",
        content_uri(&h, sms),
        None,
    )
    .await;
    assert_ne!(status, StatusCode::OK, "nothing was unlocked");

    // An unknown kind is refused before anything is checked or held. (A
    // volume kind is known since HUNT-254; `sevenz_password` opens nothing
    // for reading.)
    let (status, body) = call(
        &h,
        "POST",
        unlock_uri(&h, folder),
        Some(json!({ "kind": "sevenz_password", "secret": password })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("ios_backup_password"));
    // A volume kind aimed at a backup folder is refused too: it is not a
    // volume, and nothing is held.
    let (status, body) = call(
        &h,
        "POST",
        unlock_uri(&h, folder),
        Some(json!({ "kind": "bitlocker_password", "secret": password })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!String::from_utf8_lossy(&body).contains(&password));
    assert!(seance_api::unlocked_volumes::volumes().is_empty());

    h.runner.abort();
    let _ = std::fs::remove_dir_all(&backup);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_the_case_forgets_its_keys_and_audits_the_forget() {
    let h = harness().await;
    let (backup, password, folder, _sms) = ingested_backup(&h).await;
    let ring = seance_api::backup_keyring::ios_backups();

    let (status, body) = call(
        &h,
        "POST",
        unlock_uri(&h, folder),
        Some(json!({ "kind": "ios_backup_password", "secret": password })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(ring.held_for_case(h.case_id), 1);

    let (status, body) = call_as(
        &h,
        &h.owner_token.clone(),
        "DELETE",
        format!("/api/v1/cases/{}", h.case_id),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        ring.held_for_case(h.case_id),
        0,
        "the keys go with the case"
    );
    // The row is written against the case as a resource, so it is found
    // after the case's own rows have had their case_id nulled.
    let rows =
        h.db.count_audit_actions_for_resource("unlock_forgotten", h.case_id)
            .await
            .unwrap();
    assert_eq!(rows, 1, "the forget by case delete is audited");

    h.runner.abort();
    let _ = std::fs::remove_dir_all(&backup);
}
