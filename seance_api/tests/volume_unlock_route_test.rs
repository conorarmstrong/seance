//! Unlock-to-read for a decrypted BitLocker volume (`HUNT-254`), end to end.
//!
//! The real BitLocker decryptor runs through the credential route over the
//! real BitLocker To Go volume `test_data/bdetogo.raw` (password `bde-TEST`),
//! behind the real router with authentication on. After the run the key is
//! gone and the decrypted volume — and a window beneath it — are refused;
//! `POST …/unlock` with the password makes them readable (checked against the
//! boot record the plugin's own real-image test pins), `DELETE` makes
//! them unreadable again, and the password is nowhere: not in the database
//! file, an audit row, a job row, an HTTP response or the process log.

#[path = "support/volume_unlock_harness.rs"]
mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use serde_json::{json, Value};
use std::time::Duration;
use support::*;
use tower::util::ServiceExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_under_a_decrypted_bitlocker_volume_reads_back_after_unlock_for_reading() {
    let Some(image) = bdetogo() else {
        eprintln!("skipping: test_data/bdetogo.raw is not present");
        return;
    };
    let h = harness("read_write").await;
    let (volume, decrypted, window) = decrypt_once(&h, &image).await;
    let mut responses = String::new();

    // The ancestor chain marks the decrypted volume, so a client can offer
    // the unlock on anything beneath it.
    let (status, body) = call(
        &h,
        "GET",
        format!("/api/v1/cases/{}/artifacts/{window}/ancestors", h.case_id),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let chain: Vec<Value> = serde_json::from_str(&body).unwrap();
    let marked: Vec<&Value> = chain
        .iter()
        .filter(|a| a["decrypted_volume"] == json!("bitlocker"))
        .collect();
    assert_eq!(marked.len(), 1, "{chain:#?}");
    assert_eq!(marked[0]["id"], json!(decrypted.to_string()));

    // After the run: refused, and the refusal names the route that opens it.
    let (status, body) = call(&h, "GET", content_uri(&h, window), None).await;
    assert_ne!(status, StatusCode::OK, "served without a key: {body}");
    assert!(body.contains("/unlock"), "{body}");
    assert!(body.contains("bitlocker_password"), "{body}");

    // A wrong password: refused, nothing held, still unreadable.
    let (status, body) = post_json(
        &h,
        unlock_uri(&h, window),
        json!({ "kind": "bitlocker_password", "secret": WRONG }),
    )
    .await;
    responses.push_str(&body);
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("refused"), "{body}");
    let (status, _) = call(&h, "GET", content_uri(&h, window), None).await;
    assert_ne!(status, StatusCode::OK);

    // The right one, aimed at the file beneath: readable, as plaintext.
    let (status, body) = post_json(
        &h,
        unlock_uri(&h, window),
        json!({ "kind": "bitlocker_password", "secret": RIGHT }),
    )
    .await;
    responses.push_str(&body);
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "unlocked");
    assert_eq!(v["kind"], "bitlocker_password");
    assert_eq!(v["volume_artifact_id"], json!(volume.to_string()));
    assert!(v["expires_in_secs"].as_u64().unwrap() > 0);

    let res = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(content_uri(&h, window))
                .header("authorization", format!("Bearer {}", h.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let boot = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(boot.len(), 512);
    // The volume's real boot record, relocated by BitLocker and put back at
    // the front by the decrypting view: `mkdosfs` OEM and the 0x55AA
    // signature, the facts the plugin's real-image test pins at 0x2110800.
    // (The ciphertext view here would read the To Go discovery volume's
    // `MSWIN4.1` instead.)
    assert_eq!(&boot[3..11], b"mkdosfs\0", "the decrypted boot record");
    assert_eq!(&boot[510..512], &[0x55, 0xAA]);
    // The decrypted volume itself reads too.
    let (status, _) = call(&h, "GET", content_uri(&h, decrypted), None).await;
    assert_eq!(status, StatusCode::OK);

    // Locked again (aimed at the locked volume this time): refused again.
    let (status, body) = call(&h, "DELETE", unlock_uri(&h, volume), None).await;
    responses.push_str(&body);
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["was_unlocked"], json!(true), "{v}");
    let (status, body) = call(&h, "GET", content_uri(&h, window), None).await;
    assert_ne!(status, StatusCode::OK, "served after the lock: {body}");

    // The audit: by kind, attributed, never by value.
    let audit = h.db.get_audit_log(h.case_id, 500, 0).await.unwrap();
    let rows = |action: &str| -> Vec<String> {
        audit
            .iter()
            .filter(|e| e["action"] == json!(action) && e["user_id"] == json!("erin"))
            .map(|e| e["details"].as_str().unwrap_or_default().to_string())
            .collect()
    };
    assert_eq!(rows("unlock_supplied").len(), 2, "{audit:#?}");
    let outcomes = rows("unlock_outcome").join("\n");
    assert!(
        outcomes.contains("kind=bitlocker_password; outcome=rejected"),
        "{outcomes}"
    );
    assert!(
        outcomes.contains("kind=bitlocker_password; outcome=accepted"),
        "{outcomes}"
    );
    let forgot = rows("unlock_forgotten").join("\n");
    assert!(
        forgot.contains("kind=bitlocker_password; reason=lock; held=true"),
        "{forgot}"
    );

    // The secret is nowhere.
    let audit_text = serde_json::to_string(&audit).unwrap();
    let jobs_text = format!("{:?}", h.db.list_jobs(h.case_id).await.unwrap());
    h.runner.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let log_bytes = logs().0.lock().unwrap().clone();
    assert!(contains(&log_bytes, "unlock"), "the log capture is live");
    for secret in [RIGHT, WRONG] {
        assert!(
            !audit_text.contains(secret),
            "{secret} reached the audit log"
        );
        assert!(!jobs_text.contains(secret), "{secret} reached a job row");
        assert!(
            !responses.contains(secret),
            "{secret} reached an HTTP response"
        );
        assert!(
            !contains(&log_bytes, secret),
            "{secret} reached the process log"
        );
        for suffix in ["", "-wal", "-shm"] {
            let path = format!("{}{}", h.db_path.display(), suffix);
            if let Ok(bytes) = std::fs::read(&path) {
                assert!(!contains(&bytes, secret), "{secret} was written to {path}");
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_only_grantee_cannot_unlock_a_volume_for_reading() {
    let h = harness("read_only").await;
    let target = Artifact::new(
        h.case_id,
        ArtifactType::RawEvidence,
        None,
        json!({"name": "v"}),
    );
    h.db.record_artifact(&target).await.unwrap();
    let (status, body) = post_json(
        &h,
        unlock_uri(&h, target.id),
        json!({ "kind": "luks_passphrase", "secret": "ro-secret-4471" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(!body.contains("ro-secret-4471"));
    let audit = h.db.get_audit_log(h.case_id, 50, 0).await.unwrap();
    assert!(audit
        .iter()
        .all(|e| e["action"] != json!("unlock_supplied")));
    h.runner.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_volume_kind_aimed_at_something_that_is_not_that_volume_is_refused() {
    let Some(image) = bdetogo() else {
        eprintln!("skipping: test_data/bdetogo.raw is not present");
        return;
    };
    let h = harness("read_write").await;
    let (volume, _decrypted, window) = decrypt_once(&h, &image).await;
    // A LUKS passphrase for a BitLocker volume: refused before anything is tried.
    let (status, body) = post_json(
        &h,
        unlock_uri(&h, window),
        json!({ "kind": "luks_passphrase", "secret": "lk-secret-9920" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("BitLocker"), "{body}");
    assert!(!body.contains("lk-secret-9920"));
    // Nothing is held for it.
    assert!(seance_api::unlocked_volumes::lookup(h.case_id, volume).is_none());
    h.runner.abort();
}
