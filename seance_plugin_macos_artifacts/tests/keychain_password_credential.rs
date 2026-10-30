//! KEYCHAIN-1: a keychain password supplied through the audited credential
//! route (`macos_keychain_password`), graded on the real openwall TestUser1
//! login keychain (password `password`, SHA-256 `af7f1126...ffeb0`; see
//! `john_keychain_unlock.rs` for the master-key known answer).
//!
//! The accepted path reports that the `DbBlob` opened and nothing else: no key,
//! no hex, no password, and every item stays locked. Without the corpus the
//! tests say so and pass vacuously.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::credential::{self, CredentialKind, CredentialOutcome, RunCredential};
use seance_core::data_source::ByteSliceDataSource;
use seance_core::module::ForensicsModule;
use seance_plugin_macos_artifacts::KeychainParser;
use std::sync::Arc;

fn path() -> String {
    format!(
        "{}/forensic_corpora/john_samples_apple_keychain/TestUser1-password/login.keychain",
        std::env::var("HOME").unwrap_or_default()
    )
}
const PASSWORD: &str = "password";
const MASTER_KEY_HEX: &str =
    "856eef4556b5858c15477db17b95c5cb015d510b9f3710ce9d44f65d8b6cbd5da066ee9dd085c20dfa537825";

fn artifact() -> Option<Artifact> {
    let path = path();
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("KEYCHAIN-1 could not look: {path} is absent");
        return None;
    };
    Some(Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(ByteSliceDataSource::new(bytes))),
        serde_json::json!({
            "name": "login.keychain",
            "path": "/Users/TestUser1/Library/Keychains/login.keychain"
        }),
    ))
}

fn run_with(a: &Artifact, secret: &str) -> (Vec<Artifact>, Option<CredentialOutcome>) {
    let cred = Arc::new(RunCredential::new(
        a.id,
        CredentialKind::MacosKeychainPassword,
        secret.to_string(),
        "erin",
    ));
    let out = credential::scoped(Some(cred.clone()), || KeychainParser.process(a))
        .expect("a refused password is a verdict, not a module error");
    (out, cred.outcome())
}

fn status(out: &[Artifact]) -> &serde_json::Value {
    out.iter()
        .map(|a| &a.metadata)
        .find(|m| m["type"] == "KeychainStatus")
        .expect("a status record")
}

#[test]
fn the_right_password_is_accepted_and_the_key_reaches_no_record() {
    let Some(a) = artifact() else { return };
    let (out, outcome) = run_with(&a, PASSWORD);
    assert_eq!(outcome, Some(CredentialOutcome::Accepted));
    let st = status(&out);
    assert_eq!(st["password_state"], "accepted");
    assert_eq!(st["master_key_unwrapped"], true);
    let all = serde_json::to_string(&out.iter().map(|a| &a.metadata).collect::<Vec<_>>()).unwrap();
    assert!(!all.contains(MASTER_KEY_HEX));
    assert!(!all.contains(&MASTER_KEY_HEX[..16]));
    assert!(!all.contains("\"password\""), "the password is on a record");
}

#[test]
fn a_wrong_password_is_rejected_and_the_record_is_unchanged() {
    let Some(a) = artifact() else { return };
    let (out, outcome) = run_with(&a, "letmein");
    match outcome {
        Some(CredentialOutcome::Rejected { reason }) => {
            assert!(!reason.contains("letmein"), "{reason}");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    assert!(status(&out).get("password_state").is_none());
}

#[test]
fn no_credential_leaves_the_status_record_as_it_was() {
    let Some(a) = artifact() else { return };
    let out = KeychainParser.process(&a).unwrap();
    assert!(status(&out).get("password_state").is_none());
}
