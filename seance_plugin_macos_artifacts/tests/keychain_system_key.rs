//! KEYCHAIN-3: `System.keychain` opened with `/var/db/SystemKey` instead of a password (`HUNT-111`).
//!
//! The evidence is Josh Hickman's public macOS 11 Big Sur reference image (a VMware guest, macOS 11.2.1,
//! `macOS-BigSur.zip`, SHA-256 `ccdfab33...89687`), which holds both `/Library/Keychains/System.keychain`
//! and `/private/var/db/SystemKey` (48 bytes). They were extracted with libfsapfs and are held at
//! `~/forensic_corpora/found_macos_bigsur/extract/` (see its `SOURCE.md`).
//!
//! The ground truth is independent of this crate: `oracle_python_unwrap.py` found, by trying every
//! 24-byte window of the file against the `DbBlob` and keeping only a valid PKCS#7 pad, that exactly one
//! window (bytes 8..32) opens it; and n0fate/chainbreaker (`--unlock-file`, a different codebase that
//! reads the same layout as `8s 24s 16s`) lists the keychain's items with that key.
//!
//! Without the corpus the tests say so and pass; `SEANCE_REQUIRE_CORPUS` makes that a failure.

use seance_plugin_macos_artifacts::{
    decrypt_item_secrets, unlock_keychain_with_system_key, ItemKind, UnlockError,
};
use sha2::{Digest, Sha256};

const KEYCHAIN_SHA256: &str = "fc33fe78c2b2fcdef1f7a89fb110d8bf0676dc004babae3a0152e525903a2a93";
const SYSTEM_KEY_SHA256: &str = "6ccb2773cc0959a74d24d22c6642038bf7d9297a050ee8367c18b962a21cde50";
/// The `DbBlob` master key the independent Python unwrap recovered (44 bytes).
const MASTER_KEY_HEX: &str =
    "0a5c162159c73c3c644434a197d1a8ba747b0dbf91b09ee360eea548ffc83827982e446ebca3232da834561e";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn load(rel: &str, sha: &str) -> Option<Vec<u8>> {
    let path = std::path::PathBuf::from(std::env::var("HOME").ok()?)
        .join("forensic_corpora/found_macos_bigsur/extract")
        .join(rel);
    match std::fs::read(&path) {
        Ok(b) => {
            assert_eq!(hex(&Sha256::digest(&b)), sha, "{}", path.display());
            Some(b)
        }
        Err(_) => {
            assert!(
                !std::env::var("SEANCE_REQUIRE_CORPUS").is_ok_and(|v| v != "0" && !v.is_empty()),
                "{} is absent but SEANCE_REQUIRE_CORPUS demands it",
                path.display()
            );
            eprintln!("KEYCHAIN-3 could not look: {} is absent", path.display());
            None
        }
    }
}

fn evidence() -> Option<(Vec<u8>, Vec<u8>)> {
    Some((
        load("Library/Keychains/System.keychain", KEYCHAIN_SHA256)?,
        load("private/var/db/SystemKey", SYSTEM_KEY_SHA256)?,
    ))
}

#[test]
fn the_system_key_opens_the_db_blob_to_the_master_key_the_oracle_found() {
    let Some((kc, sk)) = evidence() else { return };
    assert_eq!(sk.len(), 48);
    let unlock = unlock_keychain_with_system_key(&kc, &sk)
        .expect("the SystemKey opens the DbBlob")
        .expect("a DbBlob is present");
    assert_eq!(hex(unlock.master_key()), MASTER_KEY_HEX);
}

#[test]
fn a_changed_or_malformed_system_key_is_refused() {
    let Some((kc, sk)) = evidence() else { return };
    // One flipped bit inside the key window: a right-shaped file, the wrong key. Not the low bit:
    // DES ignores each byte's parity bit, so flipping it leaves the same key.
    let mut bad = sk.clone();
    bad[20] ^= 0x80;
    assert!(matches!(
        unlock_keychain_with_system_key(&kc, &bad),
        Err(UnlockError::WrongPassword)
    ));
    // Wrong length, wrong magic: not a SystemKey at all, told apart from a wrong key.
    assert!(matches!(
        unlock_keychain_with_system_key(&kc, &sk[..47]),
        Err(UnlockError::NotASystemKey)
    ));
    let mut no_magic = sk.clone();
    no_magic[0] = 0;
    assert!(matches!(
        unlock_keychain_with_system_key(&kc, &no_magic),
        Err(UnlockError::NotASystemKey)
    ));
}

/// The SystemKey is not the user's login keychain's key: it must not open another keychain's `DbBlob`.
#[test]
fn the_system_key_does_not_open_a_different_keychain() {
    let Some((_, sk)) = evidence() else { return };
    let Ok(other) = std::fs::read(
        std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
            .join("forensic_corpora/john_samples_apple_keychain/TestUser1-password/login.keychain"),
    ) else {
        return;
    };
    assert!(matches!(
        unlock_keychain_with_system_key(&other, &sk),
        Err(UnlockError::WrongPassword)
    ));
}

#[test]
fn the_items_decrypt_to_what_chainbreaker_lists() {
    let Some((kc, sk)) = evidence() else { return };
    let unlock = unlock_keychain_with_system_key(&kc, &sk).unwrap().unwrap();
    let got = decrypt_item_secrets(&kc, &unlock);
    // The generic password chainbreaker prints for com.apple.loginwindow.guest-account / Guest.
    let passwords: Vec<_> = got
        .decrypted
        .iter()
        .filter(|d| d.kind == Some(ItemKind::GenericPassword))
        .collect();
    assert_eq!(passwords.len(), 1);
    // The other generic password (LocalBeaconStore / LocalBeaconStoreKey) has a 28-byte payload: a
    // 20-byte label and an 8-byte IV and no ciphertext. chainbreaker prints an empty password for it;
    // this reader does not claim an empty secret from a payload with nothing in it, and says so.
    assert_eq!(got.failed.len(), 1, "{:?}", got.failed);
    assert!(
        got.failed[0].2.contains("28-byte payload"),
        "{:?}",
        got.failed
    );
    assert!(
        passwords.iter().any(|d| d.secret() == b"AlSPT2l:1VMGGtTI"),
        "{} password(s) decrypted, none the guest-account secret; failed: {:?}",
        passwords.len(),
        got.failed
    );
    // The three RSA private keys (com.apple.systemdefault and two com.apple.kerberos.kdc).
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;
    let keys: Vec<_> = got
        .decrypted
        .iter()
        .filter(|d| d.kind == Some(ItemKind::PrivateKey))
        .collect();
    assert_eq!(keys.len(), 3);
    for k in keys {
        let key = rsa::RsaPrivateKey::from_pkcs8_der(k.secret()).expect("PKCS#8");
        assert_eq!(key.size() * 8, 2048);
        key.validate().expect("primes, exponents and modulus agree");
    }
}

mod records {
    use super::*;
    use seance_core::artifact::{Artifact, ArtifactType};
    use seance_core::credential::{self, CredentialKind, CredentialOutcome, RunCredential};
    use seance_core::data_source::ByteSliceDataSource;
    use seance_core::module::ForensicsModule;
    use seance_plugin_macos_artifacts::KeychainParser;
    use std::sync::Arc;

    fn run(kc: Vec<u8>, secret: &str) -> (Vec<Artifact>, Option<CredentialOutcome>) {
        let a = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(kc))),
            serde_json::json!({
                "name": "System.keychain",
                "path": "/Library/Keychains/System.keychain"
            }),
        );
        let cred = Arc::new(RunCredential::new(
            a.id,
            CredentialKind::MacosSystemKey,
            secret.to_string(),
            "erin",
        ));
        let out = credential::scoped(Some(cred.clone()), || KeychainParser.process(&a))
            .expect("a verdict, not a module error");
        (out, cred.outcome())
    }

    #[test]
    fn a_supplied_system_key_is_accepted_and_neither_key_nor_secret_reaches_a_record() {
        let Some((kc, sk)) = evidence() else { return };
        let (out, outcome) = run(kc, &hex(&sk));
        assert_eq!(outcome, Some(CredentialOutcome::Accepted));
        let all =
            serde_json::to_string(&out.iter().map(|a| &a.metadata).collect::<Vec<_>>()).unwrap();
        for leak in [
            MASTER_KEY_HEX,
            &hex(&sk),
            &hex(&sk[8..32]),
            "AlSPT2l:1VMGGtTI",
        ] {
            assert!(!all.contains(leak), "{leak} is on a record");
        }
        let st = out
            .iter()
            .map(|a| &a.metadata)
            .find(|m| m["type"] == "KeychainStatus")
            .unwrap();
        assert_eq!(st["password_state"], "accepted");
        assert!(st["items_secret_decrypted"].as_u64().unwrap() >= 4, "{st}");
    }

    #[test]
    fn a_wrong_or_malformed_system_key_is_rejected_without_echoing_it() {
        let Some((kc, sk)) = evidence() else { return };
        let mut bad = sk.clone();
        bad[20] ^= 0x80;
        for secret in [hex(&bad), "not hex".to_string(), hex(&sk[..40])] {
            let (out, outcome) = run(kc.clone(), &secret);
            match outcome {
                Some(CredentialOutcome::Rejected { reason }) => {
                    assert!(!reason.contains(&secret), "{reason}");
                }
                other => panic!("expected Rejected, got {other:?}"),
            }
            let st = out
                .iter()
                .map(|a| &a.metadata)
                .find(|m| m["type"] == "KeychainStatus")
                .unwrap();
            assert!(st.get("password_state").is_none());
        }
    }
}
