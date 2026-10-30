//! KEYCHAIN-2: per-item decryption of a macOS keychain, graded on a real file with a published answer
//! (`HUNT-111`, ROADMAP 3.1).
//!
//! The evidence is `testdata/test.keychain-db` of moond4rk/keychainbreaker (Apache-2.0), "a self-contained
//! keychain created with the macOS `security` command" (its `rfcs/002-api-design.md`), held at
//! `~/forensic_corpora/public_keychain/keychainbreaker/testdata/`. The keychain password is
//! `keychainbreaker-test`. The answer is that project's own test table, written by the person who made the
//! file: two generic passwords (service `moond4rk.com` and `HackBrowserData`, account `admin`) and two
//! internet passwords (`moond4rk.com` over `htps`/443 and `smb `/445), all four secrets `password#123`; the
//! file also holds an RSA key and a certificate.
//!
//! What this grades: the password opens the `DbBlob`, every one of the four `ssgp` items is matched to its
//! symmetric key record by the 20-byte label, the item key is unwrapped under the master key, and the
//! secret decrypts to the published value; the wrong password decrypts nothing. Without the corpus the
//! tests say so and pass; `SEANCE_REQUIRE_CORPUS` makes that a failure.

use seance_plugin_macos_artifacts::{decrypt_item_secrets, unlock_keychain, ItemKind, UnlockError};
use sha2::{Digest, Sha256};

const PASSWORD: &[u8] = b"keychainbreaker-test";

fn keychain() -> Option<Vec<u8>> {
    let path = std::path::PathBuf::from(std::env::var("HOME").ok()?)
        .join("forensic_corpora/public_keychain/keychainbreaker/testdata/test.keychain-db");
    match std::fs::read(&path) {
        Ok(b) => {
            assert_eq!(b.len(), 31_992, "{}: the published size", path.display());
            let _ = Sha256::digest(&b);
            Some(b)
        }
        Err(_) => {
            assert!(
                !std::env::var("SEANCE_REQUIRE_CORPUS").is_ok_and(|v| v != "0" && !v.is_empty()),
                "{} is absent but SEANCE_REQUIRE_CORPUS demands it",
                path.display()
            );
            eprintln!("KEYCHAIN-2 could not look: {} is absent", path.display());
            None
        }
    }
}

#[test]
fn all_four_password_items_decrypt_to_the_published_secret() {
    let Some(data) = keychain() else { return };
    let unlock = unlock_keychain(&data, PASSWORD)
        .expect("the published password opens the DbBlob")
        .expect("a DbBlob is present");
    let got = decrypt_item_secrets(&data, &unlock);
    assert!(got.failed.is_empty(), "{:?}", got.failed);
    // The four password items and the RSA private key; the four symmetric key records that wrap the
    // password items stay locked.
    assert_eq!(got.decrypted.len(), 5);
    let got_passwords: Vec<_> = got
        .decrypted
        .iter()
        .filter(|d| d.kind != Some(ItemKind::PrivateKey))
        .collect();
    assert_eq!(got_passwords.len(), 4);
    let mut kinds: Vec<_> = got_passwords.iter().map(|d| d.kind).collect();
    kinds.sort_by_key(|k| format!("{k:?}"));
    assert_eq!(
        kinds,
        vec![
            Some(ItemKind::GenericPassword),
            Some(ItemKind::GenericPassword),
            Some(ItemKind::InternetPassword),
            Some(ItemKind::InternetPassword),
        ]
    );
    for d in &got_passwords {
        assert_eq!(
            d.secret(),
            b"password#123",
            "{} #{}",
            d.relation,
            d.record_number
        );
    }
}

/// The RSA private key (print name `93B7C5C0`, 2048 bits) unwraps to a PKCS#8 key that an independent
/// parser (the `rsa` crate) accepts, of the published size, and whose primes multiply to its modulus.
/// The published test checks the same: the file's maker states validity, not the key's bytes.
#[test]
fn the_private_key_decrypts_to_a_valid_pkcs8_rsa_key() {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;
    let Some(data) = keychain() else { return };
    let unlock = unlock_keychain(&data, PASSWORD).unwrap().unwrap();
    let got = decrypt_item_secrets(&data, &unlock);
    let keys: Vec<_> = got
        .decrypted
        .iter()
        .filter(|d| d.kind == Some(ItemKind::PrivateKey))
        .collect();
    assert_eq!(keys.len(), 1);
    let key = rsa::RsaPrivateKey::from_pkcs8_der(keys[0].secret())
        .expect("the unwrapped bytes are a PKCS#8 private key");
    assert_eq!(key.size() * 8, 2048);
    key.validate()
        .expect("the primes, exponents and modulus agree");
}

#[test]
fn a_wrong_password_decrypts_nothing() {
    let Some(data) = keychain() else { return };
    assert!(matches!(
        unlock_keychain(&data, b"not-the-password"),
        Err(UnlockError::WrongPassword)
    ));
}

mod records {
    use super::*;
    use seance_core::artifact::{Artifact, ArtifactType};
    use seance_core::credential::{self, CredentialKind, CredentialOutcome, RunCredential};
    use seance_core::data_source::ByteSliceDataSource;
    use seance_core::module::ForensicsModule;
    use seance_plugin_macos_artifacts::KeychainParser;
    use std::sync::Arc;

    fn run(data: Vec<u8>, password: Option<&str>) -> (Vec<Artifact>, Option<CredentialOutcome>) {
        let a = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(data))),
            serde_json::json!({
                "name": "test.keychain-db",
                "path": "/Users/x/Library/Keychains/test.keychain-db"
            }),
        );
        match password {
            Some(p) => {
                let cred = Arc::new(RunCredential::new(
                    a.id,
                    CredentialKind::MacosKeychainPassword,
                    p.to_string(),
                    "erin",
                ));
                let out = credential::scoped(Some(cred.clone()), || KeychainParser.process(&a))
                    .expect("a verdict, not a module error");
                (out, cred.outcome())
            }
            None => (KeychainParser.process(&a).unwrap(), None),
        }
    }

    fn items(out: &[Artifact]) -> Vec<&serde_json::Value> {
        out.iter()
            .map(|a| &a.metadata)
            .filter(|m| m["subtype"] == "keychain_item")
            .collect()
    }

    /// With the right password the four password items say their secret decrypted and is withheld, and no
    /// record, anywhere, holds the secret or the keys.
    #[test]
    fn a_decrypted_secret_is_marked_withheld_and_reaches_no_record() {
        let Some(data) = keychain() else { return };
        let (out, outcome) = run(data, Some("keychainbreaker-test"));
        assert_eq!(outcome, Some(CredentialOutcome::Accepted));
        let passwords: Vec<_> = items(&out)
            .into_iter()
            .filter(|m| {
                matches!(
                    m["item_kind"].as_str(),
                    Some("generic_password" | "internet_password")
                )
            })
            .collect();
        assert_eq!(passwords.len(), 4);
        for m in &passwords {
            assert_eq!(m["secret_state"], "withheld", "{m}");
            assert_eq!(m["secret_present"], true);
            assert_eq!(m["secret_bytes"], 12, "password#123 is 12 bytes");
        }
        // The private key decrypts too, and is withheld the same way; its bytes (PKCS#8) are on no record.
        let key = items(&out)
            .into_iter()
            .find(|m| m["item_kind"] == "private_key")
            .unwrap();
        assert_eq!(key["secret_state"], "withheld");
        assert!(key["secret_bytes"].as_u64().unwrap() > 1000, "{key}");
        let all =
            serde_json::to_string(&out.iter().map(|a| &a.metadata).collect::<Vec<_>>()).unwrap();
        assert!(!all.contains("password#123"), "the secret is on a record");
        assert!(
            !all.contains("70617373776f726423313233"),
            "the secret's hex is on a record"
        );
        assert!(
            !all.contains("cGFzc3dvcmQjMTIz"),
            "the secret's base64 is on a record"
        );
        let st = out
            .iter()
            .map(|a| &a.metadata)
            .find(|m| m["type"] == "KeychainStatus")
            .unwrap();
        // The keychain's own key and certificate are labelled with the same words, so only the status
        // record, where a supplied password would be reported, is checked for it.
        assert!(
            !st.to_string().contains("keychainbreaker-test"),
            "the password is on the status record"
        );
        assert_eq!(st["items_secret_decrypted"], 5);
        // The four symmetric keys that wrap the item secrets stay locked.
        assert_eq!(st["items_with_locked_secret"], 4);
    }

    /// Without a password every item stays locked, as before.
    #[test]
    fn without_a_password_nothing_is_decrypted() {
        let Some(data) = keychain() else { return };
        let (out, _) = run(data, None);
        assert!(items(&out).iter().all(|m| m["secret_state"] != "withheld"));
    }
}
