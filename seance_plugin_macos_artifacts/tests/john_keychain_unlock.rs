//! KEYCHAIN-1: the macOS keychain master-key unwrap (HUNT-111, ROADMAP 3.1),
//! graded on real third-party files with known passwords.
//!
//! The evidence is the two Apple login keychains in openwall's
//! John-the-Ripper sample set (`john_samples_apple_keychain`, see its
//! `SOURCE.md`): TestUser1 with password `password` and TestUser2 with
//! password `letmein`. The pinned master keys below were computed first by an
//! independent Python implementation (`hashlib.pbkdf2_hmac` plus
//! `cryptography`'s 3DES-CBC), not by this crate.
//!
//! What this grades: the `DbBlob` salt/IV/ciphertext location, the PBKDF2 +
//! 3DES unwrap, and wrong-password detection. What it does NOT grade: item
//! decryption. Both files hold zero `ssgp` items; item decryption is graded
//! on another keychain, `keychain_items_real.rs` (`KEYCHAIN-2`). Without the corpus the tests say so
//! and pass vacuously.

use seance_plugin_macos_artifacts::{unlock_keychain, UnlockError};
use sha2::{Digest, Sha256};

fn root() -> String {
    format!(
        "{}/forensic_corpora/john_samples_apple_keychain",
        std::env::var("HOME").unwrap_or_default()
    )
}

struct Sample {
    dir: &'static str,
    password: &'static str,
    sha256: &'static str,
    master_key_hex: &'static str,
}

const SAMPLES: [Sample; 2] = [
    Sample {
        dir: "TestUser1-password",
        password: "password",
        sha256: "af7f112629d18a088a41234a74c885e5993e52cd20da06fe38a73cafbd3ffeb0",
        master_key_hex: "856eef4556b5858c15477db17b95c5cb015d510b9f3710ce9d44f65d8b6cbd5da066ee9dd085c20dfa537825",
    },
    Sample {
        dir: "TestUser2-letmein",
        password: "letmein",
        sha256: "10a21b0e77af9be8381c1e4d39e60dfcef21b57d73b55706b428a053442e819c",
        master_key_hex: "b17480c174ba5e2410c7f6a52337befc64b6d1da6c2d9defd1c818a4d82ce82e2c520a7b30947aba85330f05",
    },
];

fn load(s: &Sample) -> Option<Vec<u8>> {
    let path = format!("{}/{}/login.keychain", root(), s.dir);
    match std::fs::read(&path) {
        Ok(b) => {
            assert_eq!(
                hex(&Sha256::digest(&b)),
                s.sha256,
                "{path} is not the sample SOURCE.md records"
            );
            Some(b)
        }
        Err(_) => {
            eprintln!("KEYCHAIN-1 could not look: {path} is absent");
            None
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn the_right_password_unwraps_the_pinned_master_key() {
    for s in &SAMPLES {
        let Some(data) = load(s) else { return };
        let u = unlock_keychain(&data, s.password.as_bytes())
            .expect("the right password must not be refused")
            .expect("the file carries a DbBlob");
        assert_eq!(u.db_blob_version, 0x100);
        assert_eq!(hex(u.master_key()), s.master_key_hex, "{}", s.dir);
    }
}

#[test]
fn any_other_password_is_a_wrong_password() {
    for (i, s) in SAMPLES.iter().enumerate() {
        let Some(data) = load(s) else { return };
        let other = SAMPLES[1 - i].password;
        for bad in [other, "", "Password", "passwor", "password "] {
            if bad == s.password {
                continue;
            }
            assert!(
                matches!(
                    unlock_keychain(&data, bad.as_bytes()),
                    Err(UnlockError::WrongPassword)
                ),
                "{} with {bad:?}",
                s.dir
            );
        }
    }
}

#[test]
fn the_debug_form_of_an_unlock_never_prints_the_key() {
    let s = &SAMPLES[0];
    let Some(data) = load(s) else { return };
    let u = unlock_keychain(&data, s.password.as_bytes())
        .unwrap()
        .unwrap();
    let shown = format!("{u:?}");
    assert!(!shown.contains(&s.master_key_hex[..16]));
    assert!(shown.contains("redacted"));
}
