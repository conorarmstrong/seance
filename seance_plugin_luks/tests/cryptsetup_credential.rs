//! HUNT-120 on volumes `cryptsetup` itself wrote.
//!
//! `roundtrip.rs` builds its LUKS images with an encoder written in this
//! project, so it proves two readings of LUKS agree. These tests build the
//! images with the real `cryptsetup luksFormat` on a plain file — which needs
//! no root, because formatting writes only the header and keyslots — and
//! hand the passphrase to the module the way an examiner now does after
//! ingest: for one artifact and one run, through `seance_core::credential`,
//! with the module constructed holding no passphrase at all.
//!
//! What this establishes: the header, keyslot, anti-forensic split and
//! master-key digest `cryptsetup` wrote are read and the passphrase recovers a
//! master key whose digest verifies (LUKS1 and LUKS2); a wrong passphrase is
//! reported back as rejected. What it does not: the payload is never opened
//! through dm-crypt (that needs root), so no plaintext written by the kernel is
//! compared — the plaintext round trip is `roundtrip.rs`'s.
//!
//! Skips, saying so, where `cryptsetup` is not installed.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::credential::{self, CredentialKind, CredentialOutcome, RunCredential};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_luks::LuksDecryptor;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

const PASSPHRASE: &str = "cryptsetup fixture passphrase 4471";

fn cryptsetup_available() -> bool {
    Command::new("cryptsetup")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A fresh LUKS volume on a sparse file, formatted by `cryptsetup`.
fn format_volume(dir: &Path, luks_type: &str) -> PathBuf {
    let path = dir.join(format!("{luks_type}.img"));
    let f = std::fs::File::create(&path).unwrap();
    f.set_len(20 * 1024 * 1024).unwrap();
    drop(f);
    let mut child = Command::new("cryptsetup")
        .args([
            "luksFormat",
            "--type",
            luks_type,
            "--batch-mode",
            "--disable-locks",
            "--pbkdf",
            "pbkdf2",
            "--pbkdf-force-iterations",
            "1000",
            "--key-file",
            "-",
        ])
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cryptsetup");
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(PASSPHRASE.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "cryptsetup luksFormat --type {luks_type} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    path
}

fn run(path: &Path, secret: &str) -> (Vec<Artifact>, Option<CredentialOutcome>, u64) {
    let src: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.to_path_buf()).unwrap());
    let size = src.size();
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::Partition,
        Some(src),
        serde_json::json!({ "name": "vol0" }),
    );
    let cred = Arc::new(RunCredential::new(
        artifact.id,
        CredentialKind::LuksPassphrase,
        secret.to_string(),
        "erin",
    ));
    let out = credential::scoped(Some(cred.clone()), || {
        LuksDecryptor::new().process(&artifact).expect("process")
    });
    (out, cred.outcome(), size)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "seance-luks-{name}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn a_passphrase_supplied_for_this_run_opens(luks_type: &str) {
    if !cryptsetup_available() {
        eprintln!("skipping: cryptsetup is not installed");
        return;
    }
    let dir = scratch(luks_type);
    let img = format_volume(&dir, luks_type);

    let (out, outcome, size) = run(&img, PASSPHRASE);
    assert_eq!(outcome, Some(CredentialOutcome::Accepted), "{luks_type}");
    assert_eq!(out.len(), 2, "the plaintext volume and the unlocked record");
    let plain = out[0].data.as_ref().expect("a decrypting source");
    assert_eq!(out[0].metadata["luks_decrypted"], true);
    assert!(
        plain.size() > 0 && plain.size() < size,
        "the plaintext is the payload, after the header"
    );
    assert_eq!(out[1].metadata["type"], "VolumeDecryption");
    assert_eq!(out[1].metadata["status"], "Unlocked");
    assert_eq!(out[1].metadata["credential_kind"], "luks_passphrase");
    assert_eq!(
        out[1].metadata["credential_source"],
        "supplied_for_this_run"
    );
    for a in &out {
        assert!(!a.metadata.to_string().contains(PASSPHRASE));
    }

    let (out, outcome, _) = run(&img, "not the passphrase");
    match outcome {
        Some(CredentialOutcome::Rejected { reason }) => {
            assert!(!reason.contains("not the passphrase"), "{reason}");
        }
        other => panic!("{luks_type}: a wrong passphrase must be rejected, got {other:?}"),
    }
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["status"], "UnlockFailed");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_luks1_volume_formatted_by_cryptsetup_opens_with_a_passphrase_supplied_for_this_run() {
    a_passphrase_supplied_for_this_run_opens("luks1");
}

#[test]
fn a_luks2_volume_formatted_by_cryptsetup_opens_with_a_passphrase_supplied_for_this_run() {
    a_passphrase_supplied_for_this_run_opens("luks2");
}
