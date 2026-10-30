//! Known-answer test against a REAL Windows BitLocker-To-Go volume.
//!
//! `test_data/bdetogo.raw` (from the plaso project) is encrypted with the
//! password `bde-TEST`. This test unlocks it and asserts the exact recovered
//! FVEK, which authenticates the entire key hierarchy (detection -> FVE parse ->
//! password KDF -> AES-CCM VMK unwrap -> AES-CCM FVEK unwrap) against genuine
//! Windows crypto. Skips if the (gitignored) image is absent.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::credential::{self, CredentialKind, CredentialOutcome, RunCredential};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_bitlocker::{
    is_bitlocker, unlock_bitlocker, BitlockerDecryptor, Credential, EncryptionMethod,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

fn image_path() -> std::path::PathBuf {
    let root = std::env::current_dir().unwrap();
    let base = if root.ends_with("seance_plugin_bitlocker") {
        root.parent().unwrap().to_path_buf()
    } else {
        root
    };
    base.join("test_data/bdetogo.raw")
}

#[test]
fn unlocks_real_bitlocker_to_go_volume_with_password() {
    let img = image_path();
    if !img.exists() {
        eprintln!(
            "skipping: {} not present (gitignored corpus)",
            img.display()
        );
        return;
    }

    let src: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open image"));
    assert!(
        is_bitlocker(src.as_ref()),
        "bdetogo.raw must detect as BitLocker"
    );

    let unlocked = unlock_bitlocker(src, &Credential::Password("bde-TEST".to_string()))
        .expect("unlock with correct password must succeed");

    // Documented cipher for this Vista/7-era To Go volume.
    assert_eq!(
        unlocked.encryption_method,
        EncryptionMethod::AesCbc128Diffuser,
        "expected AES-CBC 128 + Elephant diffuser"
    );

    // The exact FVEK recovered from the real image — the strongest known-answer:
    // every AES-CCM MAC verified to produce these bytes.
    let fvek_hex = unlocked
        .fvek
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(
        fvek_hex,
        "d607b439fd6b816e1a7bfdd44f5d607410533ea7b58bab01dbe8ffd595319204\
         ec062f1dd8f8903ed1d9c833e5a802c6952612468135f09f8c3350914265a127",
        "recovered FVEK must match the real image's known key"
    );

    // The diffuser volume fully decrypts. Validate against the real plaintext:
    // BitLocker relocates the original FAT boot record to 0x2110800; decrypting
    // that sector must recover a valid boot sector (0x55AA signature, mkdosfs
    // OEM) — proof the AES-CBC + Elephant-diffuser transform is byte-correct.
    let decrypted = unlocked
        .decrypting_source
        .expect("diffuser volume must expose a decrypting source");
    let mut boot = [0u8; 512];
    let n = decrypted
        .read_at(0x2110800, &mut boot)
        .expect("read decrypted");
    assert_eq!(n, 512);
    assert_eq!(
        &boot[510..512],
        &[0x55, 0xAA],
        "relocated boot sector must decrypt to a valid 0x55AA signature"
    );
    assert!(
        boot.windows(7).any(|w| w == b"mkdosfs"),
        "decrypted boot sector must contain its real OEM string"
    );

    // An empty FAT cluster in the data region decrypts to all-zeros (the other
    // half of the known-answer: correct decryption of unused space).
    let mut cluster = [0xFFu8; 512];
    decrypted
        .read_at(0x600000, &mut cluster)
        .expect("read empty cluster");
    assert!(
        cluster.iter().all(|&b| b == 0),
        "an empty cluster must decrypt to zeros, not garbage"
    );
}

#[test]
fn wrong_password_is_rejected() {
    let img = image_path();
    if !img.exists() {
        eprintln!("skipping: {} not present", img.display());
        return;
    }
    let src: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open"));
    let result = unlock_bitlocker(src, &Credential::Password("wrong-password".to_string()));
    assert!(
        result.is_err(),
        "a wrong password must not unlock the volume"
    );
}

/// The image is a BitLocker **To Go** volume, and its volume boot record is a
/// perfectly ordinary FAT32 BPB: `MSWIN4.1` at offset 3, `FAT32   ` at 0x52.
///
/// That is by design — the "discovery volume" is what a legacy Windows sees —
/// and it is exactly why the repo's generic detector in
/// `seance_plugin_file_analysis` (which fingerprints BitLocker by the
/// `-FVE-FS-` OEM ID at offset 3) cannot see this volume at all. The only
/// component that can is this crate, which reads the BitLocker volume GUID at
/// 0x1a8 and the three FVE metadata offsets at 0x1b8.
///
/// So this crate is the *only* place a To Go volume can be reported from, and
/// it must report it whether or not anyone handed it a password.
#[test]
fn the_to_go_boot_record_looks_like_fat32_and_hides_the_fve_offsets() {
    let img = image_path();
    if !img.exists() {
        eprintln!("skipping: {} not present", img.display());
        return;
    }
    let src = FileDataSource::new(img).expect("open");
    let mut boot = [0u8; 512];
    assert_eq!(src.read_at(0, &mut boot).expect("read VBR"), 512);

    // A FAT32 BPB, not the `-FVE-FS-` OEM ID the generic detector looks for.
    assert_eq!(&boot[3..11], b"MSWIN4.1");
    assert_eq!(&boot[0x52..0x5a], b"FAT32   ");
    assert_ne!(&boot[3..11], b"-FVE-FS-");

    // The BitLocker volume identifier GUID lives at 0x1a8 in this layout.
    assert_eq!(
        &boot[0x1a8..0x1b8],
        &[
            0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3,
            0xd0, 0x01
        ]
    );

    // ...and the three FVE metadata block offsets at 0x1b8, each pointing at a
    // real `-FVE-FS-` block far inside the volume.
    for i in 0..3 {
        let off = u64::from_le_bytes(boot[0x1b8 + i * 8..0x1c0 + i * 8].try_into().unwrap());
        assert!(off > 0, "FVE metadata offset {i} must be present");
        let mut sig = [0u8; 8];
        src.read_at(off, &mut sig).expect("read FVE block");
        assert_eq!(&sig, b"-FVE-FS-", "block {i} at {off:#x}");
    }
}

/// Detection must not be conditional on holding the key.
///
/// The decryptor used to return `Ok(vec![])` the instant it saw no credential —
/// *before* it ever asked whether the volume was BitLocker. A locked volume
/// therefore reached the case as complete silence, which an examiner reads as
/// "there was nothing encrypted here". For a To Go volume nothing else in the
/// tree can correct that: the generic detector is looking for `-FVE-FS-` at
/// offset 3 and this volume says `MSWIN4.1` there.
#[test]
fn a_locked_volume_is_reported_when_no_credential_was_supplied() {
    let img = image_path();
    if !img.exists() {
        eprintln!("skipping: {} not present", img.display());
        return;
    }
    let src: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open"));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(src),
        json!({ "name": "bdetogo.raw" }),
    );

    let out = BitlockerDecryptor::new()
        .process(&artifact)
        .expect("process must not error");

    assert_eq!(
        out.len(),
        1,
        "a BitLocker volume with no credential must still be REPORTED, not silently skipped"
    );
    let md = &out[0].metadata;
    assert_eq!(md["type"], "VolumeDecryption");
    assert_eq!(md["scheme"], "BitLocker");
    assert_eq!(md["status"], "NotUnlocked");
    assert_eq!(md["subtype"], "detected_locked");
    assert_eq!(md["volume_name"], "bdetogo.raw");
    assert_eq!(out[0].parent_id, Some(artifact.id));

    // The standard incompleteness pair, so the completeness census and the
    // report's "not recovered" section both carry this volume.
    assert_eq!(md["content_incomplete"], true);
    assert_eq!(md["content_incomplete_reason"], "encrypted");
    assert_eq!(md["inventory_incomplete"], true);
    assert_eq!(md["inventory_incomplete_reason"], "encrypted");

    // The FVE metadata is unencrypted, so what it says is knowable with no
    // credential at all and belongs in the record.
    assert_eq!(
        md["bitlocker_encryption_method"],
        "AES-CBC 128-bit + Elephant diffuser"
    );
    assert_eq!(
        md["bitlocker_volume_identifier"],
        "b1454b16-2fe6-4668-a9fa-ad1e84ba88db"
    );
    // Both of this volume's VMK protectors, in metadata order: a user password
    // (type 0x2000) and a 48-digit recovery password (type 0x0800). That is
    // what tells the examiner which key to go and obtain.
    assert_eq!(
        md["bitlocker_key_protectors"],
        json!(["password", "recovery password"])
    );

    let detail = md["detail"].as_str().expect("detail text");
    assert!(
        detail.contains("no credential"),
        "the detail must say why it was not unlocked: {detail}"
    );
}

/// The same volume, with a credential that does not fit, is a *different*
/// finding — and both are findings, neither is silence.
#[test]
fn a_wrong_credential_is_a_distinct_report_from_no_credential() {
    let img = image_path();
    if !img.exists() {
        eprintln!("skipping: {} not present", img.display());
        return;
    }
    let src: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open"));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(src),
        json!({ "name": "bdetogo.raw" }),
    );
    let out = BitlockerDecryptor::from_secrets(Some("not-the-password".into()), None)
        .process(&artifact)
        .expect("process must not error");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["status"], "UnlockFailed");
    assert_eq!(out[0].metadata["subtype"], "unlock_failed");
}

/// HUNT-239, the HUNT-235 shape for BitLocker. The encryption detector writes
/// its own record for a `-FVE-FS-` volume; every record this module writes
/// for the volume — locked, failed, or the decrypted child — carries the
/// volume's artifact id as `volume_artifact_id`, the same reference the
/// detector's record carries, so the statements about one volume are tied
/// together. (This To Go volume says `MSWIN4.1` at offset 3, so the detector
/// does not fire on it; the reference is the decryptor's either way.)
#[test]
fn every_record_for_a_bitlocker_volume_names_it_by_the_shared_volume_reference() {
    let img = image_path();
    if !img.exists() {
        eprintln!("skipping: {} not present", img.display());
        return;
    }
    let src: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open"));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(src),
        json!({ "name": "bdetogo.raw" }),
    );
    let want = json!(artifact.id.to_string());
    for (label, decryptor, decrypted) in [
        ("locked", BitlockerDecryptor::new(), false),
        (
            "failed",
            BitlockerDecryptor::from_secrets(Some("not-the-password".into()), None),
            false,
        ),
        (
            "decrypted",
            BitlockerDecryptor::from_secrets(Some("bde-TEST".into()), None),
            true,
        ),
    ] {
        let out = decryptor.process(&artifact).expect("process");
        // A decryption writes the plaintext volume and the record saying the
        // volume was unlocked (HUNT-120); a locked or failed volume one record.
        assert_eq!(out.len(), if decrypted { 2 } else { 1 }, "{label}");
        assert_eq!(out[0].data.is_some(), decrypted, "{label}");
        for record in &out {
            assert_eq!(record.metadata["volume_artifact_id"], want, "{label}");
        }
    }
}

// ── a credential supplied for this artifact and this run (HUNT-120) ─────────

fn bdetogo_artifact() -> Option<Artifact> {
    let img = image_path();
    if !img.exists() {
        eprintln!("skipping: {} not present", img.display());
        return None;
    }
    let src: Arc<dyn DataSource> = Arc::new(FileDataSource::new(img).expect("open"));
    Some(Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(src),
        json!({ "name": "bdetogo.raw" }),
    ))
}

/// The examiner types the password into the attention queue after ingest. The
/// module was built with no credential at all — as the server always builds
/// it now — and the password reaches it for this one artifact and this one
/// run, not through the process environment.
#[test]
fn a_password_supplied_for_this_run_unlocks_the_real_volume() {
    let Some(artifact) = bdetogo_artifact() else {
        return;
    };
    let cred = Arc::new(RunCredential::new(
        artifact.id,
        CredentialKind::BitlockerPassword,
        "bde-TEST".to_string(),
        "erin",
    ));
    let out = credential::scoped(Some(cred.clone()), || {
        BitlockerDecryptor::new()
            .process(&artifact)
            .expect("process")
    });
    assert_eq!(cred.outcome(), Some(CredentialOutcome::Accepted));
    assert_eq!(out.len(), 2, "the plaintext volume and the unlocked record");

    let volume = &out[0];
    let plain = volume.data.as_ref().expect("a decrypting data source");
    assert_eq!(volume.metadata["bitlocker_decrypted"], true);
    // The relocated FAT boot record decrypts to a valid boot sector signature.
    let mut sector = [0u8; 512];
    plain
        .read_at(0, &mut sector)
        .expect("read the decrypted boot sector");
    assert_eq!(&sector[510..512], &[0x55, 0xAA], "a decrypted boot sector");

    let record = &out[1];
    assert_eq!(record.metadata["type"], "VolumeDecryption");
    assert_eq!(record.metadata["status"], "Unlocked");
    assert_eq!(record.metadata["credential_kind"], "bitlocker_password");
    assert_eq!(
        record.metadata["credential_source"],
        "supplied_for_this_run"
    );
    assert!(record.metadata.get("content_incomplete").is_none());
    assert_eq!(record.parent_id, Some(artifact.id));

    for a in &out {
        let text = a.metadata.to_string();
        assert!(
            !text.contains("bde-TEST"),
            "the secret reached a record: {text}"
        );
    }
}

/// A wrong password supplied for this run is reported back as rejected, so
/// the orchestrator leaves the locked record standing.
#[test]
fn a_wrong_password_supplied_for_this_run_is_rejected() {
    let Some(artifact) = bdetogo_artifact() else {
        return;
    };
    let cred = Arc::new(RunCredential::new(
        artifact.id,
        CredentialKind::BitlockerPassword,
        "not-the-password".to_string(),
        "erin",
    ));
    let out = credential::scoped(Some(cred.clone()), || {
        BitlockerDecryptor::new()
            .process(&artifact)
            .expect("process")
    });
    match cred.outcome() {
        Some(CredentialOutcome::Rejected { reason }) => {
            assert!(!reason.contains("not-the-password"), "{reason}");
            assert!(reason.contains("volume master key"), "{reason}");
        }
        other => panic!("a wrong password must be reported rejected, got {other:?}"),
    }
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["status"], "UnlockFailed");
    assert!(out[0].data.is_none());
}

/// A credential supplied for one artifact does not reach another: the same
/// volume under a different artifact id is reported locked, and the
/// credential is not consumed.
#[test]
fn a_credential_for_another_artifact_is_not_used() {
    let Some(artifact) = bdetogo_artifact() else {
        return;
    };
    let cred = Arc::new(RunCredential::new(
        Uuid::new_v4(),
        CredentialKind::BitlockerPassword,
        "bde-TEST".to_string(),
        "erin",
    ));
    let out = credential::scoped(Some(cred.clone()), || {
        BitlockerDecryptor::new()
            .process(&artifact)
            .expect("process")
    });
    assert_eq!(cred.outcome(), None);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["status"], "NotUnlocked");
}
