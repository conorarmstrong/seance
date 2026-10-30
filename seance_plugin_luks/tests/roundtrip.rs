//! End-to-end synthetic round-trip validation.
//!
//! `cryptsetup` is not available on the build host, so these tests build real
//! LUKS1 and LUKS2 images from scratch: a proper on-disk header, an AF-split
//! master key, and an AES-XTS-encrypted payload carrying a known marker string.
//! They then drive the public `unlock_luks` API with the correct passphrase and
//! assert the marker reads back in the clear. This exercises the full
//! KDF -> keyslot-decrypt -> AF-merge -> digest-verify -> XTS-payload path with
//! genuine cryptography end to end.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_plugin_luks::test_support::{
    af_split, encrypt_sectors, HashSpec, LUKS1_KEY_ENABLED, LUKS_MAGIC,
};
use seance_plugin_luks::{is_luks, unlock_luks};
use std::sync::Arc;

const PASSPHRASE: &str = "correct horse battery staple";
const MARKER: &[u8] = b"SEANCE_LUKS_PLAINTEXT_OK::0xC0FFEE";
const MARKER_OFFSET: usize = 137;
const KEY_BYTES: usize = 64; // aes-256-xts
const STRIPES: usize = 8; // 64 * 8 = 512 bytes = one AF sector

/// Deterministic filler so images are reproducible without a RNG dependency.
fn lcg(buf: &mut [u8], mut state: u64) {
    for b in buf.iter_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (state >> 33) as u8;
    }
}

/// A 1024-byte plaintext payload (2 sectors) with a marker embedded.
fn make_plaintext_payload() -> Vec<u8> {
    let mut p = vec![0u8; 1024];
    lcg(&mut p, 0x5EA0_CE01);
    p[MARKER_OFFSET..MARKER_OFFSET + MARKER.len()].copy_from_slice(MARKER);
    p
}

fn assert_decrypts(src: Arc<dyn DataSource>) {
    assert!(is_luks(src.as_ref()), "image should be recognised as LUKS");
    let plain = unlock_luks(src, PASSPHRASE).expect("unlock should succeed");

    // Read the whole payload back and confirm the marker is present in the clear.
    let mut out = vec![0u8; 1024];
    let n = plain.read_at(0, &mut out).unwrap();
    assert_eq!(n, 1024);
    assert_eq!(
        &out[MARKER_OFFSET..MARKER_OFFSET + MARKER.len()],
        MARKER,
        "decrypted payload must contain the marker"
    );

    // Also exercise an unaligned, cross-sector read.
    let mut mid = vec![0u8; 40];
    let got = plain.read_at(500, &mut mid).unwrap();
    assert_eq!(got, 40);
    let full = make_plaintext_payload();
    assert_eq!(
        &mid[..],
        &full[500..540],
        "unaligned read must match plaintext"
    );
}

// ---------------------------------------------------------------------------
// LUKS1
// ---------------------------------------------------------------------------

fn build_luks1_image(passphrase: &str) -> Vec<u8> {
    let hash = HashSpec::Sha256;
    let slot_iters = 1000u32;
    let mk_iters = 1000u32;
    let km_offset_sectors = 4u32; // keyslot material at byte 2048
    let payload_offset_sectors = 8u32; // payload at byte 4096

    // Master key and salts (deterministic).
    let mut master_key = vec![0u8; KEY_BYTES];
    lcg(&mut master_key, 0xA11CE);
    let mut slot_salt = [0u8; 32];
    lcg(&mut slot_salt, 0x0BEEF);
    let mut mk_salt = [0u8; 32];
    lcg(&mut mk_salt, 0xF00D);

    // MK digest = PBKDF2(master_key, mk_salt) truncated to 20 bytes.
    let mut mk_digest = [0u8; 20];
    hash.pbkdf2(&master_key, &mk_salt, mk_iters, &mut mk_digest);

    // Keyslot key = PBKDF2(passphrase, slot_salt).
    let mut slot_key = vec![0u8; KEY_BYTES];
    hash.pbkdf2(passphrase.as_bytes(), &slot_salt, slot_iters, &mut slot_key);

    // AF-split the master key, then XTS-encrypt the material with the slot key.
    let mut af_material = af_split(&master_key, STRIPES, hash, |b| lcg(b, 0x1357));
    encrypt_sectors(&slot_key, 512, 0, &mut af_material).unwrap();

    // Plaintext payload -> XTS-encrypt with the master key.
    let mut payload = make_plaintext_payload();
    encrypt_sectors(&master_key, 512, 0, &mut payload).unwrap();

    // Assemble the image.
    let total = payload_offset_sectors as usize * 512 + payload.len();
    let mut img = vec![0u8; total];

    // Header fields.
    img[..6].copy_from_slice(&LUKS_MAGIC);
    img[6..8].copy_from_slice(&1u16.to_be_bytes());
    img[8..11].copy_from_slice(b"aes");
    img[40..51].copy_from_slice(b"xts-plain64");
    img[72..78].copy_from_slice(b"sha256");
    img[104..108].copy_from_slice(&payload_offset_sectors.to_be_bytes());
    img[108..112].copy_from_slice(&(KEY_BYTES as u32).to_be_bytes());
    img[112..132].copy_from_slice(&mk_digest);
    img[132..164].copy_from_slice(&mk_salt);
    img[164..168].copy_from_slice(&mk_iters.to_be_bytes());
    img[168..172].copy_from_slice(b"uuid");
    // Keyslot 0.
    img[208..212].copy_from_slice(&LUKS1_KEY_ENABLED.to_be_bytes());
    img[212..216].copy_from_slice(&slot_iters.to_be_bytes());
    img[216..248].copy_from_slice(&slot_salt);
    img[248..252].copy_from_slice(&km_offset_sectors.to_be_bytes());
    img[252..256].copy_from_slice(&(STRIPES as u32).to_be_bytes());

    // Encrypted keyslot material and payload.
    let km_off = km_offset_sectors as usize * 512;
    img[km_off..km_off + af_material.len()].copy_from_slice(&af_material);
    let payload_off = payload_offset_sectors as usize * 512;
    img[payload_off..payload_off + payload.len()].copy_from_slice(&payload);

    img
}

#[test]
fn luks1_full_roundtrip() {
    let img = build_luks1_image(PASSPHRASE);
    assert_decrypts(Arc::new(ByteSliceDataSource::new(img)));
}

#[test]
fn luks1_wrong_passphrase_is_rejected() {
    let img = build_luks1_image(PASSPHRASE);
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(img));
    let err = unlock_luks(src, "wrong passphrase").unwrap_err();
    assert!(
        matches!(err, seance_plugin_luks::LuksError::BadPassphrase),
        "expected BadPassphrase, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// LUKS2
// ---------------------------------------------------------------------------

enum Kdf {
    Pbkdf2,
    Argon2id,
}

fn build_luks2_image(passphrase: &str, kdf: Kdf) -> Vec<u8> {
    let hash = HashSpec::Sha256;
    let hdr_size: u64 = 8192; // 4096 binary + 4096 JSON area
    let area_off: u64 = 12288; // keyslot AF material
    let payload_off: u64 = 16384; // segment (payload) start
    let digest_iters = 2000u32;

    // Master key + salts.
    let mut master_key = vec![0u8; KEY_BYTES];
    lcg(&mut master_key, 0xB0B);
    let mut area_salt = [0u8; 32];
    lcg(&mut area_salt, 0xACE1);
    let mut digest_salt = [0u8; 32];
    lcg(&mut digest_salt, 0xD16E);

    // Derive the keyslot area key with the chosen KDF.
    let mut area_key = vec![0u8; KEY_BYTES];
    let kdf_json = match kdf {
        Kdf::Pbkdf2 => {
            let iters = 1000u32;
            hash.pbkdf2(passphrase.as_bytes(), &area_salt, iters, &mut area_key);
            serde_json::json!({
                "type": "pbkdf2",
                "hash": "sha256",
                "iterations": iters,
                "salt": B64.encode(area_salt),
            })
        }
        Kdf::Argon2id => {
            let (mem, time, cpus) = (32u32, 1u32, 1u32);
            let params = argon2::Params::new(mem, time, cpus, Some(KEY_BYTES)).unwrap();
            let a =
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
            a.hash_password_into(passphrase.as_bytes(), &area_salt, &mut area_key)
                .unwrap();
            serde_json::json!({
                "type": "argon2id",
                "time": time,
                "memory": mem,
                "cpus": cpus,
                "salt": B64.encode(area_salt),
            })
        }
    };

    // Digest over the master key for verification.
    let mut digest = [0u8; 32];
    hash.pbkdf2(&master_key, &digest_salt, digest_iters, &mut digest);

    // AF material, XTS-encrypted with the area key.
    let mut af_material = af_split(&master_key, STRIPES, hash, |b| lcg(b, 0x2468));
    encrypt_sectors(&area_key, 512, 0, &mut af_material).unwrap();

    // Payload, XTS-encrypted with the master key.
    let mut payload = make_plaintext_payload();
    encrypt_sectors(&master_key, 512, 0, &mut payload).unwrap();

    let meta = serde_json::json!({
        "keyslots": {
            "0": {
                "type": "luks2",
                "key_size": KEY_BYTES,
                "af": {"type": "luks1", "stripes": STRIPES, "hash": "sha256"},
                "area": {
                    "type": "raw",
                    "offset": area_off.to_string(),
                    "size": (KEY_BYTES * STRIPES).to_string(),
                    "encryption": "aes-xts-plain64",
                    "key_size": KEY_BYTES
                },
                "kdf": kdf_json
            }
        },
        "segments": {
            "0": {
                "type": "crypt",
                "offset": payload_off.to_string(),
                "size": "dynamic",
                "iv_tweak": "0",
                "encryption": "aes-xts-plain64",
                "sector_size": 512
            }
        },
        "digests": {
            "0": {
                "type": "pbkdf2",
                "keyslots": ["0"],
                "segments": ["0"],
                "hash": "sha256",
                "iterations": digest_iters,
                "salt": B64.encode(digest_salt),
                "digest": B64.encode(digest)
            }
        }
    });
    let json = serde_json::to_string(&meta).unwrap();

    let total = payload_off as usize + payload.len();
    let mut img = vec![0u8; total];

    // Binary header.
    img[..6].copy_from_slice(&LUKS_MAGIC);
    img[6..8].copy_from_slice(&2u16.to_be_bytes());
    img[8..16].copy_from_slice(&hdr_size.to_be_bytes());
    // JSON area (NUL-padded), immediately after the 4096-byte binary header.
    img[4096..4096 + json.len()].copy_from_slice(json.as_bytes());
    // Encrypted keyslot material and payload.
    img[area_off as usize..area_off as usize + af_material.len()].copy_from_slice(&af_material);
    img[payload_off as usize..payload_off as usize + payload.len()].copy_from_slice(&payload);

    img
}

#[test]
fn luks2_pbkdf2_full_roundtrip() {
    let img = build_luks2_image(PASSPHRASE, Kdf::Pbkdf2);
    assert_decrypts(Arc::new(ByteSliceDataSource::new(img)));
}

#[test]
fn luks2_argon2id_full_roundtrip() {
    let img = build_luks2_image(PASSPHRASE, Kdf::Argon2id);
    assert_decrypts(Arc::new(ByteSliceDataSource::new(img)));
}

#[test]
fn luks2_wrong_passphrase_is_rejected() {
    let img = build_luks2_image(PASSPHRASE, Kdf::Pbkdf2);
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(img));
    let err = unlock_luks(src, "nope").unwrap_err();
    assert!(matches!(err, seance_plugin_luks::LuksError::BadPassphrase));
}

// ---------------------------------------------------------------------------
// Module wiring: secret handling (B3-060) and unlock-failure visibility (B3-084)
// ---------------------------------------------------------------------------

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::module::ForensicsModule;
use seance_plugin_luks::LuksDecryptor;

fn luks_artifact(img: Vec<u8>) -> Artifact {
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::Partition,
        Some(Arc::new(ByteSliceDataSource::new(img))),
        serde_json::json!({ "name": "vol0" }),
    )
}

/// B3-060: the decryptor takes its passphrase from process memory, so nothing
/// has to put the secret into artifact metadata (which is persisted to
/// `metadata_json` and served by the artifact-detail API).
#[test]
fn decrypts_from_an_in_memory_passphrase_with_no_secret_in_metadata() {
    let artifact = luks_artifact(build_luks1_image(PASSPHRASE));
    let out = LuksDecryptor::with_passphrase(Some(PASSPHRASE.to_string()))
        .process(&artifact)
        .expect("module must not fail the pipeline");

    // One plaintext volume, and the record saying it was unlocked (HUNT-120).
    assert_eq!(out.len(), 2, "one plaintext volume and its unlocked record");
    assert_eq!(out[0].metadata["luks_decrypted"], true);
    assert_eq!(out[1].metadata["status"], "Unlocked");
    assert_eq!(out[1].metadata["credential_source"], "process_start");
    for a in &out {
        let serialised = a.metadata.to_string();
        assert!(
            !serialised.contains(PASSPHRASE),
            "the passphrase must never appear in emitted metadata: {serialised}"
        );
    }
    assert!(
        !artifact.metadata.to_string().contains(PASSPHRASE),
        "the source artifact's metadata carries no secret"
    );
}

/// HUNT-196: detection must not be conditional on holding the key.
///
/// The decryptor used to return `Ok(vec![])` the instant it saw no passphrase,
/// before it asked whether the volume was LUKS at all, so a locked volume
/// reached the case as silence — no `VolumeDecryption` record, nothing on the
/// Needs attention queue. With no passphrase nothing is unlocked, but the
/// volume is reported with the incompleteness pair (reason `encrypted`) that
/// the attention queue and the completeness census read, exactly as BitLocker's
/// `detected_locked` record is.
#[test]
fn a_locked_volume_is_reported_when_no_passphrase_was_supplied() {
    for (version, img) in [
        (1u64, build_luks1_image(PASSPHRASE)),
        (2u64, build_luks2_image(PASSPHRASE, Kdf::Pbkdf2)),
    ] {
        let artifact = luks_artifact(img);
        let out = LuksDecryptor::new()
            .process(&artifact)
            .expect("a locked volume is not a pipeline failure");

        assert_eq!(
            out.len(),
            1,
            "a LUKS{version} volume with no passphrase must still be REPORTED, not silently skipped"
        );
        let md = &out[0].metadata;
        assert_eq!(md["type"], "VolumeDecryption");
        assert_eq!(md["scheme"], "LUKS");
        assert_eq!(md["status"], "NotUnlocked");
        assert_eq!(md["subtype"], "detected_locked");
        assert_eq!(md["volume_name"], "vol0");
        assert_eq!(md["luks_version"], version);
        assert_eq!(out[0].parent_id, Some(artifact.id));
        assert!(out[0].data.is_none(), "nothing is decrypted without a key");

        assert_eq!(md["content_incomplete"], true);
        assert_eq!(md["content_incomplete_reason"], "encrypted");
        assert_eq!(md["inventory_incomplete"], true);
        assert_eq!(md["inventory_incomplete_reason"], "encrypted");

        // The header is plaintext, so what it says is knowable with no key.
        assert_eq!(md["luks_cipher"], "aes-xts-plain64");
        assert!(md["luks_active_keyslots"].as_u64().unwrap() >= 1);

        let detail = md["detail"].as_str().expect("detail text");
        assert!(
            detail.contains("no passphrase was supplied"),
            "the detail must say why it was not unlocked: {detail}"
        );
    }
}

/// Without a passphrase, a volume that is not LUKS still produces nothing.
#[test]
fn a_non_luks_volume_without_a_passphrase_produces_nothing() {
    let artifact = luks_artifact(vec![0u8; 8192]);
    assert!(LuksDecryptor::new().process(&artifact).unwrap().is_empty());
}

/// B3-084: a wrong passphrase used to return `Ok(vec![])` plus a `warn!`, which
/// is byte-for-byte what an unencrypted volume produces. The case record then
/// could not distinguish "we failed to decrypt this" from "this was never
/// encrypted". A status record with the standard incompleteness pair must be
/// emitted instead.
#[test]
fn wrong_passphrase_leaves_an_examiner_visible_status_record() {
    let artifact = luks_artifact(build_luks1_image(PASSPHRASE));
    let out = LuksDecryptor::with_passphrase(Some("definitely wrong".to_string()))
        .process(&artifact)
        .expect("a wrong passphrase is not a pipeline failure");

    assert_eq!(out.len(), 1, "failure must not be silent");
    let md = &out[0].metadata;
    assert_eq!(md["type"], "VolumeDecryption");
    assert_eq!(md["status"], "UnlockFailed");
    assert_eq!(md["scheme"], "LUKS");
    assert_eq!(md["volume_name"], "vol0");
    // The standard pair the API and export honesty paths actually read.
    assert_eq!(md["content_incomplete"], true);
    assert_eq!(md["content_incomplete_reason"], "encrypted");
    assert_eq!(md["inventory_incomplete"], true);
    assert_eq!(md["inventory_incomplete_reason"], "encrypted");
    assert_eq!(out[0].parent_id, Some(artifact.id));
    assert!(
        !md.to_string().contains("definitely wrong"),
        "the attempted passphrase must not be recorded"
    );
}

/// A volume that is not LUKS stays silent: the passphrase may belong to another
/// volume in the same image, and every partition reaches this module.
#[test]
fn a_non_luks_volume_produces_nothing() {
    let artifact = luks_artifact(vec![0u8; 8192]);
    assert!(LuksDecryptor::with_passphrase(Some(PASSPHRASE.to_string()))
        .process(&artifact)
        .unwrap()
        .is_empty());
}

/// HUNT-235. The encryption detector writes its own record for a LUKS volume;
/// every record this module writes for the volume — locked, failed, or the
/// decrypted child — carries the same `volume_artifact_id` as that one, so
/// the two statements about one volume are tied together.
#[test]
fn every_record_for_a_luks_volume_names_it_by_the_shared_volume_reference() {
    let artifact = luks_artifact(build_luks1_image(PASSPHRASE));
    let want = serde_json::json!(artifact.id.to_string());
    for (label, decryptor) in [
        ("locked", LuksDecryptor::new()),
        (
            "failed",
            LuksDecryptor::with_passphrase(Some("definitely wrong".to_string())),
        ),
        (
            "decrypted",
            LuksDecryptor::with_passphrase(Some(PASSPHRASE.to_string())),
        ),
    ] {
        let out = decryptor.process(&artifact).unwrap();
        let expected = if label == "decrypted" { 2 } else { 1 };
        assert_eq!(out.len(), expected, "{label}");
        for record in &out {
            assert_eq!(record.metadata["volume_artifact_id"], want, "{label}");
        }
    }
}
