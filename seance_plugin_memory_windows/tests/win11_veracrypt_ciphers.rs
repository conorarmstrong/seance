//! VeraCrypt in memory (`MEM-044`) with a **Serpent volume and an AES-Twofish-Serpent cascade mounted together**: the same
//! Windows 11 25H2 / VeraCrypt 1.25.9 lab VM as `win11_veracrypt_1259.rs`, `c.hc` (Serpent / SHA-512 / NTFS, password
//! `SeanceVC-C-1129`) and `d.hc` (AES(Twofish(Serpent)), password `SeanceVC-D-6650`) mounted as `X:` and `Y:` when the memory was
//! dumped. The ground truth is independent of this crate: each header was decrypted on the host with
//! `scripts/oracle/vc_header_keys_all.py` (PBKDF2-HMAC-SHA512, then XTS under Serpent, Twofish and AES in every order until the
//! header reads `VERA` with a matching CRC-32; the Serpent is Gladman's `pyserpent` and the Twofish Niels Ferguson's C library),
//! which gave the digests pinned here. The test asks whether the sweep finds every one of the eight master keys by its hash
//! (the Twofish keys are not in memory as keys: they are recovered from their schedules) and what the container read around
//! them says.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_ciphers/mem.raw` or name it
//! with `SEANCE_WIN11_VCCIPHERS_MEMORY`. Release only.

use std::path::PathBuf;
use std::sync::Arc;

use seance_core::data_source::DataSource;
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_windows::automagic::{self, DiscoveryOptions};
use seance_plugin_memory_windows::modules::{list_kernel_modules, ModuleSymbols, ModuleWalkConfig};
use seance_plugin_memory_windows::truecrypt::*;
use seance_plugin_memory_windows::virtual_map::{survey_virtual_map, VirtualMapSymbols};

fn symbol_dirs() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    vec![
        root.join("test_data/win11_bitlocker/symbols"),
        root.join("reference/volatility3/volatility3/symbols"),
    ]
}

fn capture() -> Option<PathBuf> {
    let p = match std::env::var("SEANCE_WIN11_VCCIPHERS_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_ciphers/mem.raw"),
    };
    p.exists().then_some(p)
}

/// SHA-256 of the master keys: `c.hc` (Serpent) and `d.hc` (each layer of the cascade).
const C_SERPENT: (&str, &str) = (
    "d3da6a50cc6ca12458c5ebe71fa1551a202f70ca8c80c6b3438368c0588fe3a8",
    "496afd37a6015c733bfa18c53c9c797bed9256bb798df7568a96805403d627ec",
);
const D_SERPENT: (&str, &str) = (
    "b78838fc47223fe1f96d6263935fa5bfadbb1fe44ead467d1cd2fd2a3edc8171",
    "25bc3075932b91a478a2205a6d9d7933741f5f68632396ea737b08169c394be9",
);
const D_TWOFISH: (&str, &str) = (
    "2ddf2eb8a0a24e5f798059ada92e945513afd7ed69613d71dde23a9933172746",
    "90948f601a2aa67cd66ab0def2c66ceb51557b903b70b335a5fc951530df2650",
);
const D_AES: (&str, &str) = (
    "0b8324525c595e5a57665a983c1b4f0517c4566dec70d684b1bf17cbc3589ae0",
    "0680c4cf84304c40c18276e3ef27d212dfffd51bdb2329b6aae79dfcb7a6c37b",
);

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn a_serpent_volume_and_a_three_cipher_cascade_are_found_with_every_key_and_their_containers_read()
{
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_ciphers/mem.raw"
        );
        return;
    };
    let source: Arc<dyn DataSource> =
        Arc::new(seance_core::data_source::FileDataSource::new(path).expect("open"));
    let physical: Arc<dyn MemoryLayer> = Arc::new(PhysicalLayer::raw(source).expect("raw"));
    let profile = automagic::discover(physical, &symbol_dirs(), &DiscoveryOptions::default())
        .expect("discovery");
    let ms = ModuleSymbols::from_profile(&profile).expect("symbols");
    let kernel = list_kernel_modules(&profile, &ms, &ModuleWalkConfig::default()).expect("modules");
    let candidates: Vec<DriverCandidate> = kernel
        .modules
        .iter()
        .map(|m| DriverCandidate {
            name: m.base_name.name().map(str::to_string),
            base: m.base,
            size: m.size_of_image,
        })
        .collect();
    let vs = VirtualMapSymbols::from_profile(&profile).expect("MiState");
    let map = survey_virtual_map(&profile, &vs);
    let region = map
        .regions
        .iter()
        .find(|r| r.type_name.as_deref() == Some("MiVaNonPagedPool") && !r.is_empty())
        .map(|r| SweepRegion {
            layer: Arc::clone(&profile.kernel_space),
            base: r.base,
            bytes: r.bytes,
            description: "MiVaNonPagedPool".to_string(),
        });
    let out = survey_truecrypt(
        &candidates,
        kernel.is_complete(),
        region,
        &TrueCryptConfig::default(),
    );
    eprintln!("truecrypt: {}", out.describe());
    match &out.driver {
        DriverPresence::Present { name, .. } => {
            assert!(name.eq_ignore_ascii_case("veracrypt.sys"), "{name}")
        }
        other => panic!("{other:?}"),
    }
    let sweep = out.sweep.as_ref().expect("sweep ran");
    let hashes: Vec<&str> = sweep
        .schedules
        .iter()
        .map(|s| s.key_sha256.as_str())
        .collect();
    for (name, (primary, secondary)) in [
        ("c Serpent", C_SERPENT),
        ("d Serpent", D_SERPENT),
        ("d Twofish", D_TWOFISH),
        ("d AES", D_AES),
    ] {
        assert!(
            hashes.contains(&primary),
            "{name}: primary key not reported"
        );
        assert!(
            hashes.contains(&secondary),
            "{name}: secondary key not reported"
        );
    }
    // The containers: c.hc is a Serpent volume, d.hc the cascade, each decoded with its layers' keys.
    let serpent = sweep
        .crypto_infos
        .iter()
        .find(|c| c.cipher == Some("Serpent"))
        .expect("the Serpent volume's container");
    assert_eq!((serpent.cipher_id, serpent.mode), (2, Some("XTS")));
    assert_eq!(
        serpent.layout,
        "VeraCrypt 1.19 to 1.26.24 (observed on 1.19, 1.21, 1.22, 1.23, 1.23-Hotfix-2, 1.24, 1.24-Hotfix1, 1.24-Update2, 1.24-Update4, 1.24-Update5, 1.24-Update6, 1.24-Update7, 1.25, 1.25.4, 1.25.7, 1.25.9, 1.26.7, 1.26.14, 1.26.15, 1.26.18, 1.26.20, 1.26.24, 1.26.28-Beta4)"
    );
    assert_eq!(serpent.members[0].primary_key_sha256, C_SERPENT.0);
    assert_eq!(serpent.members[0].secondary_key_sha256, C_SERPENT.1);
    let cascade = sweep
        .crypto_infos
        .iter()
        .find(|c| c.cipher == Some("AES-Twofish-Serpent"))
        .expect("the cascade's container");
    assert_eq!((cascade.cipher_id, cascade.mode), (8, Some("XTS")));
    let by: std::collections::BTreeMap<_, _> =
        cascade.members.iter().map(|m| (m.cipher, m)).collect();
    for (cipher, (primary, secondary)) in [
        ("Serpent", D_SERPENT),
        ("Twofish", D_TWOFISH),
        ("AES", D_AES),
    ] {
        assert_eq!(by[cipher].primary_key_sha256, primary, "{cipher}");
        assert_eq!(by[cipher].secondary_key_sha256, secondary, "{cipher}");
    }
}
