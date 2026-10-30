//! VeraCrypt **1.22** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.22 installed from
//! `VeraCrypt Setup 1.22.exe` (SHA-256 `5fb3d3ee...c981`, equal to the release's list) through its own wizard, and seven volumes mounted
//! together as `P:` to `V:`: `a.hc` Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES) and
//! `g.hc` Kuznyechik(Twofish) (SHA-512 / NTFS, passwords `SeanceVC-122-A` to `SeanceVC-122-G`; this version's Format has no `/quick`). The ground
//! truth is independent of this crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`. This version's
//! driver is still called `truecrypt.sys`, and the container layout and ids are the 1.25.9 ones, **2, 3, 7, 9, 4, 6, 13**, so the same table reads it.
//! The capture's kernel (build 26100 after an update) needed its own ISF, made from Microsoft's PDB (GUID `B661C6FE...5470`, age 1).
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_122/mem.raw` or name it
//! with `SEANCE_WIN11_VC122_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC122_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_122/mem.raw"),
    };
    p.exists().then_some(p)
}

/// `(volume, cascade name, container id, [(cipher, primary key SHA-256, tweak key SHA-256)])`: the keys as the host
/// oracle read them out of each volume's header. The cipher order is the oracle's, not the buffer's.
#[allow(clippy::type_complexity)]
const VOLUMES: &[(&str, &str, u32, &[(&str, &str, &str)])] = &[
    (
        "a.hc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "0defb9a20d04e84984666566a23f4090c74c184e12d9fb264e56ea9897f04dbb",
            "a673cc22c8c85561974dae9d885adbf19e3642feb985aa9a4d03ba5d9ac7263f",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "fd809954bbd1794926493ba1a0e50752db7983a43f9525c0bc5951386b7ba701",
            "06ece45f0e821756f4b2d50300e76dccb47b965dc5ff1957119c8997dd244578",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "c6b04f6a4311f27ed9b8cd27c8bd916869a3481bc5f2d213dad103f7abff6c47",
            "0a1018460136d97682b9474e62b55bdef54bd8c269b19300236cf1822b60d66d",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        6,
        &[(
            "Kuznyechik",
            "6ebfbd38095d68c0458e764fe1740cd14246e5b72d0e290cc48c586fe1071497",
            "d2a718e38a908b1e17caa7b4ff98dc5316837b2bfd96c79eecadd0637fe86839",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        7,
        &[
            (
                "Twofish",
                "d1ae7f006ebe2c9c3717961e2f094fc1200890279e22da7d5ad3d67f3c92f001",
                "c220d120ac97593f611e2bd445576596499a564194d9fbbc59d77c1db197c48a",
            ),
            (
                "AES",
                "edb06df9debc25dc633ca747e411701af660e15194ecf892d7a430392717bccc",
                "e80ed9e7eaa4a66febcdf7bb4071b6ad08c3a69725c1a1d8062861cff8df9746",
            ),
        ],
    ),
    (
        "f.hc",
        "Serpent-AES",
        9,
        &[
            (
                "AES",
                "2a57761ad27cf9b46c654a035b4d6a306383e42ce3e860a2a250505054fbc57a",
                "7f023db39ed711e45ac216054f40da6a306bcbcfba03f3c09b33cd424dd28c0f",
            ),
            (
                "Serpent",
                "c10f67995010c3422be808b004e8463678abea6a30c74714ca93078f8ff0a4b9",
                "91935cdc79008ef9c9babbb54f6ad14c06f5486d13f24d0b23a20cbad45f4aa4",
            ),
        ],
    ),
    (
        "g.hc",
        "Kuznyechik-Twofish",
        13,
        &[
            (
                "Twofish",
                "10983b9025e6f57bc487ada41e12742f2bd1fc98e126e4f9f6e44d0c97b83511",
                "fdb006c76eeec75ab38b9b1de37ce82f5818bbd46c8080f9f829b36cdcea99db",
            ),
            (
                "Kuznyechik",
                "ffe0081315f3a4af58e818fe2b149509b65e8138794e69416e71ff3f59a82b01",
                "ddb1a694dab92e7b668e48add3b0f61d25d7ed8c57242513a65d05f12a874911",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_veracrypt_122_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_122/mem.raw"
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
            assert!(name.eq_ignore_ascii_case("truecrypt.sys"), "{name}")
        }
        other => panic!("{other:?}"),
    }
    let sweep = out.sweep.as_ref().expect("sweep ran");
    let hashes: Vec<&str> = sweep
        .schedules
        .iter()
        .map(|s| s.key_sha256.as_str())
        .collect();
    for (volume, _, _, keys) in VOLUMES {
        for (cipher, primary, secondary) in *keys {
            assert!(
                hashes.contains(primary),
                "{volume} {cipher}: primary key not reported"
            );
            assert!(
                hashes.contains(secondary),
                "{volume} {cipher}: tweak key not reported"
            );
        }
    }
    // One container per volume, named by its id, with every layer's keys.
    for (volume, name, id, keys) in VOLUMES {
        let info = sweep
            .crypto_infos
            .iter()
            .find(|c| c.cipher == Some(*name))
            .unwrap_or_else(|| {
                panic!(
                    "{volume}: no container named {name}: {:?}",
                    sweep.crypto_infos
                )
            });
        assert_eq!((info.cipher_id, info.mode), (*id, Some("XTS")), "{volume}");
        assert_eq!(
            info.layout,
            "VeraCrypt 1.19 to 1.26.24 (observed on 1.19, 1.21, 1.22, 1.23, 1.23-Hotfix-2, 1.24, 1.24-Hotfix1, 1.24-Update2, 1.24-Update4, 1.24-Update5, 1.24-Update6, 1.24-Update7, 1.25, 1.25.4, 1.25.7, 1.25.9, 1.26.7, 1.26.14, 1.26.15, 1.26.18, 1.26.20, 1.26.24, 1.26.28-Beta4)"
        );
        assert_eq!(info.members.len(), keys.len(), "{volume}");
        for (cipher, primary, secondary) in *keys {
            let m = info
                .members
                .iter()
                .find(|m| m.cipher == *cipher)
                .unwrap_or_else(|| panic!("{volume}: no {cipher} layer"));
            assert_eq!(m.primary_key_sha256, *primary, "{volume} {cipher}");
            assert_eq!(m.secondary_key_sha256, *secondary, "{volume} {cipher}");
        }
    }
    assert_eq!(
        sweep.crypto_infos.len(),
        VOLUMES.len(),
        "{:?}",
        sweep.crypto_infos
    );
}
