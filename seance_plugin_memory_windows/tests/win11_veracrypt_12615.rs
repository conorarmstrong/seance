//! VeraCrypt **1.26.15** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.26.15 installed from
//! `VeraCrypt.Setup.1.26.15.exe` (SHA-256 `bc569a78...`, equal to the release's list) through its own wizard, and seven volumes mounted
//! together as `P:` to `V:`: `a.hc` Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES) and
//! `g.hc` Kuznyechik(Twofish) (SHA-512 / NTFS, passwords `SeanceVC-12615-A` to `SeanceVC-12615-G`). The ground truth is independent of this
//! crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`. Like 1.26.7 this version's driver is still
//! `truecrypt.sys` and it keeps the 1.25.9 container geometry with 1.26.29's cipher ids (2, 3, 4, 5, 6, 8, 12 here), and it is read with no code change.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_12615/mem.raw` or name it
//! with `SEANCE_WIN11_VC12615_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC12615_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_12615/mem.raw"),
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
            "4a2b644eb6ed6603587628ffaca0c6e23a92eadd9c1e72771b90995b9f3a37e5",
            "5580638d6759fe842b04c43638b5e62dfd0a5a85f2167a15e3d184ac1f5614d5",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "8b71552c1ed460ebfa8b130dc72664d6f27f709fc1af76569e431df79911ff48",
            "fb98857933d8dcc4f843f5877c25767bce4ad8331bdda47d1bab0fcbc8e7c801",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "d035071d6b0223a7ae2b92157ee6cb9027234b563a990338686a09b8f24ebfaa",
            "a2c89a5b6bce3ba6fb00c4bb899d5e3fbb3d7346c9f6b312f6ab9bbc2fcb4e32",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        5,
        &[(
            "Kuznyechik",
            "632247e05e71a90016e04c53bf538bd0891d2f8817ea6adfccfdf3b0415d0cb8",
            "dc6a5602afd9a2ffbe8c2059424bf8ea10ef15749a7149932de57b4f46e1ad30",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        6,
        &[
            (
                "Twofish",
                "398ad1724e571b78278d101208b42f6086e646eb4c6bf51f0a58f3eacfe1fc42",
                "e82c1daf7ad01256a0359487df799d81f0156e04c535fff6952df28355ab9f04",
            ),
            (
                "AES",
                "912e37a0e17a658ee7485ca1520602ecdf6277948a770569b37c11128b1c81a7",
                "085f7b018f599fbdcbed3110dc7f8162e525cd63b481d307c7c67af200ee3dea",
            ),
        ],
    ),
    (
        "f.hc",
        "Serpent-AES",
        8,
        &[
            (
                "AES",
                "31aaf69fb05b4dd8894e5a0f960126bf727e4171a15255a645c66b595231e26e",
                "d04758b25585c65db9c4c25d3d39a9ce6430c92e52820ea47184edde4697b9d5",
            ),
            (
                "Serpent",
                "0e0d5845ccec9977ce38152de2dbd3a07790fd8e698ba38ed722b331b6ab0456",
                "af2d977c27fc07963a80df37e33cfc2aabbdb7f16ae85e3877c2685f2cd25bce",
            ),
        ],
    ),
    (
        "g.hc",
        "Kuznyechik-Twofish",
        12,
        &[
            (
                "Twofish",
                "fcd35d98db3156857c6fbee93bd6832042dce5a416b929bf5e6c947e9da52a62",
                "3795d335bed9dd3f845b64cfd050ea5e53565a3fc0b4dc51a3a253828645f714",
            ),
            (
                "Kuznyechik",
                "197939a78796fdfb94863a64e81b82a069d23810de188f1cbd4423aa17cab57e",
                "e4c9da2466790fda3d78f78eddd328f334f3b9634a2ee4f6f40c757217856d5e",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_veracrypt_12615_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_12615/mem.raw"
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
