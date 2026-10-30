//! VeraCrypt in memory (`MEM-044`) with **a Twofish volume and four more cascades mounted together**: the same
//! Windows 11 25H2 / VeraCrypt 1.25.9 lab VM as `win11_veracrypt_1259.rs`, `e.hc` Twofish, `f.hc` AES-Twofish, `g.hc` Serpent-AES, `h.hc` Twofish-Serpent and `i.hc` Serpent-Twofish-AES (all SHA-512 / NTFS, passwords
//! `SeanceVC-E-4471` to `SeanceVC-I-8815`) mounted as `P:` to `T:` when the memory was dumped. The ground truth is independent of this crate: each header was decrypted on the host with
//! `scripts/oracle/vc_header_keys_all.py` (PBKDF2-HMAC-SHA512, then XTS under Serpent, Twofish and AES in every order until the
//! header reads `VERA` with a matching CRC-32; the Serpent is Gladman's `pyserpent` and the Twofish Niels Ferguson's C library),
//! which gave the digests pinned here. The test asks whether the sweep finds every one of the master keys (ten schedules of five volumes, two per cipher per volume) by its hash
//! (the Twofish keys are not in memory as keys: they are recovered from their schedules) and what the container read around
//! them says.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_cascades/mem.raw` or name it
//! with `SEANCE_WIN11_VCCASCADES_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VCCASCADES_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_cascades/mem.raw"),
    };
    p.exists().then_some(p)
}

/// `(volume, cascade name, container id, [(cipher, primary key SHA-256, tweak key SHA-256)])`: the keys as the host
/// oracle read them out of each volume's header. The cipher order is the oracle's, not the buffer's.
#[allow(clippy::type_complexity)]
const VOLUMES: &[(&str, &str, u32, &[(&str, &str, &str)])] = &[
    (
        "e.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "ece93d06787cea040fdd92c48b8acb80be0265785ea7e54a0818712616419689",
            "e6477d6bdaf13910d1c3b034afba786f42bb5bdf91b47e97242b2749a1c73afa",
        )],
    ),
    (
        "f.hc",
        "AES-Twofish",
        7,
        &[
            (
                "Twofish",
                "15fcdb4ec1a36cdf77aa3747075ae4acf8b306a65c77af13428111f51a36b79c",
                "ca3281d4f6f6226964ba0281fd184f67cea9c9786070efcc1ecce96b469c6d44",
            ),
            (
                "AES",
                "cae99e157e6364dc3e33093f50127b656eac10ff342b8015946ea0c2e7ab376e",
                "9c1c76799ed2d003eba04e2e5fee5a736678ead12623e9828afd2ccb78341395",
            ),
        ],
    ),
    (
        "g.hc",
        "Serpent-AES",
        9,
        &[
            (
                "AES",
                "5339d6d6383246134687c8c8818097a485293f9cad1480d80dc48c7fd7328d9d",
                "cb7563e4044fd9a9d3868408f5ab49eb9ec6a26e112b7f6a62c7689c1b1a64a4",
            ),
            (
                "Serpent",
                "865ee96e9f81aba533534a0c470cccc55506df90a9771a3f35603393a9e75075",
                "00cf9511ffd75e5e23ca946a1ea55750073fd3abc348fee4fa2a692bdc20d054",
            ),
        ],
    ),
    (
        "h.hc",
        "Twofish-Serpent",
        11,
        &[
            (
                "Serpent",
                "37bd47a49a45dbfbeb3ca5da0b7d77f14cba43d29704e056367a387518b54f7b",
                "fa2fb3bd702e759cde61148b2f339672793752fd1f7cc2224aa78d8cab819640",
            ),
            (
                "Twofish",
                "b997c5cc5370922caad54e5849f9da35a16c8ce47545abaa46924e2ad19dc09f",
                "49f579ff63a7b610ec1cc56f5bfcc2a7ed61c5d44e83192948171895b6110711",
            ),
        ],
    ),
    (
        "i.hc",
        "Serpent-Twofish-AES",
        10,
        &[
            (
                "AES",
                "333b4d431ff75a9bc4b9e9d5269367bbd7bd18c9f1eaaf9a56cdbabde78d360b",
                "a74aef49757739257cd1ab4f94bb7c377c159de4f68f42c338837eef495abf88",
            ),
            (
                "Twofish",
                "892b78bafc220c11e8eab5374c50feb69c6ef4e466cc0e8a2ee77fc1cd4efc6c",
                "fa3526fd10d84d1e5e3937fb6f2f0454935b688b2359423be3c01f64e2707047",
            ),
            (
                "Serpent",
                "d1bb582f67f739ff204ee43a3674aad9bc2ffa1e87bb17b6f50434e6dbe1e3b1",
                "da8c927e1446e5a747fda1cf3d7fbb056e34796017afddd83b66aac3f9f85216",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn a_twofish_volume_and_four_cascades_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_cascades/mem.raw"
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
