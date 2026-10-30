//! VeraCrypt **1.25** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.25 installed from
//! the signed public installer (`forensic_corpora/veracrypt_installer`; detached signature good) and seven volumes mounted
//! together as `P:` to `V:`: `a.hc` Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES) and
//! `g.hc` Kuznyechik(Twofish) (SHA-512 / NTFS, passwords `SeanceVC-125-A` to `SeanceVC-125-G`, created by `VeraCrypt Format.exe /create`). The ground
//! truth is independent of this crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`, which gave the
//! digests pinned here. Before this version was installed the guest was cleaned of every other TrueCrypt and VeraCrypt install and
//! restarted, so the driver in the capture is this version's own.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_125/mem.raw` or name it
//! with `SEANCE_WIN11_VC125_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC125_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_125/mem.raw"),
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
            "b72e3e6c30e0fe90d298ee0b63ff11ab33bdde642218990229521422f813a379",
            "33c90fc2f0b6a4e3a29ab66d37c084ab73366be50aa47239e039ba0f303c906f",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "63c19a1489c20cc47710b6f39b4eb869a199cb6fea4b6ea7c574f6c3f521f738",
            "c203c6e8fab96690d132481f30fed436ef65580e4682eb727fff95f5bcf63265",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "40785f12b778fe9a47a8ccad66d245799bb1fb873c413bc19ce97ce4981b088d",
            "07c1d98c4608ece3dde7d668400e619c3eb59f6445aa74572de2746ddad1e154",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        6,
        &[(
            "Kuznyechik",
            "b050d8a74fe4db14089f1eabd3dd4741fa930faec3f0420bbb21da1a170cd3b0",
            "61c80f1d3737ee59927682ad75c5fd407a275dceb8a20d8262d3f95bff5853e9",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        7,
        &[
            (
                "Twofish",
                "472d171d4f301dda99c2ca4d11a0efd62e6fa9869c46deeb4f13b8f57e491252",
                "4498f5127c488578d55e8beca09a5e244451cf44a7a90334fbffb7a72830b384",
            ),
            (
                "AES",
                "bf0a7c25cf44e333afb36ad39c89d12ab376dc3720259443061eb44cbff965f9",
                "1597b0c613a86ad7d637563210973884d5b26a512ed8166b50741fcb0877f8aa",
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
                "f32eafb08ddb3ed6fdd7309578940e266c14b3568b34a04218d8af44def04218",
                "5bcdecdc883c8f0d8e3d2c75e33cea0705e25b1d35d8130fdfc078daffd61860",
            ),
            (
                "Serpent",
                "e72869807af955039c4318097f6f574281b06a619dbc5affaf7395190eb4b6d3",
                "b19e62e2412c3b15d1f74b4e8c2a0ffd955a7b98565d42431476c74b4e2aeed7",
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
                "d13a0ae4c4e75c4b7589bc80b84ab944cc4082f97caa8c4dbbedc00551966ae5",
                "9ebdebfca05f2df8a94ea8fd22ef73cc3d685ea2ba0e1cedea5c1b8a67caadc8",
            ),
            (
                "Kuznyechik",
                "64f8981eed61a620b394d927fde2374f2cc818eab24f54eeb22f2188f4f310fd",
                "0ba1891f5cd5dbc38da4dcc49f1993e7d3692ced43d11e7f87735236932315df",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_veracrypt_125_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_125/mem.raw"
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
