//! VeraCrypt **1.21** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.21 installed from
//! the signed public installer (`forensic_corpora/veracrypt_installer`; detached signature good) and seven volumes mounted
//! together as `P:` to `V:`: `a.hc` Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES) and
//! `g.hc` AES(Twofish(Serpent)) (SHA-512 / NTFS, passwords `SeanceVC-121-A` to `SeanceVC-121-G`, created by `VeraCrypt Format.exe /create`). The ground
//! truth is independent of this crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`, which gave the
//! digests pinned here. Before this version was installed the guest was cleaned of every other TrueCrypt and VeraCrypt install and
//! restarted, so the driver in the capture is this version's own.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_121/mem.raw` or name it
//! with `SEANCE_WIN11_VC121_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC121_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_121/mem.raw"),
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
            "529568a3691e8a5a36379de2256d441111a1b186bd5de19ada633c16a2823806",
            "a3882a73d8d49898b70d698e7953dc2e6f28a87b545bc889309d32c900083b7b",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "1f0b655282da820f1803d986e787f52b20e18f64153bd223d33b92140d1f3293",
            "789f723d004e54535ca3942b56314233e6e85c8732885ab011fa37ebb1e8c45e",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "e505f0bdf685d36b674fd4aae70707a043619106c5c3989887106047e8bf497d",
            "5e7d4da0e24a309041ea9240789b8876825d92b1b755d3dcb5d31498bb9b11e2",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        6,
        &[(
            "Kuznyechik",
            "10ddd7893aaf97de623445fe8b2671a9929bc6a5afe5a88c9f43e8de4f57fac0",
            "1109e8050237a8c0dd1f64f2faf6d54178491d4cae1c91697b6bd7c46708d4e4",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        7,
        &[
            (
                "Twofish",
                "36deba02e7230bc6d7d8a2898e93c651219028c907807d9070392b3d591c0a0c",
                "ddabdeb229cb44cd42bca76d6314e06bf270924a564520d8d712a5b475eed648",
            ),
            (
                "AES",
                "b2ab94b8b5818c01e8c81ca3ae73efd7f01a2072c083f36d03d1851ee4dde150",
                "debe2cae058cb7e68c7444e771a1622ec97f8b94854b34907da5d64b80ede89c",
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
                "4fbea44757ca6cc55eb722d004bb6fdb19df512d4e2842f62562900047606422",
                "6e367dd1ed43099cad0f46be22d0c8a40fbb9f0e168a8cc1e42271c34259c292",
            ),
            (
                "Serpent",
                "cea4b69979ed8304db22d2c548c7a06882f2deeb8265c1efb077b2f1fbdb5db3",
                "1ae0903453f6401d14b2d9c578b7719a004386050d6c05476dc3b17ca095ce32",
            ),
        ],
    ),
    (
        "g.hc",
        "AES-Twofish-Serpent",
        8,
        &[
            (
                "Serpent",
                "ccd88b3ff99029c4dcf148e0dd0fc06f3b6c4bb53f654ab3eb5b5570be96b97c",
                "cda1d1630f84f0f53934bb2d388a52697fdc5de5c6709d9d094e82971fbe0396",
            ),
            (
                "Twofish",
                "bfdcd6e58fd6ed11d7a3e65842a0478896a9eeb80e69ab93bda3fcf02f71588e",
                "73fc74c313ba8b833570855391904f75032828702a4c8072e2dd490bcb23b839",
            ),
            (
                "AES",
                "d005b2198d30d08d3c9cd3bcc6e2f0a21827e5194290f39da8c3b813772a15a9",
                "86d0aafd1fdcfeb43e1db763c7344bd881deee213909dc4da1624e4173921feb",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_veracrypt_121_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_121/mem.raw"
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
