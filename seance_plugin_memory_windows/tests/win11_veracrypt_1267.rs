//! VeraCrypt **1.26.7** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.26.7 installed from
//! `VeraCrypt.Setup.1.26.7.exe` (SHA-256 `5efb272a...23b4`, equal to the release's list) through its own wizard, and seven volumes mounted
//! together as `P:` to `V:`: `a.hc` Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES) and
//! `g.hc` Kuznyechik(Twofish) (SHA-512 / NTFS, passwords `SeanceVC-1267-A` to `SeanceVC-1267-G`). The ground truth is independent of this
//! crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`. **This version is a hybrid:** its driver is still
//! `truecrypt.sys` and its container has the 1.25.9 geometry (header of three dwords, buffer at `+0x0c`, tweak keys 5,304 bytes on), but it
//! numbers the ciphers as 1.26.29 does: Serpent 2, Twofish 3, Camellia 4, Kuznyechik 5, AES-Twofish 6, Serpent-AES 8, Kuznyechik-Twofish 12. Before the
//! 1.26.7 id table was added the sweep decoded 4 of the 7 containers and published one of them with an id it could not name.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_1267/mem.raw` or name it
//! with `SEANCE_WIN11_VC1267_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC1267_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_1267/mem.raw"),
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
            "f1ed0c05575918e21c04eadc97e52612c9051f072da04742da324a838e1a8d2e",
            "12cdc5bad01013d04df1ef8fbc59b5ae5b8582bd3a10360d3e37221eb005ea36",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "abab97f0dda2f824bcde2e51c8822080c4947ea6c2efae8f2ffbf784f1762861",
            "ac8c8d35d8fedb114365b1fa9d50b9a4b59fd11ade9a691a38e05028513de000",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "861c4e4805edf0e998b1272af92f97c5419faed3a1060613a9892a5f15bb152d",
            "3df052e74073116e1199c0c34c35c68c816cd3f24b29476cba333a11c6ce85e9",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        5,
        &[(
            "Kuznyechik",
            "cf1798c063902ee82799357519888c164640ffd756f318d37013c25f4e7578ba",
            "9584b541a7f97109a5e0084e2f1ad0c7585a61d786b46590ab37ae8c6b004889",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        6,
        &[
            (
                "Twofish",
                "930d41b6467c9c04a00e365ccd576f64df76475b469b1ffe99776cc09b92e3e7",
                "92f73ce71383142e7da612369e51bb3d31d6d08ff0292827c314131a750b7b32",
            ),
            (
                "AES",
                "6cb98f43aed6a6818b4903d48ff5753181214e905254a7e1ce36d3a1b30520d0",
                "7b99fbbc9f1b914dcf0e8edf8372ec582c866fc19f62476dc789cceeb77c1524",
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
                "d3c351114340b4b5915f7ab20c8e7c82757b8000d409c0501794964704214287",
                "2dffcce5d1e1be4dde0295cd8a97925d9cf4e90dc5d004013aa0d1982a14c066",
            ),
            (
                "Serpent",
                "60e79f7eff5c4fabe5887d1e9876b260f0620505cd84068d5076ec2c16c4e9d5",
                "869ef8e4fbdc1ec3eb3806b8d8529ef533be6f47ed79a92279ac1afd74846214",
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
                "c456aa25316ab46c5ffddc2463d296cec40ecc7c53cdc5ac2e93bba8b6e0f386",
                "22cfb76b85628d2f213340e2543bf8e665c1546d267a366c4745b56cd061661f",
            ),
            (
                "Kuznyechik",
                "38ce8b424792148553887dcde8e6b664c028defaf127e2ee1bed32c7b57ab7fa",
                "05baab635db8be602b88433b85069cfd0c62e797f65d1a772b2e2c972832d0f8",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_veracrypt_1267_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_1267/mem.raw"
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
