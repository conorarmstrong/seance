//! VeraCrypt **1.24-Update7** in memory (`MEM-044`): the Windows 11 25H2 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.24-Update7 installed
//! from `VeraCrypt Setup 1.24-Update7.exe` (SHA-256 `699c48f2...6a1d`, equal to the release's list) through its own wizard, and seven volumes mounted
//! together as `P:` to `V:`: `a.hc` Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES) and
//! `g.hc` Kuznyechik(Twofish) (SHA-512 / NTFS, passwords `SeanceVC-1247-A` to `SeanceVC-1247-G`). The ground truth is independent of this crate:
//! each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`, which gave the digests pinned here. The test asks whether the
//! sweep finds every master key by its hash and reads each container. **Two things differ from 1.25.9 and one does not:** this version's driver
//! is still called `truecrypt.sys` (1.25.9 and 1.26.29 load `veracrypt.sys`); the container layout and the ids are the 1.25.9 ones, **2, 3, 7, 9, 4, 6, 13**,
//! so the same table reads it.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_1247/mem.raw` or name it
//! with `SEANCE_WIN11_VC1247_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC1247_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_1247/mem.raw"),
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
            "27be095357ffbe11b1ddab9b247fe7f2c90b8c1ab4039db4d2749103ef45555f",
            "29fe5c2e347c5907d2e7a3449dc46b15ab865a0e43387bbff7cf6c3f2896e0d1",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "6c1227d62a7d889d7ceafcee8d4c48882008dc5c567f7e97a0412820ce620a51",
            "0f9de10319c641cb345de40bc439cb8830d5e9554aceedb2ad1f7266ada92e53",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "ae5acc6b2a224b86449cac51f06882338a7673d5fe1a88769646a689c3fe0ccf",
            "27197a85ade85e5b9a8eea7606d06063c2ae2fae45c9375da7a56f999f46af54",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        6,
        &[(
            "Kuznyechik",
            "4cbaaceef71685368d33e5b2240b25161f4144163dac21727303fb6fa8451c8a",
            "9ab2a7d30aa4581b3b8be136ace9a8851fcc591c45c120ebe25d5b0eb46fb1e2",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        7,
        &[
            (
                "Twofish",
                "73a7dabce2fcde306661a495fa0e69f4eb67cfbdc8b5dfc029948fef77c27819",
                "67fc5e4111e7118fd828801603645ddef91a0445a3b5911e8d98ec9e147090f2",
            ),
            (
                "AES",
                "dd66ca956ef288be98f97b6efbb83708edf4a64f9d55642248ce7053da01e592",
                "067836ba3745624d2e3b01d8fbc26c4534a126c5900d61788e9e3c70e3601b05",
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
                "891fb1f464055199c8401e04cb85ec9b8292e2f0b165ad9807981bc29b101fb5",
                "7bb0acc2cd881c43880a9bc20189e15ecde9d8c68d8b4dd26aaeb279eba2e7c9",
            ),
            (
                "Serpent",
                "8561833b957fb244fe2b690c1f9bd9268ad2fc55e657a520a1c480935077ed5b",
                "b4836cd21a7c027c3788b0f9335d198c731e8ec2d943d360170a887217d61c05",
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
                "508899e73a0b12fc855921c20733eacfea3bb65f87b5e2332cac077991dff22f",
                "3c82b07db71b5d2d1227303d77dc48ed895e9437c6e8369e0c9b90067b4c1dd4",
            ),
            (
                "Kuznyechik",
                "27c97325e9523466720b5628b6709b1b578347fbd8c92e60459bce23a3cd84e4",
                "b37077ef11ebe594c098535965bb97a167d104b33bc3b8aecac83cbd3708bf4d",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_veracrypt_1_24_update7_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_1247/mem.raw"
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
