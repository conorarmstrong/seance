//! VeraCrypt **1.25.4** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.25.4 installed from
//! the signed public installer (`forensic_corpora/veracrypt_installer`; detached signature good) and seven volumes mounted
//! together as `P:` to `V:`: `a.hc` Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES) and
//! `g.hc` Kuznyechik(Twofish) (SHA-512 / NTFS, passwords `SeanceVC-1254-A` to `SeanceVC-1254-G`, created by `VeraCrypt Format.exe /create`). The ground
//! truth is independent of this crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`, which gave the
//! digests pinned here. Before this version was installed the guest was cleaned of every other TrueCrypt and VeraCrypt install and
//! restarted, so the driver in the capture is this version's own.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_1254/mem.raw` or name it
//! with `SEANCE_WIN11_VC1254_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC1254_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_1254/mem.raw"),
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
            "d00ce16a9946683697a00e5222c1af2575b25c25e74cc678a0d99fb247262f61",
            "c394558138cd8b7c600b1c786f9039a769688b247268ced131b8674aac1b7c00",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "7922ddaa651f9b478b5cbb46c0f5d23ae4b569db54a2c8321cf68ce76a7383ba",
            "54dc97c01d69e2ce846e8ccad07da25671edbb9c221a1347e87b96e178a3c7e1",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "0dc6853b54a1d76a5ca4a491e839a13d3ab90a9075d988470d8e5caa2ceaa98c",
            "863fd8138b3c327e909548136e30ff7dc3a6a0f84da812c9b3e24426df7a15c8",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        6,
        &[(
            "Kuznyechik",
            "3dc83b5d043ff718a0302af18e863c556d799f51aa08423b34bcd1c1a96458b2",
            "382f804331080139a32f1bf6546e154f75fcadb2cf21b0a177de6e7c4a07dd9c",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        7,
        &[
            (
                "Twofish",
                "684bc4038647c10be9b9fc594eb9b525a93cdcdd5c2df9006c34fa8ffdfd219c",
                "781b6323aae2d2404c4dc5bd4a258ef7bfb3e311cb1a6a224eadd201c76340d1",
            ),
            (
                "AES",
                "52e7a0246173ec39ae4e68cb21c18a32602b2bd0df7c807426f52d0e0763c324",
                "23227bb42571d03bec22901374635d2ca6eed60ca73098b35fecae87b544db0e",
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
                "9cc5108d26dcbad1d8430b44e547ffb78170940f5778f250d4fcb8d7eb58de9a",
                "6121c989f48ae692d47128ca35fc866501137e1d83be4d4e54f48b3567ff71b3",
            ),
            (
                "Serpent",
                "1f6ea109cb0790469782211c595658848e6a7eed991057719db01dfcab59774a",
                "23f80d350e028aa5a96ee89d5d80120e2656b3d6841d3844c403adf3539a3b66",
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
                "fa26062ca474b905e187e9e045031a7d2545e6ec826fa9662bc8f89b7097adcf",
                "536e719f4f7e04af79729d5c3a992cf136e56a6a8a18140ef7047ec8eae0683f",
            ),
            (
                "Kuznyechik",
                "b059239ca6f76d7ac059a0874aeda5eec0491ce6e4c3f7f89566fa400a0a9129",
                "195e41fe4a3da95b9cefe6a5403deb4dd6d5915bcc044c350ce94804554840ad",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_veracrypt_1254_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_1254/mem.raw"
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
