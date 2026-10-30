//! VeraCrypt **1.24** in memory on **Windows Server 2019** build 17763.379 (version 1809) (`MEM-044`, a fourth OS build): the Server 2019
//! Standard Evaluation ISO (`17763.379.190312-0539.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso`, fetched over HTTPS from
//! software-download.microsoft.com, SHA-256 `221f9acb...`), installed unattended under QEMU/KVM with the Server 2022 answer file, with
//! VeraCrypt 1.24 installed from its MSI and seven volumes created by `VeraCrypt Format.exe /create` and mounted together as `P:` to `V:`: `a.hc`
//! Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES), `g.hc` Kuznyechik(Twofish) (SHA-512 /
//! NTFS, passwords `SeanceVC-W19-124-A` to `-G`). The ground truth is independent of this crate: each header was decrypted on the host with
//! `scripts/oracle/vc_header_keys_all.py`. The kernel's symbols are `ntkrnlmp.pdb/8B11040A5928757B11390AC78F6B6925-1.json.xz`.
//!
//! The 4 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_w19_vc/run_124/mem.raw` or name it with
//! `SEANCE_W19_VC124_MEMORY`. Release only.

use std::path::PathBuf;
use std::sync::Arc;

use seance_core::data_source::DataSource;
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_windows::automagic::{self, DiscoveryOptions};
use seance_plugin_memory_windows::modules::{list_kernel_modules, ModuleSymbols, ModuleWalkConfig};
use seance_plugin_memory_windows::truecrypt::*;
use seance_plugin_memory_windows::virtual_map::{
    pool_sweep_region, survey_virtual_map, PoolRegionBasis, VirtualMapSymbols,
};

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
    let p = match std::env::var("SEANCE_W19_VC124_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_w19_vc/run_124/mem.raw"),
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
            "5486e57886d8250925d14851e07bdb274a346544d6cd08a99890e9747a5923bd",
            "9f1324c4ab16fe50f4784241a2f3eb5d8804758d52c9e6bc03044fde15e8f240",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "7499f0ff711201cb01a4ab69f7e284c437730982f3a1c35e178e3338c5c2d53b",
            "e5b5094e0c261aad67cf552fbbed9a701930f87c123a6db9d34a835080180187",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "4844b71f33b8d9d10c1945ec09db2be084565bdb35d61a0fa7708aff4df9fdf9",
            "2061ed79c75071658ee646f73a5c20203257df6df77a3e303de48c0c438fca23",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        6,
        &[(
            "Kuznyechik",
            "3a253d943d1604a43bf18fffc9be54a8929d5708db08b0920588d1ba0079a991",
            "a129d74a3337a5cd89899537ec32609640d74ed1c654498eb27675fab9afa337",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        7,
        &[
            (
                "Twofish",
                "3bd0cb5640529a556a796f327890002d35a39beb8d6e859b62d290bca2c452ec",
                "2b0b7146931cb590cbe1b9b4f3a1582cb657bbccf47a09b34f3b332200121cd9",
            ),
            (
                "AES",
                "ca48f58d169cd09f658f1cd1ec8ab6b3ee140a65dfc0999bb56f1f23ea118267",
                "acffa65ee6d699ee81e6bb5b277da4383597f31f821c3c7cf06d843876d5ec22",
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
                "a62e45bf1a3192f9ffe695c585015686874e54dd5be0d998812b7729e79ccee4",
                "d81b15cd3e5467f000068c3fe37991a0aec63cf1a9834fe434e6105a804e8617",
            ),
            (
                "Serpent",
                "0ef0198e2d19124b8f65941f745f868152b15ced8583e2fc515cfd8555b2474d",
                "e0b7bc449d0d15addbf342194e5437054095b12f454f322d63224bbf62ab32f9",
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
                "35dd852788bf605d8075d40f536858eb259c73d07d3e1722ab537bbfa5d24abe",
                "934b09ec03201bda495ef591133c0fff8b317ad1240ec792bfab46362ce8d962",
            ),
            (
                "Kuznyechik",
                "508f2fbea73070b526ad4eeb3ccfce9581cc538e4c83f5e4d9b5d45a7cd972e0",
                "b0b92d7cc901193ffed51f6a1268720dd01ccc68ecaf4abb5df9a2e28c3c9e66",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_w19_veracrypt_124_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_w19_vc/run_124/mem.raw");
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
    let entries: Vec<u64> = kernel.modules.iter().map(|m| m.entry).collect();
    // On this kernel the map's names do not follow the allocations (the region holding the loader entries is
    // named differently on each boot); the key schedules lie where the loader entries do.
    let (chosen, basis) = pool_sweep_region(&map.regions, &entries).expect("a pool region");
    assert_eq!(basis, PoolRegionBasis::Label);
    let region = Some(SweepRegion {
        layer: Arc::clone(&profile.kernel_space),
        base: chosen.base,
        bytes: chosen.bytes,
        description: "the MiVaNonPagedPool region".to_string(),
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
        assert_eq!(info.layout, "VeraCrypt 1.19 to 1.26.24 (observed on 1.19, 1.21, 1.22, 1.23, 1.23-Hotfix-2, 1.24, 1.24-Hotfix1, 1.24-Update2, 1.24-Update4, 1.24-Update5, 1.24-Update6, 1.24-Update7, 1.25, 1.25.4, 1.25.7, 1.25.9, 1.26.7, 1.26.14, 1.26.15, 1.26.18, 1.26.20, 1.26.24, 1.26.28-Beta4)");
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
