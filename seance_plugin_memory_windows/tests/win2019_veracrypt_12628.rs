//! VeraCrypt **1.26.28 Beta4** in memory on **Windows Server 2019** build 17763.379 (version 1809) (`MEM-044`, a fourth OS build): the Server 2019
//! Standard Evaluation ISO (`17763.379.190312-0539.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso`, fetched over HTTPS from
//! software-download.microsoft.com, SHA-256 `221f9acb...`), installed unattended under QEMU/KVM with the Server 2022 answer file, with
//! VeraCrypt 1.26.28 Beta4 installed from its MSI and seven volumes created by `VeraCrypt Format.exe /create` and mounted together as `P:` to `V:`: `a.hc`
//! Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES), `g.hc` Kuznyechik(Twofish) (SHA-512 /
//! NTFS, passwords `SeanceVC-W19-12628-A` to `-G`). The ground truth is independent of this crate: each header was decrypted on the host with
//! `scripts/oracle/vc_header_keys_all.py`. The kernel's symbols are `ntkrnlmp.pdb/8B11040A5928757B11390AC78F6B6925-1.json.xz`.
//!
//! The 4 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_w19_vc/run_12628/mem.raw` or name it with
//! `SEANCE_W19_VC12628_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_W19_VC12628_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_w19_vc/run_12628/mem.raw"),
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
            "55bedee693ba9509306790d052ed60a21fcf8efeb1b0c66c009b4cfce8cd5c54",
            "a40635fe60ee49792ce6a8a7bf57ce8aefcde66b00efcff49e94a2a3a83b9a14",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "47947307496dc8a609a5c4535832870e0e949fa3006511cbe50ccf493453efc0",
            "d220bf8056bde3ea9b0918703e2eb2b61a40ec28360a183a982cfcd935d25dae",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "0fa9ba4950f46affbaec11c7e0b5a0ad760b6b0f2f303857356b14378e10b406",
            "ba0adf945ac6c84a1262ba385e05af15bf499a1e964e667f82fb71cfc970b2b4",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        5,
        &[(
            "Kuznyechik",
            "0416152e2f1bec21c55a91c4890212c929a4fd569e113bb84fc70dec6d265635",
            "356b36a51307c248bd41a6dbba9715b23be2f848d6c6fda92ccc706269b99fb3",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        6,
        &[
            (
                "Twofish",
                "5aeed39ba3d5a7bb9ee1f9c629a723104b0b01f53e14da8e77c31b6064ffe1b8",
                "1ed295e5d728bdc9bfab098f5fc961dc0fc6f832229b975eccc1f697f39a357a",
            ),
            (
                "AES",
                "3977a95112b7abafeaf2cd06bdf69ea0bafdde93128d8dcd30d570a15d8d8b69",
                "cc2027087eea01d3132b02d0079026245ddc8176db82c69937b43e9e1ffb3509",
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
                "fa04c3eb0767582a63396f309e96eccc4f31c9ac639e1e91be7bc0f766b991c1",
                "017b06097e11d8d903bff914db798fa1cc2204d2aaa26326f3706e903d415b97",
            ),
            (
                "Serpent",
                "041ef35e734c43ead7e33aeb8165a74dec6c51639a37442d1929ae500bf6bb66",
                "4cb65d45937574e2fc9770cfc0919b302007c44f326177a6e8fbbe700b31691d",
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
                "4b708c41ac5cad59a2fe9ca23040e6be6aec3095302815e3c4170d63b4d9c6bc",
                "fd8b9a1a3da9f9b439758d5183cad19dd0218536ee971fc0cff1e8b0dfb55c52",
            ),
            (
                "Kuznyechik",
                "37694a22333a55bb6d4661eb25b0c31c909b6cb04b7fb275262529e8906e5bab",
                "98ad12fac0131eebacfe7e277f7f12c8f8fc2f443242aa47f02bb21bc26f553f",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_w19_veracrypt_12628_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_w19_vc/run_12628/mem.raw");
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
