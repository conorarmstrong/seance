//! VeraCrypt **1.23-Hotfix-2** in memory on **Windows Server 2019** build 17763.379 (version 1809) (`MEM-044`, a fourth OS build): the Server 2019
//! Standard Evaluation ISO (`17763.379.190312-0539.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso`, fetched over HTTPS from
//! software-download.microsoft.com, SHA-256 `221f9acb...`), installed unattended under QEMU/KVM with the Server 2022 answer file, with
//! VeraCrypt 1.23-Hotfix-2 installed from its MSI and seven volumes created by `VeraCrypt Format.exe /create` and mounted together as `P:` to `V:`: `a.hc`
//! Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES), `g.hc` Kuznyechik(Twofish) (SHA-512 /
//! NTFS, passwords `SeanceVC-W19-123h2-A` to `-G`). The ground truth is independent of this crate: each header was decrypted on the host with
//! `scripts/oracle/vc_header_keys_all.py`. The kernel's symbols are `ntkrnlmp.pdb/8B11040A5928757B11390AC78F6B6925-1.json.xz`.
//!
//! The 4 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_w19_vc/run_123h2/mem.raw` or name it with
//! `SEANCE_W19_VC123h2_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_W19_VC123h2_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_w19_vc/run_123h2/mem.raw"),
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
            "69b58f8b34fdd19c824e788758f41908fc62bb76e1a18f61e96e63a555e80acf",
            "bcf43435c0e04bec60ae1f1e30327d27cd5f832ea27faed1f3ab48cd985e4bab",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "1583522dd5b90a4ef5f21a37f1c0b75291c107445c4c98806f57b5c0793a2293",
            "6e55c4531a4da61c50d61f80ed154a75fab1cb74226626f97ad9a97ac3d58a16",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "45c052a28855cd3bb34066070f5d2ade4083cffb0ab0f30d955c06799e4edb5f",
            "562d1580ac5cc302ccfc3ea5580420699874c9922f5db9f4e57af1d273136596",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        6,
        &[(
            "Kuznyechik",
            "12b05d8e5af77bf3d85eb4e2c13d8dd6a08b3efc4ec1975a614cf4a1654a7bdb",
            "72d2977511ef846aa09e7b75caa967233de94e682d556b81ee4c349520f3a02e",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        7,
        &[
            (
                "Twofish",
                "57a36e86853a426d2e90a3d44deb693f98735cb7a5d6ce003f23e43c860a07ea",
                "85662be542cc9b2a8f6aa0b9a9e28211490402235019dc2769edc2fda93cfd36",
            ),
            (
                "AES",
                "f18c574a9f8374e0370f43aaf0c1b87432213f162815765b11b42116d1f240d7",
                "49674e153ac46fcfa87eea70aba363f608b27c20b601a3102edd08112f186ab6",
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
                "bad1c5da176295e3ef58c13394a6736a652473fc7c5f946306ebf0ebc15a86e1",
                "485cb98de87f52c25a09024927427f8a72a6c4f9251f3b0b65deab0c1a3561ec",
            ),
            (
                "Serpent",
                "636c2bd88892c7035bbf357fa1b025cc30e4b2b917df7cc3dd8124ea28e3e293",
                "06c2bfbc38f9e8ff30f262dbb3ad561b12717f4a1d3ceb56af1504f624230fa7",
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
                "49c6aaa2f0c6e0931d8050a2f032ae9f2005049c952ee9d6792bc1979f77afd7",
                "ff3c33bda635c14e2d8981d1cf40055f83c3a9a21057c02bad0614b46b78599e",
            ),
            (
                "Kuznyechik",
                "702538b475a1f88796694e0b671d9c6ac3f2c6eb4bb9e93bd1a22c2b562813ed",
                "fde9a6b8ba8b4ab51ce57f39bca86ac19c7b25866729a2ff27ad603adabe8701",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_w19_veracrypt_123h2_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_w19_vc/run_123h2/mem.raw");
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
