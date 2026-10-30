//! VeraCrypt **1.26.29** in memory on **Windows Server 2019** build 17763.379 (version 1809) (`MEM-044`, a fourth OS build): the Server 2019
//! Standard Evaluation ISO (`17763.379.190312-0539.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso`, fetched over HTTPS from
//! software-download.microsoft.com, SHA-256 `221f9acb...`), installed unattended under QEMU/KVM with the Server 2022 answer file, with
//! VeraCrypt 1.26.29 installed from its MSI and seven volumes created by `VeraCrypt Format.exe /create` and mounted together as `P:` to `V:`: `a.hc`
//! Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES), `g.hc` Kuznyechik(Twofish) (SHA-512 /
//! NTFS, passwords `SeanceVC-W19-12629-A` to `-G`). The ground truth is independent of this crate: each header was decrypted on the host with
//! `scripts/oracle/vc_header_keys_all.py`. The kernel's symbols are `ntkrnlmp.pdb/8B11040A5928757B11390AC78F6B6925-1.json.xz`.
//!
//! The 4 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_w19_vc/run_12629/mem.raw` or name it with
//! `SEANCE_W19_VC12629_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_W19_VC12629_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_w19_vc/run_12629/mem.raw"),
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
            "0589588bdebd38949dcdac9a750bfe89c55105d23d446b38fbeae593e6b28caf",
            "4ad85eae018fc1cc5da44fbb3298a0eb4de3f4c5edea7fea83d77c4ad8af3fa6",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "92dc3bbabff0120a6fcfe82fba395053f8b1f64b20542671a70f45bddba23143",
            "eafbbb2641170ff90fcf0207bc8a9a498859a5f0b5ade852b307ab253cd6e6d9",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "4d62d751b6374f0405ec65a9503c7749c3dd911e1dd1c699909633e60fc5aca7",
            "557901bc70cf4f5ba9bc59680956c9c227e1d5352fc634a0ed7d921a7fca43df",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        5,
        &[(
            "Kuznyechik",
            "ff21f7037a692045bcf01264b28e46d223ceb65c6e945d891453453cdc786c83",
            "29f0780ccf89f04d7b7b570756744aac6a31711392c3456eae9717a7448fccea",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        6,
        &[
            (
                "Twofish",
                "cb4d906c9f42a30950fe05db2a900c6757dc21d446edf252dbbd3b0079428603",
                "9acf4616137f691d251970ac0907a9769c1a20f838467b00394e9fbf6a3201b1",
            ),
            (
                "AES",
                "26f7b81153f17a4797db24f2fe6042e93344b04c4823ecf68344a8a75af8ada2",
                "06b1392f721d166d1937f61f74e494d6169ba92c49fde9395ca40c41eefdaf80",
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
                "bd2ce856010da249b0cbc7beaba5895a7c3017755c1dca2902758ca19e92e963",
                "62ddeb6961582b2ff206ceade5a323c5187989a8fc833c81012f0b1869b14d34",
            ),
            (
                "Serpent",
                "37eb9f2542152fcd8925ab7d6ca72041cfa78ac27d5be4f9361cc7a30915007c",
                "0ba35457b13b0ae1257fec919306892ca76efeb30aa2019625f2119e54d3409a",
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
                "8d0a2d5693f6fa46e6c47ca722c4af0c0304fe5b56adfc413da237e8e2cf3a54",
                "3dfa84624a1857f5e3b9b321b7d984f78dcf61d32bc151ce575b4e0f7d4ca257",
            ),
            (
                "Kuznyechik",
                "5d1e881be9fe07f54bab2e3eb744ba184362de837e8f3c63cb9a8aba6a9edeff",
                "46b8751599d28b510dc8a6580725f2c04e3069cdb80fb28fda9c527c78c18ac0",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_w19_veracrypt_12629_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_w19_vc/run_12629/mem.raw");
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
        assert_eq!(
            info.layout,
            "VeraCrypt 1.26.29 to 1.26.30 (observed on 1.26.29, 1.26.30)"
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
