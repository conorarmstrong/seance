//! VeraCrypt **1.26.14** in memory on **Windows Server 2022** build 20348.587 (`MEM-044`): a fresh copy of the Server 2022 lab disk
//! (`forensic_corpora/lab_s2022_eval`) with VeraCrypt 1.26.14 installed from its signed MSI (the detached signature verifies against the
//! VeraCrypt Team key 5069A233...) and seven volumes created by `VeraCrypt Format.exe /create` and mounted together as `P:` to `V:`:
//! `a.hc` Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES), `g.hc`
//! Kuznyechik(Twofish) (SHA-512 / NTFS, passwords `SeanceVC-S22-12614-A` to `-G`). The ground truth is independent of this crate: each header was
//! decrypted on the host with `scripts/oracle/vc_header_keys_all.py`. See `win2022_veracrypt_12629.rs` for the host and the pool region.
//!
//! The 4 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_s2022_vc/run_12614/mem.raw` or name it with
//! `SEANCE_S22_VC12614_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_S22_VC12614_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_s2022_vc/run_12614/mem.raw"),
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
            "731fe216bea277eaef276668fcbc421c2fd9106063d4f4708ec8830680abd89a",
            "afebac89f2307cb7a640c81e46f124c8ab4a9a4c6dfedbf518dbad048af6c48c",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "011e39b9dd4a9bc09f0892b954d996cb3f697b3642486a7d0b52e6ecd9ccf1f1",
            "8dc05e26f3f58919b9ba09a1df449f3a2a8f984f88d259f29c674cd56e83a97a",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "4686f588208e96c07bd18af9b7cf3eb64f9092d7dfecf444b660a6a4bc840c80",
            "b92d104d8eea644924d5d0c57a0244e6505fce38eb3f7a30672a5ca87d8d1438",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        5,
        &[(
            "Kuznyechik",
            "63357177e7a8c62cfecb2ddd675760d1598f12a5df789e2ecfc6784a2e289589",
            "b5c5354b6e851fbcc1fafe94067c352ff61d62279fbdfbcf1b3f60231ad42028",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        6,
        &[
            (
                "Twofish",
                "446d164367cf9ce92b8de1fa63964a33109b69e0686ccdaa6cc47d54620e393e",
                "0e9f02589eacf399a21551641cdbb1734e94708a67631c4addd43604f97f356e",
            ),
            (
                "AES",
                "c9e824883ccec4e5e4de553b6c2f88fcb9270d9410333f2bfff4918b0e313b1c",
                "7abca0adfd072c465e5f238921356f281a41c14e7f00c32d39587792a1602296",
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
                "cd377ab702a43d4999df76246767584d702a3b6fc9e2c5557bee449a7b55ef19",
                "d547446b24fc63d8e182a0c52c56215fbdbd58e744f1d6abf6ac21cbb20e8028",
            ),
            (
                "Serpent",
                "6fa9fb3a54b68974021ab423c95047576a167793696c21a9dee851eeddbfbfaf",
                "bc147368288e2ab79c29b1f573fc8386fc5ce4eaf717acd847b9bd62d81b8dee",
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
                "024d5073c380672db5e08019442740dd1a84c850b6ae9e932e0eb81382631eff",
                "10f1f16a614d0872a768edfd327d5b4a5c91508fb46fce6853e7e01b573b393b",
            ),
            (
                "Kuznyechik",
                "5c23238f5925ed75bf1e8222651f4c80e5288cd1e2f3990a74b5df9ad528b614",
                "27d9d690eaee69fc7eac9588c9fefd781758bdbf893cffed6b1482f54555be85",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_s2022_veracrypt_12614_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_s2022_vc/run_12614/mem.raw");
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
    assert_eq!(basis, PoolRegionBasis::LoaderEntries);
    let region = Some(SweepRegion {
        layer: Arc::clone(&profile.kernel_space),
        base: chosen.base,
        bytes: chosen.bytes,
        description: "the region holding the loader entries".to_string(),
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
