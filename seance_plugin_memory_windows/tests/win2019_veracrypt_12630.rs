//! VeraCrypt **1.26.30** in memory on **Windows Server 2019** build 17763.379 (version 1809) (`MEM-044`, a fourth OS build): the Server 2019
//! Standard Evaluation ISO (`17763.379.190312-0539.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso`, fetched over HTTPS from
//! software-download.microsoft.com, SHA-256 `221f9acb...`), installed unattended under QEMU/KVM with the Server 2022 answer file, with
//! VeraCrypt 1.26.30 installed from its MSI and seven volumes created by `VeraCrypt Format.exe /create` and mounted together as `P:` to `V:`: `a.hc`
//! Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES), `g.hc` Kuznyechik(Twofish) (SHA-512 /
//! NTFS, passwords `SeanceVC-W19-12630-A` to `-G`). The ground truth is independent of this crate: each header was decrypted on the host with
//! `scripts/oracle/vc_header_keys_all.py`. The kernel's symbols are `ntkrnlmp.pdb/8B11040A5928757B11390AC78F6B6925-1.json.xz`.
//!
//! The 4 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_w19_vc/run_12630/mem.raw` or name it with
//! `SEANCE_W19_VC12630_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_W19_VC12630_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_w19_vc/run_12630/mem.raw"),
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
            "ee93f3130e42e4a867c079ae9b25d312f08a593e4e9cfb3360674f46f91a9d50",
            "c185899c93dbdba5c0015b4de90924b0aa3e8226039001977a7b6ed05afde1d3",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "5825ff3b41a422085e3492a97ec93520c716c33dc61adf7bb7d942c0e7c77aa2",
            "b4270b1caa8529fcb4235c54dfcfa0a0b161d8a83ea7707e867333954cc67dca",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "469e7e7a49b7fd66f5698545efbecef5cd1884ae1c85b550d05f5e806bf639f0",
            "75634314620ed9dcfbfeaa86d36933958d8a92c005d6704db08904fda425f66a",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        5,
        &[(
            "Kuznyechik",
            "6d4e8d7b7da5119d40915b3de464b2fe3d2f521ac6c3f873643aae61220ff140",
            "d10c20774b1d7a827272ed67d8169f819f86d50dfc704b79717f108e4d634430",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        6,
        &[
            (
                "Twofish",
                "45fdb276502928b6f689e208f608ce26f277e9c43ae83f3842560cd82b457066",
                "4a00573c54b7f63d1cbf701b1ce092387810d2453043701478b0f01a9b1fa18e",
            ),
            (
                "AES",
                "1ea3cec1bc6716ab5faa8c9bd47b020d781799fab9bdaf28be3b0f815b4c82f3",
                "e5fcd62a5ef8068bf9e232c608cea6c33b00f0845ef65faf96bcf665c270bd19",
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
                "ee48b47f7e9514b53c4d62f4754747ee8dc44207d37fead5c1301d452aa5fd62",
                "ccc5529ee8e3da5e497fc4927b7ee6917e42d0a86ab4440d06bfdf48c5515ca5",
            ),
            (
                "Serpent",
                "d6bfc8bdc84a67545bc83b460f19d4f95b679425ae2dfd47ed8a86faae6c6273",
                "04c9cbe1a656e638db88fc45d3071ec91fb53b39ba03cce2019ae09bb69f2c66",
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
                "a58d01ccb970b87dffc434a4b7a95597c4e71469da2f224396d9ae45a91cf3d0",
                "4505d0952b631627bc073a7c6f239c4e396dd76155f8c0d2c2c3a5530d28f089",
            ),
            (
                "Kuznyechik",
                "c48277d76046c726301e511335904f573c527ad7a3a7d52d4b6fa8e6ff758ff9",
                "9f3348462f1b1aa8aeb0a1256741ad33b91cf3701f5b28e54ac1edc02ef5cc05",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_w19_veracrypt_12630_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_w19_vc/run_12630/mem.raw");
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
