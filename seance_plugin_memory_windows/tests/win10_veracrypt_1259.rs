//! VeraCrypt **1.25.9** in memory on **Windows 10 Enterprise build 14393** (version 1607, the Windows Server 2016 kernel) (`MEM-044`, a
//! third OS build): the evaluation ISO of Windows 10 Enterprise 1607 (`14393.0.160715-1616.RS1_RELEASE_CLIENTENTERPRISEEVAL_OEMRET_X64FRE_EN-US.ISO`,
//! fetched over HTTPS from download.microsoft.com, SHA-256 `f32f451f...`), installed unattended under QEMU/KVM, with VeraCrypt 1.25.9 installed from
//! its MSI (SHA-256 checked against the release's list) and seven volumes created by `VeraCrypt Format.exe /create` and mounted together as `P:` to
//! `V:`: `a.hc` Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES), `g.hc` Kuznyechik(Twofish)
//! (SHA-512 / NTFS, passwords `SeanceVC-W10-1259-A` to `-G`). VeraCrypt 1.26.29 refuses to run on this build (it needs Windows 10 1809), so 1.25.9
//! is used. The ground truth is independent of this crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`.
//!
//! The 4 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_w10_vc/run_1259/mem.raw` or name it with
//! `SEANCE_W10_VC1259_MEMORY`. Its symbol file is `ntkrnlmp.pdb/DD08DD42692B43F199A079D60E79D217-1.json.xz`. Release only.

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
    let p = match std::env::var("SEANCE_W10_VC1259_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_w10_vc/run_1259/mem.raw"),
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
            "e9588a181b4a60034af24b83fc286e6cf4efa0457572a05338ddb2271c344380",
            "7b138b27a8cf5464ce7ce4cce826277f7bfb8d113f36048717b89e9833283a35",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "510ccd988f3996b060e9c93ac01c5932a6972c8a8d2b0989a65e60dc3e25c5f1",
            "17ecb3db6f340d0b0f5e6b6a638b9a3ce0459082da54fa67b30002b49a6fff4d",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "197322ce193ee08be2bc2b362beb383acef8c5e100ce9774a75dc854cab4bc1c",
            "3ec88b873b988fe003fa90e88dced08ad036f87828d44d0a28c4d2efdf6b46ee",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        6,
        &[(
            "Kuznyechik",
            "cce9b440e40a4b446e620e08343fcbf260ad5d6732128161450d816466663b87",
            "c746945ebe56fa4dd94738d180fbc853c41fe2697606902591976c1141215eed",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        7,
        &[
            (
                "Twofish",
                "8537bb1ffeb79f5c846e5185e17995794257451526a3f9750e762fc5f4fb83d8",
                "bc21f1f19234d76b6a81fe2e2635a55d0869b86c365daf7977bc8914d0723924",
            ),
            (
                "AES",
                "7dcb91f4667fbb7e2f99e15525516db768c26fadb8e36635cfcf2d1103ef73f8",
                "0ce5885b9662398606185648247bace76f3a71973f339df2ce033a4740ac0e25",
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
                "cbf75dcaf90d53cd7a64ccc5db2e0876ac872d2be09ee55f5732325f4d9f77ca",
                "2c0f3a6003b4a9a80d8c52bbeb1cf30655c4392e9ccb666e255a8d82af360714",
            ),
            (
                "Serpent",
                "1601617ad647244e592cc322e4a5584215c96fa892eb744c4bf28b4415d21714",
                "2022da718338040ba8520ae92e5264fa216938ee7a175830dd6ca75231aa9c60",
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
                "223940c54a0c7bcdf0851670eaeb06f20a3fbf35503e96015895146a2fac2f1c",
                "12b692250d56ff957927bacc02ad5d81afd8cc2f7b577122fbb0afa0b0b2e19d",
            ),
            (
                "Kuznyechik",
                "3636fa9f8b4dc1453b2f636d5eecae8af4956e4244053eb0b2b5cbcf99ea2999",
                "24d892d74c43562f63d0a9bcfbe1bc5425db6605fca45df6cd3bd94a2ed974bf",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_w10_veracrypt_1259_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_w10_vc/run_1259/mem.raw");
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
