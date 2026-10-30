//! VeraCrypt 1.25.9 in memory (`MEM-044`) with **a Camellia volume, a Kuznyechik volume and five cascades of them mounted
//! together**: the Windows 11 25H2 lab VM of `win11_veracrypt_1259.rs`, with `p1.hc` Camellia, `p2.hc` Kuznyechik, `p3.hc`
//! Camellia(Kuznyechik), `p4.hc` Camellia(Serpent), `p5.hc` Kuznyechik(AES), `p6.hc` Kuznyechik(Serpent(Camellia)) and `p7.hc`
//! Kuznyechik(Twofish) (SHA-512 / NTFS, passwords `SeanceVC-P1-1111` to `SeanceVC-P7-7777`) mounted as `P:` to `V:` when the
//! memory was dumped. The ground truth is independent of this crate: each header was decrypted on the host with
//! `scripts/oracle/vc_header_keys_all.py` (Camellia by `cryptography`, Kuznyechik by `gostcrypto`, both checked against the RFC
//! vectors first), which gave the digests pinned here. The test asks whether the sweep finds every master key by its hash
//! (the Camellia keys are recovered from their `ke` subkeys, the Kuznyechik keys are the round keys' first 32 bytes) and reads
//! each container: the ids on this version are **4, 6, 12, 13, 14, 15, 16**: Kuznyechik alone is 6 here and 5 on 1.26.29, and the cascades are one higher.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_ck1259/mem.raw` or name it
//! with `SEANCE_WIN11_VCCK1259_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VCCK1259_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_ck1259/mem.raw"),
    };
    p.exists().then_some(p)
}

/// `(volume, cascade name, container id, [(cipher, primary key SHA-256, tweak key SHA-256)])`: the keys as the host
/// oracle read them out of each volume's header. The cipher order is the oracle's, not the buffer's.
#[allow(clippy::type_complexity)]
const VOLUMES: &[(&str, &str, u32, &[(&str, &str, &str)])] = &[
    (
        "p1.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "ac1540afaca24cde8eb4ba9c5626dda3eab2bae243593ab7be070cc54fa32660",
            "71fb92732844e1e68d253986849e48fe9afc690a734b08492b4758854485def9",
        )],
    ),
    (
        "p2.hc",
        "Kuznyechik",
        6,
        &[(
            "Kuznyechik",
            "04d68577d379aebdfa056675c32504223ecc8ae13ba28c03fe64a0c3cdb1ba02",
            "cf6f873162316a55eb5edeef18e9418b8c7029fb8c343e7ab11252758b15d634",
        )],
    ),
    (
        "p3.hc",
        "Camellia-Kuznyechik",
        12,
        &[
            (
                "Kuznyechik",
                "d8b573d5c257bb46bdd2408a775c4ec473a4e5b923e2997e02bbda29eeef1cfc",
                "59dc5a903f92e1375a3b8bf60030d0578dc74566af3e601ff5f15bcad6dfe121",
            ),
            (
                "Camellia",
                "d41e435ea25d7c58c694c57d5f1dd7fe42ac7bf46c9b9028cee4a8bab94f7bb5",
                "5cc6b6029947a449fd48185cb8df8e83d7235f5fbd476e4e5406d5b51c7231d5",
            ),
        ],
    ),
    (
        "p4.hc",
        "Camellia-Serpent",
        14,
        &[
            (
                "Serpent",
                "ce6cd29f53b7b344d4befa3f8475b8777a648577176b7e44bb48d9472948a463",
                "12b618c999a101f4d1a89f7c056282ac3ee2e4d8cbf0e472ad96f280028cd0c4",
            ),
            (
                "Camellia",
                "dc8e8e7f921489908d9c67e4ef2f1784c6b4de0232b5a134806b9bb66cc65372",
                "f591bc40dd4916d786072322ca100663af35d5cb5f11637c6003e542028768b6",
            ),
        ],
    ),
    (
        "p5.hc",
        "Kuznyechik-AES",
        15,
        &[
            (
                "AES",
                "b1ee34d524916259f32d54b24586df9541c0842ebc443bb25e4e284647868730",
                "c5cea9aaf68fda007f7b8deb625652b004875e1a4f36315a4d774cc432125641",
            ),
            (
                "Kuznyechik",
                "270e5eb3a5d8c4c7368248ff619d26f69c52a50056cbd74cd651bde78e0f5e9a",
                "cc1bd14fec66ce0c26ff1bbd64a4a1effe5f5019c325b027b5e7382d0dc04f0b",
            ),
        ],
    ),
    (
        "p6.hc",
        "Kuznyechik-Serpent-Camellia",
        16,
        &[
            (
                "Camellia",
                "9c72fc7319e4f1fdd4fee6cafeeebb0324268dfaa5be406ef70c975d5812c773",
                "b69f85683d0c129b9399b3d2a04b1ee76d91a77499ed909d67d507993c26969e",
            ),
            (
                "Serpent",
                "65cd4eca8896a2c689d79abc20237f079fcc8947799d3fcc7400ba6793448492",
                "c4292d7424a003c21cefa361fda20c360ec619c16a23c88e4d1faa06ad502150",
            ),
            (
                "Kuznyechik",
                "deb37c03ce3c501cac82e2e00028adbd9f05412951f8a86a6ef6f644aaa8db69",
                "f33f5cb0fd2804f9e7af577efb22056530450de5f39ed7d4d50b23761e7656e1",
            ),
        ],
    ),
    (
        "p7.hc",
        "Kuznyechik-Twofish",
        13,
        &[
            (
                "Twofish",
                "928a9f0b59063c4bf24f76fde9422167cc963b679f32c4b7ef298b7a551ae947",
                "e9c2cad9da1fa2829b3cc3081efc81b2b6e989fe5179da6107c12fd1c9aeab65",
            ),
            (
                "Kuznyechik",
                "0fa59de7d6c7d55c4286b589e6b2d1ac039b3eb52accef65106765d0a04113a8",
                "820e87e87ae9c2e71128a0460cdf4953e79c78e65ced5bc9a93214235c9818ab",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn camellia_kuznyechik_and_five_cascades_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_ck1259/mem.raw"
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
