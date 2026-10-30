//! TrueCrypt 6.3 in memory (`MEM-044`) with **a plain AES volume, a Serpent volume, a Twofish volume and five cascades mounted
//! together**: the Windows 11 lab VM of `win11_veracrypt.rs`, TrueCrypt Setup 6.3 installed from the TrueCrypt Foundation's
//! signed installer (detached PGP signature good; `forensic_corpora/truecrypt_installer/v63`) by its own wizard, `t1.tc` AES,
//! `t2.tc` Serpent, `t3.tc` Twofish, `t4.tc` AES-Twofish, `t5.tc` AES-Twofish-Serpent, `t6.tc` Serpent-AES, `t7.tc`
//! Serpent-Twofish-AES and `t8.tc` Twofish-Serpent mounted as `P:` to `W:` by the real driver. `TrueCrypt Format.exe` has no
//! command line for creating a volume, so the container files were written by `scripts/oracle/tc7_make_volume.py` from the
//! volume format specification (header version 4, as TrueCrypt 6.x writes it, fresh random keys; `vc_header_keys_all.py --magic=TRUE --hash=sha512` reads each header back
//! and its keys equal the writer's); the real driver accepted every one (the mount is the check that the headers are
//! TrueCrypt's). Only `truecrypt.sys` is loaded in the capture (the guest was cleaned of every other TrueCrypt and VeraCrypt
//! driver and restarted before this version was installed). The test asks whether the sweep finds every master key by its hash
//! and reads each container.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_truecrypt63/mem.raw` or name it
//! with `SEANCE_WIN11_TC63_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_TC63_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_truecrypt63/mem.raw"),
    };
    p.exists().then_some(p)
}

/// `(volume, cascade name, container id, [(cipher, primary key SHA-256, tweak key SHA-256)])`: the keys as the host
/// oracle read them out of each volume's header. The cipher order is the oracle's, not the buffer's.
#[allow(clippy::type_complexity)]
const VOLUMES: &[(&str, &str, u32, &[(&str, &str, &str)])] = &[
    (
        "t1.tc",
        "AES",
        1,
        &[(
            "AES",
            "11c6c24003e584a0d12aa9c5faae32c0146677896a194854e7f152cb0966879a",
            "1d1c35c9d75819877cab57de425390e7a9ad12f1081e56e3ca82945ac629485b",
        )],
    ),
    (
        "t2.tc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "9c73eb58937a95d83c56f66d49b62280bd9fc10e60eed5b7088f2a6be548877b",
            "b5dd78290125e56de62ce5482b08c65ef41f88fe2a78e6177a320e24ed0dfa57",
        )],
    ),
    (
        "t3.tc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "96945322a9dfd4f0a61ca7af55a0ce823f526a90a6e25656abe43408a2c7cf11",
            "94bb6fc8297518f663343e682fda5e858461d93e16dd5ad0352a95b930fd5103",
        )],
    ),
    (
        "t4.tc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "22e4793018841c853b1426cdeeea12d5a6c822704c3b3804729c1aff68ca53c6",
                "575b8a186bf6b0d3c933578e2b5e684b87b67b3d94521c74f4f4518e14842283",
            ),
            (
                "AES",
                "01087f5f2efb1e89838ac35d71bf0962aabafdb71aa19cdc1082ad0a055b1ac0",
                "fbb5896954bc9633135b19f08bf1bf02d7915207355f02d76236802dc9bacc4e",
            ),
        ],
    ),
    (
        "t5.tc",
        "AES-Twofish-Serpent",
        5,
        &[
            (
                "Serpent",
                "1c7c965108466dc9de0433038927ad40e770bbe822daf0803b68a42daa58642a",
                "371a29e93478169c051b2d51ab49235c00f91c40fa9b75aa2f3a23dae5267426",
            ),
            (
                "Twofish",
                "2a62fb73d3886d1baf0e7216c20fec68fcb83b47e5098541909e543b8c42ce80",
                "2c4ad0037910fbf27dfec27252708692983ea12280148f51c8f3781e6adf29ca",
            ),
            (
                "AES",
                "357cda3934a53a3b82251671f420f0f06660846d2a384463039ebd8234a4e43a",
                "792ada11d4d3bcfe6daf716cac379f37c43ccd5ec6fe3a5e8b34483cc1af1bbd",
            ),
        ],
    ),
    (
        "t6.tc",
        "Serpent-AES",
        6,
        &[
            (
                "AES",
                "4956f1eb94bff31c0f54ee0088e68315fdb93a3ab1e544406ad7180fe8912707",
                "a8ca36b5bd50a7f068d0c3316a6b40206815184da0d03a025eb8acabe320b5d7",
            ),
            (
                "Serpent",
                "951ba7ff4c92f44ce4eb113ec79c3eb72a2b8729675042eb0183fc06a74bd983",
                "a743c65dac0de5edce738d43aee1cfaf5e65f2903b87ddc8239997a3cca36d2a",
            ),
        ],
    ),
    (
        "t7.tc",
        "Serpent-Twofish-AES",
        7,
        &[
            (
                "AES",
                "7a3c769809a1a1db53d528753291d705ae98392373cc7f0fbf532da467badf3e",
                "9f3d8f4676a8fb9fac67a53e349f906ac1cf3dd29fda3f40e26be15663bd3bc9",
            ),
            (
                "Twofish",
                "be9ba1780205b463cd4f187e2f187d2b018b0ac5927c9df7e06db7ab4dc254d2",
                "ade44e52ab77a28a0908733b23dde65c583773d09eec9fa350fa912f7900b269",
            ),
            (
                "Serpent",
                "b184b4fa2aa72c938999891cde6c478ac6c25d954b2844fddce10cfbcab2733e",
                "9db2b7939b2a23617df08311763b02d24afe660ed0b721f73b8a127eb0f7a071",
            ),
        ],
    ),
    (
        "t8.tc",
        "Twofish-Serpent",
        8,
        &[
            (
                "Serpent",
                "025c67142d3b86a4c45ca66ded8e8981041609e63c77a330a46aa01a56803adf",
                "7ff7f02dd8befca4a8b93947b21c291ab2a144443ab523a146081ff61a9dba5b",
            ),
            (
                "Twofish",
                "7c00da78fdcb1610c858fdec0ad9d06f40f97921f0a85029732e4668854f95a0",
                "fee1983cee274381194292763dd565c1d2e4fe203f01b41505f8bbcc59c22ef1",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn truecrypt_63_eight_volumes_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_win11_truecrypt63/mem.raw");
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
            "TrueCrypt 6.0 to 7.2 and VeraCrypt 1.0e (observed on TrueCrypt 6.0, 6.0a, 6.1, 6.1a, 6.2, 6.2a, 6.3, 6.3a, 7.0, 7.0a, 7.1, 7.1a, 7.2 and VeraCrypt 1.0e)"
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
