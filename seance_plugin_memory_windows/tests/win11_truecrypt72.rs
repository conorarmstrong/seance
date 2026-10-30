//! TrueCrypt 7.2 in memory (`MEM-044`) with **a plain AES volume, a Serpent volume, a Twofish volume and five cascades mounted
//! together**: the Windows 11 lab VM of `win11_veracrypt.rs`, TrueCrypt Setup 7.2 installed from the TrueCrypt Foundation's
//! signed installer (detached PGP signature good; `forensic_corpora/truecrypt_installer/v72`) by its own wizard, `t1.tc` AES,
//! `t2.tc` Serpent, `t3.tc` Twofish, `t4.tc` AES-Twofish, `t5.tc` AES-Twofish-Serpent, `t6.tc` Serpent-AES, `t7.tc`
//! Serpent-Twofish-AES and `t8.tc` Twofish-Serpent mounted as `P:` to `W:` by the real driver. `TrueCrypt Format.exe` has no
//! command line for creating a volume, so the container files were written by `scripts/oracle/tc7_make_volume.py` from the
//! volume format specification (fresh random keys; `vc_header_keys_all.py --magic=TRUE --hash=sha512` reads each header back
//! and its keys equal the writer's); the real driver accepted every one (the mount is the check that the headers are
//! TrueCrypt's). Only `truecrypt.sys` is loaded in the capture (the guest was cleaned of every other TrueCrypt and VeraCrypt
//! driver and restarted before this version was installed). The test asks whether the sweep finds every master key by its hash
//! and reads each container.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_truecrypt72/mem.raw` or name it
//! with `SEANCE_WIN11_TC72_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_TC72_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_truecrypt72/mem.raw"),
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
            "df100b59d8f776d733b43be756530572ef1749add1961c64518f2d5be14558a2",
            "e64d8855d77e3cbb5ad649cc6ce81c98a6037930c124c429bbc6def79276751b",
        )],
    ),
    (
        "t2.tc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "136df0e9faaa0ad3b9a62e89ff320f148aa37ccfc4514ce0b8eb922cd79bc3b5",
            "f9038235bc17957f3c9fffae087da0ee4b7b3b565e8adae388acc6683ecc1b18",
        )],
    ),
    (
        "t3.tc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "f4571fc88587bfdcc8a0d8b6695e0bb405dba744fec4d5df3e3e0cbf80affcea",
            "c13d4ae4ce5f29fad1e44b62ba8233bbda634ab8ec3e3bc54f7c809ca4c2d8fe",
        )],
    ),
    (
        "t4.tc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "1c079d542fb45f5cbde24ee9d281e490d272f4cf0cb0fd837b56dddf4df86d2c",
                "421fdfa9c5d7ccbe4586ef15db71e54449d4354f31fc95032dc4b64c1c8bd486",
            ),
            (
                "AES",
                "74c64f68feb4a31194bd0de047a06a9544b1fcbbc3ccc856373165f759f0d0c5",
                "b662141581a8fb1540aa7bf4ce7cc6e8a8a8b581fa24ecc72d8835f4fe0cb8ee",
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
                "231ad732c408fb0b109c3c8c9ba1eef49c9a0289f25f03d23af8b13596543ff2",
                "b6b1caabb8f465a473809540a727ca06eddc5d2ef6e9e039751fd361c8720754",
            ),
            (
                "Twofish",
                "227da030aceed02f0bc67f085d5f7db94bc4d011f6821b61483304b3b06514fc",
                "ab1896fa75c7281a7e5a1d7bd769de0a9ca0f3ea0b493de3b9c5caa88689ca19",
            ),
            (
                "AES",
                "dc71ac28fe25c16bf0232f200192e8efee6703efbd6c594563671db25ca557f4",
                "c1a658f424992a39d7cc6533ff969730fa609e196972263ab68e79a0b0b14d51",
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
                "24208c19574f6b6942f6854514de1fd51441434ff97fcd962910dcd7425c4af7",
                "95e424cb5fdd350a50d3fed98a1507986a06d55cf0e4243e3b092a6e978f4fe8",
            ),
            (
                "Serpent",
                "ea6481a9ac58d4d58e442536dd273e5fce0f9abb2498cee9aa124b5a75c182f7",
                "956b7c7f6bf47066d7808c6b1383558c7b7b4ee830e6019e21ba5af9236b618c",
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
                "4e7f72fe4c541d3f86c2474b0ed0d82e7cd4817623b9eba614c69d91b142f0df",
                "c13548a53ad9660e87c2a82b724b2946144fcbae2a295bf73f1476d87e888053",
            ),
            (
                "Twofish",
                "488ab2070abb16d6448ec34504fcf5716d108c6dd122eaccfab26b6168a94908",
                "14e72d55a6adcbb14259307676e78c6b6bd51ae08268f042aafa61d7853410d3",
            ),
            (
                "Serpent",
                "4c82190cd3e7e7a8dba222fd54710201c60bdf36df29269d1aa6e3dee0b752c3",
                "9563c5bffefd73845c9e7541207db435f6583ee5ed523630acece93dd44c542e",
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
                "64b214d541e23f87917d3eb2b363a4ea9318c0dfac1720d89d672c1674271bf4",
                "49a5fd9f55ea78060592ab91b28b905b91dc1d3ea9475e3be602e60d0fd971f4",
            ),
            (
                "Twofish",
                "4f2dc423d8ef26a678b1c72b75cf13d60049047f0324e278f6b0a87268ca217a",
                "311873ab933a8b127ba14229832fd321ecd813c9cabfeae632c8c2c5c10ea7fc",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn truecrypt_72_eight_volumes_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_win11_truecrypt72/mem.raw");
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
