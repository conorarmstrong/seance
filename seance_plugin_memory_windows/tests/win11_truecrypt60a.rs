//! TrueCrypt 6.0a in memory (`MEM-044`) with **a plain AES volume, a Serpent volume, a Twofish volume and five cascades mounted
//! together**: the Windows 11 lab VM of `win11_veracrypt.rs`, TrueCrypt Setup 6.0a installed from the TrueCrypt Foundation's
//! signed installer (detached PGP signature good; `forensic_corpora/truecrypt_installer/v60a`) by its own wizard, `t1.tc` AES,
//! `t2.tc` Serpent, `t3.tc` Twofish, `t4.tc` AES-Twofish, `t5.tc` AES-Twofish-Serpent, `t6.tc` Serpent-AES, `t7.tc`
//! Serpent-Twofish-AES and `t8.tc` Twofish-Serpent mounted as `P:` to `W:` by the real driver. `TrueCrypt Format.exe` has no
//! command line for creating a volume, so the container files were written by `scripts/oracle/tc7_make_volume.py` from the
//! volume format specification (header version 4, as TrueCrypt 6.x writes it, fresh random keys; `vc_header_keys_all.py --magic=TRUE --hash=sha512` reads each header back
//! and its keys equal the writer's); the real driver accepted every one (the mount is the check that the headers are
//! TrueCrypt's). Only `truecrypt.sys` is loaded in the capture (the guest was cleaned of every other TrueCrypt and VeraCrypt
//! driver and restarted before this version was installed). The test asks whether the sweep finds every master key by its hash
//! and reads each container.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_truecrypt60a/mem.raw` or name it
//! with `SEANCE_WIN11_TC60A_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_TC60A_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_truecrypt60a/mem.raw"),
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
            "32b6cd3a509a3cbfe7e3620157766b4fb49a32e84454e751fc5749c42ea477c7",
            "5adaa7d5ea1386e60def9ec9700ceeab82cef867adca40d9c748f1e10ca735b3",
        )],
    ),
    (
        "t2.tc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "b81f87a0e3359ae16b01ca41807d0e82f7fd66f9be183bda76830ac00de19421",
            "08fa99d32125a7eb678f600e188a8b74299c2bc1aee78ec48940a4344a674abf",
        )],
    ),
    (
        "t3.tc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "093b23d4f54c178c7a483686b46a80b76a93dc818ed6a3d90e982abf53eaccfd",
            "24c7d3fe004eff805a0ec1a2a2b3d4d403776efb0ea76b4ad798e347cf629d9e",
        )],
    ),
    (
        "t4.tc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "d0d2413216c044b9a75707d541545440bc221180c9695cb6a8f262600ae1403a",
                "2fc7f47777da1e118dfb7cfb40add019ee1cd0e2038012df4db8858134fe8e6c",
            ),
            (
                "AES",
                "badea472f5b2e80618d79841d8839fb6c9ef0267786dbc49571801782bae2b4b",
                "18a9a4e8134bcb818794bdc9070acae69320d99dd3789946fcbdf5e8cd75a091",
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
                "5dd0c275709da70b1b3672a95e7652899baa9c431e7d0a92e45e3bf925abc2e9",
                "d247f141d043cce2f1c5594a565bb9e22567121ac4248c1a1ed465f4d6f92e88",
            ),
            (
                "Twofish",
                "8f79c4ef4f8212178dc5c751704be180fbbe5030f52b96529ee5274889cd65c0",
                "b2e900ecb6adb9a901a6fefa14aa8d5a3ebce651b1e38f566c7bca460a371920",
            ),
            (
                "AES",
                "ced0f561ee7ed0ca8d463d48736a602d9af6a9b05005ab0d68ffe56ac9194333",
                "c32aca8179c4f60646dc290de8778438eb390fd9c90c489d0163cfaeb2d09a98",
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
                "c4c4cb41e10bb72c0b239db5d4cb04e06e99204338b7a92ccd11fac7f99dd375",
                "5b9683156b0ae05e1c279a050305a5a128f9efbe0102a3f28053b302437e720a",
            ),
            (
                "Serpent",
                "98f9f72a368f48422bb4e25b976b606796900813f05b531aea2abdb1e4a04eb0",
                "ab1d95ad46cb0f2fb928461662f5669e45a972cc15a1d7a35f19e259b945cd0c",
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
                "fcf7f862a149abac39dfed1c3fc4b51c650acd86d407d86f71a5715a7647767a",
                "686bf22207cb8c71e0af6f152b992ab5feee7776a8f45de1a7575ddd5de078f0",
            ),
            (
                "Twofish",
                "9fa9d4cb98f0d4061d86a1b4f778b9741b0f9dcc14ce41da9bfd0941299649d8",
                "3ff9cd2c65c6bd08990b90746a32646e95f6b0e248d17a69f020f19043719f8c",
            ),
            (
                "Serpent",
                "817dc7d38607c77f2df90d162dbc3fca8c4c07eba45d74cadcaf4eda4aeb1620",
                "5fb50afde521d7857aff7d937bad0d34fff000ca26531d6062abcfd81d7085f7",
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
                "236bc6a0c0237d6442c8d6b031219da0ee4c63e50d66522a3129bbde1f1dabfd",
                "71f8d8c749776ab6bd1a92a73d643bdd4aab5b027a2c9f2ee715e23b3c5c6ed5",
            ),
            (
                "Twofish",
                "f617a55bc17289cb43238bc76ffe57272601c4eced808dbae1272c5f509d5a7e",
                "9d63bb1d8a2191b5dd923698ad5b2c5e728f5ff7d9e8b10ef0ae8952c3935665",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn truecrypt_60a_eight_volumes_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_win11_truecrypt60a/mem.raw");
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
