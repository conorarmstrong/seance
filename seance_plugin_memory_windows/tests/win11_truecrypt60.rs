//! TrueCrypt 6.0 in memory (`MEM-044`) with **a plain AES volume, a Serpent volume, a Twofish volume and five cascades mounted
//! together**: the Windows 11 lab VM of `win11_veracrypt.rs`, TrueCrypt Setup 6.0 installed from the TrueCrypt Foundation's
//! signed installer (detached PGP signature good; `forensic_corpora/truecrypt_installer/v60`) by its own wizard, `t1.tc` AES,
//! `t2.tc` Serpent, `t3.tc` Twofish, `t4.tc` AES-Twofish, `t5.tc` AES-Twofish-Serpent, `t6.tc` Serpent-AES, `t7.tc`
//! Serpent-Twofish-AES and `t8.tc` Twofish-Serpent mounted as `P:` to `W:` by the real driver. `TrueCrypt Format.exe` has no
//! command line for creating a volume, so the container files were written by `scripts/oracle/tc7_make_volume.py` from the
//! volume format specification (header version 4, as TrueCrypt 6.x writes it, fresh random keys; `vc_header_keys_all.py --magic=TRUE --hash=sha512` reads each header back
//! and its keys equal the writer's); the real driver accepted every one (the mount is the check that the headers are
//! TrueCrypt's). Only `truecrypt.sys` is loaded in the capture (the guest was cleaned of every other TrueCrypt and VeraCrypt
//! driver and restarted before this version was installed). The test asks whether the sweep finds every master key by its hash
//! and reads each container.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_truecrypt60/mem.raw` or name it
//! with `SEANCE_WIN11_TC60_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_TC60_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_truecrypt60/mem.raw"),
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
            "67d5d32bb60535397da90ce91699ea4407dbb20709f235b112161a34b88cc94e",
            "b8cdcaaebd61675211e4ee5c95917a4d09df0f581133c14bde73c64537e4a066",
        )],
    ),
    (
        "t2.tc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "921340180f76aeccfa4921bebc28b37359ac821ff69dec0e68818e901b907b08",
            "49fbcbdc5fd27e79949147d47d2403a5a71810da4f290be04b1715b608cb79f7",
        )],
    ),
    (
        "t3.tc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "daff6d424d3c156564c4e4410848813244662caa9577bd676a4c9b91bb97ff9a",
            "5b4375f321a7473453939f9a893c5eeafc60ee5991627d6e4bc6d457d966079c",
        )],
    ),
    (
        "t4.tc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "1ecb948fe2207fb78fdbf0274ab662424939813683b5e6a6095da19754b97bdc",
                "cc0e7453067576892c6677a3bffd5ce9c6f409ca9b564cbaaa5c4684cf0aa615",
            ),
            (
                "AES",
                "6353842e97607c277ff0ceaedda86f9596d926a34029353497b571cefd92fa06",
                "eb6b7e483df8983689f250e93886ab0e9a8e712010c18637715a1791b862c3b4",
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
                "0a29a2e3e56a25a2043be67bdd737cec378d95e06c1a9a6f7983b87defa7540f",
                "d105b83c2b01cd27e7301c5f1c7328a0e6d75ff737efd7ae6facaf6d452620fa",
            ),
            (
                "Twofish",
                "e4ad79e726bc77aa655565b5a8c0cf504e3e12beb643ea2058e9c7c662c291b8",
                "5af437711009b913af1a08f5a46401ff934b6f24cdd41d09c705331127b8371e",
            ),
            (
                "AES",
                "8a666fc47059300614c70243e743a069075021b62fc1d3a6fb7c99b3ed929a0f",
                "35d209b23667048c92c9599e580731b1df4e7418a91bdacc5382c4e3a4cf4c13",
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
                "cfeea464772d60a57e26c200de80d06b8b0567f6a9d11f5063365f564a07a932",
                "6e4c72758953b6623752fc1ff2cc6b2d3699c2a787fac3c5351514b4038cc5e5",
            ),
            (
                "Serpent",
                "1a06b6f1d2456d919aa3367a2e942cdba5cd4e2072ab11e05510a78e3a35c91d",
                "48fffb447cc26d09f6c47c223faa6030cf9b60d9693fa75d08ad653e2a2a5a77",
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
                "5c97f026ee6a5ae3e80828d904976a870bfb2b793cd139dbfe2c80338c18682e",
                "57eac1e7d6ebb32eb6da3c6694c598e923f23dd77fa2b8c2f1beb1d5be41927a",
            ),
            (
                "Twofish",
                "22fd7144ab745a2625d81d4deac8c75112a89303401f17ffc1047a2997ea37a2",
                "bb4fe7c6a4879f39e0905924f8b4ad46f736767b2e128e0cc1b7720564bcebd0",
            ),
            (
                "Serpent",
                "82e84e22c0487de9885d3a4ff3b91a49dbc91a2b8bbbc1e6f9aa362eed70e92e",
                "ce01208b4271beac481d3141f9e607c41619a0dd8913d07d149f2645f2143bf7",
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
                "b4fc3ab1d597ab24cb3fdf21abc3ec702ac9efcaa40cce477822e3b691871b8f",
                "c1d65f21acae23f1b026ae6556f4da23aab95b15ebb95100dd3eb2e6433a4964",
            ),
            (
                "Twofish",
                "f59a7030fce4cfa924d08a9bea46ac6394034693812ad43b344b05c262a06da9",
                "daa7f86f4eefe0b2ad9075e304c195da081c012e79d65fe4dbce55b00ed9fbd3",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn truecrypt_60_eight_volumes_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_win11_truecrypt60/mem.raw");
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
