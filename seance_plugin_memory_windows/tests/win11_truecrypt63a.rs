//! TrueCrypt 6.3a in memory (`MEM-044`) with **a plain AES volume, a Serpent volume, a Twofish volume and five cascades mounted
//! together**: the Windows 11 lab VM of `win11_veracrypt.rs`, TrueCrypt Setup 6.3a installed from the TrueCrypt Foundation's
//! signed installer (detached PGP signature good; `forensic_corpora/truecrypt_installer/v63a`) by its own wizard, `t1.tc` AES,
//! `t2.tc` Serpent, `t3.tc` Twofish, `t4.tc` AES-Twofish, `t5.tc` AES-Twofish-Serpent, `t6.tc` Serpent-AES, `t7.tc`
//! Serpent-Twofish-AES and `t8.tc` Twofish-Serpent mounted as `P:` to `W:` by the real driver. `TrueCrypt Format.exe` has no
//! command line for creating a volume, so the container files were written by `scripts/oracle/tc7_make_volume.py` from the
//! volume format specification (header version 4, as TrueCrypt 6.x writes it, fresh random keys; `vc_header_keys_all.py --magic=TRUE --hash=sha512` reads each header back
//! and its keys equal the writer's); the real driver accepted every one (the mount is the check that the headers are
//! TrueCrypt's). Only `truecrypt.sys` is loaded in the capture (the guest was cleaned of every other TrueCrypt and VeraCrypt
//! driver and restarted before this version was installed). The test asks whether the sweep finds every master key by its hash
//! and reads each container.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_truecrypt63a/mem.raw` or name it
//! with `SEANCE_WIN11_TC63A_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_TC63A_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_truecrypt63a/mem.raw"),
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
            "66d58ad22b452c983749bc16ed4c7e00a7c1b81f8f8bcb66c1591163e472a329",
            "a648adfe18ea6dd85269e298f9e8f3c3ae9471e35459c381e568ec78d843f053",
        )],
    ),
    (
        "t2.tc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "00771800a7beedb8781fda351554c250ebe6a1513bc831ec21d57a3260938b91",
            "df108a1d1e241aa09645516dddf8753ac4866675e0b162746a7754d04eb8e36f",
        )],
    ),
    (
        "t3.tc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "e89d2c6eb00aa9d14fc2e7cecaf2c24bd971c54486f0e7d1057fb7edddb9bad7",
            "990fd4133b98c320a4d15dc65b4c85a16e25047facd85e75996721306ac4c4c0",
        )],
    ),
    (
        "t4.tc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "57f60e0df078292ce159bb680fe6c04ab8cc4a3db5ddd5361baad7705a5e1bd0",
                "5ad74e9b47e673ff20e7f5984175815d8f184f78399f3b4fb77e4791ad55fdbf",
            ),
            (
                "AES",
                "722f9b57f3aeadf965cded2332ed5a09b2a59c6653fa834e9a9d54153ff5ec5c",
                "39a64ad00178e06b437865e7b68aae5bd45f313c92fa24a49494fba71bfb5b1e",
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
                "a8f77ef630e318dc1e53960a7f6e9d6825785df787e46be69cce3cdcad4e64a4",
                "a9ebf2c015ca89b70b2b202bb01bf86ce130c8c632ef8f05564804fe72301432",
            ),
            (
                "Twofish",
                "9fc3f7dbebf0e89a8125dba0042b6bbe65a4ea7207daf006411b57ef8e0df8c3",
                "60762bc69db3672d9325d356974ca7c9cd3b131a58c273f7078b30e69b8c0e12",
            ),
            (
                "AES",
                "199b360d874256f6b1b108530079c6184009ced89a1df9d21b549e5a32af6069",
                "a214c0debccef09247e05ffd4108bec42794a63b717fa03381c9c879fa5f212e",
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
                "c45800a4133031016ebe4ba22b9e6ecf947a90dc5f38202baede677f1b3c6bad",
                "1db0dcd052415e8f95b75eee4556f2e5ce979b3f6d81eea160a87576977e9a6d",
            ),
            (
                "Serpent",
                "d322de5c1cce958b7b6dee06e5a13abc4ef78f6b999acf605aca1bea930bfea4",
                "c0c383460f361d9d1ccda1c86211ffd394b6db1463dd6fd6c0d816a56f8d024f",
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
                "cd92832d09e2d02d4316596aad870eba4baed17588340ec554d21a73e944a433",
                "6855a9c9793d2217d5e62ce3d99200990ec0ae842a2e1998996fd8999cf0dc7b",
            ),
            (
                "Twofish",
                "24aef274e31c85b61ed9f7a0e6b6c13caa7bad83a95b7fbd34d0ed7e9e2d77ab",
                "d37c0fb19ec7c9d1486ecda9803824818149a7635a4bcfe982256ceee157f947",
            ),
            (
                "Serpent",
                "e64d177bf57eafe768d60c11e10a6b38385f096aa599a13b201e3860a73e89b4",
                "5dda5c34375ff4ba52fda4e27119c6687f3d0c6e20d75881f9a88c0328fab21a",
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
                "c3dbbf3fb876e5f760d7aeabae662ee296ccf297233c8d7a57f758025bf55368",
                "6e08b5dbce75517dbe8619de53b40e4acb9d21516b51b777cf0c74d88213a2af",
            ),
            (
                "Twofish",
                "381d3ff05143a469bd24b440f9d51e701d5834a9a94465ab4253f07cb7a202ed",
                "9005378fb4dc7290b40599bf6665bcf9f07c2bd95f25c9e59d528e48f75ce217",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn truecrypt_63a_eight_volumes_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_win11_truecrypt63a/mem.raw");
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
