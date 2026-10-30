//! TrueCrypt 7.0 in memory (`MEM-044`) with **a plain AES volume, a Serpent volume, a Twofish volume and five cascades mounted
//! together**: the Windows 11 lab VM of `win11_veracrypt.rs`, TrueCrypt Setup 7.0 installed from the TrueCrypt Foundation's
//! signed installer (detached PGP signature good; `forensic_corpora/truecrypt_installer/v70`) by its own wizard, `t1.tc` AES,
//! `t2.tc` Serpent, `t3.tc` Twofish, `t4.tc` AES-Twofish, `t5.tc` AES-Twofish-Serpent, `t6.tc` Serpent-AES, `t7.tc`
//! Serpent-Twofish-AES and `t8.tc` Twofish-Serpent mounted as `P:` to `W:` by the real driver. `TrueCrypt Format.exe` has no
//! command line for creating a volume, so the container files were written by `scripts/oracle/tc7_make_volume.py` from the
//! volume format specification (fresh random keys; `vc_header_keys_all.py --magic=TRUE --hash=sha512` reads each header back
//! and its keys equal the writer's); the real driver accepted every one (the mount is the check that the headers are
//! TrueCrypt's). Only `truecrypt.sys` is loaded in the capture (the guest was cleaned of every other TrueCrypt and VeraCrypt
//! driver and restarted before this version was installed). The test asks whether the sweep finds every master key by its hash
//! and reads each container.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_truecrypt70/mem.raw` or name it
//! with `SEANCE_WIN11_TC70_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_TC70_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_truecrypt70/mem.raw"),
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
            "be12a9b1e7183d9df0566b05ea735121c04a527a2e75603721b05f9f55cc5af6",
            "7acd7169ae1d84dfa9be051e9e09613dd4d8d48290adf9dec83c9ee1533c3c4a",
        )],
    ),
    (
        "t2.tc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "a94839b02ea0582dd901b0ec0b53573d1ff86bc6a6047741de30c0febd4af805",
            "ca09aaee53546bdca59682c8d14bd5af8d17168c680c8cbae878b30c16ef3d59",
        )],
    ),
    (
        "t3.tc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "d1b87b99de7c16b7ba60849d5979c41eeb2b0aee5ec64f2237af54030a325d05",
            "134a6de90b60c6fd5d75fbdf24285b70610dd9bbc2f8b66575c48015461db0fa",
        )],
    ),
    (
        "t4.tc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "1f20f92bb89699e46bd5538b0b0c0da2fb24183c6bfddd078e23716cefcc6409",
                "68a1ec9a2b7c31fb5bd54f0df5830b0aea11d9213095e4ddfdb87fdcdd9a4d60",
            ),
            (
                "AES",
                "47e43d02fd74f64c67e06a9fc9db4ef68bf8ef503b09fd99eb4ba8dba6d02fdf",
                "5e75df26ce3d0e31d190db61e6b249e6b3f0f086593b0d2cc27d041b6fb36d2a",
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
                "edaa35d21487a7bb4242dca20c4555a413643aeef67a3cff9ae1866452aad919",
                "49a7a1c78df329ba64c389747a3d30b0e743d7e82a349e1e3941e1a3e4fc0389",
            ),
            (
                "Twofish",
                "3156b0aed63d0df97cf9f85e9b5d2f0e781bd93408fe3d9167f19b54ba90165e",
                "461e6ac70967ed4f9146edd02a77745dea5f49905d7d3b871c30ad16b2c41521",
            ),
            (
                "AES",
                "7edbdea233afb1f7157c9e6c2471ffca1b4d114ce85ea81fd5a86098a58100ea",
                "32b5f5e46b2bc240203f465f4eadcc8719849cd49fc04cda989759ad5627a4b8",
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
                "c2238fbe9dbfc4d0a32908f761e212bb870274e2e53f2179ff2ad4d15efb3e3f",
                "b0d9456d6ea6df22453aa9ba2e536ab2cd071c09575212f56d8f461c46913201",
            ),
            (
                "Serpent",
                "9bac3d988aa0dc1bbf765f2bbeb1e967acd90d013722574493e4fa3ef19019a2",
                "ae0933eb5f93a4346c47fccf7328ebe35f9d2295b7b1ab4f406d899ed22c64fa",
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
                "c0bacf599f46bde8e2e1511e5f374e8a218bb443fa566efbcb13900e84e714cc",
                "be0b97eaa13ffaf9430254df0e90a9e2d4e353d19da8ca7696d6da25e20b4977",
            ),
            (
                "Twofish",
                "6470cd06986c0856d32d9c473cf42d5a52133617b9d2bde4fc04f159fc71f98f",
                "67e71218db49489d73c3085d2c4e72f7bd608e1c6c50cf836cbd75bf0a6cd1ea",
            ),
            (
                "Serpent",
                "e3ef267b1251491312b0e6069afcbc8afd994ca642e27acbb1c476dfb802534d",
                "ab28e2fd2cb27bc15f1c3f3262d70c92ef0978bd24568b85b718bc63b14dfca4",
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
                "762920e3c044e6dfd2fcc775c3816d0aa65871ef09ff900e178d31e0aaac1d50",
                "afae2d5eb1fba3ef7368f137caebd591af50bc1d1cdb54a882f9e0632f743823",
            ),
            (
                "Twofish",
                "5608f23d40d450a6780065e3f2332bdec669a6f271c9edc6c14ba5dee29fe985",
                "14dcc8967ae957b5f9c77de71cee154e744c9ded6e9c65be3bedd00e414bffda",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn truecrypt_70_eight_volumes_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_win11_truecrypt70/mem.raw");
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
