//! TrueCrypt 7.0a in memory (`MEM-044`) with **a plain AES volume, a Serpent volume, a Twofish volume and five cascades mounted
//! together**: the Windows 11 lab VM of `win11_veracrypt.rs`, TrueCrypt Setup 7.0a installed from the TrueCrypt Foundation's
//! signed installer (detached PGP signature good; `forensic_corpora/truecrypt_installer/v70a`) by its own wizard, `t1.tc` AES,
//! `t2.tc` Serpent, `t3.tc` Twofish, `t4.tc` AES-Twofish, `t5.tc` AES-Twofish-Serpent, `t6.tc` Serpent-AES, `t7.tc`
//! Serpent-Twofish-AES and `t8.tc` Twofish-Serpent mounted as `P:` to `W:` by the real driver. `TrueCrypt Format.exe` has no
//! command line for creating a volume, so the container files were written by `scripts/oracle/tc7_make_volume.py` from the
//! volume format specification (fresh random keys; `vc_header_keys_all.py --magic=TRUE --hash=sha512` reads each header back
//! and its keys equal the writer's); the real driver accepted every one (the mount is the check that the headers are
//! TrueCrypt's). Only `truecrypt.sys` is loaded in the capture (the guest was cleaned of every other TrueCrypt and VeraCrypt
//! driver and restarted before this version was installed). The test asks whether the sweep finds every master key by its hash
//! and reads each container.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_truecrypt70a/mem.raw` or name it
//! with `SEANCE_WIN11_TC70A_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_TC70A_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_truecrypt70a/mem.raw"),
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
            "93deef53619c4b8ebddb5cc924fb01f330cda60980dea8937c522b818c9454cb",
            "d0f3ef952ef81dabf66dade8b591621965fff33af477e0726609d5196e326717",
        )],
    ),
    (
        "t2.tc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "0d0dc6c06cc9d9e6d1a087d7afd7a92d81df7581309f26242a098639c3c5fbf0",
            "1c2f9e36359e2481f01f4c8662fc89373e4603e3d6291785aa62465622cc2ef4",
        )],
    ),
    (
        "t3.tc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "4c616878afe89d37606031c0f9fe4b0b90aa4943c926b076ad03ef57d0019a7f",
            "3d59f73fb6c4a0c1535db589cde6e543ca16c9ea118aa2c932ea8dd8f79b91bd",
        )],
    ),
    (
        "t4.tc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "d5c026e0dac20c1b54d6c99a33b7d6a456e721be1b31681185441d0260f84a38",
                "4c22645cd36aa7faf02922a690f69663720bb826344b9dcc8b01a42fd8f37a8e",
            ),
            (
                "AES",
                "5c1e141f0bf1880744304a46f8f08a110c653b6784276239ae29ecbf20aab7a2",
                "22659c91d7b40dbfa4eab259f48868f42e70462e03608011541b81898f62e3b0",
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
                "c2d2cfbade7c01cb75a6564581ecb29e2c67e0e1a2dc8d901eccdb7eb1eaf98d",
                "0178b703d481bc8de7f66a2839072a1af23067e13b023d95f5a8e5bf7cb30751",
            ),
            (
                "Twofish",
                "6724efbefde1122f237b677d5de34bf66885281715a979a017639e24adec42ac",
                "35863bd51fea127daff60c7111d3460d4f27c13cd8a7f500bae98496f564a7a0",
            ),
            (
                "AES",
                "2864ee8e78cbe1dcfbaf6d0cd472f77f9e5ece55d06b249a270acef4c3c638fb",
                "28c2cc86f6399656f5d08d0cc026bff992f9355406b4c0f9df749bee8dd40d3c",
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
                "ca154c3dad088a4c2dcca6cd712cad814d694116c7266e87c7d4c924b583b66d",
                "14130bb58f77a146358e39843552cc22b40d02dbca2a01df24ddcbfd51899e1f",
            ),
            (
                "Serpent",
                "3ac731e6486d8858cd68127959d336fd24c6cada8fbc9a55bff6ddb678a06a39",
                "13a5528343f1f2ed6a0bfffadb7664de2623c71d17ac26885acc92316fbf1620",
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
                "ff2fa8cf682bf7bf392f1c27c0fd43a1339717dc52203ab2c264378de1ba1b66",
                "5574b6bf81a90baea09bcc7afa4f497955b7aa1321c5ef75b766e4bc001a79fa",
            ),
            (
                "Twofish",
                "1325c4d5e5b1aa7de4f790e6a45ed32b71675b3de57432827c251198080a5404",
                "096a563b4c05e9b83abfcf52cc0b76f8f2be2ad05afd47aee1c8604ca404949d",
            ),
            (
                "Serpent",
                "676139307d4a169a0ef6aefe7f2a6eb83bd6dbd05517b7acd91a3461db1e0280",
                "4ad81515d5d87a7522f73e99ba86dcaa49b9fcfa887af27b927d20775f1ef67f",
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
                "0ad831602bf8ac569144a642ed847d366ea2e4e0712d07eb427c2c55ebf39ae9",
                "287c366f1325b27b2ea15972650187e1e66ff0e0f78f70207b3239079de97840",
            ),
            (
                "Twofish",
                "5e0e333c8a43b7bbf308d52af54be80fcb139e846aa4706a4b2dd311aade0cf6",
                "c86e4e8977727bf0eb7b9dc1d9e77dc8b88104d03a6056d2b30a26be97e31cfe",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn truecrypt_70a_eight_volumes_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_win11_truecrypt70a/mem.raw");
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
