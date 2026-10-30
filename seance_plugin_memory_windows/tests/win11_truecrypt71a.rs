//! TrueCrypt 7.1a in memory (`MEM-044`) with **a plain AES volume, a Serpent volume, a Twofish volume and five cascades mounted
//! together**: the Windows 11 25H2 lab VM of `win11_veracrypt.rs`, TrueCrypt Setup 7.1a installed from the TrueCrypt Foundation's
//! signed installer (SHA-256 `e95eca39...0ff2`, PGP signature good), `t1.tc` AES, `t2.tc` Serpent, `t3.tc` Twofish, `t4.tc`
//! AES-Twofish, `t5.tc` AES-Twofish-Serpent, `t6.tc` Serpent-AES, `t7.tc` Serpent-Twofish-AES and `t8.tc` Twofish-Serpent mounted
//! as `P:` to `W:` by the real driver. `TrueCrypt Format.exe` 7.1a has no command line for creating a volume, so the container
//! files were written by `scripts/oracle/tc7_make_volume.py` from the volume format specification (random keys, so the keys are
//! known by construction and `vc_header_keys_all.py --magic=TRUE` reads each header back); the real driver accepted every one
//! (the mount is the check that the headers are TrueCrypt's). The test asks whether the sweep finds every master key by its
//! hash (Twofish keys recovered from their structure, which TrueCrypt lays out in another order than VeraCrypt) and reads each
//! container: algorithm ids 2 to 8 are TrueCrypt's own numbering.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_truecrypt71a/mem.raw` or name it
//! with `SEANCE_WIN11_TC71A_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_TC71A_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_truecrypt71a/mem.raw"),
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
            "c64d64d655ffc06c4fa2bf8b62ea2bebd580e5879d836ef7bc2990047c084e56",
            "7fd4bdf346ccfb466113d8189e765333dbeae7d0ff601bfb1bbc597fb78fbbd7",
        )],
    ),
    (
        "t2.tc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "174eece3d920a4564f85144bb158760af9bd36f84356d59e4874ca09ba17ec72",
            "ed1a2fbba500c3949d82e7e4dbe62a7b7cead9ef9af18be917442f228b81641e",
        )],
    ),
    (
        "t3.tc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "ff796c0258efaac60aa5dbaa341a2cd6aa28e4e806f41db1ea4f51c041b4b364",
            "877ccc5667fcd4bd63df5c042b262bad63470b20479aef2975ee8b2e9d0df9ee",
        )],
    ),
    (
        "t4.tc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "78729581b61e8ca3b33d00bf19be7b8ac75e4f5fa64618601522a1b45e8d2f3e",
                "0ad24ba2973718e4a68066414255cd523b5d45f47970bd899ef5d7e17deeedc5",
            ),
            (
                "AES",
                "2b476bca143daea37a5f1a3ebdaa23442f4de0948631df149c6ec5687b13a888",
                "c6b1d86d67ddec46a0f6c9c687ff0a3cd3c37343871e60fa04464ae5e87da879",
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
                "e04acc64f233c4f4261e5d899118f369096c0cf3abaa5d17de262fa2a55c25dd",
                "2ac1c13033113b84b4d6bb9d67b480c181816b54df7bcd0d00981d054b57d4cc",
            ),
            (
                "Twofish",
                "3fa634c4a607b3e8b7d4b5c9731200652bc46ae3f43a63fa5cee2a22e495b34e",
                "2c4f1bc04143610237662c2cf48e2c4f989e64c000cc273a8a8031f38bcb04bb",
            ),
            (
                "AES",
                "b04d3f9ac7047772b5a00939be506694bb593c6fb1e755d44af5f590513525a5",
                "50772e829e0cddb8026ede49f1bf41cc2fe25426ce73e8075862c296289b2651",
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
                "5edff84db37137471e97e5d0346afaa4037b6c8f9e48bf9d68acb2f3331feb2d",
                "d3b6767fe22644121da9c10173a54557521f750cbe1f777f0f6a808f37499522",
            ),
            (
                "Serpent",
                "a9329f3e38edc0a4345a1771892596355add2c76d07257540742272ea9e11ea6",
                "5ffa746e6eb7329e32d9bc61f3d64fe25d3219545753b100da267dbe8e51d045",
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
                "448fb33b87af83566c3f6bd8c5ea102df636ed8c389dd250e2eee6a85c174e96",
                "52f5d3abbf7d3f38d70cc08c584446e959a8852f2346365a9ecd077f931af052",
            ),
            (
                "Twofish",
                "141a9bb6088e87c615837214b90d0018c744199260a4bad9d259d9907ae351cc",
                "74d58dbb402b1dc53f3d0d457ee37a8809286a7bcc1ce4ec87bba10e3174a205",
            ),
            (
                "Serpent",
                "6e7012dba760a3bca0d2cb872fc3b024f6121a658bb18595b70224d6111ed689",
                "f7c5b47873874c3eb3992cd9a1b7cf5aa7ae63e3a7030f66c79ff7700b29bcc1",
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
                "aba015817c95b3179d315ab0118eca6b0da2f378ccee35006e297691072dd03d",
                "af0527cbdc35a4c3341803520a67837f569a4ec9fd4cc4c39ad55cd9ed6d22c6",
            ),
            (
                "Twofish",
                "6d5bba455366d7b8c14ddd2f51e8f190abd0f57614e44392c81fb421e1ea3e15",
                "9cc8f630caf1e79c328bba93c6f64aaa4440a1ac7b562aa18357a78d86eef2c2",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn truecrypt_serpent_twofish_and_five_cascades_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_win11_truecrypt71a/mem.raw");
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
