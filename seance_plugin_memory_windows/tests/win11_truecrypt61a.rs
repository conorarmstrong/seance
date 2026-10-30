//! TrueCrypt 6.1a in memory (`MEM-044`) with **a plain AES volume, a Serpent volume, a Twofish volume and five cascades mounted
//! together**: the Windows 11 lab VM of `win11_veracrypt.rs`, TrueCrypt Setup 6.1a installed from the TrueCrypt Foundation's
//! signed installer (detached PGP signature good; `forensic_corpora/truecrypt_installer/v61a`) by its own wizard, `t1.tc` AES,
//! `t2.tc` Serpent, `t3.tc` Twofish, `t4.tc` AES-Twofish, `t5.tc` AES-Twofish-Serpent, `t6.tc` Serpent-AES, `t7.tc`
//! Serpent-Twofish-AES and `t8.tc` Twofish-Serpent mounted as `P:` to `W:` by the real driver. `TrueCrypt Format.exe` has no
//! command line for creating a volume, so the container files were written by `scripts/oracle/tc7_make_volume.py` from the
//! volume format specification (header version 4, as TrueCrypt 6.x writes it, fresh random keys; `vc_header_keys_all.py --magic=TRUE --hash=sha512` reads each header back
//! and its keys equal the writer's); the real driver accepted every one (the mount is the check that the headers are
//! TrueCrypt's). Only `truecrypt.sys` is loaded in the capture (the guest was cleaned of every other TrueCrypt and VeraCrypt
//! driver and restarted before this version was installed). The test asks whether the sweep finds every master key by its hash
//! and reads each container.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_truecrypt61a/mem.raw` or name it
//! with `SEANCE_WIN11_TC61A_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_TC61A_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_truecrypt61a/mem.raw"),
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
            "f854a6f7ec4c6feb61ac7738190a77ba88038aec13d11ed7b7fb471cf5609c75",
            "f24fa0e687f8fdbac52c3e620ca276d8d2f5ba23d956018aa5ef223093336850",
        )],
    ),
    (
        "t2.tc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "edb0a4942ced941bbdcf11cc02dfb92735085df04518f9ac605ec0c98a6802ee",
            "6b5a63f0211b31456809f7b34c52af6b789cec5529bb9a8654b91672c789d904",
        )],
    ),
    (
        "t3.tc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "48da1c4a991809ee1119f1bb5d21c1605669ba3430109cd0e06096380a8d886c",
            "a305c3b413aa84b6dba0fd378b90ad520d835233a0f99a3133cfb9e2ca512b64",
        )],
    ),
    (
        "t4.tc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "e6baed4d31ac11b02b092101da0809aa2397d0393619b55888111d5949626ac2",
                "f7484d936225532f09ed46d72bcdc5dd8ecce1a707ca2873a114726965d999ad",
            ),
            (
                "AES",
                "4ca971880ff597a70aba6d27f3a36a7ac67b092db401f910a1751fc9747aef01",
                "fbd271d0327d620f390fbb81fd80d7ba729a7fd901962d41e6a2b29e1de45a2d",
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
                "923a1f1caa05740852b49d9bc572453802b7b92fbf1f122521a6589d842bc30d",
                "d6d2422a22e8e21cdaae8005a36c62beef6e170712c7706c8eacfdcc2c80dd20",
            ),
            (
                "Twofish",
                "b4a1b021989ce708446db4a279db9078bb2e06a80fc27abe8cba206e2e215684",
                "c1213425be09a9f87c792fbc8a621199ef3fd9866033e4cd1effdc7e2bfe5114",
            ),
            (
                "AES",
                "1aa6ac59bed0d3bd3d2c988673b4f548ab38f6edef1940986db9a10f4ae1f4aa",
                "362628a6e3797af2535b18e8665bcc864fd4c1ac4c2ecb97af79ed09a010df13",
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
                "98b7555d9710506f8ff04756dc7f13c1e2a267d0bc5d922aa09743d3e81ef187",
                "306657122557b4dc16840ccce96451ce54255884611b06fed50726cdf8a255a7",
            ),
            (
                "Serpent",
                "11df5878270d5a514e286f2eec8e5164cf0fc37eda0ffe78b8a5791358978a58",
                "0f89c4dc72720ea2aec5767e262f6f09315dab6b2a9da9d02c98e62c8af5d24c",
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
                "662f8ff9a1d6011214007f57f9022229a656a8e4fad546078b181d947fd1f6dd",
                "8f7b4f2624aa11a5e41de40b666fee1d028f06f3dab6af99869cf85123187320",
            ),
            (
                "Twofish",
                "d7d5943786c03e18a7e82050ea990c47af3286b99569183cb717cad809ea4111",
                "8f13ef8b42cf24adc042bdcf0d1e8695a1c4696e7307a933fdf55c4925b99ca7",
            ),
            (
                "Serpent",
                "a5a046bc5c0583682e1613d35f94de6374b65e60b0a11eda4c00e354a2d063cd",
                "e4be8f506f669cc2decdedb7a55b00c5be90fd0715dec97ba89e9679d2c19da4",
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
                "06ede04d9af48d77023688c204b7fbd4f6fd33f6b3d51a29753cecf9f0404ab6",
                "70b9d0f64e25de12f6cce700bda3847f23fc573b647e544e542bbcbaab6d8097",
            ),
            (
                "Twofish",
                "41ade1c9ac34c8640d50d0cd6d238a27eecd7eb6a597060025251afe01268607",
                "9e301e490eb607d9cb288556a6fc65aacdf425f367e75300a340c59d8ab124db",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn truecrypt_61a_eight_volumes_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_win11_truecrypt61a/mem.raw");
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
