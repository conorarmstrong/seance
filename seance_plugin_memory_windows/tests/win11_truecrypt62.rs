//! TrueCrypt 6.2 in memory (`MEM-044`) with **a plain AES volume, a Serpent volume, a Twofish volume and five cascades mounted
//! together**: the Windows 11 lab VM of `win11_veracrypt.rs`, TrueCrypt Setup 6.2 installed from the TrueCrypt Foundation's
//! signed installer (detached PGP signature good; `forensic_corpora/truecrypt_installer/v62`) by its own wizard, `t1.tc` AES,
//! `t2.tc` Serpent, `t3.tc` Twofish, `t4.tc` AES-Twofish, `t5.tc` AES-Twofish-Serpent, `t6.tc` Serpent-AES, `t7.tc`
//! Serpent-Twofish-AES and `t8.tc` Twofish-Serpent mounted as `P:` to `W:` by the real driver. `TrueCrypt Format.exe` has no
//! command line for creating a volume, so the container files were written by `scripts/oracle/tc7_make_volume.py` from the
//! volume format specification (header version 4, as TrueCrypt 6.x writes it, fresh random keys; `vc_header_keys_all.py --magic=TRUE --hash=sha512` reads each header back
//! and its keys equal the writer's); the real driver accepted every one (the mount is the check that the headers are
//! TrueCrypt's). Only `truecrypt.sys` is loaded in the capture (the guest was cleaned of every other TrueCrypt and VeraCrypt
//! driver and restarted before this version was installed). The test asks whether the sweep finds every master key by its hash
//! and reads each container.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_truecrypt62/mem.raw` or name it
//! with `SEANCE_WIN11_TC62_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_TC62_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_truecrypt62/mem.raw"),
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
            "08a0286ec77c8cfcead0be29705b305beee453feaf829fe8b9ed24868a6e4cc0",
            "14a29481affdd05c39c36e5758bc99c0940a7bbff8770f6f102314e489865bf0",
        )],
    ),
    (
        "t2.tc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "e40e2a26173a493717569a1040eb0015497f538de6a6c0ed82bbe8f7a19cffcb",
            "b989de9aa5bc3f22062c5a7fe7618e970f1b5e19629ead796fdd8bc779283888",
        )],
    ),
    (
        "t3.tc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "7106f8de3c418e3eabc3a9dc973baf9124ed55f861011d277311094cd03818a7",
            "618fce562954c584066decc58b33f3f61a0ec62c56c0941777122e4312f5ac74",
        )],
    ),
    (
        "t4.tc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "e3a1e2ce3a28726d34ee8eaaea61ef8a2de1511fc3908c33353bbf0b9c0b9903",
                "8a119e26eea2b1ee5f74e46a1b5667fc60f48e4060c4d9eceed7b23682640e78",
            ),
            (
                "AES",
                "5fba0b00961cf8ab5d424f0ba8aa2caad73dc89c7e68f81f2e9ba326fc2decc2",
                "d3501297b07380fd81bd5bb211871fb78d6ff1c216a73764135e7751aa03da06",
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
                "8154ba6b3b9ffd8a717d5c5bd07bf69e62b8766f92c2f3648a13d14d300f42c9",
                "21490322013b050741eca1efe83bfda8d25d72fbb969befc64c6e738820d9855",
            ),
            (
                "Twofish",
                "a6c42f2f72527f2c4bb036e33899114028adc249918dfaac40686a41af88d8e1",
                "dc350c2e93fa037d33587a87037c148e634efda046e38bf741ca28b9340a1e89",
            ),
            (
                "AES",
                "8f2103169fd291fa9a09b7e05fd32d98eb6c0be5aba05be58592460334341e42",
                "0e118c2f131eaa6a2c34e939c9d0f5660a85ba0091aaa38e9919be406dfb8634",
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
                "508ad8aa61f7186283484a2706df8603cbe8690bcc0ffce52f1f519bee427b29",
                "d50ed5232329a2968df77c26c23afc0f69efcaa4de0f4f3b793d61eb16a85e53",
            ),
            (
                "Serpent",
                "4efd31ee9625a57ade19808b9ecbe6958a87e235f5f041c372130625dccd17c6",
                "07a157631c56b0f462c43c0dfe3799f31ed370815de135640bac2ff0b500bef3",
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
                "d28f1f396463388c9af51b1724022976b47f47b7b919bd1b2fbb64c7152be9d0",
                "770db74aa426e5936c08d6a12dc6bc0018100ac4225df05cc164ab768c9adcf5",
            ),
            (
                "Twofish",
                "ec5ce37fc3141dad753271b2aa28d709f848237867a768960da8d6a933303af3",
                "d20aa0b38279096a27a2fb7848891a81d22c3d0125177a0773c1362ce0826cb9",
            ),
            (
                "Serpent",
                "0b43a1e049821ae0a256d776c00bc0a970d65994e1272715f63058c92e261ce3",
                "feba153123ec250affd3e1c9152597ed0218053fe3efc1c06f12ba11c83ab787",
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
                "35220174addb0b011a953a76dec0e7ec4bbc9b7e9f720f964fe7c809268538c5",
                "5e803041a02f54650b58b1eb5702da3cac02e9bce91a5403a062a38810720dda",
            ),
            (
                "Twofish",
                "1485e35d3b303f3111c2b2fa2e522bbc8c5fe3aa98756c481fe97fe29c2cab43",
                "0dfc5321d93843906ace110c54533a30ec5f747829e9bec3bd3dbe1b34481769",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn truecrypt_62_eight_volumes_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_win11_truecrypt62/mem.raw");
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
