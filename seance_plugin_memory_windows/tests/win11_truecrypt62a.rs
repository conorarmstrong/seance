//! TrueCrypt 6.2a in memory (`MEM-044`) with **a plain AES volume, a Serpent volume, a Twofish volume and five cascades mounted
//! together**: the Windows 11 lab VM of `win11_veracrypt.rs`, TrueCrypt Setup 6.2a installed from the TrueCrypt Foundation's
//! signed installer (detached PGP signature good; `forensic_corpora/truecrypt_installer/v62a`) by its own wizard, `t1.tc` AES,
//! `t2.tc` Serpent, `t3.tc` Twofish, `t4.tc` AES-Twofish, `t5.tc` AES-Twofish-Serpent, `t6.tc` Serpent-AES, `t7.tc`
//! Serpent-Twofish-AES and `t8.tc` Twofish-Serpent mounted as `P:` to `W:` by the real driver. `TrueCrypt Format.exe` has no
//! command line for creating a volume, so the container files were written by `scripts/oracle/tc7_make_volume.py` from the
//! volume format specification (header version 4, as TrueCrypt 6.x writes it, fresh random keys; `vc_header_keys_all.py --magic=TRUE --hash=sha512` reads each header back
//! and its keys equal the writer's); the real driver accepted every one (the mount is the check that the headers are
//! TrueCrypt's). Only `truecrypt.sys` is loaded in the capture (the guest was cleaned of every other TrueCrypt and VeraCrypt
//! driver and restarted before this version was installed). The test asks whether the sweep finds every master key by its hash
//! and reads each container.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_truecrypt62a/mem.raw` or name it
//! with `SEANCE_WIN11_TC62A_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_TC62A_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_truecrypt62a/mem.raw"),
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
            "3ef1277377140fe5be0b4b2b7fe6bc439999e882465610fd637f3052cb55021c",
            "cbefaefb35fae653b90218012e2fe9fb41acb90dc11c7b405a766da23402a85e",
        )],
    ),
    (
        "t2.tc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "850fa41a2144c61cc67709f4ed62db06dacf4e45277013c14fa282e06e528aab",
            "c6a869b13be9e732e2d748860232d0dcba90b848b9155aedf68a46fcfe7d801c",
        )],
    ),
    (
        "t3.tc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "0731ab44a4a000637e04238852a079286289c2e8783b59b48247e74fdbf264ef",
            "d7397fdfce30a8ba95e6e91cc71f181189175deee726b4b4d68d3da4381fc97e",
        )],
    ),
    (
        "t4.tc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "4083af8f5ca93dcabebbfbc49dc0103496637d1fbda23068bd945e371d3856f7",
                "4c9bb1d9b4ed73cf015264b6aee12ea55be1695f9c13ad0030089d9868a8592d",
            ),
            (
                "AES",
                "a3c84b8f694e75c0db36d08a8850265e8a18541534618c32386c6462f5390146",
                "5f81869e611bbfc59ca6c5bf5be425395c4ad1aef67258e80ffa434e2ad5b885",
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
                "0f21befa989519813a17b1af3e9e95f1d4d965888d729df6bbe5e216a3aca563",
                "77570c0d8fa8ccc32cc5d34e9095ae8d5ceba2fe1061e88ca8d90dd6236a647c",
            ),
            (
                "Twofish",
                "19bd9a2153dc4ad2d04579663814be44601460c1b43d7f935bbb74c82f8d0ebd",
                "1007f5fadc913387f9ae2088fbbf364a552a67a4831a0ca6d62b785c6e79a815",
            ),
            (
                "AES",
                "9bcb105258b3fe488bd2cabd688c132a3d6600eb494c257f94d8ce2f6a93a3cf",
                "5378359f8f558adfa5dfdd603d410ab622b78375706930c88d99748007527b54",
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
                "8b745c6a63bab8742b468c281c0c80607398281e0f69db2ac32d7d599db545d5",
                "865aa0433d0146587a796b131d145525e4c11c1abd1b2834eb0ebacf1bbb2c19",
            ),
            (
                "Serpent",
                "3e3cbd7b48a7c2df173ebe67ea372f26d3547635dcb75bb1ce412386ff741939",
                "6635f5de0fcbfdeca72d623753910493365d03595dd73453685318afe098b767",
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
                "5d631971f974eeac4c96e5e82c56373e9fd7c271a2ee99cb822e2519f71cb240",
                "747ce6697763e8b2627a1a9f4a227cef96d10989503adfd1b62d695d2287b9e6",
            ),
            (
                "Twofish",
                "a16544e2c7d38f8b7d675ec265e12545e861cf41dbbb515a5d7e1a29861d05b8",
                "7d12ddc0f019918b995a1b6a2ee2d3ff2688af31b9ed15dc737c6d7252edd5f7",
            ),
            (
                "Serpent",
                "3d3cce2e90dda09fd0cdd65a40c096b68d0eaa296ca41d96021ee067e5062a4a",
                "443af6d2e8f9609b56a93a1411b583742df6fb00fdf940c240d1df12901ef033",
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
                "75311ae9fd8fc57f4ef674c92acdd9fde02b883e74a42764fc45c077e0c6bac9",
                "4fb253766fa8c589b2611b664e09589929fe46b4e32dc2fee1a4a52afbef5946",
            ),
            (
                "Twofish",
                "6ca93d5c5361b84f588eb236342649487bd4738a4857fc84af8f29221a8fca59",
                "6f71535c00bb37ab5a8b92db480c43b355dc3348661f51dde14ba98effbc05b0",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn truecrypt_62a_eight_volumes_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_win11_truecrypt62a/mem.raw");
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
