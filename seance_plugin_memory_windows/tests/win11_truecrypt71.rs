//! TrueCrypt 7.1 in memory (`MEM-044`) with **a plain AES volume, a Serpent volume, a Twofish volume and five cascades mounted
//! together**: the Windows 11 lab VM of `win11_veracrypt.rs`, TrueCrypt Setup 7.1 installed from the TrueCrypt Foundation's
//! signed installer (detached PGP signature good; `forensic_corpora/truecrypt_installer/v71`) by its own wizard, `t1.tc` AES,
//! `t2.tc` Serpent, `t3.tc` Twofish, `t4.tc` AES-Twofish, `t5.tc` AES-Twofish-Serpent, `t6.tc` Serpent-AES, `t7.tc`
//! Serpent-Twofish-AES and `t8.tc` Twofish-Serpent mounted as `P:` to `W:` by the real driver. `TrueCrypt Format.exe` has no
//! command line for creating a volume, so the container files were written by `scripts/oracle/tc7_make_volume.py` from the
//! volume format specification (fresh random keys; `vc_header_keys_all.py --magic=TRUE --hash=sha512` reads each header back
//! and its keys equal the writer's); the real driver accepted every one (the mount is the check that the headers are
//! TrueCrypt's). Only `truecrypt.sys` is loaded in the capture (the guest was cleaned of every other TrueCrypt and VeraCrypt
//! driver and restarted before this version was installed). The test asks whether the sweep finds every master key by its hash
//! and reads each container.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_truecrypt71/mem.raw` or name it
//! with `SEANCE_WIN11_TC71_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_TC71_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_truecrypt71/mem.raw"),
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
            "8152f4344d0b405cae67c85cbb984b7e72ce97345fa5392727b99032c5a74513",
            "a58eaacbf1829fa9b39e72d9244c7249a834c3d32aeeef5f5f27762d3e006ac3",
        )],
    ),
    (
        "t2.tc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "9dfbf78833d45a3f59a5ffe74a37f38cefc0971046a17ee3b2469390dc7256dd",
            "05b28d8c7d24504b0484adce63f455aeb776b8278414f1e6e6eefc69b702dc2f",
        )],
    ),
    (
        "t3.tc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "fe78e3c2f66ccb5fbf3d0ea133aa4757e9530db4e31a100849043c03f0e47ebf",
            "0c349e8d6a821d105f2e3df67d82aa4d747ae1d8a78f038c319685113d5b6892",
        )],
    ),
    (
        "t4.tc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "a6c96528ae91a4feb00e49e824733d4a2ca1757e8e0fc0e8b45b3746ac979d05",
                "a780e35a2f8553eb41a4d6b8677294dbe39f8a13aa894c5914041647e8cf8179",
            ),
            (
                "AES",
                "39ce6846230a635661db2fffa880a1c10d75395053bbb4d768cb27f2f7f42d26",
                "c7ee19455d9637af4bf843b25c22564e69d8eaaeeb80bdfe6cf87a0691bccbcd",
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
                "311aab56bc9e9ef35510dcc33d5cea0153ac8ce4c7a03a493ca4fe6feee48e72",
                "251e945dfc769d3fbd2a0b24cf1758167c5215c6a973a57c2dceb4cf4466582a",
            ),
            (
                "Twofish",
                "867e53478abc69c22028115ea6045c86eaf2ae4d998569a66811c32d5588faa1",
                "ee636d091ab94b03a7930d0bca563bb76fc44e8391b9064e7c212345da38679e",
            ),
            (
                "AES",
                "74e987a6b0b59cedad5b8226c600eb42f0e79ef864d58cda5c8d14b75a6e5838",
                "8b05352affb0b258676aec025d6cfd16ee2bd845fe9a1c565c7c8381804a5e0e",
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
                "7d340e17b7893f760b575bcd83b0604666f5b22e7d3b806b425f246888f327b4",
                "7e7487fb1d113d3a5f8e9a03c7c4ab9ae6deefcf278d2e422c3161e578667aa1",
            ),
            (
                "Serpent",
                "97b27fd190dbbfd57b3a6d6ed273bf28291e0d2f8deb03da831926d99da2e9a9",
                "5045810983c0be266f4e0e43e5290ada24abb207ab65f2bdfeb3b8e0d3ad59f3",
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
                "b474c2b89100f0e2cea8f480e99c9c6ceafbd14fc7a2c354aa05ed27efb80d8d",
                "1ea4cdcda5e456354db47cdb0e1558ab60b73854c7998c40925930bf7de90f26",
            ),
            (
                "Twofish",
                "35289e03f1f79356e071082c44df149ad4ccc0ee8f48613155bcc3713633dfde",
                "0863ad040c1a80bae4ee8efdf7a0a9b1cb8b1ee5614676d81b9d5b2d8c0f1002",
            ),
            (
                "Serpent",
                "229e58759b22c939edba98ed1cb021a3ec17703939f2fa598bb0216865621874",
                "6849e9569a320804adcb4480ba344a66d209810a599a8714211730eaa73b06c8",
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
                "29fe98448dcfef3575a67119c6b96be3e5693ea7346c2f8b1613b351b2be2eb9",
                "0c3ba19ab79440e26178bdce3e5afc4fcce9d6fdd3715046908b3a2ba43d8629",
            ),
            (
                "Twofish",
                "08a6e8bc270bfc174d296229e974f4cb01fd5e48752dd7f35acddf55b2604f24",
                "560cc577545d3226cbde04da112947b21d23fe458410097e7addccd3049f734c",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn truecrypt_71_eight_volumes_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_win11_truecrypt71/mem.raw");
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
