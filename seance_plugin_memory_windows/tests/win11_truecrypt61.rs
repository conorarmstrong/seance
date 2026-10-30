//! TrueCrypt 6.1 in memory (`MEM-044`) with **a plain AES volume, a Serpent volume, a Twofish volume and five cascades mounted
//! together**: the Windows 11 lab VM of `win11_veracrypt.rs`, TrueCrypt Setup 6.1 installed from the TrueCrypt Foundation's
//! signed installer (detached PGP signature good; `forensic_corpora/truecrypt_installer/v61`) by its own wizard, `t1.tc` AES,
//! `t2.tc` Serpent, `t3.tc` Twofish, `t4.tc` AES-Twofish, `t5.tc` AES-Twofish-Serpent, `t6.tc` Serpent-AES, `t7.tc`
//! Serpent-Twofish-AES and `t8.tc` Twofish-Serpent mounted as `P:` to `W:` by the real driver. `TrueCrypt Format.exe` has no
//! command line for creating a volume, so the container files were written by `scripts/oracle/tc7_make_volume.py` from the
//! volume format specification (header version 4, as TrueCrypt 6.x writes it, fresh random keys; `vc_header_keys_all.py --magic=TRUE --hash=sha512` reads each header back
//! and its keys equal the writer's); the real driver accepted every one (the mount is the check that the headers are
//! TrueCrypt's). Only `truecrypt.sys` is loaded in the capture (the guest was cleaned of every other TrueCrypt and VeraCrypt
//! driver and restarted before this version was installed). The test asks whether the sweep finds every master key by its hash
//! and reads each container.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_truecrypt61/mem.raw` or name it
//! with `SEANCE_WIN11_TC61_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_TC61_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_truecrypt61/mem.raw"),
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
            "9dcfc2e79542a49d86b784f60e6e146b8e0eb42b05775f21bef6bab44c0bc7a0",
            "2895d9ea1ae968e328b4080fe5a9f66c326321e8e851db381a5d5db76c3f9ba4",
        )],
    ),
    (
        "t2.tc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "5da1d9d3421ffe1a5df5d68aa4ef0d3ed41b4546560a288963476ee1e301201a",
            "cba7861ba032f1ca1e26fbb2d2fad11d717b422d711d4ec2985072a221a590fe",
        )],
    ),
    (
        "t3.tc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "02f46cfd5c41670548524c0d21233e64bad74b9f08ef784617c23d9b4c781fd6",
            "71747a940b1f037798f144064b81d6b8749f50192bd7ec383dc876aefc7d4859",
        )],
    ),
    (
        "t4.tc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "3ccd88ae07f95ca08bf5b734046439b28d6d75fb9d7a32cf30a43ff7cfdf72ec",
                "16540d5ed8855438f028bc45a931a7d5a93dcd3a048df8bb49e6c57f64bc41ae",
            ),
            (
                "AES",
                "8c8266c58de753204f897e2f9d5904d1226d73cb1e7502a10dd375a2d9149fe2",
                "48845dc9737aa38e993e91d9c8f5c66ba851200aeaf6843b604d2441152cde20",
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
                "21c87f952317656897e96441726ae2587ef62862a3a80f9680f7c2f351089cb5",
                "828a795cb25c0d52c37246df6a4d85eb46cc02ecbbe85a49bcc07a9a36f8791d",
            ),
            (
                "Twofish",
                "9e0703f6fdb933e0b8ac7777a6ac19c378a943b9f67727a2338c49032b4e13b7",
                "5d83fcdf23613f522257775aeb70c701477791890ea6bdda6b7a35e5e57f20c1",
            ),
            (
                "AES",
                "9ddb18193fac56c9b12fb27a84e3a1d0ea71012033e88d2e93291b9717e6351c",
                "ba79179082994b019f6f73954e7aa07f220263e642b9ba35f6765b1d1773cc78",
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
                "3f5ae87295ccb6875725f09d349eff8109ab72b4f6b9165d17cbfbbb5fe4d797",
                "82b640d26b738759e1e26b1f137d9402715303ee983a38791893e1f267db4bb8",
            ),
            (
                "Serpent",
                "ffe5d07e70910ca76f2f451afc6503fcaab3636fcb0abdfc75ea4c93603210e3",
                "04a3b139c1c4af92d7694584580e763c33cd6b29f63e4e2bf9879d9421f62f48",
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
                "b9f123b38926e53ea406693f25ac365cc5ab5fdbbc3c71ef3152984be7f9292f",
                "c3d869aadc60e0d95546429bda3d09ae8532082e9050f5714370aed31c952421",
            ),
            (
                "Twofish",
                "3025ea48f8793da55f9664e50fa817d164fef7025ca9641c11b68874f94fa0e0",
                "476520d10f19d0ec61e89ed1ce8f5ce8c595b6cd387d853aff189933b82df36a",
            ),
            (
                "Serpent",
                "a0d554a1d31ba634c5a49945146c7769f543173935fefd09da5bd128e5333089",
                "5ccd3c00b5a547a04f5b0e452169414e8a0011d1ef30cc2326e2295dc4fab58f",
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
                "f3e5bc865dbf33523fd4eb5f4dd880e3b183799883431fa49bbf312ef878e6b5",
                "495415a33c0c792edebc82f2b26a995f779644e8a613ba4ab7306c4a2e9ba5a8",
            ),
            (
                "Twofish",
                "10b78b68612fe4d5ac18104557cd4a6fbb751207911705bf95bebbe75b5c3bf3",
                "912521b776baf782d43d13b2f05a796a929254772f3de3bcb3db7cbacd77cb42",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn truecrypt_61_eight_volumes_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_win11_truecrypt61/mem.raw");
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
