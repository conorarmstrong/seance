//! VeraCrypt **1.16** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.16 installed from
//! the signed public installer (`forensic_corpora/veracrypt_installer`; detached signature good) and 8 volumes mounted together:
//! `a.hc` Serpent, `b.hc` Twofish, `c.hc` AES(Twofish), `d.hc` Serpent(AES), `e.hc` AES(Twofish(Serpent)), `f.hc` Twofish(Serpent), `g.hc` Serpent(Twofish(AES)), `h.hc` AES (SHA-512 and no file system, the data area is random, passwords `SeanceVC-116-A` and so on, written on the host by `scripts/oracle/tc7_make_volume.py ... vera` because this version's Format has no command line; the real driver mounted every one). The ground
//! truth is independent of this crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`, which gave the
//! digests pinned here. Before this version was installed the guest was cleaned of every other TrueCrypt and VeraCrypt install and
//! restarted, so the driver in the capture is this version's own.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_116/mem.raw` or name it
//! with `SEANCE_WIN11_VC116_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC116_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_116/mem.raw"),
    };
    p.exists().then_some(p)
}

/// `(volume, cascade name, container id, [(cipher, primary key SHA-256, tweak key SHA-256)])`: the keys as the host
/// oracle read them out of each volume's header. The cipher order is the oracle's, not the buffer's.
#[allow(clippy::type_complexity)]
const VOLUMES: &[(&str, &str, u32, &[(&str, &str, &str)])] = &[
    (
        "a.hc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "777e78c58eb5d8ba517f51ae92c5facf4258c8703d2c22e522b2f38adbb10600",
            "0c0291a994294b8fd1dda0a241fa60e02a8f59d5b8ec59cb48a9eeac4dced9a0",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "3a5f3658d4d58a472caffd738028c477f8f42c92269aca9b9a5d7f9042126517",
            "c6a2828e77dccbf511fba97093942a999e8adc0d2a7c6d0206a5273e43e38b2a",
        )],
    ),
    (
        "c.hc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "05a43d56b806543e50a6209365bf637e8f83d325790c52f77f1c566dfa7dc65a",
                "aeb91620ec74207cba9dcc629d7774508340c969ba46d19d8628200aea26306a",
            ),
            (
                "AES",
                "4e2ba9d1131588e9dde190d8a4a45c39293ce0f7ea7a6689b90114f8bcd5fc1a",
                "1a13c45c262cde3ab2a87ae2a40b44fc6731fbfa5e7f52d6e8f898d6f8272081",
            ),
        ],
    ),
    (
        "d.hc",
        "Serpent-AES",
        6,
        &[
            (
                "AES",
                "0247ae62b5111e620322d21864c2e26a0c9ca31c6eb3d9ffe3fb1f5dbc488865",
                "29a18808fa002cf2fedf0402cbb5ca97ad2231b37a0ee58e37b97b37a4932d2e",
            ),
            (
                "Serpent",
                "636ddb2c21dd7de9321b3c2b6de6eaaeab6ed342d2e2a0744a2ecce27d083686",
                "facf5edf5f54a486620b7b303f93d353ff6c46ad4657ef3671a5c64ad8813b23",
            ),
        ],
    ),
    (
        "e.hc",
        "AES-Twofish-Serpent",
        5,
        &[
            (
                "Serpent",
                "c8fc0a12c1d9d3f5233db3f0e3bd81d5edd02bf3c49f5bf3117515f1d767f0d0",
                "84051a8e2725e7b00654b44e9f7a91ff6a767ac80df0fff28b5bdbde08253b93",
            ),
            (
                "Twofish",
                "444e4b837b8a896106fe9a14e70a3dbc92dc90bd7d8eec797331f5363871a92f",
                "cbb9cc7cc5c91fe73664da06c04303235eedfd2bee805e7356404b8eb471add8",
            ),
            (
                "AES",
                "72f5487b4b3cd086d71628b0e737e9a4d071f3b8071062c41fab6193a98a4a74",
                "2e721468166ba1e157b8bd7c67058eae1b3f45c7c8a9707e0e41c3fe7f7a4465",
            ),
        ],
    ),
    (
        "f.hc",
        "Twofish-Serpent",
        8,
        &[
            (
                "Serpent",
                "9f0fabffab76c6ff41225f80e7b2ad03211ede18258287481a0dc997a2e916e7",
                "0405f7b87bd4d05c47ca9242166e744c1d7bf4de34fd507c974f7d856f7c173f",
            ),
            (
                "Twofish",
                "375113c70f864d6bbf5d8356c6c0f56a5b2ef397ad9345d99e17cd264e83b50b",
                "2e2a1dbbec060668d64dc136456024035b2a328fae0039ed4440f84248ff9f70",
            ),
        ],
    ),
    (
        "g.hc",
        "Serpent-Twofish-AES",
        7,
        &[
            (
                "AES",
                "97eb8675543a75146ab8b56343e98e1bb3af98561a6ec24209674137cd1a24d5",
                "41742fbacc32a64b3157f5d3a608ea880b52d6f2728816af24f6ecdd8258b94e",
            ),
            (
                "Twofish",
                "2275d80f396ab8bff18eafacc10905f0261ff4ec194ee60b666f3be761a1c95c",
                "4ee9ed4b6953456a13bb37c2979635c85a262618a9bc6c537aa9b52a2f83d640",
            ),
            (
                "Serpent",
                "8645929be7387b9453829835d54d531d5af1afc0a707bf8f5f3c550c601f121c",
                "e7eb47a75d8b3c05f140e77cbb6b357ad433f7ab18102a9fd78ef50c578ee343",
            ),
        ],
    ),
    (
        "h.hc",
        "AES",
        1,
        &[(
            "AES",
            "c6b59d5925b51f1d44dba304d63f85f9dbcdf6595cebd19e3cf1fbd628000068",
            "de489cd22f27b03cc3fd49ec29e6a36d58178be42381a71a6201c4409e637f64",
        )],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_8_volumes_is_found_on_veracrypt_116_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_116/mem.raw"
        );
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
            "VeraCrypt 1.0f to 1.18 (observed on 1.0f, 1.0f-1, 1.0f-2, 1.12, 1.13, 1.14, 1.16, 1.17, 1.18)"
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
