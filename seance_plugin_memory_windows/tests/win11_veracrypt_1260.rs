//! VeraCrypt 1.26.29 in memory (`MEM-044`) with **a Serpent volume, a Twofish volume and five cascades mounted together**: the
//! Windows 11 25H2 lab VM of `win11_veracrypt.rs`, with `s.hc` Serpent, `t.hc` Twofish, `u.hc` AES-Twofish, `v.hc` AES-Twofish-Serpent,
//! `w.hc` Serpent-AES, `x.hc` Serpent-Twofish-AES and `y.hc` Twofish-Serpent (SHA-512 / NTFS, passwords `SeanceVC-S-1101` to
//! `SeanceVC-Y-7707`) mounted as `P:` to `V:` when the memory was dumped. The ground truth is independent of this crate: each header was
//! decrypted on the host with `scripts/oracle/vc_header_keys_all.py`, which gave the digests pinned here. The test asks whether the sweep
//! finds every master key by its hash and reads each container: the ids on this version are **2, 3, 6, 7, 8, 9, 10**, one lower than
//! 1.25.9's from the cascades up.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_1260/mem.raw` or name it
//! with `SEANCE_WIN11_VC1260_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC1260_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_1260/mem.raw"),
    };
    p.exists().then_some(p)
}

/// `(volume, cascade name, container id, [(cipher, primary key SHA-256, tweak key SHA-256)])`: the keys as the host
/// oracle read them out of each volume's header. The cipher order is the oracle's, not the buffer's.
#[allow(clippy::type_complexity)]
const VOLUMES: &[(&str, &str, u32, &[(&str, &str, &str)])] = &[
    (
        "s.hc",
        "Serpent",
        2,
        &[(
            "Serpent",
            "ce9b7fde0793c9865a5cf61e2243cf1e8ff1e3c097b59ccab0305959c97678cc",
            "4ce973c10fc474d99239559639b29efe7eb68b887e3675f89054a06977e817d0",
        )],
    ),
    (
        "t.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "dce202a638c48a572e7aa16043814306f6fa371bcdc3c94594875ad95f569ef2",
            "7c4c85dc80a0190269ba65f46e882d01d9fda164a744ebe45ebebbfd41a9c588",
        )],
    ),
    (
        "u.hc",
        "AES-Twofish",
        6,
        &[
            (
                "Twofish",
                "195eb809c2adab88ed14f1dba395b35a710dbf30e6aba4e72584f573c987f165",
                "7c1bbc2d310f8365a72c3a5024d6d8e3b4fb8986fd3f2fb195d001581c7867bd",
            ),
            (
                "AES",
                "84c8c5da87ff4d8d7c6c2fe93c4db3ca2a9d6650c0d8ecf4f6ecf4d9a221b975",
                "8bb844a927d1793c1c0f099da8a420eb35049c355f5b6151a8a50a3e7f729739",
            ),
        ],
    ),
    (
        "v.hc",
        "AES-Twofish-Serpent",
        7,
        &[
            (
                "Serpent",
                "db62171c31eb6580f5c4ae5c5b0710f45133746adf3ff82dbe07714cca093e5b",
                "34226cd9521567de4bfc6dee47cd861fd28106acf2fd6fa9fea04129810f2cee",
            ),
            (
                "Twofish",
                "fbb305b961c73b2d8ca48fb48f8f87052a9042e9fe7738c73a969106e05eceb3",
                "710900e28f67adfc8d0d620300ca400b7e5804a33a84b42a562d3d1bb90decc0",
            ),
            (
                "AES",
                "35c7742065d7e9ab011bf9277971006295e2a15b27b300140c87cb52621fc1fb",
                "98ed08db94ff81257fc656633053e8f0bd1d83379d106d2d8a60f5d86beb08f5",
            ),
        ],
    ),
    (
        "w.hc",
        "Serpent-AES",
        8,
        &[
            (
                "AES",
                "9906440e88d2ffa7654876b4b453c6c403f0a0658836f90836bac66253652674",
                "e5bb2178b38461f986b47a30b624b17403d1ac2fcf9f0dfabf3ce2293daca5cf",
            ),
            (
                "Serpent",
                "970dee640a85c09a0053a689a84c6e8ebf89a234177e87fd9ef203482fa4d601",
                "dd30025e7b2f55b1d1bc81e394baa0a9f3896b9b04ed776ae5dd98d9b1d53abd",
            ),
        ],
    ),
    (
        "x.hc",
        "Serpent-Twofish-AES",
        9,
        &[
            (
                "AES",
                "d27d0bfd344223c2de209f1a469a1b2d1792d0f8bbbf850f75f8673f782f8998",
                "84a1d6f9ae4790b72a622bd773507c1c5f1f8226f49cf5c3eaf22d7fd39f775a",
            ),
            (
                "Twofish",
                "32f6a97f560e6c5c52d2cd04947f535c8124ff324c7bc57a8c3126af78a341e4",
                "866216ed8d6dd7127cd22600c6bcb9d3c33936418acaf63d070de5f10bd840e9",
            ),
            (
                "Serpent",
                "ef0d54ff118348af1d1429ffad87dcbc44ae7591c470e97eb70e2086f291fb11",
                "42d6edebd350a42721302b51375cc540125ac3f43096b49192a2a5e72dcf3b4b",
            ),
        ],
    ),
    (
        "y.hc",
        "Twofish-Serpent",
        10,
        &[
            (
                "Serpent",
                "f43190a257e5652425d11c96c93a73165c585659f64caaee3aeb7916971487d3",
                "738dad5dd701ddf0b23dab906eb9b09dd38e048d37e693a85f700ce09c2dbc8b",
            ),
            (
                "Twofish",
                "03ba23846c6529f1e4dbf0e7f3e82d02b691cc9a563a68fa4ce06387ca706eb1",
                "a48a0a0f298969adf8de45132ed8b41cb1b7deb7b2e9bf17d18130cd171c7da0",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn a_serpent_a_twofish_and_five_cascades_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_1260/mem.raw"
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
            "VeraCrypt 1.26.29 to 1.26.30 (observed on 1.26.29, 1.26.30)"
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
