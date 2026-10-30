//! VeraCrypt **1.17** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.17 installed from
//! the signed public installer (`forensic_corpora/veracrypt_installer`; detached signature good) and 8 volumes mounted together:
//! `a.hc` Serpent, `b.hc` Twofish, `c.hc` AES(Twofish), `d.hc` Serpent(AES), `e.hc` AES(Twofish(Serpent)), `f.hc` Twofish(Serpent), `g.hc` Serpent(Twofish(AES)), `h.hc` AES (SHA-512 and no file system, the data area is random, passwords `SeanceVC-117-A` and so on, written on the host by `scripts/oracle/tc7_make_volume.py ... vera` because this version's Format has no command line; the real driver mounted every one). The ground
//! truth is independent of this crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`, which gave the
//! digests pinned here. Before this version was installed the guest was cleaned of every other TrueCrypt and VeraCrypt install and
//! restarted, so the driver in the capture is this version's own.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_117/mem.raw` or name it
//! with `SEANCE_WIN11_VC117_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC117_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_117/mem.raw"),
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
            "a077257ad94eefff57151d0541dff98874b967d66b21cbb2c699180585dbefb0",
            "53bdb64a7cd12b5a318c0eaca1aa0e4093d5cc1b14a355325f28a469661b982b",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "165afd52034d21349c35f7afa12afea1cbaea8c1bf212264d6094475babaa263",
            "01f9c5bda89bae45e4dffad5e8ba17c6d9d4a80e0e7b5ec834f7e3cbcf9eaae9",
        )],
    ),
    (
        "c.hc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "38b375b9f5acb694181f2729d1847d1d3808c0a4c8288c06aa613b9ee3af57fb",
                "6df15149d83d542ee4ee326190353495de3fc8e752a31295a738bb2c02db5792",
            ),
            (
                "AES",
                "2f03e3699ba15e739371928c4de565223bb9e2abb6b3e47ee561c70568654ea9",
                "7309bc1ad2bc7fb1fc30680d7d00620b950bb9653bc4a0f7f8fc1dbdd81f9a63",
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
                "cf67bcaec999c47c18d58706dff3bf0a83fc37b20504aa34dd49c80b80fac387",
                "cb80cb50ad444295a30f6e00ffc46bfb58c3ac2f654e70771ecd75fd0312b928",
            ),
            (
                "Serpent",
                "e6a100c3e91baab83a2ffe400273fdd2d38080bfd0f16b59021c613beb0f8f51",
                "980acce967c7951d983c62f630a427af06e6be0062453707004f923ea4997227",
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
                "2abeccb8fff428d5719b587811a8489e02d0ae528dc9baea197ef15918aee1f4",
                "481e13e449d6ba638ceb62aa783c9da830548ae92f4be37ba66718d1b68a30fe",
            ),
            (
                "Twofish",
                "3a7add06e9a82e57009cc1423e3a1c03a3debf75837da2c221b45fc855c70953",
                "16488295f31e350d816170ea1856e51ce6fd643f26ce96bade6924c841fd5351",
            ),
            (
                "AES",
                "405bea96d1a49f795ba6d2464f1747aaaa66b9896cfbe393efd240323e67c807",
                "d9336c1c54fb6e39ee3e28850994d2f986aff709c59c63fd000438d96a72af65",
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
                "8412a3c25ecfe0ea631d3d02cf7cd8f8f914f8f460e046ac28a8238373af4f5d",
                "8aafe48bf78223f158e2e830e28545a19366d05f54d3b6d170daba549675c4f3",
            ),
            (
                "Twofish",
                "94cd92e55120dd3b0d1c57ce45a8ed413178c870e50a3a84098d4b2a0d73a493",
                "3e5d2e380a9c5437fb800a94b845d8e5e13ac3b493e5b721daeff51aba51a776",
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
                "ed07cd7354c0ccc4e14515eb199220627fdad8edbec479d400a5a5b9ff1525be",
                "6dfdb1c600fcd65ed17ec9e6e60424c83f40a1fe664f26ad32bdcae2a1d30e23",
            ),
            (
                "Twofish",
                "18182167af7ea637f2c873713947be61ef08b21d62ebd53ded89c42cc7d868f3",
                "ad22e6575bb2cd87067ca95149c47bc8351290b80e695ed28906ac7885cd5f68",
            ),
            (
                "Serpent",
                "39a43eef0d385e0a6454b6c54eddeb7bf818a6317f8e92c443bf27fc71a324d6",
                "4c77cf25becf9250f66bee910fa546574d061bf41f65b19d5a3b32b9ecea10a5",
            ),
        ],
    ),
    (
        "h.hc",
        "AES",
        1,
        &[(
            "AES",
            "89f5c4aeba4e6378ec6b19fd95778097f566f4f6b8107a729661d0e839bdbc80",
            "826ac1c0d14d8e8441209a9545b335b24ac820d462a27bbcba9cc2dc8d3855b3",
        )],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_8_volumes_is_found_on_veracrypt_117_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_117/mem.raw"
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
