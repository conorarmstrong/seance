//! VeraCrypt **1.18** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.18 installed from
//! the signed public installer (`forensic_corpora/veracrypt_installer`; detached signature good) and 10 volumes mounted together:
//! `a.hc` Serpent, `b.hc` Twofish, `c.hc` AES(Twofish), `d.hc` Serpent(AES), `e.hc` AES(Twofish(Serpent)), `f.hc` Twofish(Serpent), `g.hc` Serpent(Twofish(AES)), `h.hc` AES, `i.hc` Camellia, `j.hc` Kuznyechik (SHA-512 and no file system, the data area is random, passwords `SeanceVC-118-A` and so on, written on the host by `scripts/oracle/tc7_make_volume.py ... vera` because this version's Format has no command line; the real driver mounted every one). The ground
//! truth is independent of this crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`, which gave the
//! digests pinned here. Before this version was installed the guest was cleaned of every other TrueCrypt and VeraCrypt install and
//! restarted, so the driver in the capture is this version's own.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_118/mem.raw` or name it
//! with `SEANCE_WIN11_VC118_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC118_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_118/mem.raw"),
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
            "6477c2531c58ec1a6f2472eff8f3d0bd3c56aa515698c5a5ba6ede430998b5fb",
            "4fad327ca9dc3a57ca9c679a09a5b39125203f912cf2116952495722d6b888e2",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "4c18ba54f311fab79fa3936d793734d8694e1ee3b865a41fe5f70bab61d10d85",
            "6ba13fd9795701c1684f339422e2f0a2ee00ec9a55c7d333f7e2d50b642d56ac",
        )],
    ),
    (
        "c.hc",
        "AES-Twofish",
        7,
        &[
            (
                "Twofish",
                "7b6fa7e5346a19f82d21032de668794efd0eb8c1c16bcee65e57588eb6f497b6",
                "7ba1cecfc476d0a0d97748d96953c1fdce3d53b3be5a9d2e9719c20ea7b84b69",
            ),
            (
                "AES",
                "00c4d083db5f96a60e1be7c100b0f215113af142ba6118af684839624ba65131",
                "95f5cde517dba220b6a8207c25d86f5585a19c0142edbdc6fa5750d172b58291",
            ),
        ],
    ),
    (
        "d.hc",
        "Serpent-AES",
        9,
        &[
            (
                "AES",
                "814e72e4251ff6bdd76cfbfc78e35349539ebfd89a590145d17b407d380f5a31",
                "c9a8798d4cd10cba4169d1e72f6cbbf7db3d6032df69666cbad2ba81226aa6ce",
            ),
            (
                "Serpent",
                "ce1d81f121909e8bbff44c0e34728e7c031f7e3974d80ce5f08979abdef99a39",
                "66a6bcb245ffa152334eab1933bf61b7e45fc1432a980b3a169f5cf5d28efc35",
            ),
        ],
    ),
    (
        "e.hc",
        "AES-Twofish-Serpent",
        8,
        &[
            (
                "Serpent",
                "a2dd502f728ce4e2eba4058a480b8a32f24369ee468e332d0972d6b119bc8e60",
                "c5cbefc2d28c831a2f5a02d78c958dd717795c51e917ae65bc57322241fbd120",
            ),
            (
                "Twofish",
                "b17eb9bab1e655bcbaa4ae1d85ebd14939b74ec97229520884997e0446257c60",
                "3a3cf59e2c8e965a863cb27c41821c43eeda96a6108ebf496f9299e753016d34",
            ),
            (
                "AES",
                "db0dcdde2b363c9a39dae8d7a9d1206f5457b39b422a50977836674c947368a2",
                "91940eee9a9de9462b5f6558ebfa825eae183cefd7d1368ceeb3c97cf7b25740",
            ),
        ],
    ),
    (
        "f.hc",
        "Twofish-Serpent",
        11,
        &[
            (
                "Serpent",
                "de12f1f7f8eeeeaf863778374cf2799b51eabea487b33e62571b09b5a3fd2dc3",
                "79ef4ffaf9044c73129d3c1e3c963c808bb03ff8929fe06cf384398cac9f67da",
            ),
            (
                "Twofish",
                "876211bf18308aedf4b63a9ab8e3a0dd3c258f7d04d9de250a699470040479fb",
                "ed95a6d36e5e54b3803a8df2f7745ead44fe0f73da15817c51c11bbd4a3b012d",
            ),
        ],
    ),
    (
        "g.hc",
        "Serpent-Twofish-AES",
        10,
        &[
            (
                "AES",
                "c339ed2c93d5ba65652d2b4c3bc9415c9c4b1caca766ed9b0093925a8283054f",
                "5e3f40fb3d43dfd28a83d5625f3e0133b557cacdd30b147ecc55a994ec83eb37",
            ),
            (
                "Twofish",
                "ebfdbaaa92494b47b48ad6fdac93487411a05d3ac110bee86484992b75040180",
                "6a02956bdcb817a43984d154c33e04757d00cf5c722271c764836f7c8a118bc3",
            ),
            (
                "Serpent",
                "300f3317fadb630bb6a5113cc0f3d992a9c471b710ebf7e10e4d84009d665b14",
                "9257bb242e745ecd5a38f61d75561085e7c65d67ba974e8682389e84d008e122",
            ),
        ],
    ),
    (
        "h.hc",
        "AES",
        1,
        &[(
            "AES",
            "f632bdd0a549d539012654c43211643282a6228340f33220de897d58b688449b",
            "3ddb6620e2530418332ea478b7be9f60adacaeff52265ec8ec7d494a1740ded1",
        )],
    ),
    (
        "i.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "542f2e8fe9bb0ea5ef00d0027ad72f49fe4c0c95c05cac304285059412c617a4",
            "6dd98efde6f2ec204bb5452265767672baa226ba7773d3ef9fd20a1c2c8fc6ee",
        )],
    ),
    (
        "j.hc",
        "Kuznyechik",
        6,
        &[(
            "Kuznyechik",
            "5363ef95d81e9836a2ff2158995d5fb6e40867563d8139379c96b8883b3dc603",
            "cd72ba31df385c911cec73d111c414a469ea4f8ab80290b213df9c641f26bdb4",
        )],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_10_volumes_is_found_on_veracrypt_118_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_118/mem.raw"
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
