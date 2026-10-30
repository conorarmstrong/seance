//! VeraCrypt **1.0f** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.0f installed from
//! the signed public installer (`forensic_corpora/veracrypt_installer`; detached signature good) and 8 volumes mounted together:
//! `a.hc` Serpent, `b.hc` Twofish, `c.hc` AES(Twofish), `d.hc` Serpent(AES), `e.hc` AES(Twofish(Serpent)), `f.hc` Twofish(Serpent), `g.hc` Serpent(Twofish(AES)), `h.hc` AES (SHA-512 and no file system, the data area is random, passwords `SeanceVC-10f-A` and so on, written on the host by `scripts/oracle/tc7_make_volume.py ... vera` because this version's Format has no command line; the real driver mounted every one). The ground
//! truth is independent of this crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`, which gave the
//! digests pinned here. Before this version was installed the guest was cleaned of every other TrueCrypt and VeraCrypt install and
//! restarted, so the driver in the capture is this version's own.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_10f/mem.raw` or name it
//! with `SEANCE_WIN11_VC10F_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC10F_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_10f/mem.raw"),
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
            "5f6a560bce1efc9bc336cf9937866e97bba0266286da101c34db59adc7b91537",
            "32eda3cb24aee252d4196b2d05f9b606e86a1f13948fe0ffd0147dbb35ac6db4",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "6fb4f8dfcb57c10b47221065184f3a7d2a8a3cdef137426cb3349ea93647b747",
            "5d887ed9f37a507c47dc7481df6c43dff73e8519aea62678500061b671ffd3d8",
        )],
    ),
    (
        "c.hc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "dcb97c1b2dd3bf96d0727b96a15e94517b11ab41d294a43a9929629e7ffbe8bb",
                "afb019fa14acd3d4e2c179823d3794cab378e9dd5aaf80b7571a60ba90a1617c",
            ),
            (
                "AES",
                "11033ec6a4a3683992dc65c3d35b65731162c671216816e7a007d2dc7b9ef632",
                "ba2bbfef7317c3eebad921842f47c63250d532837666f62bfcb71cde0ffb70ff",
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
                "a3d97412b0283745f8286d4f88d9a3e81f5a74c3b5857043df1e130f5c27adee",
                "74c58ac642a7f07c7669471c2a3f5259abef1efcf34a04c95c5283f79a5eabab",
            ),
            (
                "Serpent",
                "edc4d1ac2fd10a6de72009dd8810c7b4aa5087917115082c658059f7b864345f",
                "99ee948ec9d0c8ec32a61f305620c2240bf9e2413081e3b4e84333e6ec101961",
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
                "9b2eaaf5aabebda0119afc92ae55b3fb9ac47f13d9c71903ad42d4043e8cb301",
                "6f821ffab945dd9970090401503ce287004d6563200c3dc6d6d45ddbb5143355",
            ),
            (
                "Twofish",
                "3c820be0f7c1fe0494b029da89150cffa76aa8e1f9bfd0e99471220bbbad9dad",
                "c73ee62df49e8bf93e987ece463979716aaa5fdda31b21c74c52d3f10761bb02",
            ),
            (
                "AES",
                "958fbab9146ea17f336e07db853542a3ed920a6d116776787361aa4defc679d9",
                "b5cb3afc75cfe6982612e9786ef121077f0f51b344738ace95ca766f33184c76",
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
                "4799c1e23f4e2d61cf0eec5152036e51c259d760f4d8ac4d0999614b4dd0fe65",
                "5e286918939c65afd8276d3eb76a52c5f3dafe85fcd6f63e420b33e38fd1b7fa",
            ),
            (
                "Twofish",
                "f1d97d67c3e972f97ae7722f474ec943d8e6550fda13a09295a0273f5b13c44a",
                "ade0023d9a8be5b7d3f7003baee21f35d4c14b23c1c4b63c4e069c210048b430",
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
                "66029d96ba6027243c0542ff9255cdb9651605442f73cc34b5c09eca72952416",
                "c33e7d048dd67c8a9ea395e913be3a6a1a834e5ddf1fd156d782d59ba9c83072",
            ),
            (
                "Twofish",
                "ef0b098072190c9d2fcf98d5fc007396eb4eaab14c96a4b3b411e8f4741b0f48",
                "7a023d0189ad4448e115beafadc16599df0edcb056e1cc5b86763557ec9b5b79",
            ),
            (
                "Serpent",
                "1604d4963290bed00fe831ae485ab3f1662b799f060e08c49493ad15fef7c483",
                "2679d339c94fcc25e14b49bb7fed73953e4a364dd066cfb94f395b8deba9d906",
            ),
        ],
    ),
    (
        "h.hc",
        "AES",
        1,
        &[(
            "AES",
            "fe220e5125bbd9d88ce6431eecdb715a636b4278190e6acb8631f2953c0acfdd",
            "f6d46c5120e7785529e0b67123a84b8aa88b64d19f090b30637b06e6f5f5a808",
        )],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_8_volumes_is_found_on_veracrypt_10f_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_10f/mem.raw"
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
