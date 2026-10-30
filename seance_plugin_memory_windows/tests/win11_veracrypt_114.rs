//! VeraCrypt **1.14** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.14 installed from
//! the signed public installer (`forensic_corpora/veracrypt_installer`; detached signature good) and 8 volumes mounted together:
//! `a.hc` Serpent, `b.hc` Twofish, `c.hc` AES(Twofish), `d.hc` Serpent(AES), `e.hc` AES(Twofish(Serpent)), `f.hc` Twofish(Serpent), `g.hc` Serpent(Twofish(AES)), `h.hc` AES (SHA-512 and no file system, the data area is random, passwords `SeanceVC-114-A` and so on, written on the host by `scripts/oracle/tc7_make_volume.py ... vera` because this version's Format has no command line; the real driver mounted every one). The ground
//! truth is independent of this crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`, which gave the
//! digests pinned here. Before this version was installed the guest was cleaned of every other TrueCrypt and VeraCrypt install and
//! restarted, so the driver in the capture is this version's own.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_114/mem.raw` or name it
//! with `SEANCE_WIN11_VC114_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC114_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_114/mem.raw"),
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
            "169b928371b89b3efda2b4677a228f5e581fbf3a660e4787a08c4ae9d002a731",
            "209070db2b238de7b366eb2c089035087b9272e1bd6f842814d923885857095d",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "30648f952e3e8d558b313b0ebcf2b678d4914f284433b1e20632d92edee65af1",
            "82ab97e8db661ac00a59044a8f8df3a8484bf2271340f5d58aa9e3235b3450a5",
        )],
    ),
    (
        "c.hc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "fe5ce12dc811c0a2744c36c8f26cd6de68d56089af143ac7da63b835fbbf975c",
                "8e33f2af1ef4180a402f578bc7c10a90c02a167578b9d4e67c49388402ee79e4",
            ),
            (
                "AES",
                "e14a090ef0903337edfb952554c718ad476c8d6a0b4cb2a3e0f774b03c0403b7",
                "c90d1bc94745207b66e05722b7109126545139ab6c42aba50769c8ee5a173686",
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
                "d4adced9a821beeb6e709d3c3b0b351461a20c692960194604ea4ba00eef7109",
                "46aa73ae1750a77115f5ada365b2f01a91ad7438feef5113f10e4877f3c7fdbf",
            ),
            (
                "Serpent",
                "482b83597a29d9407381e2d862861098793c21cc32576d66eee339b65bff9ab4",
                "086ce289fe1a82f6f3f56d5e77fe044264e8ba6377a2fcb5cd4094c9c4867bd3",
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
                "bf3f89bf1dbf9286a30a5bfc606fcdb41bdeccbf540194fe889db1b18e62d2a9",
                "d80205506f6d1c6fc0105d3004f7e309dbf7711468deca3043659eafb88f5cce",
            ),
            (
                "Twofish",
                "25b3bdd47e4e5314f9ab1680b4a56bf4ea47254689a210d0b1062d4663c4686d",
                "c472c0e2ffbebcd003909cd68c7c1a89a4091c1dd48d5a760f7297ea8c5a1f79",
            ),
            (
                "AES",
                "d0cf0b1dcc83601bda95256d457ec042876887a1b52966962f47a33e0f9bc645",
                "e166d8b11172d84aa8130602af74c4f80780165e3cd53210f8553fb60c92b8ea",
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
                "64de2e9489c8458061e5c4fd5f528d02a92d3b25b1cdce6cb916300d19226906",
                "e758269ff1fcf5a313d722ad42ffefc6bd3b3083b17108095e5ae0c4eeb8683e",
            ),
            (
                "Twofish",
                "06ee97dab42f93c0e7b8a359bddb21991b783e0aae554292749603a0d7ed8e47",
                "5b6f3c87f411537f59a21c5cff7e1087f4e55494b1aa36aa8d57d6dfdfe42ec8",
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
                "179f68f7062d82fc665f49e1c9f5206d17cb3f334fa6d20f7327a2db59f55bda",
                "eade0758272830f51b5021a26b8e11e694dbe879af38effaf2693e0014a4304b",
            ),
            (
                "Twofish",
                "14858d5748214b522d3b9f52e7c5b7aaeac3fa21a8b657d93819975fdbf1d75f",
                "fccbf2fec574a101276ef66563a4a6e2ac1957f687469147e85de0db972cbbf2",
            ),
            (
                "Serpent",
                "815eb521ae306c281227456f949058b564f388476ba58158ffc84414d590f7af",
                "ac1084979409bebba816deb43d9c37723d19f793c057cdec49eee486ef970afe",
            ),
        ],
    ),
    (
        "h.hc",
        "AES",
        1,
        &[(
            "AES",
            "3a4a5c94451633b5d05b764bd5cd3449688822efd20d83a6bbe69e9b6cf78349",
            "9fa80204274183768fe0f16550321d9d2816879ea4db256e8bdca8f8092690a1",
        )],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_8_volumes_is_found_on_veracrypt_114_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_114/mem.raw"
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
