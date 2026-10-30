//! VeraCrypt **1.0f-2** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.0f-2 installed from
//! the signed public installer (`forensic_corpora/veracrypt_installer`; detached signature good) and 8 volumes mounted together:
//! `a.hc` Serpent, `b.hc` Twofish, `c.hc` AES(Twofish), `d.hc` Serpent(AES), `e.hc` AES(Twofish(Serpent)), `f.hc` Twofish(Serpent), `g.hc` Serpent(Twofish(AES)), `h.hc` AES (SHA-512 and no file system, the data area is random, passwords `SeanceVC-10f2-A` and so on, written on the host by `scripts/oracle/tc7_make_volume.py ... vera` because this version's Format has no command line; the real driver mounted every one). The ground
//! truth is independent of this crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`, which gave the
//! digests pinned here. Before this version was installed the guest was cleaned of every other TrueCrypt and VeraCrypt install and
//! restarted, so the driver in the capture is this version's own.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_10f2/mem.raw` or name it
//! with `SEANCE_WIN11_VC10F2_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC1247_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_10f2/mem.raw"),
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
            "470cce8ca98fe26b128c969315f4f90226cae538df4b5df3750d26d916aac668",
            "ede7a4214d00aa6268b8b8991484cd0beacbf47e17fbb57e36404876b73a7da0",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "db0ad67d7f4f656db5abef71892b9e7c13b6185aa711ac89327f96e72a6ca1b4",
            "92d88cbd843c9c3b781c9cd9eb54496a52e93e2f4c1f974f6daaba318a215f98",
        )],
    ),
    (
        "c.hc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "4a7f446262bb16e5d9d297f8ea43ac4ab688c2358f53f38741b3f44e17b4ca6d",
                "49946c9ee779c0903dd11c699d68bae13e7bdf8d696d712521dbb39aad260b18",
            ),
            (
                "AES",
                "cd77ec2429904916ed6baa14e0c7e13b081e8af40922e54aaa703b84425406b1",
                "6ec8a4382dcb174a62d3c9523592a46d2439be38dd314b6ad5a723e2ab1778c6",
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
                "9131ac58115dd6608609e79f02d7ef7f1059e4f16c31e2e4fd38ea6aa9b02c89",
                "6a5cc01c90c2a4b4e92792ec99141772daa3dae2886806ece975fcccd4356ed2",
            ),
            (
                "Serpent",
                "f10bd0c6e3940d37f292cc4e5fb5ffaae3e5b808cd01ecb58af9836cb15fc202",
                "3762d4fd3e30e8078cc9e3ec1f7d80f73f357298c679642ad2e86d95c78a7a7a",
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
                "25b469e2c377957883de9d0f6ef74db6489df5857796ccd3b1ace640797add4b",
                "3f4049f028fdeb394d8fa638783c3ca51e0517b695123738e9b8ae397db8f651",
            ),
            (
                "Twofish",
                "e303db37766b95a2803002f7afb03d5ccc687e80a141f518a66914b314e19172",
                "6e1bd0e8fa1ecad6fddf399a5b085c9aa4e101824260c80a1f88233f6a4669cb",
            ),
            (
                "AES",
                "55bf4904f7c49e283cfc632a5dea0147f6083a0e0485185a3b8bed851d5c8f1c",
                "48715b1b0f702cc22014825a55dae3e3f0b98634f94323abba5cbab2afdf432f",
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
                "60dd9178f36cb312d5b048c999899a45e5cc19b6b58a06704c27907ce631b9fb",
                "67068b0540e15af0e1d1a57b1b03df0590ce9346b83e395e4a1a0bcdc1d3aa3d",
            ),
            (
                "Twofish",
                "e9b05734b20f24272518a378fada081b1e4766fdb5fdd2b55b367cd4faf57d54",
                "2a5f6dc5e1aaeaa5a6a23ea0c26d9a2ee093a711e04996a5db9a6722973c4af2",
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
                "5647cb215bef8f3bbd6bbdbaa56faa8f078e86bd5ad29f80fc772f2d605e9f14",
                "5d3e7f6d05b42dffeb67cae566f5b81faace24a8038667c63a46b224e30dde6c",
            ),
            (
                "Twofish",
                "d167a9f3f3dc81181c7d53eff8d6c2f1c986c575430d1e25578d693fe966cf9d",
                "64438e512bd7745ca7816fddd57ce32338f45f8c560a5d99706e265f20c129e7",
            ),
            (
                "Serpent",
                "ae8f8d8465f9b7a5dbe77a9d010bb46e448ed46463993853f9f5786dd2a38eee",
                "b51791b03b540dd368de03d0b1a8dfd52a2bd86daa25e91e237977e7d2bf50b5",
            ),
        ],
    ),
    (
        "h.hc",
        "AES",
        1,
        &[(
            "AES",
            "1475412c34d1bf11abdc25d002c0abba385bc47e2103d53aaa8bde75ba9ba5c9",
            "1e58d5304dcf54402071ed14e77bcfec2b660af1a71321562ecac5b92470e4a6",
        )],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_8_volumes_is_found_on_veracrypt_10f2_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_10f2/mem.raw"
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
