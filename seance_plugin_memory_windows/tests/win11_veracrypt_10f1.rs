//! VeraCrypt **1.0f-1** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.0f-1 installed from
//! the signed public installer (`forensic_corpora/veracrypt_installer`; detached signature good) and 8 volumes mounted together:
//! `a.hc` Serpent, `b.hc` Twofish, `c.hc` AES(Twofish), `d.hc` Serpent(AES), `e.hc` AES(Twofish(Serpent)), `f.hc` Twofish(Serpent), `g.hc` Serpent(Twofish(AES)), `h.hc` AES (SHA-512 and no file system, the data area is random, passwords `SeanceVC-10f1-A` and so on, written on the host by `scripts/oracle/tc7_make_volume.py ... vera` because this version's Format has no command line; the real driver mounted every one). The ground
//! truth is independent of this crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`, which gave the
//! digests pinned here. Before this version was installed the guest was cleaned of every other TrueCrypt and VeraCrypt install and
//! restarted, so the driver in the capture is this version's own.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_10f1/mem.raw` or name it
//! with `SEANCE_WIN11_VC10F1_MEMORY`. Release only.

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
            .join("forensic_corpora/lab_win11_veracrypt_10f1/mem.raw"),
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
            "9014fbc22e8972920028031d5cb91ded12d91c055452391a8aa1c72182ed8274",
            "f81bee6f2c186aca12d98288f4577ca7c88fe59aeb0a88f4a2ab9c9e445a15d0",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "0428460718d0b8851f7a5d17b78bdeb38bb924c6fbe684ba3fabc8ca0f63c3ea",
            "a6782f82c2527407b1c6cc87549677ee71637598aeba26c95e7eb202cb820fdd",
        )],
    ),
    (
        "c.hc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "32471a97295cbc004cdf0b7ea695b4693dddebcece9b1bcaf6a2779aec3a46b7",
                "013c9b7d9929850b836712c5a1b26203e6b8325ebdbf15e4e84a7532cb379455",
            ),
            (
                "AES",
                "f90437550e4810fb396a67f0ef636c884e56c632ac60552701da7036ab5bf674",
                "bea3023e665c4d8a745c97f940acbbe2cc9ee9f31bb5d9877755ce9b21058745",
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
                "91829913af4493312761b04dc12f21dc53065ab6d6b0c0a204b9fd5fed828d41",
                "7ac67fe4b70f98355dc143c06dfd82be54262c1a2ad2cf14564a2490f590604f",
            ),
            (
                "Serpent",
                "2be1b9217461d82ac0a8b00240845fdffbfd80ef0743f2518f62bba14c6e73eb",
                "077c8a5e1674ae6b0c49ab60da2dd101e178548eca8366aaef5d4d8de4c09d57",
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
                "90826cdd5e383fa2661df15ae4f9980e060983700f15803aab838e09ff08ce96",
                "43fa0b5ab3d4a16103f87d33d52569695533fc95595f46d55f5e1acd2e69bbad",
            ),
            (
                "Twofish",
                "af2910aa006c660afdb952aef9ed9797509c0b5aaf2369ed5ef4a3ab2c8c1a04",
                "354a932a5fb2ad96703f7f8f6020d94969e7364ae101d6f8a0121541dc22ca37",
            ),
            (
                "AES",
                "c14feb8a0a8b137a9a3103596615a5fe969fddfd4e951d512c94c90450e5e8df",
                "9107c5a41f5766d3841538d0a233f784bb8b79d63aaa85fa63d0e3918906f583",
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
                "012b68b2b0a261e6df539f1ac552a6079bfda6fea3e4541f8a8ff6521b1ff19c",
                "70e6010892281da1ffb4008430a0711786fdb52fb2141345ddb588be937cc8ac",
            ),
            (
                "Twofish",
                "f60f64981c428e8e26946b24b80cc07d01b9c6d24cdf5ed83b457c213c354829",
                "cacb46a128b9b35e5d02a8390ec5d8561487dc5d761e9afeaafc77965ab9dc6b",
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
                "c41b6648758fbf5aabf3e4eaccb8ab61bf1dd1dc0573a72ddd608e0636019cd6",
                "f96cb2a93e353c6c759647ffbbcacbea53ae91b0fd03e401320cf770aa04a60e",
            ),
            (
                "Twofish",
                "3c32e6d494c6f59dd5437634704b635fc3321b731136900638819af1ba2f22cb",
                "07a4f5a16b7ba172e7d948ef263bc0d987fe511290d28111a048aea4120b1fc6",
            ),
            (
                "Serpent",
                "2b7ab12f90d7ba4adb9c9bb6e941ca79f8f2151c173658a45d1495f50c623f82",
                "c7b57fdf45ca5f5876ea839f2b6f2d33384954d3ef33a208a76be3b7c6892200",
            ),
        ],
    ),
    (
        "h.hc",
        "AES",
        1,
        &[(
            "AES",
            "8d57dc7cf04ae3a90ca05979d0d8f114c283c4246dc9897fd94a105d3daaea27",
            "f4d955e0ffdeb5365b76209f6c375d9aadd4a61e8cd9e146ca804221ed57da18",
        )],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_8_volumes_is_found_on_veracrypt_10f1_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_10f1/mem.raw"
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
