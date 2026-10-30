//! VeraCrypt **1.13** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.13 installed from
//! the signed public installer (`forensic_corpora/veracrypt_installer`; detached signature good) and 8 volumes mounted together:
//! `a.hc` Serpent, `b.hc` Twofish, `c.hc` AES(Twofish), `d.hc` Serpent(AES), `e.hc` AES(Twofish(Serpent)), `f.hc` Twofish(Serpent), `g.hc` Serpent(Twofish(AES)), `h.hc` AES (SHA-512 and no file system, the data area is random, passwords `SeanceVC-113-A` and so on, written on the host by `scripts/oracle/tc7_make_volume.py ... vera` because this version's Format has no command line; the real driver mounted every one). The ground
//! truth is independent of this crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`, which gave the
//! digests pinned here. Before this version was installed the guest was cleaned of every other TrueCrypt and VeraCrypt install and
//! restarted, so the driver in the capture is this version's own.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_113/mem.raw` or name it
//! with `SEANCE_WIN11_VC113_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC113_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_113/mem.raw"),
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
            "de5cd7ea4e6415f57a24326cf86905a04e553508496fe93a13f817cdfcd2e290",
            "ad8f63ab4132104a64cf0612e8f9fab143cd461cbe20064b357ddc2c2d63c7ab",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "11820a78f6c5c1461d39e2c7c4a6c227844ebf4916bf438d816eeecc7e95f3be",
            "cab71f1c72eb42295b03bab640a13202db4ec0eb1f450e3c3bfcbbe72efcaf42",
        )],
    ),
    (
        "c.hc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "6d9447a8a349e62627a718a9607d0ba5f2809aae9e625debdfb1471271838b37",
                "7ae2871803a1cd0582fcf1011c358dd9c8978e0f54984c840a1fbc61e03d8aaa",
            ),
            (
                "AES",
                "b4655e47c403b06872a28ca46717ba7c2db4e42b887130720f39a4737dde0156",
                "d536c2fbf1d9ec288df387ea1bc83c43d13f3a9034191349ddacd3e14c57f85c",
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
                "0d22271a3659d77a561d9cd8c596ce49a2596e0805ca1ee6b7822e83d3e8bb57",
                "5c1ece7ee043573f3eb8ddc05d026b45e880af4458dec2eac9f7e48c40dcb1b5",
            ),
            (
                "Serpent",
                "3b86436d0bdbc218d55b24c17df709a21e0b18b256ae63bd1ff2633d07aaee5a",
                "ffb7d2f4380da1370191e06b9377503ce3696e5f986decd4364408f16d9be1f9",
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
                "6addda60141a1fe0ac3056bfcefe0f1653ba4955b53f819bb0f539fc633322d2",
                "2e6747536464ea28ef37de81ec28c7cb27381a121f5c68ddb4123258e00c3007",
            ),
            (
                "Twofish",
                "93a4d95850baad02600d9d97a26f6d3cc5a7fa3159f5148f51edb8e212024726",
                "7ae6731d8660b26a586d66ae89fc7ae059f46719cab9559a8522d1f188aa559d",
            ),
            (
                "AES",
                "8c393ec2ed56c8af81725d9d73ba92f284cdfae56878c941860a674bd4b59088",
                "66f76b3a2a94ca6c6e05c715144f08a54218f18f52b9ddb1ec8448fde5abe1b0",
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
                "76041ce1d2dbae91a52f3d8262d4a8b61e3b2be5c31320e71ebf8475b09ab4b2",
                "6fa62c41e189b1d36843db1f4833c4afe6111770656eef0f334322f02eb81ae4",
            ),
            (
                "Twofish",
                "54b599b6c5fb3d4109b89cffa6792dc22533f1556f5e058c78b5f83e2757a018",
                "4f458f414a3195be4e7cbf914fd24253c9d40f729550f5f6446eeb2e2a17b556",
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
                "b5182bbbbf4fc492a89eb1dc02ac3fd8b396e91ad1cac89b5ebb04b1ef837347",
                "204d02af8a29381dd4924c14dec97870d1d44ab17b422568dc43b79316f0aec3",
            ),
            (
                "Twofish",
                "77afdb6b70088e4a1604d92f03feaba44bf6adb2d03a95ed30c7298adf74ddd0",
                "2eb939bd5a16ff308a23eafd85969957b7225694b31558474f1d0bb4d4170c18",
            ),
            (
                "Serpent",
                "fc41ee3355110d64f5c4645757701c4967a457c48b3786ddaa8febef6948cbd3",
                "d366a46f19101b12eabbb6b7e9b2415e24900fd90a9ae64ef92d0af1ffca081e",
            ),
        ],
    ),
    (
        "h.hc",
        "AES",
        1,
        &[(
            "AES",
            "58085037827b1a28a45a2060af85e65c3bfe2c0dabc4719bb992a3af78409fbe",
            "0d40e8c960f281af385ba85dadfa235a15ce1a6f13f98a6de661831c1ead0254",
        )],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_8_volumes_is_found_on_veracrypt_113_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_113/mem.raw"
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
