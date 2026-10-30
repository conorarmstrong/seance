//! VeraCrypt **1.12** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.12 installed from
//! the signed public installer (`forensic_corpora/veracrypt_installer`; detached signature good) and 8 volumes mounted together:
//! `a.hc` Serpent, `b.hc` Twofish, `c.hc` AES(Twofish), `d.hc` Serpent(AES), `e.hc` AES(Twofish(Serpent)), `f.hc` Twofish(Serpent), `g.hc` Serpent(Twofish(AES)), `h.hc` AES (SHA-512 and no file system, the data area is random, passwords `SeanceVC-112-A` and so on, written on the host by `scripts/oracle/tc7_make_volume.py ... vera` because this version's Format has no command line; the real driver mounted every one). The ground
//! truth is independent of this crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`, which gave the
//! digests pinned here. Before this version was installed the guest was cleaned of every other TrueCrypt and VeraCrypt install and
//! restarted, so the driver in the capture is this version's own.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_112/mem.raw` or name it
//! with `SEANCE_WIN11_VC112_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC112_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_112/mem.raw"),
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
            "d1048203fc7427308d1ba585abed5206cddd7e9fa8f983f9e9c342a43a336ce7",
            "5734c2a38ddcdb6c12261a5a1a4d2efc40bc9854690f6d5dcf80b72a0f0fca83",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "e62fc3d39edee5560d5df1bd856dcae9b63f54a607660b1086a533079a5c6708",
            "296f2eedc3e3d15e816424b939afce843abc6bd2014dde9a34200d02d31bfe33",
        )],
    ),
    (
        "c.hc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "49cc60ee4c4ac71b20772fd34b2145112db8a184c9a9a274ad88cbd2e11cbdc9",
                "a7f54a0cfe295a9a40fe1ed44719b38205a99e94be0584ad0a567f385b4fdea3",
            ),
            (
                "AES",
                "9a207d193491e0895e637c44bbe7a29ca66313854c91d53dc5113948951baa3c",
                "f97088e9eae80cbe87631de9b1770f3fac074eb31c194755b3a47dc2b873c9c6",
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
                "3434c802eda915ea04b1597c6db773f04fa8eac4250f38171c418f1a3a344c95",
                "95f424378eae4e44f82a8fc394e710b3745cc0a3f77340da6248bc75cac68b63",
            ),
            (
                "Serpent",
                "1aa3cba8417161b920a8518638f1bd8ad6029d2de1f0c868bd9f3e004e299d9a",
                "ecffbb18163813b12020afd813110b46d16167624fb8a28a3e7b73b800f442f9",
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
                "a456d71c2bfc47aded8a64935d8de68b44b613fede47204328d1acafafe05ebd",
                "4d7e457a793dcf50fbc35db63c9461ccad459afa7c204420d99f7494035bfef0",
            ),
            (
                "Twofish",
                "78e442d9b1cdcd6f89190b6ffd18bee0346f4a7f3d80ce4dd97b1e7f33a1001b",
                "49ba3a40fb3e2e3ac8c59c1ee7a2d470cf6b3b330a2ed75564b952f9a86209bd",
            ),
            (
                "AES",
                "cbd9eba58036e55f8d18c45ac67ac3bb521810996087fb526936862e99dba806",
                "4235977afb2debe4a0cc9cad1189769f3d393dd94139ba538efd0d64d2525726",
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
                "7403e6d5b01eab39c03d397c9e0bf652c99d2e56c9e65b4792057dbbc3acab2e",
                "d6893adcae7635ca1b70ec9091c5d7cd323b92d7a467e2fc9c1be1ecece1897c",
            ),
            (
                "Twofish",
                "23fc87d5224b51a0f7bb76483f93e9646f8d268e1f73956e6f95f76e20b28726",
                "0d8dada8c4e587c61185b6a31cbb43b05c24cbd90b478217e7d0101d607a1127",
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
                "04286b7aeb00442f2e801a1fca30674aeb7a07e282336a43407cdd10a93486ab",
                "20f913fa12b59e8255cfeef1c526abc51945d58fc797032d8e3fe808fc5ff54c",
            ),
            (
                "Twofish",
                "3343dbbc718caff9ab2ec3bdd57f6490bc0cf527796dbd30fc6884faf181fd46",
                "37442de31608d6c8cf73d3870959deab38319ff87248425ef54d3b7cd8722e92",
            ),
            (
                "Serpent",
                "7f4c483e2d1e226763a1a8ea57bba26a79fc9ad2fd11d29d8083c4a9d20c67de",
                "99cc0b034e2cccac8bbb0a98f09ae27f9ce386e46204401372e77a4d09eb4094",
            ),
        ],
    ),
    (
        "h.hc",
        "AES",
        1,
        &[(
            "AES",
            "09798a5cc67f037ac0c18a1d793bf75f36a23546fe48435163b445189a587868",
            "6736f2aa93edb6a2effa37cc59f99f468f9c406462f98625c7945c8102c37a14",
        )],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_8_volumes_is_found_on_veracrypt_112_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_112/mem.raw"
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
