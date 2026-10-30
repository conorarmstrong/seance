//! VeraCrypt **1.0e** in memory (`MEM-044`): the Windows 11 lab VM of `win11_veracrypt_1259.rs` with VeraCrypt 1.0e installed from
//! the signed public installer (`forensic_corpora/veracrypt_installer`; detached signature good) and 8 volumes mounted together:
//! `a.hc` Serpent, `b.hc` Twofish, `c.hc` AES(Twofish), `d.hc` Serpent(AES), `e.hc` AES(Twofish(Serpent)), `f.hc` Twofish(Serpent), `g.hc` Serpent(Twofish(AES)), `h.hc` AES (SHA-512 and no file system, the data area is random, passwords `SeanceVC-10e-A` and so on, written on the host by `scripts/oracle/tc7_make_volume.py ... vera` because this version's Format has no command line; the real driver mounted every one). The ground
//! truth is independent of this crate: each header was decrypted on the host with `scripts/oracle/vc_header_keys_all.py`, which gave the
//! digests pinned here. Before this version was installed the guest was cleaned of every other TrueCrypt and VeraCrypt install and
//! restarted, so the driver in the capture is this version's own.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_10e/mem.raw` or name it
//! with `SEANCE_WIN11_VC10E_MEMORY`. Release only.

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
            .join("forensic_corpora/lab_win11_veracrypt_10e/mem.raw"),
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
            "ed430156fe33cbc602dfa8ba73563f23588874f16a798edd2504bc5056d4e4cd",
            "4e5b08762537ee2aa23dcb3a097461be0c902950ad6734dd4f0d6dd407e6e4e2",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "e47b2fd5358652b0f6f538d7c29efbb6e38f31f233456317a30327af05dbc4b2",
            "362123abf10e583bf0acb64a01bb8782afe85d1e31d980320bba3c837c04a9a7",
        )],
    ),
    (
        "c.hc",
        "AES-Twofish",
        4,
        &[
            (
                "Twofish",
                "82f9604bf7870fe182dbcc2a21f02cba44a778e3a1113323e49fbc9a177f18f0",
                "0c2950b2813302664be8ae17635fd81aaacd206e1400d4dd8e3b579ea03e975e",
            ),
            (
                "AES",
                "24a40893b2740f1a0edf2439d0cf81df219ba8da558b765328eadc5ac36f91b6",
                "9cc772015dd82d16a79167d1b5804b62caf7a39dda0aa20c070ac298cac8b893",
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
                "915f6142737bc1e942ac95bb09bb87d7b4e4f86f39adc4a197fc0c79ab073c33",
                "251e9d9ec3f9c6e84a0ef44a20f3c0fb835cf55e51e9dab38d38e16aeafa8dbb",
            ),
            (
                "Serpent",
                "12acae3b21808d1cc477c710703b373aae590fc057f6edb489556b08e5e66e8d",
                "8d4daed4a55cdc64694fcc457a7888079c572e1c7dc1f4eb629c2c6616c98518",
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
                "d93ae7120b0c87cb1b032ca002e0fc844d4612b2750b49addb664e01057d9e93",
                "802a9d4fbecfbb50b3cd5f6c9cd82f9a909f6560b57787674c0fd4296c4492eb",
            ),
            (
                "Twofish",
                "52c4a0fb589e7a1794a94048a6a9a93f6469d463bba8171362cf3e5d78cd0a5f",
                "7c58f599613bb617e2861f6166530c584b2e119adb13ae704a1f8af70cca7806",
            ),
            (
                "AES",
                "2ad42503c2b49bf97aad7ee0765df4ddb17b85fa47f56820efdcb6092957e159",
                "36491eafa56b1940cd08ef622fb7dd8f0f2352cae43803426a55b2375c24981c",
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
                "4c85cfc64a06defe0d4433c4ba80adc9635529264035af8b67916a78648800f8",
                "3dcf16d266eeab5254de9b42fd9949142ff7283054202b810c1eb5e19960ffc5",
            ),
            (
                "Twofish",
                "9632406c7b7c369cdf2b605bbd6a3223ad8583c9413e2aa83e1342741b57cc9b",
                "777fe10ea35f2ac252963dec3c26909cd7f0854b7e70fc282d315daa2599c0a7",
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
                "799633093a6b5c2bee1f84a96bff2cd79415641f21db6b2b808ebe6e1ddbf520",
                "7dc207610dfffdd95a9d2cf02a66741aac7c0fcc11430df4a381b5da8ab835b9",
            ),
            (
                "Twofish",
                "f6d746670a1294c2f55df3031eba872259eaad60046f65122f950d919fb3e922",
                "0476d53df22640b23ff27a0abce9571a4a4313e8b1824b9ba95dc5986c9a0ea7",
            ),
            (
                "Serpent",
                "38620ce433b775a77a4097f74787628aff56b1a81c38ca21d9d6931d182a61b0",
                "c4ceed12fea6c5ead29c48ef6bdc86efd8aaf6acd734866db7ddb92270543843",
            ),
        ],
    ),
    (
        "h.hc",
        "AES",
        1,
        &[(
            "AES",
            "fdce0446ed141033cfc82902413127374603d9c99398359fecc3ce20fe1c02da",
            "ce46fd3f06dd3a7cba7a737cf477386e5dbf0c320893a76ccb4cf02958289b67",
        )],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_8_volumes_is_found_on_veracrypt_10e_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!(
            "skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_10e/mem.raw"
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
            "TrueCrypt 6.0 to 7.2 and VeraCrypt 1.0e (observed on TrueCrypt 6.0, 6.0a, 6.1, 6.1a, 6.2, 6.2a, 6.3, 6.3a, 7.0, 7.0a, 7.1, 7.1a, 7.2 and VeraCrypt 1.0e)"
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
