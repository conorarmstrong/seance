//! VeraCrypt 1.26.29 in memory (`MEM-044`) with **a Camellia volume, a Kuznyechik volume and five cascades of them mounted
//! together**: the Windows 11 25H2 lab VM of `win11_veracrypt.rs`, with `p1.hc` Camellia, `p2.hc` Kuznyechik, `p3.hc`
//! Camellia(Kuznyechik), `p4.hc` Camellia(Serpent), `p5.hc` Kuznyechik(AES), `p6.hc` Kuznyechik(Serpent(Camellia)) and `p7.hc`
//! Kuznyechik(Twofish) (SHA-512 / NTFS, passwords `SeanceVC-P1-1111` to `SeanceVC-P7-7777`) mounted as `P:` to `V:` when the
//! memory was dumped. The ground truth is independent of this crate: each header was decrypted on the host with
//! `scripts/oracle/vc_header_keys_all.py` (Camellia by `cryptography`, Kuznyechik by `gostcrypto`, both checked against the RFC
//! vectors first), which gave the digests pinned here. The test asks whether the sweep finds every master key by its hash
//! (the Camellia keys are recovered from their `ke` subkeys, the Kuznyechik keys are the round keys' first 32 bytes) and reads
//! each container: the ids on this version are **4, 5, 11, 12, 13, 14, 15**.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_ck/mem.raw` or name it
//! with `SEANCE_WIN11_VCCK_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VCCK_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_ck/mem.raw"),
    };
    p.exists().then_some(p)
}

/// `(volume, cascade name, container id, [(cipher, primary key SHA-256, tweak key SHA-256)])`: the keys as the host
/// oracle read them out of each volume's header. The cipher order is the oracle's, not the buffer's.
#[allow(clippy::type_complexity)]
const VOLUMES: &[(&str, &str, u32, &[(&str, &str, &str)])] = &[
    (
        "p1.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "6461eaa91233f7f0fdec35d023c3a2aa15e9a0fad29f8c639e11b305244265e8",
            "77022133adb27cd67b58be43ba250807be8399c60c00bd722ee6527b9506e939",
        )],
    ),
    (
        "p2.hc",
        "Kuznyechik",
        5,
        &[(
            "Kuznyechik",
            "ad5f50b70eac024a7a6674232af38e807573c4517a54ac29168d05196bef58d8",
            "0823fff634102fc4525c1a20097bc43f0c9f001914f5794ecc37ec1b4ca1bedf",
        )],
    ),
    (
        "p3.hc",
        "Camellia-Kuznyechik",
        11,
        &[
            (
                "Kuznyechik",
                "0e50631a60eccb6c70e46b5af96c757227f80940dfe0db21a090f7a06ea2e320",
                "cac49e90e272d4bce362298e06e072afdc1cf93b8fb212f34ec853336f9b530f",
            ),
            (
                "Camellia",
                "c535178b003bc4b2db9bd182ef7de8de19e2842b9dba5ac05ab9cdd5bc5f37bf",
                "c39d892a7c766e9eac1e0cf38e34e00bedf3854e32a62592a6aef62e7b663167",
            ),
        ],
    ),
    (
        "p4.hc",
        "Camellia-Serpent",
        13,
        &[
            (
                "Serpent",
                "c6d5791b3a7baba6af371005cb19990725ba267a103cabe4ffc7de45d32f9f51",
                "57170f96d18d5d88e8ecefb1e3f8819d56d809c38598b52af045322344477f5d",
            ),
            (
                "Camellia",
                "1ec8b161401e9cb3f4acb52c44ae24b9a4593abf5a5df79e483d4c414b240e91",
                "f047648f14049fff69626b54e46b8b33101ee9a334cf8bda0a48a6460f5b1244",
            ),
        ],
    ),
    (
        "p5.hc",
        "Kuznyechik-AES",
        14,
        &[
            (
                "AES",
                "53d0f46f26e796188026da1089b3688d4e0666e194ee9ae4781406a835ed3dc6",
                "55d4514cd737c6c45b93d7f74a05caa989062def62040b906d7b652d7748966f",
            ),
            (
                "Kuznyechik",
                "d1c0ef79a35bf5499d8eca6b0ba53bb5e0650a9258614b142565dddede6dcf0e",
                "bf021491ee2c70fae00f1caa9073427dfa29eee6f592ef6408f71a1ed96b4283",
            ),
        ],
    ),
    (
        "p6.hc",
        "Kuznyechik-Serpent-Camellia",
        15,
        &[
            (
                "Camellia",
                "0eb49eb0c3751887014f402b27616b405255f1aed7a08a2127c432168ae2992d",
                "9d280df15733362ec0a9c2587442ec8a9a02b5e5991e33b7601c3e89fde904c9",
            ),
            (
                "Serpent",
                "ef645b3ce9a8c0c8aaf71045d0f1f63b59ad546b24fb24697e2e827e4382e251",
                "7af763758fd50b50d400a5d06f60d8b710cb447015186ec6306b8c3d28f55b44",
            ),
            (
                "Kuznyechik",
                "4211e6080b28ceb48e646fe43e906b991ecc6ffd0bc2516cfa48d553f7e15e68",
                "205e0cb79863906bca88b38a93ef3bbcb00098fdfeb5826fdeba09f5413c9f38",
            ),
        ],
    ),
    (
        "p7.hc",
        "Kuznyechik-Twofish",
        12,
        &[
            (
                "Twofish",
                "3ce169ebcdcb001b0311c1b7546297729331e367afbf7ed0b8c1e361d29b0938",
                "9987f4f2ff8caf30bf6bc5d52eb48c281dca19805879a8e42794af3174a327f0",
            ),
            (
                "Kuznyechik",
                "d982e526f085e941ce4298a27734910bf7eaeb9dce5bc80c54d1c7efb77e9175",
                "e7c529a19d59afc5826234174c1bddf9656e1a9524a67889e70177cca4934420",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn camellia_kuznyechik_and_five_cascades_are_found_with_every_key_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_win11_veracrypt_ck/mem.raw");
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
