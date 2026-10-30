//! VeraCrypt **1.26.18** in memory on **Windows Server 2022** build 20348.587 (`MEM-044`): a fresh copy of the Server 2022 lab disk
//! (`forensic_corpora/lab_s2022_eval`) with VeraCrypt 1.26.18 installed from its signed MSI (the detached signature verifies against the
//! VeraCrypt Team key 5069A233...) and seven volumes created by `VeraCrypt Format.exe /create` and mounted together as `P:` to `V:`:
//! `a.hc` Serpent, `b.hc` Twofish, `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES), `g.hc`
//! Kuznyechik(Twofish) (SHA-512 / NTFS, passwords `SeanceVC-S22-12618-A` to `-G`). The ground truth is independent of this crate: each header was
//! decrypted on the host with `scripts/oracle/vc_header_keys_all.py`. See `win2022_veracrypt_12629.rs` for the host and the pool region.
//!
//! The 4 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_s2022_vc/run_12618/mem.raw` or name it with
//! `SEANCE_S22_VC12618_MEMORY`. Release only.

use std::path::PathBuf;
use std::sync::Arc;

use seance_core::data_source::DataSource;
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_windows::automagic::{self, DiscoveryOptions};
use seance_plugin_memory_windows::modules::{list_kernel_modules, ModuleSymbols, ModuleWalkConfig};
use seance_plugin_memory_windows::truecrypt::*;
use seance_plugin_memory_windows::virtual_map::{
    pool_sweep_region, survey_virtual_map, PoolRegionBasis, VirtualMapSymbols,
};

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
    let p = match std::env::var("SEANCE_S22_VC12618_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_s2022_vc/run_12618/mem.raw"),
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
            "21a0059b1129fe35ab53ad761809fbf99709c797fac7cb480d1b63ee01f9d4d1",
            "1316309434e1497f69d248495f0ea2c93be94734161c87efee936567b0fab994",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "7f977e595dc7cd0f29ca9810129883ac28c59ae0a9cb3a6badba6ae957076b2c",
            "23c7f408d974e804ee2b19731937ec753fe269c6469afcb697a3b9c81184add3",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "5131b0f62a6d032dc1e6cef016ddb97f0d50dcb1333cd496013eb9dd92cfbad3",
            "895a6ed45b22b240a1d7e67a524ac566bed9bf7e49f4a050bbf874b4ec49fc6e",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        5,
        &[(
            "Kuznyechik",
            "a15d708f3f3d8ac335600231b0f1320b06756d7d9cefc547ae793a51356c4a38",
            "bf5e6975c4968202f52cd10054a3cc8508ce46a410f499f0c8f60f04305d400d",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        6,
        &[
            (
                "Twofish",
                "6fb39c34344080953584032efefa6d65f1277e134f3c11485940abf20b211787",
                "9055c20cca9df5c40e5c2e5f3db527b8e9a93e38da945edd25c0649f9fc5016e",
            ),
            (
                "AES",
                "12582e511ec1904c7a9c8dca47b982e2abe945248059b95721203ed8a3ecc171",
                "ec31efc9ea63008ae329089313162d11c306d027ccffa6b97103e964bf36ae12",
            ),
        ],
    ),
    (
        "f.hc",
        "Serpent-AES",
        8,
        &[
            (
                "AES",
                "f9a8116a759c7b7c2c34c1a0456bcad73245cd6c1aa204c093781b1b7a7c0f59",
                "a87b9bcdc306e6d4bb24b881f3f45e85e2bd079eb5d694e9d0f73ac218ca076f",
            ),
            (
                "Serpent",
                "234d40a54d3e94ce45575c2a346fed5fd50fc6313589007e451dbda4ac100608",
                "1638ac6f4b7149989b51d3466df980f76ae85f1a29ca68e92c0e10f97b116c01",
            ),
        ],
    ),
    (
        "g.hc",
        "Kuznyechik-Twofish",
        12,
        &[
            (
                "Twofish",
                "42350738c4d7670ca687f26024b7d58458b6a1d818108933cddc122aa87f35fb",
                "899c878eac2cddde848aff1567ee0a80fba10c6535c268ad5cc563e850b201cf",
            ),
            (
                "Kuznyechik",
                "d0585fe3a569906e9015835fdb1363ef58068e331870fbef294782991fa5d42c",
                "d92fdaa90e9ead16338a783391679d61a7edb14b2ca4b09dcab94fc33f74c2c1",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_s2022_veracrypt_12618_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_s2022_vc/run_12618/mem.raw");
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
    let entries: Vec<u64> = kernel.modules.iter().map(|m| m.entry).collect();
    // On this kernel the map's names do not follow the allocations (the region holding the loader entries is
    // named differently on each boot); the key schedules lie where the loader entries do.
    let (chosen, basis) = pool_sweep_region(&map.regions, &entries).expect("a pool region");
    assert_eq!(basis, PoolRegionBasis::LoaderEntries);
    let region = Some(SweepRegion {
        layer: Arc::clone(&profile.kernel_space),
        base: chosen.base,
        bytes: chosen.bytes,
        description: "the region holding the loader entries".to_string(),
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
        assert_eq!(info.layout, "VeraCrypt 1.19 to 1.26.24 (observed on 1.19, 1.21, 1.22, 1.23, 1.23-Hotfix-2, 1.24, 1.24-Hotfix1, 1.24-Update2, 1.24-Update4, 1.24-Update5, 1.24-Update6, 1.24-Update7, 1.25, 1.25.4, 1.25.7, 1.25.9, 1.26.7, 1.26.14, 1.26.15, 1.26.18, 1.26.20, 1.26.24, 1.26.28-Beta4)");
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
