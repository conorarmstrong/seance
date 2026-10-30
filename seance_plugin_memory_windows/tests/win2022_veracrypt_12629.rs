//! VeraCrypt **1.26.29** in memory on **Windows Server 2022** (`MEM-044`, a second OS build): the Server 2022 Standard Evaluation lab
//! disk (`forensic_corpora/lab_s2022_eval`, kernel 10.0.20348.587, `ntkrnlmp.pdb` GUID `D801A9AFC0FB7761380800F708633DEA`, age 1) booted under
//! QEMU/KVM with 4 GiB of RAM, VeraCrypt 1.26.29 installed from `VeraCrypt_Setup_x64_1.26.29.msi` (SHA-256 `5ba64269...`, equal to the release's
//! list), and seven volumes created by `VeraCrypt Format.exe /create` and mounted together as `P:` to `V:`: `a.hc` Serpent, `b.hc` Twofish,
//! `c.hc` Camellia, `d.hc` Kuznyechik, `e.hc` AES(Twofish), `f.hc` Serpent(AES) and `g.hc` Kuznyechik(Twofish) (SHA-512 / NTFS, passwords
//! `SeanceVC-S22-A` to `SeanceVC-S22-G`). The ground truth is independent of this crate: each header was decrypted on the host with
//! `scripts/oracle/vc_header_keys_all.py`. Every earlier VeraCrypt capture is a Windows 11 build 26200 guest; this one is a different kernel
//! (build 20348, Windows Server 2022).
//!
//! The 4 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_s2022_vc/mem.raw` or name it with
//! `SEANCE_S22_VC12629_MEMORY`. Its symbol file is `ntkrnlmp.pdb/D801A9AFC0FB7761380800F708633DEA-1.json.xz`, made with Volatility's
//! `pdbconv` from Microsoft's PDB and placed in `reference/volatility3/volatility3/symbols/windows/`. Release only.

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
    let p = match std::env::var("SEANCE_S22_VC12629_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => {
            PathBuf::from(std::env::var("HOME").ok()?).join("forensic_corpora/lab_s2022_vc/mem.raw")
        }
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
            "299a67d52e5e30e9072851daa39a44f7a2229c108f315ae24fba9d9b1c8e36f5",
            "34e7c170c44c1e7cc996238789f8ee6610a119d2eb36eefb9e3c60f4e9b9d25b",
        )],
    ),
    (
        "b.hc",
        "Twofish",
        3,
        &[(
            "Twofish",
            "4e94155bdcc091db399ab712433023e5a43121f8caa8dd465a292df8767a45c9",
            "d573ad45f10aeeb7f9459e4824eb014bb686a541de2269b2365f2fae9dacf3c2",
        )],
    ),
    (
        "c.hc",
        "Camellia",
        4,
        &[(
            "Camellia",
            "b2cdc673bb0c2d7a328ceec9a2fcfa06bbd12a847a73fa4d08af704163c1041b",
            "d3c6aa975816e9cd8b923c84a99709d05b65de13eeb69c58b9dd018b0164798d",
        )],
    ),
    (
        "d.hc",
        "Kuznyechik",
        5,
        &[(
            "Kuznyechik",
            "cfc3091071b38da2c742ee141c9f5e5ee08c8840db1d8867f4ea26853e5b037d",
            "9c22c560458bf850f49609da48134dc7d499b3950cf7fc7732920d68f9f103d0",
        )],
    ),
    (
        "e.hc",
        "AES-Twofish",
        6,
        &[
            (
                "Twofish",
                "be2651004d279bf136bcdfcea7e3d3aa14de02232202c415da268f5ea8603a7b",
                "e68fcab049e6c76d7ce4d2c5e3729afb870c9eca34dbace1e0b0ccafca3ab55e",
            ),
            (
                "AES",
                "f027d531e67238e463756fcd22e9a16d1a396859a06cfc8fbd0ba35439b7474f",
                "53e2b09a08f61e4248304fb80d4f13596c7ca0b30c919288230e818da83f9544",
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
                "35bce1ec641a2b95f226b4ded9733483c262f1ff0a1375bd477a1029782c7b5f",
                "684a6089772a071bfdd1bf21ab00a21f96ba86177dc1bc19e699590f01344106",
            ),
            (
                "Serpent",
                "b71bcfc818d1ab1336ef514170016dc17b717a5e4551cc703e9e7277cc82115d",
                "bc6dbcf5b3662e4efaa15ad09a9ae1c430db3dfcc4026b49dc5ebedd3b230f85",
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
                "e2271d642c07f72d21bf74462bb3e563a7e1230a59aa9f8d4e82b1ecd33f488e",
                "8ac0b90671a35a35eb4ac9193bb97c6d5e4a9626c9263470b82bda9c5ddf9f1a",
            ),
            (
                "Kuznyechik",
                "d89d68f91f2347bb383a24a259b6b0dfe2f1054772a3acb7abf152b7a4030cd4",
                "cb4b00a091c59a4ccc0bfbe8bbf1dc270f1ffd51b1df2644eabccaf476078000",
            ),
        ],
    ),
];

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_key_of_seven_volumes_is_found_on_s2022_veracrypt_12629_and_each_container_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the capture at ~/forensic_corpora/lab_s2022_vc/mem.raw");
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
    // On this kernel the map names the region holding every loader entry (non-paged allocations, tag `MmLd`)
    // `MiVaPagedPool`, and the capture's key schedules lie in it; the labelled `MiVaNonPagedPool` region holds
    // none of them.
    let (chosen, basis) = pool_sweep_region(&map.regions, &entries).expect("a pool region");
    assert_eq!(basis, PoolRegionBasis::LoaderEntries);
    assert_eq!(chosen.type_name.as_deref(), Some("MiVaPagedPool"));
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
