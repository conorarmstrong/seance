//! VeraCrypt in memory (`MEM-044`) on a **second version and two volumes at once**: a Windows 11 25H2 capture from
//! the Séance corpus VM with VeraCrypt **1.25.9** installed (MSI, SHA-256 checked against the release's
//! `veracrypt-1.25.9-sha256sum.txt`) and two AES / SHA-512 / NTFS volumes, `a.hc` (password `SeanceVC-A-4417`) and `b.hc`
//! (`SeanceVC-B-9082`), mounted as `X:` and `Y:` when the memory was dumped (QMP `dump-guest-memory`, ELF, converted with
//! `elf2raw.py`). The ground truth is independent of this crate: each header was decrypted on the host
//! (`scripts/oracle/vc_header_keys.py`: PBKDF2-HMAC-SHA512, AES-256-XTS, `VERA` magic and the master-key area's CRC-32), which
//! reproduced the pinned digests of the 1.26.29 volume first. The test asks whether the sweep reports schedules whose key
//! digests equal them, and what the container read around them says.
//!
//! The 10 GiB capture is not in the repository. Put it at `~/forensic_corpora/lab_win11_veracrypt_1259/mem.raw` or name it with
//! `SEANCE_WIN11_VC1259_MEMORY`. Release only.

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
    let p = match std::env::var("SEANCE_WIN11_VC1259_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?)
            .join("forensic_corpora/lab_win11_veracrypt_1259/mem.raw"),
    };
    p.exists().then_some(p)
}

/// SHA-256 of the master keys decrypted from `a.hc` and `b.hc`.
const A_PRIMARY: &str = "7e6ad35afe354a40cfc956c4b89eb4c9944bed6e859b12bb2eb80a88922a4bd2";
const A_SECONDARY: &str = "255916388df3858823ab7a2c03047c9249b02d3e5822b961b683b095a98fdb30";
const B_PRIMARY: &str = "8b47b7bea80f64d332a95bb59670367f8da4e7bd1e864d390be709e7ce65c081";
const B_SECONDARY: &str = "101dc8d8da26257ef9c672bd6b1405deb24d62c657c2ea379ec5441446720703";

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn both_volumes_of_a_second_veracrypt_version_are_found_and_their_containers_read() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the VeraCrypt 1.25.9 capture at ~/forensic_corpora/lab_win11_veracrypt_1259/mem.raw");
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
    let at = |h: &str| {
        sweep
            .schedules
            .iter()
            .find(|s| s.key_sha256 == h)
            .unwrap_or_else(|| panic!("master key {h} not reported"))
            .address
    };
    for (primary, secondary, volume) in [
        (A_PRIMARY, A_SECONDARY, "a.hc"),
        (B_PRIMARY, B_SECONDARY, "b.hc"),
    ] {
        let (p, s) = (at(primary), at(secondary));
        assert!(
            sweep.possible_xts_pairs.contains(&(p, s)),
            "{volume}: {:?}",
            sweep.possible_xts_pairs
        );
        let infos: Vec<_> = sweep
            .crypto_infos
            .iter()
            .filter(|c| c.primary_schedule == p)
            .collect();
        assert_eq!(infos.len(), 1, "{volume}: {:?}", sweep.crypto_infos);
        let info = infos[0];
        assert_eq!(info.secondary_schedule, s, "{volume}");
        assert_eq!(info.cipher, Some("AES"), "{volume}");
        assert_eq!(info.mode, Some("XTS"), "{volume}");
        // This version lays the container out differently from 1.26.29: the schedule sits 0x0c from
        // its start and the pair 5,304 bytes apart, and the container says which layout it matched.
        assert_eq!(info.address, p - 0x0c, "{volume}");
        assert_eq!(s - p, 5304, "{volume}");
        assert_eq!(
            info.layout, "VeraCrypt 1.19 to 1.26.24 (observed on 1.19, 1.21, 1.22, 1.23, 1.23-Hotfix-2, 1.24, 1.24-Hotfix1, 1.24-Update2, 1.24-Update4, 1.24-Update5, 1.24-Update6, 1.24-Update7, 1.25, 1.25.4, 1.25.7, 1.25.9, 1.26.7, 1.26.14, 1.26.15, 1.26.18, 1.26.20, 1.26.24, 1.26.28-Beta4)",
            "{volume}"
        );
    }
}
