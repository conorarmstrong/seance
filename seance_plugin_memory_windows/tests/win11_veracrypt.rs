//! VeraCrypt in memory (`ROADMAP` §5.3, `MEM-044`) graded against a **known
//! answer**: a Windows 11 build 26200 capture taken from the corpus VM while a
//! VeraCrypt 1.26.29 volume (AES, SHA-512, NTFS, 20 MiB, password recorded in
//! `~/win11-lab/vc/GROUND-TRUTH.txt`) was mounted as `X:`.
//!
//! The ground truth is independent of this crate: the container's header was
//! decrypted on the host with PBKDF2-HMAC-SHA512 and AES-256-XTS from the
//! password (the decrypted header reads `VERA`), which yields the two 32-byte
//! master keys; their SHA-256 digests are pinned below. The test asks whether
//! the sweep reports schedules whose key digests equal them.
//!
//! The 10 GiB capture is not in the repository. Put it at
//! `~/win11-lab/vc/mem.raw` or name it with `SEANCE_WIN11_VC_MEMORY`.

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
    let p = match std::env::var("SEANCE_WIN11_VC_MEMORY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").ok()?).join("win11-lab/vc/mem.raw"),
    };
    p.exists().then_some(p)
}

/// SHA-256 of the two master keys decrypted from the container header.
const PRIMARY_SHA256: &str = "6c8dea88b211aa5df4d5792c037207e38e9e2ba25925186206f47d5e11093a39";
const SECONDARY_SHA256: &str = "76e4cb197f4a686c7954734fc8ed940843aa2e69eaf8e9cebbe1fd8a42a02a7e";

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_mounted_veracrypt_volumes_master_keys_are_found_on_the_known_answer_capture() {
    let Some(path) = capture() else {
        eprintln!("skipping: put the VeraCrypt capture at ~/win11-lab/vc/mem.raw");
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
    eprintln!("{}", serde_json::to_string_pretty(&out.to_json()).unwrap());
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
    assert!(
        hashes.contains(&PRIMARY_SHA256),
        "primary master key not reported: {hashes:?}"
    );
    assert!(
        hashes.contains(&SECONDARY_SHA256),
        "secondary master key not reported: {hashes:?}"
    );
    // The two master keys sit 5,312 bytes apart and are reported as a possible pair.
    let at = |h: &str| {
        sweep
            .schedules
            .iter()
            .find(|s| s.key_sha256 == h)
            .unwrap()
            .address
    };
    assert!(
        sweep
            .possible_xts_pairs
            .contains(&(at(PRIMARY_SHA256), at(SECONDARY_SHA256))),
        "{:?}",
        sweep.possible_xts_pairs
    );
    // The container read around the pair names AES, XTS and the keys in the
    // order the header decrypts to (primary || secondary). The layout was
    // derived from this capture, so this grades one version, one cipher.
    let infos: Vec<_> = sweep
        .crypto_infos
        .iter()
        .filter(|c| c.primary_schedule == at(PRIMARY_SHA256))
        .collect();
    assert_eq!(infos.len(), 1, "{:?}", sweep.crypto_infos);
    let info = infos[0];
    assert_eq!(info.secondary_schedule, at(SECONDARY_SHA256));
    assert_eq!(info.cipher, Some("AES"));
    assert_eq!(info.mode, Some("XTS"));
    assert_eq!(info.address, at(PRIMARY_SHA256) - 0x10);
    assert_eq!(
        info.layout,
        "VeraCrypt 1.26.29 to 1.26.30 (observed on 1.26.29, 1.26.30)"
    );
    // The same pool holds other AES-256 schedules (the VM's BitLocker keys); none is claimed as VeraCrypt's.
    assert!(sweep.schedules.len() > 2);
}
