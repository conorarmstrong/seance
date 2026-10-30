//! Analysis of the Windows 11 25H2 memory capture built for this repo.
//!
//! The capture is guest RAM taken from the corpus VM **while its BitLocker
//! volume was unlocked**, so it holds what a live Windows machine holds: the
//! process list, the handle table, mapped files, registry hives in memory and
//! the volume's own metadata objects.
//!
//! Ground truth is known exactly, which is what makes it worth asserting on.
//! The machine is `FORENSIC-W11`, its interactive user is `analyst`, and at
//! capture time `msedge.exe`, `powershell.exe` and OpenSSH's `sshd.exe` were
//! running — because the session that built this corpus drove them.
//!
//! # Provisioning
//!
//! Put `memory-unlocked.raw` in `test_data/win11_bitlocker/` (or point
//! `SEANCE_WIN11_MEMORY` at it), and the matching ISF in
//! `test_data/win11_bitlocker/symbols/ntkrnlmp.pdb/` (or `SEANCE_SYMBOL_DIRS`).
//! The ISF is generated from Microsoft's own PDB for this kernel:
//!
//! ```text
//! curl -o ntkrnlmp.pdb https://msdl.microsoft.com/download/symbols/\
//!   ntkrnlmp.pdb/E6426A07C26E66F8EB8594621A7B273B1/ntkrnlmp.pdb
//! python3 -m volatility3.framework.symbols.windows.pdbconv \
//!   -f ntkrnlmp.pdb -o E6426A07C26E66F8EB8594621A7B273B-1.json
//! ```
//!
//! # Why these are release-only
//!
//! Reading a 10 GiB capture through the page tables is arithmetic-bound, and an
//! unoptimised build makes it minutes per stage — enough that a plain
//! `cargo test --workspace` stops being something anyone runs. They are marked
//! ignored in debug and run under `--release`, which reports them as *ignored*
//! rather than passing silently over nothing.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::DataSource;
use seance_core::module::ForensicsModule;
use seance_memory::analysis::MemoryAnalysisModule;
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_windows::automagic::{self, DiscoveryOptions};
use seance_plugin_memory_windows::WindowsMemoryAnalysis;

fn capture_path() -> Option<PathBuf> {
    let p = if let Ok(p) = std::env::var("SEANCE_WIN11_MEMORY") {
        PathBuf::from(p)
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()?
            .join("test_data/win11_bitlocker/memory-unlocked.raw")
    };
    p.exists().then_some(p)
}

/// A real PAGEDU64 crash dump of this machine, from `SEANCE_WIN_CRASHDUMP`.
fn crashdump_path() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var("SEANCE_WIN_CRASHDUMP").ok()?);
    p.exists().then_some(p)
}

fn symbol_dirs() -> Vec<PathBuf> {
    if let Ok(list) = std::env::var("SEANCE_SYMBOL_DIRS") {
        let dirs: Vec<PathBuf> = list
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
        if !dirs.is_empty() {
            return dirs;
        }
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate sits under the workspace root")
        .to_path_buf();
    vec![
        root.join("test_data/win11_bitlocker/symbols"),
        root.join("reference/volatility3/volatility3/symbols"),
    ]
}

/// The analysis, run once for the whole binary.
///
/// Every test below wants the same output of the same expensive pass. Running
/// it per test meant re-reading 10 GiB through the page tables each time.
static ANALYSIS: OnceLock<Option<Vec<Artifact>>> = OnceLock::new();

fn analysis() -> Option<&'static Vec<Artifact>> {
    ANALYSIS
        .get_or_init(|| {
            let path = capture_path()?;
            let source: Arc<dyn DataSource> =
                Arc::new(seance_core::data_source::FileDataSource::new(path).ok()?);
            let image = Artifact::new(
                uuid::Uuid::new_v4(),
                ArtifactType::ParsedRecord,
                Some(source),
                serde_json::json!({"type": "MemoryImage", "image_format": "raw"}),
            );
            MemoryAnalysisModule::new(WindowsMemoryAnalysis::new().with_symbol_dirs(symbol_dirs()))
                .process(&image)
                .ok()
        })
        .as_ref()
}

macro_rules! require_capture {
    () => {
        match analysis() {
            Some(a) => a,
            None => {
                eprintln!(
                    "skipping: put memory-unlocked.raw and its ISF in \
                     test_data/win11_bitlocker/"
                );
                return;
            }
        }
    };
}

/// **Discovery on a build newer than any other capture in this corpus.**
///
/// A raw capture says nothing about itself. The directory table base, the
/// kernel load address and the kernel's PDB identity all have to be recovered
/// from the bytes before any analysis is possible, and none of that depends on
/// having symbols. Failing here would mean this build cannot read a Windows 11
/// 26200 capture at all.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_win11_capture_is_discovered_from_its_bytes() {
    let Some(path) = capture_path() else {
        eprintln!("skipping: capture not present");
        return;
    };
    let source: Arc<dyn DataSource> =
        Arc::new(seance_core::data_source::FileDataSource::new(path).expect("open"));
    let physical: Arc<dyn MemoryLayer> =
        Arc::new(PhysicalLayer::raw(source).expect("a raw image is a physical layer"));

    let profile = automagic::discover(physical, &symbol_dirs(), &DiscoveryOptions::default())
        .expect("discovery must succeed on this capture");

    assert_eq!(
        profile.build.guid, "E6426A07C26E66F8EB8594621A7B273B",
        "the kernel's CodeView identity must be read from the image itself"
    );
    assert_eq!(
        profile.build.build,
        Some(26200),
        "the build number comes from KUSER_SHARED_DATA, not the build-lab \
         string, which on this image says 26100 and is wrong"
    );
    // `Found<T>` pairs each fact with how it was established, so assert the
    // value and the grade. A directory table base that was merely *supplied*
    // would carry the same number and mean something much weaker.
    assert!(
        profile.dtb.value != 0,
        "a directory table base must be recovered"
    );
    assert!(
        profile.kernel_base.value > 0xffff_0000_0000_0000,
        "the kernel must be found in kernel space, got {:#x}",
        profile.kernel_base.value
    );
    assert!(
        profile.dtb.evidence <= seance_memory::binding::evidence::Evidence::Scanned,
        "the DTB must be established by evidence no weaker than a scan, got {:?}",
        profile.dtb.evidence
    );
}

/// The PAGEDU64 crash dump decodes to an address space whose page tables walk to
/// the SAME Windows kernel the raw capture of this machine found (MEM-004).
///
/// This is the cross-check the finding asked for: not merely that the header
/// parses, but that the decoded run table yields a physical space in which
/// discovery recovers a real directory-table-base, the kernel in kernel space,
/// and the exact build GUID the raw capture read — all from the crash dump's own
/// bytes. A run-table or bitmap-geometry bug would misplace physical pages and
/// discovery would fail or recover a different kernel.
///
/// The dump is a genuine acquisition — a `MANUALLY_INITIATED_CRASH (0xE2)`
/// kernel dump from the corpus VM — provided out of band via
/// `SEANCE_WIN_CRASHDUMP` (it is hundreds of MiB and not in the repo).
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_crash_dump_decodes_to_the_same_kernel_the_raw_capture_found() {
    let Some(path) = crashdump_path() else {
        eprintln!("skipping: set SEANCE_WIN_CRASHDUMP to a PAGEDU64 crash dump");
        return;
    };
    let source: Arc<dyn DataSource> =
        Arc::new(seance_core::data_source::FileDataSource::new(path).expect("open crash dump"));
    let layer =
        seance_memory::formats::crash::open(Arc::clone(&source)).expect("decode the PAGEDU64 dump");
    let physical: Arc<dyn MemoryLayer> = Arc::new(layer);

    let profile = automagic::discover(physical, &symbol_dirs(), &DiscoveryOptions::default())
        .expect("discovery must succeed on the decoded crash dump");

    assert_eq!(
        profile.build.guid, "E6426A07C26E66F8EB8594621A7B273B",
        "the crash dump is the same build as the raw capture; its GUID must be \
         read back from the decoded address space, not a different or empty one"
    );
    assert!(
        profile.dtb.value != 0,
        "a directory table base must be recovered from the crash dump"
    );
    assert!(
        profile.kernel_base.value > 0xffff_0000_0000_0000,
        "the kernel must be found in kernel space, got {:#x}",
        profile.kernel_base.value
    );
    assert!(
        profile.dtb.evidence <= seance_memory::binding::evidence::Evidence::Scanned,
        "the DTB must be established by evidence no weaker than a scan, got {:?}",
        profile.dtb.evidence
    );
}

/// A real Windows hibernation file (`hiberfil.sys`) from `SEANCE_WIN_HIBERFIL`.
fn hiberfil_path() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var("SEANCE_WIN_HIBERFIL").ok()?);
    p.exists().then_some(p)
}

/// Occurrences of `"HIBRMARK"` in the reconstructed Windows 11 26200 corpus
/// hibernation file, measured 2026-09-19 with the match ceiling raised. A
/// string count, not a page count: 2 × 65,536 marker pages + 38 occurrences
/// inside other pages (33 of them the marker script's own source text). The
/// accounting is asserted page by page in
/// `seance_memory/tests/hibernation_corpus_test.rs`; see
/// `an_examiners_rules_search_a_reconstructed_hibernation_file`.
const MARKER_STRINGS_IN_THE_RECONSTRUCTION: u64 = 131_110;

/// **A hibernation file reconstructs to a coherent kernel.**
///
/// The reconstruction walks the restore sets, decompresses each Xpress block,
/// and places every recovered page at its physical address. If any of that is
/// wrong the pages land in the wrong places and discovery finds no kernel; that
/// discovery recovers a directory-table-base, the kernel in kernel space, and a
/// non-empty build GUID from the reconstructed image is the page-map's
/// end-to-end proof — the same standard the crash-dump path is held to. Gated on
/// `SEANCE_WIN_HIBERFIL` (the file is several GiB and not in the repo).
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn a_hibernation_file_reconstructs_to_a_coherent_kernel() {
    let Some(path) = hiberfil_path() else {
        eprintln!("skipping: set SEANCE_WIN_HIBERFIL to a hiberfil.sys");
        return;
    };
    let source: Arc<dyn DataSource> =
        Arc::new(seance_core::data_source::FileDataSource::new(path).expect("open hiberfil"));
    let layer = seance_memory::formats::hibernation::open(Arc::clone(&source))
        .expect("reconstruct hiberfil");
    let physical: Arc<dyn MemoryLayer> = Arc::new(layer);

    let profile = automagic::discover(physical, &symbol_dirs(), &DiscoveryOptions::default())
        .expect("discovery must succeed on the reconstructed hibernation image");

    assert!(
        profile.dtb.value != 0,
        "a directory table base must be recovered from the hibernation image"
    );
    assert!(
        profile.kernel_base.value > 0xffff_0000_0000_0000,
        "the kernel must be found in kernel space, got {:#x}",
        profile.kernel_base.value
    );
    assert!(
        !profile.build.guid.is_empty(),
        "a build GUID must be read back from the reconstructed address space"
    );
    eprintln!(
        "hibernation discovery: dtb={:#x} kernel_base={:#x} build={:?} guid={}",
        profile.dtb.value, profile.kernel_base.value, profile.build.build, profile.build.guid
    );
}

/// **Credential recovery: the `analyst` NT hash comes out of memory and matches
/// the known password (MEM-008).**
///
/// The corpus machine's `analyst` account has a password fixed by the build
/// (`Seance!2026`), so the ground truth is exact: recovering the NT hash from the
/// `SYSTEM`+`SAM` hives in the image and comparing it to `MD4(UTF-16LE(password))`
/// proves the boot-key extraction, the hashed-boot-key decryption and the
/// per-account AES+DES unwrap end to end. A wrong boot key or a wrong offset
/// yields 16 bytes that do not match.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_analyst_nt_hash_is_recovered_from_memory_and_matches_the_known_password() {
    use md4::{Digest, Md4};
    use seance_plugin_memory_windows::credential_decrypt::recover_sam_hashes;

    let Some(path) = capture_path() else {
        eprintln!("skipping: capture not present");
        return;
    };
    let source: Arc<dyn DataSource> =
        Arc::new(seance_core::data_source::FileDataSource::new(path).expect("open"));
    let physical: Arc<dyn MemoryLayer> =
        Arc::new(PhysicalLayer::raw(source).expect("a raw image is a physical layer"));
    let profile = automagic::discover(physical, &symbol_dirs(), &DiscoveryOptions::default())
        .expect("discovery must succeed");

    let recovered = recover_sam_hashes(&profile);
    assert!(
        recovered.unavailable.is_none(),
        "credential decryption should run: {:?}",
        recovered.unavailable
    );
    assert!(
        recovered.boot_key.is_some(),
        "the boot key must be recovered from the SYSTEM hive"
    );

    // Ground truth: the build set `analyst`'s password to this.
    let expected: String = {
        let utf16: Vec<u8> = "Seance!2026"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let digest = Md4::digest(&utf16);
        digest.iter().map(|b| format!("{b:02x}")).collect()
    };

    let analyst = recovered
        .credentials
        .iter()
        .find(|c| c.username.eq_ignore_ascii_case("analyst"))
        .expect("the analyst account must be among the recovered credentials");
    eprintln!(
        "recovered analyst rid={} nt_hash={:?} note={:?}",
        analyst.rid, analyst.nt_hash, analyst.note
    );
    assert_eq!(
        analyst.nt_hash.as_deref(),
        Some(expected.as_str()),
        "the recovered NT hash must equal MD4(UTF-16LE(\"Seance!2026\"))"
    );
}

/// The processes that were genuinely running when the capture was taken.
///
/// `sshd.exe` and `powershell.exe` are here because the build session drove the
/// machine over SSH; `msedge.exe` because the browser was run to build the
/// history database. They are facts about the evidence, not about this
/// implementation.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_processes_that_were_running_are_all_recovered() {
    let out = require_capture!();

    let mut procs: BTreeMap<String, usize> = BTreeMap::new();
    for a in out {
        for key in ["process", "process_name", "name", "image_name"] {
            if let Some(v) = a.metadata.get(key).and_then(|v| v.as_str()) {
                // Not only `*.exe`: the System process carries no extension,
                // and filtering on the suffix reported it missing when it was
                // present throughout.
                let lv = v.to_lowercase();
                if lv.ends_with(".exe") || lv == "system" {
                    *procs.entry(lv).or_default() += 1;
                }
            }
        }
    }

    for expected in [
        "system",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "explorer.exe",
        "svchost.exe",
        "sshd.exe",
        "msedge.exe",
    ] {
        assert!(
            procs.contains_key(expected),
            "{expected} was running when this capture was taken and must be \
             recovered; found {} distinct process names",
            procs.len()
        );
    }
}

/// Open file handles must be resolved to object types **and names**.
///
/// A handle table decoded to addresses without types or names is not an answer
/// an examiner can use. The names also corroborate the disk layout: `FVE2.{…}`
/// under System Volume Information are BitLocker's own metadata files.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn open_file_handles_are_resolved_to_types_and_names() {
    let out = require_capture!();

    let mut by_type: BTreeMap<String, usize> = BTreeMap::new();
    let mut named_files = 0usize;
    let mut saw_fve_metadata = false;
    for a in out {
        if a.metadata["record_type"] != "MemoryProcessHandles" {
            continue;
        }
        let Some(rows) = a.metadata["handles"].as_array() else {
            continue;
        };
        for r in rows {
            // `object_type`, not `type`. Reading the wrong key reported every
            // one of 45,463 handles as unknown, which looked like a decoding
            // failure and was a defect in the reader, not the decoder.
            let t = r["object_type"].as_str().unwrap_or("?").to_string();
            if t.eq_ignore_ascii_case("file") {
                if let Some(n) = r["object_name"].as_str() {
                    named_files += 1;
                    if n.contains("FVE2.") {
                        saw_fve_metadata = true;
                    }
                }
            }
            *by_type.entry(t).or_default() += 1;
        }
    }

    assert!(
        by_type.len() > 5,
        "handles must be resolved to several distinct object types, got {by_type:?}"
    );
    assert_eq!(
        by_type.get("?").copied().unwrap_or(0),
        0,
        "no handle should be left with an unresolved object type"
    );
    assert!(
        named_files > 500,
        "a live Windows machine holds thousands of open file handles; only \
         {named_files} were resolved to a name"
    );
    assert!(
        saw_fve_metadata,
        "this machine's volume was BitLocker-protected and mounted, so its \
         FVE2 metadata files must appear among the open handles"
    );
}

/// Files recoverable out of memory, which is much of the reason to take a
/// capture at all when the disk is encrypted.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn file_content_is_recoverable_from_memory() {
    let out = require_capture!();

    let names: Vec<String> = out
        .iter()
        .filter(|a| a.metadata["record_type"] == "MemoryRecoveredFile")
        .filter_map(|a| {
            a.metadata["name"]
                .as_str()
                .or_else(|| a.metadata["path"].as_str())
        })
        .map(|s| s.to_string())
        .collect();

    assert!(
        names.len() > 1000,
        "a live Windows capture holds thousands of recoverable files; got {}",
        names.len()
    );
    // NTFS metafiles resident in memory: proof this reaches real cached
    // filesystem structure rather than only loose strings.
    assert!(
        names
            .iter()
            .any(|n| n.contains("$LogFile") || n.contains("$Directory")),
        "NTFS metadata files should be recoverable from the cache"
    );
}

/// The credentials stage must inventory accounts **and refuse to overstate
/// what it did**.
///
/// Locating credential material is not recovering it. This stage finds the
/// accounts and says plainly that nothing was decrypted, which is the
/// difference between a usable finding and a misleading one.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_credentials_stage_inventories_accounts_without_claiming_to_crack_them() {
    let out = require_capture!();

    let rec = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemoryCredentials")
        .expect("the credentials stage must produce a record");

    let accounts: Vec<&str> = rec.metadata["accounts"]
        .as_array()
        .map(|v| v.iter().filter_map(|a| a["name"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        accounts.contains(&"analyst"),
        "the machine's interactive user must be inventoried; got {accounts:?}"
    );
    assert!(
        accounts.contains(&"Administrator"),
        "the built-in Administrator must be inventoried; got {accounts:?}"
    );

    assert_eq!(
        rec.metadata["content_incomplete"], true,
        "nothing was decrypted, so the record must not read as complete"
    );
    let reason = rec.metadata["content_incomplete_reason"]
        .as_str()
        .unwrap_or_default();
    assert!(
        reason.contains("not decrypted"),
        "the record must state plainly that no secret was recovered; got {reason:?}"
    );
}

/// The Windows services list is recovered from the real capture by walking the
/// Service Control Manager's list head — the `Sc27`-tagged `_SERVICE_HEADER`
/// chain inside `services.exe`. This is the residual real-image validation
/// MEM-012 asks for: the stray-head / short-magic risk it names can only be
/// settled by proving the walk reaches the SCM's real, still-linked service set
/// on a genuine build (here Windows 11 26200), not a synthetic fixture.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_services_list_is_recovered_by_walking_the_control_managers_list_head() {
    let out = require_capture!();

    let rec = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemoryServices")
        .expect("the services stage must produce a record");

    // The record superimposes the sweep (top level) with the SCM chain walk under
    // `chain` (or the reason under `chain_unavailable`), and the diff between
    // them. MEM-012 is about the chain walk — reaching the SCM's list head via
    // its `Sc27`-tagged `_SERVICE_HEADER` and following the record chain.
    let chain = &rec.metadata["chain"];
    let chain_unavailable = rec.metadata["chain_unavailable"].as_str();
    assert!(
        chain.is_object(),
        "the SCM chain walk (Sc27 list head) must succeed on this real Windows 11 \
         26200 build, but it was unavailable: {chain_unavailable:?}"
    );

    assert_eq!(
        chain["method"].as_str(),
        Some("listed"),
        "the chain must be reached by the list-head walk, not the sweep"
    );
    let chain_count = chain["count"].as_u64().unwrap_or(0);
    assert!(
        chain_count > 100,
        "a live Windows 11 machine links well over a hundred services; the \
         Sc27 list-head walk reached only {chain_count}"
    );

    // A Field-JSON value renders as `{kind:"known", value:"..."}` (or a bare
    // string / an `unavailable` object otherwise).
    fn field_str(v: &serde_json::Value) -> Option<String> {
        if v.get("kind").and_then(|k| k.as_str()) == Some("known") {
            return v.get("value").and_then(|x| x.as_str()).map(String::from);
        }
        v.as_str().map(String::from)
    }
    let names: std::collections::BTreeSet<String> = chain["services"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|s| field_str(&s["name"]))
                .map(|n| n.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();

    // Core services that run on every Windows 11 machine. If the walk had latched
    // onto a stray `Sc27` and followed garbage, it would not reach the SCM's
    // real, well-known set — so requiring most of these present is what turns
    // "the walk returned records" into "the walk returned the RIGHT records".
    let expected = [
        "rpcss", "dnscache", "schedule", "eventlog", "winmgmt", "dhcp", "themes", "spooler",
    ];
    let hits = expected.iter().filter(|s| names.contains(**s)).count();
    assert!(
        hits >= 5,
        "the chain walk must reach the SCM's well-known services; matched only \
         {hits} of {:?} among {} names",
        expected,
        names.len()
    );

    // The diff against the sweep must have run (that is the whole point of the
    // list walk): every swept service the chain does not link is an unlinked-
    // service finding. Here it is 0, and the count being present proves the two
    // enumerations were comparable.
    assert!(
        rec.metadata["unlinked_count"].is_number(),
        "the sweep/chain diff must have run so unlinked services can be reported"
    );
    // The `svcdiff` known answer for this capture (recorded 2026-09-14): the
    // lab VM ran nothing that unlinks a service from the SCM, so every swept
    // record is also chained. A non-zero count here is either a real unlinked
    // service or a diff made over an incomplete chain — both worth failing on.
    let unlinked = rec.metadata["unlinked_count"].as_u64().unwrap_or(u64::MAX);
    eprintln!(
        "svcdiff over the Win11 26200 capture: chain {chain_count}, sweep {}, unlinked {unlinked}",
        rec.metadata["count"]
    );
    assert_eq!(
        unlinked, 0,
        "a clean lab capture links every service; the diff reported {unlinked} unlinked"
    );
}

/// Report which stages ran and which did not, as a coverage statement.
///
/// A stage failing on a real image is a finding about this build's reach, so it
/// is printed rather than swallowed. Run with `--nocapture`.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn report_stage_coverage_over_the_win11_capture() {
    let out = require_capture!();

    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for a in out {
        *kinds
            .entry(
                a.metadata["record_type"]
                    .as_str()
                    .unwrap_or("?")
                    .to_string(),
            )
            .or_default() += 1;
    }
    println!("\n=== record types ===");
    for (k, n) in &kinds {
        println!("  {k:<32} {n}");
    }

    println!("\n=== stages that did NOT run ===");
    for a in out {
        if a.metadata["record_type"] == "MemoryStageFailure" {
            println!(
                "  {:<20} {}",
                a.metadata["stage"].as_str().unwrap_or("?"),
                a.metadata["failure"].as_str().unwrap_or("?")
            );
        }
    }

    // The network stage cannot run, and not for want of provisioning.
    //
    // It needs tcpip.sys's `_TCP_ENDPOINT` layout. Microsoft's public symbol
    // server ships tcpip.pdb as a *public* PDB: 10,376 symbols and zero types.
    // Volatility's bundled ISF for the same file is identical in that respect
    // (9,329 symbols, zero types), which is why Volatility carries hand-authored
    // structure definitions per Windows build instead — and its newest covers
    // build 20348, where this capture is 26200. The layouts for this build are
    // not published by anyone, so closing this means deriving them from the
    // binary, not downloading them. This corpus ships the tcpip ISF anyway, so
    // the next person does not repeat the attempt to find out.
    //
    // **And the pattern scan does not run, because this pass names no rules.**
    // The shared analysis is built with none — Séance ships none — so the stage
    // reports that it did not run with that reason, which is a different
    // statement from an empty match list and has to stay one. Its own tests
    // drive it with a rule set.
    //
    // **And the strings map does not run either, for the same reason**: this
    // pass names no `strings` output, and the stage searches for nothing of
    // its own. When that stage landed this assertion was not brought along,
    // so the test failed at HEAD from that commit until the eight §5.3 stages
    // were added on 2026-09-19 and it was re-run; none of those eight is in
    // this set, because each runs without provisioning.
    //
    // Asserting the exact SET of stages that did not run, not a count: a count
    // of three would be satisfied by three stages failing for the wrong
    // reasons, and the reason is the whole content of a `MemoryStageFailure`.
    let mut did_not_run: BTreeMap<String, String> = BTreeMap::new();
    for a in out {
        if a.metadata["record_type"] == "MemoryStageFailure" {
            did_not_run.insert(
                a.metadata["stage"].as_str().unwrap_or("?").to_string(),
                a.metadata["failure"].as_str().unwrap_or("?").to_string(),
            );
        }
    }
    assert_eq!(
        did_not_run.keys().cloned().collect::<Vec<_>>(),
        vec![
            "network".to_string(),
            "pattern_scan".to_string(),
            "strings_map".to_string()
        ],
        "exactly these three stages may report that they did not run on this capture"
    );
    assert!(
        did_not_run["pattern_scan"].contains("no YARA rule set and no pattern was named"),
        "the pattern scan must say WHY it did not run: {}",
        did_not_run["pattern_scan"]
    );
    assert!(
        did_not_run["strings_map"].contains("no strings file was named"),
        "the strings map must say WHY it did not run: {}",
        did_not_run["strings_map"]
    );
    assert_eq!(
        kinds.get("MemoryStageFailure").copied().unwrap_or(0),
        3,
        "one record per stage that did not run"
    );

    // The eight §5.3 stages that landed on 2026-09-19 each produce their
    // record on this capture, and each says whether it established its result
    // in full.
    for (record_type, complete) in [
        ("MemoryProcessorBlocks", true),
        ("MemoryBigPool", true),
        ("MemoryVirtualMap", true),
        ("MemoryHiveCellRoutines", true),
        // Three of the 129 processes have no readable DLL list (their loader
        // data is paged out), so their images were not examined, and the
        // stage says so rather than listing them as processes with nothing
        // loaded.
        ("MemoryVersionInfo", false),
        ("MemoryMbrScan", true),
        // Two of the 246 tasks have a value whose data cell was paged out, and
        // the stage says so rather than listing them as tasks with less on
        // them.
        ("MemoryScheduledTasks", false),
        ("MemoryTrueCrypt", true),
    ] {
        let record = out
            .iter()
            .find(|a| a.metadata["record_type"] == record_type)
            .unwrap_or_else(|| panic!("{record_type} is emitted"));
        assert_eq!(record.metadata["stage_ran"], serde_json::json!(true));
        println!(
            "  {record_type:<28} complete={} {}",
            record.metadata["content_complete"],
            record.metadata["content_incomplete_reason"]
                .as_str()
                .unwrap_or("")
        );
        assert_eq!(
            record.metadata["content_complete"],
            serde_json::json!(complete),
            "{record_type}: {}",
            record.metadata["content_incomplete_reason"]
        );
    }
}

/// **A session layout this build does not publish is not a failed read**
/// (`MEM-023`).
///
/// On build 26200 `_EPROCESS.Session` points at a `_PSP_SESSION_SPACE` that
/// the ISF does not declare, and `read_session_id` declines to read a session
/// id at an offset nobody can check. Before `MEM-023` closed that refusal was
/// recorded as `unavailable` — every process with a session was "exist and
/// could not be read: session_id" — so the process inventory was a floor and every
/// per-process stage reported `content_complete: false` on every modern
/// capture, for a reason that had nothing to do with any of them.
///
/// The owner decision (2026-09-26, option A) is that a field the build declares
/// no layout for does not cost the inventory its completeness: it is
/// `not_declared` on each row and disclosed once, with a count, under the
/// list's `undescribed`. What is asserted here is that classification on real
/// evidence, and that no stage's inventory names the session id; whether a
/// stage is complete otherwise is its own business and is not asserted here.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_session_layout_this_build_does_not_publish_is_not_counted_as_a_failed_read() {
    let out = require_capture!();
    let list = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemoryProcessList")
        .expect("the process list is walked");
    let processes = list.metadata["processes"].as_array().expect("processes");
    let unavailable = processes
        .iter()
        .filter(|p| p["session_id"]["kind"] == "unavailable")
        .count();
    let not_declared = processes
        .iter()
        .filter(|p| p["session_id"]["kind"] == "not_declared")
        .count();
    eprintln!(
        "  session_id over {} processes: {not_declared} not_declared, {unavailable} unavailable",
        processes.len()
    );
    for p in processes {
        if p["session_id"]["kind"] != "not_declared" {
            eprintln!(
                "    {:?} session_id {}",
                p["image_file_name"]["value"], p["session_id"]
            );
        }
    }
    assert_eq!(
        unavailable, 0,
        "no session id on this capture failed to read"
    );
    assert_eq!(processes.len(), 129, "this machine had 129 processes");

    let undescribed = list.metadata["undescribed"]
        .as_array()
        .expect("the list discloses what this build does not describe");
    let session = undescribed
        .iter()
        .find(|u| u["field"] == "session_id")
        .unwrap_or_else(|| panic!("session_id is disclosed: {undescribed:?}"));
    assert_eq!(session["member"], "_MM_SESSION_SPACE.SessionId");
    // Measured 2026-09-26: every process but the four whose `Session` pointer
    // is null — System, Registry, the master smss.exe and MemCompression, none
    // of which belongs to a session — and those four are `not_applicable`.
    // (The register entry's "128 of 129" overstated it by three.)
    assert_eq!(session["processes"], 125);
    assert_eq!(session["processes"].as_u64(), Some(not_declared as u64));

    let mentions_session = |v: &serde_json::Value| v.to_string().contains("session_id");
    for incomplete in list.metadata["incomplete"].as_array().into_iter().flatten() {
        assert!(!mentions_session(incomplete), "{incomplete}");
    }

    // Every per-process stage's inventory: the session id is never the reason
    // it is a floor, and when the list itself walked end to end the inventory
    // is complete.
    //
    // Measured 2026-09-26: this capture's list walks end to end with every
    // other field read, so with the session id no longer counted against it
    // the list is complete and so is every inventory stamped from it.
    assert_eq!(list.metadata["forward_stop"], "wrapped");
    assert!(list.metadata["backward_stop"].is_null());
    assert_eq!(
        list.metadata["complete"], true,
        "{}",
        list.metadata["incomplete"]
    );
    let mut stamped = 0;
    let mut by_stage: BTreeMap<String, usize> = BTreeMap::new();
    for a in out {
        let Some(inventory) = a.metadata.get("process_inventory") else {
            continue;
        };
        stamped += 1;
        let stage = a.metadata["record_type"].as_str().unwrap_or("?");
        for incomplete in inventory["incomplete"].as_array().into_iter().flatten() {
            assert!(!mentions_session(incomplete), "{stage}: {incomplete}");
        }
        *by_stage.entry(stage.to_string()).or_default() += 1;
        assert_eq!(inventory["complete"], true, "{stage}: {inventory}");
    }
    eprintln!("  records stamped with a complete inventory: {by_stage:?}");
    assert!(
        stamped > 0,
        "at least one per-process stage carries its inventory"
    );
}

/// **The kernel's unloaded-driver table, read from a real capture** (`ROADMAP`
/// §5.3, the `unloadedmodules` group).
///
/// The layout this reader uses was measured across the 46 `ntkrnlmp.pdb` ISFs
/// on this machine that declare `_UNLOADED_DRIVERS` — and *this* build's ISF is
/// not one of them, so the read here goes through the documented x64 fallback.
/// That makes this the test that matters: a wrong offset yields names that are
/// not names and times that are not times, and nothing in a synthetic fixture
/// would catch it because the fixture is written at the same offsets it is read
/// at.
///
/// What is asserted is what a live Windows machine is always true of, never a
/// count that this one capture happens to have: the table read, it holds
/// plausible driver names, and its write counter agrees with how many slots
/// carry a range.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_unloaded_driver_table_is_read_from_the_win11_capture() {
    let out = require_capture!();

    let rec = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemoryTamperChecks")
        .expect("the tamper-checks stage must produce a record");

    let group = rec.metadata["groups"]
        .as_array()
        .expect("one status per group")
        .iter()
        .find(|g| g["group"] == "unloaded_modules")
        .expect("the unloaded-modules group is reported")
        .clone();
    assert_eq!(
        group["ran"],
        serde_json::json!(true),
        "the group must run on a build whose symbols name MmUnloadedDrivers: {:?}",
        group["detail"]
    );

    let table = &rec.metadata["unloaded_modules"];
    assert!(table.is_object(), "the table must be carried on the record");
    let drivers = table["drivers"].as_array().expect("a driver list");
    let write_count = table["write_count"].as_u64().expect("a write count");
    eprintln!(
        "unloaded drivers: {} slot(s) read, write_count={write_count}, wrapped={}",
        drivers.len(),
        table["wrapped"]
    );

    // The counter is a write count, not a length: slots read is
    // min(count, 50). A reader that treated it as a length would report more
    // slots than the kernel keeps.
    let capacity = table["table_capacity"].as_u64().expect("a capacity");
    assert_eq!(
        drivers.len() as u64,
        write_count.min(capacity),
        "slots read must be min(write count, capacity)"
    );
    assert_eq!(
        table["wrapped"],
        serde_json::json!(write_count > capacity),
        "wrapped is the counter against the capacity, nothing else"
    );

    // Every name that was read must look like a driver rather than like bytes
    // read at the wrong offset. A name is allowed to be absent -- an unwritten
    // slot has none -- but a present one that is not a name means the offsets
    // are wrong.
    let mut named = 0usize;
    for d in drivers {
        let Some(name) = d["driver_name"].as_str() else {
            assert!(
                d["name_unavailable_reason"].is_string(),
                "a slot with no name must say why: {d}"
            );
            continue;
        };
        named += 1;
        assert!(
            name.chars().all(|c| !c.is_control()) && name.chars().any(char::is_alphanumeric),
            "{name:?} is not a driver name; the record offsets are wrong"
        );
    }
    eprintln!("  named slots: {named} of {}", drivers.len());

    // **The time field on this build is an interval since boot, not a
    // FILETIME**, and the record says so rather than dating nine unloads to
    // 1601-01-01. Measured here: every populated slot carries an interval, and
    // the intervals rise with the slot order — which is what a since-boot
    // counter does and what a wall-clock FILETIME could not do at these
    // magnitudes.
    let mut intervals: Vec<f64> = Vec::new();
    for d in drivers {
        assert!(
            d["unloaded_at"].is_null() || d["unloaded_at"].is_string(),
            "the time field is either rendered or absent: {d}"
        );
        if let Some(after_boot) = d["unloaded_seconds_after_boot"].as_f64() {
            assert!(
                d["unloaded_at"].is_null(),
                "an interval since boot must not also be published as an absolute time: {d}"
            );
            intervals.push(after_boot);
        }
        for field in ["unloaded_at", "unloaded_at_absent_reason"] {
            assert!(
                !d[field].as_str().unwrap_or_default().contains("1601-"),
                "no unload may be dated to 1601: {d}"
            );
        }
    }
    eprintln!(
        "  since-boot intervals: {} of {} slot(s), {:?}",
        intervals.len(),
        drivers.len(),
        intervals
    );
    assert_eq!(
        intervals.len(),
        drivers.len(),
        "every populated slot on this build carries a since-boot interval, not a FILETIME"
    );
    assert!(
        intervals.windows(2).all(|w| w[1] >= w[0]),
        "the intervals must rise with the slot order, which is what makes them a since-boot \
         counter rather than noise: {intervals:?}"
    );
    assert!(
        intervals.last().copied().unwrap_or(f64::MAX) < 600.0,
        "these unloads are all from the first minutes of boot; an interval far past that would \
         mean the field is not what this build reads it as: {intervals:?}"
    );

    // **The known answer, pinned** (`seance_memory/tests/KNOWN_ANSWERS.md`).
    // The nine drivers Windows unloads during boot on this machine, in slot
    // order, and the nine raw `CurrentTime` values. Recorded so a later change
    // that starts reading a different offset — or starts emitting absolute
    // times for these — fails here rather than in a report.
    const EXPECTED_NAMES: [&str; 9] = [
        "hwpolicy.sys",
        "WdBoot.sys",
        "uiomap.sys",
        "KMPDC.sys",
        "dam.sys",
        "dump_dumpfve.sys",
        "dump_storahci.sys",
        "dump_storport.sys",
        "NetworkPrivacyPolicy.sys",
    ];
    const EXPECTED_TIMES: [u64; 9] = [
        0x00e3_93cb,
        0x00f6_79a5,
        0x0143_2ad9,
        0x0152_ff1d,
        0x0152_ff1d,
        0x029d_0047,
        0x029d_0047,
        0x029d_0047,
        0x0372_8e86,
    ];
    let names: Vec<&str> = drivers
        .iter()
        .map(|d| d["driver_name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(names, EXPECTED_NAMES, "the recorded known answer");
    let times: Vec<u64> = drivers
        .iter()
        .map(|d| d["unloaded_time_raw"].as_u64().unwrap_or_default())
        .collect();
    assert_eq!(times, EXPECTED_TIMES, "the recorded raw time values");
    // Every range is page-aligned in kernel space, which is the cheapest
    // independent check that the two pointer offsets are right.
    for d in drivers {
        for field in ["start_address", "end_address"] {
            let hex = d[field].as_str().unwrap_or_default();
            let value = u64::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0);
            assert_eq!(value & 0xFFF, 0, "{field} {hex} is not page-aligned");
            assert!(
                value > 0xFFFF_0000_0000_0000,
                "{field} {hex} is not in kernel space"
            );
        }
    }

    // And the layout the read went through is on the record, with its basis,
    // because on this build it is the documented fallback and not the ISF.
    let layout = table["record_layout"].as_str().unwrap_or_default();
    assert!(
        matches!(layout, "isf" | "documented_x64"),
        "an x64 capture reads through the ISF or the validated x64 layout, got {layout:?}"
    );
    assert!(
        table["record_layout_basis"]
            .as_str()
            .unwrap_or_default()
            .len()
            > 80,
        "the basis for the layout must be stated on the record"
    );
}

/// **The per-processor timer tables, walked on the real capture** (`ROADMAP`
/// §5.3, the `timers` group).
///
/// The measurement that matters here is the clean-machine baseline: how many
/// timers a real Windows 11 machine holds, how many carry a DPC routine, and —
/// the one a rule would be built on — how many of those routines land in no
/// loaded module. `HUNT-051` is this project's own lesson about writing the
/// rule before taking that measurement.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_timer_tables_are_walked_on_the_win11_capture() {
    let out = require_capture!();

    let rec = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemoryTamperChecks")
        .expect("the tamper-checks stage must produce a record");
    let group = rec.metadata["groups"]
        .as_array()
        .expect("one status per group")
        .iter()
        .find(|g| g["group"] == "timers")
        .expect("the timers group is reported")
        .clone();
    assert_eq!(
        group["ran"],
        serde_json::json!(true),
        "the group must run on a build declaring KiProcessorBlock: {:?}",
        group["detail"]
    );

    let timers = &rec.metadata["timers"];
    let layout = &timers["layout"];
    // Build 26200 declares `[2][256]`. The product is what must be walked; the
    // outer dimension alone would walk 2 of 512 buckets and find timers in
    // both.
    assert_eq!(layout["shape"], serde_json::json!("per_processor"));
    assert_eq!(
        layout["bucket_dimensions"],
        serde_json::json!([2, 256]),
        "the declared dimensions of this build"
    );
    assert_eq!(layout["buckets_declared"], serde_json::json!(512));

    let rows = timers["timers"].as_array().expect("a timer list");
    let with_dpc = timers["timers_with_a_dpc"].as_u64().unwrap_or(0);
    let outside = timers["routines_outside_any_module"].as_u64().unwrap_or(0);
    eprintln!(
        "timers: {} row(s) over {} bucket(s) on {} processor table(s); {with_dpc} with a DPC, \
         {outside} outside any module",
        rows.len(),
        timers["buckets_walked"],
        timers["processors_walked"],
    );
    eprintln!(
        "  processor count claimed: {} ({:?})",
        timers["processors_claimed"], timers["processor_count_note"]
    );

    // **The clean-machine baseline, recorded** (KNOWN_ANSWERS.md). Measured
    // 2026-09-15: eight processor tables, 4,096 buckets, 209 timers, and
    // **not one** routine outside a loaded module -- which, until `MEM-052`
    // decoded the DPC field on 2026-09-24, was vacuous (see below). That last number is the one a rule would be built on, and it is
    // zero on a clean capture — which is what makes the signal worth
    // reporting at all.
    assert_eq!(timers["processors_walked"].as_u64(), Some(8));
    assert_eq!(timers["buckets_walked"].as_u64(), Some(4096));
    assert_eq!(rows.len(), 209, "the recorded known answer");
    // `MEM-055`, measured 2026-09-26: on this clean capture every
    // bucket list closes at its own head, so 209 sightings are 209 distinct
    // timers and none is reached twice.
    assert_eq!(timers["timers_reported"].as_u64(), Some(209));
    assert_eq!(timers["rows_walked"].as_u64(), Some(209));
    assert_eq!(timers["timers_reached_more_than_once"].as_u64(), Some(0));
    // **`MEM-052`, 2026-09-24.** This build encodes `_KTIMER.Dpc` with
    // `KiWaitNever`/`KiWaitAlways`. Until it was decoded, all 209 encoded
    // fields were published as DPC addresses, no routine was read from any
    // of them, and the zero below measured nothing. Decoded: 52 timers carry
    // a DPC, and all 52 match Volatility 3's `windows.timers` in timer
    // address and routine; the other 157 decode to exactly 0 -- timers that
    // name no DPC, whose stored field is the encoding of null.
    assert_eq!(with_dpc, 52, "timers carrying a decoded, checked DPC");
    assert_eq!(timers["dpc_encoding"]["state"], "decoded");
    assert_eq!(timers["dpc_pointers_decoded"].as_u64(), Some(52));
    assert_eq!(
        timers["dpc_unreadable"].as_u64(),
        Some(0),
        "an encoded null is a timer with no DPC, not an unreadable one"
    );
    assert_eq!(
        rows.iter()
            .filter(|r| r["deferred_routine"].is_string())
            .count(),
        52,
        "a routine was read through every located DPC"
    );
    assert_eq!(
        outside, 0,
        "the false-positive count on a clean machine, which is what makes this signal usable"
    );
    // `MEM-054`, measured 2026-09-26: no row on this capture has PatchGuard's
    // shape (unaligned `_KTIMER`, routine in no module, non-canonical
    // context), so the count above is not held at zero by that recognition.
    assert_eq!(timers["patchguard_shaped"].as_u64(), Some(0));
    // Every bucket of every processor table was reached.
    let processors = timers["processors_walked"].as_u64().unwrap_or(0);
    assert_eq!(
        timers["buckets_walked"].as_u64(),
        Some(processors * 512),
        "every declared bucket of every processor table"
    );
    // The count the kernel claimed and the array agree here, so no note.
    assert_eq!(timers["processors_claimed"].as_u64(), Some(8));
    assert!(
        timers["processor_count_note"].is_null(),
        "nothing to say when the claim and the array agree: {:?}",
        timers["processor_count_note"]
    );

    // No row may carry a due time, in any form.
    for row in rows {
        assert!(
            row.get("due_time").is_none() && row.get("due_time_raw").is_none(),
            "no due time may reach a record: {row}"
        );
        assert!(row["due_time_note"].is_string());
        // A routine, when there is one, must be a kernel address.
        if let Some(routine) = row["deferred_routine"].as_str() {
            let value = u64::from_str_radix(routine.trim_start_matches("0x"), 16).unwrap_or(0);
            assert!(
                value > 0xFFFF_0000_0000_0000,
                "a DPC routine outside kernel space means the offsets are wrong: {routine}"
            );
        }
    }
}

/// **The three thread groups on the real capture** (`ROADMAP` §5.3:
/// `suspended_threads`, `debugregisters`, `orphan_kernel_threads`).
///
/// The measurement that gates the orphan rule: how many kernel threads on a
/// clean machine start outside every loaded module. A non-zero answer here
/// would mean the rule fires on a stock Windows 11 install, which is the
/// `HUNT-051` shape.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_thread_groups_are_measured_on_the_win11_capture() {
    let out = require_capture!();
    let rec = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemoryTamperChecks")
        .expect("the tamper-checks stage must produce a record");

    for group in [
        "suspended_threads",
        "debug_registers",
        "orphan_kernel_threads",
    ] {
        let g = rec.metadata["groups"]
            .as_array()
            .expect("one status per group")
            .iter()
            .find(|g| g["group"] == group)
            .unwrap_or_else(|| panic!("{group} is reported"));
        assert_eq!(
            g["ran"],
            serde_json::json!(true),
            "{group} must run on this capture: {:?}",
            g["detail"]
        );
    }

    let threads = &rec.metadata["threads"];
    eprintln!(
        "threads: {} examined over {} process(es); {} suspended, {} with debug state ({} armed), \
         {} orphan candidate(s) ({} graded)",
        threads["threads_examined"],
        threads["processes_walked"],
        threads["suspended_total"],
        threads["debug_register_rows"],
        threads["threads_with_a_breakpoint"],
        threads["orphan_kernel_threads"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        threads["orphan_graded"],
    );
    eprintln!(
        "  suspend counts read: {} of {} examined",
        threads["suspend_counts_read"], threads["threads_examined"]
    );
    eprintln!("  symbols: {}", threads["symbols"]);
    if let Some(notes) = threads["notes"].as_array() {
        for note in notes.iter().take(5) {
            eprintln!("  note: {note}");
        }
    }

    // **The clean-machine baseline, recorded** (KNOWN_ANSWERS.md). Measured
    // 2026-09-15: 1,514 threads over 129 processes, and all three groups
    // silent. Each zero below is a different statement, and the record
    // distinguishes them.
    assert_eq!(threads["threads_examined"].as_u64(), Some(1514));
    assert_eq!(threads["processes_walked"].as_u64(), Some(129));

    // Suspended: zero, and every count was READ -- which is what makes the
    // zero a statement about the machine rather than about the build.
    assert_eq!(threads["suspended_total"].as_u64(), Some(0));
    assert_eq!(
        threads["suspend_counts_read"].as_u64(),
        Some(1514),
        "a zero here would mean the field was never read, not that nothing was suspended"
    );

    // Debug registers: no thread on this machine claims live debug state, so
    // no register is read from any of them. **This is the measurement that
    // corrected the check.** Reading the trap frame regardless produced nine
    // rows here, five claiming armed breakpoints -- every one a
    // `ShadowStackFrame` pointer read through the union `Dr0` shares with it.
    assert_eq!(threads["threads_claiming_debug_state"].as_u64(), Some(0));
    assert_eq!(threads["debug_register_rows"].as_u64(), Some(0));
    assert_eq!(threads["threads_with_a_breakpoint"].as_u64(), Some(0));

    // Orphan kernel threads: no candidate at all -- every kernel thread's
    // start address attributes to a loaded module -- and 1,284 user threads
    // set aside, because a kernel-module map cannot attribute
    // `RtlUserThreadStart`.
    assert_eq!(threads["orphan_graded"].as_u64(), Some(0));
    assert_eq!(threads["orphan_observations"].as_u64(), Some(0));
    assert_eq!(threads["user_threads_set_aside"].as_u64(), Some(1284));

    // Every armed breakpoint is armed by DR7's own enable bits AND confirmed
    // by the thread's flags; a row claiming one must satisfy both.
    for row in threads["debug_register_threads"]
        .as_array()
        .unwrap_or(&vec![])
    {
        let armed = row["armed_slots"].as_u64().unwrap_or(0);
        let confirmed = row["claim"]
            .as_str()
            .unwrap_or_default()
            .starts_with("confirmed");
        let null_page_only = row["armed_only_in_the_null_page"] == serde_json::json!(true);
        assert_eq!(
            row["has_breakpoint"],
            serde_json::json!(armed > 0 && confirmed && !null_page_only),
            "a breakpoint claim must follow from an armed slot AND a confirmed claim AND an \
             armed address outside the null page (MEM-050): {row}"
        );
    }
}

/// **The ETW write path across every process on the real capture**
/// (`ROADMAP` §5.3, the `etwpatch` group).
///
/// The measurement both routes need: what the modal prologue of each export
/// actually is on a clean machine, how many processes agree with it, and how
/// many could not be assessed at all. A signal count above zero here would
/// mean the check fires on a stock Windows 11 install.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_etw_write_path_is_examined_on_the_win11_capture() {
    let out = require_capture!();
    let rec = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemoryTamperChecks")
        .expect("the tamper-checks stage must produce a record");
    let group = rec.metadata["groups"]
        .as_array()
        .expect("one status per group")
        .iter()
        .find(|g| g["group"] == "etw_patch")
        .expect("the etw group is reported")
        .clone();
    assert_eq!(
        group["ran"],
        serde_json::json!(true),
        "the group must run on this capture: {:?}",
        group["detail"]
    );

    let etw = &rec.metadata["etw"];
    eprintln!(
        "etw: {} export(s) over {} process(es); {} signal(s); {} unassessed",
        etw["exports_read"], etw["processes_assessed"], etw["signals"], etw["unassessed_total"],
    );
    for mode in etw["modes"].as_array().unwrap_or(&vec![]) {
        eprintln!(
            "  {}: {} agreed of {} — {}",
            mode["export"], mode["agreed"], mode["population"], mode["modal_prologue"]
        );
    }
    for row in etw["unassessed"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .take(5)
    {
        eprintln!("  unassessed: {row}");
    }

    // **The clean-machine baseline, recorded** (KNOWN_ANSWERS.md). Measured
    // 2026-09-15: 491 export prologues over 123 processes, every one agreeing
    // with its export's mode and classifying as ordinary, no signal on either
    // route, and six processes unassessed — the three that genuinely map no
    // ntdll (System, Registry, MemCompression) and three whose loader list
    // could not be reached.
    assert_eq!(etw["processes_assessed"].as_u64(), Some(123));
    assert_eq!(etw["exports_read"].as_u64(), Some(491));
    assert_eq!(etw["unassessed_total"].as_u64(), Some(6));
    assert_eq!(
        etw["signals"].as_u64(),
        Some(0),
        "a signal on a stock Windows 11 install means this check fires on a clean machine"
    );

    // **The modal prologue of each export on this build, which is the known
    // answer.** Note `EtwEventWrite`'s last two bytes: `48 81` is the start of
    // a `sub rsp,imm32` that the sixteen-byte window cuts in half. Calling
    // that undecodable classified 369 of these 491 as unreadable in an earlier
    // draft, which is why the bytes are pinned here and not only the counts.
    let modal = |export: &str| -> String {
        etw["modes"]
            .as_array()
            .expect("modes")
            .iter()
            .find(|m| m["export"] == export)
            .and_then(|m| m["modal_prologue"].as_str())
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(
        modal("EtwEventWrite"),
        "40 55 57 41 54 41 56 41 57 48 8d 6c 24 80 48 81"
    );
    assert_eq!(
        modal("EtwEventWriteFull"),
        "4c 8b dc 48 83 ec 58 48 8b 84 24 90 00 00 00 49"
    );
    assert_eq!(
        modal("EtwEventWriteEx"),
        "4c 8b dc 48 83 ec 58 48 8b 84 24 98 00 00 00 45"
    );
    assert_eq!(
        modal("EtwEventWriteTransfer"),
        "40 55 57 41 54 41 55 41 57 48 8d ac 24 70 ff ff"
    );

    // Every row agrees with its export's mode, classifies as ordinary, and is
    // no signal.
    for row in etw["exports"].as_array().expect("rows") {
        assert_eq!(
            row["agrees_with_the_mode"],
            serde_json::json!(true),
            "a minority prologue on a clean machine: {row}"
        );
        assert_eq!(
            row["classification"],
            serde_json::json!("ordinary"),
            "a genuine prologue must classify as ordinary: {row}"
        );
        assert_eq!(row["is_signal"], serde_json::json!(false));
    }
    for mode in etw["modes"].as_array().expect("modes") {
        let agreed = mode["agreed"].as_u64().unwrap_or(0);
        let population = mode["population"].as_u64().unwrap_or(0);
        assert!(agreed > 0 && agreed <= population, "{mode}");
    }
}

/// **The skeleton-key check on the real capture** (`ROADMAP` §5.3,
/// `skeleton_key_check`).
///
/// The expected answer on a clean machine is zero on the one route that runs —
/// and the record must still not read as an all-clear, because the second route
/// does not run on any build.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_skeleton_key_check_examines_lsass_on_the_win11_capture() {
    let out = require_capture!();
    let rec = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemoryTamperChecks")
        .expect("the tamper-checks stage must produce a record");
    let group = rec.metadata["groups"]
        .as_array()
        .expect("one status per group")
        .iter()
        .find(|g| g["group"] == "skeleton_key")
        .expect("the skeleton-key group is reported")
        .clone();
    assert_eq!(
        group["ran"],
        serde_json::json!(true),
        "the group must run on this capture: {:?}",
        group["detail"]
    );

    let skeleton = &rec.metadata["skeleton_key"];
    eprintln!(
        "skeleton key: {} lsass found, {} examined, {} signal(s); unassessed {}",
        skeleton["lsass_found"],
        skeleton["lsass_examined"],
        skeleton["signals"],
        skeleton["unassessed"],
    );
    for row in skeleton["lsass_processes"].as_array().unwrap_or(&vec![]) {
        eprintln!("  {row}");
    }

    // A running Windows machine has exactly one lsass.exe.
    assert_eq!(skeleton["lsass_found"].as_u64(), Some(1));
    assert_eq!(skeleton["lsass_examined"].as_u64(), Some(1));
    assert_eq!(skeleton["signals"].as_u64(), Some(0));
    assert_eq!(skeleton["assessed_anything"], serde_json::json!(true));

    // **And it is still not complete**, because the `CSystems` route does not
    // run on any build. A clean answer here must not read as an all-clear.
    assert_eq!(skeleton["content_incomplete"], serde_json::json!(true));
    assert!(
        skeleton["route_not_run_detail"]
            .as_str()
            .unwrap_or_default()
            .contains("not pending an ISF"),
        "the unrun route says why it will not run: {:?}",
        skeleton["route_not_run_detail"]
    );
    // The known answer for this build: `CDLocateCSystem`'s real prologue,
    // measured 2026-09-15 (KNOWN_ANSWERS.md). A wrong export address or a
    // wrong module would not produce these bytes.
    let row = &skeleton["lsass_processes"][0];
    assert_eq!(row["classification"], serde_json::json!("ordinary"));
    assert_eq!(row["module"], serde_json::json!("cryptdll.dll"));
    assert_eq!(row["export"], serde_json::json!("CDLocateCSystem"));
    assert_eq!(row["image_mapped"], serde_json::json!(true));
    assert_eq!(
        row["prologue"],
        serde_json::json!("8b 05 aa b9 00 00 4c 8d 15 83 c0 00 00 44 8b c9")
    );
}

/// **The PEB-masquerade checks on the real capture** (`ROADMAP` §5.3's
/// `pebmasquerade`, answered inside the `tampering` stage).
///
/// Two rules are measured here rather than assumed: how often the kernel's own
/// audit record disagrees with the path a process publishes on a clean machine,
/// and how often the loader's own length invariant on that string does not
/// hold. A rule that fires here fires on a stock Windows 11 install.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_peb_masquerade_checks_are_measured_on_the_win11_capture() {
    let out = require_capture!();
    let rec = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemoryProcessTampering")
        .expect("the tampering stage must produce a record");

    let processes = rec.metadata["examined"]
        .as_array()
        .cloned()
        .expect("per-process rows");
    let mut by_kind: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for process in processes.iter() {
        for signal in process["signals"].as_array().unwrap_or(&vec![]) {
            *by_kind
                .entry(signal["signal"].as_str().unwrap_or_default().to_string())
                .or_default() += 1;
        }
    }
    eprintln!("  signals by kind: {by_kind:?}");
    let mut audit_differs = 0usize;
    let mut length_inconsistent = 0usize;
    let mut audit_unchecked = 0usize;
    let mut protection_unchecked = 0usize;
    let mut audit_read = 0usize;
    for process in processes.iter() {
        if process["audit_image_path"].is_string() {
            audit_read += 1;
        }
        for signal in process["signals"].as_array().unwrap_or(&vec![]) {
            match signal["signal"].as_str().unwrap_or_default() {
                "audit_path_differs" => audit_differs += 1,
                "process_parameter_string_inconsistent" => {
                    length_inconsistent += 1;
                    if length_inconsistent <= 5 {
                        eprintln!("  length inconsistent: {signal}");
                    }
                }
                _ => {}
            }
        }
        if process["not_checked"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .any(|n| n["check"] == "audit_image_path")
        {
            audit_unchecked += 1;
        }
        // `MEM-022`: this check reported itself unmade for every process on
        // every machine, because the stage built a VAD walk config that never
        // read the kernel's own protection table -- and then said the table
        // "was not available", of one the symbols publish.
        if process["not_checked"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .any(|n| n["check"] == "image_vad_protection")
        {
            protection_unchecked += 1;
        }
    }
    eprintln!(
        "peb masquerade over {} process(es): {audit_read} audit paths read, {audit_differs} \
         disagreements, {length_inconsistent} length inconsistencies, {audit_unchecked} not \
         checked",
        processes.len()
    );

    // **The clean-machine baseline, recorded** (KNOWN_ANSWERS.md). Measured
    // 2026-09-15: the whole tampering stage produces **no signal of any kind**
    // over 123 processes, and the kernel's audit path was read for every one.
    assert_eq!(processes.len(), 123);
    assert_eq!(
        audit_read, 123,
        "the audit path is declared on every ISF measured, so it must have been read"
    );
    assert_eq!(audit_unchecked, 0);
    // **The protection check is MADE, on every process, and raises nothing.**
    // Two of this stage's checks rest on the kernel's protection table; before
    // `MEM-022` neither could run at all. This is their clean-capture
    // baseline, and the number that would go back to 123 if the config
    // regressed.
    assert_eq!(
        protection_unchecked, 0,
        "the image range's protection could not be named for {protection_unchecked} of 123 \
         processes, which is MEM-022 back"
    );
    assert_eq!(
        audit_differs, 0,
        "a masquerade signal on a stock Windows 11 install means this rule fires on a clean \
         machine"
    );
    assert_eq!(
        length_inconsistent, 0,
        "the loader's own length invariant on ImagePathName holds for all 123 processes here, \
         which is what makes a breach of it worth reporting"
    );

    // **And no other signal either.** This is the assertion that caught a
    // defect rather than confirming one: before the fix recorded with
    // `names_agree`, 23 processes on this clean capture were reported as
    // mapping a file other than the one they claim to be -- every one of them
    // a name cut off by the fifteen-byte array's own NUL terminator
    // (`fontdrvhost.ex`, `RuntimeBroker.`, `msedgewebview2` ...).
    assert!(
        by_kind.is_empty(),
        "a clean Windows 11 install must raise no tampering signal at all; got {by_kind:?}"
    );
}

/// **Job objects on the real capture, against the upstream oracle**
/// (`ROADMAP` §5.3, `joblinks`).
///
/// Volatility 3.2.28.2 on this image prints **56 rows: 24 job rows plus 32
/// member rows**. Those are not comparable to this stage's row count by
/// construction — upstream prints one row per *process that has a job* and
/// repeats that job's members under each, where this stage emits one record per
/// *distinct job object*. What is comparable, and what is asserted, is the set
/// of processes that have a job and the set of `(job, member pid)` pairs.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn job_objects_are_surveyed_on_the_win11_capture() {
    let out = require_capture!();
    let rec = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemoryJobs")
        .expect("the jobs stage must produce a record");

    let jobs = rec.metadata["jobs"].as_array().expect("job rows");
    eprintln!(
        "jobs: {} distinct job(s); {} of {} processes in a job, {} in none, {} unreadable",
        jobs.len(),
        rec.metadata["processes_in_a_job"],
        rec.metadata["processes_walked"],
        rec.metadata["processes_without_a_job"],
        rec.metadata["processes_unreadable"],
    );
    for job in jobs {
        eprintln!(
            "  {} named by {} process(es), {} member(s), counter {} (agrees {})",
            job["job"],
            job["named_by_total"],
            job["members_walked"],
            job["active_processes"],
            job["counter_agrees_with_the_list"],
        );
    }

    for job in jobs {
        if !job["walk_stop"].is_null() {
            eprintln!("  walk stop: {} -> {}", job["job"], job["walk_stop"]);
        }
    }
    // **The upstream oracle, compared like with like.** Volatility prints one
    // row per process that has a job (24) and repeats that job's members under
    // each (32 member rows). This stage emits one record per distinct job, so
    // the comparable quantities are the count of processes in a job and the
    // sum, over those processes, of their job's member count.
    let upstream_member_rows: u64 = jobs
        .iter()
        .map(|job| {
            job["named_by_total"].as_u64().unwrap_or(0)
                * job["members_walked"].as_u64().unwrap_or(0)
        })
        .sum();
    eprintln!("  upstream-shaped member rows: {upstream_member_rows}");

    // **Parity, recorded** (KNOWN_ANSWERS.md). Measured 2026-09-15: 21
    // distinct job objects named by 24 processes of 129, and 32 member rows
    // under upstream's shape -- which is exactly what Volatility 3.2.28.2
    // prints for this image (its 24 job rows + 32 member rows = 56).
    assert_eq!(jobs.len(), 21, "distinct job objects");
    assert_eq!(
        rec.metadata["processes_in_a_job"].as_u64(),
        Some(24),
        "upstream prints one job row per process that has a job, and prints 24"
    );
    assert_eq!(
        upstream_member_rows, 32,
        "upstream repeats each job's members under every process that names it, and prints 32"
    );
    assert_eq!(rec.metadata["processes_walked"].as_u64(), Some(129));
    assert_eq!(rec.metadata["processes_without_a_job"].as_u64(), Some(105));
    assert_eq!(
        rec.metadata["process_list_complete"],
        serde_json::json!(true)
    );
    assert_eq!(rec.metadata["processes_unreadable"], serde_json::json!(0));
    // No member list ended abnormally, so each member count is the kernel's
    // and not this walk's ceiling.
    for job in jobs {
        assert!(
            job["walk_stop"].is_null(),
            "a member walk that ended early makes its count this walk's rather than the \
             kernel's: {job}"
        );
    }
    // **One job's counter disagrees with its list, on a clean machine** -- it
    // reports 7 active processes and holds 3. Both numbers are reported rather
    // than one preferred, and this pins that the disagreement stays visible.
    let disagreeing = jobs
        .iter()
        .filter(|job| job["counter_agrees_with_the_list"] == serde_json::json!(false))
        .count();
    assert_eq!(disagreeing, 1, "the measured answer on this capture");

    // Every member address was recovered by CONTAINING_RECORD from its link,
    // so a wrong offset would put them outside kernel space.
    for job in jobs {
        for member in job["members"].as_array().unwrap_or(&vec![]) {
            let hex = member["process"].as_str().unwrap_or_default();
            let value = u64::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0);
            assert!(
                value > 0xFFFF_0000_0000_0000,
                "a member address outside kernel space means the JobLinks offset is wrong: {hex}"
            );
        }
    }
}

/// **The device tree on the real capture, against the upstream oracle**
/// (`ROADMAP` §5.3, `devicetree`).
///
/// Volatility 3.2.28.2 on this image prints **255 rows: 129 DRV, 100 DEV and
/// 26 ATT**, over 126 distinct driver names. Those rows map one-for-one onto
/// this stage's counts — a DRV row per driver, a DEV row per device, an ATT row
/// per attachment — so unlike `joblinks` the comparison needs no reshaping.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_device_tree_is_walked_on_the_win11_capture() {
    let out = require_capture!();
    let rec = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemoryDriverDevices")
        .expect("the device-tree stage must produce a record");

    let drivers = rec.metadata["drivers"].as_array().expect("driver rows");
    eprintln!(
        "device tree: {} driver(s) (DRV), {} device(s) (DEV), {} attachment(s) (ATT), {} of them \
         by another driver",
        drivers.len(),
        rec.metadata["devices_total"],
        rec.metadata["attachments_total"],
        rec.metadata["foreign_attachments"],
    );
    let mut named: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut attachments_shown = 0usize;
    for driver in drivers {
        if let Some(name) = driver["driver_name"].as_str() {
            named.insert(name.to_string());
        }
        if !driver["device_stop"].is_null() {
            eprintln!(
                "  device chain stop: {} {}",
                driver["driver"], driver["device_stop"]
            );
        }
        for device in driver["devices"].as_array().unwrap_or(&vec![]) {
            if !device["attached_stop"].is_null() {
                eprintln!(
                    "  attachment stop: {} {}",
                    device["device"], device["attached_stop"]
                );
            }
            for attached in device["attached"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .take(3)
            {
                if attachments_shown < 6 {
                    attachments_shown += 1;
                    eprintln!(
                        "  ATT {} on {} by {}",
                        attached["name"]["name"],
                        device["name"]["name"],
                        attached["attaching_driver_name"]
                    );
                }
            }
        }
    }
    eprintln!("  distinct driver names: {}", named.len());
    // **The measured answer, recorded** (KNOWN_ANSWERS.md). 2026-09-15: 124
    // drivers, 245 devices, 113 attachments over 76 distinct attached devices.
    let mut addresses: Vec<&str> = drivers
        .iter()
        .flat_map(|d| {
            d["devices"]
                .as_array()
                .map(|a| a.as_slice())
                .unwrap_or_default()
        })
        .filter_map(|d| d["device"].as_str())
        .collect();
    let device_rows = addresses.len();
    addresses.sort_unstable();
    addresses.dedup();
    assert_eq!(
        addresses.len(),
        device_rows,
        "a device reported under two drivers would be double-counted; each NextDevice chain \
         carries its own visited set"
    );

    assert_eq!(
        drivers.len(),
        124,
        "drivers reached from the hook stage's sweep"
    );
    assert_eq!(rec.metadata["devices_total"].as_u64(), Some(245));
    assert_eq!(rec.metadata["attachments_total"].as_u64(), Some(113));
    assert_eq!(
        rec.metadata["foreign_attachments"].as_u64(),
        Some(113),
        "every attachment on this machine is by a driver other than the one owning the device \
         beneath, which is what a filter is"
    );
    assert_eq!(named.len(), 124);

    // **Agreement with upstream where upstream reports at all.** Volatility
    // 3.2.28.2 on this image prints 129 DRV, 100 DEV and 26 ATT rows, and at
    // most one device per driver; these four `(driver, device)` pairs are from
    // its own output and must be in this record too. The devices it does not
    // print are the rest of each driver's `NextDevice` chain -- `\Driver\ACPI`
    // owns 32 of them here, with the sequential PnP names an ACPI enumeration
    // produces. Why upstream stops is NOT established here and this test makes
    // no claim about it.
    let has_device = |driver: &str, device: &str| -> bool {
        drivers
            .iter()
            .filter(|d| d["driver_name"].as_str() == Some(driver))
            .flat_map(|d| {
                d["devices"]
                    .as_array()
                    .map(|a| a.as_slice())
                    .unwrap_or_default()
            })
            .any(|d| d["name"]["name"].as_str() == Some(device))
    };
    for (driver, device) in [
        ("\\Driver\\ACPI", "00000029"),
        ("\\Driver\\ACPI_HAL", "0000000f"),
        ("\\Driver\\PnpManager", "0000000e"),
        ("\\Driver\\Wdf01000", "KMDF0"),
    ] {
        assert!(
            has_device(driver, device),
            "upstream prints {driver} owning {device} and this record does not"
        );
    }

    assert!(!drivers.is_empty(), "no driver object reached");
    assert!(
        rec.metadata["devices_total"].as_u64().unwrap_or(0) > 50,
        "a Windows machine's drivers own many devices"
    );
}

/// The profile, discovered once for the tests below that drive one stage
/// directly rather than reading the whole analysis's output.
///
/// Separate from [`analysis`] on purpose: a stage that takes examiner-supplied
/// input — a YARA rule set — cannot be exercised through the shared pass,
/// which is deliberately built with none.
static PROFILE: OnceLock<Option<seance_plugin_memory_windows::WindowsProfile>> = OnceLock::new();

fn corpus_profile() -> Option<&'static seance_plugin_memory_windows::WindowsProfile> {
    PROFILE
        .get_or_init(|| {
            let path = capture_path()?;
            let source: Arc<dyn DataSource> =
                Arc::new(seance_core::data_source::FileDataSource::new(path).ok()?);
            let physical: Arc<dyn MemoryLayer> = Arc::new(PhysicalLayer::raw(source).ok()?);
            automagic::discover(physical, &symbol_dirs(), &DiscoveryOptions::default()).ok()
        })
        .as_ref()
}

/// **Examiner-supplied YARA rules over one process's own memory, graded against
/// the upstream oracle** (`ROADMAP` §5.3, upstream's `vadyarascan`).
///
/// Volatility 3.2.28.2 on this image:
///
/// ```text
/// windows.vadyarascan --pid 4708 --yara-string FORENSIC-W11
/// ```
///
/// prints **8 matches** in `taskhostw.exe`, at the eight addresses asserted
/// below. Compared as a **set of addresses**, not as a count: two scans can
/// agree on eight and disagree about where, and a disagreement about where
/// means the planning or the attribution is wrong. A count-only comparison
/// would pass on that.
///
/// The engine is the product's own: rules compiled by `YaraScanner`'s loader
/// and driven through `seance_memory::scan` by `MemoryYaraScanner`, over the
/// address space assembled from this process's directory table base. A
/// fixed-string scanner would find the same eight bytes and would not prove any
/// of that.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn yara_rules_find_the_known_marker_in_one_process_own_memory() {
    use seance_plugin_memory_windows::pattern_scan::{
        scan_patterns, PatternScanConfig, PatternScanSymbols, PatternSet,
    };
    use seance_plugin_memory_windows::process::{
        list_processes, ProcessListConfig, ProcessSymbols,
    };
    use seance_plugin_yara::memory::{MemoryYaraScanner, CONDITION_SCOPE};
    use seance_plugin_yara::YaraScanner;
    use std::io::Write;

    /// What `vadyarascan` prints for this process and this string.
    const UPSTREAM: [u64; 8] = [
        0x2ca2f84c44e,
        0x2ca2f84d9ed,
        0x2ca2f8508cb,
        0x2ca2f8511ba,
        0x2ca2f991c4b,
        0x2ca2f991d0d,
        0x2ca2f99206c,
        0x2ca2f992093,
    ];

    let Some(profile) = corpus_profile() else {
        eprintln!("skipping: capture not present");
        return;
    };

    // A rule set through the product's own loader, so a rule that would not
    // compile fails here rather than searching for nothing.
    let dir = tempfile::tempdir().expect("temp dir");
    let mut file = std::fs::File::create(dir.path().join("marker.yar")).expect("create");
    file.write_all(
        br#"rule forensic_w11_marker {
  strings: $a = "FORENSIC-W11"
  condition: $a
}"#,
    )
    .expect("write");
    drop(file);
    let rules = Arc::new(YaraScanner::from_rule_path(dir.path()).expect("the rules compile"));
    let engine = Arc::new(MemoryYaraScanner::new("yara.memory", Arc::clone(&rules)));
    let set = PatternSet {
        kind: "yara",
        source: dir.path().display().to_string(),
        pattern_names: rules.rule_identifiers(),
        diagnostics: Some(Arc::clone(&engine) as Arc<dyn seance_memory::scan::ScannerDiagnostics>),
        scanner: engine as Arc<dyn seance_memory::scan::Scanner>,
        scope_note: Some(CONDITION_SCOPE.to_string()),
    };

    let ps = ProcessSymbols::from_profile(profile).expect("process symbols");
    let list = list_processes(profile, &ps, &ProcessListConfig::default()).expect("the list walks");
    let symbols = PatternScanSymbols::from_profile(profile).expect("a describable build");
    let config = PatternScanConfig {
        pids: Some(vec![4708]),
        // The kernel's space is measured by its own test; this one is the
        // per-process route upstream's oracle covers.
        include_kernel: false,
        ..PatternScanConfig::default()
    };
    let survey = scan_patterns(profile, &symbols, Some(&list), &[set], &config);

    let json = survey.to_json();
    eprintln!("pattern scan: {}", json["statement"]);
    for process in json["processes"].as_array().unwrap_or(&vec![]) {
        eprintln!(
            "  pid {} {}: {} vad(s), {} match(es), {} byte(s) scanned, pass {}",
            process["pid"],
            process["name"],
            process["vads"],
            process["matches"],
            process["bytes_scanned"],
            process["passes"][0],
        );
    }
    for row in json["matches"].as_array().unwrap_or(&vec![]) {
        eprintln!(
            "  {} at {} in {}..{} ({}, private {}, file {})",
            row["pattern"],
            row["address_hex"],
            row["region"]["start_hex"],
            row["region"]["end_hex"],
            row["region"]["protection"],
            row["region"]["private_memory"],
            row["region"]["mapped_file"],
        );
    }

    // **The set, not the count.**
    let found: Vec<u64> = survey.matches.iter().map(|m| m.address).collect();
    assert_eq!(
        found,
        UPSTREAM.to_vec(),
        "the addresses `vadyarascan` prints for this process, in ascending order"
    );
    assert_eq!(survey.matches_total, 8);
    assert_eq!(
        survey.matches_by_pattern.get("forensic_w11_marker"),
        Some(&8),
        "every match is attributed to the rule that produced it"
    );

    // One process, the one that was asked for.
    assert_eq!(survey.processes.len(), 1, "the pid filter scoped the scan");
    let scanned = &survey.processes[0];
    assert_eq!(scanned.pid, Some(4708));
    assert_eq!(scanned.name.as_deref(), Some("taskhostw.exe"));
    assert!(scanned.not_scanned.is_none());
    assert!(survey.pids_not_found.is_empty());

    // **Every match names the allocation that held it, and the address is
    // inside it.** An off-by-one in the region arithmetic, or attribution by
    // section rather than by address, shows up here rather than on a screen.
    for row in &survey.matches {
        let region = row
            .region
            .as_ref()
            .unwrap_or_else(|| panic!("a match with no allocation: {:#x}", row.address));
        assert!(
            region.start <= row.address && row.address <= region.end,
            "{:#x} is outside the allocation {:#x}..{:#x} it was attributed to",
            row.address,
            region.start,
            region.end
        );
        // The marker was written into the process's own private memory by the
        // session that built this corpus, so it is in a private allocation
        // with no file behind it. A match reported against a mapped image here
        // would mean the attribution had landed in the wrong range.
        assert_eq!(
            row.region.as_ref().map(|r| r.private_memory),
            Some(Some(true))
        );
    }

    // The engine refused nothing, so the eight are eight and not a floor.
    assert!(
        survey.refused_chunks.is_empty(),
        "{:?}",
        survey.refused_chunks
    );
    assert!(survey.matched_without_address.is_empty());
    // And the scan of the one process it was asked about was complete: the
    // allocation tree walked end to end, no ceiling fired, and every mapped
    // byte inside the allocations was read.
    assert!(scanned.vad_tree_complete, "{:?}", scanned.vad_incomplete);
    for pass in &scanned.passes {
        assert_eq!(pass.unreadable_bytes, 0, "{:?}", pass.capped);
        assert!(pass.capped.is_none(), "{:?}", pass.capped);
        assert_eq!(pass.ranges_unplannable, 0);
        // YARA's match length is unbounded, so the boundary limitation is
        // declared on every pass whether or not it bit.
        assert!(pass.pattern_may_exceed_overlap);
    }
    // **The survey's own verdict is about the machine, not about the one
    // process.** This capture's active process list does not walk end to end
    // by the inventory's measure -- a field of some row could not be read --
    // so the stage declines to call the answer complete even though the
    // process it was asked about was searched in full. Both halves are
    // asserted, because collapsing them is exactly how "we searched one
    // process" comes to read as "we searched the machine".
    let inventory = survey
        .inventory
        .as_ref()
        .expect("the list was walked and handed in");
    eprintln!(
        "  process list: {} listed, complete {}, {:?}",
        inventory.listed,
        inventory.is_complete(),
        inventory.incomplete
    );
    if inventory.is_complete() {
        assert!(survey.is_complete(), "{:?}", survey.incomplete());
    } else {
        assert!(!survey.is_complete());
        let incomplete = survey.incomplete();
        assert!(
            incomplete
                .iter()
                .any(|i| i.detail.contains("did not walk end to end")),
            "a short process list must be named as the reason: {incomplete:?}"
        );
    }
}

/// **The same rule set over the whole machine: every process's own address
/// space and the kernel's** (`ROADMAP` §5.3, upstream's `vadyarascan` with no
/// `--pid`, and `yarascan`).
///
/// The clean-capture baseline this stage ships against, measured before any
/// claim was made about it. The numbers are in
/// `seance_memory/tests/KNOWN_ANSWERS.md`; what is asserted here is the shape
/// an examiner depends on:
///
/// * `taskhostw.exe` (pid 4708) reports **exactly** the eight matches upstream
///   prints for it, in a run that searched every other process too. The string
///   is this machine's own host name, so it is in most processes on it — a
///   *per-process* count that drifts when the neighbours are scanned is what a
///   page-table mix-up looks like, and this is the assertion that catches it;
/// * every process on the list is either searched or carries a reason;
/// * the kernel's own space is searched, and its matches are reported with no
///   allocation and the reason there is none.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_marker_is_found_in_the_one_process_that_holds_it_and_the_kernel_space_is_searched() {
    use seance_plugin_memory_windows::pattern_scan::{
        scan_patterns, PatternScanConfig, PatternScanSymbols, PatternSet, ProcessScan,
    };
    use seance_plugin_memory_windows::process::{
        list_processes, ProcessListConfig, ProcessSymbols,
    };
    use seance_plugin_yara::memory::{MemoryYaraScanner, CONDITION_SCOPE};
    use seance_plugin_yara::YaraScanner;
    use std::io::Write;

    let Some(profile) = corpus_profile() else {
        eprintln!("skipping: capture not present");
        return;
    };

    let dir = tempfile::tempdir().expect("temp dir");
    let mut file = std::fs::File::create(dir.path().join("marker.yar")).expect("create");
    file.write_all(
        br#"rule forensic_w11_marker {
  strings: $a = "FORENSIC-W11"
  condition: $a
}"#,
    )
    .expect("write");
    drop(file);
    let rules = Arc::new(YaraScanner::from_rule_path(dir.path()).expect("the rules compile"));
    let engine = Arc::new(MemoryYaraScanner::new("yara.memory", Arc::clone(&rules)));
    let set = PatternSet {
        kind: "yara",
        source: dir.path().display().to_string(),
        pattern_names: rules.rule_identifiers(),
        diagnostics: Some(Arc::clone(&engine) as Arc<dyn seance_memory::scan::ScannerDiagnostics>),
        scanner: engine as Arc<dyn seance_memory::scan::Scanner>,
        scope_note: Some(CONDITION_SCOPE.to_string()),
    };

    let ps = ProcessSymbols::from_profile(profile).expect("process symbols");
    let list = list_processes(profile, &ps, &ProcessListConfig::default()).expect("the list walks");
    let symbols = PatternScanSymbols::from_profile(profile).expect("a describable build");
    let started = std::time::Instant::now();
    let survey = scan_patterns(
        profile,
        &symbols,
        Some(&list),
        &[set],
        &PatternScanConfig::default(),
    );
    let elapsed = started.elapsed();

    eprintln!(
        "whole-machine pattern scan in {elapsed:?}: {}",
        survey.describe()
    );
    eprintln!(
        "  {} process(es) searched, {} not; {} byte(s); {} match(es)",
        survey.processes_scanned(),
        survey.processes_not_scanned(),
        survey.bytes_scanned,
        survey.matches_total,
    );
    if let Some(reason) = &survey.kernel_not_scanned {
        eprintln!("  kernel space NOT searched: {reason}");
    }
    for pass in &survey.kernel {
        eprintln!(
            "  kernel space: {} section(s), {} byte(s), {} match(es), {} unreadable, capped {:?}",
            pass.sections,
            pass.bytes_scanned,
            pass.hits.len(),
            pass.unreadable_bytes,
            pass.capped,
        );
    }
    let matched: Vec<&_> = survey.processes.iter().filter(|p| p.matches > 0).collect();
    eprintln!(
        "  {} of {} process(es) hold the string at all; the busiest: {:?}",
        matched.len(),
        survey.processes.len(),
        matched
            .iter()
            .max_by_key(|p| p.matches)
            .map(|p| (p.pid, p.name.clone(), p.matches)),
    );
    for process in survey.processes.iter().filter(|p| p.not_scanned.is_some()) {
        eprintln!(
            "  pid {:?} {:?} NOT searched: {}",
            process.pid,
            process.name,
            process.not_scanned.as_deref().unwrap_or_default()
        );
    }
    let unreadable: u64 = survey
        .processes
        .iter()
        .flat_map(|p| p.passes.iter())
        .map(|pass| pass.unreadable_bytes)
        .sum();
    eprintln!("  mapped process bytes that would not read: {unreadable}");

    // **The oracle's process still reports the oracle's eight**, in a run that
    // searched every other process as well. `FORENSIC-W11` is this machine's
    // own host name, so most processes on it hold the string somewhere; what
    // must not move is the count and the addresses for the one process
    // upstream was asked about. A scan that read one address space through
    // another's page tables would shift exactly this number.
    let taskhostw = survey
        .processes
        .iter()
        .find(|p| p.pid == Some(4708))
        .expect("pid 4708 is on this capture's process list");
    assert_eq!(taskhostw.name.as_deref(), Some("taskhostw.exe"));
    assert_eq!(taskhostw.matches, 8, "the eight `vadyarascan` prints");
    let in_4708: Vec<u64> = survey
        .matches
        .iter()
        .filter(|m| {
            matches!(
                &m.scope,
                seance_plugin_memory_windows::pattern_scan::MatchScope::Process { pid, .. }
                    if *pid == Some(4708)
            )
        })
        .map(|m| m.address)
        .collect();
    assert_eq!(
        in_4708,
        vec![
            0x2ca2f84c44e,
            0x2ca2f84d9ed,
            0x2ca2f8508cb,
            0x2ca2f8511ba,
            0x2ca2f991c4b,
            0x2ca2f991d0d,
            0x2ca2f99206c,
            0x2ca2f992093,
        ],
        "the same addresses as the pid-scoped run, with every other process scanned too"
    );
    // **The clean-capture baseline**, measured 2026-09-15 and recorded in
    // `seance_memory/tests/KNOWN_ANSWERS.md`. `FORENSIC-W11` is this machine's
    // own host name, so it is in most of its processes: 1,482 matches across
    // 116 of 129 processes, over 3,361,828,864 bytes of mapped process memory,
    // with **not one mapped byte unread**. The busiest process is a
    // `svchost.exe` with 540.
    //
    // Pinned exactly, not as a floor. This is what the stage says about an
    // image nothing is wrong with, and a number that moves is either a change
    // in what is planned or a change in what is read -- both of which an
    // examiner would want to know about before trusting the next answer.
    assert_eq!(
        survey.processes.len(),
        129,
        "every process on this capture's active list"
    );
    assert_eq!(matched.len(), 116, "processes holding the host name at all");
    assert_eq!(
        survey.processes.iter().map(|p| p.matches).sum::<u64>(),
        1482,
        "matches in process memory"
    );
    assert_eq!(
        survey
            .processes
            .iter()
            .map(ProcessScan::bytes_scanned)
            .sum::<u64>(),
        3_361_828_864,
        "mapped process bytes examined"
    );
    assert_eq!(survey.processes.iter().map(|p| p.matches).max(), Some(540));

    // **Not one mapped byte of any process went unread.**
    assert_eq!(unreadable, 0);

    // Every process is accounted for: searched, or carrying a reason.
    assert_eq!(
        survey.processes.len(),
        list.processes.len(),
        "a process on the list with no row at all would be an unexplained silence"
    );
    for process in &survey.processes {
        assert!(
            process.not_scanned.is_some() || !process.passes.is_empty(),
            "pid {:?} was neither searched nor given a reason",
            process.pid
        );
    }

    // **The kernel's own space was searched** -- upstream's `yarascan` route --
    // and a match there carries no allocation, with the reason.
    //
    // Pinned, and the number is the point: before `MEM-025` this sweep
    // enumerated **156 KiB** and reported itself complete, because the walk
    // read the non-addressable middle of the 64-bit space as the end of it and
    // the kernel's whole half lies above that gap.
    assert_eq!(survey.kernel.len(), 1, "one pass for the one pattern set");
    let kernel = &survey.kernel[0];
    assert_eq!(
        kernel.sections, 8084,
        "mapped regions of the kernel's space"
    );
    assert_eq!(kernel.bytes_scanned, 2_212_950_016);
    assert_eq!(kernel.hits.len(), 105, "the host name in kernel memory");
    assert_eq!(kernel.unreadable_bytes, 0);
    assert!(kernel.capped.is_none(), "{:?}", kernel.capped);
    assert!(survey.kernel_not_scanned.is_none());
    assert_eq!(
        survey.matches_total, 1587,
        "1,482 in process memory and 105 in the kernel's"
    );
    assert_eq!(survey.bytes_scanned, 5_574_778_880);
    for row in survey.matches.iter().filter(|m| {
        matches!(
            m.scope,
            seance_plugin_memory_windows::pattern_scan::MatchScope::Kernel
        )
    }) {
        assert!(row.region.is_none());
    }

    assert!(
        survey.refused_chunks.is_empty(),
        "{:?}",
        survey.refused_chunks
    );
}

/// **`vadregexscan`: a second engine, the same plan, the same eight
/// addresses** (`ROADMAP` §5.3).
///
/// The regex route and the YARA route are two different engines driven over one
/// plan. Run in the **same pass** over the same process, they must agree
/// exactly: a difference would mean the disagreement is in the planning or the
/// attribution rather than in either engine, which is the failure neither
/// engine's own tests can see.
///
/// Upstream's `windows.vadregexscan --pid 4708 --pattern FORENSIC-W1[0-9]` is
/// the comparable plugin. It is not run here as an oracle — the YARA oracle
/// above already fixes the eight addresses, and a regex of a literal string
/// must find the same bytes — so what this pins is the agreement of the two
/// routes this build ships.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_regex_route_and_the_yara_route_agree_on_the_same_process() {
    use seance_plugin_memory_windows::pattern_scan::{
        scan_patterns, MatchScope, PatternScanConfig, PatternScanSymbols, PatternSet, REGEX_SCOPE,
    };
    use seance_plugin_memory_windows::process::{
        list_processes, ProcessListConfig, ProcessSymbols,
    };
    use seance_plugin_yara::memory::{MemoryYaraScanner, CONDITION_SCOPE};
    use seance_plugin_yara::YaraScanner;
    use std::io::Write;

    let Some(profile) = corpus_profile() else {
        eprintln!("skipping: capture not present");
        return;
    };

    let dir = tempfile::tempdir().expect("temp dir");
    let mut file = std::fs::File::create(dir.path().join("marker.yar")).expect("create");
    file.write_all(
        br#"rule forensic_w11_marker {
  strings: $a = "FORENSIC-W11"
  condition: $a
}"#,
    )
    .expect("write");
    drop(file);
    let rules = Arc::new(YaraScanner::from_rule_path(dir.path()).expect("the rules compile"));
    let engine = Arc::new(MemoryYaraScanner::new("yara.memory", Arc::clone(&rules)));
    let yara = PatternSet {
        kind: "yara",
        source: dir.path().display().to_string(),
        pattern_names: rules.rule_identifiers(),
        diagnostics: Some(Arc::clone(&engine) as Arc<dyn seance_memory::scan::ScannerDiagnostics>),
        scanner: engine as Arc<dyn seance_memory::scan::Scanner>,
        scope_note: Some(CONDITION_SCOPE.to_string()),
    };
    // A pattern that is not a plain string, so the regex engine is really
    // doing the work: a character class the literal cannot stand in for.
    let pattern = "FORENSIC-W1[0-9]";
    let regex = PatternSet {
        kind: "regex",
        source: pattern.to_string(),
        pattern_names: vec![pattern.to_string()],
        diagnostics: None,
        scanner: Arc::new(
            seance_memory::scan::RegexScanner::new("regex.memory", pattern)
                .expect("a valid pattern"),
        ),
        scope_note: Some(REGEX_SCOPE.to_string()),
    };

    let ps = ProcessSymbols::from_profile(profile).expect("process symbols");
    let list = list_processes(profile, &ps, &ProcessListConfig::default()).expect("the list walks");
    let symbols = PatternScanSymbols::from_profile(profile).expect("a describable build");
    let config = PatternScanConfig {
        pids: Some(vec![4708]),
        include_kernel: false,
        ..PatternScanConfig::default()
    };
    // Both sets in one call: two passes over one plan, which is what makes the
    // comparison a statement about the plan.
    let survey = scan_patterns(profile, &symbols, Some(&list), &[yara, regex], &config);

    let addresses = |kind: &str| -> Vec<u64> {
        survey
            .matches
            .iter()
            .filter(|m| m.kind == kind)
            .filter(|m| matches!(&m.scope, MatchScope::Process { pid, .. } if *pid == Some(4708)))
            .map(|m| m.address)
            .collect()
    };
    let by_yara = addresses("yara");
    let by_regex = addresses("regex");
    eprintln!(
        "pid 4708: {} yara match(es), {} regex match(es)",
        by_yara.len(),
        by_regex.len()
    );

    assert_eq!(
        by_yara,
        vec![
            0x2ca2f84c44e,
            0x2ca2f84d9ed,
            0x2ca2f8508cb,
            0x2ca2f8511ba,
            0x2ca2f991c4b,
            0x2ca2f991d0d,
            0x2ca2f99206c,
            0x2ca2f992093,
        ]
    );
    assert_eq!(
        by_regex, by_yara,
        "two engines over one plan must find the same bytes at the same addresses"
    );
    // Two passes, two sets, and the record says which engine each row came
    // from -- so a reader can tell the two apart rather than seeing sixteen
    // matches of one thing.
    assert_eq!(survey.matches_total, 16);
    assert_eq!(survey.sets.len(), 2);
    assert_eq!(survey.processes.len(), 1);
    assert_eq!(survey.processes[0].passes.len(), 2);
    assert_eq!(survey.processes[0].matches, 16);
    // Every match of both engines is inside the allocation the row names.
    for row in &survey.matches {
        let region = row.region.as_ref().expect("an allocation");
        assert!(region.start <= row.address && row.address <= region.end);
    }
    // And each set's own caveat is on the record.
    let json = survey.to_json();
    let notes = json["scope_notes"].as_array().expect("scope notes");
    assert_eq!(notes.len(), 2);
    assert!(notes
        .iter()
        .any(|n| n.as_str().is_some_and(|s| s.contains("one CHUNK"))));
    assert!(notes
        .iter()
        .any(|n| n.as_str().is_some_and(|s| s.contains("RAW BYTES"))));
}

/// **An examiner's rules over a reconstructed hibernation file** (`ROADMAP`
/// §3.8 — "run the §2.1 selectors and YARA over a reconstructed hibernation or
/// swap blob, which nothing does today").
///
/// A hibernation file holds physical memory Xpress-compressed, so a rule run
/// over the file on the disk image finds nothing at all: the bytes an examiner
/// is hunting for are not in it in any recognisable form. The image-level
/// pattern scan searches the **reconstructed** space instead, which is the
/// only route for a capture with no page tables to plan from.
///
/// The ground truth is exact (`~/win11-lab/hiber/GROUND-TRUTH.txt`):
/// before hibernating, the corpus machine filled a resident 256 MiB buffer with
/// one marker per 4 KiB page — `"HIBRMARK"` followed by the page index — so a
/// correct reconstruction holds those **65,536** pages. A string search counts
/// every occurrence of the string, and this reconstruction holds more of them
/// than 65,536: each marked page is at two physical addresses, and the
/// script's own source text is in memory too. So the count this test pins is
/// what a rules search *sees*, and the accounting of it — exactly 65,536
/// distinct byte-exact marker pages, each at exactly two addresses, plus 38
/// occurrences inside other pages — is asserted where a page can be told
/// from a copy of one, in `seance_memory/tests/hibernation_corpus_test.rs`.
/// That the 131,072 addresses are page numbers the file's kernel set names
/// once each, and the boot set never, is not asserted by any test: it was
/// measured by an independent walk of the file's table entries, recorded in
/// that test's module doc.
///
/// The default pass cannot count them: the reconstruction holds more
/// occurrences than the shipped match ceiling (`MAX_HITS_PER_SPACE`), so what
/// that pass reports is the ceiling and the statement that it fired. The exact
/// count is taken with the ceiling raised, in the same test.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn an_examiners_rules_search_a_reconstructed_hibernation_file() {
    use seance_core::module::ForensicsModule;
    use seance_memory::patterns::{ImagePatternScan, PatternSet};
    use seance_plugin_yara::memory::{MemoryYaraScanner, CONDITION_SCOPE};
    use seance_plugin_yara::YaraScanner;
    use std::io::Write;

    let Some(path) = hiberfil_path() else {
        eprintln!("skipping: set SEANCE_WIN_HIBERFIL to a hiberfil.sys");
        return;
    };
    let source: Arc<dyn DataSource> =
        Arc::new(seance_core::data_source::FileDataSource::new(path).expect("open hiberfil"));

    // **Through the container stage, not around it.** That stage is what
    // decodes the file and records the geometry of what it recovered, and the
    // geometry is what keeps the scan from reading -- and reporting as
    // unreadable -- the 10.6 GB of address space a sparse reconstruction does
    // not fill. A hand-built record without it measured 64 MiB of coverage and
    // called the other ten gigabytes evidence it could not read.
    let evidence = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(Arc::clone(&source)),
        serde_json::json!({
            "name": "hiberfil.sys",
            "memory_image_format": "hibernation",
        }),
    );
    let produced = seance_memory::module::MemoryImageModule
        .process(&evidence)
        .expect("the container stage decodes this file");
    let record = produced
        .into_iter()
        .find(|a| a.metadata["type"] == "MemoryImage")
        .expect("an image record");
    assert_eq!(record.metadata["image_format"], "windows_hibernation");
    eprintln!(
        "  reconstructed: {} addressable byte(s), {} backed range(s)",
        record.metadata["addressable_bytes"],
        record.metadata["backed_ranges"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0),
    );

    let dir = tempfile::tempdir().expect("temp dir");
    let mut file = std::fs::File::create(dir.path().join("marker.yar")).expect("create");
    file.write_all(
        br#"rule hibernation_marker {
  strings: $a = "HIBRMARK"
  condition: $a
}"#,
    )
    .expect("write");
    drop(file);
    let rules = Arc::new(YaraScanner::from_rule_path(dir.path()).expect("the rules compile"));
    let engine = Arc::new(MemoryYaraScanner::new("yara.memory", Arc::clone(&rules)));
    let set = PatternSet {
        kind: "yara",
        source: dir.path().display().to_string(),
        pattern_names: rules.rule_identifiers(),
        diagnostics: Some(Arc::clone(&engine) as Arc<dyn seance_memory::scan::ScannerDiagnostics>),
        scanner: engine as Arc<dyn seance_memory::scan::Scanner>,
        scope_note: Some(CONDITION_SCOPE.to_string()),
    };

    let started = std::time::Instant::now();
    let out = ImagePatternScan::new(vec![set])
        .expect("one set is a module")
        .process(&record)
        .expect("the reconstructed space is readable");
    let elapsed = started.elapsed();

    assert_eq!(out.len(), 1, "one record for the image");
    let md = &out[0].metadata;
    eprintln!(
        "hibernation pattern scan in {elapsed:?}: {} match(es) over {} byte(s); pass {}",
        md["matches_total"], md["bytes_scanned"], md["passes"][0]
    );
    eprintln!("  first rows: {}", md["matches"][0]);

    // **`MEM-026`, closed: both restore sets walk to the page counts the
    // header states, and the record says so.**
    //
    // Until 2026-09-18 this test pinned the defect: 7 marker strings, 163 MiB
    // of a 10 GiB space, both walks stopped about 30 MB in. The kernel walk
    // stopped because the compressed-size field of a table header is 21 bits
    // and bit 29 is a flag, read as size; the boot walk had in fact reached
    // its header's count all along. The numbers below are the fixed state,
    // measured on the corpus file.
    let notes = &record.metadata["layer_meta"]["notes"];
    let sets = notes["hibernation_restore_sets"]
        .as_array()
        .expect("the record carries one entry per restore set");
    assert_eq!(sets.len(), 2, "{sets:?}");
    let set = |name: &str| {
        sets.iter()
            .find(|s| s["set"] == name)
            .unwrap_or_else(|| panic!("no record for the {name} set: {sets:?}"))
    };
    let boot = set("boot");
    assert_eq!(boot["pages"], 40_004, "{boot}");
    assert_eq!(boot["header_count"], 40_004, "{boot}");
    assert_eq!(boot["complete"], true, "{boot}");
    let kernel = set("kernel");
    assert_eq!(kernel["pages"], 511_499, "{kernel}");
    assert_eq!(kernel["header_count"], 511_499, "{kernel}");
    assert_eq!(kernel["complete"], true, "{kernel}");
    assert_eq!(notes["hibernation_pages_restored"], 551_503);
    assert_eq!(notes["hibernation_restored_bytes"], 2_258_956_288_u64);
    assert_eq!(
        record.metadata["content_complete"], true,
        "nothing on the record says a walk stopped: {}",
        record.metadata["incomplete"]
    );
    assert!(
        record.metadata["incomplete"].is_null(),
        "{}",
        record.metadata["incomplete"]
    );

    // **The default pass hits the match ceiling, and says so.** A rules search
    // an examiner runs as shipped stops at `MAX_HITS_PER_SPACE` matches; the
    // reconstruction holds more occurrences of the string than that, so what
    // that pass reports is the ceiling, `truncated`, and the statement of
    // which ceiling fired -- not a count. Pinned so that the ceiling can never
    // be mistaken for the number of marked pages.
    assert_eq!(
        md["matches_total"].as_u64(),
        Some(seance_memory::patterns::MAX_HITS_PER_SPACE as u64),
        "the default ceiling fires on this file"
    );
    assert_eq!(md["passes"][0]["truncated"], true, "{}", md["passes"][0]);
    assert_eq!(md["passes"][0]["complete"], false, "{}", md["passes"][0]);
    let capped = md["passes"][0]["capped"]
        .as_str()
        .expect("the ceiling is named");
    assert!(
        capped.contains("the match ceiling of 100000 fired"),
        "{capped}"
    );
    // MEM-041: the capped pass read everything it asked for. What lay past the
    // ceiling was not searched, and is not reported as unreadable. Before the
    // fix this pass reported 4,554,682,367 unreadable bytes.
    assert_eq!(
        md["passes"][0]["unreadable_bytes"], 0,
        "{}",
        md["passes"][0]
    );
    assert!(
        md["passes"][0]["not_searched_bytes"].as_u64().unwrap_or(0) > 0,
        "{}",
        md["passes"][0]
    );

    // **With the ceiling raised, the count is exact and the pass is complete.**
    // Every byte the reconstruction holds is scanned -- `bytes_scanned` is the
    // restored byte count -- and nothing is unreadable.
    let rules = Arc::new(YaraScanner::from_rule_path(dir.path()).expect("the rules compile"));
    let engine = Arc::new(MemoryYaraScanner::new("yara.memory", Arc::clone(&rules)));
    let uncapped_set = PatternSet {
        kind: "yara",
        source: dir.path().display().to_string(),
        pattern_names: rules.rule_identifiers(),
        diagnostics: Some(Arc::clone(&engine) as Arc<dyn seance_memory::scan::ScannerDiagnostics>),
        scanner: engine as Arc<dyn seance_memory::scan::Scanner>,
        scope_note: Some(CONDITION_SCOPE.to_string()),
    };
    let mut caps = seance_memory::patterns::PatternCaps::default();
    caps.scan.max_hits = 2_000_000;
    let started = std::time::Instant::now();
    let full = ImagePatternScan::with_caps(vec![uncapped_set], caps)
        .expect("one set is a module")
        .process(&record)
        .expect("the reconstructed space is readable");
    let full = &full[0].metadata;
    eprintln!(
        "hibernation pattern scan with the ceiling raised, in {:?}: {} match(es) over {} \
         byte(s); pass {}",
        started.elapsed(),
        full["matches_total"],
        full["bytes_scanned"],
        full["passes"][0]
    );
    assert_eq!(
        full["passes"][0]["truncated"], false,
        "{}",
        full["passes"][0]
    );
    assert_eq!(full["passes"][0]["complete"], true, "{}", full["passes"][0]);
    assert_eq!(
        full["passes"][0]["unreadable_bytes"], 0,
        "{}",
        full["passes"][0]
    );
    assert_eq!(
        full["bytes_scanned"].as_u64(),
        Some(2_258_956_288),
        "every restored byte was searched: {}",
        full["bytes_scanned"]
    );
    // Measured 2026-09-19 with the ceiling raised: the number of `"HIBRMARK"`
    // strings in the reconstruction. More than the 65,536 marked pages, and
    // accounted for page by page in `seance_memory`'s corpus test, which
    // asserts that every one of the 65,536 marker pages is byte-exact at
    // exactly two physical addresses (131,072) and that the remaining 38 are
    // the string inside other pages -- 33 of them the marker script's source
    // text, 5 in binary structures. That each of the 131,072 addresses is a
    // page number the file's kernel set names once is measured by an
    // independent table walk described in that test's module doc, not
    // asserted. A known answer, pinned as measured; a wrong decompression or
    // a page placed where the file does not put it changes it.
    let strings = full["matches_total"].as_u64().expect("a count");
    assert!(
        strings >= 65_536,
        "at least one string per marked page: {strings}"
    );
    assert_eq!(
        strings, MARKER_STRINGS_IN_THE_RECONSTRUCTION,
        "the measured answer over the reconstruction"
    );
    assert_eq!(
        full["matches_by_pattern"]["hibernation_marker"].as_u64(),
        Some(strings)
    );

    // **And the record says what an address in it is**, because for this format
    // it is nothing like an offset in the file on the disk image.
    let meaning = md["offset_meaning"].as_str().expect("a statement");
    assert!(
        meaning.contains("not an offset in `hiberfil.sys`"),
        "{meaning}"
    );
    assert_eq!(md["refused_chunks"].as_array().map(Vec::len), Some(0));

    // **The whole point, as a differential.** The same rule and the same
    // engine, pointed at the FILE rather than at the reconstructed space,
    // answers a different question -- and the numbers show it three ways.
    let over_the_file = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(Arc::clone(&source)),
        serde_json::json!({
            "type": "MemoryImage",
            "subtype": "memory_image",
            // Declared raw, which is what an examiner pointing a scanner at the
            // file itself would be doing.
            "image_format": "raw",
        }),
    );
    let rules = Arc::new(YaraScanner::from_rule_path(dir.path()).expect("the rules compile"));
    let engine = Arc::new(MemoryYaraScanner::new("yara.memory", Arc::clone(&rules)));
    let flat_set = PatternSet {
        kind: "yara",
        source: dir.path().display().to_string(),
        pattern_names: rules.rule_identifiers(),
        diagnostics: Some(Arc::clone(&engine) as Arc<dyn seance_memory::scan::ScannerDiagnostics>),
        scanner: engine as Arc<dyn seance_memory::scan::Scanner>,
        scope_note: Some(CONDITION_SCOPE.to_string()),
    };
    let flat = ImagePatternScan::new(vec![flat_set])
        .expect("one set is a module")
        .process(&over_the_file)
        .expect("the file is readable");
    eprintln!(
        "  over the compressed file: {} match(es) in {} byte(s)",
        flat[0].metadata["matches_total"], flat[0].metadata["bytes_scanned"]
    );
    // Measured 2026-09-15: **863**, against 131,110 in the reconstruction and
    // 65,536 pages in the machine. Re-measured 2026-09-19 and unchanged: the
    // file did not change, only its reading. Not zero, because a hibernation
    // file stores a block that did not compress at its full size, so some
    // marked pages are in it verbatim -- and not the machine's count either,
    // because most are Xpress-compressed and unrecognisable as the string.
    //
    // Three numbers for one question, which is the point: a match at a file
    // offset in a compressed container cannot be placed in the machine's
    // memory, cannot be told from a stale page of an earlier hibernation, and
    // is not comparable with either of the others. The reconstruction's
    // matches are at physical addresses.
    assert_eq!(
        flat[0].metadata["matches_total"].as_u64(),
        Some(863),
        "the measured answer over the compressed file"
    );
    let flat_meaning = flat[0].metadata["offset_meaning"]
        .as_str()
        .expect("a statement");
    assert!(
        flat_meaning.contains("only if that declaration is true"),
        "a scan of the file declares what its offsets are not: {flat_meaning}"
    );
}

/// **A sparse image analysed the way the product analyses one: through the
/// record, not around it** (`MEM-027`).
///
/// The corpus file behind `SEANCE_WIN_CRASHDUMP` on this machine is an **ELF
/// core** written by the hypervisor (`7f 45 4c 46`, seven `PT_LOAD` segments),
/// not a PAGEDU64 dump — which is exactly the kind of image this test is for:
/// sparse, with a geometry the container stage records.
///
/// Every other corpus test here hands the analysis a layer it built itself. The
/// product does not: the container stage decodes the image, records the
/// geometry of what it recovered, and hands the decoded space down as a
/// `DataSource`; the analysis then rebuilds a `PhysicalLayer` over it from that
/// geometry. For a **sparse** image — a crash dump that skips page zero, a
/// hibernation reconstruction, LiME — that rebuilt layer reports a window
/// inside a hole as `Ok` with no runs, and until `MEM-027` every scan-based
/// stage read that as a layer that could not describe itself and refused.
///
/// So this is the test that exercises the seam the others skip. If it fails
/// while `the_crash_dump_decodes_to_the_same_kernel_the_raw_capture_found`
/// passes, the defect is in the round trip and not in the format reader.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn a_sparse_image_is_analysed_through_the_record_the_container_stage_emits() {
    use seance_core::module::ForensicsModule;

    let Some(path) = crashdump_path() else {
        eprintln!("skipping: set SEANCE_WIN_CRASHDUMP to a PAGEDU64 crash dump");
        return;
    };
    let source: Arc<dyn DataSource> =
        Arc::new(seance_core::data_source::FileDataSource::new(path).expect("open the dump"));
    let evidence = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(source),
        serde_json::json!({"name": "memory-unlocked.dmp"}),
    );

    // 1. The container stage, exactly as an ingest runs it.
    let produced = seance_memory::module::MemoryImageModule
        .process(&evidence)
        .expect("the container stage decodes this image");
    let record = produced
        .into_iter()
        .find(|a| a.metadata["type"] == "MemoryImage")
        .expect("an image record");
    let ranges = record.metadata["backed_ranges"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    eprintln!(
        "image record: {} ({} addressable byte(s), {ranges} backed range(s))",
        record.metadata["image_format"], record.metadata["addressable_bytes"]
    );
    assert!(
        ranges > 1,
        "this image is sparse; a record with no geometry would not exercise this seam"
    );

    // 2. The analysis, over that record rather than over a layer of our own.
    let out =
        MemoryAnalysisModule::new(WindowsMemoryAnalysis::new().with_symbol_dirs(symbol_dirs()))
            .process(&record)
            .expect("the analysis runs over the decoded record");

    // The profile record carries `type` rather than `record_type`: it is the
    // analysis's own account of the image and not one of the stages.
    let profile = out
        .iter()
        .find(|a| a.metadata["type"] == "MemoryProfile")
        .expect("a profile record: without one, discovery failed on the round trip");
    eprintln!(
        "  discovered: dtb {} ({}), kernel base {} ({}), {} {}",
        profile.metadata["dtb"],
        profile.metadata["dtb_evidence"],
        profile.metadata["kernel_base"],
        profile.metadata["kernel_base_evidence"],
        profile.metadata["pdb"],
        profile.metadata["pdb_guid"],
    );
    assert_eq!(
        profile.metadata["pdb_guid"], "E6426A07C26E66F8EB8594621A7B273B",
        "the same kernel the raw capture of this machine reads"
    );
    assert_ne!(profile.metadata["dtb"], serde_json::json!(0));

    // **The process list walked**, which is the other half of the round trip:
    // discovery proved the address space and a structural walk read it.
    let list = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemoryProcessList")
        .expect("the process list must be walked over a sparse image");
    let walked = list.metadata["processes"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    eprintln!("  process list: {walked} process(es)");
    assert!(
        walked > 100,
        "this machine had 129 processes; {walked} means the round trip lost the address space"
    );

    // **And the pool sweep swept.** This is the stage that could not run at
    // all before `MEM-027`: it derives its sections from the layer, and a
    // layer that reported a hole-only window as `Ok` with no runs ended the
    // derivation at the first hole. A sparse image's first page is very often
    // a hole.
    let pool = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemoryPoolScan")
        .expect("the pool sweep must produce a record over a sparse image");
    let objects = pool.metadata["objects"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    eprintln!(
        "  pool sweep: {objects} object(s) from {} candidate(s)",
        pool.metadata["candidates"],
    );
    assert!(
        objects > 100,
        "a sweep of a capture of this machine finds its processes in pool memory; {objects} \
         means the sweep read nothing"
    );
}

/// **The `strings` route, graded on real evidence against the criterion the
/// roadmap set: a physical offset inside a page mapped by two processes must
/// name both.**
///
/// Ground truth is established by the *other* walker, so the test is not
/// circular. `KUSER_SHARED_DATA` is one physical frame mapped into every
/// process at the same virtual address, `0x7FFE0000`. `PageWalk::translate` —
/// the upward walk, tested on its own against hand-built hierarchies — is asked
/// for that address in several processes' own address spaces, and it answers
/// with the same physical frame each time. The reverse mapping must then
/// attribute that physical offset to every one of those processes.
///
/// This is also the exact offset upstream's `windows.strings` gets wrong. Its
/// per-process branch keys its reverse map by the *virtual* page number, so
/// asking it about physical `0x7ffe0000` returns 123 of 130 processes — not
/// because they map that frame, but because `0x7ffe0` is `KUSER_SHARED_DATA`'s
/// virtual page in each of them. Measured on this same capture, 2026-09-15.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "walks every process's page tables; run with --release"
)]
fn a_physical_offset_two_processes_map_names_both_of_them() {
    use std::sync::atomic::AtomicU64;

    use seance_memory::translate::{PageWalk, TableCache, TranslationPolicy};
    use seance_plugin_memory_windows::modules::{ModuleSymbols, ModuleWalkConfig, ProcessSpace};
    use seance_plugin_memory_windows::process::{self, ProcessListConfig};
    use seance_plugin_memory_windows::strings_map::{self, Radix, StringsMapConfig, StringsSource};

    /// The virtual address `KUSER_SHARED_DATA` is mapped at in every user
    /// process, fixed by the Windows ABI.
    const KUSER_SHARED_DATA: u64 = 0x7FFE_0000;

    let Some(path) = capture_path() else {
        eprintln!("skipping: capture not present");
        return;
    };
    let source: Arc<dyn DataSource> =
        Arc::new(seance_core::data_source::FileDataSource::new(path).expect("open"));
    let physical: Arc<dyn MemoryLayer> =
        Arc::new(PhysicalLayer::raw(source).expect("a raw image is a physical layer"));
    let profile = automagic::discover(physical, &symbol_dirs(), &DiscoveryOptions::default())
        .expect("discovery must succeed on this capture");

    let symbols = ModuleSymbols::from_profile(&profile).expect("this build declares _EPROCESS");
    let process_symbols =
        process::ProcessSymbols::from_profile(&profile).expect("the process list is readable");
    let list = process::list_processes(&profile, &process_symbols, &ProcessListConfig::default())
        .expect("the process list must walk");
    assert!(
        list.processes.len() > 100,
        "this machine had 129 processes, got {}",
        list.processes.len()
    );

    // Ground truth, from the upward walk and from nothing this test is about
    // to exercise.
    let config = ModuleWalkConfig::default();
    // This corpus is x64, which the discovery above has already established;
    // the stage itself derives the spec from the profile rather than being
    // told.
    assert!(
        profile.is_64bit(),
        "this capture is an x64 Windows 11 machine"
    );
    let spec = seance_memory::translate::PagingSpec::new(
        seance_memory::translate::PagingMode::Intel32e,
        seance_memory::translate::PteSemantics::Windows,
    );
    let cache = TableCache::new();
    let suppressed = AtomicU64::new(0);
    let walk = PageWalk::new(
        profile.physical.as_ref(),
        &spec,
        &cache,
        TranslationPolicy::default(),
        &suppressed,
    );

    let mut expected: Vec<(String, u64)> = Vec::new();
    let mut shared_frame = None;
    for record in &list.processes {
        let Ok(space) = ProcessSpace::build(&profile, &symbols, record.address, &config) else {
            continue;
        };
        let Ok(translation) = walk.translate(space.dtb(), KUSER_SHARED_DATA) else {
            continue;
        };
        let name = record.image_file_name.known().cloned().unwrap_or_default();
        let pid = record.pid.known().copied().unwrap_or(0);
        match shared_frame {
            None => shared_frame = Some(translation.phys),
            Some(frame) => assert_eq!(
                translation.phys, frame,
                "KUSER_SHARED_DATA is one frame; {name} ({pid}) translated it elsewhere"
            ),
        }
        expected.push((format!("{name} ({pid})"), translation.phys));
        if expected.len() == 8 {
            break;
        }
    }
    let frame = shared_frame.expect("some process maps KUSER_SHARED_DATA");
    assert!(
        expected.len() >= 2,
        "the criterion needs two processes mapping one frame, found {}",
        expected.len()
    );
    eprintln!(
        "  ground truth: KUSER_SHARED_DATA is physical {frame:#x}, mapped by {} processes \
         including {}",
        expected.len(),
        expected
            .iter()
            .map(|(label, _)| label.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // A byte inside that frame, written as `strings -t d` would write it.
    let offset = frame + 0x40;
    let file = format!("{offset} A_STRING_INSIDE_KUSER_SHARED_DATA\n");
    let source = StringsSource::read("kuser.strings", Radix::Decimal, file.as_bytes())
        .expect("an in-memory strings file");
    assert_eq!(source.len(), 1);
    assert_eq!(source.malformed_lines, 0);

    let mapped = strings_map::map_strings(
        &profile,
        &symbols,
        Some(&list),
        Some(&source),
        &StringsMapConfig::default(),
    )
    .expect("the stage runs on this capture");

    let answer = &mapped.answers()[0];
    let attribution = &answer.attribution;
    eprintln!(
        "  answer: {} owner(s) for {:#x} ({}), verdict {}",
        attribution.owners_total,
        offset,
        answer.text,
        attribution.verdict.as_str()
    );
    assert!(
        attribution.owners_total >= 2,
        "a frame every process maps must name more than one of them, got {}",
        attribution.owners_total
    );

    // And the owners are the processes the upward walk independently named.
    let record = mapped.to_json();
    let named: Vec<String> = record["offsets"][0]["owners"]
        .as_array()
        .expect("owners is an array")
        .iter()
        .filter_map(|owner| owner["space"].as_str().map(str::to_string))
        .collect();
    for (label, _) in expected.iter().take(2) {
        assert!(
            named.iter().any(|owner| owner == label),
            "{label} maps this frame according to the upward walk, and the reverse map did not \
             name it; named: {named:?}"
        );
    }

    // Every owner states the virtual address in ITS OWN space, and for this
    // frame the ABI fixes what that address is.
    for owner in record["offsets"][0]["owners"].as_array().unwrap() {
        if owner["space"] == "kernel" {
            continue;
        }
        assert_eq!(
            owner["virtual_address"],
            format!("{:#x}", KUSER_SHARED_DATA + 0x40),
            "KUSER_SHARED_DATA is at a fixed user-mode address: {owner}"
        );
    }

    // The physical offset is not in the same column as any virtual address,
    // which is the shape upstream's own two branches disagree about.
    assert_eq!(
        record["offsets"][0]["physical_offset"],
        format!("{offset:#x}")
    );

    // A real capture has suppressed uniform tables and trimmed shared pages in
    // it, so the honest verdict here is the qualified one -- and a run that
    // claimed otherwise on this image would be the defect.
    eprintln!(
        "  coverage: {} shortfall(s); {} table(s) read, {} byte(s); {} subtree(s) declined as \
         the kernel's own",
        record["coverage_shortfalls"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0),
        record["cost"]["tables_read"],
        record["cost"]["table_bytes_read"],
        record["spaces"]["shared_subtrees_declined"],
    );
    eprintln!(
        "  prototypes: {} entry(ies), {} hop(s), {} unresolved",
        record["cost"]["prototype_entries"],
        record["cost"]["prototype_hops"],
        record["cost"]["prototypes_unresolved"],
    );
    if let Some(first) = record["coverage_shortfalls"]
        .as_array()
        .and_then(|a| a.first())
    {
        eprintln!(
            "  first shortfall: {} -- {}",
            first["space"], first["detail"]
        );
    }
    assert!(
        record["spaces"]["shared_subtrees_declined"]
            .as_u64()
            .is_some_and(|n| n > 100),
        "every process maps the same kernel through the same top-level entries, so the parity \
         must decline them rather than walk the kernel once per process: {}",
        record["spaces"]["shared_subtrees_declined"]
    );
    assert!(
        matches!(
            attribution.verdict,
            seance_memory::reverse::Verdict::Mapped
                | seance_memory::reverse::Verdict::MappedAndCoverageShort
        ),
        "a frame with owners is reported as mapped, got {:?}",
        attribution.verdict
    );
}

/// Suspicious-thread evidence measured on this clean capture (MEM-024).
///
/// The capture is a clean machine: nothing was injected into it, so every
/// evidence finding here would be a false positive. Measured 2026-09-27 on
/// build 26200: 123 processes judged, 0 evidence, 0 gaps, 0 user starts
/// unattributed, 78 kernel-mode starts -- 2 on kernel threads, 76 on threads
/// whose `SystemThread` bit is clear (see below).
/// No JIT or CLR thread on this capture started in private memory: msedge,
/// msedgewebview2 and MsMpEng all start their threads through image code. That
/// is an observation about this capture, not a rule about JITs.
const WIN11_SUSPICIOUS_THREAD_EVIDENCE: u64 = 0;
/// Kernel-mode starts on threads whose `_KTHREAD.SystemThread` is set,
/// measured on the same capture.
///
/// Re-measured 2026-09-27 after review: the first count, 78, took every
/// kernel address as a kernel thread. Only 2 are on threads flagged as kernel
/// threads; the other 76 (csrss, winlogon, services, lsass, svchost, most in
/// session space at `0xffffcc81...`) are on threads whose `SystemThread` bit
/// read **clear**. The `tamper_checks` orphan-thread group excludes every such
/// thread as a user thread, so no stage judges those 76 and the survey says it
/// is incomplete rather than calling them kernel threads.
const WIN11_KERNEL_MODE_STARTS: u64 = 2;
/// Kernel-mode starts on threads not flagged as kernel threads, same capture.
const WIN11_KERNEL_STARTS_ON_THREADS_NOT_KNOWN_AS_SYSTEM: u64 = 76;

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn suspicious_threads_on_the_clean_win11_capture() {
    let out = require_capture!();
    let rec = out
        .iter()
        .find(|a| a.metadata["record_type"] == "MemorySuspiciousThreads")
        .expect("the suspicious-thread stage must produce a record");
    let m = &rec.metadata;
    eprintln!(
        "suspicious threads: {} judged ({} analysed), {} out of scope, {} skipped; evidence {} \
         {:?}, gaps {}, starts outside the tree {}, kernel starts {}, protections {}, complete {}",
        m["processes_judged"],
        m["processes_analysed"],
        m["out_of_scope_total"],
        m["skipped_total"],
        m["evidence_count"],
        m["evidence_by_kind"],
        m["gap_count"],
        m["starts_outside_the_tree"],
        m["starts_in_kernel_space"],
        m["protections_available"],
        m["complete"],
    );
    for skipped in m["skipped"].as_array().into_iter().flatten() {
        eprintln!(
            "  skipped {} {}: {}",
            skipped["pid"], skipped["image_file_name"], skipped["reason"]
        );
    }
    let mut named = Vec::new();
    for process in m["processes"].as_array().expect("an array of processes") {
        if process["starts_outside_the_tree"].as_u64().unwrap_or(0) > 0
            || process["kernel_starts_on_threads_not_known_as_system"]
                .as_u64()
                .unwrap_or(0)
                > 0
            || process["analysed"] == false
        {
            eprintln!(
                "  {} {}: analysed {}, vads {}, outside {}, kernel starts on threads not known \
                 as system {}",
                process["pid"],
                process["image_file_name"],
                process["analysed"],
                process["vads"],
                process["starts_outside_the_tree"],
                process["kernel_starts_on_threads_not_known_as_system"]
            );
            for note in process["notes"].as_array().into_iter().flatten() {
                eprintln!("    note: {note}");
            }
        }
        for finding in process["findings"].as_array().into_iter().flatten() {
            let kinds: Vec<&str> = finding["suspicions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|s| s["kind"].as_str())
                .collect();
            let line = format!(
                "{} {} tid {} {} {:#x} in {} -> {:?}",
                process["pid"],
                process["image_file_name"],
                finding["tid"],
                finding["which"],
                finding["address"].as_u64().unwrap_or(0),
                finding["region"],
                kinds
            );
            eprintln!("  finding: {line}");
            named.push(line);
        }
    }

    assert_eq!(m["stage_ran"], serde_json::json!(true));
    assert_eq!(m["protections_available"], serde_json::json!(true));
    assert!(
        m["processes_analysed"].as_u64().unwrap_or(0) > 50,
        "a live Windows 11 machine has well over fifty user processes"
    );
    assert!(
        m["starts_tested"].as_u64().unwrap_or(0) > 500,
        "the analysis must actually have tested start addresses: {}",
        m["starts_tested"]
    );
    assert_eq!(
        m["gap_count"], 0,
        "the protection table and every file name were read"
    );
    assert_eq!(
        m["starts_outside_the_tree"], 0,
        "every user-mode start on this capture falls in a range"
    );
    assert_eq!(
        m["starts_in_kernel_space"].as_u64(),
        Some(WIN11_KERNEL_MODE_STARTS)
    );
    assert_eq!(
        m["kernel_starts_on_threads_not_known_as_system"].as_u64(),
        Some(WIN11_KERNEL_STARTS_ON_THREADS_NOT_KNOWN_AS_SYSTEM)
    );
    // Those starts are judged by no stage, so the survey is incomplete, and
    // that is the only reason it is.
    assert_eq!(m["content_complete"], false, "{}", m["incomplete"]);
    for reason in m["incomplete"].as_array().expect("the reasons") {
        let detail = reason["detail"].as_str().unwrap_or_default();
        assert!(
            detail.contains("SystemThread")
                || detail.contains("not known to be a kernel thread")
                || detail.contains("process list"),
            "an unexpected reason: {detail}"
        );
    }
    assert_eq!(
        m["evidence_count"].as_u64(),
        Some(WIN11_SUSPICIOUS_THREAD_EVIDENCE),
        "every finding on this clean capture is a false positive and must be triaged: {named:#?}"
    );
}
