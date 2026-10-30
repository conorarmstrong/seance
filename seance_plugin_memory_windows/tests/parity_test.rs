//! Parity against Volatility 3 on real reference images.
//!
//! Unit tests prove the code does what its author intended on fixtures its
//! author built. This file proves something different and harder: that on a real
//! Windows memory capture, Séance reaches the same answers as the tool the field
//! already trusts. Every expected value here was produced by running Volatility
//! 3.2.28.2 against the same file — none of it is hand-derived, and none of it
//! comes from Séance.
//!
//! The images are large and not committed, so these tests skip when they are
//! absent. Point `SEANCE_MEM_IMAGES` at a directory holding:
//!
//! - `win-xp-laptop.img` — Windows XP SP2, x86 non-PAE, the two-level page walk
//! - `Win11Dump.mem` — Windows 11 22000, x86-64, the four-level page walk
//!
//! `SEANCE_LONEWOLF` is a **separate** corpus holding `memdump.mem` — Windows
//! 10 19041, x86-64, a smeared live acquisition from Digital Corpora's 2018
//! Lone Wolf scenario, whose ISF is in the Volatility Windows symbol pack as
//! `ntkrnlmp.pdb/481F0DAABA6C4F02B456FAD74941C2A4-1`. Separate because a named
//! corpus short a file fails rather than skipping, so images sharing one
//! variable must all be provisioned or none can be used — and Lone Wolf is
//! public where the other two are not.
//!
//! Point `SEANCE_SYMBOL_DIRS` at a directory holding the matching ISF files.
//! See `seance_memory/tests/KNOWN_ANSWERS.md` for how to regenerate the oracle.
//!
//! A disagreement with Volatility is a defect in Séance until proven otherwise.
//! Where Séance deliberately differs — the VAD carry case documented in
//! `vad.rs` — the difference is asserted explicitly rather than tolerated.

use std::path::PathBuf;
use std::sync::Arc;

use seance_core::data_source::DataSource;
use seance_memory::translate::SwapFile;
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_windows::automagic::{self, DiscoveryOptions};
use seance_plugin_memory_windows::process::{self, ProcessListConfig, ProcessSymbols};
use seance_plugin_memory_windows::WindowsProfile;

/// A reference image from the corpus named by `var`, or `None` when that
/// corpus was never provisioned. Named-but-missing fails rather than reporting
/// a pass over no comparison.
fn image_from(var: &str, name: &str) -> Option<Arc<dyn MemoryLayer>> {
    let path = seance_core::test_support::corpus::file(var, name)?;
    let file = seance_core::data_source::FileDataSource::new(path.clone())
        .unwrap_or_else(|e| panic!("{} could not be opened: {e}", path.display()));
    let source: Arc<dyn DataSource> = Arc::new(file);
    let layer = PhysicalLayer::raw(source).expect("a raw image is a physical layer");
    Some(Arc::new(layer) as Arc<dyn MemoryLayer>)
}

/// The XP and Win11 reference images.
fn image(name: &str) -> Option<Arc<dyn MemoryLayer>> {
    image_from("SEANCE_MEM_IMAGES", name)
}

/// Directories holding ISF symbol files.
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
    // Resolved from the crate manifest, NOT the process CWD. `cargo test` runs an
    // integration test with the CWD set to the crate directory, so the bare
    // relative path this used to hold pointed at
    // `<crate>/reference/volatility3/...`, which does not exist. `read_dir`
    // failed, the directory was skipped, and discovery saw zero candidate ISFs —
    // so every parity test here failed to find symbols and then returned early
    // as a skip, reporting `ok` while comparing nothing. It never once ran.
    vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate sits directly under the workspace root")
        .join("reference/volatility3/volatility3/symbols")]
}

/// Discover a profile, or skip when the image or its symbols are absent.
fn profile(name: &str) -> Option<WindowsProfile> {
    profile_from("SEANCE_MEM_IMAGES", name)
}

/// As [`profile`], for an image in the corpus named by `var`.
fn profile_from(var: &str, name: &str) -> Option<WindowsProfile> {
    let physical = image_from(var, name)?;
    let dirs = symbol_dirs();
    match automagic::discover(physical, &dirs, &DiscoveryOptions::default()) {
        Ok(profile) => Some(profile),
        Err(err) => panic!("{name}: discovery failed, which is the finding: {err}"),
    }
}

/// The Lone Wolf capture, which has its own corpus variable.
///
/// Not folded into `SEANCE_MEM_IMAGES`. A corpus that is named and short a file
/// fails rather than skipping — deliberately — so every image sharing one
/// variable must be provisioned together or none can be. The XP and Win11
/// images are not redistributable and Lone Wolf is public, so demanding all
/// three to test any one of them would mean this image could never be used by
/// anyone who has only it. One variable per separately-obtainable set, as
/// `SEANCE_CFREDS_HACKING` and `SEANCE_IOS_SAMPLES` already are.
fn lonewolf_profile() -> Option<WindowsProfile> {
    profile_from(LONEWOLF_CORPUS, "memdump.mem")
}

/// The Lone Wolf capture with its own `pagefile.sys` attached.
///
/// The scenario ships both, taken from one machine at one moment, which is what
/// makes this testable at all: a pagefile from a different machine, or the same
/// machine at a different time, would decode to plausible bytes that belong to
/// neither.
///
/// Index 0 because Windows numbers `PagingFiles` from the registry order and a
/// single-pagefile machine's software PTEs name the first.
fn lonewolf_profile_with_pagefile() -> Option<WindowsProfile> {
    let physical = image_from(LONEWOLF_CORPUS, "memdump.mem")?;
    let path = seance_core::test_support::corpus::file(LONEWOLF_CORPUS, "pagefile.sys")?;
    let file = seance_core::data_source::FileDataSource::new(path.clone())
        .unwrap_or_else(|e| panic!("{} could not be opened: {e}", path.display()));
    let options = DiscoveryOptions {
        pagefiles: vec![SwapFile {
            index: 0,
            label: "pagefile.sys".to_string(),
            source: Arc::new(file),
        }],
        ..DiscoveryOptions::default()
    };
    match automagic::discover(physical, &symbol_dirs(), &options) {
        Ok(profile) => Some(profile),
        Err(err) => panic!("discovery failed with a pagefile attached: {err}"),
    }
}

/// Corpus holding Digital Corpora's 2018 Lone Wolf memory capture.
const LONEWOLF_CORPUS: &str = "SEANCE_LONEWOLF";

/// Every PID `windows.pslist` reports for the XP image, in order.
///
/// Extracted from the oracle CSV, not typed by hand. Forty-seven, not
/// forty-eight: `wc -l` on the CSV counts the header and the trailing
/// newline too.
const VOLATILITY_XP_PIDS: &[u64] = &[
    4, 188, 224, 432, 448, 504, 528, 580, 592, 688, 740, 800, 840, 864, 876, 944, 984, 1024, 1076,
    1224, 1304, 1400, 1424, 1484, 1548, 1632, 1700, 1812, 1916, 1936, 1948, 1952, 1960, 1980, 2040,
    2160, 2392, 2424, 2536, 2624, 2740, 2868, 3076, 3100, 3256, 4012, 4080,
];

// ── Windows XP SP2, x86 non-PAE ─────────────────────────────────────────────

#[test]
fn xp_discovery_matches_volatility() {
    let Some(profile) = profile("win-xp-laptop.img") else {
        return;
    };
    // windows.info: Kernel Base 0x804d7000, DTB 0x39000, Is64Bit False.
    assert_eq!(
        profile.kernel_base.value, 0x804d_7000,
        "kernel base disagrees with Volatility"
    );
    assert_eq!(profile.dtb.value, 0x39000, "DTB disagrees with Volatility");
    assert!(!profile.is_64bit(), "XP SP2 here is 32-bit");
    assert_eq!(profile.pointer_size(), 4);
    assert_eq!(profile.build.major, 5, "NtMajorVersion");
    assert_eq!(profile.build.pdb, "ntoskrnl.pdb");
    assert_eq!(
        profile.build.guid, "32962337F0F646388B39535CD8DD70E8",
        "a different symbol file was selected"
    );
    assert_eq!(profile.build.age, 2);
}

#[test]
fn xp_pslist_matches_the_process_list_volatility_reports() {
    let Some(profile) = profile("win-xp-laptop.img") else {
        return;
    };
    let symbols = ProcessSymbols::from_profile(&profile).expect("a describable build");
    let list = process::list_processes(&profile, &symbols, &ProcessListConfig::default())
        .expect("the active process list is walkable");

    assert!(
        list.forward_stop.is_complete(),
        "the walk stopped early, so any count is a floor rather than an answer: {:?}",
        list.forward_stop
    );
    // On a mismatch, say WHICH processes differ: a count alone cannot tell an
    // examiner whether a process is missing or an extra one was invented.
    let mut ours: Vec<u64> = list
        .processes
        .iter()
        .filter_map(|p| p.pid.known().copied())
        .collect();
    ours.sort_unstable();
    let theirs: Vec<u64> = VOLATILITY_XP_PIDS.to_vec();
    let missing: Vec<u64> = theirs
        .iter()
        .copied()
        .filter(|p| !ours.contains(p))
        .collect();
    let extra: Vec<u64> = ours
        .iter()
        .copied()
        .filter(|p| !theirs.contains(p))
        .collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "process lists disagree with Volatility. missing: {missing:?}, extra: {extra:?}, \
         ours={} theirs={}",
        ours.len(),
        theirs.len()
    );

    // Spot values from windows.pslist, including the offsets, so a list that
    // happened to be the right length for the wrong reason still fails.
    let by_pid = |pid: u64| {
        list.processes
            .iter()
            .find(|p| p.pid.known().copied() == Some(pid))
            .unwrap_or_else(|| panic!("PID {pid} is in Volatility's list and not in ours"))
    };

    let system = by_pid(4);
    assert_eq!(
        system.image_file_name.known().map(String::as_str),
        Some("System")
    );
    assert_eq!(system.address, 0x823c_87c0, "System _EPROCESS offset");
    assert_eq!(system.ppid.known().copied(), Some(0));
    assert_eq!(system.threads.known().copied(), Some(61));

    let smss = by_pid(448);
    assert_eq!(
        smss.image_file_name.known().map(String::as_str),
        Some("smss.exe")
    );
    assert_eq!(smss.address, 0x81fd_f020);
    assert_eq!(smss.ppid.known().copied(), Some(4));
    assert_eq!(smss.threads.known().copied(), Some(3));

    let csrss = by_pid(504);
    assert_eq!(
        csrss.image_file_name.known().map(String::as_str),
        Some("csrss.exe")
    );
    assert_eq!(csrss.address, 0x81f5_a3b8);
    assert_eq!(csrss.ppid.known().copied(), Some(448));
    assert_eq!(csrss.threads.known().copied(), Some(12));
}

#[test]
fn xp_process_names_are_never_silently_empty() {
    let Some(profile) = profile("win-xp-laptop.img") else {
        return;
    };
    let symbols = ProcessSymbols::from_profile(&profile).expect("a describable build");
    let list = process::list_processes(&profile, &symbols, &ProcessListConfig::default())
        .expect("walkable");

    // Every process in a healthy active list has a name. A blank one means a
    // field was read from the wrong offset, which is the failure that looks
    // like success.
    for p in &list.processes {
        assert!(
            p.image_file_name.known().is_some_and(|n| !n.is_empty()),
            "PID {:?} at {:#x} has no image name: {:?}",
            p.pid.known().copied(),
            p.address,
            p.notes
        );
    }
}

// ── Windows 11 22000, x86-64 ────────────────────────────────────────────────

#[test]
fn win11_discovery_matches_volatility() {
    let Some(profile) = profile("win11/Win11Dump.mem") else {
        return;
    };
    // windows.info: Kernel Base 0xf80029800000, DTB 0x1ae000, Is64Bit True.
    //
    // Volatility prints the kernel base with the sign extension stripped.
    // 0xf80029800000 has bit 47 set, so the address the hardware actually uses
    // is 0xfffff80029800000; keeping the canonical form is what makes the
    // pointer comparable to every other kernel pointer read out of the image.
    assert_eq!(profile.kernel_base.value, 0xffff_f800_2980_0000);
    assert_eq!(profile.dtb.value, 0x1ae000);
    assert!(profile.is_64bit(), "this capture is x86-64");
    assert_eq!(profile.pointer_size(), 8);
    assert_eq!(profile.build.major, 10);
    assert_eq!(profile.build.pdb, "ntkrnlmp.pdb");
    assert_eq!(profile.build.guid, "8E3373D6124E747F0E72EF8E02E676B3");
    assert_eq!(profile.build.age, 1);
    assert_eq!(
        profile.build.build,
        Some(22000),
        "the build number decides several structure layouts, so it is not optional"
    );
}

#[test]
fn win11_pslist_matches_the_processes_volatility_reports() {
    let Some(profile) = profile("win11/Win11Dump.mem") else {
        return;
    };
    let symbols = ProcessSymbols::from_profile(&profile).expect("a describable build");
    let list = process::list_processes(&profile, &symbols, &ProcessListConfig::default())
        .expect("the active process list is walkable");

    // This capture's `ActiveProcessLinks` chain is smeared: it runs off the end
    // of the real list into data that is not a `_LIST_ENTRY`. Volatility walks
    // into it too and emits one row with the process id 128017663995251, with
    // no indication that it is not a process. Comparing raw row counts would
    // therefore be comparing how far each tool got before giving up, which is
    // not a forensic fact about the image.
    //
    // What is a fact: 102 processes are really there. Both tools find them.
    let believable: Vec<&_> = list
        .processes
        .iter()
        .filter(|p| p.notes.is_empty() && p.pid.known().is_some())
        .collect();
    assert_eq!(
        believable.len(),
        102,
        "the believable process count disagrees with Volatility's"
    );

    let by_pid = |pid: u64| {
        believable
            .iter()
            .find(|p| p.pid.known().copied() == Some(pid))
            .unwrap_or_else(|| panic!("PID {pid} is in Volatility's list and not in ours"))
    };

    let system = by_pid(4);
    assert_eq!(
        system.image_file_name.known().map(String::as_str),
        Some("System")
    );
    // Volatility prints these offsets with the sign extension stripped.
    assert_eq!(system.address, 0xffff_de8c_e58c_4040);
    assert_eq!(system.threads.known().copied(), Some(152));

    let registry = by_pid(124);
    assert_eq!(
        registry.image_file_name.known().map(String::as_str),
        Some("Registry")
    );
    assert_eq!(registry.address, 0xffff_de8c_e592_e080);
    assert_eq!(registry.ppid.known().copied(), Some(4));

    let smss = by_pid(376);
    assert_eq!(
        smss.image_file_name.known().map(String::as_str),
        Some("smss.exe")
    );
    assert_eq!(smss.address, 0xffff_de8c_e78b_c040);
    assert_eq!(smss.ppid.known().copied(), Some(4));
}

#[test]
fn a_smeared_list_is_annotated_rather_than_presented_as_processes() {
    let Some(profile) = profile("win11/Win11Dump.mem") else {
        return;
    };
    let symbols = ProcessSymbols::from_profile(&profile).expect("a describable build");
    let list = process::list_processes(&profile, &symbols, &ProcessListConfig::default())
        .expect("walkable");

    // The entries past the end of the real list must not read as processes.
    // Upstream emits its equivalent row with no annotation at all, so an
    // examiner reading the table has nothing to tell them the row is rubbish.
    let unannotated_nonsense = list.processes.iter().any(|p| {
        p.notes.is_empty()
            && p.pid
                .known()
                .is_some_and(|&pid| pid % 4 != 0 || pid > u64::from(u32::MAX))
    });
    assert!(
        !unannotated_nonsense,
        "a process id no NT kernel would issue was reported without comment"
    );

    // And the walk has to say it stopped early rather than imply the list ended.
    assert!(
        !list.forward_stop.is_complete(),
        "the chain runs into non-list data, so a complete walk would be the wrong claim"
    );
}

#[test]
fn a_sixty_four_bit_walk_does_not_quietly_produce_a_thirty_two_bit_answer() {
    let Some(profile) = profile("win11/Win11Dump.mem") else {
        return;
    };
    let symbols = ProcessSymbols::from_profile(&profile).expect("a describable build");
    let list = process::list_processes(&profile, &symbols, &ProcessListConfig::default())
        .expect("walkable");

    // Every _EPROCESS on this build lives above the 32-bit boundary. An address
    // that fits in 32 bits would mean a pointer was read four bytes wide, which
    // yields a plausible-looking list of entirely wrong structures.
    for p in &list.processes {
        assert!(
            p.address > u64::from(u32::MAX),
            "PID {:?} at {:#x} looks like a truncated pointer",
            p.pid.known().copied(),
            p.address
        );
    }
}

#[test]
fn win11_the_process_list_head_is_where_the_symbol_says_it_is() {
    let Some(profile) = profile("win11/Win11Dump.mem") else {
        return;
    };
    // Computed independently from the ISF: PsActiveProcessHead has RVA
    // 0xc1bea0, and the kernel is loaded at 0xfffff80029800000.
    let rva = profile
        .symbols
        .symbol_address("PsActiveProcessHead")
        .expect("a kernel ISF names PsActiveProcessHead");
    eprintln!(
        "kernel_base={:#x} rva={:#x} head={:#x}",
        profile.kernel_base.value,
        rva,
        profile.kernel_base.value.wrapping_add(rva)
    );
    assert_eq!(rva, 0xc1_bea0, "the symbol's address is not the ISF's RVA");
    assert_eq!(
        profile.kernel_base.value.wrapping_add(rva),
        0xffff_f800_2a41_bea0,
        "the list head is not where base + RVA puts it"
    );
}

#[test]
fn win11_a_kernel_address_in_a_large_page_translates_where_volatility_puts_it() {
    let Some(profile) = profile("win11/Win11Dump.mem") else {
        return;
    };
    // PsActiveProcessHead. Volatility maps this VA to physical 0xdd21bea0, and
    // a hand walk of the page tables agrees: PML4[496] -> PDPT[0] -> PD[338],
    // whose PDE has PS=1, so the walk ends in a 2 MiB page and the low 21 bits
    // of the VA are the offset. Windows maps most of kernel space this way, so
    // a walk that missed the PS bit here would descend into page data and read
    // plausible-looking rubbish for every kernel structure.
    let head = 0xffff_f800_2a41_bea0u64;
    let map = profile
        .kernel_space
        .mapping(head, 16)
        .expect("the head is mapped");
    assert_eq!(map.len(), 1, "16 bytes inside one page is one run: {map:?}");
    assert_eq!(
        map[0].mapped_offset, 0xdd21_bea0,
        "the 2 MiB large page resolved to the wrong physical address"
    );

    // And the bytes there are the two kernel pointers Volatility reads.
    let mut buf = [0u8; 16];
    seance_core::io::read_exact_or_fail(
        profile.kernel_space.as_data_source(),
        head,
        &mut buf,
        "PsActiveProcessHead",
    )
    .expect("the list head is readable");
    let flink = u64::from_le_bytes(buf[..8].try_into().unwrap());
    assert_eq!(
        flink, 0xffff_de8c_e58c_4488,
        "the first forward link is not the one Volatility reads"
    );
}

/// The module the orchestrator registers must actually produce analysis.
///
/// This test exists because it did not, and nothing caught it: every stage was
/// written and unit-tested while `run_stages` returned an empty vector, so the
/// pipeline discovered a profile and emitted nothing else. Unit tests on the
/// stages could not see that, because the stages were never the problem — the
/// dispatch was. The assertion is deliberately about the module's OUTPUT rather
/// than about any stage's internals.
#[test]
fn the_registered_module_emits_analysis_and_not_just_a_profile() {
    use seance_core::artifact::ArtifactType;
    use seance_core::module::ForensicsModule;
    use seance_memory::analysis::MemoryAnalysisModule;
    use seance_plugin_memory_windows::WindowsMemoryAnalysis;

    let Some(physical) = image("win-xp-laptop.img") else {
        return;
    };

    // Build the record the container stage emits, which is what this module
    // subscribes to. The layer is already a `DataSource`, which is what an
    // artifact carries.
    let source: Arc<dyn seance_core::data_source::DataSource> = {
        let dir = PathBuf::from(std::env::var("SEANCE_MEM_IMAGES").expect("corpus dir"));
        Arc::new(
            seance_core::data_source::FileDataSource::new(dir.join("win-xp-laptop.img"))
                .expect("the image opens"),
        )
    };
    let _ = &physical;
    let image_record = seance_core::artifact::Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(source),
        serde_json::json!({"type": "MemoryImage", "image_format": "raw"}),
    );

    // Point the module at the symbol directory explicitly. Its last fallback is
    // the CWD-relative `reference/volatility3/volatility3/symbols`, and an
    // integration test runs with the CWD set to the crate directory, so that
    // fallback resolves to nothing and `retain(|d| d.is_dir())` drops it.
    // Discovery then found no symbols and the module emitted a manifest and
    // nothing else — which is exactly the "a profile with no analysis behind it"
    // placeholder this test exists to catch, arriving from the harness rather
    // than from the product.
    let out =
        MemoryAnalysisModule::new(WindowsMemoryAnalysis::new().with_symbol_dirs(symbol_dirs()))
            .process(&image_record)
            .expect("the module runs against a real image");

    let kinds: Vec<&str> = out
        .iter()
        .filter_map(|a| a.metadata["record_type"].as_str())
        .collect();

    // A stage that could not run says so. Print them, because a stage failing
    // on a real image is a finding about this build's coverage, not noise.
    for a in &out {
        if a.metadata["record_type"] == "MemoryStageFailure" {
            eprintln!(
                "  stage '{}' did not run: {}",
                a.metadata["stage"].as_str().unwrap_or("?"),
                a.metadata["failure"].as_str().unwrap_or("?")
            );
        }
    }

    assert!(
        out.len() > 1,
        "the module emitted only {} record(s); a profile with no analysis behind it is the \
         placeholder this test exists to catch",
        out.len()
    );
    for expected in [
        "MemoryProcessList",
        "MemoryProcessTree",
        "MemoryPoolScan",
        "MemoryCrossView",
    ] {
        assert!(
            kinds.contains(&expected),
            "no {expected} record was emitted; kinds were {kinds:?}"
        );
    }

    // Every record says which stage produced it and whether that stage ran, so
    // "the stage found nothing" is never confusable with "the stage did not run".
    for a in &out {
        assert!(
            a.metadata.get("analysed_by").is_some() || a.metadata["type"] == "MemoryProfile",
            "a record carries no provenance: {:?}",
            a.metadata
        );
    }
}

// ── Windows 10 build 19041 (Lone Wolf), x86-64, smeared live acquisition ─────
//
// `memdump.mem` from Digital Corpora's 2018 Lone Wolf scenario: 17 GB, taken
// with FTK Imager on a running machine, so it is *smeared* — pages captured at
// different instants. Volatility's own `windows.info` shows it:
// `KeNumberProcessors` reads 0 and the PE timestamp reads 2042.
//
// It earns its place beside XP and Win11 twice over. It is the only Win10 here,
// and it is the only capture on which upstream's `windows.pslist` returns *no
// processes at all* — so it is the case where "agrees with Volatility" and
// "recovers the evidence" come apart, and the tests have to say which is meant.

/// Every `_EPROCESS` `windows.psscan` finds, masked to 48 bits.
///
/// Volatility prints kernel addresses with the sign-extension truncated
/// (`0xffffae80...` as `0xae80...`), so both sides are masked before comparing
/// rather than one side being "corrected" into agreement.
///
/// Generated from the oracle CSV, not typed: 216 rows, no duplicates.
const VOLATILITY_WIN10_PSSCAN: &[u64] = &[
    0xae80000c2040,
    0xae8000113580,
    0xae8000117580,
    0xae800011f580,
    0xae8000121580,
    0xae8000123580,
    0xae8000127580,
    0xae800012b580,
    0xe602d2ec2040,
    0xe602d2f13580,
    0xe602d2f17580,
    0xe602d2f1f580,
    0xe602d2f21580,
    0xe602d2f23580,
    0xe602d2f27580,
    0xe602d2f2b580,
    0xe602d31d7580,
    0xe602d397c080,
    0xe602d3a1c100,
    0xe602d3b41580,
    0xe602d3bd7580,
    0xe602d3c8a580,
    0xe602d3dbc340,
    0xe602d3e8d580,
    0xe602d3f83080,
    0xe602d3ffd080,
    0xe602d405f580,
    0xe602d407d580,
    0xe602d4a94200,
    0xe602d4eb3580,
    0xe602d4f7e040,
    0xe602d6009580,
    0xe602d60aa580,
    0xe602d60ae580,
    0xe602d60b0580,
    0xe602d60b4580,
    0xe602d60b8580,
    0xe602d60bc580,
    0xe602d60be580,
    0xe602d60c0580,
    0xe602d60c2580,
    0xe602d60e7080,
    0xe602d60e8580,
    0xe602d611e280,
    0xe602d6139480,
    0xe602d616d580,
    0xe602d6276580,
    0xe602d6278580,
    0xe602d6279580,
    0xe602d627a580,
    0xe602d627c580,
    0xe602d627e580,
    0xe602d6280580,
    0xe602d6282580,
    0xe602d628e580,
    0xe602d64c0080,
    0xe602d64c4080,
    0xe602d64ca080,
    0xe602d64fa580,
    0xe602d6514080,
    0xe602d652d580,
    0xe602d654a080,
    0xe602d65c0580,
    0xe602d65c8080,
    0xe602d65cc080,
    0xe602d65d4580,
    0xe602d6646580,
    0xe602d664a580,
    0xe602d6650580,
    0xe602d6652580,
    0xe602d665a580,
    0xe602d668f580,
    0xe602d675b080,
    0xe602d6779580,
    0xe602d6791080,
    0xe602d67d4080,
    0xe602d68b1580,
    0xe602d6917580,
    0xe602d695a580,
    0xe602d696c580,
    0xe602d6999080,
    0xe602d69a5580,
    0xe602d69a9580,
    0xe602d6a03580,
    0xe602d6a0b580,
    0xe602d6a0d580,
    0xe602d6a0f580,
    0xe602d6a1b580,
    0xe602d6a1f580,
    0xe602d6a48080,
    0xe602d6a72380,
    0xe602d6abd580,
    0xe602d72b0580,
    0xe602d72b6580,
    0xe602d72c8580,
    0xe602d72da580,
    0xe602d73b1580,
    0xe602d73b9080,
    0xe602d73c9580,
    0xe602d73cd4c0,
    0xe602d749b580,
    0xe602d74b3580,
    0xe602d74d4580,
    0xe602d755f080,
    0xe602d7564580,
    0xe602d7571580,
    0xe602d75823c0,
    0xe602d75d2580,
    0xe602d75d4580,
    0xe602d75ef580,
    0xe602d76c9580,
    0xe602d78a8580,
    0xe602d78b0580,
    0xe602d79b8580,
    0xe602d79bc580,
    0xe602d79db080,
    0xe602d7a5a080,
    0xe602d7a76580,
    0xe602d7a83080,
    0xe602d7aaf080,
    0xe602d7ac7580,
    0xe602d7d44580,
    0xe602d7d7d540,
    0xe602d7d8a580,
    0xe602d7ecb580,
    0xe602d7f1e340,
    0xe602d7f47400,
    0xe602d7f9e580,
    0xe602d7fef580,
    0xe602d80bc580,
    0xe602d810b080,
    0xe602d8277080,
    0xe602d82ce580,
    0xe602d8589580,
    0xe602d85a9080,
    0xe602d85c1580,
    0xe602d85dc080,
    0xe602d867a080,
    0xe602d89f0400,
    0xe602d8a4e580,
    0xe602d8adf2c0,
    0xe602d8b3a080,
    0xe602d8be3580,
    0xe602d8c94400,
    0xe602d8f62440,
    0xe602d904f080,
    0xe602d90a6400,
    0xe602d910b080,
    0xe602d911e580,
    0xe602d9347080,
    0xe602d93ef380,
    0xe602d94ae580,
    0xe602d96a7100,
    0xe602d9bea080,
    0xe602d9fca080,
    0xe602d9fef080,
    0xe602d9ff2080,
    0xe602da0f1080,
    0xe602da24a2c0,
    0xe602da453080,
    0xe602da4f6280,
    0xe602da6c7580,
    0xe602da705340,
    0xe602da7d8580,
    0xe602da82c140,
    0xe602da868080,
    0xe602da869480,
    0xe602da877580,
    0xe602da87f580,
    0xe602da9a8380,
    0xe602daab1580,
    0xe602dad2b580,
    0xe602dad8e080,
    0xe602dad913c0,
    0xe602dae5a580,
    0xe602db0f4580,
    0xe602db126080,
    0xe602db2b8080,
    0xe602db60c580,
    0xe602db8a1580,
    0xe602db9df580,
    0xe602db9fd580,
    0xe602dba97580,
    0xe602dbbe8380,
    0xe602dbbf6080,
    0xe602dbc02080,
    0xe602dbccc080,
    0xe602dbd64080,
    0xe602dbd8a080,
    0xe602dbdd8080,
    0xe602dbe70080,
    0xe602dbe74240,
    0xe602dbf4d080,
    0xe602dbf6e080,
    0xe602dbf8e080,
    0xe602dc05f080,
    0xe602dc072580,
    0xe602dc0f3580,
    0xe602dc1ae580,
    0xe602dc1d3080,
    0xe602dc431580,
    0xe602dc5ee080,
    0xe602dc809240,
    0xe602dc891180,
    0xe602dcdcc080,
    0xe602dce94080,
    0xe602dd029580,
    0xe602dd470080,
    0xe602dd49b580,
    0xe602dd5c34c0,
    0xe602dd79d580,
    0xe602dd83b4c0,
    0xe602dd96a580,
    0xe602ddbe5580,
    0xf802f48b6580,
    0xf802f48be580,
];

/// Discovery: the facts `windows.info` states about this image.
#[test]
fn win10_discovery_matches_volatility() {
    let Some(profile) = lonewolf_profile() else {
        return;
    };
    // Kernel base is deliberately not asserted here — the two tools disagree
    // about it on this image, and that disagreement has its own test below
    // rather than being folded into a pass or quietly dropped.
    assert_eq!(profile.dtb.value, 0x1ab000, "DTB disagrees with Volatility");
    assert!(profile.is_64bit(), "Win10 x64");
    assert_eq!(profile.pointer_size(), 8);
    assert_eq!(profile.build.major, 10, "NtMajorVersion");
    assert_eq!(profile.build.minor, 0, "NtMinorVersion");
    assert_eq!(profile.build.pdb, "ntkrnlmp.pdb");
    assert_eq!(
        profile.build.guid, "481F0DAABA6C4F02B456FAD74941C2A4",
        "a different symbol file was selected"
    );
    assert_eq!(profile.build.age, 1);
}

/// The pool sweep, against the tool of record.
///
/// This is the test the "pool-scan placement ambiguity" entry was waiting for.
/// The sweep decides where an object body sits inside its allocation, and the
/// decision differs between builds; nothing local could show which branch this
/// build takes without a real Win10 image to take it on.
///
/// Set equality, not a count: a count that matches while the addresses differ
/// is two errors cancelling, and on a smeared image that is a live possibility.
#[test]
fn win10_psscan_matches_the_allocations_volatility_finds() {
    use seance_plugin_memory_windows::poolscan::{
        builtin_constraints_for, pool_scan, PoolScanConfig, PoolSymbols,
    };

    let Some(profile) = lonewolf_profile() else {
        return;
    };
    let symbols = PoolSymbols::from_profile(&profile).expect("a describable build");
    let outcome = pool_scan(
        &profile,
        &symbols,
        &builtin_constraints_for(&[*b"Proc"]),
        &PoolScanConfig::default(),
    )
    .expect("the pool is sweepable");

    let mut ours: Vec<u64> = outcome
        .objects
        .iter()
        .map(|object| object.address & 0xFFFF_FFFF_FFFF)
        .collect();
    ours.sort_unstable();
    ours.dedup();

    let theirs: Vec<u64> = VOLATILITY_WIN10_PSSCAN.to_vec();

    // Name what differs. A count alone cannot tell an examiner whether a
    // process was missed or an extra one invented, and those are not the same
    // defect.
    let missed: Vec<String> = theirs
        .iter()
        .filter(|a| !ours.contains(a))
        .map(|a| format!("{a:#x}"))
        .collect();
    let extra: Vec<String> = ours
        .iter()
        .filter(|a| !theirs.contains(a))
        .map(|a| format!("{a:#x}"))
        .collect();

    assert!(
        missed.is_empty() && extra.is_empty(),
        "pool sweep disagrees with Volatility: {} missed {missed:?}, {} extra {extra:?}",
        missed.len(),
        extra.len()
    );
    assert_eq!(ours.len(), 216, "the oracle holds 216 allocations");
}

/// The kernel bases disagree, and the list walk settles which one is usable.
///
/// | Tool | Kernel base |
/// |---|---|
/// | Volatility 3 `windows.info` | `0xfffff802f4012000` |
/// | Séance `automagic::discover` | `0xfffff802f4091000` |
///
/// 0x7f000 apart. Asserting parity on that number would be asserting the wrong
/// thing: on this image *every* list-walking Volatility plugin returns nothing
/// — `windows.pslist` and `windows.modules` both emit a header and no rows —
/// while its scanners, which need no base, work perfectly. A base that yields
/// no `PsActiveProcessHead` is exactly what that looks like.
///
/// So the test is not "do the two agree" but "is the walk that depends on the
/// base corroborated by the sweep that does not". The pool sweep above matches
/// Volatility's `psscan` 216 for 216, which makes it an independent oracle;
/// this checks that every process the base-derived walk reports is one of
/// those allocations. A wrong base gives a wrong list head, and a wrong list
/// head yields a failed walk or garbage — not 175 addresses that all land on
/// separately confirmed process allocations.
#[test]
fn win10_the_list_walk_is_corroborated_by_the_verified_pool_sweep() {
    use seance_plugin_memory_windows::poolscan::{
        builtin_constraints_for, pool_scan, PoolScanConfig, PoolSymbols,
    };

    let Some(profile) = lonewolf_profile() else {
        return;
    };

    let pool_symbols = PoolSymbols::from_profile(&profile).expect("a describable build");
    let swept: Vec<u64> = pool_scan(
        &profile,
        &pool_symbols,
        &builtin_constraints_for(&[*b"Proc"]),
        &PoolScanConfig::default(),
    )
    .expect("the pool is sweepable")
    .objects
    .iter()
    .map(|object| object.address)
    .collect();

    let process_symbols = ProcessSymbols::from_profile(&profile).expect("a describable build");
    let list = process::list_processes(&profile, &process_symbols, &ProcessListConfig::default())
        .expect("the active process list is walkable");

    assert!(
        !list.processes.is_empty(),
        "the walk produced nothing, which is what a wrong kernel base looks like"
    );

    let uncorroborated: Vec<String> = list
        .processes
        .iter()
        .filter(|p| !swept.contains(&p.address))
        .map(|p| format!("{:#x}", p.address))
        .collect();

    assert!(
        uncorroborated.is_empty(),
        "{} of {} processes from the list walk are at addresses the pool sweep — \
         which matches Volatility exactly — never found: {uncorroborated:?}",
        uncorroborated.len(),
        list.processes.len()
    );
}

/// Swapped-out pages resolve from the scenario's own pagefile — and only the
/// ones that name it.
///
/// Lone Wolf ships `memdump.mem` and `pagefile.sys` from one machine at one
/// moment, which is what makes this testable: a pagefile from elsewhere would
/// decode to plausible bytes belonging to neither.
///
/// What this asserts is narrow. **Pages that were unreadable because they were
/// swapped become readable, nothing that was readable changes, and no page
/// resolves from a pagefile it did not name.** It does not claim the recovered
/// bytes are correct; no third party published what was in this machine's
/// pagefile, so nothing here could.
///
/// # What the survey of this image found, and why it matters
///
/// Across all 175 process address spaces and 25,155 VADs: 6 swapped pages
/// resolved, and 1,017 did not. The 1,017 are the interesting number. 989 of
/// them name **pagefile index 2**, and the rest name 1, 3, 6, 7, 14 and 15 —
/// on a machine with exactly one pagefile, which Windows numbers 0. This
/// capture is smeared (upstream's own `windows.info` reports
/// `KeNumberProcessors` as 0 and a PE timestamp in 2042), so those index bits
/// are read out of page-table entries that were inconsistent when the image
/// was taken.
///
/// That is the case for [`VirtualLayer::with_swap`] refusing to fall back to
/// "the only pagefile we have". Under such a rule 989 pages would have
/// "resolved" here — real offsets, read out of a real file, decoded from
/// garbage — and been attributed to named processes in a report. An offset
/// applied to a pagefile the PTE did not name does not fail. It returns bytes.
#[test]
fn win10_an_attached_pagefile_resolves_pages_that_were_holes() {
    use seance_plugin_memory_windows::vad;

    let Some(plain) = lonewolf_profile() else {
        return;
    };
    let Some(swapped) = lonewolf_profile_with_pagefile() else {
        return;
    };

    let symbols = ProcessSymbols::from_profile(&plain).expect("a describable build");
    let list = process::list_processes(&plain, &symbols, &ProcessListConfig::default())
        .expect("the active process list is walkable");
    assert!(!list.processes.is_empty(), "no processes to sample");

    let cache = std::sync::Arc::new(seance_memory::translate::TableCache::default());
    let vad_symbols = vad::VadSymbols::from_profile(&plain).expect("a describable build");

    let mut resolved = 0usize;
    let mut still_holes = 0usize;
    let mut disagreed = 0usize;
    let mut altered = 0usize;

    for process in list.processes.iter() {
        let (Ok(plain_space), Ok(swapped_space)) = (
            process::process_address_space(&plain, &symbols, process.address, &cache),
            process::process_address_space(&swapped, &symbols, process.address, &cache),
        ) else {
            continue;
        };
        let Ok(tree) = vad::list_vads(
            &plain,
            &vad_symbols,
            process.address,
            &vad::VadWalkConfig::default(),
        ) else {
            continue;
        };

        for region in tree.vads.iter() {
            for step in 0..4u64 {
                let va = region.start.wrapping_add(step * 0x1000);
                if va > region.end {
                    break;
                }
                let mut before = [0u8; 8];
                let mut after = [0u8; 8];
                let a = plain_space.read_at(va, &mut before);
                let b = swapped_space.read_at(va, &mut after);

                let was_swapped = |err: &std::io::Error| {
                    err.get_ref()
                        .and_then(|e| e.downcast_ref::<seance_memory::MemoryHole>())
                        .map(|h| h.reason == seance_memory::HoleReason::SwappedOut)
                        .unwrap_or(false)
                };

                match (a, b) {
                    (Ok(_), Ok(_)) if before != after => altered += 1,
                    (Ok(_), Ok(_)) => {}
                    (Err(err), Ok(_)) if was_swapped(&err) => resolved += 1,
                    // Readable only with the pagefile attached, for a reason
                    // that was not "swapped out", would mean the attachment
                    // changed something it has no business changing.
                    (Err(_), Ok(_)) => disagreed += 1,
                    (Ok(_), Err(_)) => disagreed += 1,
                    (Err(err), Err(_)) if was_swapped(&err) => still_holes += 1,
                    _ => {}
                }
            }
        }
    }

    assert_eq!(
        altered, 0,
        "attaching a pagefile changed {altered} page(s) RAM already answered for, which is a \
         routing defect rather than a recovery"
    );
    assert_eq!(
        disagreed, 0,
        "attaching a pagefile changed readability for {disagreed} page(s) that were not swapped"
    );
    assert!(
        resolved > 0,
        "no swapped page resolved from this image's own pagefile, so the attachment is inert; \
         this capture is known to hold some"
    );
    assert!(
        still_holes > 0,
        "every swapped page resolved, which on this image would mean pages naming a pagefile \
         that does not exist were answered from the one that does"
    );

    println!(
        "swapped pages resolved: {resolved}; left as holes (naming other pagefiles): {still_holes}"
    );
}
