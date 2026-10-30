//! Parity against Volatility 3's `windows.psscan` on real reference images.
//!
//! `pslist` walks the kernel's own list of processes. `psscan` sweeps the pool
//! allocator for `_EPROCESS` allocations regardless of whether anything still
//! links to them. The two answer different questions, and the difference is the
//! finding: an allocation the sweep reaches and the list does not is either a
//! process that exited before acquisition or one a rootkit unlinked.
//!
//! Two images, chosen because they exercise opposite halves of the same claim.
//!
//! * **Windows XP SP2, x86 non-PAE.** 62 pool hits against 47 linked
//!   processes. Reproducing only the 47 would mean pool scanning is not working
//!   even though `pslist` looks perfect, so the fifteen unlinked remnants are
//!   asserted by name and offset rather than by a count.
//! * **Windows 11 22000, x86-64.** 103 rows on both sides — and *different*
//!   rows, which is exactly why a count is the wrong assertion here. See
//!   [`win11_psscan_and_pslist_have_the_same_row_count_and_not_the_same_rows`].
//!
//! # The open question this file settles
//!
//! `poolscan::examine` enumerates the candidate body placements inside one
//! allocation and returns the **first** that survives validation, because
//! emitting all of them — which is what upstream does — defeats the validity
//! checks: a candidate whose own fields are nonsense is still reported when some
//! other offset in the same allocation happens to satisfy the test. The
//! divergence is only safe if, on real data, the first survivor is the true
//! object. Two things prove it here:
//!
//! * the offset set matches Volatility's exactly, so nothing was deflated by
//!   rejecting the true placement, and
//! * no two returned objects share a `pool_header`, so nothing was inflated by
//!   duplicate placements.
//!
//! Both are checked against the Windows 11 image, which is the top-down build
//! where more than one placement can survive. Windows XP places executive
//! objects bottom-up, where there is only ever one candidate.
//!
//! # Two traps in the oracle CSV
//!
//! * The column is headed `Offset(V)` in both files and is **not** a virtual
//!   address in both. Volatility sweeps physical memory before Windows 10 and
//!   the kernel virtual space from Windows 10, and prints whichever it swept.
//!   The XP offsets are physical; the Windows 11 offsets are virtual with the
//!   sign extension stripped. Séance makes the same choice of space, so the two
//!   are comparable — once ours is truncated to 48 bits.
//! * `(PID, ImageFileName)` is **not** a key. The XP sweep finds ten pairs twice
//!   over, because a terminated process leaves its `_EPROCESS` behind and the
//!   kernel later reissues the id. Offsets are unique in both files, so offsets
//!   are the key.
//!
//! The corpus is not committed; these tests skip when it is absent. Point
//! `SEANCE_MEM_IMAGES` at the images directory and `SEANCE_SYMBOL_DIRS` at the
//! ISF directories. See `seance_memory/tests/KNOWN_ANSWERS.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use seance_memory::object::StructReader;
use seance_memory::MemoryLayer;
use seance_plugin_memory_windows::poolscan::{
    builtin_constraints_for, image_file_name, pool_scan, ObjectTypeMap, PoolScanConfig,
    PoolScanOutcome, PoolSymbols, ScanSpace,
};
use seance_plugin_memory_windows::process::{self, ProcessListConfig, ProcessSymbols};
use seance_plugin_memory_windows::WindowsProfile;

mod common;
use common::{oracle, profile, truncate_to_48, WIN11, XP};

/// Oracle directory for the Windows XP image.
const ORACLE_XP: &str = "oracle";

/// Oracle directory for the Windows 11 image.
const ORACLE_WIN11: &str = "oracle_win11";

/// The Volatility plugin whose CSV this file compares against.
const PSSCAN: &str = "windows.psscan";

/// The structure a process allocation holds, as the constraint names it.
const EPROCESS: &str = "_EPROCESS";

/// The two pool tags Windows has ever allocated an `_EPROCESS` under.
///
/// `Pro\xe3` is the pre-Windows-8 spelling, whose top bit marks a protected
/// allocation. Both are swept on both images: the build number says which one
/// the running kernel *writes* and says nothing about what is still lying in
/// freed pool.
const PROCESS_TAGS: [[u8; 4]; 2] = [*b"Pro\xe3", *b"Proc"];

/// Thread pool tags: `Thr\xe5` before Windows 8, `Thre` from it.
const THREAD_TAGS: [[u8; 4]; 2] = [*b"Thr\xe5", *b"Thre"];

/// Processes `windows.pslist` reports for the XP image.
const XP_LINKED_PROCESSES: usize = 47;

/// Rows `windows.psscan` reports for the XP image.
const XP_POOL_PROCESSES: usize = 62;

/// Rows `windows.psscan` reports for the Windows 11 image.
const WIN11_POOL_PROCESSES: usize = 103;

/// The System process's `_EPROCESS` in the Windows 11 image, canonical.
///
/// Volatility prints `0xde8ce58c4040`; bit 47 is set, so the address the
/// hardware uses is the one here.
const WIN11_SYSTEM_EPROCESS: u64 = 0xffff_de8c_e58c_4040;

// ── Scaffolding ─────────────────────────────────────────────────────────────

/// One process sweep, and the reader its results are addressed in.
struct Sweep {
    /// The layout facts the sweep was decoded through.
    symbols: PoolSymbols,
    /// What the sweep found and everything it could not do.
    outcome: PoolScanOutcome,
    /// A reader over the swept layer, with pointers resolving in kernel space.
    reader: StructReader,
}

impl Sweep {
    /// Our result as the oracle presents it: offset to id and name.
    ///
    /// Keyed on the address truncated to 48 bits, which is what Volatility
    /// prints. A physical address on the XP image is unaffected by the mask, so
    /// one key function serves both images.
    fn by_offset(&self) -> BTreeMap<u64, (Option<u64>, String)> {
        let mut map = BTreeMap::new();
        for object in &self.outcome.objects {
            assert_eq!(
                object.type_name, EPROCESS,
                "the process sweep decoded an allocation as a {}, which no process constraint \
                 asks for",
                object.type_name
            );
            let key = truncate_to_48(object.address);
            let previous = map.insert(key, self.describe(object.address));
            assert!(
                previous.is_none(),
                "two objects were reported at {key:#x}, so one allocation was counted twice"
            );
        }
        map
    }

    /// The id and name stored in the `_EPROCESS` at an address.
    ///
    /// Read here rather than carried on [`PoolScanOutcome`] because the whole
    /// point of comparing against the oracle is to compare the bytes at the
    /// address, not a summary of them.
    fn describe(&self, address: u64) -> (Option<u64>, String) {
        let Ok(object) = self.reader.object(address, EPROCESS) else {
            return (None, String::from("<unreadable>"));
        };
        let pid = object
            .int("UniqueProcessId")
            .ok()
            .and_then(|value| value.as_u64());
        let name = object
            .bytes("ImageFileName")
            .map(|raw| image_file_name(&raw))
            .unwrap_or_else(|_| String::from("<unreadable>"));
        (pid, name)
    }
}

/// Sweep an image for process allocations exactly as a `psscan` stage would.
fn sweep_for_processes(profile: &WindowsProfile) -> Sweep {
    let symbols = PoolSymbols::from_profile(profile)
        .expect("both reference builds can be described well enough to sweep");
    let constraints = builtin_constraints_for(&PROCESS_TAGS);
    assert_eq!(
        constraints.len(),
        PROCESS_TAGS.len(),
        "a process tag lost its builtin constraint, so half the allocations would never be looked \
         at and the short list would look complete"
    );

    let config = PoolScanConfig {
        type_map: ObjectTypeMap::from_profile(profile).ok().map(Arc::new),
        ..PoolScanConfig::default()
    };
    let outcome = pool_scan(profile, &symbols, &constraints, &config)
        .expect("the process sweep is runnable on both reference images");

    // The allocation's bytes come from whichever layer was swept; the pointers
    // inside it are kernel virtual addresses either way.
    let layer: Arc<dyn MemoryLayer> = match symbols.space {
        ScanSpace::Physical => Arc::clone(&profile.physical),
        ScanSpace::KernelVirtual => Arc::clone(&profile.kernel_space),
    };
    let reader = StructReader::with_native(
        layer,
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );

    Sweep {
        symbols,
        outcome,
        reader,
    }
}

/// Volatility's `windows.psscan` rows, offset to id and name.
///
/// `None` when the corpus is absent, which is a skip rather than a failure.
fn oracle_processes(dir: &str) -> Option<BTreeMap<u64, (u64, String)>> {
    let rows = oracle(dir, PSSCAN)?;
    let mut map = BTreeMap::new();
    for row in &rows {
        assert!(
            row.len() >= 5,
            "a {PSSCAN} row in {dir} has {} field(s); PID, ImageFileName and Offset are at 1, 3 \
             and 4: {row:?}",
            row.len()
        );
        let pid = row[1]
            .trim()
            .parse::<u64>()
            .unwrap_or_else(|err| panic!("{dir}/{PSSCAN} PID {:?} is not a number: {err}", row[1]));
        let name = row[3].trim().to_string();
        let offset = parse_hex(&row[4])
            .unwrap_or_else(|| panic!("{dir}/{PSSCAN} offset {:?} is not hexadecimal", row[4]));
        let previous = map.insert(offset, (pid, name));
        assert!(
            previous.is_none(),
            "{dir}/{PSSCAN} lists {offset:#x} twice, so the offset is not the key this file \
             assumes it is"
        );
    }
    Some(map)
}

/// A `0x`-prefixed hexadecimal field from the oracle.
fn parse_hex(field: &str) -> Option<u64> {
    let text = field.trim();
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    u64::from_str_radix(digits, 16).ok()
}

/// The two sets, differenced, in the terms an examiner needs.
///
/// A bare count mismatch says nothing: it cannot distinguish a process the
/// sweep missed from one it invented. This names both, by offset, with the id
/// and name at that address on whichever side has it.
fn difference(
    theirs: &BTreeMap<u64, (u64, String)>,
    ours: &BTreeMap<u64, (Option<u64>, String)>,
) -> String {
    let missing: Vec<String> = theirs
        .iter()
        .filter(|&(offset, _)| !ours.contains_key(offset))
        .map(|(offset, (pid, name))| format!("{offset:#x} pid={pid} name={name:?}"))
        .collect();
    let extra: Vec<String> = ours
        .iter()
        .filter(|&(offset, _)| !theirs.contains_key(offset))
        .map(|(offset, (pid, name))| format!("{offset:#x} pid={pid:?} name={name:?}"))
        .collect();
    format!(
        "Volatility found {} allocation(s) and Séance found {}.\n  \
         Volatility found and Séance did not ({}): {missing:?}\n  \
         Séance found and Volatility did not ({}): {extra:?}",
        theirs.len(),
        ours.len(),
        missing.len(),
        extra.len()
    )
}

/// Offsets where both tools found an allocation but disagree about what is in
/// it.
fn field_disagreements(
    theirs: &BTreeMap<u64, (u64, String)>,
    ours: &BTreeMap<u64, (Option<u64>, String)>,
) -> Vec<String> {
    theirs
        .iter()
        .filter_map(|(offset, (their_pid, their_name))| {
            let (our_pid, our_name) = ours.get(offset)?;
            if *our_pid == Some(*their_pid) && our_name == their_name {
                return None;
            }
            Some(format!(
                "{offset:#x}: Volatility says pid={their_pid} name={their_name:?}, Séance says \
                 pid={our_pid:?} name={our_name:?}"
            ))
        })
        .collect()
}

/// Where a kernel virtual address's bytes actually live.
///
/// `pslist` reports virtual addresses and the XP sweep reports physical ones,
/// so comparing the two means walking the page tables rather than subtracting a
/// constant: three of the XP processes live above `0xff000000`, where the
/// kernel is not direct-mapped and the subtraction gives an address that is not
/// even in the image.
fn physical_of(profile: &WindowsProfile, virtual_address: u64) -> Option<u64> {
    let runs = profile.kernel_space.mapping(virtual_address, 1).ok()?;
    runs.first().map(|run| run.mapped_offset)
}

/// The processes the active list links, with a usable id and no annotation.
///
/// The Windows 11 capture's `ActiveProcessLinks` chain is smeared and runs off
/// into data that is not a `_LIST_ENTRY`; the entries past the end of the real
/// list carry notes, and comparing them against a pool sweep would be comparing
/// how far the list walk got before giving up.
fn believable_processes(profile: &WindowsProfile) -> Vec<(u64, Option<u64>, String)> {
    let symbols = ProcessSymbols::from_profile(profile).expect("a describable build");
    let list = process::list_processes(profile, &symbols, &ProcessListConfig::default())
        .expect("the active process list is walkable on both reference images");
    list.processes
        .iter()
        .filter(|record| record.notes.is_empty() && record.pid.known().is_some())
        .map(|record| {
            (
                record.address,
                record.pid.known().copied(),
                record
                    .image_file_name
                    .known()
                    .cloned()
                    .unwrap_or_else(|| String::from("<unknown>")),
            )
        })
        .collect()
}

// ── Windows XP SP2, x86 non-PAE ─────────────────────────────────────────────

#[test]
fn xp_the_process_sweep_runs_in_physical_memory_as_volatility_does() {
    let Some(profile) = profile(XP) else {
        return;
    };
    let sweep = sweep_for_processes(&profile);

    // Before Windows 10 the objects a sweep exists to find are precisely the
    // ones the kernel virtual address space no longer maps. Sweeping the
    // virtual space instead would still produce a table — of only the linked
    // processes — and it would read as a complete answer.
    assert_eq!(
        sweep.symbols.space,
        ScanSpace::Physical,
        "an XP sweep that runs in the kernel virtual space cannot reach an unlinked _EPROCESS, so \
         it would silently degrade into a second process list"
    );
    assert!(
        !sweep.symbols.top_down,
        "XP places an executive object at the bottom of its allocation; searching top-down would \
         put every _EPROCESS at the wrong address, and every one of them would still parse"
    );
    assert_eq!(
        sweep.symbols.alignment, 8,
        "the pool allocator's granularity on a 32-bit kernel is 8 bytes"
    );
}

#[test]
fn xp_the_process_sweep_finds_exactly_the_allocations_volatility_finds() {
    let Some(profile) = profile(XP) else {
        return;
    };
    let Some(theirs) = oracle_processes(ORACLE_XP) else {
        return;
    };
    let sweep = sweep_for_processes(&profile);

    // A sweep that stopped early makes "Séance found no allocation there" a
    // statement about the cap rather than about the image.
    assert!(
        !sweep.outcome.truncated,
        "the object cap fired, so a missing allocation would be a cap and not a finding"
    );
    assert!(
        !sweep.outcome.scan.truncated,
        "the byte scan stopped early, so the sweep did not reach the whole image"
    );

    let ours = sweep.by_offset();
    assert!(
        theirs.keys().eq(ours.keys()),
        "the XP process sweep disagrees with Volatility.\n{}",
        difference(&theirs, &ours)
    );

    // Right-sized and right-placed is still not right: the bytes at each offset
    // have to be the same process on both sides. An off-by-sixteen placement
    // that happened to land on another allocation's tag would pass the offset
    // comparison and fail here.
    let disagreements = field_disagreements(&theirs, &ours);
    assert!(
        disagreements.is_empty(),
        "the two tools found the same allocations and read different processes out of them:\n  {}",
        disagreements.join("\n  ")
    );

    assert_eq!(
        ours.len(),
        XP_POOL_PROCESSES,
        "the recorded answer for this image is {XP_POOL_PROCESSES} pool hits"
    );
}

#[test]
fn xp_the_process_sweep_finds_every_process_the_active_list_links() {
    let Some(profile) = profile(XP) else {
        return;
    };
    let sweep = sweep_for_processes(&profile);
    let found: BTreeSet<u64> = sweep.by_offset().keys().copied().collect();

    // A linked process is, by definition, still in pool memory. A sweep that
    // misses one is broken however good its count looks: it would mean the
    // placement arithmetic lands on the right address only sometimes.
    let linked = believable_processes(&profile);
    assert_eq!(
        linked.len(),
        XP_LINKED_PROCESSES,
        "the active list is the wrong length before the comparison even starts"
    );

    let mut missing = Vec::new();
    for (address, pid, name) in &linked {
        let Some(physical) = physical_of(&profile, *address) else {
            panic!(
                "pid {pid:?} ({name:?}) is linked into the active list at {address:#x} and that \
                 address does not translate, so the two spaces cannot be compared at all"
            );
        };
        if !found.contains(&physical) {
            missing.push(format!(
                "pid {pid:?} {name:?} at {address:#x} (physical {physical:#x})"
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "the pool sweep missed {} process(es) the active list links, which are by definition still \
         in pool memory:\n  {}",
        missing.len(),
        missing.join("\n  ")
    );
}

#[test]
fn xp_the_process_sweep_recovers_fifteen_processes_the_active_list_no_longer_links() {
    let Some(profile) = profile(XP) else {
        return;
    };
    let Some(theirs) = oracle_processes(ORACLE_XP) else {
        return;
    };
    let sweep = sweep_for_processes(&profile);
    let ours = sweep.by_offset();

    // Which of ours the active list also holds. Everything else is a terminated
    // or unlinked remnant, and those are the rows a pool sweep exists to
    // produce. Reproducing only the linked 47 would mean pool scanning is not
    // working even though pslist looks perfect.
    let linked: BTreeSet<u64> = believable_processes(&profile)
        .iter()
        .filter_map(|(address, _, _)| physical_of(&profile, *address))
        .collect();

    let unlinked: Vec<String> = ours
        .iter()
        .filter(|&(offset, _)| !linked.contains(offset))
        .map(|(offset, (pid, name))| format!("{offset:#x} pid={pid:?} name={name:?}"))
        .collect();
    assert_eq!(
        unlinked.len(),
        XP_POOL_PROCESSES - XP_LINKED_PROCESSES,
        "the sweep should hold {} allocation(s) the active list does not; it holds {}:\n  {}",
        XP_POOL_PROCESSES - XP_LINKED_PROCESSES,
        unlinked.len(),
        unlinked.join("\n  ")
    );

    // And they must be the same fifteen Volatility recovers, not fifteen of
    // something else. Four of them are processes whose ExitTime the oracle
    // records; the rest are stale copies at addresses the kernel has reused.
    let theirs_unlinked: BTreeSet<u64> = theirs
        .keys()
        .copied()
        .filter(|offset| !linked.contains(offset))
        .collect();
    let ours_unlinked: BTreeSet<u64> = ours
        .keys()
        .copied()
        .filter(|offset| !linked.contains(offset))
        .collect();
    assert_eq!(
        ours_unlinked,
        theirs_unlinked,
        "the unlinked remnants disagree with Volatility's.\n{}",
        difference(&theirs, &ours)
    );

    // One of them, named, so that a set that is the right size for the wrong
    // reason still fails. PluckUpdater.ex exited at 16:53:49, six minutes
    // before the image was taken, and the active list does not link it.
    let (pid, name) = ours
        .get(&0x16c7_f9d0)
        .expect("Volatility recovers a terminated PluckUpdater at physical 0x16c7f9d0");
    assert_eq!(*pid, Some(1916));
    assert_eq!(name, "PluckUpdater.ex");
}

#[test]
fn xp_every_tag_match_is_either_an_object_or_a_counted_rejection() {
    let Some(profile) = profile(XP) else {
        return;
    };
    let sweep = sweep_for_processes(&profile);
    let outcome = &sweep.outcome;

    // `Proc` occurs constantly in ordinary data — inside "Processor", inside
    // compressed streams, inside string tables. None of it is evidence, and
    // none of it may be emitted with defaults filled in. Every match must land
    // on exactly one side of the ledger.
    assert_eq!(
        outcome.candidates,
        outcome.objects.len() + outcome.rejected_total,
        "{} tag match(es) produced {} object(s) and {} rejection(s), so some matches were neither \
         reported nor accounted for",
        outcome.candidates,
        outcome.objects.len(),
        outcome.rejected_total
    );
    assert!(
        outcome.rejected_total > 0,
        "not one four-byte coincidence in a 512 MiB image was rejected, which means the validity \
         checks did not run"
    );
    for rejection in &outcome.rejected {
        assert!(
            !rejection.reason.trim().is_empty(),
            "the candidate at {:#x} was discarded without a reason, and an examiner cannot audit \
             a silent rejection",
            rejection.tag_address
        );
    }
}

// ── Windows 11 22000, x86-64 ────────────────────────────────────────────────

#[test]
fn win11_the_process_sweep_runs_in_the_kernel_virtual_space_as_volatility_does() {
    let Some(profile) = profile(WIN11) else {
        return;
    };
    let sweep = sweep_for_processes(&profile);

    assert_eq!(
        sweep.symbols.space,
        ScanSpace::KernelVirtual,
        "from Windows 10 the pool is laid out such that a physical sweep no longer finds it"
    );
    assert!(
        sweep.symbols.top_down,
        "Windows 8 and later place the optional object headers per object, so the body is found \
         by searching forward rather than by measuring back from the end of the allocation"
    );
    assert_eq!(
        sweep.symbols.alignment, 16,
        "the pool allocator's granularity on a 64-bit kernel is 16 bytes"
    );
}

#[test]
fn win11_the_process_sweep_finds_exactly_the_allocations_volatility_finds() {
    let Some(profile) = profile(WIN11) else {
        return;
    };
    let Some(theirs) = oracle_processes(ORACLE_WIN11) else {
        return;
    };
    let sweep = sweep_for_processes(&profile);

    assert!(
        !sweep.outcome.truncated,
        "the object cap fired, so a missing allocation would be a cap and not a finding"
    );
    assert!(
        !sweep.outcome.scan.truncated,
        "the byte scan stopped early, so the sweep did not reach the whole address space"
    );

    let ours = sweep.by_offset();
    assert!(
        theirs.keys().eq(ours.keys()),
        "the Windows 11 process sweep disagrees with Volatility.\n{}",
        difference(&theirs, &ours)
    );

    let disagreements = field_disagreements(&theirs, &ours);
    assert!(
        disagreements.is_empty(),
        "the two tools found the same allocations and read different processes out of them:\n  {}",
        disagreements.join("\n  ")
    );

    assert_eq!(
        ours.len(),
        WIN11_POOL_PROCESSES,
        "the recorded answer for this image is {WIN11_POOL_PROCESSES} pool hits"
    );

    // Every _EPROCESS on this build lives above the 32-bit boundary. An address
    // that fits in 32 bits would mean a pointer was read four bytes wide, which
    // yields a plausible-looking table of entirely wrong structures.
    for object in &sweep.outcome.objects {
        assert!(
            object.address > u64::from(u32::MAX),
            "the object at {:#x} looks like a truncated pointer",
            object.address
        );
    }
}

#[test]
fn win11_a_pool_allocation_yields_one_process_rather_than_one_per_candidate_placement() {
    let Some(profile) = profile(WIN11) else {
        return;
    };
    let Some(theirs) = oracle_processes(ORACLE_WIN11) else {
        return;
    };
    let sweep = sweep_for_processes(&profile);

    // This is the image where the question has an answer. Windows 11 is a
    // top-down build: the object header's distance from the pool header is not
    // fixed, several aligned offsets inside one allocation can pass the
    // PointerCount and InfoMask tests, and upstream emits a row for each. Séance
    // returns the first survivor instead.
    assert!(
        sweep.symbols.top_down,
        "the candidate-placement question only arises on a top-down build"
    );

    let mut by_allocation: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for object in &sweep.outcome.objects {
        by_allocation
            .entry(object.pool_header)
            .or_default()
            .push(object.address);
    }
    let doubled: Vec<String> = by_allocation
        .iter()
        .filter(|(_, addresses)| addresses.len() > 1)
        .map(|(pool_header, addresses)| {
            let rendered: Vec<String> = addresses.iter().map(|a| format!("{a:#x}")).collect();
            format!("{pool_header:#x} -> {}", rendered.join(", "))
        })
        .collect();
    assert!(
        doubled.is_empty(),
        "one pool allocation holds one object, and {} allocation(s) produced more than one row, \
         which is the same evidence counted twice:\n  {}",
        doubled.len(),
        doubled.join("\n  ")
    );

    // The other half of the claim: taking only the first survivor did not throw
    // the true object away. If it had, the count would be short of the oracle's
    // and the offset comparison above would already have named which.
    assert_eq!(
        by_allocation.len(),
        theirs.len(),
        "{} allocation(s) produced rows against Volatility's {}; taking the first surviving body \
         placement has changed the answer",
        by_allocation.len(),
        theirs.len()
    );
}

#[test]
fn win11_psscan_and_pslist_have_the_same_row_count_and_not_the_same_rows() {
    let Some(profile) = profile(WIN11) else {
        return;
    };
    let Some(theirs) = oracle_processes(ORACLE_WIN11) else {
        return;
    };
    let sweep = sweep_for_processes(&profile);
    let ours = sweep.by_offset();

    // Both tables have 103 rows on this image, and the equality is a
    // coincidence rather than agreement: the sweep does not hold the System
    // process, the list does not hold a terminated autochk.exe or a second
    // svchost.exe, and the list holds one row that is not a process at all.
    // Asserting the counts match would assert nothing.
    let linked = believable_processes(&profile);
    let linked_offsets: BTreeSet<u64> = linked
        .iter()
        .map(|(address, _, _)| truncate_to_48(*address))
        .collect();

    let scan_only: Vec<String> = ours
        .iter()
        .filter(|&(offset, _)| !linked_offsets.contains(offset))
        .map(|(offset, (pid, name))| format!("{offset:#x} pid={pid:?} name={name:?}"))
        .collect();
    assert!(
        !scan_only.is_empty(),
        "the sweep found nothing the active list does not, which on this image means it degraded \
         into a second process list"
    );

    // The sweep must still hold every linked process bar one, and that one is
    // named and explained below rather than tolerated as slack.
    let mut absent = Vec::new();
    for (address, pid, name) in &linked {
        let offset = truncate_to_48(*address);
        if !ours.contains_key(&offset) {
            absent.push((offset, *pid, name.clone()));
        }
    }
    let unexplained: Vec<String> = absent
        .iter()
        .filter(|(offset, _, _)| *offset != truncate_to_48(WIN11_SYSTEM_EPROCESS))
        .map(|(offset, pid, name)| format!("{offset:#x} pid={pid:?} name={name:?}"))
        .collect();
    assert!(
        unexplained.is_empty(),
        "the pool sweep missed {} linked process(es) other than System, which are by definition \
         still in pool memory:\n  {}",
        unexplained.len(),
        unexplained.join("\n  ")
    );

    // Volatility reaches the same conclusion about System, so this is not a
    // place where Séance is quietly worse.
    assert!(
        !theirs.contains_key(&truncate_to_48(WIN11_SYSTEM_EPROCESS)),
        "Volatility's psscan does list the System process on this image, so Séance omitting it \
         would be a defect rather than a property of the capture"
    );
}

#[test]
fn win11_the_system_process_is_absent_from_the_sweep_because_its_allocation_carries_no_tag() {
    let Some(profile) = profile(WIN11) else {
        return;
    };
    let sweep = sweep_for_processes(&profile);
    let ours = sweep.by_offset();

    // The System process is in the active list and in no pool sweep of this
    // image — neither Séance's nor Volatility's. That is a fact about the
    // capture, not a defect in either tool, and this test proves it from the
    // bytes rather than asserting the absence and leaving it unexplained.
    assert!(
        !ours.contains_key(&truncate_to_48(WIN11_SYSTEM_EPROCESS)),
        "the System process appeared in the sweep; if its allocation really is tagged, the reason \
         recorded here is wrong and the rest of this file's expectations rest on it"
    );

    // Where a `Proc` tag would have to lie for the top-down search to place a
    // body at System's address: at most the pool header, the object header and
    // every optional header this build declares, in front of the body. The
    // reach is computed from the symbol table rather than written down, because
    // a constant here would be a different window on a different build.
    let body_offset = sweep
        .symbols
        .body_offset
        .expect("_OBJECT_HEADER is in this build's symbols");
    let reach = sweep
        .symbols
        .max_optional_headers
        .saturating_add(sweep.symbols.pool_header_size)
        .saturating_add(body_offset);
    let start = WIN11_SYSTEM_EPROCESS
        .checked_sub(reach)
        .expect("the System _EPROCESS is not within one pool allocation of address zero");

    let kernel = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let bytes = kernel
        .read_bytes(start, reach)
        .expect("the bytes in front of the System _EPROCESS are mapped");
    let tagged: Vec<usize> = bytes
        .windows(4)
        .enumerate()
        .filter(|(_, window)| PROCESS_TAGS.iter().any(|tag| window.starts_with(tag)))
        .map(|(index, _)| index)
        .collect();
    assert!(
        tagged.is_empty(),
        "a process pool tag lies {tagged:?} byte(s) into the {reach} byte(s) in front of the \
         System _EPROCESS, so the allocation is tagged after all and the sweep should have found it"
    );
}

// ── Threads: the other half of the placement question ───────────────────────

/// One `Thre` allocation must yield one thread, on both reference images.
///
/// The process half of this question is settled by
/// [`win11_a_pool_allocation_yields_one_process_rather_than_one_per_candidate_placement`],
/// which can check both halves of its claim because Volatility's
/// `windows.psscan` gives a row count to compare against.
///
/// Threads have no such oracle: **Volatility 3 2.28.2 ships no `windows.thrdscan`**
/// — the plugin list offers only `suspended_threads`, `suspicious_threads` and
/// `orphan_kernel_threads` — so there is no upstream sweep whose count this could
/// be measured against, and there is no honest way to assert "we found the right
/// number of threads" here.
///
/// What needs no oracle is the half that actually caused the doubt. A `Thre`
/// allocation constrained only by its CID can have several aligned body
/// placements that all satisfy that one check, and emitting a row for each turns
/// one thread into several. "Several placements survived" and "several threads
/// existed" are different claims, and a report must make the second. That is
/// checkable from the sweep alone: no allocation may produce more than one row.
#[test]
fn a_thread_allocation_yields_one_thread_rather_than_one_per_candidate_placement() {
    for image in [XP, WIN11] {
        let Some(profile) = profile(image) else {
            continue;
        };
        let symbols = PoolSymbols::from_profile(&profile)
            .expect("both reference builds can be described well enough to sweep");
        // Both tags, as the process sweep uses both of its own. XP tags a
        // thread allocation `Thr\xe5`; `Thre` arrives with Windows 8. Sweeping
        // for one of them found nothing at all on XP, which is exactly what an
        // examiner would have read as "no threads".
        let constraints = builtin_constraints_for(&THREAD_TAGS);
        assert_eq!(
            constraints.len(),
            THREAD_TAGS.len(),
            "{image}: a thread tag lost its builtin constraint, so half the allocations would \
             never be looked at and the short list would look complete"
        );

        let config = PoolScanConfig {
            type_map: ObjectTypeMap::from_profile(&profile).ok().map(Arc::new),
            ..PoolScanConfig::default()
        };
        let outcome = pool_scan(&profile, &symbols, &constraints, &config)
            .expect("the thread sweep is runnable on both reference images");

        // An empty sweep would make the assertion below vacuous, and a machine
        // with no threads at all is not a thing.
        assert!(
            !outcome.objects.is_empty(),
            "{image}: the thread sweep found nothing, so the check below proves nothing"
        );

        let mut by_allocation: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for object in &outcome.objects {
            by_allocation
                .entry(object.pool_header)
                .or_default()
                .push(object.address);
        }
        let doubled: Vec<String> = by_allocation
            .iter()
            .filter(|(_, addresses)| addresses.len() > 1)
            .map(|(pool_header, addresses)| {
                let rendered: Vec<String> = addresses.iter().map(|a| format!("{a:#x}")).collect();
                format!("{pool_header:#x} -> {}", rendered.join(", "))
            })
            .collect();
        assert!(
            doubled.is_empty(),
            "{image}: one pool allocation holds one thread, and {} allocation(s) produced more \
             than one row, which is the same evidence counted twice:\n  {}",
            doubled.len(),
            doubled.join("\n  ")
        );
    }
}
