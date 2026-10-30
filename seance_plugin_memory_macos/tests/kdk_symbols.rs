//! The macOS tier's symbol half, against a real Apple Kernel Debug Kit.
//!
//! # What this does and does not establish
//!
//! There is no macOS memory capture in this repository and no oracle to compare
//! one against, so **nothing here shows that a process list this tier produces
//! is correct**. That gate stays shut: the tier is registered and runs, and
//! every record it emits carries the marker saying so, because withholding the
//! analysis altogether left a Mac capture silent rather than caveated.
//!
//! What a real KDK does establish is everything up to the address space: that
//! Apple's own symbols pass the admission gate, that the banner this tier keys
//! on is where it expects, and that every member `PROC_LAYOUT` declares
//! required actually exists in a shipped kernel. Those are the parts that would
//! otherwise rot silently against changes to `seance_symbols` — and, until this
//! crate joined the workspace, no build even compiled them.
//!
//! The pack is `macOS10.12.3KDK.dmg.json.xz`, produced by dwarf2json 0.6.0:
//! 4,839 user types and 43,548 symbols from xnu-3789.41.3~3, RELEASE_X86_64.

use std::path::PathBuf;
use std::sync::Arc;

use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable};

/// The one real Apple symbol pack in the tree, or `None` when `reference/` is
/// absent — that is a skip, not a failure, because the corpus is gitignored.
fn kdk_path() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .join("reference/volatility3/volatility3/symbols/macOS10.12.3KDK.dmg.json.xz");
    path.exists().then_some(path)
}

fn kdk() -> Option<Arc<SymbolTable>> {
    let path = kdk_path()?;
    let table = SymbolTable::compile_path(
        &path,
        &DecompressLimits::default(),
        &CompileOptions::default(),
    )
    .unwrap_or_else(|err| panic!("Apple's own KDK must compile: {err}"));
    Some(Arc::new(table))
}

#[test]
fn a_real_apple_kernel_debug_kit_passes_the_admission_gate() {
    let Some(table) = kdk() else {
        eprintln!("skipping: reference/ is gitignored and absent here");
        return;
    };
    // The gate refuses a table it cannot vouch for. Apple's own symbols must
    // not be among them -- if they are, the gate is wrong, not the kit.
    let report = table.admission();
    assert!(
        report.failures().next().is_none(),
        "a shipped Apple KDK was refused: {:?}",
        report.failures().collect::<Vec<_>>()
    );
}

#[test]
fn the_banner_this_tier_keys_on_is_where_it_expects() {
    let Some(table) = kdk() else {
        return;
    };
    // Identification rests entirely on this symbol: `version` carries the
    // Darwin banner as constant data, and a pack without it can never be
    // selected (which is why the 32-bit packs of 10.6-10.7 cannot be).
    let symbol = table
        .symbol("version")
        .expect("a macOS ISF names its banner symbol `version`");
    // `constant_data` is base64 in the ISF; the reader decodes it.
    let bytes = symbol
        .constant_bytes()
        .expect("the banner must be strict base64")
        .expect("the banner is carried as constant data, not read from the image");
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.starts_with("Darwin Kernel Version "),
        "the banner must be Darwin's: {text}"
    );
    assert!(text.contains("RELEASE_X86_64"), "{text}");
}

#[test]
fn every_member_the_process_stage_requires_exists_in_a_shipped_kernel() {
    let Some(table) = kdk() else {
        return;
    };
    // The point of the declarative binding: a member the stage marks Required
    // must be present in a real build, or the stage can never run on that
    // build. Checking against Apple's own types is the only way to know that
    // before a capture arrives.
    for (type_name, member) in [
        ("proc", "p_pid"),
        ("proc", "p_ppid"),
        ("proc", "p_uid"),
        ("proc", "p_comm"),
        ("proc", "p_stat"),
        ("proclist", "lh_first"),
    ] {
        assert!(
            table.has_member(type_name, member),
            "xnu-3789 declares no `{type_name}.{member}`, so the stage's \
             declaration is wrong about a shipped kernel"
        );
    }

    // And the two facts the paging half needs.
    assert!(
        table.symbol("BootPML4").is_ok(),
        "the page-table root symbol"
    );
    assert!(
        table.aggregate("task").is_ok(),
        "the task structure the thread walk reads"
    );
}

/// The binding resolves to the offsets Apple actually declares.
///
/// Stronger than "a member of that name exists", which the test above checks.
/// A `MemberSpec` lists candidate names in preference order, so a declaration
/// naming the wrong candidate first still finds *something* and reads the wrong
/// bytes — a pid taken from `p_ppid` is a plausible integer, and nothing
/// downstream would catch it. Pinning the resolved offset against the shipped
/// kernel is what makes the declaration falsifiable.
///
/// Values are xnu-3789.41.3~3 (macOS 10.12.3), read out of the kit itself.
#[test]
fn the_declarations_resolve_to_the_offsets_the_shipped_kernel_uses() {
    let Some(table) = kdk() else {
        return;
    };

    for (type_name, member, expected) in [
        ("proc", "p_list", 0u64),
        ("proc", "p_pid", 16),
        ("proc", "p_ppid", 40),
        ("proc", "p_uid", 48),
        ("proc", "p_gid", 52),
        ("proc", "p_stat", 104),
        ("proc", "p_comm", 740),
        ("proclist", "lh_first", 0),
    ] {
        let offset = table
            .member_offset(type_name, member)
            .unwrap_or_else(|e| panic!("{type_name}.{member}: {e}"));
        assert_eq!(
            offset, expected,
            "{type_name}.{member} is at {offset} in xnu-3789, not {expected}; either the kit \
             changed or the reader is resolving a different member"
        );
    }

    // The size the walk bounds-checks each entry against, before it reads one.
    assert_eq!(
        table.size_of("proc").expect("proc has a declared size"),
        1144,
        "the entry size the walk uses to refuse an out-of-bounds read"
    );
}

// ── The walk, over Apple's real structure geometry ──────────────────────────

use seance_core::data_source::ByteSliceDataSource;
use seance_memory::binding::{Evidence, Found};
use seance_memory::translate::{PagingMode, PagingSpec, PteSemantics, VirtualLayer};
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_macos::process::{list_allproc, ProcessSymbols, ProcessWalkConfig};
use seance_plugin_memory_macos::profile::MacProfile;
use seance_plugin_memory_macos::DarwinVersion;

/// Physical layout of the synthetic image. Small because one page table covers
/// every address used: `allproc` and both `proc` entries share pml4 511,
/// pdpt 0, pd 5.
const PML4: u64 = 0x1000;
const PDPT: u64 = 0x2000;
const PD: u64 = 0x3000;
const PT: u64 = 0x4000;
const ALLPROC_PAGE: u64 = 0x5000;
const PROC1_PAGE: u64 = 0x6000;
const PROC2_PAGE: u64 = 0x7000;
const IMAGE_SIZE: usize = 0x9000;
const PRESENT: u64 = 1;

/// Virtual addresses, taken from the kit rather than invented: `allproc` is
/// where xnu-3789 declares it. The two `proc` entries are placed on their own
/// pages inside the same page table.
const ALLPROC_VA: u64 = 0xffff_ff80_00ab_c490;
const PROC1_VA: u64 = 0xffff_ff80_00b0_0000;
const PROC2_VA: u64 = 0xffff_ff80_00b0_1000;

/// Apple's own offsets for xnu-3789.41.3~3, asserted by the test above.
const P_LIST: u64 = 0;
const P_PID: u64 = 16;
const P_PPID: u64 = 40;
const P_COMM: u64 = 740;

fn put64(bytes: &mut [u8], base: u64, index: u64, value: u64) {
    let at = (base + index * 8) as usize;
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_at(bytes: &mut [u8], page: u64, offset: u64, data: &[u8]) {
    let at = (page + offset) as usize;
    bytes[at..at + data.len()].copy_from_slice(data);
}

/// An image whose page tables map the three kernel addresses this walk touches,
/// with a two-entry process list laid out at Apple's real member offsets.
///
/// Ground truth is what is written here: pids 1 and 42, named `launchd` and
/// `mds`, in that order, and the list ends with a null forward link.
fn image() -> Vec<u8> {
    image_slid(0)
}

/// The same image with every pointer it writes moved by `slide`, which is what
/// a running kernel actually stores: the links in memory are slid addresses,
/// not the ones the symbol pack declares.
fn image_slid(slide: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; IMAGE_SIZE];
    put64(&mut bytes, PML4, 511, PDPT | PRESENT);
    put64(&mut bytes, PDPT, 0, PD | PRESENT);
    put64(&mut bytes, PD, 5, PT | PRESENT);
    put64(&mut bytes, PT, 188, ALLPROC_PAGE | PRESENT);
    put64(&mut bytes, PT, 256, PROC1_PAGE | PRESENT);
    put64(&mut bytes, PT, 257, PROC2_PAGE | PRESENT);

    // `allproc.lh_first` -> first proc. The head sits at offset 0x490 in its
    // page, which is where the symbol's address lands.
    put_at(
        &mut bytes,
        ALLPROC_PAGE,
        0x490,
        &(PROC1_VA + slide).to_le_bytes(),
    );

    put_at(
        &mut bytes,
        PROC1_PAGE,
        P_LIST,
        &(PROC2_VA + slide).to_le_bytes(),
    );
    put_at(&mut bytes, PROC1_PAGE, P_PID, &1i32.to_le_bytes());
    put_at(&mut bytes, PROC1_PAGE, P_PPID, &0i32.to_le_bytes());
    put_at(&mut bytes, PROC1_PAGE, P_COMM, b"launchd\0");

    // A null forward link ends the list; nothing follows this entry.
    put_at(&mut bytes, PROC2_PAGE, P_LIST, &0u64.to_le_bytes());
    put_at(&mut bytes, PROC2_PAGE, P_PID, &42i32.to_le_bytes());
    put_at(&mut bytes, PROC2_PAGE, P_PPID, &1i32.to_le_bytes());
    put_at(&mut bytes, PROC2_PAGE, P_COMM, b"mds\0");
    bytes
}

fn profile(table: Arc<SymbolTable>) -> MacProfile {
    profile_with(table, image(), 0)
}

/// The same profile with an explicit image and kernel slide.
fn profile_with(table: Arc<SymbolTable>, bytes: Vec<u8>, slide: u64) -> MacProfile {
    let physical: Arc<dyn MemoryLayer> = Arc::new(
        PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(bytes))).expect("a non-empty image"),
    );
    let kernel_space: Arc<dyn MemoryLayer> = Arc::new(
        VirtualLayer::new(
            Arc::clone(&physical),
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare),
        )
        .expect("a usable page-table base"),
    );
    MacProfile {
        kernel_space,
        physical,
        symbols: table,
        dtb: Found::new(PML4, Evidence::Validated),
        slide: Found::new(slide, Evidence::Validated),
        kernel_base: Found::new(0xffff_ff80_0020_0000, Evidence::Validated),
        banner: "Darwin Kernel Version 16.4.0".to_string(),
        version: DarwinVersion {
            major: 16,
            minor: 4,
            patch: 0,
        },
        isf_path: kdk_path().expect("the kit"),
    }
}

/// The process walk, run over Apple's real member offsets.
///
/// This is not a substitute for a capture: the memory is synthetic and the
/// ground truth is what the fixture wrote. What it does establish is that the
/// walk reads `p_pid` and `p_comm` where a shipped kernel actually puts them,
/// follows `p_list.le_next` correctly, and stops on a null link — with real
/// geometry rather than a hand-written ISF that could agree with a wrong
/// declaration.
#[test]
fn the_walk_recovers_the_processes_placed_at_the_kernels_own_offsets() {
    let Some(table) = kdk() else {
        return;
    };
    let profile = profile(table);
    let symbols = ProcessSymbols::from_profile(&profile).expect("PROC_LAYOUT binds to xnu-3789");
    let list = list_allproc(&profile, &symbols, &ProcessWalkConfig::default())
        .expect("the list is walkable");

    let pids: Vec<Option<i64>> = list.processes.iter().map(|p| p.known_pid()).collect();
    assert_eq!(pids, vec![Some(1), Some(42)], "both entries, in list order");

    assert!(
        list.is_complete(),
        "a walk that ended on a null link is complete, not short: {:?}",
        list.stop
    );
}

/// A kernel slide moves every declared address, and the walk must follow.
///
/// The slide is not cosmetic: `profile.symbol()` adds it to what the kit
/// declares, so a tier that ignored it would look for `allproc` at the
/// unslid address and find whatever happens to live there. On a real Mac that
/// is the ordinary case — ASLR is on — so a walk that only works at slide zero
/// works on no capture at all.
///
/// The image is rebuilt with every page shifted by one 2 MiB page-directory
/// entry, which is what a slide does to the address space.
#[test]
fn the_walk_follows_the_kernel_slide_rather_than_the_declared_address() {
    let Some(table) = kdk() else {
        return;
    };
    // One PD entry is 2 MiB of virtual address space, so sliding by that lands
    // the same offsets in pd index 6 instead of 5.
    const SLIDE: u64 = 0x20_0000;

    let mut bytes = image_slid(SLIDE);
    // Re-point the tables: the slid addresses resolve through pd[6].
    put64(&mut bytes, PD, 5, 0);
    put64(&mut bytes, PD, 6, PT | PRESENT);

    let profile = profile_with(table, bytes, SLIDE);
    let symbols = ProcessSymbols::from_profile(&profile).expect("PROC_LAYOUT binds");

    // The head is now reached at allproc + SLIDE, and every link the fixture
    // wrote must be followed the same way.
    assert_eq!(
        profile.symbol("allproc").expect("a slid symbol"),
        ALLPROC_VA + SLIDE,
        "the slide must be added to the declared address"
    );

    let list = list_allproc(&profile, &symbols, &ProcessWalkConfig::default())
        .expect("the slid list is walkable");
    let pids: Vec<Option<i64>> = list.processes.iter().map(|p| p.known_pid()).collect();
    assert_eq!(
        pids,
        vec![Some(1), Some(42)],
        "the same two processes, reached through the slid address space"
    );
}

/// A link into memory the acquisition did not capture ends the walk *loudly*.
///
/// This is the defect class this whole tree guards against, in its macOS form.
/// A list whose second entry sits on an unacquired page can be reported two
/// ways: as a one-process machine, or as a walk that reached one process and
/// could not follow the chain further. The first is a claim the evidence never
/// supported, and in a report it is indistinguishable from a Mac that really
/// was running one process.
///
/// The fixture removes the page-table entry for the second `proc`, which is
/// what an unacquired region looks like from the walker's side.
#[test]
fn a_link_into_unacquired_memory_is_reported_rather_than_silently_ending_the_list() {
    let Some(table) = kdk() else {
        return;
    };
    let mut bytes = image();
    // The second process's page is no longer mapped: its link still points
    // there, so the chain continues and this image cannot follow it.
    put64(&mut bytes, PT, 257, 0);

    let profile = profile_with(table, bytes, 0);
    let symbols = ProcessSymbols::from_profile(&profile).expect("PROC_LAYOUT binds");
    let list = list_allproc(&profile, &symbols, &ProcessWalkConfig::default())
        .expect("a walk that cannot finish is still a walk");

    let pids: Vec<Option<i64>> = list.processes.iter().map(|p| p.known_pid()).collect();
    assert_eq!(pids, vec![Some(1)], "only the reachable entry is listed");

    assert!(
        !list.is_complete(),
        "a list that could not be followed to its end must not read as complete"
    );
    match &list.stop {
        seance_plugin_memory_macos::process::ChainStop::Unreadable { at, detail, .. } => {
            assert_eq!(
                *at,
                Some(PROC2_VA),
                "the stop names the address it could not read, so an examiner can see where \
                 the list was lost"
            );
            assert!(!detail.is_empty(), "and says why");
        }
        other => panic!("an unfollowable link must be Unreadable, not {other:?}"),
    }
}

/// The kernel mapped with 2 MiB pages, which is how a real Mac maps it.
///
/// macOS maps kernel text and data with large pages, so the page walk ends at
/// the page-directory level with PS=1 rather than descending to a page table.
/// A walk that only handles 4 KiB leaves would translate nothing on a real
/// capture — every address in the kernel half would look unmapped, and the
/// whole tier would report an image it could not read.
///
/// Same list, same offsets, one 2 MiB mapping covering all three addresses.
#[test]
fn the_walk_translates_a_kernel_mapped_with_large_pages() {
    let Some(table) = kdk() else {
        return;
    };
    // Bit 7 of a PDE. Set, the walk ends there and the low 21 bits of the
    // virtual address index into the 2 MiB frame.
    const LARGE_PAGE: u64 = 1 << 7;
    // 2 MiB-aligned, as a large frame must be.
    const FRAME: u64 = 0x20_0000;
    // The virtual 2 MiB region pd[5] covers begins here.
    const REGION_BASE: u64 = 0xffff_ff80_00a0_0000;
    const BIG_IMAGE: usize = 0x40_0000;

    let mut bytes = vec![0u8; BIG_IMAGE];
    put64(&mut bytes, PML4, 511, PDPT | PRESENT);
    put64(&mut bytes, PDPT, 0, PD | PRESENT);
    // No page table at all: the walk must stop here.
    put64(&mut bytes, PD, 5, FRAME | PRESENT | LARGE_PAGE);

    let at = |va: u64| FRAME + (va - REGION_BASE);
    put_at(&mut bytes, at(ALLPROC_VA), 0, &PROC1_VA.to_le_bytes());
    put_at(&mut bytes, at(PROC1_VA), P_LIST, &PROC2_VA.to_le_bytes());
    put_at(&mut bytes, at(PROC1_VA), P_PID, &7i32.to_le_bytes());
    put_at(&mut bytes, at(PROC1_VA), P_COMM, b"kernel_task\0");
    put_at(&mut bytes, at(PROC2_VA), P_LIST, &0u64.to_le_bytes());
    put_at(&mut bytes, at(PROC2_VA), P_PID, &99i32.to_le_bytes());
    put_at(&mut bytes, at(PROC2_VA), P_COMM, b"WindowServer\0");

    let profile = profile_with(table, bytes, 0);
    let symbols = ProcessSymbols::from_profile(&profile).expect("PROC_LAYOUT binds");
    let list = list_allproc(&profile, &symbols, &ProcessWalkConfig::default())
        .expect("a large-page kernel is walkable");

    let pids: Vec<Option<i64>> = list.processes.iter().map(|p| p.known_pid()).collect();
    assert_eq!(
        pids,
        vec![Some(7), Some(99)],
        "both processes, reached through a 2 MiB mapping rather than a page table"
    );
    assert!(list.is_complete(), "{:?}", list.stop);
}

/// A 1 GiB mapping, which is how the physical map is often laid down.
///
/// The last translation shape a real x86-64 kernel can present: PS=1 at the
/// page-directory-pointer level, so the walk ends two levels above a page
/// table and the low 30 bits of the address index the frame. A tier that
/// handled 4 KiB and 2 MiB but not this would read most of the kernel and
/// silently lose whatever the physmap covers.
#[test]
fn the_walk_translates_a_one_gibibyte_mapping() {
    let Some(table) = kdk() else {
        return;
    };
    const LARGE_PAGE: u64 = 1 << 7;
    // A 1 GiB frame must be 1 GiB aligned; zero is, and keeps the fixture to
    // the twelve megabytes the addresses themselves need.
    const FRAME: u64 = 0;
    const BIG_IMAGE: usize = 0xC0_0000;

    let mut bytes = vec![0u8; BIG_IMAGE];
    put64(&mut bytes, PML4, 511, PDPT | PRESENT);
    // No page directory and no page table beneath this.
    put64(&mut bytes, PDPT, 0, FRAME | PRESENT | LARGE_PAGE);

    // Within a 1 GiB page the low 30 bits of the virtual address are the offset.
    let at = |va: u64| FRAME + (va & 0x3FFF_FFFF);
    put_at(&mut bytes, at(ALLPROC_VA), 0, &PROC1_VA.to_le_bytes());
    put_at(&mut bytes, at(PROC1_VA), P_LIST, &PROC2_VA.to_le_bytes());
    put_at(&mut bytes, at(PROC1_VA), P_PID, &11i32.to_le_bytes());
    put_at(&mut bytes, at(PROC1_VA), P_COMM, b"launchservicesd\0");
    put_at(&mut bytes, at(PROC2_VA), P_LIST, &0u64.to_le_bytes());
    put_at(&mut bytes, at(PROC2_VA), P_PID, &203i32.to_le_bytes());
    put_at(&mut bytes, at(PROC2_VA), P_COMM, b"opendirectoryd\0");

    let profile = profile_with(table, bytes, 0);
    let symbols = ProcessSymbols::from_profile(&profile).expect("PROC_LAYOUT binds");
    let list = list_allproc(&profile, &symbols, &ProcessWalkConfig::default())
        .expect("a gibibyte-mapped kernel is walkable");

    let pids: Vec<Option<i64>> = list.processes.iter().map(|p| p.known_pid()).collect();
    assert_eq!(
        pids,
        vec![Some(11), Some(203)],
        "both processes, reached through a 1 GiB mapping"
    );
    assert!(list.is_complete(), "{:?}", list.stop);
}

/// The other two stages' declarations, pinned the same way as the process one.
///
/// `PROC_LAYOUT` was checked above; `TASK_LAYOUT` and `KEXT_LAYOUT` were not,
/// and an unchecked declaration is the same hazard whichever stage owns it — a
/// `MemberSpec` that names a member this kernel does not have fails the stage
/// on every capture, and one that resolves to the wrong member reads plausible
/// bytes from the wrong place.
///
/// Offsets are xnu-3789.41.3~3, read out of the kit.
#[test]
fn the_task_and_kext_declarations_match_the_shipped_kernel_too() {
    let Some(table) = kdk() else {
        return;
    };

    // The Mach side of a process, which the cross-view compares against the
    // BSD list to find a task with no `proc` behind it.
    for (type_name, member, expected) in [("task", "tasks", 40u64), ("task", "bsd_info", 896)] {
        assert_eq!(
            table
                .member_offset(type_name, member)
                .unwrap_or_else(|e| panic!("{member}: {e}")),
            expected,
            "{type_name}.{member} moved, or the declaration resolves elsewhere"
        );
    }
    assert_eq!(table.size_of("task").expect("task has a size"), 1360);
    assert!(
        table.aggregate("queue_entry").is_ok(),
        "the task list is a Mach queue, so its link type must be describable"
    );

    // Loaded kernel extensions.
    for (member, expected) in [
        ("next", 0u64),
        ("id", 12),
        ("name", 16),
        ("version", 80),
        ("reference_count", 144),
        ("address", 156),
        ("size", 164),
        ("hdr_size", 172),
        ("info_version", 8),
    ] {
        assert_eq!(
            table
                .member_offset("kmod_info", member)
                .unwrap_or_else(|e| panic!("kmod_info.{member}: {e}")),
            expected,
            "kmod_info.{member} moved, or the declaration resolves elsewhere"
        );
    }
    assert_eq!(
        table.size_of("kmod_info").expect("kmod_info has a size"),
        196
    );
}

/// The kernel-extension walk, over the kernel's own `kmod_info` geometry.
///
/// `KEXT_LAYOUT` was pinned above; this runs the walk that uses it. A loaded
/// kext list is what an examiner reaches for when asking whether something was
/// loaded into the kernel, so a chain that silently ends one entry early is a
/// rootkit's best friend.
#[test]
fn the_kext_walk_recovers_the_extensions_placed_at_the_kernels_own_offsets() {
    use seance_plugin_memory_macos::kext::{list_kexts, KextSymbols, KextWalkConfig};

    let Some(table) = kdk() else {
        return;
    };
    const LARGE_PAGE: u64 = 1 << 7;
    const FRAME: u64 = 0x20_0000;
    const REGION_BASE: u64 = 0xffff_ff80_00a0_0000;
    const BIG_IMAGE: usize = 0x40_0000;
    // `kmod` is where xnu-3789 declares the head of the loaded-extension chain.
    const KMOD_VA: u64 = 0xffff_ff80_00ac_2538;
    const KEXT1_VA: u64 = 0xffff_ff80_00b8_0000;
    const KEXT2_VA: u64 = 0xffff_ff80_00b8_1000;
    // kmod_info offsets, asserted against the kit above.
    const K_NEXT: u64 = 0;
    const K_NAME: u64 = 16;
    const K_VERSION: u64 = 80;
    const K_ADDRESS: u64 = 156;
    const K_SIZE: u64 = 164;

    let mut bytes = vec![0u8; BIG_IMAGE];
    put64(&mut bytes, PML4, 511, PDPT | PRESENT);
    put64(&mut bytes, PDPT, 0, PD | PRESENT);
    put64(&mut bytes, PD, 5, FRAME | PRESENT | LARGE_PAGE);
    let at = |va: u64| FRAME + (va - REGION_BASE);

    put_at(&mut bytes, at(KMOD_VA), 0, &KEXT1_VA.to_le_bytes());

    put_at(&mut bytes, at(KEXT1_VA), K_NEXT, &KEXT2_VA.to_le_bytes());
    put_at(
        &mut bytes,
        at(KEXT1_VA),
        K_NAME,
        b"com.apple.iokit.IOHIDFamily\0",
    );
    put_at(&mut bytes, at(KEXT1_VA), K_VERSION, b"2.0.0\0");
    put_at(
        &mut bytes,
        at(KEXT1_VA),
        K_ADDRESS,
        &0xffff_ff7f_8000_0000u64.to_le_bytes(),
    );
    put_at(&mut bytes, at(KEXT1_VA), K_SIZE, &0x8000u64.to_le_bytes());

    // Null forward link: the chain ends here and the walk must say so.
    put_at(&mut bytes, at(KEXT2_VA), K_NEXT, &0u64.to_le_bytes());
    put_at(&mut bytes, at(KEXT2_VA), K_NAME, b"com.example.rootkit\0");
    put_at(&mut bytes, at(KEXT2_VA), K_VERSION, b"1.0\0");
    put_at(
        &mut bytes,
        at(KEXT2_VA),
        K_ADDRESS,
        &0xffff_ff7f_9000_0000u64.to_le_bytes(),
    );
    put_at(&mut bytes, at(KEXT2_VA), K_SIZE, &0x1000u64.to_le_bytes());

    let profile = profile_with(table, bytes, 0);
    let symbols = KextSymbols::from_profile(&profile).expect("KEXT_LAYOUT binds to xnu-3789");
    let list = list_kexts(&profile, &symbols, &KextWalkConfig::default())
        .expect("the loaded-extension chain is walkable");

    let names: Vec<Option<&str>> = list
        .kexts
        .iter()
        .map(|k| k.name.known().map(String::as_str))
        .collect();
    assert_eq!(
        names,
        vec![
            Some("com.apple.iokit.IOHIDFamily"),
            Some("com.example.rootkit")
        ],
        "both extensions, in chain order, read at the kernel's own offsets"
    );
    assert!(
        list.is_complete(),
        "a null forward link is a complete ending: {:?}",
        list.stop
    );
}

/// The Mach task queue, walked over the kernel's own geometry.
///
/// The last of the three stages to have its walk exercised. A Mach queue is
/// circular rather than null-terminated — the final entry's `next` points back
/// at the head — and the links point at the `queue_entry` *inside* each task,
/// so the walker subtracts `task.tasks` (40) to reach the structure. Both are
/// places a walk can go wrong in a way that still returns plausible rows.
///
/// This listing is also half of the concealment check: a task with no `proc`
/// behind it is a process the BSD list does not admit to.
#[test]
fn the_task_queue_is_walked_and_paired_with_its_bsd_processes() {
    use seance_plugin_memory_macos::process::{list_tasks, TaskSymbols};

    let Some(table) = kdk() else {
        return;
    };
    const LARGE_PAGE: u64 = 1 << 7;
    const FRAME: u64 = 0x20_0000;
    const REGION_BASE: u64 = 0xffff_ff80_00a0_0000;
    const BIG_IMAGE: usize = 0x40_0000;
    // Where xnu-3789 declares the head of the task queue.
    const TASKS_VA: u64 = 0xffff_ff80_00a6_7a80;
    const TASK1_VA: u64 = 0xffff_ff80_00b4_0000;
    const TASK2_VA: u64 = 0xffff_ff80_00b4_1000;
    // Asserted against the kit above.
    const TASK_LINK: u64 = 40;
    const TASK_BSD_INFO: u64 = 896;

    let mut bytes = vec![0u8; BIG_IMAGE];
    put64(&mut bytes, PML4, 511, PDPT | PRESENT);
    put64(&mut bytes, PDPT, 0, PD | PRESENT);
    put64(&mut bytes, PD, 5, FRAME | PRESENT | LARGE_PAGE);
    let at = |va: u64| FRAME + (va - REGION_BASE);

    // The head points at the first task's link, not at the task itself.
    put_at(
        &mut bytes,
        at(TASKS_VA),
        0,
        &(TASK1_VA + TASK_LINK).to_le_bytes(),
    );
    put_at(
        &mut bytes,
        at(TASK1_VA),
        TASK_LINK,
        &(TASK2_VA + TASK_LINK).to_le_bytes(),
    );
    put_at(
        &mut bytes,
        at(TASK1_VA),
        TASK_BSD_INFO,
        &PROC1_VA.to_le_bytes(),
    );
    // Circular: the last entry closes the ring on the head.
    put_at(&mut bytes, at(TASK2_VA), TASK_LINK, &TASKS_VA.to_le_bytes());
    put_at(
        &mut bytes,
        at(TASK2_VA),
        TASK_BSD_INFO,
        &PROC2_VA.to_le_bytes(),
    );

    // The BSD processes the tasks point at.
    put_at(&mut bytes, at(PROC1_VA), P_PID, &1i32.to_le_bytes());
    put_at(&mut bytes, at(PROC1_VA), P_COMM, b"launchd\0");
    put_at(&mut bytes, at(PROC2_VA), P_PID, &88i32.to_le_bytes());
    put_at(&mut bytes, at(PROC2_VA), P_COMM, b"loginwindow\0");

    let profile = profile_with(table, bytes, 0);
    let task_symbols = TaskSymbols::from_profile(&profile).expect("TASK_LAYOUT binds to xnu-3789");
    let proc_symbols = ProcessSymbols::from_profile(&profile).expect("PROC_LAYOUT binds");
    let list = list_tasks(
        &profile,
        &task_symbols,
        &proc_symbols,
        &ProcessWalkConfig::default(),
    )
    .expect("the task queue is walkable");

    let pids: Vec<Option<i64>> = list.processes.iter().map(|p| p.known_pid()).collect();
    assert_eq!(
        pids,
        vec![Some(1), Some(88)],
        "both tasks, paired with the BSD process each points at"
    );
    assert!(
        list.is_complete(),
        "a queue that came back to its head is a complete ending, not a short walk: {:?}",
        list.stop
    );
}

/// A task with no entry on the BSD list, which is what concealment looks like.
///
/// The two listings exist to be compared: `allproc` is what the system will
/// admit to, the Mach queue is what it is actually running. A process unlinked
/// from `allproc` still has a task, so it appears in one listing and not the
/// other — and the cross-view is the only place that difference is visible.
///
/// The fixture gives the task queue two entries and `allproc` only the first.
#[test]
fn a_task_missing_from_the_bsd_list_is_surfaced_by_the_cross_view() {
    use seance_plugin_memory_macos::process::{cross_view, list_tasks, TaskSymbols};

    let Some(table) = kdk() else {
        return;
    };
    const LARGE_PAGE: u64 = 1 << 7;
    const FRAME: u64 = 0x20_0000;
    const REGION_BASE: u64 = 0xffff_ff80_00a0_0000;
    const BIG_IMAGE: usize = 0x40_0000;
    const TASKS_VA: u64 = 0xffff_ff80_00a6_7a80;
    const TASK1_VA: u64 = 0xffff_ff80_00b4_0000;
    const TASK2_VA: u64 = 0xffff_ff80_00b4_1000;
    const TASK_LINK: u64 = 40;
    const TASK_BSD_INFO: u64 = 896;

    let mut bytes = vec![0u8; BIG_IMAGE];
    put64(&mut bytes, PML4, 511, PDPT | PRESENT);
    put64(&mut bytes, PDPT, 0, PD | PRESENT);
    put64(&mut bytes, PD, 5, FRAME | PRESENT | LARGE_PAGE);
    let at = |va: u64| FRAME + (va - REGION_BASE);

    // Two tasks, each pointing at its BSD process.
    put_at(
        &mut bytes,
        at(TASKS_VA),
        0,
        &(TASK1_VA + TASK_LINK).to_le_bytes(),
    );
    put_at(
        &mut bytes,
        at(TASK1_VA),
        TASK_LINK,
        &(TASK2_VA + TASK_LINK).to_le_bytes(),
    );
    put_at(
        &mut bytes,
        at(TASK1_VA),
        TASK_BSD_INFO,
        &PROC1_VA.to_le_bytes(),
    );
    put_at(&mut bytes, at(TASK2_VA), TASK_LINK, &TASKS_VA.to_le_bytes());
    put_at(
        &mut bytes,
        at(TASK2_VA),
        TASK_BSD_INFO,
        &PROC2_VA.to_le_bytes(),
    );

    // `allproc` admits to the first process only: the second is unlinked, which
    // is exactly what a process hiding itself does.
    put_at(&mut bytes, at(ALLPROC_VA), 0, &PROC1_VA.to_le_bytes());
    put_at(&mut bytes, at(PROC1_VA), P_LIST, &0u64.to_le_bytes());
    put_at(&mut bytes, at(PROC1_VA), P_PID, &1i32.to_le_bytes());
    put_at(&mut bytes, at(PROC1_VA), P_COMM, b"launchd\0");
    put_at(&mut bytes, at(PROC2_VA), P_PID, &666i32.to_le_bytes());
    put_at(&mut bytes, at(PROC2_VA), P_COMM, b"hidden\0");

    let profile = profile_with(table, bytes, 0);
    let proc_symbols = ProcessSymbols::from_profile(&profile).expect("PROC_LAYOUT binds");
    let task_symbols = TaskSymbols::from_profile(&profile).expect("TASK_LAYOUT binds");

    let allproc = list_allproc(&profile, &proc_symbols, &ProcessWalkConfig::default())
        .expect("the BSD list is walkable");
    let tasks = list_tasks(
        &profile,
        &task_symbols,
        &proc_symbols,
        &ProcessWalkConfig::default(),
    )
    .expect("the task queue is walkable");

    assert_eq!(
        allproc.processes.len(),
        1,
        "the BSD list admits to one process"
    );
    assert_eq!(tasks.processes.len(), 2, "the task queue runs two");

    let view = cross_view(&allproc, &tasks);
    assert!(
        view.both_listings_complete,
        "both walks finished, so a difference between them is a finding rather than a gap"
    );
    let hidden = view
        .rows
        .iter()
        .find(|r| r.pid == 666)
        .expect("the unlinked process must appear in the comparison");
    assert!(
        !hidden.on_allproc,
        "it is absent from the list the system admits to"
    );
    assert_eq!(hidden.name.as_deref(), Some("hidden"));
}

// ── Discovery: the path a real capture actually enters through ──────────────

/// Discovery succeeds on an image carrying the banner its symbol pack names.
///
/// Every fixture above hands the stages a `MacProfile` built by hand, which
/// skips the step a real capture cannot skip: finding the Darwin banner in raw
/// bytes, deriving the kernel slide from where it sits, reading `BootPML4` for
/// the page-table base, building the address space, and reading the banner back
/// through it to prove the whole chain holds together.
///
/// The crate had tests for every way that chain *fails* — no banner, no symbol
/// pack, a short read of the page-table base — and none for it succeeding. A
/// discovery that could only fail would take every real capture with it.
///
/// The image is laid out the way `kernel_virtual_to_physical` says a macOS
/// kernel sits: physical address equals virtual minus `0xffffff8000000000`, so
/// at slide zero the banner belongs at physical `0x95fda0`.
#[test]
fn discovery_finds_the_banner_derives_the_slide_and_builds_a_working_address_space() {
    use seance_plugin_memory_macos::{discover_reported, DiscoveryOptions};

    let Some(kdk) = kdk_path() else {
        return;
    };
    const LARGE_PAGE: u64 = 1 << 7;
    // `BootPML4`'s own physical address IS the page-table root -- the symbol
    // marks where the boot tables sit, it does not point at them -- so the top
    // level must be laid down exactly there.
    const T_PML4: u64 = 0x10_0000;
    const T_PDPT: u64 = 0x2000;
    const T_PD: u64 = 0x3000;
    // Where the kit declares each symbol, folded to physical at slide zero.
    const VERSION_PHYS: u64 = 0x95_fda0;
    const VERSION_MAJOR_PHYS: u64 = 0x95_fe00;
    const VERSION_MINOR_PHYS: u64 = 0x95_fe04;
    // The runtime page-table base lives here; discovery reads it through the
    // boot tables, which is why that region has to be mapped as well.
    const IDLEPML4_PHYS: u64 = 0xa8_b6d0;
    const IMAGE: usize = 0xC0_0000;

    let banner = b"Darwin Kernel Version 16.4.0: Thu Dec 22 22:53:21 PST 2016; \
root:xnu-3789.41.3~3/RELEASE_X86_64\0";

    let mut bytes = vec![0u8; IMAGE];
    // The tables, and the 2 MiB mapping that makes the kernel region readable
    // through them. The fold is identity here, so the frame is its own address.
    put64(&mut bytes, T_PML4, 511, T_PDPT | PRESENT);
    put64(&mut bytes, T_PDPT, 0, T_PD | PRESENT);
    put64(&mut bytes, T_PD, 4, 0x80_0000 | PRESENT | LARGE_PAGE);
    put64(&mut bytes, T_PD, 5, 0xa0_0000 | PRESENT | LARGE_PAGE);

    // `IdlePML4` holds the runtime base, which is the same table here.
    bytes[IDLEPML4_PHYS as usize..IDLEPML4_PHYS as usize + 8]
        .copy_from_slice(&T_PML4.to_le_bytes());

    // The banner, where the kit's `version` symbol says it lives.
    bytes[VERSION_PHYS as usize..VERSION_PHYS as usize + banner.len()].copy_from_slice(banner);
    bytes[VERSION_MAJOR_PHYS as usize..VERSION_MAJOR_PHYS as usize + 4]
        .copy_from_slice(&16u32.to_le_bytes());
    bytes[VERSION_MINOR_PHYS as usize..VERSION_MINOR_PHYS as usize + 4]
        .copy_from_slice(&4u32.to_le_bytes());

    let physical: Arc<dyn MemoryLayer> = Arc::new(
        PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(bytes))).expect("a non-empty image"),
    );
    let dirs = vec![kdk.parent().expect("the symbols directory").to_path_buf()];

    let (profile, report) = discover_reported(physical, &dirs, &DiscoveryOptions::default())
        .expect("an image carrying a banner its pack names must be discoverable");

    assert_eq!(profile.slide.value, 0, "the banner sits at slide zero");
    assert_eq!(
        profile.dtb.value, T_PML4,
        "the page-table base is the one BootPML4 held"
    );
    assert_eq!(profile.version.major, 16);
    assert_eq!(profile.version.minor, 4);
    assert!(
        profile.banner.starts_with("Darwin Kernel Version 16.4.0"),
        "{}",
        profile.banner
    );
    // Not `Verified`: several admission gates read the image itself, and a
    // fixture holding three mapped regions cannot satisfy those. What matters
    // is that the pack was not *refused* -- a rejected table would have stopped
    // discovery, not produced a profile.
    assert_ne!(
        profile.symbols.state(),
        seance_symbols::AdmissionState::Rejected,
        "a refused pack cannot produce a profile"
    );
    // The chain is only proved by reading back through the space it produced.
    assert_eq!(
        profile.symbol("allproc").expect("a symbol resolves"),
        0xffff_ff80_00ab_c490,
        "at slide zero a symbol keeps the address the kit declares"
    );
    let _ = report;
}

/// The module's own entry point, on an image discovery can profile.
///
/// This is what the orchestrator calls, and it is the seam this project has
/// been caught by repeatedly: stages that work, reached by nothing. Everything
/// above tests a stage or the discovery beneath it; none of it proves that
/// `analyse` — handed a decoded layer and the image record, as the pipeline
/// hands it — produces records at all.
///
/// The image is the one from the discovery test, so the profile it builds is
/// the profile that test asserts.
#[test]
fn the_module_entry_point_produces_stamped_records_from_a_profiled_image() {
    use seance_core::artifact::{Artifact, ArtifactType};
    use seance_memory::analysis::MemoryAnalysis;
    use seance_plugin_memory_macos::MacMemoryAnalysis;

    let Some(kdk) = kdk_path() else {
        return;
    };
    const LARGE_PAGE: u64 = 1 << 7;
    const T_PML4: u64 = 0x10_0000;
    const T_PDPT: u64 = 0x2000;
    const T_PD: u64 = 0x3000;
    const VERSION_PHYS: u64 = 0x95_fda0;
    const IDLEPML4_PHYS: u64 = 0xa8_b6d0;
    const IMAGE: usize = 0xC0_0000;

    let banner = b"Darwin Kernel Version 16.4.0: Thu Dec 22 22:53:21 PST 2016; \
root:xnu-3789.41.3~3/RELEASE_X86_64\0";

    let mut bytes = vec![0u8; IMAGE];
    put64(&mut bytes, T_PML4, 511, T_PDPT | PRESENT);
    put64(&mut bytes, T_PDPT, 0, T_PD | PRESENT);
    put64(&mut bytes, T_PD, 4, 0x80_0000 | PRESENT | LARGE_PAGE);
    put64(&mut bytes, T_PD, 5, 0xa0_0000 | PRESENT | LARGE_PAGE);
    bytes[IDLEPML4_PHYS as usize..IDLEPML4_PHYS as usize + 8]
        .copy_from_slice(&T_PML4.to_le_bytes());
    bytes[VERSION_PHYS as usize..VERSION_PHYS as usize + banner.len()].copy_from_slice(banner);
    bytes[0x95_fe00..0x95_fe04].copy_from_slice(&16u32.to_le_bytes());
    bytes[0x95_fe04..0x95_fe08].copy_from_slice(&4u32.to_le_bytes());

    let physical: Arc<dyn MemoryLayer> = Arc::new(
        PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(bytes))).expect("a non-empty image"),
    );

    let image_record = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        None,
        serde_json::json!({"type": "MemoryImage", "name": "fixture.vmem"}),
    );

    let analysis = MacMemoryAnalysis::new().with_symbol_dirs(vec![kdk
        .parent()
        .expect("the symbols directory")
        .to_path_buf()]);
    let records = analysis
        .analyse(physical, &image_record)
        .expect("a profiled image must yield records");

    assert!(
        !records.is_empty(),
        "an image this tier profiled must produce records, not an empty vector — \
         stages that work and are reached by nothing is the failure this asserts against"
    );

    // Every record, without exception, must carry the marker. A single
    // unstamped one is a finding an examiner would read as validated.
    for record in &records {
        assert_eq!(
            record.metadata["validated_against_real_capture"],
            serde_json::json!(false),
            "unstamped record: {:?}",
            record.metadata.get("type")
        );
        assert!(
            record.metadata["validation_notice"].is_string(),
            "and carries the sentence that says what that means: {:?}",
            record.metadata.get("type")
        );
    }

    // And the profile itself must be among them, or nothing says what the rest
    // rests on.
    assert!(
        records
            .iter()
            .any(|r| r.metadata["type"] == "MemoryProfile"),
        "the profile record is what every other record's grading rests on"
    );
}
