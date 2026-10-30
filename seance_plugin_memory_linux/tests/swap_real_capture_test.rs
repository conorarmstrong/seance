//! Linux swap resolution against a real capture built for this purpose.
//!
//! `SEANCE_LINUX_SWAP_MEM` must name a directory holding `mem.raw` (a raw
//! physical memory image of a Linux guest) and `swap-area.raw` (that guest's
//! swap area). The guest ran a workload that filled a 16 MiB anonymous mapping
//! with a known per-page marker (`b"SWAPMARK" + le64(page_index)`) and then
//! `madvise(MADV_PAGEOUT)`-ed it, so those pages are in the swap area at known
//! slots and the process page table holds `swp_entry_t` PTEs for them.
//!
//! Absent, these skip; named and missing, they fail.

use seance_core::data_source::{DataSource, FileDataSource};
use seance_memory::translate::VirtualLayer;
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_linux::discovery::{self, DiscoveryOptions};
use seance_plugin_memory_linux::profile::LinuxProfile;
use seance_plugin_memory_linux::swap::{self, AttachedSwapArea, SwapResolution};
use seance_plugin_memory_linux::{envars, proc_maps, space, tasks};
use std::path::PathBuf;
use std::sync::Arc;

fn dir() -> Option<PathBuf> {
    let d = PathBuf::from(std::env::var("SEANCE_LINUX_SWAP_MEM").ok()?);
    d.is_dir().then_some(d)
}

fn profiled() -> Option<&'static LinuxProfile> {
    static ONCE: std::sync::OnceLock<Option<LinuxProfile>> = std::sync::OnceLock::new();
    let _ = dir()?;
    ONCE.get_or_init(|| {
        let src: Arc<dyn DataSource> =
            Arc::new(FileDataSource::new(dir().unwrap().join("mem.raw")).expect("open mem.raw"));
        let physical: Arc<dyn MemoryLayer> =
            Arc::new(PhysicalLayer::raw(src).expect("raw is a physical layer"));
        discovery::discover(physical, &[], &DiscoveryOptions::default()).ok()
    })
    .as_ref()
}

#[test]
fn the_linux_swap_capture_is_discovered_from_its_bytes() {
    let Some(profile) = profiled() else {
        eprintln!("skipping: set SEANCE_LINUX_SWAP_MEM to the capture dir");
        return;
    };
    assert!(profile.dtb.value != 0, "a DTB must be recovered");
    assert_eq!(
        swap::layouts_for(profile).len(),
        2,
        "x86-64 has two candidate swap-entry layouts to try"
    );
}

/// **The whole chain: a swapped page is located from a `swp_entry_t` PTE and its
/// bytes read back out of the attached swap area — validated against ground
/// truth.**
///
/// Page `i` of the workload's mapping was written `b"SWAPMARK" + le64(i)` and
/// forced to swap, so a correct resolution reads a page whose first 16 bytes are
/// exactly that. Nothing in the decode is told the layout: the attached area's
/// bounds are what select it.
#[test]
fn swapped_pages_are_recovered_and_match_their_known_markers() {
    let Some(profile) = profiled() else {
        eprintln!("skipping: set SEANCE_LINUX_SWAP_MEM to the capture dir");
        return;
    };
    let d = dir().unwrap();

    // Attach the swap area as area index 0 (the only one on this guest).
    let swap_src: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(d.join("swap-area.raw")).expect("open swap-area.raw"));
    let area = AttachedSwapArea::open(Arc::clone(&swap_src), 0, "swap-area.raw")
        .expect("valid swap header");
    // The empty-body guard (MEM-011) meeting a real acquisition, and the reason
    // it is not decided at area level alone. This area came off the block device
    // and holds the workload's pages, but the machine had only 16 MiB swapped out
    // of it: the bounded body survey reads all 64 of the pages it samples and
    // finds data in *one* of them. An area-level verdict would therefore sit one
    // unlucky sample away from condemning every page below — which is why a slot
    // that holds bytes is recovered whatever the survey found. The assertion here
    // is the part that must hold on any corpus: the body was readable.
    assert_eq!(
        area.body.pages_read, area.body.pages_sampled,
        "every sampled page of an acquired area must read: {:?}",
        area.body
    );
    eprintln!("real swap area body survey: {:?}", area.body);
    let areas = [area];
    let layouts = swap::layouts_for(profile);

    // Find the workload: the python3 process and its 16 MiB anonymous mapping.
    let task_layout = tasks::bind(profile).expect("bind tasks");
    let list = tasks::list_tasks(profile, &task_layout, &tasks::TaskListConfig::default())
        .expect("list tasks");
    let maps_layout = proc_maps::bind(profile).expect("bind maps");
    let survey = proc_maps::survey_process_maps(
        profile,
        &maps_layout,
        &list,
        &proc_maps::ProcessMapsConfig::default(),
    )
    .expect("survey maps");

    let env_layout = envars::bind(profile).expect("bind envars");
    let task_type = env_layout.member("mm").unwrap().type_name().unwrap();
    let reader = tasks::reader_for(profile);

    let mut recovered = 0u32;
    let mut checked = 0u32;
    for pm in &survey.processes {
        let is_py = pm
            .comm
            .known()
            .map(|c| c.contains("python"))
            .unwrap_or(false);
        if !is_py {
            continue;
        }
        let region = pm.regions.iter().find(|r| {
            r.anonymous
                && matches!(
                    (r.vm_start.known(), r.vm_end.known()),
                    (Some(s), Some(e)) if e - s == 0x100_0000
                )
        });
        let Some(region) = region else { continue };
        let start = *region.vm_start.known().unwrap();

        let task_obj = reader
            .object(pm.task_address, task_type)
            .expect("reopen task");
        let mm = space::memory_descriptor(&env_layout, &task_obj, "mm")
            .expect("descriptor")
            .expect("has mm");
        let ps = space::open(profile, &env_layout, &mm, "pgd")
            .expect("open")
            .expect("space");
        let vl = VirtualLayer::new(Arc::clone(&profile.physical), ps.dtb, profile.paging)
            .expect("virtual layer");
        // The product path: the SAME layer with the swap area attached resolves a
        // swapped page transparently on a plain read, exactly as the stages read
        // process memory. A read of a swapped VA must return its marker bytes.
        let vl_swap = VirtualLayer::new(Arc::clone(&profile.physical), ps.dtb, profile.paging)
            .expect("virtual layer")
            .with_swap(vec![seance_memory::translate::SwapFile {
                index: 0,
                label: "swap-area.raw".to_string(),
                source: Arc::clone(&swap_src),
            }]);

        // Sample across the mapping: every 61st page (a prime stride, so the
        // sample is not aligned to any power-of-two artefact) plus the ends.
        let indices = (0..4096u64)
            .step_by(61)
            .chain([1, 4094, 4095])
            .collect::<Vec<_>>();
        for i in indices {
            let va = start + i * 0x1000;
            let mut want = b"SWAPMARK".to_vec();
            want.extend_from_slice(&i.to_le_bytes());

            match swap::resolve_page(&vl, va, &areas, layouts) {
                SwapResolution::Recovered {
                    layout,
                    swap_type,
                    slot,
                    bytes,
                    ..
                } => {
                    checked += 1;
                    recovered += 1;
                    // The ground truth is the CONTENT: page i was written
                    // `SWAPMARK + le64(i)`, so a correct resolution reads that
                    // whatever slot the allocator chose. The slots are not
                    // sequential — MADV_PAGEOUT allocates in clusters — so
                    // matching arbitrary slots to the right markers is the
                    // stronger check.
                    let _ = slot;
                    assert_eq!(
                        &bytes[..16],
                        &want[..],
                        "page {i} recovered the wrong bytes: slot {slot}, type {swap_type}"
                    );
                    assert_eq!(swap_type, 0);
                    assert_eq!(
                        layout,
                        seance_memory::formats::linux_swap::X86SwapLayout::PostL1tf,
                        "the evidence must select the post-L1TF layout for a 5.15 kernel"
                    );

                    // Product path: a plain read through the swap-attached layer
                    // must transparently return the same marker bytes.
                    let mut got = [0u8; 16];
                    let n = vl_swap.as_data_source().read_at(va, &mut got).unwrap_or(0);
                    assert_eq!(
                        (n, &got[..]),
                        (16, &want[..]),
                        "page {i} did not resolve through the swap-attached layer's read path"
                    );
                }
                other => {
                    panic!("page {i} at {va:#x} was not recovered: {}", other.note());
                }
            }
        }
    }

    assert!(checked > 0, "the workload's mapping was never found");
    assert_eq!(
        recovered, checked,
        "every sampled swapped page must be recovered and match its marker"
    );
    eprintln!("recovered and verified {recovered} swapped pages against ground truth");
}
