//! Image-derived discovery against a modern-kernel capture.
//!
//! Kernel 6.4 reordered the kallsyms arrays — `kallsyms_offsets` and
//! `kallsyms_relative_base` moved from before `kallsyms_num_syms` to after the
//! token index — so a decoder written for the pre-6.4 order recovered symbol
//! *names* correctly but read *addresses* from the wrong bytes and rejected the
//! table. This validates the fix against a real Ubuntu 24.04 (6.8) capture.
//!
//! `SEANCE_LINUX_NOBLE_MEM` must name a directory holding `mem.raw` (a raw
//! physical image of a 6.8 guest). Absent, this skips. The expected symbol
//! addresses are the guest's own `/proc/kallsyms` at capture time.

use seance_core::data_source::{DataSource, FileDataSource};
use seance_memory::kallsyms::Kallsyms;
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_linux::discovery::{self, DiscoveryOptions};
use std::path::PathBuf;
use std::sync::Arc;

fn dir() -> Option<PathBuf> {
    let d = PathBuf::from(std::env::var("SEANCE_LINUX_NOBLE_MEM").ok()?);
    d.is_dir().then_some(d)
}

#[test]
fn a_6_8_kernel_is_discovered_from_its_own_symbols() {
    let Some(d) = dir() else {
        eprintln!("skipping: set SEANCE_LINUX_NOBLE_MEM to the 6.8 capture dir");
        return;
    };
    let src: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(d.join("mem.raw")).expect("open mem.raw"));
    let physical: Arc<dyn MemoryLayer> = Arc::new(PhysicalLayer::raw(src).expect("raw"));
    let profile = discovery::discover(physical, &[], &DiscoveryOptions::default())
        .expect("a 6.8 capture must be discovered now that the modern kallsyms layout is read");
    assert!(profile.dtb.value != 0, "a DTB must be recovered");
}

#[test]
fn modern_kallsyms_addresses_match_the_guests_proc_kallsyms() {
    let Some(d) = dir() else {
        eprintln!("skipping: set SEANCE_LINUX_NOBLE_MEM to the 6.8 capture dir");
        return;
    };
    let src = FileDataSource::new(d.join("mem.raw")).expect("open mem.raw");
    let sz = src.size();
    let (mut off, chunk) = (0u64, 64 * 1024 * 1024u64);
    let mut buf = vec![0u8; chunk as usize];
    let mut ks: Option<Kallsyms> = None;
    while off < sz {
        let want = chunk.min(sz - off) as usize;
        if src.read_at(off, &mut buf[..want]).is_ok() {
            if let Some((_, k)) = Kallsyms::find_in(&buf[..want]) {
                if k.len() > 100_000 {
                    ks = Some(k);
                    break;
                }
            }
        }
        off += chunk - 16 * 1024 * 1024;
    }
    let ks = ks.expect("a kernel symbol table must be recovered from the 6.8 image");
    // Ground truth: the guest's /proc/kallsyms at capture (Ubuntu 24.04,
    // 6.8.0-136-generic). A wrong offset-array home yields name bytes here, not
    // these addresses.
    assert_eq!(ks.address_of("init_task"), Some(0xffffffffb800fb40));
    assert_eq!(ks.address_of("commit_creds"), Some(0xffffffffb5b48750));
}

/// **The 6.1+ maple-tree VMA walk, end to end.** On a 6.8 kernel the VMAs live
/// in `mm_struct.mm_mt`; before the maple walk every process reported an empty
/// map. A process with real regions here proves the tree was walked.
#[test]
fn a_6_8_process_has_vma_regions_from_the_maple_tree() {
    use seance_plugin_memory_linux::{proc_maps, tasks};
    let Some(d) = dir() else {
        eprintln!("skipping: set SEANCE_LINUX_NOBLE_MEM to the 6.8 capture dir");
        return;
    };
    let src: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(d.join("mem.raw")).expect("open mem.raw"));
    let physical: Arc<dyn MemoryLayer> = Arc::new(PhysicalLayer::raw(src).expect("raw"));
    let profile =
        discovery::discover(physical, &[], &DiscoveryOptions::default()).expect("discover");

    let task_layout = tasks::bind(&profile).expect("bind tasks");
    let list = tasks::list_tasks(&profile, &task_layout, &tasks::TaskListConfig::default())
        .expect("list tasks");
    let maps_layout = proc_maps::bind(&profile).expect("bind maps");
    let survey = proc_maps::survey_process_maps(
        &profile,
        &maps_layout,
        &list,
        &proc_maps::ProcessMapsConfig::default(),
    )
    .expect("survey maps");

    // At least one userland process must have regions walked out of the tree —
    // and no process may be left with the "tree not walked" refusal.
    let with_regions = survey
        .processes
        .iter()
        .filter(|p| !p.regions.is_empty())
        .count();
    let unwalked = survey
        .processes
        .iter()
        .filter(|p| matches!(p.outcome, proc_maps::MapsOutcome::MapleTreeUnwalked))
        .count();
    eprintln!(
        "maple: {}/{} processes have regions; {unwalked} left tree-unwalked",
        with_regions,
        survey.processes.len()
    );
    assert!(
        with_regions > 0,
        "the maple tree yielded no VMAs on a 6.8 capture"
    );
    assert_eq!(
        unwalked, 0,
        "no 6.8 process should be left 'maple tree not walked'"
    );
}
