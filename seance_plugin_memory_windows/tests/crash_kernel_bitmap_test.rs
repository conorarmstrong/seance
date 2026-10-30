//! Discovery over a real Windows kernel-bitmap crash dump (DumpType 0x6).
//!
//! The kernel-bitmap dump holds only the pages the kernel owns, so user memory
//! is absent — but the DTB, the kernel image and the loaded-module list are all
//! present, which is what discovery needs. `SEANCE_WIN_CRASHDUMP` names such a
//! dump; `SEANCE_SYMBOL_DIRS` its matching symbols. Absent, this skips.

use seance_core::data_source::{DataSource, FileDataSource};
use seance_memory::MemoryLayer;
use seance_plugin_memory_windows::automagic::{self, DiscoveryOptions};
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn a_kernel_bitmap_crash_dump_is_discovered() {
    let Some(p) = std::env::var("SEANCE_WIN_CRASHDUMP").ok() else {
        eprintln!("skipping: set SEANCE_WIN_CRASHDUMP to a kernel-bitmap crash dump");
        return;
    };
    let src: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(PathBuf::from(p)).expect("open crash dump"));
    let layer = seance_memory::formats::crash::open(Arc::clone(&src)).expect("crash dump opens");
    // A kernel bitmap records that user space was deliberately not written.
    assert!(
        layer
            .layer_meta()
            .incomplete()
            .iter()
            .any(|i| i.detail.contains("kernel bitmap") || i.detail.contains("user-mode")),
        "a kernel-bitmap dump must flag user memory as absent"
    );
    let physical: Arc<dyn MemoryLayer> = Arc::new(layer);
    let dirs: Vec<PathBuf> = std::env::var("SEANCE_SYMBOL_DIRS")
        .ok()
        .map(|l| l.split(':').map(PathBuf::from).collect())
        .unwrap_or_default();
    let profile = automagic::discover(physical, &dirs, &DiscoveryOptions::default())
        .expect("discovery must succeed on a kernel-bitmap dump");
    assert!(profile.dtb.value != 0);
    assert!(profile.kernel_base.value > 0xffff_0000_0000_0000);
    eprintln!(
        "kernel-bitmap discovery: dtb={:#x} kbase={:#x} build={:?}",
        profile.dtb.value, profile.kernel_base.value, profile.build.build
    );
}
