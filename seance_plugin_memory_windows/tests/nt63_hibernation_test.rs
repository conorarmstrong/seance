//! Full reconstruction of the older NT6.2/6.3 (Windows 8/8.1/Server 2012[R2])
//! hibernation layout.
//!
//! These images carry the same PO_MEMORY_IMAGE version (9) as Windows 10/11, but
//! Win10 inserted a field ahead of the restore-set pointers, so on an NT6.x image
//! the boot/kernel pointers sit at 0x60/0x68 rather than 0x68/0x70. `open` now
//! picks the layout by which one's kernel pointer lands on a real table, so a
//! 2012 R2 hiberfil reconstructs into a coherent address space discovery can walk.
//!
//! `SEANCE_WIN_NT63_HIBERFIL` names such a hiberfil (several GiB, not in the
//! repo). Absent, this skips.

use seance_core::data_source::{DataSource, FileDataSource};
use seance_memory::MemoryLayer;
use seance_plugin_memory_windows::automagic::{self, DiscoveryError, DiscoveryOptions};
use std::sync::Arc;

fn hiberfil() -> Option<Arc<dyn DataSource>> {
    let p = std::env::var("SEANCE_WIN_NT63_HIBERFIL").ok()?;
    Some(Arc::new(
        FileDataSource::new(std::path::PathBuf::from(p)).ok()?,
    ))
}

/// The NT6.3 image reconstructs and discovery walks the reconstructed page
/// tables to a coherent kernel — proven by reading ntoskrnl's own debug GUID out
/// of it. (Full discovery would also need a matching 2012 R2 symbol pack, which
/// is a separate concern; reaching the kernel is what validates the layout.)
#[test]
fn an_nt63_hiberfil_reconstructs_to_a_coherent_kernel() {
    let Some(src) = hiberfil() else {
        eprintln!("skipping: set SEANCE_WIN_NT63_HIBERFIL to a Win8.1/2012 R2 hiberfil");
        return;
    };
    let layer = seance_memory::formats::hibernation::open(Arc::clone(&src))
        .expect("the NT6.3 hiberfil must reconstruct");
    let restored = layer
        .layer_meta()
        .note("hibernation_pages_restored")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(restored > 1000, "almost no page was restored ({restored})");

    let physical: Arc<dyn MemoryLayer> = Arc::new(layer);
    let dirs: Vec<std::path::PathBuf> = std::env::var("SEANCE_SYMBOL_DIRS")
        .ok()
        .map(|l| l.split(':').map(std::path::PathBuf::from).collect())
        .unwrap_or_default();
    match automagic::discover(physical, &dirs, &DiscoveryOptions::default()) {
        // With a matching symbol pack, discovery fully succeeds.
        Ok(profile) => {
            assert!(profile.dtb.value != 0);
            assert!(profile.kernel_base.value > 0xffff_0000_0000_0000);
            eprintln!(
                "NT6.3 discovery OK: dtb={:#x} kbase={:#x}",
                profile.dtb.value, profile.kernel_base.value
            );
        }
        // Without one, discovery still proves the page tables and reads the
        // kernel's debug GUID from the reconstruction — a garbage image cannot.
        Err(DiscoveryError::SymbolsNotFound { guid, pdb, .. }) => {
            assert!(
                !guid.is_empty(),
                "no kernel GUID was read — the reconstruction is not coherent"
            );
            eprintln!("NT6.3 reconstruction coherent: reached kernel, pdb={pdb} guid={guid} (2012 R2 symbols not present)");
        }
        Err(other) => panic!("NT6.3 reconstruction did not reach a coherent kernel: {other:?}"),
    }
}
