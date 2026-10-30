//! Shared scaffolding for the parity tests.
//!
//! Every parity test needs the same three things: a reference image, the ISF
//! directories, and a discovered profile. They live here so each test file
//! states only what it is comparing against Volatility.
//!
//! Point `SEANCE_MEM_IMAGES` at a directory holding `win-xp-laptop.img` and
//! `win11/Win11Dump.mem`, and `SEANCE_SYMBOL_DIRS` at the ISF directories.
//! Tests skip when the corpus is absent rather than failing a clean checkout.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use seance_core::data_source::{DataSource, FileDataSource};
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_windows::automagic::{self, DiscoveryOptions};
use seance_plugin_memory_windows::WindowsProfile;

/// The Windows XP SP2 reference image: x86, non-PAE, two-level page walk.
pub const XP: &str = "win-xp-laptop.img";

/// The Windows 11 22000 reference image: x86-64, four-level walk, large pages.
pub const WIN11: &str = "win11/Win11Dump.mem";

/// A reference image as a physical layer, or `None` when the corpus was never
/// provisioned.
///
/// Named-but-missing panics rather than skipping (see
/// [`seance_core::test_support::corpus`]): this suite printed `ok` while
/// comparing zero rows for its entire existence, which is how `psscan`
/// returning 0 processes against the oracle's 103 went unnoticed.
pub fn image(name: &str) -> Option<Arc<dyn MemoryLayer>> {
    let path = seance_core::test_support::corpus::file("SEANCE_MEM_IMAGES", name)?;
    let file = FileDataSource::new(path.clone())
        .unwrap_or_else(|e| panic!("{} could not be opened: {e}", path.display()));
    let source: Arc<dyn DataSource> = Arc::new(file);
    let layer = PhysicalLayer::raw(source).expect("a raw image is a physical layer");
    Some(Arc::new(layer) as Arc<dyn MemoryLayer>)
}

/// Directories searched for ISF symbol files.
pub fn symbol_dirs() -> Vec<PathBuf> {
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

/// A discovered profile for a reference image, or `None` when it is absent.
///
/// Discovery failing is a panic rather than a skip: the image is present, so a
/// failure here is a defect and silence would hide it.
pub fn profile(name: &str) -> Option<WindowsProfile> {
    let physical = image(name)?;
    match automagic::discover(physical, &symbol_dirs(), &DiscoveryOptions::default()) {
        Ok(profile) => Some(profile),
        Err(err) => panic!("{name}: discovery failed, which is itself the finding: {err}"),
    }
}

/// Rows of a Volatility CSV in the oracle directory, or `None` when the corpus
/// was never provisioned.
///
/// Blank trailing lines are dropped: counting them is what made the first pass
/// at these numbers one too high everywhere.
///
/// Once the corpus IS provisioned, a missing or unreadable oracle file is a
/// defect and not a skip. It used to be `read_to_string(&path).ok()?`, so a
/// comparison against an oracle nobody had generated reported `ok` having
/// compared nothing — the same silence that let netscan and netstat pass over
/// zero rows.
pub fn oracle(dir: &str, plugin: &str) -> Option<Vec<Vec<String>>> {
    let base = seance_core::test_support::corpus::dir("SEANCE_MEM_IMAGES")?;
    let path = base.join(dir).join(format!("{plugin}.csv"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "the corpus is present but the {plugin} oracle at {} could not be read: {e}. \
             Treating this as a skip would report agreement with an oracle that was never \
             consulted.",
            path.display()
        )
    });
    let mut lines = text.lines();
    let _header = lines
        .next()
        .unwrap_or_else(|| panic!("{} is empty: it has not even a header row", path.display()));
    Some(
        lines
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.split(',').map(str::to_string).collect())
            .collect(),
    )
}

/// Strip the sign extension Volatility drops when it prints a kernel pointer.
///
/// Volatility renders `0xfffff80029800000` as `0xf80029800000`. Comparing a
/// Séance address with an oracle address means putting them in the same space,
/// and truncating ours is lossless where re-extending theirs is guesswork.
pub fn truncate_to_48(address: u64) -> u64 {
    address & 0x0000_FFFF_FFFF_FFFF
}
