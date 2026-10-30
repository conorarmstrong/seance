//! Windows memory analysis: the plugin tier over `seance_memory`.
//!
//! `seance_memory` can translate a virtual address and read a struct member at
//! a symbol-declared offset. That is a general capability with no opinion about
//! operating systems. This crate holds the Windows-specific knowledge that
//! turns it into evidence: which structure the process list hangs off, which
//! pool tag marks a terminated process, how a VAD tree is shaped, where the
//! registry hives live in kernel memory.
//!
//! Every stage here takes a [`WindowsProfile`] and produces artifacts. None of
//! them rediscover the DTB, the kernel base or the symbol table; discovery
//! happens once, in [`automagic`], and records how each fact was established so
//! that confidence travels with the result instead of being asserted at the end.
#![forbid(unsafe_code)]

pub mod amcache;
pub mod automagic;
/// The big-page pool tracker: every slot, freed slots told apart from empty
/// ones, and the kernel's own counter beside the walk.
pub mod big_pool;
pub mod console_history;
pub mod credential_decrypt;
pub mod credentials;
pub mod device_tree;
pub mod dump;
pub mod environment;
pub mod handles;
/// Each loaded hive's cell routines, placed against the kernel and the
/// loaded-module map.
pub mod hive_cell_routines;
pub mod hollow;
pub mod jobs;
pub mod kernel_hooks;
/// Boot sectors in physical memory, each held to the partition table's rules.
pub mod mbr_scan;
pub mod mftscan;
pub mod module;
pub mod modules;
pub mod netscan;
pub mod objects;
pub mod pattern_scan;
pub mod poolscan;
pub mod process;
/// The processor control regions: one record per processor, cross-checked
/// against what each structure says about itself.
pub mod processor_blocks;
pub mod profile;
pub mod psxview;
pub mod recovered;
pub mod registry;
/// Scheduled tasks from the TaskCache in the in-memory SOFTWARE hive.
pub mod scheduled_tasks;
pub mod scheduled_tasks_triggers;
pub mod services;
/// `strings` over memory: which address spaces reach a physical offset.
pub mod strings_map;
pub mod syscalls;
pub mod tamper;
pub mod tamper_etw;
pub mod tamper_skeleton;
pub mod tamper_threads;
pub mod tamper_timers;
pub mod tamper_unloaded;
/// TrueCrypt/VeraCrypt: the driver's presence, and the key-schedule sweep
/// that runs only when it is loaded.
pub mod truecrypt;
pub mod vad;
/// Version resources of loaded images, read from the bytes in memory.
pub mod version_info;
/// The kernel's system virtual-address regions, with the kernel placed in one.
pub mod virtual_map;

/// The pattern scan: where a match is looked for, what a ceiling says, and
/// the claims an empty match list must not carry.
#[cfg(test)]
mod pattern_scan_tests;

/// One hand-built image fixture, shared by the modules that write kernel
/// structures by address. Test-only; see the module docs for why the size is a
/// caller's constant.
#[cfg(test)]
mod image_fixture;

/// The tamper stage's floor: that it reports every group whether or not the
/// group ran. See the module for why an unreported group is the failure.
#[cfg(test)]
mod tamper_tests;

/// The skeleton-key check: which process it looks in, and what it says when it
/// could not look.
#[cfg(test)]
mod tamper_skeleton_tests;

/// The device tree: where a filter attached, an unnamed device, and a stack
/// that eats itself.
#[cfg(test)]
mod device_tree_tests;

#[cfg(test)]
mod console_history_tests;
/// TrueCrypt: the presence decision, the sweep, and the pair labelled as inference.
#[cfg(test)]
mod truecrypt_tests;

/// The TaskCache blobs: actions record by record, dynamic info by length.
#[cfg(test)]
mod scheduled_tasks_tests;

/// The TaskCache `Triggers` blob: each trigger kind, and the ways it refuses.
#[cfg(test)]
mod scheduled_tasks_triggers_tests;

/// Version resources: the fixed block, the string tables, and the seven
/// outcomes told apart.
#[cfg(test)]
mod version_info_tests;

/// The MBR sweep: alignment, the six checks, and the sweep's own bounds.
#[cfg(test)]
mod mbr_scan_tests;

/// The hive cell routines: named in the kernel, flagged elsewhere, undetermined
/// without a map.
#[cfg(test)]
mod hive_cell_routines_tests;

/// The virtual-address map: every slot, the enumeration, and the kernel placed.
#[cfg(test)]
mod virtual_map_tests;

/// The big-page pool table: three kinds of slot, the counter, and the totals
/// that stay exact past the publication cap.
#[cfg(test)]
mod big_pool_tests;

/// The processor control regions: the array against the count, and the three
/// self-checks each block is held to.
#[cfg(test)]
mod processor_blocks_tests;

/// Job objects: one record per job, the counter beside the list, and the two
/// things an empty answer must not mean.
#[cfg(test)]
mod jobs_tests;

/// The ETW classifier and the modal comparison, on bytes rather than fixtures.
#[cfg(test)]
mod tamper_etw_tests;

/// The three thread groups: a listing, a reading, and one graded claim whose
/// grading is gated on every exclusion having been assessable.
#[cfg(test)]
mod tamper_threads_tests;

/// The timer walk: the bucket count that comes from nested array dimensions,
/// `CONTAINING_RECORD`, and the two omissions that are deliberate.
#[cfg(test)]
mod tamper_timers_tests;

/// `MmUnloadedDrivers`: the circular arithmetic, the layout measured across
/// 1,724 ISFs, and the cross-reference that is a lead and not a verdict.
#[cfg(test)]
mod tamper_unloaded_tests;

pub use module::{
    windows_memory_module, windows_memory_module_configured, windows_memory_module_with_patterns,
    WindowsMemoryAnalysis, MODULE_ID, MODULE_VERSION,
};
pub use profile::{Evidence, Found, KernelBuild, WindowsProfile};
