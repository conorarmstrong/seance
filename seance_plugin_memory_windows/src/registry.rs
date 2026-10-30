//! In-memory registry hives: `hivelist`, the hive address space, and
//! `printkey`.
//!
//! # Why this is not "hand the hive file to the registry parser"
//!
//! Séance already has a registry parser for hives on disk, and the obvious plan
//! is to find a hive in RAM, take a window over it, and hand that window over.
//! It does not work, and the reason is worth stating once here because
//! everything in this module follows from it:
//!
//! **There is no window.** A hive on disk is one contiguous file. A hive in
//! memory is a set of bins the kernel allocated wherever paged pool had room,
//! plus a *second* set of bins for volatile keys that has no on-disk
//! counterpart at all. What ties them together is the hive's own storage map,
//! a two-level table of `_HMAP_ENTRY` records reached through `_HHIVE.Storage`,
//! and every cell read has to go through it, one 4 KiB page at a time.
//!
//! So the address space is the port, and it is [`space::HiveSpace`]: a
//! [`seance_memory::layer::MemoryLayer`] whose addresses are **cell indices**
//! and whose reads translate through the hive's map. Above it,
//! [`key::CellReader`] decodes the cells, and [`printkey`] resolves a key path
//! through them.
//!
//! # The three things this module refuses to do
//!
//! Each of these is something upstream Volatility does, for good reasons that
//! do not apply to evidence:
//!
//! 1. **Pad an unreadable read with NUL bytes.** A value whose data cell was
//!    paged out comes back as [`key::ValueData::Unavailable`], never as an empty
//!    value, because "the suspect cleared this setting" and "we did not capture
//!    this page" are opposite findings that would otherwise render identically.
//! 2. **Default the root cell to `0x20`.** A hive whose base block is
//!    unreadable gets its root *probed and validated* — the candidate has to
//!    look like a key node — and the weaker evidence is recorded on the result.
//! 3. **Report an unnamed hive as an empty string.** The volatile hives
//!    legitimately have no backing file; [`hivelist::HiveName::NoBackingFile`]
//!    says so, and it does not look like a failed read.
//!
//! # Shape of a full analysis
//!
//! ```no_run
//! # use seance_plugin_memory_windows::profile::WindowsProfile;
//! # use seance_plugin_memory_windows::registry::{hivelist, printkey};
//! # fn demo(profile: &WindowsProfile) -> Result<(), Box<dyn std::error::Error>> {
//! let listing = hivelist::list_hives(profile)?;
//! for hive in &listing.hives {
//!     // The hive's address is the provenance every key below it carries.
//!     let run = printkey::print_key_in_hive(
//!         profile,
//!         hive.address,
//!         Some("Microsoft\\Windows\\CurrentVersion\\Run"),
//!     );
//!     if let Ok(run) = run {
//!         for value in &run.values.values {
//!             let _ = (&value.name, &value.data);
//!         }
//!         // Never the values alone: a listing that could not be completed is
//!         // not a short listing, it is a wrong one until the report says so.
//!         let _ = run.incomplete();
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # What is deliberately not here
//!
//! - **`hivescan`.** Finding a `_CMHIVE` by its `CM10` pool tag belongs with the
//!   pool scanner, which owns pool-header validation for every object type.
//!   This module takes an address from wherever the caller got it.
//! - **Rendering.** `userassist`, `amcache`, `shellbags` and the rest are
//!   decoders over registry values, and they belong with the registry plugin
//!   that already has to decode the same values off disk.
//!
//! # Windows 10 17063 and later
//!
//! From that build the kernel maps hive bins through the *Registry* process
//! rather than into paged pool, so `_HMAP_ENTRY.BlockAddress` is only
//! meaningful in that process's address space. [`space::locate_bin_space`]
//! finds it and [`space::HiveSpace::open_for_image`] opens hives through it,
//! which is what every production path uses. When the process cannot be found
//! the kernel's space is used — holes rather than wrong bytes — and
//! [`space::HiveSpace::bin_source`] records that the holes are unexplained,
//! because a hive read from the wrong address space and a hive whose pages were
//! never captured look identical otherwise.

#[path = "registry_error.rs"]
pub mod error;
#[path = "registry_hivelist.rs"]
pub mod hivelist;
#[path = "registry_key.rs"]
pub mod key;
#[path = "registry_printkey.rs"]
pub mod printkey;
#[path = "registry_space.rs"]
pub mod space;

#[cfg(test)]
#[path = "registry_test_support.rs"]
pub(crate) mod test_support;

pub use error::RegistryError;
pub use hivelist::{
    list_hives, list_hives_from, HiveListing, HiveName, HiveNameSource, HiveRecord, RejectedHive,
    WalkDirection,
};
pub use key::{
    CellKind, CellReader, KeyNode, KeyValue, RegName, RegText, RegValueType, RegistryData, Subkeys,
    ValueData, Values,
};
pub use printkey::{print_key, print_key_in_hive, resolve_key, KeyListing};
pub use space::{locate_bin_space, BinSource, BinSpace, CellIndex, CellLocation, HiveSpace, Store};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::test_support::{xp_profile, XP_CMHIVE};

    /// The whole tier end to end: find the hives, open one, resolve a path
    /// through three index formats and two stores, and read its values.
    #[test]
    fn a_hive_goes_from_a_kernel_symbol_to_decoded_registry_values() {
        let profile = xp_profile();

        let listing = list_hives(&profile).expect("the hive list walks");
        let hive = listing
            .hives
            .iter()
            .find(|hive| hive.name.file_name() == Some("NTUSER.DAT"))
            .expect("the named hive is on the list");
        assert_eq!(hive.address, XP_CMHIVE);

        let run = print_key_in_hive(&profile, hive.address, Some("Sarah"))
            .expect("the key resolves inside the hive");
        assert_eq!(run.path, "ROOT\\Sarah");

        let names: Vec<&str> = run
            .values
            .values
            .iter()
            .map(|value| value.name.text.as_str())
            .collect();
        assert_eq!(names, vec!["Path", "Count", "", "List"]);

        // Three values were readable and one was not, and the difference is
        // visible rather than inferred from an empty string.
        let readable = run
            .values
            .values
            .iter()
            .filter(|value| value.data.is_available())
            .count();
        assert_eq!(readable, 3);
        assert!(run.values.is_complete(), "no value was silently dropped");
    }

    /// Volatile keys are the thing a memory image has that a disk image cannot,
    /// so the whole tier has to carry them end to end.
    #[test]
    fn a_volatile_key_survives_from_the_storage_map_to_the_listing() {
        let profile = xp_profile();
        let listing = print_key_in_hive(&profile, XP_CMHIVE, None).expect("the root resolves");
        let volatile: Vec<&KeyNode> = listing
            .subkeys
            .keys
            .iter()
            .filter(|key| key.is_volatile())
            .collect();
        assert_eq!(volatile.len(), 1);
        assert_eq!(volatile[0].name.text, "Volatile");
        assert_eq!(volatile[0].cell.store(), Store::Volatile);
    }
}
