#![forbid(unsafe_code)]
//! A read-only parser for Windows registry hive (`regf`) files.
//!
//! # Why this exists
//!
//! Séance is MIT licensed. This crate replaced a GPL-2.0-or-later dependency
//! so that the whole product could be, and it is written from the published
//! format description rather than from that crate's source: Maxim Suhanov's
//! [*Windows registry file format
//! specification*](https://github.com/msuhanov/regf), which is CC BY 4.0.
//!
//! Graded against the reader it replaced in `docs/COMPARISON.md`: identical key
//! trees on six real hives, two values-of-substance it reads that the other
//! does not, zero panics against its two under a 3,000-case mutation fuzz, and
//! about a third slower on a full walk.
//!
//! # What it reads
//!
//! The base block, hive bins and cells; key nodes (`nk`) with their names,
//! timestamps and class names; all four subkey index forms (`lf`, `lh`, `li`,
//! `ri`); values (`vk`) in all three data shapes, including big data (`db`)
//! reassembled across segments; and both name encodings.
//!
//! Layered keys, as of 2026-09-27: the differencing hives (minor version 6)
//! a Windows container stacks over its base hives. [`KeyNode::layered_key_bits`]
//! reads a node's layer semantics and inherit-class bit, and [`LayeredHive`]
//! merges a base and its deltas into the view the container saw — tombstones
//! hiding, supersedes cutting, the class inherited — while returning what
//! the merge hid rather than dropping it. See the [`layered`] module.
//!
//! # What it does not
//!
//! Writing, and transaction-log replay (`seance_plugin_registry` does that
//! against the primary file this crate opens). Recovery of deleted cells is
//! read as of 2026-09-18 — [`Hive::unallocated_cells`] walks a hive's
//! unallocated space for `nk`/`vk`-shaped cells a deletion marked free but did
//! not overwrite — but only as an explicit, separately typed walk: it is never
//! folded into [`Hive::root_key_node`]'s own tree, so a caller cannot mistake
//! recovered evidence for live evidence by forgetting to check which one it
//! asked for. See the [`unallocated`] module.
//!
//! Security descriptors (`sk`) are read as of 2026-09-15 — the cell, its ring
//! links, its reference count and the self-relative descriptor bytes — but
//! **decoded** elsewhere: owner SIDs, ACLs and ACEs are
//! `seance_core::secdesc`'s subject, because the same NT descriptor appears in
//! NTFS `$Secure:$SDS` and one decoder for both cannot disagree with itself on
//! a court-facing surface.
//!
//! # The rules it was written to
//!
//! * **Every read is bounded by the cell it is in**, and every bound failure
//!   is an error that names the structure and the byte. Hive data arrives here
//!   from disk images, carved fragments and hostile input; a panic in a parser
//!   is an outage in an ingest pipeline.
//! * **An absent structure and an unreadable one are different answers.**
//!   `subkeys()` returns `None` for a key with no subkeys and
//!   `Some(Err(...))` for one whose index would not read — because "there was
//!   nothing there" and "this could not be read" are not the same sentence,
//!   and an examiner is entitled to both.
//! * **A partial hive is still evidence.** A hive whose sequence numbers
//!   differ, or which is cut short of its declared size, opens under
//!   [`Tolerances`] so that the keys it does hold are not lost to the ones it
//!   does not. The caller is expected to carry that qualification onto
//!   whatever it reports.
//!
//! # Example
//!
//! ```no_run
//! use seance_hive::Hive;
//!
//! let bytes = std::fs::read("SOFTWARE")?;
//! let hive = Hive::new(&bytes)?;
//! let root = hive.root_key_node()?;
//! if let Some(Ok(subkeys)) = root.subkeys() {
//!     for key in subkeys.flatten() {
//!         println!("{}", key.name()?);
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod error;
pub mod hive;
pub mod key_node;
pub mod key_value;
pub mod layered;
pub mod name;
pub mod security;
pub mod unallocated;

#[cfg(test)]
mod tests;

pub use error::{HiveError, Result};
pub use hive::{Hive, Tolerances};
pub use key_node::{KeyNode, SubKeyNodes, UnresolvedSublist};
pub use key_value::{KeyValue, KeyValueData, KeyValueDataType, KeyValues};
pub use layered::{
    LayerFault, LayerSemantics, LayeredClass, LayeredHive, LayeredKey, LayeredKeyBits,
    LayeredSubkeys, LayeredValue, LayeredValues, TombstonedKey, MAX_LAYERS,
};
pub use name::HiveNameString;
pub use security::{SecurityCell, SecurityRing};
pub use unallocated::{RecoveredCell, UnallocatedCell, UnallocatedCells, MAX_UNALLOCATED_CELLS};
