//! The object model: turning "a struct name plus an address" into typed field
//! reads, through the symbol table rather than through hardcoded offsets.
//!
//! Everything above this module — every process list, every module list, every
//! injected-code finding — is ultimately a member read at an ISF-declared
//! offset. This is where a symbol table's claims about layout meet the bytes an
//! acquisition actually captured, and it is the last place where a mistake is
//! still visible as a mistake: one level up, a wrong offset has already become
//! a plausible PID next to a plausible process name.
//!
//! ## The four rules this module exists to enforce
//!
//! **1. Offsets come from the symbol table, never from a constant.** A member
//! this build does not have is [`ObjError::Symbols`] naming the member, never
//! offset zero. `_EPROCESS.UniqueProcessId` moved between Windows builds; a
//! reader that hardcoded it would produce a full, confident, wrong process
//! list, and nothing downstream could tell.
//!
//! **2. Width, byte order and signedness come from the symbol table too.** A
//! four-byte signed `pid` holding `0xFFFFFFFF` is `-1`, not `4294967295`, and a
//! pointer is as wide as the ISF's `pointer` base type says — never as wide as
//! the machine running Séance. See [`Obj::int`] and [`Obj::pointer`].
//!
//! **3. A member whose bytes were not acquired is an error carrying the hole.**
//! Never zeros, never a default, never a silently skipped row. A struct
//! straddling an unmapped page yields real values for the mapped members and
//! [`ObjError::Hole`] for the rest, and every [`ObjError`] maps onto an
//! [`seance_core::io::IncompleteReason`] so "we could not read it" survives into
//! the artifact.
//!
//! **4. A list walk that stopped early says so.** A truncated process list is a
//! wrong answer in court, not a short one. [`ListWalk`] is cycle-safe, capped,
//! and always ends with a [`ListStop`] stating whether it came back to the head
//! or gave up, and why.
//!
//! ## The space / native split
//!
//! A [`StructReader`] holds **two** layers:
//!
//! - `layer()` — where these *bytes* live.
//! - `native_layer()` — where the *pointers inside those bytes* resolve.
//!
//! They are usually the same. They are not the same during pool scanning, which
//! finds a kernel structure by scanning the **physical** layer while every
//! pointer inside that structure is a kernel **virtual** address. Getting it
//! backwards does not fail: every dereference quietly returns bytes from the
//! wrong address that parse perfectly. So both are required at construction
//! ([`StructReader::with_native`]), [`Obj::follow`] always lands in the native
//! space, and [`StructReader::walk_list`] runs entirely in it, because every
//! address in a linked list is a native-space address.
//!
//! ## Worked shape
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use seance_memory::layer::MemoryLayer;
//! # use seance_memory::object::{ListSpec, StructReader};
//! # use seance_symbols::SymbolTable;
//! # fn demo(kernel: Arc<dyn MemoryLayer>, symbols: Arc<SymbolTable>, head: u64)
//! #     -> Result<(), seance_memory::object::ObjError> {
//! let reader = StructReader::new(kernel, symbols);
//!
//! let spec = ListSpec::new("_LIST_ENTRY", "Flink")
//!     .in_container("_EPROCESS", "ActiveProcessLinks");
//! let mut walk = reader.walk_list(head, &spec)?;
//!
//! for entry in &mut walk {
//!     let process = entry?;
//!     let pid = process.int("UniqueProcessId")?;
//!     let name = process.bytes("ImageFileName")?;
//!     let _ = (pid, name);
//! }
//!
//! // Never the entry count alone: the reason the walk ended is part of the
//! // finding, and a list that stopped early is not a short list, it is a wrong
//! // one until the report says otherwise.
//! if !walk.is_complete() {
//!     // Stamp `walk.stop()`'s `incomplete()` onto the artifact.
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## What is deliberately not here
//!
//! - **Back-link verification.** Checking that `entry.Flink.Blink == entry` is a
//!   real unlinking detector, but what a mismatch *means* is OS-specific, so it
//!   belongs with the plugin that can say "this process was unlinked" rather
//!   than with the walker that can only say "the links disagree".
//! - **Struct snapshotting.** Serving a whole `_EPROCESS` from one buffered read
//!   is a performance change, not a correctness one, and it introduces a second
//!   copy of the hole accounting. It belongs with the first plugin that measures
//!   a problem.
//! - **Enumeration labels.** [`Obj::int`] reads an enum member at the right
//!   width through its base type; naming the value is
//!   [`seance_symbols::SymbolTable::enum_constant_name`], which returns `None`
//!   for a value the enumeration does not define rather than inventing a label.

pub mod error;
pub mod list;
pub mod reader;
pub mod sanity;

#[cfg(test)]
pub(crate) mod test_support;

pub use error::ObjError;
pub use list::{ListSpec, ListStop, ListWalk, DEFAULT_MAX_LIST_ENTRIES};
pub use reader::{
    ArrayShape, IntValue, Obj, StructReader, MAX_MEMBER_BYTES, MAX_PATH_SEGMENTS, MAX_TYPE_DEPTH,
};
pub use sanity::{is_canonical, Plausibility, PlausibilityFailure, MAX_CHECKED_POINTERS};
