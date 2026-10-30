//! [`ListWalk`]: walking a kernel doubly-linked list as an iterator that cannot
//! loop, cannot silently truncate, and always says why it ended.
//!
//! Nearly every Windows plugin is a list walk. `pslist` walks
//! `_EPROCESS.ActiveProcessLinks`, `modules` walks `_LDR_DATA_TABLE_ENTRY`,
//! `handles`, `hivelist`, `driverscan`'s cross-view all reduce to the same
//! shape: a `_LIST_ENTRY` embedded somewhere inside a structure, whose `Flink`
//! points at the *next structure's embedded link*, not at the next structure.
//! Recovering the containing structure is `CONTAINING_RECORD`, which here is
//! `link_address - offset_of(container, member)` with the offset taken from the
//! symbol table.
//!
//! # Why this is an iterator with a stop reason and not a `Vec`
//!
//! A process list that stopped after 40 of 400 entries is not a short answer,
//! it is a **wrong** answer, and in a report it is indistinguishable from a
//! machine that had 40 processes. Three things follow, and all three are
//! correctness rather than robustness:
//!
//! 1. **Cycle safety.** Every link address visited is remembered. A list that
//!    was being modified during acquisition, or that a rootkit spliced, points
//!    back into itself; a naive walk then loops forever or reports the same
//!    process a hundred times. The walk stops at the first repeat and says so.
//! 2. **A hard cap.** Even without a repeated address, a corrupt link chain can
//!    wander through memory indefinitely. [`DEFAULT_MAX_LIST_ENTRIES`] bounds
//!    it, and hitting the cap is reported as a cap, never as the end of the
//!    list.
//! 3. **An honest stop at a hole.** A link whose bytes were never acquired ends
//!    the walk with the unmapped range attached, so the artifact can record
//!    "the list continues past here and we could not follow it" instead of
//!    quietly ending.
//!
//! Every abnormal ending yields exactly one `Err` item *and* records a
//! [`ListStop`], so both styles of caller are served: one that
//! `collect::<Result<Vec<_>, _>>()`s and fails loudly, and one that keeps the
//! partial list and stamps [`ListStop::incomplete`] onto the artifact.

use std::collections::HashSet;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_symbols::{SymbolError, TypeId, TypeKind};

use super::error::ObjError;
use super::reader::{raw_bits, Obj, Scalar, StructReader};
use crate::layer::MemoryHole;
use crate::meta::Incomplete;

/// Default ceiling on the number of entries a single walk will return.
///
/// Chosen well above any real kernel list — a busy Windows machine has hundreds
/// of processes and a few thousand modules — so that hitting it means the link
/// chain is wrong, not that the machine was busy. Raise it with
/// [`ListSpec::with_max_entries`] for a list that is genuinely larger, and
/// remember that the visited-address set grows with it.
pub const DEFAULT_MAX_LIST_ENTRIES: usize = 65_536;

/// Which links to follow, and what the links are embedded in.
///
/// Nothing here is a hardcoded offset: the type and member names are resolved
/// through the symbol table when the walk is created, so a build that names its
/// link member differently fails at [`StructReader::walk_list`] naming the
/// member, rather than at entry 3,000 with a wrong address.
#[derive(Debug, Clone)]
pub struct ListSpec {
    /// The list-link structure, e.g. `_LIST_ENTRY` or `list_head`.
    pub link_type: String,
    /// The forward-link member of that structure, e.g. `Flink` or `next`.
    pub forward: String,
    /// The structure the link is embedded in, and the member holding it, for
    /// `CONTAINING_RECORD`. `None` yields the link structures themselves.
    pub container: Option<(String, String)>,
    /// Hard ceiling on entries returned.
    pub max_entries: usize,
}

impl ListSpec {
    /// Follow `forward` links through structures of type `link_type`.
    pub fn new(link_type: impl Into<String>, forward: impl Into<String>) -> Self {
        Self {
            link_type: link_type.into(),
            forward: forward.into(),
            container: None,
            max_entries: DEFAULT_MAX_LIST_ENTRIES,
        }
    }

    /// Recover the containing structure from each link, the way
    /// `CONTAINING_RECORD` does.
    ///
    /// `member` must be the member of `container_type` that holds the link, and
    /// this is checked against the symbol table: pointing it at a different
    /// member would subtract the wrong number from every entry and yield a list
    /// of structures that are all off by a constant.
    pub fn in_container(
        mut self,
        container_type: impl Into<String>,
        member: impl Into<String>,
    ) -> Self {
        self.container = Some((container_type.into(), member.into()));
        self
    }

    /// Raise or lower the entry cap.
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }
}

/// Why a walk ended.
///
/// Only [`ListStop::Wrapped`] means the list was fully enumerated. Everything
/// else means the answer is partial, and the artifact must say so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListStop {
    /// The walk returned to the head: every entry in the list was visited.
    Wrapped,
    /// A forward link pointed at an address the walk had already visited. The
    /// list is corrupt, or it was being modified while the image was captured.
    Cycle {
        /// The address the walk arrived at for the second time.
        address: u64,
    },
    /// A forward link's bytes were never acquired, so the rest of the list
    /// cannot be followed. The list does continue; this image cannot show it.
    Hole(MemoryHole),
    /// A forward link was null. A circular kernel list never closes with a
    /// null, so this is truncation or corruption, not the end.
    NullLink {
        /// The link whose forward pointer was null.
        at: u64,
    },
    /// The entry cap fired. The walk stopped; the list did not.
    CapReached {
        /// The cap that fired.
        cap: usize,
    },
    /// Something else ended the walk: a symbol lookup, an arithmetic refusal,
    /// or an I/O failure.
    Failed {
        /// What happened, in the examiner's terms.
        detail: String,
        /// How the artifact should record it.
        reason: IncompleteReason,
    },
}

impl ListStop {
    /// Whether the list was fully enumerated.
    pub fn is_complete(&self) -> bool {
        matches!(self, ListStop::Wrapped)
    }

    /// Stable identifier for artifact metadata and log lines.
    pub fn as_str(&self) -> &'static str {
        match self {
            ListStop::Wrapped => "wrapped",
            ListStop::Cycle { .. } => "cycle",
            ListStop::Hole(_) => "hole",
            ListStop::NullLink { .. } => "null_link",
            ListStop::CapReached { .. } => "cap_reached",
            ListStop::Failed { .. } => "failed",
        }
    }

    /// The unmapped range that ended the walk, if one did.
    pub fn hole(&self) -> Option<MemoryHole> {
        match self {
            ListStop::Hole(hole) => Some(*hole),
            _ => None,
        }
    }

    /// What to stamp onto the artifact, or `None` if the list was complete.
    ///
    /// A caller that ignores this publishes a list it cannot vouch for.
    pub fn incomplete(&self) -> Option<Incomplete> {
        match self {
            ListStop::Wrapped => None,
            ListStop::Cycle { address } => Some(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!("the list returned to {address:#x}, so it does not terminate"),
            )),
            ListStop::Hole(hole) => Some(Incomplete::new(
                hole.incomplete_reason(),
                format!("the list continues past an unacquired region: {hole}"),
            )),
            ListStop::NullLink { at } => Some(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!("the forward link at {at:#x} is null, so the list does not close"),
            )),
            ListStop::CapReached { cap } => Some(Incomplete::new(
                IncompleteReason::CapReached,
                format!("the walk stopped at its cap of {cap} entries; the list continues"),
            )),
            ListStop::Failed { detail, reason } => Some(Incomplete::new(*reason, detail.clone())),
        }
    }

    /// Classify the failure that ended a walk.
    fn from_error(err: &ObjError) -> ListStop {
        if let Some(hole) = err.hole() {
            return ListStop::Hole(hole);
        }
        match err {
            ObjError::Cycle { address } => ListStop::Cycle { address: *address },
            ObjError::NullLink { address } => ListStop::NullLink { at: *address },
            ObjError::Cap { cap, .. } => ListStop::CapReached { cap: *cap as usize },
            other => ListStop::Failed {
                detail: other.to_string(),
                reason: other.incomplete_reason(),
            },
        }
    }
}

/// The containing structure a link is embedded in.
#[derive(Debug, Clone)]
struct Container {
    ty: TypeId,
    name: Arc<str>,
    offset: u64,
}

/// A cycle-safe, capped, hole-honest walk of a doubly-linked list.
///
/// Yields one [`Obj`] per entry. On any abnormal ending it yields exactly one
/// `Err` and then stops; [`ListWalk::stop`] holds the reason from that point
/// on. Created by [`StructReader::walk_list`].
#[derive(Debug)]
pub struct ListWalk {
    reader: StructReader,
    head: u64,
    forward_offset: u64,
    forward: Scalar,
    link_ty: TypeId,
    link_name: Arc<str>,
    container: Option<Container>,
    cursor: Option<u64>,
    visited: HashSet<u64>,
    yielded: usize,
    max_entries: usize,
    stop: Option<ListStop>,
}

impl ListWalk {
    /// The head the walk started from.
    pub fn head(&self) -> u64 {
        self.head
    }

    /// Why the walk ended, once it has. `None` while it is still running.
    pub fn stop(&self) -> Option<&ListStop> {
        self.stop.as_ref()
    }

    /// Whether the walk came back to its head, having seen every entry.
    ///
    /// False while the walk is still running, and false for every abnormal
    /// ending. A caller reporting a count should report this beside it.
    pub fn is_complete(&self) -> bool {
        matches!(self.stop, Some(ListStop::Wrapped))
    }

    /// How many entries have been yielded so far.
    pub fn yielded(&self) -> usize {
        self.yielded
    }

    /// The entry cap this walk is bounded by.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Run the walk to its end, keeping what it found and why it stopped.
    ///
    /// The partial list is deliberately kept: the entries before a hole are
    /// real evidence, and discarding them because the walk could not finish
    /// loses more than it protects. The [`ListStop`] is what stops the partial
    /// list from being mistaken for a complete one.
    pub fn walk_to_end(mut self) -> (Vec<Obj>, ListStop) {
        let mut entries = Vec::new();
        for item in &mut self {
            match item {
                Ok(object) => entries.push(object),
                Err(_) => break,
            }
        }
        // `next` never ends without recording a reason, so the fallback is
        // unreachable. It is written as a failure rather than as `Wrapped`
        // because the one thing that must never be produced by accident is a
        // claim that the list was complete.
        let stop = self.stop.take().unwrap_or(ListStop::Failed {
            detail: "the walk ended without recording a reason".to_string(),
            reason: IncompleteReason::UnresolvedStructure,
        });
        (entries, stop)
    }

    /// Read the forward link out of the link structure at `address`.
    fn forward_of(&self, address: u64) -> Result<u64, ObjError> {
        let at = address.checked_add(self.forward_offset).ok_or_else(|| {
            ObjError::Overflow(format!(
                "the forward link of '{}' at {address:#x} lies past the end of the 64-bit \
                 address space",
                self.link_name
            ))
        })?;
        let what = format!("{}.forward link", self.link_name);
        let value = self.reader.read_scalar_at(at, self.forward, &what)?;
        Ok(raw_bits(value))
    }

    /// The object a link address belongs to: the container it is embedded in,
    /// or the link structure itself.
    fn object_at(&self, link: u64) -> Result<Obj, ObjError> {
        match &self.container {
            Some(container) => {
                let address = link.checked_sub(container.offset).ok_or_else(|| {
                    ObjError::Overflow(format!(
                        "the list link at {link:#x} lies {} byte(s) inside '{}', which would \
                         place the structure below address zero",
                        container.offset, container.name
                    ))
                })?;
                Ok(self
                    .reader
                    .object_of(address, container.ty, Arc::clone(&container.name)))
            }
            None => Ok(self
                .reader
                .object_of(link, self.link_ty, Arc::clone(&self.link_name))),
        }
    }

    /// End the walk, recording why, and hand the failure to the caller.
    fn halt(&mut self, err: ObjError) -> Result<Obj, ObjError> {
        self.stop = Some(ListStop::from_error(&err));
        Err(err)
    }
}

impl Iterator for ListWalk {
    type Item = Result<Obj, ObjError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.stop.is_some() {
            return None;
        }

        let from = self.cursor.unwrap_or(self.head);
        let link = match self.forward_of(from) {
            Ok(link) => link,
            Err(err) => return Some(self.halt(err)),
        };

        // The one normal ending: back at the head, having seen everything.
        if link == self.head {
            self.stop = Some(ListStop::Wrapped);
            return None;
        }
        // A circular kernel list never closes with a null.
        if link == 0 {
            return Some(self.halt(ObjError::NullLink { address: from }));
        }
        if self.yielded >= self.max_entries {
            return Some(self.halt(ObjError::Cap {
                what: "list entries",
                cap: self.max_entries as u64,
            }));
        }
        // Cycle safety: an address seen twice means the chain does not
        // terminate, and continuing would either loop forever or report the
        // same structure repeatedly.
        if !self.visited.insert(link) {
            return Some(self.halt(ObjError::Cycle { address: link }));
        }

        let object = match self.object_at(link) {
            Ok(object) => object,
            Err(err) => return Some(self.halt(err)),
        };
        self.cursor = Some(link);
        self.yielded += 1;
        Some(Ok(object))
    }
}

impl StructReader {
    /// Start a walk of the doubly-linked list whose head is at `head`.
    ///
    /// Every offset the walk needs is resolved here, once: the forward link's
    /// position inside the link structure, and the link member's position
    /// inside the container. A member this build does not have fails now,
    /// naming the member, rather than producing a list of structures that are
    /// all at the wrong address.
    ///
    /// The walk runs entirely in the **native** space, because every address in
    /// a linked list is a native-space address — including when the head was
    /// found by scanning a physical layer.
    ///
    /// # Errors
    ///
    /// [`ObjError::Symbols`] if a type or member does not exist, if the forward
    /// member is not a pointer, or if the named container member is not the
    /// link type. No memory is read here.
    pub fn walk_list(&self, head: u64, spec: &ListSpec) -> Result<ListWalk, ObjError> {
        let reader = self.in_native_space();
        let link_ty = reader.symbols().type_id(&spec.link_type)?;
        reader.aggregate_of(link_ty, &spec.link_type)?;

        let (forward_offset, forward_ty) =
            reader.resolve_path(link_ty, &spec.link_type, &spec.forward)?;
        let what = format!("{}.{}", spec.link_type, spec.forward);
        let forward = match &reader.symbols().entry(forward_ty)?.kind {
            TypeKind::Pointer { size, endian, .. } => {
                if *size != 4 && *size != 8 {
                    return Err(ObjError::PointerWidth { what, size: *size });
                }
                Scalar {
                    size: *size,
                    endian: *endian,
                    signed: false,
                    bitfield: None,
                }
            }
            other => {
                return Err(SymbolError::WrongTypeKind {
                    name: what,
                    actual: other.as_str(),
                    expected: "a pointer member",
                }
                .into())
            }
        };

        let container = match &spec.container {
            Some((container_type, member)) => {
                let ty = reader.symbols().type_id(container_type)?;
                reader.aggregate_of(ty, container_type)?;
                let (offset, member_ty) = reader.resolve_path(ty, container_type, member)?;
                if member_ty != link_ty {
                    return Err(SymbolError::malformed(format!(
                        "'{container_type}.{member}' is a '{}', not the list-link type \
                         '{}', so subtracting its offset would place every entry at the \
                         wrong address",
                        reader.type_name_of(member_ty)?,
                        spec.link_type
                    ))
                    .into());
                }
                Some(Container {
                    ty,
                    name: Arc::from(container_type.as_str()),
                    offset,
                })
            }
            None => None,
        };

        Ok(ListWalk {
            reader,
            head,
            forward_offset,
            forward,
            link_ty,
            link_name: Arc::from(spec.link_type.as_str()),
            container,
            cursor: None,
            visited: HashSet::new(),
            yielded: 0,
            max_entries: spec.max_entries,
            stop: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::test_support::{
        fixture, fixture32, physical_reader, HEAD32, HEAD_CHAIN, HEAD_CYCLE, HEAD_HOLE, HEAD_LOOP,
        HEAD_MAIN, HEAD_NULL, LINKS_OFFSET, LOOP_BASE, NODE32_A, NODE32_B, PROC_A, PROC_B, PROC_C,
        PROC_D, PROC_IN_HOLE, STAIR_BASE, STAIR_COUNT, STAIR_STRIDE,
    };

    fn spec() -> ListSpec {
        ListSpec::new("list_head", "next").in_container("proc", "links")
    }

    #[test]
    fn a_well_formed_circular_list_yields_every_entry_and_says_it_wrapped() {
        let reader = fixture();
        let walk = reader.walk_list(HEAD_MAIN, &spec()).unwrap();
        let (entries, stop) = walk.walk_to_end();

        let addresses: Vec<u64> = entries.iter().map(|e| e.address()).collect();
        assert_eq!(addresses, vec![PROC_A, PROC_B, PROC_C]);
        assert_eq!(stop, ListStop::Wrapped);
        assert!(stop.is_complete());
        assert!(
            stop.incomplete().is_none(),
            "a complete list has nothing to declare"
        );
    }

    #[test]
    fn container_arithmetic_recovers_the_structure_from_its_embedded_link() {
        // The link addresses are eight bytes into each `proc`; the entries must
        // come back as the `proc`s, not as the links.
        let reader = fixture();
        let mut walk = reader.walk_list(HEAD_MAIN, &spec()).unwrap();
        let first = walk.next().expect("one entry").expect("readable");
        assert_eq!(first.type_name(), "proc");
        assert_eq!(
            first.address(),
            PROC_A,
            "the link is at {LINKS_OFFSET} bytes into the structure and must be subtracted"
        );
        assert_eq!(
            reader.read_pointer_at(HEAD_MAIN).unwrap(),
            PROC_A + LINKS_OFFSET,
            "the raw link really does point into the middle of the structure"
        );
        assert_eq!(first.signed("pid").unwrap(), -1);
    }

    #[test]
    fn without_a_container_the_walk_yields_the_link_structures_themselves() {
        let reader = fixture();
        let walk = reader
            .walk_list(HEAD_MAIN, &ListSpec::new("list_head", "next"))
            .unwrap();
        let (entries, stop) = walk.walk_to_end();
        assert_eq!(stop, ListStop::Wrapped);
        assert_eq!(
            entries.iter().map(|e| e.address()).collect::<Vec<_>>(),
            vec![PROC_A + 8, PROC_B + 8, PROC_C + 8]
        );
        assert_eq!(entries[0].type_name(), "list_head");
    }

    #[test]
    fn a_list_of_four_byte_links_is_followed_at_the_width_the_table_declares() {
        // Read at the host's eight bytes, the head's forward link would be
        // 0x00001144_00001104 — an address in nobody's kernel, from which the
        // walk would never come back to the head.
        let reader = fixture32();
        let walk = reader
            .walk_list(
                HEAD32,
                &ListSpec::new("link32", "next").in_container("node32", "links"),
            )
            .unwrap();
        let (entries, stop) = walk.walk_to_end();
        assert_eq!(
            entries.iter().map(|e| e.address()).collect::<Vec<_>>(),
            vec![NODE32_A, NODE32_B]
        );
        assert_eq!(stop, ListStop::Wrapped);
        assert_eq!(entries[1].unsigned("id").unwrap(), 2);
    }

    #[test]
    fn a_list_that_links_to_itself_stops_at_the_cycle_rather_than_looping_forever() {
        let reader = fixture();
        let mut walk = reader.walk_list(HEAD_CYCLE, &spec()).unwrap();

        let first = walk.next().expect("one entry").expect("readable");
        assert_eq!(first.address(), PROC_D);

        let err = walk
            .next()
            .expect("the cycle is reported, not skipped")
            .expect_err("a repeated address must not be walked again");
        assert_eq!(err.class(), "cycle");
        assert_eq!(
            walk.stop(),
            Some(&ListStop::Cycle {
                address: PROC_D + LINKS_OFFSET
            })
        );
        assert!(!walk.is_complete());
        assert!(walk.next().is_none(), "a halted walk stays halted");

        let incomplete = walk.stop().unwrap().incomplete().expect("declared");
        assert!(incomplete.detail.contains("does not terminate"));
    }

    #[test]
    fn a_loop_that_closes_onto_a_middle_entry_is_caught_by_the_visited_set() {
        // The self-link above is the easy case: the walk arrives back where it
        // just was. A rootkit splicing a list, or a list captured mid-edit,
        // produces this shape instead — the tail points at the *second* entry,
        // so neither "is this the head" nor "is this where I came from" catches
        // it, and only the visited set can.
        let reader = fixture();
        let walk = reader
            .walk_list(HEAD_LOOP, &ListSpec::new("list_head", "next"))
            .unwrap();
        let (entries, stop) = walk.walk_to_end();

        let addresses: Vec<u64> = entries.iter().map(|e| e.address()).collect();
        assert_eq!(
            addresses,
            vec![LOOP_BASE, LOOP_BASE + 0x10, LOOP_BASE + 0x20],
            "each entry is reported once, and the loop is not walked twice"
        );
        assert_eq!(
            stop,
            ListStop::Cycle {
                address: LOOP_BASE + 0x10
            },
            "the repeat is named, and it is not the head"
        );
        assert!(
            !stop.is_complete(),
            "a list that loops onto itself did not wrap"
        );
    }

    #[test]
    fn an_unterminated_chain_of_fresh_addresses_is_stopped_by_the_cap_alone() {
        // Cycle detection cannot save a walk whose every link is a new address:
        // a corrupt chain wanders through memory forever, and only the cap ends
        // it. This is the case the cap exists for, and the well-formed list the
        // other cap test uses could not prove it.
        let reader = fixture();
        let walk = reader
            .walk_list(
                HEAD_CHAIN,
                &ListSpec::new("list_head", "next").with_max_entries(5),
            )
            .unwrap();
        let (entries, stop) = walk.walk_to_end();

        let addresses: Vec<u64> = entries.iter().map(|e| e.address()).collect();
        assert_eq!(
            addresses,
            (0..5)
                .map(|i| STAIR_BASE + i * STAIR_STRIDE)
                .collect::<Vec<u64>>()
        );
        assert_eq!(stop, ListStop::CapReached { cap: 5 });
        let unique: HashSet<u64> = addresses.iter().copied().collect();
        assert_eq!(
            unique.len(),
            addresses.len(),
            "no address repeated, so the visited set cannot be what stopped this"
        );
        assert!(!stop.is_complete());
    }

    #[test]
    fn the_same_chain_uncapped_ends_at_its_null_rather_than_claiming_to_have_wrapped() {
        // The control for the cap test: without the cap the walk runs the chain
        // out, and what it finds at the end is a null — which is truncation,
        // not the end of a circular list.
        let reader = fixture();
        let walk = reader
            .walk_list(HEAD_CHAIN, &ListSpec::new("list_head", "next"))
            .unwrap();
        let (entries, stop) = walk.walk_to_end();

        assert_eq!(entries.len(), STAIR_COUNT as usize);
        assert_eq!(
            stop,
            ListStop::NullLink {
                at: STAIR_BASE + (STAIR_COUNT - 1) * STAIR_STRIDE
            }
        );
        assert!(
            !stop.is_complete(),
            "a chain that ends in a null is not a list that closed"
        );
        assert_eq!(
            stop.incomplete().expect("declared").reason,
            IncompleteReason::UnresolvedStructure
        );
    }

    #[test]
    fn a_walk_that_reaches_unacquired_memory_stops_and_says_exactly_where() {
        // The entry the head names is a fact even though its bytes were never
        // captured, so it is yielded; the walk then cannot follow it further,
        // and that is a stated gap rather than the end of the list.
        let reader = fixture();
        let mut walk = reader.walk_list(HEAD_HOLE, &spec()).unwrap();

        let first = walk.next().expect("one entry").expect("the link is a fact");
        assert_eq!(first.address(), PROC_IN_HOLE);
        assert!(
            first.signed("pid").is_err(),
            "its bytes were never acquired, so no member reads"
        );

        let err = walk
            .next()
            .expect("the walk reports why it stopped")
            .expect_err("an unreadable link is not the end of the list");
        let hole = err.hole().expect("the unmapped range must survive");
        assert_eq!(hole.address, PROC_IN_HOLE + LINKS_OFFSET);

        match walk.stop() {
            Some(ListStop::Hole(stopped)) => assert_eq!(*stopped, hole),
            other => panic!("expected a hole stop, got {other:?}"),
        }
        let incomplete = walk.stop().unwrap().incomplete().expect("declared");
        assert_eq!(incomplete.reason, IncompleteReason::ShortRead);
    }

    #[test]
    fn a_null_forward_link_is_reported_rather_than_treated_as_the_end() {
        let reader = fixture();
        let mut walk = reader.walk_list(HEAD_NULL, &spec()).unwrap();
        let err = walk
            .next()
            .expect("a null link is reported")
            .expect_err("a circular list never closes with a null");
        assert_eq!(err.class(), "null_link");
        assert_eq!(walk.stop(), Some(&ListStop::NullLink { at: HEAD_NULL }));
        assert_eq!(walk.yielded(), 0);
    }

    #[test]
    fn the_cap_stops_the_walk_and_is_never_mistaken_for_the_end_of_the_list() {
        let reader = fixture();
        let walk = reader
            .walk_list(HEAD_MAIN, &spec().with_max_entries(2))
            .unwrap();
        assert_eq!(walk.max_entries(), 2);
        let (entries, stop) = walk.walk_to_end();

        assert_eq!(entries.len(), 2, "the list has three; the cap allowed two");
        assert_eq!(stop, ListStop::CapReached { cap: 2 });
        assert!(!stop.is_complete());
        let incomplete = stop.incomplete().expect("declared");
        assert_eq!(incomplete.reason, IncompleteReason::CapReached);
        assert!(incomplete.detail.contains("the list continues"));
    }

    #[test]
    fn a_missing_link_member_fails_when_the_walk_is_built_not_at_entry_three_thousand() {
        let reader = fixture();
        let err = reader
            .walk_list(HEAD_MAIN, &ListSpec::new("list_head", "Flink"))
            .expect_err("this build has no such member");
        assert_eq!(err.class(), "symbols");
        assert!(err.to_string().contains("Flink"), "{err}");
    }

    #[test]
    fn a_forward_member_that_is_not_a_pointer_is_refused_before_any_read() {
        let reader = fixture();
        let err = reader
            .walk_list(HEAD_MAIN, &ListSpec::new("proc", "pid"))
            .expect_err("an integer is not a link");
        assert!(err.to_string().contains("pointer"), "{err}");
    }

    #[test]
    fn the_container_member_must_be_the_link_type_itself() {
        // Subtracting the offset of the wrong member would put every entry at
        // the wrong address, and every one of them would still parse.
        let reader = fixture();
        let err = reader
            .walk_list(
                HEAD_MAIN,
                &ListSpec::new("list_head", "next").in_container("proc", "ticks"),
            )
            .expect_err("`ticks` is not the embedded list link");
        assert!(err.to_string().contains("ticks"), "{err}");
    }

    #[test]
    fn a_walk_started_from_a_physically_scanned_reader_runs_in_the_native_space() {
        // Pool scanning finds the head by scanning physical memory, but the
        // links inside it are kernel virtual addresses.
        let (reader, native) = physical_reader();
        let walk = reader.walk_list(HEAD_MAIN, &spec()).unwrap();
        let (entries, stop) = walk.walk_to_end();
        assert_eq!(stop, ListStop::Wrapped);
        assert_eq!(entries.len(), 3);
        for entry in &entries {
            assert!(
                Arc::ptr_eq(entry.reader().layer(), &native),
                "list entries are addressed in the native space"
            );
        }
    }

    #[test]
    fn a_stop_reason_maps_onto_something_the_artifact_can_carry() {
        for stop in [
            ListStop::Cycle { address: 0x1000 },
            ListStop::Hole(MemoryHole::unmapped(0x2000, 0x1000)),
            ListStop::NullLink { at: 0x1000 },
            ListStop::CapReached { cap: 8 },
            ListStop::Failed {
                detail: "the symbol table has no such member".into(),
                reason: IncompleteReason::UnresolvedStructure,
            },
        ] {
            assert!(!stop.is_complete(), "{stop:?}");
            assert!(!stop.as_str().is_empty());
            assert!(stop.incomplete().is_some(), "{stop:?}");
        }
        assert!(ListStop::Wrapped.incomplete().is_none());
        assert_eq!(
            ListStop::Hole(MemoryHole::unmapped(0x2000, 0x1000))
                .hole()
                .map(|h| h.address),
            Some(0x2000)
        );
    }
}
