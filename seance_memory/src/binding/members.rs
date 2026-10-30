//! Declarative resolution of the structure members a stage needs.
//!
//! # The defect this removes
//!
//! On 2026-07-30 a real Windows XP capture produced 3 of 20 stages complete and
//! 9 failed. Eight of the nine were one line:
//!
//! ```text
//! reader.member_offset(TYPE_OBJECT_HEADER, "InfoMask")?;   // statement position
//! ```
//!
//! The offset is discarded — the call is a pure existence proof. `InfoMask`
//! arrived in Vista; XP and 2003 carry `NameInfoOffset` instead. The member is
//! never read on XP: it is consumed only under the top-down object-header
//! search, which is Windows 8 and later. So a member no XP code path reaches
//! killed pool scanning, cross-view, services, kernel objects, VAD, syscall
//! scanning, tampering and recovered files — including VAD, which touches those
//! symbols for one `_POOL_HEADER` fact and never reads an object header at all.
//!
//! **The class: a build-variant member proved fatally in a pre-flight that the
//! branch reading it never reaches.**
//!
//! # The rule
//!
//! > A structure member that is absent because this kernel build never had it
//! > is **not declared**. It is not incompleteness, and it is not an error.
//!
//! Escalating that to a stage failure tells an examiner the analysis could not
//! run when it ran fine and one column does not exist on this operating system.
//! Escalating it to *incompleteness* would be as wrong in the other direction:
//! it would say evidence was missed when none was. So resolution yields
//! [`Field::NotDeclared`] **by default**, and fails only for a member a stage
//! declared [`Necessity::Required`] — which forces whoever marks it required to
//! write down, in `without_it`, what the stage cannot do.
//!
//! # Why this is not tidying
//!
//! The Linux tier is this problem 231 times over: that is the count of
//! `has_member` branches across Volatility 3's Linux symbols and plugins.
//! macOS varies across 129 real Kernel Debug Kit packs — `trap_table` absent in
//! 24, `BootPML4` in 12, `ifnet_head` in 6, the type `kevent_qos_s` in 34 — and
//! credentials need a fallback in *both* directions, `ucred.cr_posix` being
//! absent in 6 packs where `ucred.cr_uid` exists and `cr_uid` absent in the
//! other 123. Volatility itself fails from exactly this class on our Linux
//! sample: Debian 3.2 names the type `kernel_cap_t` where its extension is
//! registered on `kernel_cap_struct`. That is why candidate lists here are
//! ordered lists of **type** names as well as of member** names.
//!
//! # Shape of a declaration
//!
//! ```
//! use seance_memory::binding::{MemberSet, MemberSpec, StageId, TypeSpec};
//!
//! const STAGE: StageId = StageId::new(
//!     "pool_scan",
//!     "MemoryPoolScan",
//!     false,
//!     "Process objects found by scanning the kernel pool.",
//! );
//!
//! const LAYOUT: MemberSet = MemberSet::new(
//!     STAGE,
//!     &[TypeSpec::new("pool_header", &["_POOL_HEADER"]).required(
//!         "no pool allocation can be sized, so no candidate object can be found at all",
//!     )],
//!     &[
//!         // Vista and later; XP and 2003 have none of these, and that is not an error.
//!         MemberSpec::new("info_mask", &["_OBJECT_HEADER"], &["InfoMask"]),
//!         // XP and 2003 spell the same idea as a direct byte.
//!         MemberSpec::new("name_info_offset", &["_OBJECT_HEADER"], &["NameInfoOffset"]),
//!     ],
//! );
//!
//! assert_eq!(LAYOUT.stage.key, "pool_scan");
//! assert_eq!(LAYOUT.members.len(), 2);
//! ```
//!
//! # Finding what has not been migrated
//!
//! The compiler finds it. `member_offset` and `size_of` return `#[must_use]`
//! newtypes, so the statement-position, result-discarded existence proof this
//! module exists to replace fails the build rather than waiting for a reviewer
//! to grep for it.
//!
//! What the compiler does *not* judge is whether a bound-and-read offset should
//! have been a declaration instead. That is still a reading of the code: an
//! offset read on every branch is correct, and one read only under a branch
//! some builds never take is this module's job.
//!
//! # What is deliberately not this class
//!
//! A whole-stage refusal with a written reason must stay fatal. Refusing to
//! decode network structures on a kernel whose `_ADDRESS_OBJECT` /
//! `_TCPT_OBJECT` decoder was never written is an honest refusal of an
//! unimplemented decoder, and downgrading it to "no network activity" would be
//! a regression. `Required` exists for exactly that case; `without_it` is where
//! the reason is written.

use seance_symbols::{SymbolError, SymbolTable};
use serde_json::json;

use super::field::Field;
use super::stage::StageId;
use crate::object::{Obj, ObjError, StructReader};

// ── Absence versus failure ──────────────────────────────────────────────────

/// Whether a lookup failure means "this build's declared layout does not
/// provide it", as opposed to "the symbol table could not answer".
///
/// The three absence errors:
///
/// - `UnknownType` — no type of that name in this build.
/// - `UnknownMember` — the type exists and has no such field.
/// - `WrongTypeKind` — the name exists but is not an aggregate, so it has no
///   members to reach. This is what `kernel_cap_t` looks like on a kernel where
///   it is a typedef to a scalar rather than a struct, and it is a statement
///   about the build's layout, not about the table being broken.
///
/// Everything else — a shadowed name the table refuses to disambiguate, an
/// unresolved type reference, an overflowed offset, a path deeper than the
/// reader walks — means the question was put and could not be answered. Calling
/// that "this build has no such member" would be a fabricated claim about the
/// suspect's machine.
///
/// The unresolved reference is the one that has to be kept out of
/// `WrongTypeKind` deliberately. A reference the document never defined stays in
/// the arena as its own entry and fails at the point of use, so a member path
/// walked through one asks the reader for an aggregate and does not get one.
/// The reader answers that with `SymbolError::UnresolvedType`, not with
/// `WrongTypeKind`, which is what keeps a symbol table that could not be read
/// out of the set of claims about the machine the image came from. Folding the
/// two together is not a cosmetic slip: it reports "this kernel has no such
/// member" over a table the analysis simply failed to load.
fn is_absence(err: &ObjError) -> bool {
    matches!(err, ObjError::Symbols(inner) if is_symbol_absence(inner))
}

/// [`is_absence`] for a table consulted directly rather than through a reader.
///
/// The same three errors mean the same thing whichever way the question was
/// put, and a second hand-written list of them would drift: the one that
/// matters is [`SymbolError::AmbiguousMember`], which is *not* absence and
/// which a `has_member`-style boolean silently reports as one.
fn is_symbol_absence(err: &SymbolError) -> bool {
    matches!(
        err,
        SymbolError::UnknownType(_)
            | SymbolError::UnknownMember { .. }
            | SymbolError::WrongTypeKind { .. }
    )
}

/// `'a', 'b'` — candidate names for a message an examiner reads.
fn name_list(names: &[&str]) -> String {
    names
        .iter()
        .map(|name| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

// ── The low-level idiom ─────────────────────────────────────────────────────

/// The first of `candidates` that this build's `type_name` actually declares.
///
/// # What an examiner learns
///
/// Which spelling of a field this kernel build uses, which is what a report has
/// to name when two builds store the same fact under different member names.
///
/// # Outcomes
///
/// - `Ok(Some(name))` — this build declares `name`, and it is the first
///   candidate it declares.
/// - `Ok(None)` — this build declares none of them. Nothing was missed; the
///   field does not exist on this operating system build.
/// - `Err` — the symbol table could not answer for a reason that is not
///   absence. Returned rather than folded into `None`, because "this build has
///   no such member" is a claim about the suspect's machine and a broken symbol
///   table is not evidence for it.
///
/// A prior version of this helper returned bare `Option` and used
/// `member_offset(..).is_ok()`, which collapsed the third outcome into the
/// second.
pub fn first_member<'a>(
    reader: &StructReader,
    type_name: &str,
    candidates: &'a [&'a str],
) -> Result<Option<&'a str>, ObjError> {
    let mut failure: Option<ObjError> = None;
    for candidate in candidates {
        match reader.member_offset(type_name, candidate) {
            Ok(_) => return Ok(Some(*candidate)),
            Err(err) if is_absence(&err) => {}
            Err(err) => {
                if failure.is_none() {
                    failure = Some(err);
                }
            }
        }
    }
    match failure {
        Some(err) => Err(err),
        None => Ok(None),
    }
}

/// [`first_member`] against a symbol table held directly.
///
/// Some stages hold a [`SymbolTable`] rather than a [`StructReader`] — the
/// registry space is compiled from a hive rather than read through a reader, and
/// the network tier carries two tables side by side. Those stages had no
/// absence-aware idiom at all, so they used `has_member`, which answers `false`
/// for a member the table refuses to disambiguate as readily as for one the
/// build does not have. Those are opposite claims: the first is a table this
/// analysis could not read, the second is a statement about the suspect's
/// machine.
///
/// Outcomes are those of [`first_member`]. `candidates` are plain member names:
/// a table consulted directly does not walk a `.`-separated path, so a stage
/// needing one must go through [`first_member`] and a reader.
pub fn first_declared_member<'a>(
    symbols: &SymbolTable,
    type_name: &str,
    candidates: &'a [&'a str],
) -> Result<Option<&'a str>, SymbolError> {
    let mut failure: Option<SymbolError> = None;
    for candidate in candidates {
        match symbols.member_offset(type_name, candidate) {
            Ok(_) => return Ok(Some(*candidate)),
            Err(err) if is_symbol_absence(&err) => {}
            Err(err) => {
                if failure.is_none() {
                    failure = Some(err);
                }
            }
        }
    }
    match failure {
        Some(err) => Err(err),
        None => Ok(None),
    }
}

/// The first of `candidates` that this build declares as a type at all.
///
/// The type-name half of the same problem: Debian 3.2 names a capability set
/// `kernel_cap_t` where other kernels name it `kernel_cap_struct`, and asking
/// for the wrong one is not a broken image.
///
/// Outcomes are those of [`first_member`].
pub fn first_type<'a>(
    reader: &StructReader,
    candidates: &'a [&'a str],
) -> Result<Option<&'a str>, SymbolError> {
    let mut failure: Option<SymbolError> = None;
    for candidate in candidates {
        match reader.symbols().type_id(candidate) {
            Ok(_) => return Ok(Some(*candidate)),
            Err(SymbolError::UnknownType(_)) => {}
            Err(err) => {
                if failure.is_none() {
                    failure = Some(err);
                }
            }
        }
    }
    match failure {
        Some(err) => Err(err),
        None => Ok(None),
    }
}

// ── One required value, without a whole declaration ─────────────────────────

/// The size of a type the stage genuinely cannot proceed without.
///
/// # When this is the right answer rather than [`Necessity::Optional`]
///
/// A handle table cannot be walked without knowing an entry's stride: with no
/// stride there is no second entry to read, so failing *is* correct and
/// downgrading it would report an empty handle table for a process that had
/// hundreds. What was wrong at those sites was never the fatality, it was the
/// sentence the examiner got. `reader.size_of(T)?` reaches a stage error's
/// `#[error(transparent)]` variant as a bare `SymbolError` — "unknown type
/// '_HANDLE_TABLE_ENTRY'" — which names neither the stage that stopped nor what
/// stopping cost. This produces [`BindError::RequiredNotDeclared`] or
/// [`BindError::RequiredUnresolved`] instead, both of which say all three.
///
/// It also keeps apart the two failures that a `has_type` pre-flight cannot:
/// `has_type` is `type_id(..).is_ok()`, so it answers `false` for a name the
/// table declares in two blocks at once and cannot disambiguate. A guard built
/// on it then tells an examiner "this build has no `_SID_AND_ATTRIBUTES`" — a
/// claim about the suspect's machine — when the truth is that this analysis
/// could not read its own symbol table.
///
/// `without_it` completes the sentence "Without it, …" and is printed verbatim.
/// See [`Necessity::Required`] for what counts as a justification.
///
/// # Errors
///
/// [`BindError::RequiredNotDeclared`] when this build declares none of
/// `candidates`, [`BindError::RequiredUnresolved`] when the table could not
/// answer, and [`BindError::NoCandidates`] for an empty candidate list, which
/// would leave nothing to name in either message.
pub fn required_size(
    symbols: &SymbolTable,
    stage: StageId,
    candidates: &'static [&'static str],
    without_it: &'static str,
) -> Result<u64, BindError> {
    let Some(key) = candidates.first().copied() else {
        return Err(BindError::NoCandidates {
            stage: stage.key,
            kind: "type",
            key: UNNAMED,
        });
    };
    match resolve_type(symbols, candidates) {
        TypeUse::Declared { size, .. } => Ok(size),
        TypeUse::NotDeclared => Err(BindError::RequiredNotDeclared {
            stage: stage.key,
            kind: "type",
            key,
            candidates: name_list(candidates),
            without_it,
        }),
        TypeUse::Unavailable { detail } => Err(BindError::RequiredUnresolved {
            stage: stage.key,
            kind: "type",
            key,
            candidates: name_list(candidates),
            detail,
            without_it,
        }),
    }
}

/// The offset of a member the stage genuinely cannot proceed without.
///
/// The member half of [`required_size`], with the same justification and the
/// same two failures. `members` may reach through embedded aggregates with `.`,
/// as [`MemberSpec::members`] does.
///
/// # Errors
///
/// Those of [`required_size`].
pub fn required_offset(
    reader: &StructReader,
    stage: StageId,
    types: &'static [&'static str],
    members: &'static [&'static str],
    without_it: &'static str,
) -> Result<u64, BindError> {
    let key = members.first().copied().unwrap_or(UNNAMED);
    if members.is_empty() || types.is_empty() {
        return Err(BindError::NoCandidates {
            stage: stage.key,
            kind: "member",
            key,
        });
    }
    match resolve_member(reader, types, members) {
        MemberUse::Declared { offset, .. } => Ok(offset),
        MemberUse::NotDeclared => Err(BindError::RequiredNotDeclared {
            stage: stage.key,
            kind: "member",
            key,
            candidates: name_list(members),
            without_it,
        }),
        MemberUse::Unavailable { detail } => Err(BindError::RequiredUnresolved {
            stage: stage.key,
            kind: "member",
            key,
            candidates: name_list(members),
            detail,
            without_it,
        }),
    }
}

/// Stand-in key for a declaration that listed no candidate names, so there is no
/// name to quote. Refused rather than resolved; see [`BindError::NoCandidates`].
const UNNAMED: &str = "(no candidate names)";

// ── Declarations ────────────────────────────────────────────────────────────

/// Whether a stage can run without the thing being resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Necessity {
    /// The stage runs whether or not this build declares it. Absence yields
    /// [`Field::NotDeclared`], which is a complete answer and not a gap.
    ///
    /// This is the default, and it is the default because the alternative is
    /// what killed eight stages on a Windows XP image.
    Optional,
    /// The stage cannot produce an answer worth reading without it, so its
    /// absence is a stage failure.
    ///
    /// Marking something required is a claim that must be justified in writing:
    /// `without_it` is that justification, and it is printed verbatim to the
    /// examiner when the failure happens. "The pool header cannot be sized, so
    /// no candidate object can be found at all" is a justification. "Needed for
    /// parsing" is not — it tells an examiner nothing about what is lost, and
    /// a member that is merely convenient must be [`Necessity::Optional`].
    Required {
        /// What the stage cannot do without it, in the examiner's terms,
        /// completing the sentence "Without it, …".
        without_it: &'static str,
    },
}

impl Necessity {
    /// Whether absence is a stage failure.
    pub fn is_required(self) -> bool {
        matches!(self, Necessity::Required { .. })
    }
}

/// A named type a stage needs, and the names this build might declare it under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeSpec {
    /// How the stage refers to it. Lookups use this, never a candidate name, so
    /// the stage's own code does not change when a build spells the type
    /// differently.
    pub key: &'static str,
    /// Candidate type names, most preferred first.
    pub candidates: &'static [&'static str],
    /// Whether the stage can run without it.
    pub necessity: Necessity,
}

impl TypeSpec {
    /// An optional type: absence is an answer, not a failure.
    pub const fn new(key: &'static str, candidates: &'static [&'static str]) -> Self {
        Self {
            key,
            candidates,
            necessity: Necessity::Optional,
        }
    }

    /// Mark it required, stating what the stage cannot do without it.
    ///
    /// `without_it` completes the sentence "Without it, …" in the failure an
    /// examiner reads. See [`Necessity::Required`] for what counts as a
    /// justification.
    pub const fn required(self, without_it: &'static str) -> Self {
        Self {
            key: self.key,
            candidates: self.candidates,
            necessity: Necessity::Required { without_it },
        }
    }
}

/// A structure member a stage wants, and every name this build might have it
/// under.
///
/// Both dimensions vary in real evidence. The type name varies
/// (`kernel_cap_t` / `kernel_cap_struct`) and the member name varies
/// (`InfoMask` / `NameInfoOffset`, `cr_posix.cr_uid` / `cr_uid`), so
/// resolution walks the types in order and, within each, the members in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberSpec {
    /// How the stage refers to it.
    pub key: &'static str,
    /// Candidate type names, most preferred first.
    pub types: &'static [&'static str],
    /// Candidate member paths within those types, most preferred first. A path
    /// may reach through embedded aggregates with `.`, e.g. `"cr_posix.cr_uid"`
    /// or `"Token.Object"`; it never dereferences a pointer.
    pub members: &'static [&'static str],
    /// Whether the stage can run without it.
    pub necessity: Necessity,
}

impl MemberSpec {
    /// An optional member: absence is an answer, not a failure.
    pub const fn new(
        key: &'static str,
        types: &'static [&'static str],
        members: &'static [&'static str],
    ) -> Self {
        Self {
            key,
            types,
            members,
            necessity: Necessity::Optional,
        }
    }

    /// Mark it required, stating what the stage cannot do without it.
    ///
    /// `without_it` completes the sentence "Without it, …" in the failure an
    /// examiner reads. See [`Necessity::Required`] for what counts as a
    /// justification.
    pub const fn required(self, without_it: &'static str) -> Self {
        Self {
            key: self.key,
            types: self.types,
            members: self.members,
            necessity: Necessity::Required { without_it },
        }
    }
}

/// Everything one stage needs out of the symbol table, declared in one place.
///
/// The stage declares; [`MemberSet::bind`] resolves. Nothing between the two
/// can turn an absent build-variant member into a stage failure, because the
/// only route to a failure is a [`Necessity::Required`] declaration carrying a
/// written justification.
#[derive(Debug, Clone, Copy)]
pub struct MemberSet {
    /// The stage these belong to. Named in every failure, so an examiner reads
    /// which analysis stopped rather than only which field was missing.
    pub stage: StageId,
    /// Types this stage needs to name or size.
    pub types: &'static [TypeSpec],
    /// Members this stage needs to locate.
    pub members: &'static [MemberSpec],
}

impl MemberSet {
    /// One stage's declaration.
    pub const fn new(
        stage: StageId,
        types: &'static [TypeSpec],
        members: &'static [MemberSpec],
    ) -> Self {
        Self {
            stage,
            types,
            members,
        }
    }

    /// Resolve every declaration against this build's symbol table.
    ///
    /// Reads no memory: this is a pure symbol-table question, so it can be done
    /// once at the top of a stage and the answer carried through the walk.
    ///
    /// # Errors
    ///
    /// Only for a declaration the stage marked [`Necessity::Required`] and
    /// could not resolve, or for a malformed declaration — a key declared
    /// twice, or a spec with no candidate names, both of which would make a
    /// later lookup ambiguous or unanswerable. A build-variant member this
    /// kernel does not have is **not** an error; it lands as
    /// [`MemberUse::NotDeclared`].
    pub fn bind(&self, reader: &StructReader) -> Result<BuildBinding, BindError> {
        let stage = self.stage.key;

        let mut types: Vec<BoundType> = Vec::with_capacity(self.types.len());
        for spec in self.types {
            check_declaration(stage, "type", spec.key, spec.candidates, |key| {
                types.iter().any(|bound: &BoundType| bound.key == key)
            })?;
            let resolution = resolve_type(reader.symbols(), spec.candidates);
            if let Necessity::Required { without_it } = spec.necessity {
                require(stage, "type", spec.key, spec.candidates, without_it, {
                    match &resolution {
                        TypeUse::Declared { .. } => Resolved::Yes,
                        TypeUse::NotDeclared => Resolved::Absent,
                        TypeUse::Unavailable { detail } => Resolved::Failed(detail.clone()),
                    }
                })?;
            }
            types.push(BoundType {
                key: spec.key,
                candidates: spec.candidates,
                necessity: spec.necessity,
                resolution,
            });
        }

        let mut members: Vec<BoundMember> = Vec::with_capacity(self.members.len());
        for spec in self.members {
            check_declaration(stage, "member", spec.key, spec.members, |key| {
                members.iter().any(|bound: &BoundMember| bound.key == key)
            })?;
            if spec.types.is_empty() {
                return Err(BindError::NoCandidates {
                    stage,
                    kind: "member",
                    key: spec.key,
                });
            }
            let resolution = resolve_member(reader, spec.types, spec.members);
            if let Necessity::Required { without_it } = spec.necessity {
                require(stage, "member", spec.key, spec.members, without_it, {
                    match &resolution {
                        MemberUse::Declared { .. } => Resolved::Yes,
                        MemberUse::NotDeclared => Resolved::Absent,
                        MemberUse::Unavailable { detail } => Resolved::Failed(detail.clone()),
                    }
                })?;
            }
            members.push(BoundMember {
                key: spec.key,
                types: spec.types,
                candidates: spec.members,
                necessity: spec.necessity,
                resolution,
            });
        }

        Ok(BuildBinding {
            stage: self.stage,
            types,
            members,
        })
    }
}

/// Outcome of one resolution, reduced to what the required check cares about.
enum Resolved {
    Yes,
    Absent,
    Failed(String),
}

/// Refuse a declaration that a later lookup could not answer unambiguously.
fn check_declaration(
    stage: &'static str,
    kind: &'static str,
    key: &'static str,
    candidates: &'static [&'static str],
    already_seen: impl Fn(&'static str) -> bool,
) -> Result<(), BindError> {
    if candidates.is_empty() {
        return Err(BindError::NoCandidates { stage, kind, key });
    }
    if already_seen(key) {
        return Err(BindError::DuplicateKey { stage, kind, key });
    }
    Ok(())
}

/// Turn an unresolved *required* declaration into the stage failure it is.
fn require(
    stage: &'static str,
    kind: &'static str,
    key: &'static str,
    candidates: &'static [&'static str],
    without_it: &'static str,
    resolved: Resolved,
) -> Result<(), BindError> {
    match resolved {
        Resolved::Yes => Ok(()),
        Resolved::Absent => Err(BindError::RequiredNotDeclared {
            stage,
            kind,
            key,
            candidates: name_list(candidates),
            without_it,
        }),
        Resolved::Failed(detail) => Err(BindError::RequiredUnresolved {
            stage,
            kind,
            key,
            candidates: name_list(candidates),
            detail,
            without_it,
        }),
    }
}

/// Walk the type candidates in order and take the first this build declares.
fn resolve_type(symbols: &SymbolTable, candidates: &'static [&'static str]) -> TypeUse {
    let mut failure: Option<String> = None;
    for candidate in candidates {
        match symbols.type_id(candidate) {
            Ok(_) => {
                return match symbols.size_of(candidate) {
                    Ok(size) => TypeUse::Declared {
                        type_name: candidate,
                        size,
                    },
                    Err(err) => TypeUse::Unavailable {
                        detail: format!(
                            "this build declares '{candidate}' and its size could not be \
                             computed: {err}"
                        ),
                    },
                }
            }
            Err(SymbolError::UnknownType(_)) => {}
            Err(err) => {
                if failure.is_none() {
                    failure = Some(format!("'{candidate}': {err}"));
                }
            }
        }
    }
    match failure {
        Some(detail) => TypeUse::Unavailable { detail },
        None => TypeUse::NotDeclared,
    }
}

/// Walk the type candidates in order and, within each, the member candidates in
/// order, taking the first pair this build declares.
///
/// A genuine table failure seen along the way is remembered and reported only
/// if no candidate resolved, so a build that declares a later candidate is
/// still answered rather than being blamed for an earlier one.
fn resolve_member(
    reader: &StructReader,
    types: &'static [&'static str],
    members: &'static [&'static str],
) -> MemberUse {
    let mut failure: Option<String> = None;
    for type_name in types {
        for member in members {
            match reader.member_offset(type_name, member) {
                Ok(offset) => {
                    return MemberUse::Declared {
                        type_name,
                        member,
                        offset: offset.bytes(),
                    }
                }
                Err(err) if is_absence(&err) => {}
                Err(err) => {
                    if failure.is_none() {
                        failure = Some(format!("'{type_name}.{member}': {err}"));
                    }
                }
            }
        }
    }
    match failure {
        Some(detail) => MemberUse::Unavailable { detail },
        None => MemberUse::NotDeclared,
    }
}

// ── Resolution outcomes ─────────────────────────────────────────────────────

/// What resolving a declared type found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeUse {
    /// This build declares it, under this name and at this size.
    Declared {
        /// The candidate this build actually declares — the one a report names.
        type_name: &'static str,
        /// Size in bytes, as the symbol table computes it.
        size: u64,
    },
    /// This build declares none of the candidates. Nothing was missed.
    NotDeclared,
    /// The symbol table could not answer. The evidence about layout is damaged,
    /// which is not the same as the layout not having it.
    Unavailable {
        /// Why, in the examiner's terms.
        detail: String,
    },
}

/// What resolving a declared member found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberUse {
    /// This build declares it, on this type, under this name, at this offset.
    Declared {
        /// The type candidate this build declares it on.
        type_name: &'static str,
        /// The member path this build declares it under — the one a report
        /// names, because an examiner needs to know which layout was used.
        member: &'static str,
        /// Byte offset within the type.
        offset: u64,
    },
    /// This build declares none of the candidates on any of the candidate
    /// types. Nothing was missed.
    NotDeclared,
    /// The symbol table could not answer.
    Unavailable {
        /// Why, in the examiner's terms.
        detail: String,
    },
}

/// One resolved type declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundType {
    key: &'static str,
    candidates: &'static [&'static str],
    necessity: Necessity,
    resolution: TypeUse,
}

impl BoundType {
    /// The stage's own name for it.
    pub fn key(&self) -> &'static str {
        self.key
    }

    /// Every name that was tried, in the order they were tried.
    pub fn candidates(&self) -> &'static [&'static str] {
        self.candidates
    }

    /// What was found.
    pub fn resolution(&self) -> &TypeUse {
        &self.resolution
    }

    /// Whether this build declares any of the candidates.
    pub fn is_declared(&self) -> bool {
        matches!(self.resolution, TypeUse::Declared { .. })
    }

    /// The name this build declares it under, when it declares one.
    ///
    /// This is the name to pass to a reader: using a candidate the stage
    /// preferred rather than the one the build declares reads the wrong type.
    pub fn type_name(&self) -> Option<&'static str> {
        match self.resolution {
            TypeUse::Declared { type_name, .. } => Some(type_name),
            _ => None,
        }
    }

    /// Size in bytes, when this build declares it.
    pub fn size(&self) -> Option<u64> {
        match self.resolution {
            TypeUse::Declared { size, .. } => Some(size),
            _ => None,
        }
    }

    /// The size as a reportable field.
    ///
    /// [`Field::NotDeclared`] carries the first candidate name — for a type
    /// spec that is the type's canonical name rather than a member's.
    pub fn size_field(&self) -> Field<u64> {
        match &self.resolution {
            TypeUse::Declared { size, .. } => Field::Known(*size),
            TypeUse::NotDeclared => Field::NotDeclared {
                member: self.candidates[0],
            },
            TypeUse::Unavailable { detail } => Field::Unavailable(detail.clone()),
        }
    }

    /// Serializable form for the layout report.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = json!({
            "key": self.key,
            "candidates": self.candidates,
            "required": self.necessity.is_required(),
        });
        let object = value
            .as_object_mut()
            .expect("to_json builds an object literal");
        match &self.resolution {
            TypeUse::Declared { type_name, size } => {
                object.insert("kind".into(), json!("declared"));
                object.insert("type".into(), json!(type_name));
                object.insert("size".into(), json!(size));
            }
            TypeUse::NotDeclared => {
                object.insert("kind".into(), json!("not_declared"));
            }
            TypeUse::Unavailable { detail } => {
                object.insert("kind".into(), json!("unavailable"));
                object.insert("detail".into(), json!(detail));
            }
        }
        value
    }
}

/// One resolved member declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundMember {
    key: &'static str,
    types: &'static [&'static str],
    candidates: &'static [&'static str],
    necessity: Necessity,
    resolution: MemberUse,
}

impl BoundMember {
    /// The stage's own name for it.
    pub fn key(&self) -> &'static str {
        self.key
    }

    /// Every type name that was tried, in the order they were tried.
    pub fn types(&self) -> &'static [&'static str] {
        self.types
    }

    /// Every member name that was tried, in the order they were tried.
    ///
    /// A report that says a value is absent has to be able to say what was
    /// looked for, or an examiner cannot tell a missing field from a misnamed
    /// one.
    pub fn candidates(&self) -> &'static [&'static str] {
        self.candidates
    }

    /// What was found.
    pub fn resolution(&self) -> &MemberUse {
        &self.resolution
    }

    /// Whether this build declares the member under any candidate name.
    pub fn is_declared(&self) -> bool {
        matches!(self.resolution, MemberUse::Declared { .. })
    }

    /// The type this build declares it on, when it declares it.
    pub fn type_name(&self) -> Option<&'static str> {
        match self.resolution {
            MemberUse::Declared { type_name, .. } => Some(type_name),
            _ => None,
        }
    }

    /// The member path this build declares it under, when it declares it.
    pub fn member(&self) -> Option<&'static str> {
        match self.resolution {
            MemberUse::Declared { member, .. } => Some(member),
            _ => None,
        }
    }

    /// Byte offset within the type, when this build declares the member.
    pub fn offset(&self) -> Option<u64> {
        match self.resolution {
            MemberUse::Declared { offset, .. } => Some(offset),
            _ => None,
        }
    }

    /// The offset as a reportable field, with absence and damage kept apart.
    pub fn offset_field(&self) -> Field<u64> {
        match &self.resolution {
            MemberUse::Declared { offset, .. } => Field::Known(*offset),
            MemberUse::NotDeclared => Field::NotDeclared {
                member: self.candidates[0],
            },
            MemberUse::Unavailable { detail } => Field::Unavailable(detail.clone()),
        }
    }

    /// Serializable form for the layout report.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = json!({
            "key": self.key,
            "candidate_types": self.types,
            "candidates": self.candidates,
            "required": self.necessity.is_required(),
        });
        let object = value
            .as_object_mut()
            .expect("to_json builds an object literal");
        match &self.resolution {
            MemberUse::Declared {
                type_name,
                member,
                offset,
            } => {
                object.insert("kind".into(), json!("declared"));
                object.insert("type".into(), json!(type_name));
                object.insert("member".into(), json!(member));
                object.insert("offset".into(), json!(offset));
            }
            MemberUse::NotDeclared => {
                object.insert("kind".into(), json!("not_declared"));
            }
            MemberUse::Unavailable { detail } => {
                object.insert("kind".into(), json!("unavailable"));
                object.insert("detail".into(), json!(detail));
            }
        }
        value
    }
}

// ── The binding ─────────────────────────────────────────────────────────────

/// What one build's symbol table actually provides for one stage.
///
/// # What an examiner learns
///
/// Which structure layout the analysis used. [`BuildBinding::to_json`] is the
/// record of it: for every member the stage wanted, whether this build had it,
/// which of the accepted names it had it under, and where. That is what makes a
/// blank column readable — "this build has no such field" rather than an empty
/// cell — and it is what a defence expert needs in order to check the analysis
/// against the same symbol pack.
#[derive(Debug, Clone)]
pub struct BuildBinding {
    stage: StageId,
    types: Vec<BoundType>,
    members: Vec<BoundMember>,
}

/// Whether a resolved member can be read from a given object, or already has
/// its answer.
enum ReadTarget {
    /// Read this member path.
    Read(&'static str),
    /// There is nothing to read; this is the answer.
    Answer(Field<u64>),
}

impl BuildBinding {
    /// The stage this binding belongs to.
    pub fn stage(&self) -> StageId {
        self.stage
    }

    /// Every resolved type, in declaration order.
    pub fn types(&self) -> &[BoundType] {
        &self.types
    }

    /// Every resolved member, in declaration order.
    pub fn members(&self) -> &[BoundMember] {
        &self.members
    }

    /// One resolved member, by the stage's own key.
    ///
    /// # Errors
    ///
    /// [`BindError::UndeclaredKey`] for a key the stage never declared. An
    /// unknown key is a programming error and is refused rather than answered
    /// with "not declared", because the two are opposite claims: the first says
    /// the analysis asked the wrong question, the second says the machine had
    /// no answer.
    pub fn member(&self, key: &'static str) -> Result<&BoundMember, BindError> {
        self.members
            .iter()
            .find(|bound| bound.key == key)
            .ok_or(BindError::UndeclaredKey {
                stage: self.stage.key,
                kind: "member",
                key,
            })
    }

    /// One resolved type, by the stage's own key.
    ///
    /// # Errors
    ///
    /// [`BindError::UndeclaredKey`], for the reason [`BuildBinding::member`]
    /// gives.
    pub fn type_of(&self, key: &'static str) -> Result<&BoundType, BindError> {
        self.types
            .iter()
            .find(|bound| bound.key == key)
            .ok_or(BindError::UndeclaredKey {
                stage: self.stage.key,
                kind: "type",
                key,
            })
    }

    /// Read a declared member of `obj` as an unsigned value.
    ///
    /// The whole point of the ergonomics: the three ways there is no value are
    /// produced for the caller, so the shortest correct route is also the
    /// shortest route. A member this build does not declare returns
    /// [`Field::NotDeclared`]; a member whose bytes were not acquired returns
    /// [`Field::Unavailable`]; neither is an error and neither stops the stage.
    ///
    /// # Errors
    ///
    /// [`BindError::UndeclaredKey`] for a key the stage never declared, and
    /// [`BindError::WrongObjectType`] when `obj` is not the type this build
    /// declares the member on — which would otherwise read a real value from
    /// an unrelated offset and report it as fact.
    pub fn read_unsigned(&self, obj: &Obj, key: &'static str) -> Result<Field<u64>, BindError> {
        match self.read_target(obj, key)? {
            ReadTarget::Answer(field) => Ok(field),
            ReadTarget::Read(path) => Ok(match obj.unsigned(path) {
                Ok(value) => Field::Known(value),
                Err(err) => Field::Unavailable(err.to_string()),
            }),
        }
    }

    /// Read a declared member of `obj` as a guest pointer, at the width and
    /// byte order the symbol table declares.
    ///
    /// Outcomes and errors are those of [`BuildBinding::read_unsigned`].
    pub fn read_pointer(&self, obj: &Obj, key: &'static str) -> Result<Field<u64>, BindError> {
        match self.read_target(obj, key)? {
            ReadTarget::Answer(field) => Ok(field),
            ReadTarget::Read(path) => Ok(match obj.pointer(path) {
                Ok(value) => Field::Known(value),
                Err(err) => Field::Unavailable(err.to_string()),
            }),
        }
    }

    /// Resolve a key against an object, refusing an object of the wrong type.
    fn read_target(&self, obj: &Obj, key: &'static str) -> Result<ReadTarget, BindError> {
        let bound = self.member(key)?;
        match &bound.resolution {
            MemberUse::Declared {
                type_name, member, ..
            } => {
                if obj.type_name() != *type_name {
                    return Err(BindError::WrongObjectType {
                        stage: self.stage.key,
                        key,
                        expected: type_name,
                        actual: obj.type_name().to_string(),
                    });
                }
                Ok(ReadTarget::Read(member))
            }
            MemberUse::NotDeclared => Ok(ReadTarget::Answer(Field::NotDeclared {
                member: bound.candidates[0],
            })),
            MemberUse::Unavailable { detail } => {
                Ok(ReadTarget::Answer(Field::Unavailable(detail.clone())))
            }
        }
    }

    /// The layout this build provided, as a stage should record it.
    ///
    /// Emit this alongside the stage's findings. Without it a report says a
    /// column is empty and cannot say whether the kernel had no such field, or
    /// the analysis looked under a name this kernel does not use.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "stage": self.stage.key,
            "types": self.types.iter().map(BoundType::to_json).collect::<Vec<_>>(),
            "members": self.members.iter().map(BoundMember::to_json).collect::<Vec<_>>(),
        })
    }
}

// ── Failures ────────────────────────────────────────────────────────────────

/// A stage could not be bound to this build.
///
/// Every variant is a genuine stop. A build-variant member this kernel does not
/// have is deliberately not in here: it is [`MemberUse::NotDeclared`], and a
/// stage that treated it as a failure is the defect this module exists to
/// remove.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BindError {
    /// A declaration the stage marked required is absent from this build.
    #[error(
        "the {stage} stage requires the {kind} '{key}', and this kernel build declares none of \
         the names it can appear under ({candidates}). Without it, {without_it}"
    )]
    RequiredNotDeclared {
        /// Stage key.
        stage: &'static str,
        /// `"type"` or `"member"`.
        kind: &'static str,
        /// The stage's own name for the thing.
        key: &'static str,
        /// The candidate names, quoted and comma-separated.
        candidates: String,
        /// What the stage cannot do without it.
        without_it: &'static str,
    },

    /// A declaration the stage marked required exists in principle and the
    /// symbol table could not resolve it.
    ///
    /// Distinct from [`BindError::RequiredNotDeclared`]: this says the symbol
    /// table is unusable here, not that the kernel lacks the field.
    #[error(
        "the {stage} stage requires the {kind} '{key}', and the symbol table could not resolve \
         it from {candidates}: {detail}. Without it, {without_it}"
    )]
    RequiredUnresolved {
        /// Stage key.
        stage: &'static str,
        /// `"type"` or `"member"`.
        kind: &'static str,
        /// The stage's own name for the thing.
        key: &'static str,
        /// The candidate names, quoted and comma-separated.
        candidates: String,
        /// Why the table could not answer.
        detail: String,
        /// What the stage cannot do without it.
        without_it: &'static str,
    },

    /// A lookup used a key the stage never declared.
    #[error(
        "the {stage} stage asked its build binding for the {kind} '{key}', which it never \
         declared, so nothing can be said about whether this build has it"
    )]
    UndeclaredKey {
        /// Stage key.
        stage: &'static str,
        /// `"type"` or `"member"`.
        kind: &'static str,
        /// The key that was asked for.
        key: &'static str,
    },

    /// The same key is declared twice, so a lookup by it is ambiguous.
    #[error(
        "the {stage} stage declares the {kind} '{key}' more than once, so a lookup by that key \
         cannot say which declaration was meant"
    )]
    DuplicateKey {
        /// Stage key.
        stage: &'static str,
        /// `"type"` or `"member"`.
        kind: &'static str,
        /// The repeated key.
        key: &'static str,
    },

    /// A declaration lists no candidate names, so there is nothing to resolve
    /// and nothing to name in a report that says it is absent.
    #[error(
        "the {stage} stage declares the {kind} '{key}' with no candidate names, so there is \
         nothing to look for"
    )]
    NoCandidates {
        /// Stage key.
        stage: &'static str,
        /// `"type"` or `"member"`.
        kind: &'static str,
        /// The empty declaration's key.
        key: &'static str,
    },

    /// A member was read from an object of a type this build does not declare
    /// it on.
    ///
    /// Refused rather than read: the offset is real and the bytes at it in an
    /// unrelated structure parse perfectly, so this would produce a confident
    /// wrong value with nothing downstream able to tell.
    #[error(
        "the {stage} stage read the member '{key}' from a '{actual}', and this build declares \
         that member on '{expected}'"
    )]
    WrongObjectType {
        /// Stage key.
        stage: &'static str,
        /// The stage's own name for the member.
        key: &'static str,
        /// The type this build declares the member on.
        expected: &'static str,
        /// The type of the object it was read from.
        actual: String,
    },
}

impl BindError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            BindError::RequiredNotDeclared { .. } => "required_not_declared",
            BindError::RequiredUnresolved { .. } => "required_unresolved",
            BindError::UndeclaredKey { .. } => "undeclared_key",
            BindError::DuplicateKey { .. } => "duplicate_key",
            BindError::NoCandidates { .. } => "no_candidates",
            BindError::WrongObjectType { .. } => "wrong_object_type",
        }
    }

    /// The stage that could not be bound.
    pub fn stage(&self) -> &'static str {
        match self {
            BindError::RequiredNotDeclared { stage, .. }
            | BindError::RequiredUnresolved { stage, .. }
            | BindError::UndeclaredKey { stage, .. }
            | BindError::DuplicateKey { stage, .. }
            | BindError::NoCandidates { stage, .. }
            | BindError::WrongObjectType { stage, .. } => stage,
        }
    }
}
