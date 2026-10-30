//! The build binding: what *this* kernel build declares, and how a stage says
//! what it needs.
//!
//! ## The one idea
//!
//! **A structure member that is absent because this kernel build never had it
//! is `not_declared`. It is not incompleteness, and it is not an error.**
//!
//! Four claims, and an examiner acts on each differently:
//!
//! | Outcome | What it means | What the examiner does |
//! |---|---|---|
//! | [`Field::Known`] | the value was read | reads it |
//! | [`Field::NotDeclared`] | this build has no such member | nothing was missed; move on |
//! | [`Field::Unavailable`] | the member exists, the bytes would not read | the evidence is damaged here |
//! | [`BindError`] | the analysis could not run at all | re-run, or the tool cannot do this |
//!
//! Escalating the second into the fourth tells an examiner the analysis could
//! not run, when it ran fine and one column does not exist on this operating
//! system. Escalating it into *incompleteness* would be as wrong in the other
//! direction: it would say evidence was missed when none was.
//!
//! ## Why it is here rather than in an OS tier
//!
//! Every one of the four pieces below was private to the Windows tier, and
//! every OS tier has the same problem harder. Linux has 231 `has_member`
//! branches across Volatility 3's Linux support. macOS varies across 129 real
//! Kernel Debug Kit packs, and its credential structure needs a fallback in
//! *both* directions. Volatility itself fails from this class on a Debian 3.2
//! sample, where the capability type is named `kernel_cap_t` rather than
//! `kernel_cap_struct`. A tier that re-invents this reproduces the
//! nine-stages-dead outcome on its first non-canonical kernel.
//!
//! ## What is here
//!
//! - [`Field`] — one fact, with *read*, *not applicable*, *not declared on this
//!   build* and *unreadable* kept apart. Its JSON shape is already decoded by
//!   `frontend/src/pages/memory/normalize.ts`, which prints a different
//!   sentence for each; that shape is fixed by the decoder.
//! - [`MemberSet`], [`MemberSpec`], [`TypeSpec`], [`Necessity`] — a stage
//!   declares what it wants; [`MemberSet::bind`] resolves it against this
//!   build and yields [`MemberUse::NotDeclared`] by default rather than an
//!   error. A stage fails only for something it declared
//!   [`Necessity::Required`], and that declaration carries a written statement
//!   of what is lost.
//! - [`BuildBinding`], [`BoundMember`], [`BoundType`] — the resolved answer,
//!   including *which* candidate name this build declared, because a report has
//!   to name the layout that was used.
//! - [`first_member`] / [`first_type`] / [`first_declared_member`] — the
//!   low-level idiom, for the cases a declaration does not fit. The third is for
//!   a stage holding a symbol table rather than a reader.
//! - [`required_size`] / [`required_offset`] — for the value a stage genuinely
//!   cannot proceed without, where failing is right and the only question is
//!   whether the examiner is told which stage stopped and what it cost. See
//!   [`required_size`] for why a `has_type` pre-flight is not that.
//! - [`StageId`] — the identity a finding is filed under, so a binding failure
//!   names the stage that stopped.
//! - [`Evidence`] / [`Found`] — how a discovered fact was established.
//!
//! ## Migrating a stage
//!
//! The form this replaces is the statement-position existence proof, whose only
//! effect is to turn a build-variant member into a fatal error in a branch that
//! never reads it:
//!
//! ```text
//! reader.member_offset(TYPE_OBJECT_HEADER, "InfoMask")?;   // the defect
//! ```
//!
//! **That line no longer compiles.**
//! [`crate::object::StructReader::member_offset`] returns
//! [`crate::object::MemberOffset`] and
//! [`crate::object::StructReader::size_of`] returns
//! [`crate::object::TypeSize`], both `#[must_use]`. The attribute used to sit
//! on the *functions*, where it caught the call written without `?` — the form
//! nobody writes — and missed the one above, because the value of `f()?;` is
//! whatever the `?` unwrapped and a `u64` is not `must_use`. Moving it onto the
//! returned type puts it where the `?` leaves it.
//!
//! This replaced two greps that had to be remembered and run:
//!
//! ```text
//! rg -n 'member_offset\([^)]*\)\?;'
//! rg -n 'size_of\([^)]*\)\?;'
//! ```
//!
//! They are kept here only as a record of what the check used to be. A grep is
//! run by whoever remembers it; the compiler is run by everyone.

pub mod evidence;
pub mod field;
pub mod members;
pub mod stage;

#[cfg(test)]
mod tests;

pub use evidence::{Evidence, Found};
pub use field::Field;
pub use members::{
    first_declared_member, first_member, first_type, required_offset, required_size, BindError,
    BoundMember, BoundType, BuildBinding, MemberSet, MemberSpec, MemberUse, Necessity, TypeSpec,
    TypeUse,
};
pub use stage::{StageId, MEMORY_STAGE_MANIFEST_RECORD};
