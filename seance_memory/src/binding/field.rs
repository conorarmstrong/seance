//! One fact, with the ways it can be missing kept apart.
//!
//! A single `Option` collapses them, and the collapse is what puts an empty
//! cell in a report that an examiner then reads as a zero.
//!
//! This type was private to the Windows tier. It is here because every OS tier
//! has the same four outcomes, and because the wire shape it produces is
//! already decoded by `frontend/src/pages/memory/normalize.ts`, which prints a
//! different sentence for each kind. That decoder is correct; the shape below
//! is fixed by it and must not drift.

use serde_json::json;

/// One attribute of one thing, with the three ways it can be missing kept
/// apart.
///
/// # What an examiner learns
///
/// Which of four different claims is being made:
///
/// | Variant | The claim | What the examiner does |
/// |---|---|---|
/// | [`Field::Known`] | the value was read | reads it |
/// | [`Field::NotApplicable`] | the member exists and this thing has no value for it | nothing was missed |
/// | [`Field::NotDeclared`] | this kernel build has no such member | nothing was missed; the column does not exist here |
/// | [`Field::Unavailable`] | the member exists and the bytes would not read | the evidence is damaged here |
///
/// A wrong answer here is not a corrupted value, it is a false statement about
/// the machine: a session id rendered blank because the build declares no
/// `Session` member reads exactly like a process that had no session, and an
/// examiner will testify to the second when the truth is the first.
///
/// # Wire shape
///
/// [`Field::to_json_with`] emits `{"kind": …}` with the kind-specific siblings
/// `value`, `member` and `detail`. The frontend decoder matches on `kind` and
/// falls through to a `malformed` state for anything it does not recognise, so
/// renaming a kind silently blanks a column rather than failing a build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field<T> {
    /// The value, as the image held it.
    Known(T),
    /// The member exists on this build and the value is genuinely absent: a
    /// process with no PEB because it has no user address space, a count of
    /// something the thing has none of.
    ///
    /// A fact about *this thing*.
    NotApplicable,
    /// This build's structure declares no such member at all, so the question
    /// could not be put.
    ///
    /// A fact about *the build*, and a different one. Merging the two lets a
    /// consumer read "the build has no `Peb` member" as "this process has no
    /// user address space", and skip every process on such an image while
    /// reporting a scan that found nothing. The distinction is in the type so
    /// no consumer has to remember to consult the symbol table to recover it.
    NotDeclared {
        /// The member that this build does not have, for a report to name.
        ///
        /// When the reader accepted several spellings, this is the first
        /// candidate — the canonical name for the thing that is missing. Which
        /// spellings were tried is recorded by the binding that resolved them,
        /// [`crate::binding::BoundMember::candidates`].
        member: &'static str,
    },
    /// The value exists and could not be read. The string says why.
    Unavailable(String),
}

impl<T> Field<T> {
    /// The value, when it was read.
    pub fn known(&self) -> Option<&T> {
        match self {
            Field::Known(value) => Some(value),
            _ => None,
        }
    }

    /// Whether the value was read.
    pub fn is_known(&self) -> bool {
        matches!(self, Field::Known(_))
    }

    /// Whether the value exists but could not be read — the state a report must
    /// declare rather than render as blank.
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Field::Unavailable(_))
    }

    /// Whether this build's structure declares the member at all.
    ///
    /// Distinct from [`Field::is_unavailable`]: the member being absent from
    /// the build means the question was never put, where unavailable means it
    /// was put and the bytes would not come back. A stage that cannot run
    /// without the member reports it as unevaluated rather than as clean.
    pub fn is_not_declared(&self) -> bool {
        matches!(self, Field::NotDeclared { .. })
    }

    /// The member this build does not declare, when that is why there is no
    /// value.
    pub fn undeclared_member(&self) -> Option<&'static str> {
        match self {
            Field::NotDeclared { member } => Some(member),
            _ => None,
        }
    }

    /// Stable identifier for artifact metadata.
    pub fn kind(&self) -> &'static str {
        match self {
            Field::Known(_) => "known",
            Field::NotApplicable => "not_applicable",
            Field::NotDeclared { .. } => "not_declared",
            Field::Unavailable(_) => "unavailable",
        }
    }

    /// Serializable form, given a renderer for the value.
    pub fn to_json_with(&self, render: impl FnOnce(&T) -> serde_json::Value) -> serde_json::Value {
        match self {
            Field::Known(value) => json!({"kind": "known", "value": render(value)}),
            Field::NotApplicable => json!({"kind": "not_applicable"}),
            Field::NotDeclared { member } => {
                json!({"kind": "not_declared", "member": member})
            }
            Field::Unavailable(detail) => {
                json!({"kind": "unavailable", "detail": detail})
            }
        }
    }
}

impl Field<u64> {
    /// Serializable form for a numeric field.
    ///
    /// For counts, offsets, sizes and identifiers. A field holding an
    /// **address** must use [`Field::to_json_address`] instead: a process id
    /// fits in a double and a kernel pointer does not.
    pub fn to_json(&self) -> serde_json::Value {
        self.to_json_with(|value| json!(value))
    }

    /// Serializable form for a field holding an address.
    ///
    /// The known value carries a `value_hex` sibling beside `value`, because
    /// the numeric form of a pointer above 2^53 arrives at a JSON consumer
    /// rounded, and a PEB address quoted from it is the wrong address. The
    /// `kind` discrimination is untouched, so a consumer still tells "no user
    /// address space" from "the pointer could not be read".
    pub fn to_json_address(&self) -> serde_json::Value {
        match self {
            Field::Known(value) => json!({
                "kind": "known",
                "value": value,
                "value_hex": format!("{value:#x}"),
            }),
            other => other.to_json_with(|value| json!(value)),
        }
    }
}

impl Field<bool> {
    /// Serializable form for a flag.
    pub fn to_json(&self) -> serde_json::Value {
        self.to_json_with(|value| json!(value))
    }
}

impl Field<String> {
    /// Serializable form for a text field.
    pub fn to_json(&self) -> serde_json::Value {
        self.to_json_with(|value| json!(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four kinds are four different sentences on the wire, and the
    /// frontend decoder switches on exactly this string. A rename here blanks a
    /// column instead of failing a build, so the strings are asserted.
    #[test]
    fn every_kind_has_the_wire_name_the_frontend_decodes() {
        assert_eq!(Field::Known(4u64).kind(), "known");
        assert_eq!(Field::<u64>::NotApplicable.kind(), "not_applicable");
        assert_eq!(
            Field::<u64>::NotDeclared { member: "InfoMask" }.kind(),
            "not_declared"
        );
        assert_eq!(
            Field::<u64>::Unavailable("a hole".into()).kind(),
            "unavailable"
        );
    }

    #[test]
    fn a_not_declared_field_names_the_member_the_build_lacks() {
        let field: Field<u64> = Field::NotDeclared { member: "InfoMask" };
        let json = field.to_json();
        assert_eq!(json["kind"], "not_declared");
        assert_eq!(json["member"], "InfoMask");
        assert!(
            json.get("value").is_none(),
            "there was never a value: {json}"
        );
        assert_eq!(field.undeclared_member(), Some("InfoMask"));
        assert!(!field.is_unavailable(), "an absent member is not damage");
    }

    /// The distinction the whole type exists for: a build with no such member
    /// and an unreadable member must not serialise the same.
    #[test]
    fn not_declared_and_unavailable_do_not_render_alike() {
        let absent: Field<u64> = Field::NotDeclared { member: "Session" };
        let damaged: Field<u64> = Field::Unavailable("page not acquired".into());
        assert_ne!(absent.to_json(), damaged.to_json());
        assert_eq!(damaged.to_json()["detail"], "page not acquired");
    }

    #[test]
    fn an_address_field_carries_a_hex_sibling_so_it_survives_a_double() {
        let field = Field::Known(0xFFFF_8E01_2345_6789u64);
        let json = field.to_json_address();
        assert_eq!(json["value_hex"], "0xffff8e0123456789");
        assert_eq!(json["kind"], "known");
    }
}
