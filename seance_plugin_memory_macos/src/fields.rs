//! Reading one column of one structure, with the four answers kept apart.
//!
//! Every stage in this crate reads structure members the same way, so it is done
//! in one place. The four outcomes are the ones
//! [`seance_memory::binding::Field`] exists to distinguish:
//!
//! | Outcome | What it means |
//! |---|---|
//! | [`Field::Known`] | the value was read |
//! | [`Field::NotDeclared`] | this kernel build has no such member; nothing was missed |
//! | [`Field::Unavailable`] | the member exists and the bytes would not read |
//! | [`Field::NotApplicable`] | the member exists and the thing genuinely has no value |
//!
//! Collapsing any two of them is how a report comes to say a process had no
//! start time when in truth the page holding it was never acquired.
//!
//! **Unvalidated.** See [`crate::unvalidated`].

use seance_memory::binding::{BuildBinding, Field};
use seance_memory::object::Obj;

/// How a declared member resolved on this build.
pub(crate) enum Resolved {
    /// The member path to read.
    Path(&'static str),
    /// This build declares none of the candidate names.
    NotDeclared(&'static str),
    /// The declaration itself could not be looked up — a key the stage never
    /// declared, which is a defect in the stage rather than a fact about the
    /// kernel, and is reported as such rather than as an absent member.
    Unavailable(String),
}

/// Look one declaration up.
pub(crate) fn resolve(binding: &BuildBinding, key: &'static str) -> Resolved {
    match binding.member(key) {
        Err(err) => Resolved::Unavailable(err.to_string()),
        Ok(bound) => match bound.member() {
            Some(path) => Resolved::Path(path),
            None => Resolved::NotDeclared(bound.candidates().first().copied().unwrap_or(key)),
        },
    }
}

/// The member path for a declaration a walk cannot proceed without.
///
/// [`MemberSet::bind`] has already refused a [`Necessity::Required`] member this
/// build does not declare, so reaching the failure arms here means the stage
/// asked for a key it never declared, or the binding could not be consulted.
/// Both are stated rather than collapsed into "not found": a stage that names a
/// key it never declared is a defect in the stage, and reporting it as a missing
/// kernel member would send an examiner looking at the evidence for a fault in
/// the tool.
///
/// [`MemberSet::bind`]: seance_memory::binding::MemberSet::bind
/// [`Necessity::Required`]: seance_memory::binding::Necessity::Required
pub(crate) fn required_path(
    binding: &BuildBinding,
    key: &'static str,
    without_it: &str,
) -> Result<&'static str, String> {
    match resolve(binding, key) {
        Resolved::Path(path) => Ok(path),
        Resolved::NotDeclared(member) => Err(format!(
            "this kernel build declares no '{member}', so {without_it}"
        )),
        Resolved::Unavailable(detail) => Err(format!(
            "the '{key}' declaration could not be resolved against this build, so {without_it} \
             ({detail})"
        )),
    }
}

/// Read an integer column at whatever width and signedness this build declares.
///
/// Deliberately not [`BuildBinding::read_unsigned`]: `proc.p_pid` and
/// `proc.p_start.tv_sec` are **signed** on every symbol pack in this repository,
/// and asking for them as unsigned is an error naming the field rather than a
/// value. Reading through [`Obj::int`] takes the signedness from the symbol
/// table, which is the only place that knows it — a four-byte signed field
/// holding `0xFFFFFFFF` is `-1`, and reporting `4294967295` puts a number in the
/// case record that the machine never held.
pub(crate) fn int_field(binding: &BuildBinding, object: &Obj, key: &'static str) -> Field<i64> {
    match resolve(binding, key) {
        Resolved::NotDeclared(member) => Field::NotDeclared { member },
        Resolved::Unavailable(detail) => Field::Unavailable(detail),
        Resolved::Path(path) => match object.int(path) {
            Ok(value) => {
                let wide = value.as_i128();
                match i64::try_from(wide) {
                    Ok(number) => Field::Known(number),
                    Err(_) => Field::Unavailable(format!(
                        "'{path}' holds {wide}, which does not fit a 64-bit signed integer, and \
                         truncating it would put a different number in the record"
                    )),
                }
            }
            Err(err) => Field::Unavailable(err.to_string()),
        },
    }
}

/// Read an integer column that the build declares **unsigned**, keeping the
/// full 64-bit range.
///
/// Needed because `kmod_info.address` is a `long unsigned int` holding a kernel
/// pointer such as `0xffffff7f80000000`, which is above `i64::MAX`.
/// [`int_field`] would refuse it as "does not fit a 64-bit signed integer" — a
/// correct refusal for a signed column and a wrong answer for this one, turning
/// every kext's load address into "unavailable".
///
/// A negative signed value is refused rather than cast: reinterpreting `-1` as
/// `18446744073709551615` is exactly the plausible nonsense this crate exists to
/// avoid.
pub(crate) fn unsigned_field(
    binding: &BuildBinding,
    object: &Obj,
    key: &'static str,
) -> Field<u64> {
    match resolve(binding, key) {
        Resolved::NotDeclared(member) => Field::NotDeclared { member },
        Resolved::Unavailable(detail) => Field::Unavailable(detail),
        Resolved::Path(path) => match object.int(path) {
            Ok(value) => match value.as_u64() {
                Some(number) => Field::Known(number),
                None => Field::Unavailable(format!(
                    "'{path}' holds {value}, which is negative, and reinterpreting it as an \
                     unsigned value would put a number in the record the machine never held"
                )),
            },
            Err(err) => Field::Unavailable(err.to_string()),
        },
    }
}

/// Read a pointer column.
///
/// Null is a value, not a failure: a task with a null `bsd_info` is the kernel
/// task, which is a finding rather than a read error.
pub(crate) fn pointer_field(binding: &BuildBinding, object: &Obj, key: &'static str) -> Field<u64> {
    match resolve(binding, key) {
        Resolved::NotDeclared(member) => Field::NotDeclared { member },
        Resolved::Unavailable(detail) => Field::Unavailable(detail),
        Resolved::Path(path) => match object.pointer(path) {
            Ok(value) => Field::Known(value),
            Err(err) => Field::Unavailable(err.to_string()),
        },
    }
}

/// Read a NUL-terminated character array column.
///
/// Bytes that are not valid UTF-8 are **not** transliterated. A lossy conversion
/// puts U+FFFD into a process or kext name that then goes into a report, and a
/// name with a fabricated character in it is a different name. The bytes are
/// reported in hex inside the unavailability instead, so nothing that was read
/// is lost and nothing that was not read is invented.
pub(crate) fn text_field(binding: &BuildBinding, object: &Obj, key: &'static str) -> Field<String> {
    match resolve(binding, key) {
        Resolved::NotDeclared(member) => Field::NotDeclared { member },
        Resolved::Unavailable(detail) => Field::Unavailable(detail),
        Resolved::Path(path) => match object.bytes(path) {
            Ok(bytes) => {
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                let trimmed = &bytes[..end];
                match std::str::from_utf8(trimmed) {
                    Ok(text) => Field::Known(text.to_string()),
                    Err(_) => Field::Unavailable(format!(
                        "'{path}' holds bytes that are not valid UTF-8 and are reported here \
                         rather than transliterated: {}",
                        hex(trimmed)
                    )),
                }
            }
            Err(err) => Field::Unavailable(err.to_string()),
        },
    }
}

/// Lowercase hex, for reporting bytes that cannot be rendered as text.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` cannot fail; the result is discarded rather
        // than unwrapped so a formatting change cannot introduce a panic.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_render_as_lowercase_hex() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(hex(&[]), "");
    }
}
