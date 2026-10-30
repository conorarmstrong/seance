//! Reading a declared member, with the ways there is no value kept apart.
//!
//! [`seance_memory::binding::BuildBinding`] already produces
//! [`Field::NotDeclared`] and [`Field::Unavailable`] for integers and pointers.
//! Linux structures also carry fixed-length character arrays — `task_struct.comm`
//! and `module.name` are both one — and C strings reached through a pointer, and
//! those need the same four outcomes. This module supplies them, so that no
//! stage in this crate has to reach past the binding and re-derive "this build
//! does not have that member" for itself.
//!
//! The rule every helper here obeys: **a member this build does not declare is
//! an answer, and a member whose bytes were not acquired is damage, and the two
//! never render the same.** A `comm` rendered blank because the build has no
//! such member reads exactly like a process with no name, and an examiner will
//! testify to the second when the truth is the first.

use seance_memory::binding::{BindError, BuildBinding, Field, MemberUse};
use seance_memory::layer::MemoryLayer;
use seance_memory::object::{Obj, ObjError};

/// Longest C string any helper here will follow.
///
/// The length is not declared anywhere in the evidence — a C string ends when it
/// ends — so the bound is ours to state. A kernel module's argument string and a
/// shell history line are both well inside it, and a "string" that runs longer
/// than this is not one.
pub const MAX_C_STRING: usize = 4096;

/// What reading a declared member of an object resolves to.
enum Reading {
    /// Read this member path from the object.
    Read(&'static str),
    /// There is nothing to read; this is the answer.
    Answer(&'static str),
    /// The symbol table could not answer, and said why.
    Damaged(String),
}

/// Resolve a stage's key against an object, refusing an object of the wrong
/// type.
///
/// The refusal matters: the offset this build declares for `module.name` is a
/// real number, and the bytes at that offset inside a `task_struct` parse
/// perfectly into a plausible wrong answer that nothing downstream could catch.
fn reading(binding: &BuildBinding, obj: &Obj, key: &'static str) -> Result<Reading, BindError> {
    let bound = binding.member(key)?;
    match bound.resolution() {
        MemberUse::Declared {
            type_name, member, ..
        } => {
            if obj.type_name() != *type_name {
                return Err(BindError::WrongObjectType {
                    stage: binding.stage().key,
                    key,
                    expected: type_name,
                    actual: obj.type_name().to_string(),
                });
            }
            Ok(Reading::Read(member))
        }
        MemberUse::NotDeclared => Ok(Reading::Answer(bound.candidates()[0])),
        MemberUse::Unavailable { detail } => Ok(Reading::Damaged(detail.clone())),
    }
}

/// Read a declared member as a signed integer.
///
/// Linux keeps `pid`, `tgid` and `exit_state` as `int`, and a four-byte signed
/// field holding `0xFFFFFFFF` is `-1` and not `4294967295`.
///
/// # Errors
///
/// [`BindError::UndeclaredKey`] for a key the stage never declared, and
/// [`BindError::WrongObjectType`] when `obj` is not the type this build declares
/// the member on. A member this build does not have is **not** an error.
pub fn read_signed(
    binding: &BuildBinding,
    obj: &Obj,
    key: &'static str,
) -> Result<Field<i64>, BindError> {
    Ok(match reading(binding, obj, key)? {
        Reading::Read(path) => match obj.signed(path) {
            Ok(value) => Field::Known(value),
            Err(err) => Field::Unavailable(err.to_string()),
        },
        Reading::Answer(member) => Field::NotDeclared { member },
        Reading::Damaged(detail) => Field::Unavailable(detail),
    })
}

/// Read a declared member as an integer of whatever signedness this build
/// declares for it, widened to `i64`.
///
/// For fields whose signedness varies by build: Linux 3.2 declares `cred.uid` as
/// a bare `unsigned int`, and from 3.5 the same idea is a `kuid_t` wrapping a
/// `uid_t`. Asking for one and getting the other is a build difference, not a
/// wrong answer, so this reads either.
pub fn read_integer(
    binding: &BuildBinding,
    obj: &Obj,
    key: &'static str,
) -> Result<Field<i64>, BindError> {
    Ok(match reading(binding, obj, key)? {
        Reading::Read(path) => match obj.int(path) {
            Ok(value) => match value.as_i64() {
                Some(value) => Field::Known(value),
                None => Field::Unavailable(format!(
                    "'{path}' holds {value}, which does not fit in a signed 64-bit value"
                )),
            },
            Err(err) => Field::Unavailable(err.to_string()),
        },
        Reading::Answer(member) => Field::NotDeclared { member },
        Reading::Damaged(detail) => Field::Unavailable(detail),
    })
}

/// Read a declared `kernel_cap_t` member as an 8-byte little-endian capability
/// mask.
///
/// A `kernel_cap_t` is a struct, not a scalar, so [`read_integer`] cannot read
/// it — this reads the raw member bytes at its declared offset instead. Both the
/// historical `struct { __u32 cap[2] }` and the modern `struct { u64 val }` are
/// 8 bytes at the same offset and read identically as one little-endian `u64`,
/// so no per-build type distinction is needed for the value (only the offset,
/// which the symbols supply). A member this build lacks (e.g. `cap_ambient`
/// before Linux 4.3) is [`Field::NotDeclared`], not damage.
pub fn read_cap_mask(
    binding: &BuildBinding,
    obj: &Obj,
    key: &'static str,
) -> Result<Field<u64>, BindError> {
    Ok(match reading(binding, obj, key)? {
        Reading::Read(path) => match obj.member_address(path) {
            Ok(addr) => match obj.reader().read_bytes(addr, 8) {
                Ok(bytes) if bytes.len() == 8 => {
                    Field::Known(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
                }
                Ok(_) => Field::Unavailable(format!("'{path}' capability mask was a short read")),
                Err(err) => Field::Unavailable(err.to_string()),
            },
            Err(err) => Field::Unavailable(err.to_string()),
        },
        Reading::Answer(member) => Field::NotDeclared { member },
        Reading::Damaged(detail) => Field::Unavailable(detail),
    })
}

/// Read a declared fixed-length character array as a string, truncated at its
/// first NUL.
///
/// Returns the string and whether every byte before the NUL was valid UTF-8. A
/// `false` there means bytes were replaced to render it and the name in the
/// image differed — which is worth an examiner's attention, because a process
/// name is one of the few fields an attacker chooses.
pub fn read_char_array(
    binding: &BuildBinding,
    obj: &Obj,
    key: &'static str,
) -> Result<(Field<String>, bool), BindError> {
    Ok(match reading(binding, obj, key)? {
        Reading::Read(path) => match obj.bytes(path) {
            Ok(bytes) => {
                let (text, well_formed) = decode_nul_terminated(&bytes);
                (Field::Known(text), well_formed)
            }
            Err(err) => (Field::Unavailable(err.to_string()), true),
        },
        Reading::Answer(member) => (Field::NotDeclared { member }, true),
        Reading::Damaged(detail) => (Field::Unavailable(detail), true),
    })
}

/// Read a declared pointer member and follow it to a C string.
///
/// A null pointer is [`Field::NotApplicable`]: the member exists and this
/// structure genuinely has no string for it, which is a different claim from
/// "the build has no such member" and from "the bytes would not read".
pub fn read_c_string_member(
    binding: &BuildBinding,
    obj: &Obj,
    key: &'static str,
    max: usize,
) -> Result<Field<String>, BindError> {
    Ok(match reading(binding, obj, key)? {
        Reading::Read(path) => match obj.pointer(path) {
            Ok(0) => Field::NotApplicable,
            Ok(address) => match read_c_string(&**obj.reader().native_layer(), address, max) {
                Ok((text, _)) => Field::Known(text),
                Err(err) => Field::Unavailable(err.to_string()),
            },
            Err(err) => Field::Unavailable(err.to_string()),
        },
        Reading::Answer(member) => Field::NotDeclared { member },
        Reading::Damaged(detail) => Field::Unavailable(detail),
    })
}

/// Decode bytes up to their first NUL, replacing anything that is not UTF-8.
///
/// Returns the text and whether the bytes were valid UTF-8 throughout. The flag
/// is the point: silently substituting replacement characters would put a name
/// in a report that was never in the image.
pub fn decode_nul_terminated(bytes: &[u8]) -> (String, bool) {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let slice = &bytes[..end];
    match std::str::from_utf8(slice) {
        Ok(text) => (text.to_string(), true),
        Err(_) => (String::from_utf8_lossy(slice).into_owned(), false),
    }
}

/// Read a NUL-terminated string from a layer, up to `max` bytes.
///
/// Returns the text and whether the bytes were valid UTF-8. Reads in page-sized
/// steps so a string that runs into an unacquired page yields an error naming
/// that page rather than a string with fabricated bytes on the end.
///
/// # Errors
///
/// The layer's own error, unchanged. In particular a read into an unacquired
/// region carries the hole, so a caller can say which bytes were never captured.
pub fn read_c_string(
    layer: &dyn MemoryLayer,
    address: u64,
    max: usize,
) -> Result<(String, bool), std::io::Error> {
    let max = max.min(MAX_C_STRING);
    let mut out: Vec<u8> = Vec::new();
    let mut at = address;
    while out.len() < max {
        // Stop at the next page boundary, so an unacquired page fails at the
        // page and not somewhere inside a buffer that spans two.
        let to_page_end = 0x1000 - (at & 0xFFF);
        let want = to_page_end.min((max - out.len()) as u64) as usize;
        let mut buf = vec![0u8; want];
        seance_core::io::read_exact_or_fail(
            layer.as_data_source(),
            at,
            &mut buf,
            "a NUL-terminated string",
        )?;
        if let Some(end) = buf.iter().position(|&b| b == 0) {
            out.extend_from_slice(&buf[..end]);
            let (text, well_formed) = decode_bytes(&out);
            return Ok((text, well_formed));
        }
        out.extend_from_slice(&buf);
        let Some(next) = at.checked_add(want as u64) else {
            break;
        };
        at = next;
    }
    // No terminator inside the bound. The bytes read are returned, because they
    // are real evidence, and the caller decides what an unterminated string
    // means; nothing is invented to close it.
    let (text, well_formed) = decode_bytes(&out);
    Ok((text, well_formed))
}

/// Decode bytes that hold no NUL, replacing anything that is not UTF-8.
fn decode_bytes(bytes: &[u8]) -> (String, bool) {
    match std::str::from_utf8(bytes) {
        Ok(text) => (text.to_string(), true),
        Err(_) => (String::from_utf8_lossy(bytes).into_owned(), false),
    }
}

/// A field's JSON form for a signed value.
///
/// [`Field`] ships `to_json` for `u64`, `bool` and `String`; a Linux `pid` is a
/// signed `int`, so this supplies the same shape for `i64` through the generic
/// renderer rather than casting a negative value into a large positive one.
pub fn signed_to_json(field: &Field<i64>) -> serde_json::Value {
    field.to_json_with(|value| serde_json::json!(value))
}

/// How a stage should record a structure it could not read at all.
///
/// The distinction a row must carry: a structure the acquisition never captured
/// is damage to the evidence, and one whose bytes are there but do not parse is
/// a disagreement between the symbol table and the image. They send an examiner
/// to different places.
pub fn unreadable_detail(what: &str, address: u64, err: &ObjError) -> String {
    match err.hole() {
        Some(hole) => {
            format!("{what} at {address:#x} lies in memory the acquisition did not capture: {hole}")
        }
        None => format!("{what} at {address:#x} could not be read: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_stops_at_its_nul_and_reports_whether_it_was_text() {
        let (text, ok) = decode_nul_terminated(b"swapper/0\0\0\0\0\0\0\0");
        assert_eq!(text, "swapper/0");
        assert!(ok);

        // Replacement characters must be flagged: a process name is one of the
        // few fields an attacker chooses, and a report that silently repaired
        // one would quote a name that was never in the image.
        let (text, ok) = decode_nul_terminated(&[0x62, 0x61, 0xFF, 0x00]);
        assert!(!ok, "the bytes were not UTF-8 and the caller must be told");
        assert!(text.starts_with("ba"));

        let (text, ok) = decode_nul_terminated(b"");
        assert_eq!(text, "");
        assert!(ok);
    }

    #[test]
    fn a_signed_field_serialises_as_a_signed_number() {
        let known = signed_to_json(&Field::Known(-1i64));
        assert_eq!(known["kind"], "known");
        assert_eq!(known["value"], -1);

        let absent: Field<i64> = Field::NotDeclared { member: "tgid" };
        let json = signed_to_json(&absent);
        assert_eq!(json["kind"], "not_declared");
        assert_eq!(json["member"], "tgid");
        assert!(
            json.get("value").is_none(),
            "there was never a value: {json}"
        );
    }
}
