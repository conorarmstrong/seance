//! The access token a process ran under.
//!
//! Every thing a Windows process is *allowed* to do is decided by one
//! structure: the `_TOKEN` hanging off `_EPROCESS.Token`. It carries the user
//! and group SIDs the process runs as, and the privilege bitmaps that say
//! whether it could debug other processes, load a driver, or take ownership of
//! any file on the machine. Two separate stages read it — [`privileges`] and
//! [`sid`] — and both start here, so finding it is factored out rather than
//! written twice with two different ideas about what a reference count is.
//!
//! [`privileges`]: crate::handles::privileges
//! [`sid`]: crate::handles::sid
//!
//! # `Token` is not a pointer
//!
//! `_EPROCESS.Token` is an `_EX_FAST_REF`: the kernel packs a small reference
//! count into the bits below the pointer's natural alignment — three bits on
//! x86, four on x64 — and the address is what is left once they are masked off.
//! An unmasked value is up to fifteen bytes past the real structure, and a
//! `_TOKEN` read there is not empty: it is a full structure whose every member
//! is shifted, so the privilege bitmaps come out of the wrong words and the SID
//! array pointer points into the middle of something else. The result is a
//! plausible, complete, wrong list of what the suspect's process was allowed to
//! do.
//!
//! The mask is derived from the pointer width the symbol table declares, never
//! from the host Séance is running on and never written down as 7 or 15.
//!
//! # A process without a token
//!
//! A token pointer of zero is a fact, not a failure: a process that has exited
//! has had its token dereferenced away, and the System idle process never had
//! one. [`ProcessToken::None`] says so, and it does not render the same as
//! [`ProcessToken::Unavailable`], which means the process *has* a token and the
//! bytes describing it were not captured. A report that showed both as an empty
//! privilege list would be claiming the suspect's process held no privileges.

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::binding::BindError;
use seance_memory::object::{ObjError, StructReader};
use seance_memory::Incomplete;
use seance_symbols::SymbolError;

use crate::profile::WindowsProfile;

/// The process structure the token hangs off.
pub const TYPE_EPROCESS: &str = "_EPROCESS";

/// The access token itself.
pub const TYPE_TOKEN: &str = "_TOKEN";

/// The union that packs a reference count into a pointer's low bits.
pub const TYPE_EX_FAST_REF: &str = "_EX_FAST_REF";

// ── Errors ──────────────────────────────────────────────────────────────────

/// Everything that stops a token from being read at all.
///
/// Note what is *not* here: a process that has no token. That is an answer, and
/// it is [`ProcessToken::None`].
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// This build's token cannot be read with what is available, and no partial
    /// answer would be honest. The message names what is missing.
    #[error("a process's access token cannot be read on this build: {detail}")]
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },

    /// A typed read failed for a reason that invalidates the whole stage rather
    /// than one field.
    #[error(transparent)]
    Object(#[from] ObjError),

    /// The symbol table could not answer a question the stage depends on.
    #[error(transparent)]
    Symbols(#[from] SymbolError),

    /// A layout the stage cannot proceed without could not be bound to this
    /// build.
    ///
    /// `#[error(transparent)]` here is deliberate, and it is not the
    /// transparency that made the original defect undiagnosable: a
    /// [`BindError`] states the stage that stopped, every name that was tried
    /// and what stopping cost, where a bare [`SymbolError`] states only that
    /// some type was unknown.
    #[error(transparent)]
    Bind(#[from] BindError),
}

impl TokenError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            TokenError::Unsupported { .. } => "unsupported_build",
            TokenError::Object(err) => err.class(),
            TokenError::Symbols(_) => "symbols",
            TokenError::Bind(err) => err.class(),
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            TokenError::Object(err) => err.incomplete_reason(),
            _ => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this build cannot be read" refusal.
    pub fn unsupported(detail: impl Into<String>) -> TokenError {
        TokenError::Unsupported {
            detail: detail.into(),
        }
    }
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// Resolve the first of `candidates` that this build's `type_name` actually has.
///
/// Defined once, in [`seance_memory::binding::first_member`], and re-exported
/// here because this module and its siblings were where the Windows tier's copy
/// lived. The shared one has three outcomes rather than two: the version that
/// used to be written here returned a bare `Option` built from
/// `member_offset(..).is_ok()`, which collapsed "the symbol table could not
/// answer" into "this build has no such member". Those are opposite claims —
/// the second is a statement about the suspect's machine — so the shared helper
/// returns `Err` for the first and `Ok(None)` for the second.
pub(crate) use seance_memory::binding::first_member;

/// How this build's `_EPROCESS` names its token, and how to unpack it.
#[derive(Debug, Clone)]
pub struct TokenSymbols {
    /// Path to the member holding the token pointer, which is a member *inside*
    /// the `_EX_FAST_REF` on every build that has one.
    pub token_path: String,
    /// Whether the low bits of that value are a reference count rather than
    /// part of the address.
    pub is_fast_ref: bool,
    /// Mask covering the reference-count bits: `2 × pointer_size − 1`, which is
    /// 7 on x86 and 15 on x64.
    pub fast_ref_mask: u64,
    /// Pointer width in bytes, as the symbol table declares it.
    pub pointer_size: u64,
}

impl TokenSymbols {
    /// Resolve how a token is reached on this build.
    ///
    /// # Errors
    ///
    /// [`TokenError::Unsupported`] when the symbol table has no `_TOKEN`, no
    /// `_EPROCESS`, or no member of `_EPROCESS` that could hold a token. Each
    /// message names what was looked for, because "this build stores tokens
    /// somewhere we do not know about" and "this process had no privileges" are
    /// opposite statements.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, TokenError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );

        if !profile.symbols.has_type(TYPE_EPROCESS) {
            return Err(TokenError::unsupported(format!(
                "the symbol table has no '{TYPE_EPROCESS}', so there is no process structure to \
                 take a token from"
            )));
        }
        if !profile.symbols.has_type(TYPE_TOKEN) {
            return Err(TokenError::unsupported(format!(
                "the symbol table has no '{TYPE_TOKEN}', so a process's privileges and SIDs cannot \
                 be read"
            )));
        }

        let pointer_size = u64::from(reader.pointer_size()?);
        if pointer_size != profile.pointer_size() {
            return Err(TokenError::unsupported(format!(
                "the symbol table declares {pointer_size}-byte pointers and the image profile \
                 records {}-byte pointers, so one of the two does not describe this image",
                profile.pointer_size()
            )));
        }

        // `Token.Object` and `Token.Value` are the two spellings of the address
        // inside an `_EX_FAST_REF`. A bare `Token` is the pre-`_EX_FAST_REF`
        // shape, where the value is already an address and masking it would
        // move it.
        let fast_ref = first_member(&reader, TYPE_EPROCESS, &["Token.Object", "Token.Value"])?;
        let (token_path, is_fast_ref) = match fast_ref {
            Some(path) => (path.to_string(), true),
            None => match first_member(&reader, TYPE_EPROCESS, &["Token"])? {
                Some(path) => (path.to_string(), false),
                None => {
                    return Err(TokenError::unsupported(format!(
                        "'{TYPE_EPROCESS}' has no Token member on this build, so the token a \
                         process ran under cannot be located"
                    )))
                }
            },
        };

        Ok(Self {
            token_path,
            is_fast_ref,
            // Three bits on x86 and four on x64: the count occupies the bits
            // below the pointer's alignment, so the mask is `2 × width − 1`.
            fast_ref_mask: if is_fast_ref {
                pointer_size.saturating_mul(2).saturating_sub(1)
            } else {
                0
            },
            pointer_size,
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "token_path": self.token_path,
            "is_fast_ref": self.is_fast_ref,
            "fast_ref_mask": self.fast_ref_mask,
            "pointer_size": self.pointer_size,
        })
    }
}

// ── Result ──────────────────────────────────────────────────────────────────

/// Where a process's token is, or why there is not one to read.
///
/// Three states and not two. Collapsing [`ProcessToken::None`] and
/// [`ProcessToken::Unavailable`] into a single "no token" is what puts an empty
/// privilege table in a report that an examiner reads as "this process held no
/// privileges", when what actually happened is that the page holding its token
/// was never captured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessToken {
    /// The token's address, with the reference count stripped off.
    At {
        /// The `_TOKEN`'s address in the kernel address space.
        address: u64,
        /// The reference count that was packed into the low bits, when this
        /// build packs one. Kept because it is evidence the value really was an
        /// `_EX_FAST_REF` rather than a coincidence.
        reference_count: Option<u64>,
    },
    /// The process genuinely has no token: it has exited, or it never had one.
    None,
    /// The process has a token and it could not be read. The string says why.
    Unavailable(String),
}

impl ProcessToken {
    /// The address, when there is one.
    pub fn address(&self) -> Option<u64> {
        match self {
            ProcessToken::At { address, .. } => Some(*address),
            _ => None,
        }
    }

    /// Whether the token was located.
    pub fn is_known(&self) -> bool {
        matches!(self, ProcessToken::At { .. })
    }

    /// Whether the token exists and could not be read — the state a report must
    /// declare rather than render as an empty list.
    pub fn is_unavailable(&self) -> bool {
        matches!(self, ProcessToken::Unavailable(_))
    }

    /// Stable identifier for artifact metadata.
    pub fn kind(&self) -> &'static str {
        match self {
            ProcessToken::At { .. } => "at",
            ProcessToken::None => "none",
            ProcessToken::Unavailable(_) => "unavailable",
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            ProcessToken::At {
                address,
                reference_count,
            } => serde_json::json!({
                "kind": "at",
                "address": address,
                "reference_count": reference_count,
            }),
            ProcessToken::None => serde_json::json!({"kind": "none"}),
            ProcessToken::Unavailable(detail) => {
                serde_json::json!({"kind": "unavailable", "detail": detail})
            }
        }
    }
}

/// Find the token of one process.
///
/// `process` is the address of an `_EPROCESS` in the **kernel** address space.
///
/// # Errors
///
/// [`TokenError::Object`] only when the `_EPROCESS` itself could not be
/// constructed, which means the type is wrong rather than the process. Every
/// other failure is a [`ProcessToken`] variant, because a process whose token
/// could not be read is a row in the report, not the end of the analysis.
pub fn token_for(
    reader: &StructReader,
    symbols: &TokenSymbols,
    process: u64,
) -> Result<ProcessToken, TokenError> {
    let eprocess = reader.object(process, TYPE_EPROCESS)?;
    let raw = match eprocess.int(&symbols.token_path) {
        Ok(value) => match value.as_u64() {
            Some(value) => value,
            None => {
                return Ok(ProcessToken::Unavailable(format!(
                    "'{}' holds a negative value, which is not an address",
                    symbols.token_path
                )))
            }
        },
        Err(err) => {
            return Ok(ProcessToken::Unavailable(format!(
                "'{}' could not be read: {err}",
                symbols.token_path
            )))
        }
    };

    if !symbols.is_fast_ref {
        if raw == 0 {
            return Ok(ProcessToken::None);
        }
        return Ok(ProcessToken::At {
            address: raw,
            reference_count: None,
        });
    }

    let address = raw & !symbols.fast_ref_mask;
    let reference_count = raw & symbols.fast_ref_mask;
    if address == 0 {
        // A non-zero reference count over a null address is not a token; it is
        // whatever those bits were. Reporting it as an address would send every
        // later read to the bottom of the address space.
        return Ok(ProcessToken::None);
    }
    Ok(ProcessToken::At {
        address,
        reference_count: Some(reference_count),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handles::test_support::{win10_profile, xp_profile, WIN10_EPROCESS, WIN10_TOKEN};
    use crate::handles::test_support::{XP_EPROCESS, XP_TOKEN};

    #[test]
    fn the_reference_count_packed_into_a_token_pointer_is_masked_off_on_x64() {
        let profile = win10_profile();
        let symbols = TokenSymbols::from_profile(&profile).expect("the layout resolves");
        assert!(symbols.is_fast_ref);
        assert_eq!(symbols.fast_ref_mask, 15, "four bits on a 64-bit kernel");

        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        let token = token_for(&reader, &symbols, WIN10_EPROCESS).expect("the process reads");
        assert_eq!(
            token,
            ProcessToken::At {
                address: WIN10_TOKEN,
                reference_count: Some(3),
            }
        );
    }

    #[test]
    fn the_reference_count_is_three_bits_wide_on_a_thirty_two_bit_kernel() {
        let profile = xp_profile();
        let symbols = TokenSymbols::from_profile(&profile).expect("the layout resolves");
        assert_eq!(symbols.fast_ref_mask, 7, "three bits on a 32-bit kernel");

        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        let token = token_for(&reader, &symbols, XP_EPROCESS).expect("the process reads");
        assert_eq!(token.address(), Some(XP_TOKEN));
    }

    /// The whole point of the mask: fifteen bytes of drift produces a structure
    /// that parses, so the difference has to be visible in a test rather than
    /// trusted.
    #[test]
    fn an_unmasked_token_pointer_would_not_be_the_token_address() {
        let profile = win10_profile();
        let symbols = TokenSymbols::from_profile(&profile).expect("the layout resolves");
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        let eprocess = reader
            .object(WIN10_EPROCESS, TYPE_EPROCESS)
            .expect("the process is a structure");
        let raw = eprocess
            .int(&symbols.token_path)
            .expect("the member reads")
            .as_u64()
            .expect("an address is not negative");
        assert_ne!(raw, WIN10_TOKEN, "the fixture packs a reference count");
        assert_eq!(raw & !symbols.fast_ref_mask, WIN10_TOKEN);
    }

    #[test]
    fn a_process_whose_token_pointer_is_null_reports_none_rather_than_an_error() {
        let profile = win10_profile();
        let symbols = TokenSymbols::from_profile(&profile).expect("the layout resolves");
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        // Address 0 in the fixture is a page of zeros, so every member of the
        // `_EPROCESS` read there is zero — including the token.
        let token = token_for(&reader, &symbols, 0).expect("a zeroed process still reads");
        assert_eq!(token, ProcessToken::None);
    }

    #[test]
    fn a_token_whose_bytes_were_never_captured_is_unavailable_rather_than_absent() {
        let profile = win10_profile();
        let symbols = TokenSymbols::from_profile(&profile).expect("the layout resolves");
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        // Past the top of the fixture's address space: the process structure
        // itself cannot be read, which is a gap in the evidence and not a
        // process without a token.
        let token = token_for(&reader, &symbols, 0x00FF_0000).expect("the type is still valid");
        assert!(
            token.is_unavailable(),
            "an unread token must not render as no token: {token:?}"
        );
    }

    #[test]
    fn a_build_without_a_token_type_is_refused_by_name() {
        // The refusal has to name `_TOKEN`, because a stage that silently
        // produced nothing would look exactly like a machine whose processes
        // held no privileges.
        let profile = crate::handles::test_support::win10_profile_without(&["_TOKEN"]);
        let err = TokenSymbols::from_profile(&profile).expect_err("the build is refused");
        assert!(err.to_string().contains("_TOKEN"), "{err}");
        assert_eq!(err.class(), "unsupported_build");
    }
}
