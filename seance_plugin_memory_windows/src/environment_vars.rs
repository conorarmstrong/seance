//! The environment block itself: finding it, reading it, and decoding it.
//!
//! # The layout
//!
//! `_RTL_USER_PROCESS_PARAMETERS.Environment` points at a run of UTF-16LE text
//! in the **process's own** address space:
//!
//! ```text
//! P A T H = C : \ … \0 U S E R N A M E = s a r a h \0 \0
//! └────── one variable ──┘ └──── another variable ────┘ └ terminator
//! ```
//!
//! Each variable is `NAME=VALUE` followed by one NUL code unit; the list ends
//! with an empty entry, which is to say a second NUL. Nothing states how many
//! variables there are, so the *only* thing that distinguishes "that was all of
//! them" from "the rest of the block was not captured" is whether that
//! terminator was reached. [`DecodedBlock::terminated`] is that fact, and it is
//! carried all the way to the artifact.
//!
//! # Three ways to read this wrong
//!
//! * **Reading it in the kernel address space.** The pointer is a user-space
//!   address. Following it through the kernel's page tables does not fail — it
//!   returns whatever the kernel has mapped at that address, and UTF-16LE
//!   decoding is forgiving enough that it produces plausible-looking text.
//!   Everything here is read through a reader over the process's own space, and
//!   [`read_environment`] builds it.
//! * **Trusting the declared length.** Windows XP does not record the
//!   environment's length at all, and where a length exists it can have been
//!   smeared. The read is capped, the decode stops at the terminator whatever
//!   the length said, and a length that had to be ignored is a note on the row.
//! * **Reporting a short read as a short environment.** An environment block
//!   frequently spans several pages, and the second page is frequently not in
//!   the capture. Reading it as one call and giving up would lose the variables
//!   on the first page; reading it as one call and *succeeding* on a truncated
//!   buffer would report a shorter list as though it were the whole one. The
//!   block is read a page at a time, the bytes that were readable are decoded,
//!   and the row records exactly where reading stopped.

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::object::StructReader;
use seance_memory::translate::TableCache;
use seance_memory::Incomplete;

use crate::environment::{EnvironmentConfig, EnvironmentSymbols, TYPE_EPROCESS};
use crate::process::{self, ProcessSymbols};
use crate::profile::WindowsProfile;
use crate::registry::key::decode_utf16le;

/// The process environment block, in the process's own address space.
pub const TYPE_PEB: &str = "_PEB";

/// The parameter block the environment pointer lives in.
pub const TYPE_PROCESS_PARAMETERS: &str = "_RTL_USER_PROCESS_PARAMETERS";

/// Ceiling on bytes read from one environment block.
///
/// A real block is a few kilobytes. A megabyte is far past anything Windows
/// creates and still small enough to hold, so reaching it means the declared
/// length is not a length — which is reported, not silently clamped.
pub const MAX_ENVIRONMENT_BYTES: u64 = 0x10_0000;

/// Ceiling on variables individually recorded for one process. The *count*
/// stays exact past this point.
pub const MAX_ENVIRONMENT_VARIABLES: usize = 4_096;

/// How much of a block one read asks for.
///
/// A page, because a page is the unit in which the block is present or absent
/// from the capture: asking for the whole block in one call turns a block whose
/// tail was paged out into no block at all.
pub const ENVIRONMENT_CHUNK: u64 = 4_096;

// ── Length ──────────────────────────────────────────────────────────────────

/// What the member giving the block's length actually measures.
///
/// The two are not interchangeable, and a report that shows a byte count owes
/// an examiner the difference: one is the environment's own size and the other
/// is an upper bound that happens to contain it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthSource {
    /// `_RTL_USER_PROCESS_PARAMETERS.EnvironmentSize`: the block's own length,
    /// in bytes. Present from Windows Vista.
    EnvironmentSize,
    /// `_RTL_USER_PROCESS_PARAMETERS.Length`: the length of the *parameter
    /// block*, used as an upper bound on Windows XP, which records no size for
    /// the environment. Always an over-estimate, so the decode still stops at
    /// the double NUL and no variable can be invented by using it.
    ParametersLength,
    /// This build records neither, so the block was read up to the cap and
    /// decoded to its double NUL.
    Terminator,
}

impl LengthSource {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            LengthSource::EnvironmentSize => "environment_size",
            LengthSource::ParametersLength => "parameters_length",
            LengthSource::Terminator => "terminator",
        }
    }
}

// ── Decoded contents ────────────────────────────────────────────────────────

/// One `NAME=VALUE` pair out of a process's environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVar {
    /// The name, exactly as stored. Windows also keeps per-drive current
    /// directories in names that themselves begin with `=`, such as `=C:`, and
    /// those are reported rather than dropped.
    pub name: String,
    /// The value.
    pub value: String,
    /// Whether every UTF-16 code unit in the entry decoded cleanly. `false`
    /// means replacement characters stand in for units that are not valid
    /// UTF-16, so what is on screen is not byte-for-byte what the process held.
    pub well_formed: bool,
    /// Whether the entry's own NUL terminator was reached.
    ///
    /// `false` for the fragment at the end of a block that was read short: the
    /// value shown is a prefix of the real one, and treating it as the whole
    /// value would understate — for instance — a `PATH` an attacker prepended to.
    pub complete: bool,
    /// Whether a variable of this name is set persistently in the registry.
    ///
    /// `Some(false)` is the interesting one: the variable was set at runtime
    /// with `SetEnvironmentVariable`, or inherited from a parent that did.
    /// `None` means the persistent set could not be established, and must never
    /// be rendered as `Some(false)` — "we could not check" is not "this was
    /// deliberately set".
    pub persistent: Option<bool>,
}

impl EnvVar {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "value": self.value,
            "well_formed": self.well_formed,
            "complete": self.complete,
            "persistent": self.persistent,
            "commonly_inherited": crate::environment::is_commonly_inherited(&self.name),
        })
    }
}

/// An entry in the block that is not a `NAME=VALUE` pair.
///
/// Kept rather than discarded. An entry with no `=` in it is either smear or
/// something deliberately malformed, and both are worth a line; neither belongs
/// among the variables, because everything downstream would read it as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalformedEntry {
    /// The entry's text as decoded.
    pub text: String,
    /// Whether it decoded cleanly.
    pub well_formed: bool,
}

impl MalformedEntry {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"text": self.text, "well_formed": self.well_formed})
    }
}

/// What decoding one buffer of block bytes produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecodedBlock {
    /// The variables, in block order, capped by
    /// [`EnvironmentConfig::max_variables`].
    pub variables: Vec<EnvVar>,
    /// How many variables the buffer held in total. Exact even when the list
    /// above was capped.
    pub variables_total: usize,
    /// Entries that were not `NAME=VALUE`, capped the same way.
    pub malformed: Vec<MalformedEntry>,
    /// How many such entries there were in total.
    pub malformed_total: usize,
    /// Whether the double-NUL terminator was reached.
    ///
    /// The single most important field on this structure: `false` means the
    /// list of variables is a floor, not a total.
    pub terminated: bool,
    /// Whether the variable cap fired.
    pub capped: bool,
    /// How many bytes of the buffer the decode consumed.
    pub bytes_consumed: u64,
    /// Everything odd about the buffer that did not stop the decode.
    pub notes: Vec<String>,
}

/// Decode an environment block's bytes.
///
/// Pure, so the decoding can be tested without a page-table walk, and so the
/// one piece of logic that turns bytes into the variables an examiner reads has
/// no dependency on how those bytes were obtained.
///
/// `max_variables` bounds the number of entries *recorded*; the totals stay
/// exact, and [`DecodedBlock::capped`] says the cap fired.
pub fn decode_environment_block(bytes: &[u8], max_variables: usize) -> DecodedBlock {
    let mut out = DecodedBlock::default();
    if !bytes.len().is_multiple_of(2) {
        out.notes.push(format!(
            "the block is {} byte(s) long, which is not a whole number of UTF-16 code units, so \
             its final byte was not decoded",
            bytes.len()
        ));
    }
    let units = bytes.len() / 2;
    let unit_at = |index: usize| -> u16 {
        let at = index * 2;
        u16::from_le_bytes([bytes[at], bytes[at + 1]])
    };

    let mut start = 0usize;
    let mut index = 0usize;
    while index < units {
        if unit_at(index) != 0 {
            index += 1;
            continue;
        }
        if index == start {
            // An empty entry is the double NUL that ends the list.
            out.terminated = true;
            out.bytes_consumed = (index.saturating_add(1) as u64).saturating_mul(2);
            return out;
        }
        push_entry(&mut out, &bytes[start * 2..index * 2], true, max_variables);
        index += 1;
        start = index;
    }

    // The buffer ran out before the terminator did. Whatever is left is a
    // fragment of a variable whose NUL was never read, and it is reported as a
    // fragment rather than as a variable.
    if start < units {
        push_entry(&mut out, &bytes[start * 2..units * 2], false, max_variables);
        out.notes.push(
            "the block ended in the middle of an entry, so that entry's value is a prefix of the \
             real one"
                .to_string(),
        );
    }
    out.bytes_consumed = (units as u64).saturating_mul(2);
    out
}

/// Decode one entry's bytes and file it as a variable or as malformed.
fn push_entry(out: &mut DecodedBlock, bytes: &[u8], complete: bool, max_variables: usize) {
    let (text, well_formed) = decode_utf16le(bytes);
    match split_entry(&text) {
        Some((name, value)) => {
            out.variables_total = out.variables_total.saturating_add(1);
            if out.variables.len() >= max_variables {
                out.capped = true;
                return;
            }
            out.variables.push(EnvVar {
                name,
                value,
                well_formed,
                complete,
                persistent: None,
            });
        }
        None => {
            out.malformed_total = out.malformed_total.saturating_add(1);
            if out.malformed.len() >= max_variables {
                out.capped = true;
                return;
            }
            out.malformed.push(MalformedEntry { text, well_formed });
        }
    }
}

/// Split one entry into its name and value at the separating `=`.
///
/// Windows keeps the current directory of each drive in variables whose *name*
/// begins with `=` — `=C:=C:\Users\sarah`, `=ExitCode=00000000`. Splitting at
/// the first `=` names every one of them the empty string; upstream Volatility
/// drops them entirely. Both lose evidence about where a process had been
/// working, so the separator is looked for past a leading `=`.
///
/// `None` for an entry with no separator at all, which is not a variable.
fn split_entry(text: &str) -> Option<(String, String)> {
    let from = if text.starts_with('=') {
        // One byte, because `=` is one byte in UTF-8 and is a character
        // boundary.
        1
    } else {
        0
    };
    let at = text.get(from..)?.find('=')?.checked_add(from)?;
    let name = text.get(..at)?.to_string();
    let value = text.get(at.checked_add(1)?..)?.to_string();
    Some((name, value))
}

// ── One process's block ─────────────────────────────────────────────────────

/// One process's environment block as read out of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentRecord {
    /// The block's address, in the process's own address space.
    pub address: u64,
    /// The length the parameter block declared, when it declared one.
    pub declared_bytes: Option<u64>,
    /// What that declared length measures.
    pub length_source: LengthSource,
    /// How many bytes were actually read.
    pub bytes_read: u64,
    /// Where reading stopped, when it stopped before the requested length.
    /// `None` means every requested byte was read.
    pub stopped: Option<String>,
    /// The variables.
    pub variables: Vec<EnvVar>,
    /// How many variables the block held in total.
    pub variables_total: usize,
    /// Entries that were not `NAME=VALUE`.
    pub malformed: Vec<MalformedEntry>,
    /// How many such entries there were.
    pub malformed_total: usize,
    /// Whether the double-NUL terminator was reached.
    pub terminated: bool,
    /// Whether a cap fired while reading or decoding.
    pub capped: bool,
    /// Everything odd about the block that did not stop it being read.
    pub notes: Vec<String>,
}

impl EnvironmentRecord {
    /// The value of a variable, matched case-insensitively as Windows matches
    /// environment variable names.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.variables
            .iter()
            .find(|var| var.name.eq_ignore_ascii_case(name))
            .map(|var| var.value.as_str())
    }

    /// Whether the whole block was read and decoded.
    ///
    /// A block that did not reach its terminator is a floor on this process's
    /// environment, not a total, and a report quoting "this process had no
    /// proxy set" must consult this first.
    pub fn is_complete(&self) -> bool {
        self.terminated && !self.capped && self.stopped.is_none()
    }

    /// Everything a report must declare about this block.
    pub fn incomplete(&self, process: u64) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let Some(stopped) = &self.stopped {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "the environment block of the process at {process:#x} was read short: \
                     {stopped}"
                ),
            ));
        }
        if !self.terminated {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "the environment block of the process at {process:#x} does not reach its \
                     terminating double NUL, so the {} variable(s) listed are a floor rather than \
                     the whole environment",
                    self.variables_total
                ),
            ));
        }
        if self.capped {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the environment block of the process at {process:#x} holds {} variable(s) \
                     and only {} are listed individually",
                    self.variables_total,
                    self.variables.len()
                ),
            ));
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            // Exact beside the number: the environment block sits at a
            // user-space address that can still exceed 2^53 on 64-bit
            // Windows, and JSON numbers are IEEE doubles.
            "address_hex": format!("{:#x}", self.address),
            "declared_bytes": self.declared_bytes,
            "length_source": self.length_source.as_str(),
            "bytes_read": self.bytes_read,
            "stopped": self.stopped,
            "variables": self.variables.iter().map(EnvVar::to_json).collect::<Vec<_>>(),
            "variable_count": self.variables.len(),
            "variables_total": self.variables_total,
            "malformed": self.malformed.iter().map(MalformedEntry::to_json).collect::<Vec<_>>(),
            "malformed_total": self.malformed_total,
            "terminated": self.terminated,
            "capped": self.capped,
            "notes": self.notes,
            "complete": self.is_complete(),
        })
    }
}

/// A process's environment, with every way of not having one kept apart.
///
/// Five outcomes rather than "some variables or none", because the differences
/// carry findings. A service with a deliberately stripped environment and a
/// service whose block was never captured look identical if both render as an
/// empty list, and the variables are the whole point of looking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentBlock {
    /// The process has no user address space, so there is no PEB and no
    /// environment to have. The ordinary state of System, Registry and Memory
    /// Compression. Not a failure.
    NoUserSpace,
    /// The PEB was readable and its `ProcessParameters` pointer is null, which
    /// is what a process caught during creation looks like.
    NoParameters,
    /// The parameter block was readable and its `Environment` pointer is null:
    /// this process really was given no environment block.
    NoBlock,
    /// The block was found and read.
    Block(EnvironmentRecord),
    /// The block exists and could not be read at all: the PEB, the parameter
    /// block or the block's first page was not captured, or the process's page
    /// tables could not be walked. Never an empty environment.
    Unavailable(String),
}

impl EnvironmentBlock {
    /// Whether the answer is a positive statement about the process rather than
    /// a gap in the evidence.
    pub fn is_answered(&self) -> bool {
        !matches!(self, EnvironmentBlock::Unavailable(_))
    }

    /// The block, when there is one.
    pub fn record(&self) -> Option<&EnvironmentRecord> {
        match self {
            EnvironmentBlock::Block(record) => Some(record),
            _ => None,
        }
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            EnvironmentBlock::NoUserSpace => "no_user_space",
            EnvironmentBlock::NoParameters => "no_parameters",
            EnvironmentBlock::NoBlock => "no_block",
            EnvironmentBlock::Block(_) => "block",
            EnvironmentBlock::Unavailable(_) => "unavailable",
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            EnvironmentBlock::Block(record) => {
                let mut value = record.to_json();
                if let Some(object) = value.as_object_mut() {
                    object.insert("kind".into(), serde_json::json!("block"));
                }
                value
            }
            EnvironmentBlock::Unavailable(detail) => {
                serde_json::json!({"kind": "unavailable", "detail": detail})
            }
            other => serde_json::json!({"kind": other.as_str()}),
        }
    }
}

// ── Reading ─────────────────────────────────────────────────────────────────

/// Read as much of `want` bytes at `address` as the layer will give, a page at
/// a time.
///
/// Returns the bytes that were readable and, when the read stopped early, why.
/// Reading the whole block in one call would turn a block whose second page was
/// paged out into no block at all, and every variable on the first page would
/// be lost.
fn read_available(
    reader: &StructReader,
    address: u64,
    want: u64,
    chunk: u64,
    stop_at_terminator: bool,
) -> (Vec<u8>, Option<String>) {
    let mut bytes: Vec<u8> = Vec::new();
    let step = chunk.max(2);
    let mut offset = 0u64;
    while offset < want {
        let Some(at) = address.checked_add(offset) else {
            return (
                bytes,
                Some(format!(
                    "the block's address {address:#x} plus {offset} byte(s) leaves the address \
                     space"
                )),
            );
        };
        let take = step.min(want.saturating_sub(offset));
        match reader.read_bytes(at, take) {
            Ok(read) => {
                // Only the newly arrived bytes are examined, plus one code unit
                // of overlap so a terminator straddling the join is still seen.
                let from = bytes.len().saturating_sub(2);
                bytes.extend_from_slice(&read);
                offset = offset.saturating_add(take);
                if stop_at_terminator && holds_terminator(&bytes, from) {
                    return (bytes, None);
                }
            }
            Err(err) => {
                return (
                    bytes,
                    Some(format!(
                        "{take} byte(s) at {at:#x} could not be read, {offset} byte(s) into the \
                         block: {err}"
                    )),
                );
            }
        }
    }
    (bytes, None)
}

/// Whether `bytes` holds an empty entry — two consecutive NUL code units — at
/// or after `from`.
///
/// That pair is what ends an environment block, and it is what lets a read that
/// was given no length stop at the end of the block instead of at its cap. It
/// is only ever used to decide when to *stop reading*: the authoritative
/// decision about where the list ends belongs to
/// [`decode_environment_block`], so a false negative here costs a longer read
/// and nothing else.
fn holds_terminator(bytes: &[u8], from: usize) -> bool {
    // Code units are two bytes wide, so a terminator can only begin at an even
    // offset. Scanning odd offsets as well would find a "terminator" inside the
    // low byte of one character and the high byte of the next.
    let mut index = from - (from % 2);
    while index.saturating_add(4) <= bytes.len() {
        if bytes[index..index + 4].iter().all(|byte| *byte == 0) {
            return true;
        }
        index = index.saturating_add(2);
    }
    false
}

/// Read a process's environment out of a PEB, in a reader over the
/// **process's own** address space.
///
/// Separated from [`read_environment`] so the reading is testable without a
/// page-table walk, and so a caller that already holds a process address space
/// — one dumping several things out of the same process — does not build a
/// second one.
///
/// `peb` is an address in that reader's space. Passing a reader over the kernel
/// space instead is the mistake this signature exists to make visible: the
/// answer would be whatever the kernel maps at a user address, and it would
/// decode.
pub fn read_environment_in(
    reader: &StructReader,
    symbols: &EnvironmentSymbols,
    peb: u64,
    config: &EnvironmentConfig,
) -> EnvironmentBlock {
    if peb == 0 {
        return EnvironmentBlock::NoUserSpace;
    }
    let block = match reader.object(peb, TYPE_PEB) {
        Ok(block) => block,
        Err(err) => return EnvironmentBlock::Unavailable(err.to_string()),
    };
    let parameters = match block.int(&symbols.process_parameters) {
        // A negative value is not an address. Folding it to zero would render as
        // `NoParameters`, which is a positive statement that this process was
        // caught during creation — a claim about the suspect's machine drawn
        // from a member that did not read as a pointer.
        Ok(value) => match value.as_u64() {
            Some(address) => address,
            None => {
                return EnvironmentBlock::Unavailable(format!(
                    "'{TYPE_PEB}.{}' holds {value}, which is not an address, so whether this \
                     process has a parameter block is unknown rather than no",
                    symbols.process_parameters
                ))
            }
        },
        Err(err) => return EnvironmentBlock::Unavailable(err.to_string()),
    };
    if parameters == 0 {
        return EnvironmentBlock::NoParameters;
    }
    let parameters = match reader.object(parameters, TYPE_PROCESS_PARAMETERS) {
        Ok(object) => object,
        Err(err) => return EnvironmentBlock::Unavailable(err.to_string()),
    };
    let address = match parameters.int(&symbols.environment) {
        // Likewise: a negative value folded to zero renders as `NoBlock`, which
        // says this process really was given no environment. That is a finding
        // in its own right and it must not be manufactured out of a member that
        // did not read as a pointer.
        Ok(value) => match value.as_u64() {
            Some(address) => address,
            None => {
                return EnvironmentBlock::Unavailable(format!(
                    "'{TYPE_PROCESS_PARAMETERS}.{}' holds {value}, which is not an address, so \
                     whether this process has an environment block is unknown rather than no",
                    symbols.environment
                ))
            }
        },
        Err(err) => return EnvironmentBlock::Unavailable(err.to_string()),
    };
    if address == 0 {
        return EnvironmentBlock::NoBlock;
    }

    let mut notes: Vec<String> = Vec::new();
    let cap = config.max_environment_bytes.max(ENVIRONMENT_CHUNK);

    // What the build says the block is worth reading, and what that claim is
    // actually a claim about.
    let (declared_bytes, mut length_source) = match &symbols.environment_size {
        Some((path, source)) => match parameters.int(path) {
            Ok(value) => match value.as_u64() {
                Some(bytes) => (Some(bytes), *source),
                None => {
                    notes.push(format!(
                        "'{TYPE_PROCESS_PARAMETERS}.{path}' is negative, which is not a length, so \
                         the block was read to its terminator instead"
                    ));
                    (None, LengthSource::Terminator)
                }
            },
            Err(err) => {
                notes.push(format!(
                    "'{TYPE_PROCESS_PARAMETERS}.{path}' could not be read, so the block was read \
                     to its terminator instead: {err}"
                ));
                (None, LengthSource::Terminator)
            }
        },
        None => (None, LengthSource::Terminator),
    };

    let mut capped = false;
    let want = match declared_bytes {
        Some(0) => {
            // A non-null pointer to a zero-length block is not a block of zero
            // variables; it is a length that cannot be right. Reading to the
            // terminator is the honest recovery, and the note says so.
            notes.push(format!(
                "the block at {address:#x} is declared zero bytes long, which cannot be right for \
                 a block that exists, so it was read to its terminator instead"
            ));
            length_source = LengthSource::Terminator;
            cap
        }
        Some(bytes) if bytes > cap => {
            capped = true;
            notes.push(format!(
                "the block declares {bytes} byte(s), past the {cap}-byte cap, so at most {cap} \
                 were read"
            ));
            cap
        }
        Some(bytes) => bytes,
        None => cap,
    };

    // A build that states no length would otherwise read to the cap for every
    // process; stopping at the block's own terminator is the same answer for a
    // fraction of the reads.
    let stop_at_terminator = length_source == LengthSource::Terminator;
    let (bytes, stopped) =
        read_available(reader, address, want, ENVIRONMENT_CHUNK, stop_at_terminator);
    if bytes.is_empty() {
        return EnvironmentBlock::Unavailable(stopped.unwrap_or_else(|| {
            format!("no bytes of the environment block at {address:#x} were readable")
        }));
    }

    let decoded = decode_environment_block(&bytes, config.max_variables.max(1));
    notes.extend(decoded.notes);
    if length_source == LengthSource::ParametersLength && decoded.terminated {
        notes.push(
            "this build records no length for the environment itself, so the parameter block's \
             own length was used as an upper bound and the decode stopped at the terminator"
                .to_string(),
        );
    }

    EnvironmentBlock::Block(EnvironmentRecord {
        address,
        declared_bytes,
        length_source,
        bytes_read: bytes.len() as u64,
        stopped,
        variables: decoded.variables,
        variables_total: decoded.variables_total,
        malformed: decoded.malformed,
        malformed_total: decoded.malformed_total,
        terminated: decoded.terminated,
        capped: capped || decoded.capped,
        notes,
    })
}

/// Read one process's environment, building its address space to do it.
///
/// `process` is the address of an `_EPROCESS` in the kernel space. Never fails:
/// every way of not getting an answer is an [`EnvironmentBlock`] variant, so a
/// caller cannot accidentally render a failure as an empty environment.
pub fn read_environment(
    profile: &WindowsProfile,
    symbols: &EnvironmentSymbols,
    process: u64,
    cache: &Arc<TableCache>,
    config: &EnvironmentConfig,
) -> EnvironmentBlock {
    let kernel = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let object = match kernel.object(process, TYPE_EPROCESS) {
        Ok(object) => object,
        Err(err) => return EnvironmentBlock::Unavailable(err.to_string()),
    };
    let peb = match object.int(&symbols.peb) {
        // `NoUserSpace` is the ordinary state of System and Registry, and it is
        // a positive statement. A `Peb` that did not read as an address must
        // not be folded into it, or a process whose `_EPROCESS` was smeared
        // would be reported as a kernel process with no environment to have.
        Ok(value) => match value.as_u64() {
            Some(address) => address,
            None => {
                return EnvironmentBlock::Unavailable(format!(
                    "'{TYPE_EPROCESS}.{}' holds {value}, which is not an address, so whether \
                     this process has a user address space is unknown rather than no",
                    symbols.peb
                ))
            }
        },
        Err(err) => return EnvironmentBlock::Unavailable(err.to_string()),
    };
    if peb == 0 {
        return EnvironmentBlock::NoUserSpace;
    }

    let space = match process_space(profile, &symbols.process, process, cache) {
        Ok(space) => space,
        Err(err) => return EnvironmentBlock::Unavailable(err.to_string()),
    };
    read_environment_in(&space, symbols, peb, config)
}

/// A reader over one process's own address space.
fn process_space(
    profile: &WindowsProfile,
    symbols: &ProcessSymbols,
    process: u64,
    cache: &Arc<TableCache>,
) -> Result<StructReader, process::ProcessError> {
    let layer = process::process_address_space(profile, symbols, process, cache)?;
    Ok(StructReader::new(layer, Arc::clone(&profile.symbols)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a block's bytes from entries, with the trailing double NUL.
    fn block(entries: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for entry in entries {
            for unit in entry.encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes.extend_from_slice(&[0, 0]);
        }
        bytes.extend_from_slice(&[0, 0]);
        bytes
    }

    #[test]
    fn a_terminated_block_yields_every_variable_and_says_it_is_complete() {
        let bytes = block(&["PATH=C:\\Windows", "USERNAME=sarah"]);
        let decoded = decode_environment_block(&bytes, 4096);
        assert!(decoded.terminated);
        assert_eq!(decoded.variables_total, 2);
        assert_eq!(decoded.variables[0].name, "PATH");
        assert_eq!(decoded.variables[0].value, "C:\\Windows");
        assert_eq!(decoded.variables[1].name, "USERNAME");
        assert!(decoded.variables.iter().all(|var| var.complete));
        assert!(!decoded.capped);
    }

    /// The failure this whole module exists for: a block cut off mid-list is
    /// shorter, and nothing else about it looks wrong.
    #[test]
    fn a_block_cut_off_before_its_terminator_is_reported_as_unterminated() {
        let full = block(&["PATH=C:\\Windows", "USERNAME=sarah"]);
        // Drop the terminator and the last few units of the final value.
        let cut = &full[..full.len() - 8];
        let decoded = decode_environment_block(cut, 4096);
        assert!(
            !decoded.terminated,
            "a block with no double NUL must not claim to be terminated"
        );
        assert_eq!(decoded.variables_total, 2);
        assert!(
            !decoded.variables[1].complete,
            "the entry whose NUL was never read is a fragment"
        );
        assert!(!decoded.notes.is_empty());
    }

    /// A block that is entirely just the terminator is a genuinely empty
    /// environment, and it is complete.
    #[test]
    fn a_block_holding_only_the_terminator_is_an_empty_but_complete_environment() {
        let decoded = decode_environment_block(&[0, 0], 4096);
        assert!(decoded.terminated);
        assert_eq!(decoded.variables_total, 0);
        assert!(decoded.variables.is_empty());
        assert_eq!(decoded.bytes_consumed, 2);
    }

    /// Windows keeps per-drive current directories in variables whose name
    /// starts with `=`. Splitting at the first `=` would name them all "".
    #[test]
    fn a_variable_whose_name_begins_with_an_equals_sign_keeps_its_name() {
        let bytes = block(&["=C:=C:\\Users\\sarah", "=ExitCode=00000000"]);
        let decoded = decode_environment_block(&bytes, 4096);
        assert_eq!(decoded.variables[0].name, "=C:");
        assert_eq!(decoded.variables[0].value, "C:\\Users\\sarah");
        assert_eq!(decoded.variables[1].name, "=ExitCode");
        assert_eq!(decoded.variables[1].value, "00000000");
        assert_eq!(decoded.malformed_total, 0);
    }

    /// An entry with no separator is not a variable, and reporting it as one
    /// with an empty value would invent a setting the process did not have.
    #[test]
    fn an_entry_with_no_separator_is_recorded_as_malformed_not_as_a_variable() {
        let bytes = block(&["PATH=C:\\Windows", "NOTAVARIABLE"]);
        let decoded = decode_environment_block(&bytes, 4096);
        assert_eq!(decoded.variables_total, 1);
        assert_eq!(decoded.malformed_total, 1);
        assert_eq!(decoded.malformed[0].text, "NOTAVARIABLE");
    }

    /// The cap bounds what is listed and never what is counted.
    #[test]
    fn the_variable_cap_bounds_the_list_and_leaves_the_count_exact() {
        let entries: Vec<String> = (0..10).map(|n| format!("VAR{n}=value{n}")).collect();
        let refs: Vec<&str> = entries.iter().map(String::as_str).collect();
        let decoded = decode_environment_block(&block(&refs), 3);
        assert_eq!(decoded.variables.len(), 3);
        assert_eq!(decoded.variables_total, 10);
        assert!(decoded.capped);
        assert!(decoded.terminated);
    }

    /// An odd byte count cannot be a whole number of UTF-16 units, and saying
    /// so beats decoding fifteen and a half characters in silence.
    #[test]
    fn an_odd_length_buffer_is_noted_rather_than_silently_truncated() {
        let mut bytes = block(&["A=B"]);
        bytes.push(0x41);
        let decoded = decode_environment_block(&bytes, 4096);
        assert!(decoded.terminated);
        assert!(
            decoded.notes.iter().any(|note| note.contains("UTF-16")),
            "{:?}",
            decoded.notes
        );
    }

    /// An unpaired surrogate is real evidence and must render, but the row has
    /// to say the text on screen is not what was stored.
    #[test]
    fn an_unpaired_surrogate_renders_and_is_flagged_as_not_well_formed() {
        let mut bytes = Vec::new();
        for unit in "A=".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&0xD800u16.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        let decoded = decode_environment_block(&bytes, 4096);
        assert_eq!(decoded.variables.len(), 1);
        assert!(!decoded.variables[0].well_formed);
    }

    /// Lookup follows Windows, which does not care about case.
    #[test]
    fn a_variable_is_found_whatever_case_it_is_asked_for_in() {
        let record = EnvironmentRecord {
            address: 0x1000,
            declared_bytes: Some(64),
            length_source: LengthSource::EnvironmentSize,
            bytes_read: 64,
            stopped: None,
            variables: vec![EnvVar {
                name: "UserName".into(),
                value: "sarah".into(),
                well_formed: true,
                complete: true,
                persistent: None,
            }],
            variables_total: 1,
            malformed: Vec::new(),
            malformed_total: 0,
            terminated: true,
            capped: false,
            notes: Vec::new(),
        };
        assert_eq!(record.get("USERNAME"), Some("sarah"));
        assert_eq!(record.get("username"), Some("sarah"));
        assert_eq!(record.get("USER"), None);
        assert!(record.is_complete());
    }

    /// An unterminated block is not complete, and it declares why.
    #[test]
    fn an_unterminated_record_declares_the_gap_it_leaves() {
        let record = EnvironmentRecord {
            address: 0x1000,
            declared_bytes: None,
            length_source: LengthSource::Terminator,
            bytes_read: 4096,
            stopped: Some("the second page was not captured".into()),
            variables: Vec::new(),
            variables_total: 0,
            malformed: Vec::new(),
            malformed_total: 0,
            terminated: false,
            capped: false,
            notes: Vec::new(),
        };
        assert!(!record.is_complete());
        let incomplete = record.incomplete(0xDEAD);
        assert_eq!(incomplete.len(), 2);
        assert!(incomplete.iter().all(|i| i.detail.contains("dead")));
    }

    /// The terminator only exists on an even offset. Finding one on an odd
    /// offset would stop a read in the middle of a character pair.
    #[test]
    fn a_terminator_is_only_recognised_on_a_code_unit_boundary() {
        // Four zero bytes starting at offset 1: the high byte of one character
        // and the low byte of the next, which is not an empty entry. A scan
        // that did not respect the code-unit boundary would stop the read here.
        let straddling = [0x41u8, 0, 0, 0, 0, 0x41];
        assert!(!holds_terminator(&straddling, 0));
        assert!(!holds_terminator(&straddling, 1));

        let block = block(&["A=B"]);
        assert!(holds_terminator(&block, 0));
        assert!(!holds_terminator(&[0x41, 0, 0x42, 0], 0));
    }

    /// The scan starts on the even offset at or below `from`, so a terminator
    /// straddling the join between two reads is still seen.
    #[test]
    fn a_terminator_split_across_two_reads_is_still_found() {
        let bytes = [0x41u8, 0, 0, 0, 0, 0];
        // The second read began at offset 4; backing up one code unit finds the
        // pair that started at offset 2.
        assert!(holds_terminator(&bytes, 2));
        assert!(!holds_terminator(&bytes, 4), "nothing follows offset 4");
    }

    /// The variants that mean "there is nothing to have" must not render like
    /// the one that means "we could not look".
    #[test]
    fn an_unreadable_block_is_distinguishable_from_a_process_with_no_block() {
        assert!(EnvironmentBlock::NoBlock.is_answered());
        assert!(EnvironmentBlock::NoUserSpace.is_answered());
        assert!(!EnvironmentBlock::Unavailable("paged out".into()).is_answered());
        assert_eq!(
            EnvironmentBlock::Unavailable("paged out".into()).to_json()["kind"],
            serde_json::json!("unavailable")
        );
        assert_eq!(
            EnvironmentBlock::NoBlock.to_json()["kind"],
            serde_json::json!("no_block")
        );
    }
}
