//! MFT records carved out of physical memory.
//!
//! Windows keeps recently touched Master File Table records in the cache
//! manager's pages, so a memory image holds a scattering of NTFS metadata that
//! is entirely independent of the filesystem on disk. That matters because the
//! two can disagree, and where they disagree the memory copy is usually the
//! older one:
//!
//! * a file created and deleted between the last two disk snapshots leaves an
//!   MFT record in RAM and nothing on disk;
//! * a record overwritten on disk by a later allocation may still be in RAM
//!   with the *previous* file's name and timestamps in it;
//! * a timestamp forged with `SetFileTime` after the record was cached leaves
//!   the original `$STANDARD_INFORMATION` times in the cached copy, which is
//!   one of the few ways timestomping is detectable at all.
//!
//! # Why this scans rather than walks
//!
//! There is no list of cached MFT records. The records are found the way
//! carving finds anything: by sweeping physical memory for the signature at
//! offset zero of every record. `FILE` marks a record in use, `BAAD` marks one
//! the kernel found corrupt and refused, and both are worth recovering.
//!
//! The needles are five bytes, not four: `FILE` followed by the low byte of the
//! update-sequence-array offset, which NTFS writes as `0x30` (`0`) on version
//! 3.1 and `0x2A` (`*`) before it. A bare four-byte `FILE` needle matches every
//! occurrence of the word in every document in memory, and a sweep of an 8 GiB
//! image would return hundreds of thousands of candidates that are not records.
//!
//! # Fixups, and why a mismatch is not a parse failure
//!
//! NTFS overwrites the last two bytes of every 512-byte sector of a record with
//! a sequence number, and stashes the real bytes in the update-sequence array.
//! A reader that does not put them back reads two corrupt bytes per sector —
//! which, in a record whose attributes reach past 0x1FE, silently corrupts a
//! timestamp or a name.
//!
//! This module applies the fixups when the stashed sequence number matches what
//! is at each sector end, and records [`FixupState::Mismatch`] when it does not.
//! A mismatch is common and informative in a memory image rather than fatal: the
//! record may be a partially overwritten page, or the first sector may be a
//! genuine cached record whose later sectors have been reused. The first sector
//! — which holds the header and usually `$STANDARD_INFORMATION` — is still
//! evidence, so parsing continues and every field downstream carries the state
//! of the fixups it was read under.
//!
//! # What a wrong answer looks like
//!
//! A hit is five bytes. Random memory produces those five bytes regularly, and
//! a decoder that trusts them emits a file called whatever the following bytes
//! decode to, with timestamps in 1601 or 30828. Every field here is
//! bounds-checked against the record's own declared extents, every timestamp is
//! checked against a plausibility window, and a candidate that fails the header
//! checks is counted as [`RejectionReason::NotARecord`] rather than dropped —
//! so the ratio of records to rejections is visible instead of being hidden.
//!
//! # Entry point
//!
//! [`scan_mft_records`] is the whole stage.

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_core::ntfs_timestamps::{detect_timestomp_indicators, TimestompIndicator};
use seance_memory::object::{ObjError, StructReader};
use seance_memory::scan::{scan_range, MultiStringScanner, ScanConfig, ScanError, ScanOutcome};
use seance_memory::Incomplete;

use crate::profile::WindowsProfile;

// ── Constants ───────────────────────────────────────────────────────────────

/// Signature of an MFT record the kernel considers usable.
pub const SIGNATURE_FILE: &[u8; 4] = b"FILE";

/// Signature of an MFT record the kernel found corrupt.
///
/// Recovered deliberately: a record NTFS refused is still a record of a file
/// that existed, and it is exactly the kind of thing that survives in RAM after
/// being replaced on disk.
pub const SIGNATURE_BAAD: &[u8; 4] = b"BAAD";

/// The needles the sweep looks for.
///
/// Five bytes for the `FILE` forms — the signature plus the low byte of
/// `UpdateSequenceOffset`, which is `0x30` on NTFS 3.1 and `0x2A` before it —
/// because a four-byte `FILE` needle matches the English word and drowns the
/// sweep. `BAAD` is four bytes because nothing else writes it.
pub const RECORD_NEEDLES: [&[u8]; 3] = [b"FILE\x30", b"FILE\x2a", b"BAAD"];

/// Bytes of one MFT record on almost every NTFS volume.
pub const DEFAULT_RECORD_BYTES: u64 = 1_024;

/// Bytes of the sector the update-sequence array protects.
pub const SECTOR_BYTES: u64 = 512;

/// Smallest number of bytes that can hold an NTFS 3.1 record header.
pub const MIN_RECORD_HEADER_BYTES: u64 = 48;

/// Smallest `UpdateSequenceOffset` any NTFS version writes, which is the pre-3.1
/// header size.
pub const MIN_USA_OFFSET: u64 = 0x2A;

/// The `UpdateSequenceOffset` NTFS 3.1 writes, which is also the offset at which
/// `RecordNumber` becomes part of the header.
pub const NTFS31_USA_OFFSET: u64 = 0x30;

/// Ceiling on attributes walked in one record.
///
/// A record is 1 KiB and the smallest attribute is 16 bytes, so sixty-four is
/// already beyond what fits. Reaching it means the length fields are not
/// advancing sensibly.
pub const MAX_ATTRIBUTES: usize = 64;

/// Ceiling on records reported by one sweep.
pub const MAX_RECORDS: usize = 262_144;

/// Ceiling on individually recorded rejections. The *count* stays exact.
pub const MAX_RECORDED_REJECTIONS: usize = 512;

/// Ceiling on bytes of resident stream content captured per attribute.
pub const MAX_RESIDENT_BYTES: u64 = 4_096;

/// Ceiling on the character count an `$FILE_NAME` may declare.
///
/// The attribute stores the name length in *characters* in a single byte, so
/// 255 is the format's own maximum and anything at all above it is a field read
/// at the wrong offset.
pub const MAX_NAME_CHARS: u64 = 255;

/// Earliest FILETIME this module will render: 1980-01-01T00:00:00Z.
///
/// Not 1601: a record carved out of random bytes routinely produces small
/// FILETIMEs, and a 1601 date printed beside a plausible file name is
/// indistinguishable from a real one in a timeline. NTFS itself postdates 1993,
/// and 1980 leaves room for timestamps carried in from FAT media.
pub const MIN_PLAUSIBLE_FILETIME: u64 = 119_600_064_000_000_000;

/// Latest FILETIME this module will render: 2200-01-01T00:00:00Z.
pub const MAX_PLAUSIBLE_FILETIME: u64 = 189_025_920_000_000_000;

/// `$STANDARD_INFORMATION`.
pub const ATTR_STANDARD_INFORMATION: u32 = 0x10;
/// `$ATTRIBUTE_LIST`.
pub const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
/// `$FILE_NAME`.
pub const ATTR_FILE_NAME: u32 = 0x30;
/// `$DATA`.
pub const ATTR_DATA: u32 = 0x80;
/// The end-of-attributes marker.
pub const ATTR_END: u32 = 0xFFFF_FFFF;

/// The record is allocated to a file that still exists.
pub const RECORD_FLAG_IN_USE: u16 = 0x0001;
/// The record describes a directory.
pub const RECORD_FLAG_DIRECTORY: u16 = 0x0002;

/// The `$FILE_NAME` namespaces NTFS defines.
pub const NAMESPACES: [(u8, &str); 4] =
    [(0, "POSIX"), (1, "Win32"), (2, "DOS"), (3, "Win32AndDOS")];

// ── Errors ──────────────────────────────────────────────────────────────────

/// Everything that stops the sweep producing records worth reading.
///
/// Note what is *not* here: a candidate that turned out not to be a record, and
/// a record whose bytes were only partly acquired. Both are facts about the
/// image and land on [`MftScanOutcome`].
#[derive(Debug, thiserror::Error)]
pub enum MftScanError {
    /// The image cannot be swept at all, and no partial answer would be honest.
    #[error("physical memory cannot be swept for MFT records: {detail}")]
    Unsupported {
        /// What is wrong, in the examiner's terms.
        detail: String,
    },

    /// The scanner could not be built or driven.
    #[error(transparent)]
    Scan(#[from] ScanError),

    /// A read failed in a way that invalidates the whole sweep.
    #[error(transparent)]
    Object(#[from] ObjError),
}

impl MftScanError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            MftScanError::Unsupported { .. } => "unsupported_image",
            MftScanError::Scan(_) => "scan",
            MftScanError::Object(err) => err.class(),
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            MftScanError::Object(err) => err.incomplete_reason(),
            _ => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this image cannot be swept" refusal.
    pub fn unsupported(detail: impl Into<String>) -> MftScanError {
        MftScanError::Unsupported {
            detail: detail.into(),
        }
    }
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// What this stage resolves before it sweeps.
///
/// # Why almost nothing here comes from the symbol table
///
/// An MFT record is an **NTFS on-disk structure**. Its layout is fixed by the
/// filesystem format and is identical on every Windows build; `ntoskrnl.pdb`
/// does not declare it, and no version of it ever will. Resolving `FILE_NAME`'s
/// timestamp offsets "from symbols" is therefore not possible, and pretending
/// otherwise would mean inventing a source of truth. The offsets come from the
/// NTFS format and are named as constants in [`parse_file_name`] and
/// [`parse_standard_information`], each one bounds-checked against the
/// attribute's own declared length before it is read.
///
/// What *is* profile-derived, and what this type fails closed on, is whether
/// there is any physical memory to sweep at all: a layer whose bounds are
/// inverted addresses nothing, and an empty result from it would read as "this
/// machine's memory held no MFT records". The extent it records is also the
/// extent [`scan_mft_records`] sweeps, so a report can state which range of
/// physical memory the answer covers rather than saying "the image".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MftScanSymbols {
    /// Lowest physical address the sweep will examine.
    pub physical_min: u64,
    /// Highest physical address the sweep will examine, inclusive.
    pub physical_max: u64,
    /// Pointer width of the profile, recorded so a report can state which image
    /// the records came out of. Nothing in an MFT record depends on it.
    pub pointer_size: u64,
}

impl MftScanSymbols {
    /// Establish that this image has physical memory worth sweeping.
    ///
    /// # Errors
    ///
    /// [`MftScanError::Unsupported`] when the physical layer's bounds are
    /// inverted, so it addresses nothing at all. Returning an empty record list
    /// there would be a claim about the machine rather than about the
    /// acquisition.
    ///
    /// A layer with *holes* in it is deliberately **not** refused: an
    /// acquisition with gaps is the normal case, and the gaps are accounted for
    /// byte by byte in [`ScanSummary::unread_bytes`], which is a better answer
    /// than refusing to look. A layer with no mapped byte at all therefore
    /// produces an outcome with no records and the whole extent unread, and
    /// [`MftScanOutcome::is_complete`] is false — which is exactly the claim
    /// the evidence supports.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, MftScanError> {
        let min = profile.physical.min_address();
        let max = profile.physical.max_address();
        if min > max {
            return Err(MftScanError::unsupported(format!(
                "the physical layer's lowest address {min:#x} is above its highest address \
                 {max:#x}, so it addresses nothing"
            )));
        }
        Ok(Self {
            physical_min: min,
            physical_max: max,
            pointer_size: profile.pointer_size(),
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "physical_min": self.physical_min,
            "physical_max": self.physical_max,
            "pointer_size": self.pointer_size,
        })
    }
}

/// Caps and geometry for one sweep.
#[derive(Debug, Clone)]
pub struct MftScanConfig {
    /// Bytes read per candidate record.
    pub record_bytes: u64,
    /// Ceiling on records reported.
    pub max_records: usize,
    /// Ceiling on attributes walked per record.
    pub max_attributes: usize,
    /// Ceiling on individually recorded rejections.
    pub max_recorded_rejections: usize,
    /// Ceiling on bytes of resident stream content captured per attribute.
    pub max_resident_bytes: u64,
    /// Geometry for the underlying byte sweep.
    pub scan: ScanConfig,
}

impl Default for MftScanConfig {
    fn default() -> Self {
        Self {
            record_bytes: DEFAULT_RECORD_BYTES,
            max_records: MAX_RECORDS,
            max_attributes: MAX_ATTRIBUTES,
            max_recorded_rejections: MAX_RECORDED_REJECTIONS,
            max_resident_bytes: MAX_RESIDENT_BYTES,
            scan: ScanConfig::default(),
        }
    }
}

// ── Time ────────────────────────────────────────────────────────────────────

/// One of a record's timestamps.
///
/// Three states rather than an `Option`, because a record carved out of memory
/// produces all three and a report must not merge them: NTFS writes zero for a
/// time it did not record, a genuine cached record carries a real time, and a
/// false-positive hit carries eight bytes that are not a time at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MftTime {
    /// The field is zero: NTFS recorded no time here.
    Unset,
    /// The field is outside 1980–2200, so it is not a time any filesystem
    /// wrote. The raw value travels so it can be re-examined.
    Implausible {
        /// The eight bytes, as a number.
        filetime: u64,
    },
    /// A real time.
    Recorded {
        /// 100 ns ticks since 1601-01-01, exactly as the record held it.
        filetime: u64,
        /// The same instant in RFC 3339, UTC. NTFS times are UTC, so unlike
        /// Amcache's install dates this needs no zone from elsewhere.
        rfc3339: String,
    },
}

impl MftTime {
    /// Classify eight bytes as a timestamp.
    pub fn from_filetime(filetime: u64) -> MftTime {
        if filetime == 0 {
            return MftTime::Unset;
        }
        if !(MIN_PLAUSIBLE_FILETIME..=MAX_PLAUSIBLE_FILETIME).contains(&filetime) {
            return MftTime::Implausible { filetime };
        }
        match seance_core::time::filetime_to_rfc3339(filetime) {
            Some(rfc3339) => MftTime::Recorded { filetime, rfc3339 },
            None => MftTime::Implausible { filetime },
        }
    }

    /// Whether this is a time a report may print as one.
    pub fn is_recorded(&self) -> bool {
        matches!(self, MftTime::Recorded { .. })
    }

    /// The raw value, whatever state it is in.
    pub fn filetime(&self) -> u64 {
        match self {
            MftTime::Unset => 0,
            MftTime::Implausible { filetime } | MftTime::Recorded { filetime, .. } => *filetime,
        }
    }

    /// Stable identifier for artifact metadata.
    pub fn status(&self) -> &'static str {
        match self {
            MftTime::Unset => "unset",
            MftTime::Implausible { .. } => "implausible",
            MftTime::Recorded { .. } => "recorded",
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "status": self.status(),
            "filetime": self.filetime(),
            "utc": match self {
                MftTime::Recorded { rfc3339, .. } => Some(rfc3339.clone()),
                _ => None,
            },
        })
    }
}

/// The four NTFS timestamps, in the order examiners say them: MACB.
///
/// `M` modified, `A` accessed, `C` MFT-record changed, `B` born (created). The
/// order matters because the same four fields appear in both
/// `$STANDARD_INFORMATION` and `$FILE_NAME` and are stored in a *different*
/// order from the mnemonic — created first — which is a routine source of
/// swapped columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacbTimes {
    /// `B`: when the file was created.
    pub created: MftTime,
    /// `M`: when the file's data was last written.
    pub modified: MftTime,
    /// `C`: when the MFT record itself last changed.
    pub mft_changed: MftTime,
    /// `A`: when the file was last accessed.
    pub accessed: MftTime,
}

impl MacbTimes {
    /// Read the four timestamps from `bytes` starting at `offset`.
    ///
    /// The on-disk order is created, modified, MFT-changed, accessed — not the
    /// MACB order the fields are named in.
    fn read(bytes: &[u8], offset: usize) -> Option<MacbTimes> {
        Some(MacbTimes {
            created: MftTime::from_filetime(u64_at(bytes, offset)?),
            modified: MftTime::from_filetime(u64_at(bytes, offset.checked_add(8)?)?),
            mft_changed: MftTime::from_filetime(u64_at(bytes, offset.checked_add(16)?)?),
            accessed: MftTime::from_filetime(u64_at(bytes, offset.checked_add(24)?)?),
        })
    }

    /// Whether every one of the four is a time a report may print.
    pub fn all_recorded(&self) -> bool {
        self.created.is_recorded()
            && self.modified.is_recorded()
            && self.mft_changed.is_recorded()
            && self.accessed.is_recorded()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "created": self.created.to_json(),
            "modified": self.modified.to_json(),
            "mft_changed": self.mft_changed.to_json(),
            "accessed": self.accessed.to_json(),
        })
    }
}

// ── Fixups ──────────────────────────────────────────────────────────────────

/// What happened when the update-sequence array was put back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixupState {
    /// Every sector's stashed bytes were restored.
    Applied {
        /// How many sector ends were restored.
        sectors: usize,
    },
    /// At least one sector end did not carry the record's sequence number, so
    /// nothing was restored.
    ///
    /// Common in a memory image and *not* fatal: the page holding a later
    /// sector may have been reused since the record was cached, while the first
    /// sector — the header and usually `$STANDARD_INFORMATION` — is intact.
    /// Everything parsed under this state carries it.
    Mismatch {
        /// The sector whose end did not match, counting from one.
        sector: usize,
        /// The sequence number the record declares.
        expected: u16,
        /// What was actually at that sector's end.
        found: u16,
    },
    /// The record declares an update-sequence array that does not fit inside
    /// it, so no fixup can be applied and the record's own header is suspect.
    Malformed {
        /// What is wrong.
        detail: String,
    },
    /// The record declares no fixup entries at all.
    Absent,
}

impl FixupState {
    /// Whether the record's bytes are the ones NTFS wrote.
    pub fn is_applied(&self) -> bool {
        matches!(self, FixupState::Applied { .. } | FixupState::Absent)
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            FixupState::Applied { .. } => "applied",
            FixupState::Mismatch { .. } => "mismatch",
            FixupState::Malformed { .. } => "malformed",
            FixupState::Absent => "absent",
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            FixupState::Applied { sectors } => {
                serde_json::json!({"state": "applied", "sectors": sectors})
            }
            FixupState::Mismatch {
                sector,
                expected,
                found,
            } => serde_json::json!({
                "state": "mismatch", "sector": sector, "expected": expected, "found": found,
            }),
            FixupState::Malformed { detail } => {
                serde_json::json!({"state": "malformed", "detail": detail})
            }
            FixupState::Absent => serde_json::json!({"state": "absent"}),
        }
    }
}

/// Put the update-sequence array back into a record's bytes.
///
/// Returns what happened. On [`FixupState::Mismatch`] and
/// [`FixupState::Malformed`] the buffer is left exactly as it was read, so a
/// caller can still parse the first sector and can always re-examine the bytes
/// the acquisition actually held.
pub fn apply_fixups(record: &mut [u8], usa_offset: u64, usa_count: u64) -> FixupState {
    if usa_count == 0 {
        return FixupState::Absent;
    }
    let Some(array_bytes) = usa_count.checked_mul(2) else {
        return FixupState::Malformed {
            detail: format!(
                "an update-sequence array of {usa_count} entries does not fit in 64 bits"
            ),
        };
    };
    let Some(array_end) = usa_offset.checked_add(array_bytes) else {
        return FixupState::Malformed {
            detail: "the update-sequence array runs past the end of the address space".to_string(),
        };
    };
    if array_end > record.len() as u64 {
        return FixupState::Malformed {
            detail: format!(
                "the update-sequence array at {usa_offset:#x} needs {array_bytes} byte(s) and the \
                 record holds {}",
                record.len()
            ),
        };
    }
    let Some(sequence) = u16_at(record, usa_offset as usize) else {
        return FixupState::Malformed {
            detail: "the update-sequence number could not be read".to_string(),
        };
    };

    // The array's first entry is the sequence number itself; the rest are the
    // stashed bytes, one pair per sector.
    let sectors = (usa_count - 1) as usize;
    // Verify every sector before writing any: a record half-fixed is worse than
    // one not fixed, because nothing downstream could tell which half.
    for sector in 0..sectors {
        let Some(end) = sector_end_offset(sector, record.len()) else {
            return FixupState::Malformed {
                detail: format!(
                    "sector {} of the record ends past the {} byte(s) that were read",
                    sector + 1,
                    record.len()
                ),
            };
        };
        let Some(found) = u16_at(record, end) else {
            return FixupState::Malformed {
                detail: format!("sector {}'s trailing bytes could not be read", sector + 1),
            };
        };
        if found != sequence {
            return FixupState::Mismatch {
                sector: sector + 1,
                expected: sequence,
                found,
            };
        }
    }
    for sector in 0..sectors {
        let (Some(end), Some(source)) = (
            sector_end_offset(sector, record.len()),
            usa_offset
                .checked_add(2)
                .and_then(|at| at.checked_add((sector as u64).checked_mul(2)?))
                .map(|at| at as usize),
        ) else {
            return FixupState::Malformed {
                detail: "the update-sequence array's replacement bytes could not be located"
                    .to_string(),
            };
        };
        let Some(replacement) = u16_at(record, source) else {
            return FixupState::Malformed {
                detail: format!("sector {}'s stashed bytes could not be read", sector + 1),
            };
        };
        let bytes = replacement.to_le_bytes();
        record[end] = bytes[0];
        record[end + 1] = bytes[1];
    }
    FixupState::Applied { sectors }
}

/// Offset of the two bytes at the end of `sector`, when they are inside a buffer
/// of `len` bytes.
fn sector_end_offset(sector: usize, len: usize) -> Option<usize> {
    let end = sector
        .checked_add(1)?
        .checked_mul(SECTOR_BYTES as usize)?
        .checked_sub(2)?;
    if end.checked_add(2)? > len {
        return None;
    }
    Some(end)
}

// ── Records ─────────────────────────────────────────────────────────────────

/// One `$FILE_NAME` attribute.
///
/// A record normally carries two — the long name and the DOS 8.3 name — and
/// each has its own set of four timestamps. `$FILE_NAME` times are the ones
/// `SetFileTime` cannot reach, which is what the graded comparison in
/// [`MftRecord::timestamp_indicators`] rests on — with the caveat that a
/// copy, move or rename also leaves `$STANDARD_INFORMATION` older than
/// `$FILE_NAME`, so that alone is an observation and not a verdict.
#[derive(Debug, Clone)]
pub struct FileNameAttr {
    /// The name, decoded from UTF-16LE.
    pub name: String,
    /// Which namespace the name is in: `Win32`, `DOS`, `POSIX` or `Win32AndDOS`.
    pub namespace: &'static str,
    /// The raw namespace byte, kept for a value NTFS does not define.
    pub namespace_raw: u8,
    /// MFT record number of the directory holding this name.
    pub parent_record: u64,
    /// Expected sequence number of that directory's record, which is what makes
    /// a stale parent reference detectable.
    pub parent_sequence: u16,
    /// The four timestamps `SetFileTime` does not reach.
    pub times: MacbTimes,
    /// The allocated size the directory entry records.
    pub allocated_size: u64,
    /// The real size the directory entry records.
    pub real_size: u64,
    /// The DOS file-attribute flags.
    pub flags: u32,
}

impl FileNameAttr {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "namespace": self.namespace,
            "namespace_raw": self.namespace_raw,
            "parent_record": self.parent_record,
            "parent_sequence": self.parent_sequence,
            "times": self.times.to_json(),
            "allocated_size": self.allocated_size,
            "real_size": self.real_size,
            "flags": self.flags,
        })
    }
}

/// One `$STANDARD_INFORMATION` attribute.
#[derive(Debug, Clone)]
pub struct StandardInformation {
    /// The four timestamps the Win32 API can set directly.
    pub times: MacbTimes,
    /// The DOS file-attribute flags.
    pub flags: u32,
}

impl StandardInformation {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"times": self.times.to_json(), "flags": self.flags})
    }
}

/// One `$DATA` attribute: the file's contents, or one of its alternate streams.
#[derive(Debug, Clone)]
pub struct DataStream {
    /// The stream's name. `None` is the unnamed default stream — the file's
    /// actual contents. `Some` is an **alternate data stream**.
    pub name: Option<String>,
    /// Whether the content lives outside the record.
    pub non_resident: bool,
    /// The declared content length for a resident stream, or the real size for
    /// a non-resident one.
    ///
    /// `None` when the attribute is shorter than the field holding it. A stream
    /// of unknown size and a stream of zero bytes support opposite conclusions
    /// about whether anything was hidden in it, so they are never merged.
    pub size: Option<u64>,
    /// Resident content, capped by [`MftScanConfig::max_resident_bytes`].
    ///
    /// Present only for a resident stream. A small alternate data stream is
    /// entirely resident, so this is frequently the payload itself.
    pub resident_content: Option<Vec<u8>>,
    /// Whether the captured content was cut short by the cap.
    pub content_truncated: bool,
    /// Where the attribute is, relative to the start of the record.
    pub offset: u64,
}

impl DataStream {
    /// Whether this is an alternate data stream rather than the file's own
    /// contents.
    ///
    /// The distinction is the finding: a named `$DATA` stream is where data is
    /// hidden from every tool that lists files by name.
    pub fn is_alternate(&self) -> bool {
        self.name.is_some()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "alternate": self.is_alternate(),
            "non_resident": self.non_resident,
            "size": self.size,
            "offset": self.offset,
            "resident_bytes": self.resident_content.as_ref().map(Vec::len),
            "resident_content_hex": self
                .resident_content
                .as_ref()
                .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()),
            "content_truncated": self.content_truncated,
        })
    }
}

/// Why an attribute walk stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeStop {
    /// The end-of-attributes marker was reached.
    EndMarker,
    /// The attributes ran to the end of the bytes that were read.
    EndOfRecord,
    /// The attribute cap fired. The walk stopped; the record did not end.
    CapReached {
        /// The cap that fired.
        cap: usize,
    },
    /// An attribute header was not self-consistent, so the ones after it could
    /// not be located.
    Malformed {
        /// What is wrong.
        detail: String,
    },
}

impl AttributeStop {
    /// Whether every attribute in the record was walked.
    pub fn is_complete(&self) -> bool {
        matches!(self, AttributeStop::EndMarker | AttributeStop::EndOfRecord)
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            AttributeStop::EndMarker => "end_marker",
            AttributeStop::EndOfRecord => "end_of_record",
            AttributeStop::CapReached { .. } => "cap_reached",
            AttributeStop::Malformed { .. } => "malformed",
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "stop": self.as_str(),
            "detail": match self {
                AttributeStop::Malformed { detail } => Some(detail.clone()),
                AttributeStop::CapReached { cap } => Some(format!("the cap of {cap} attributes fired")),
                _ => None,
            },
        })
    }
}

/// One MFT record recovered from memory.
#[derive(Debug, Clone)]
pub struct MftRecord {
    /// Where the record starts, in the **physical** address space. Physical
    /// because that is where it was found; a cached record has no meaningful
    /// virtual address of its own.
    pub address: u64,
    /// `"FILE"` or `"BAAD"`.
    pub signature: String,
    /// Whether the record is allocated to a file that still exists.
    pub in_use: bool,
    /// Whether the record describes a directory.
    pub is_directory: bool,
    /// The raw flag word, so a bit NTFS does not define is still visible.
    pub flags: u16,
    /// The record's own number, on NTFS 3.1. `None` on earlier volumes, whose
    /// header is six bytes shorter and carries no such field — which must never
    /// render as record zero, the `$MFT` itself.
    pub record_number: Option<u32>,
    /// The record's sequence number, incremented each time it is reused.
    pub sequence: u16,
    /// How many directory entries point at this record.
    pub link_count: u16,
    /// The base record this one extends, or 0 when it is itself a base record.
    pub base_record: u64,
    /// The log-file sequence number of the last change to this record.
    pub lsn: u64,
    /// Bytes the record declares it is using.
    pub used_size: u32,
    /// Bytes the record declares are allocated to it.
    pub allocated_size: u32,
    /// What happened to the update-sequence array.
    pub fixups: FixupState,
    /// How many of the record's bytes were actually read. Below
    /// [`MftScanConfig::record_bytes`] when the acquisition ends inside it.
    pub bytes_read: u64,
    /// The `$STANDARD_INFORMATION` attribute.
    pub standard_information: Option<StandardInformation>,
    /// Every `$FILE_NAME` attribute.
    pub file_names: Vec<FileNameAttr>,
    /// Every `$DATA` attribute, named and unnamed.
    pub data_streams: Vec<DataStream>,
    /// Why the attribute walk stopped.
    pub attribute_stop: AttributeStop,
    /// Everything odd about the record that did not disqualify it.
    pub notes: Vec<String>,
}

impl MftRecord {
    /// The longest `$FILE_NAME`, which is the long name where the record has
    /// both a long name and a DOS 8.3 name.
    pub fn longest_name(&self) -> Option<&str> {
        self.file_names
            .iter()
            .max_by_key(|name| name.name.chars().count())
            .map(|name| name.name.as_str())
    }

    /// The record's alternate data streams.
    pub fn alternate_data_streams(&self) -> impl Iterator<Item = &DataStream> {
        self.data_streams.iter().filter(|data| data.is_alternate())
    }

    /// The graded `$STANDARD_INFORMATION` / `$FILE_NAME` comparison, the same
    /// rule the on-disk MFT parser applies
    /// ([`seance_core::ntfs_timestamps::detect_timestomp_indicators`]).
    ///
    /// This used to be one test — `$SI` Created earlier than `$FN` Created —
    /// reported as `timestomp_suspected`. That is what every moved or renamed
    /// file looks like, and on the domain controller's memory in DFIR Madness
    /// Case 001 it flagged 14,649 of 25,537 records (57%) while the one file
    /// the answer key names as timestomped sat among them (HUNT-073, the
    /// HUNT-051 class). Only a recorded time takes part; an unset or
    /// implausible field is simply absent from the comparison.
    pub fn timestamp_indicators(&self) -> Vec<TimestompIndicator> {
        let Some(standard) = self.standard_information.as_ref() else {
            return Vec::new();
        };
        let recorded = |t: &MftTime| t.is_recorded().then(|| t.filetime());
        let entry_created = self
            .file_names
            .iter()
            .find(|name| name.times.created.is_recorded())
            .map(|name| name.times.created.filetime());
        detect_timestomp_indicators(
            recorded(&standard.times.created),
            recorded(&standard.times.modified),
            recorded(&standard.times.mft_changed),
            recorded(&standard.times.accessed),
            entry_created,
        )
    }

    /// The verdict: a strong indicator, one no ordinary copy, move or rename
    /// produces. `None` when the record has no `$SI` or no recorded `$FN`
    /// Created to compare against — "could not tell", not "no".
    pub fn timestomp_suspected(&self) -> Option<bool> {
        let standard = self.standard_information.as_ref()?;
        standard.times.created.is_recorded().then_some(())?;
        self.file_names
            .iter()
            .find(|name| name.times.created.is_recorded())?;
        Some(self.timestamp_indicators().iter().any(|i| i.strong))
    }

    /// Whether everything in this record was read as NTFS wrote it.
    pub fn is_complete(&self) -> bool {
        self.fixups.is_applied() && self.attribute_stop.is_complete()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "signature": self.signature,
            "in_use": self.in_use,
            "is_directory": self.is_directory,
            "flags": self.flags,
            "record_number": self.record_number,
            "sequence": self.sequence,
            "link_count": self.link_count,
            "base_record": self.base_record,
            "lsn": self.lsn,
            "used_size": self.used_size,
            "allocated_size": self.allocated_size,
            "bytes_read": self.bytes_read,
            "fixups": self.fixups.to_json(),
            "name": self.longest_name(),
            "standard_information": self.standard_information.as_ref().map(StandardInformation::to_json),
            "file_names": self.file_names.iter().map(FileNameAttr::to_json).collect::<Vec<_>>(),
            "data_streams": self.data_streams.iter().map(DataStream::to_json).collect::<Vec<_>>(),
            "alternate_data_stream_count": self.alternate_data_streams().count(),
            "timestomp_suspected": self.timestomp_suspected(),
            "timestamp_indicators": self.timestamp_indicators().iter().map(|i| serde_json::json!({
                "reason": i.reason,
                "strength": if i.strong { "strong" } else { "weak" },
                "also_produced_by": i.benign_explanation,
            })).collect::<Vec<_>>(),
            "attribute_stop": self.attribute_stop.to_json(),
            "complete": self.is_complete(),
            "notes": self.notes,
        })
    }
}

/// Where one record's file sat on the volume, as far as the sweep can prove it.
///
/// `complete` is the whole of the claim: true only when the walk reached the
/// volume root, so a path that stops early is never read as a full one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathResolution {
    /// The path, leading `\\` for a complete one; for a partial walk, the
    /// components that are known, deepest last.
    pub path: String,
    /// True only when the chain reached the root directory (record 5).
    pub complete: bool,
    /// Why the walk stopped short, when it did.
    pub note: Option<String>,
}

/// NTFS record number of the volume root directory.
const ROOT_RECORD: u64 = 5;

/// How far up a parent chain to walk before calling it a cycle. Deeper than any
/// real path and shallow enough that a corrupt chain cannot spin.
const MAX_PATH_DEPTH: usize = 64;

/// The `$FILE_NAME` a path should be built from: the Win32 (long) name where
/// the record has one, since that is the name a person would recognise, and
/// otherwise whatever name it does carry.
fn preferred_file_name(record: &MftRecord) -> Option<&FileNameAttr> {
    record
        .file_names
        .iter()
        .find(|f| f.namespace == "Win32" || f.namespace == "Win32AndDOS")
        .or_else(|| record.file_names.first())
}

/// Walk one record up to the root, through the records the sweep recovered.
fn resolve_one_path(
    record: &MftRecord,
    by_number: &std::collections::HashMap<u32, &MftRecord>,
) -> Option<PathResolution> {
    let leaf = preferred_file_name(record)?;
    let mut components: Vec<String> = vec![leaf.name.clone()];
    let mut parent = (leaf.parent_record, leaf.parent_sequence);
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    if let Some(n) = record.record_number {
        seen.insert(u64::from(n));
    }

    for _ in 0..MAX_PATH_DEPTH {
        let (number, sequence) = parent;
        if number == ROOT_RECORD {
            components.reverse();
            return Some(PathResolution {
                path: format!("\\{}", components.join("\\")),
                complete: true,
                note: None,
            });
        }
        if !seen.insert(number) {
            return Some(partial(components, format!(
                "the parent chain returns to record {number}, which is a cycle no directory tree has; the walk stopped there"
            )));
        }
        // Record numbers are 32-bit; a parent reference that does not fit is
        // not a record this volume has.
        let Ok(number32) = u32::try_from(number) else {
            return Some(partial(
                components,
                format!(
                "the parent reference {number} is not a record number this volume can hold, so \
                 the path above this point cannot be read"
            ),
            ));
        };
        let Some(dir) = by_number.get(&number32) else {
            return Some(partial(components, format!(
                "record {number} is this file's parent directory and the sweep did not recover it, so the path above this point is not in the evidence"
            )));
        };
        // The slot may since have been reused. A parent on a different sequence
        // is a DIFFERENT file, and walking through it would build a path out of
        // another file's ancestry.
        if dir.sequence != sequence {
            return Some(partial(components, format!(
                "record {number} is now on sequence {} but this file recorded it at {sequence}, so that slot holds a different directory than the one it was created under and the path above this point would be another file's",
                dir.sequence
            )));
        }
        let Some(dir_name) = preferred_file_name(dir) else {
            return Some(partial(components, format!(
                "record {number} is this file's parent and carries no name, so the path above this point cannot be read"
            )));
        };
        components.push(dir_name.name.clone());
        parent = (dir_name.parent_record, dir_name.parent_sequence);
    }
    Some(partial(
        components,
        format!("the parent chain is deeper than the {MAX_PATH_DEPTH} levels this walk admits"),
    ))
}

/// A path the walk could not finish: what is known, deepest last, and why.
fn partial(mut components: Vec<String>, note: String) -> PathResolution {
    components.reverse();
    PathResolution {
        path: components.join("\\"),
        complete: false,
        note: Some(note),
    }
}

/// One alternate data stream, as a finding in its own right.
///
/// Separate from the record because that is how an examiner asks the question:
/// "what alternate data streams were in memory?", not "which records had a
/// named `$DATA` attribute". The host file's name travels with it, because an
/// ADS with no host name is not actionable.
#[derive(Debug, Clone)]
pub struct AdsFinding {
    /// Physical address of the record holding it.
    pub record_address: u64,
    /// The record's number, where the volume records one.
    pub record_number: Option<u32>,
    /// The host file's longest name.
    pub host_name: Option<String>,
    /// The stream's name — the part after the colon in `file.txt:stream`.
    pub stream_name: String,
    /// Whether the stream's content lives outside the record.
    pub non_resident: bool,
    /// The stream's declared size, or `None` when the attribute was too short
    /// to hold the field. Never rendered as zero, which would read as an empty
    /// stream.
    pub size: Option<u64>,
    /// Resident content, when the stream is small enough to live in the record.
    pub resident_content: Option<Vec<u8>>,
    /// Whether the captured content was cut short.
    pub content_truncated: bool,
}

impl AdsFinding {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "record_address": self.record_address,
            "record_number": self.record_number,
            "host_name": self.host_name,
            "stream_name": self.stream_name,
            "full_name": self
                .host_name
                .as_ref()
                .map(|host| format!("{host}:{}", self.stream_name)),
            "non_resident": self.non_resident,
            "size": self.size,
            "resident_bytes": self.resident_content.as_ref().map(Vec::len),
            "resident_content_hex": self
                .resident_content
                .as_ref()
                .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()),
            "content_truncated": self.content_truncated,
        })
    }
}

/// Why a candidate was not reported as a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectionReason {
    /// The five bytes matched and nothing else about the candidate holds up.
    ///
    /// Expected and normal: the needles are five bytes and memory is large.
    /// Counted rather than dropped so the ratio of records to false positives
    /// is visible.
    NotARecord,
    /// The candidate's bytes were not acquired, so it could not be examined.
    ///
    /// A gap in the evidence, and the only rejection that counts against the
    /// sweep being complete.
    Unreadable,
}

impl RejectionReason {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            RejectionReason::NotARecord => "not_a_record",
            RejectionReason::Unreadable => "unreadable",
        }
    }
}

/// One candidate that was not reported as a record.
#[derive(Debug, Clone)]
pub struct Rejected {
    /// Where the candidate was.
    pub address: u64,
    /// Which kind of rejection.
    pub reason: RejectionReason,
    /// Why, in the examiner's terms.
    pub detail: String,
}

impl Rejected {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "reason": self.reason.as_str(),
            "detail": self.detail,
        })
    }
}

/// What the underlying byte sweep covered.
///
/// The scanner's hit list is not kept — a sweep of a large image produces
/// millions of five-byte matches and holding them would cost more memory than
/// the records themselves — but everything needed to say what was and was not
/// examined is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanSummary {
    /// How many candidates the sweep produced.
    pub hits: usize,
    /// Distinct bytes examined.
    pub bytes_scanned: u64,
    /// Bytes that could not be examined.
    pub unread_bytes: u64,
    /// How many distinct unread ranges were recorded.
    pub unread_ranges: usize,
    /// Whether the unread *range list* was capped. The byte total stays exact.
    pub unread_truncated: bool,
    /// Whether the sweep itself stopped early.
    pub truncated: bool,
}

impl ScanSummary {
    /// Summarise a scan outcome, dropping only its hit list.
    pub fn of(outcome: &ScanOutcome) -> Self {
        Self {
            hits: outcome.hits.len(),
            bytes_scanned: outcome.bytes_scanned,
            unread_bytes: outcome.unread_bytes,
            unread_ranges: outcome.unread.len(),
            unread_truncated: outcome.unread_truncated,
            truncated: outcome.truncated,
        }
    }

    /// Whether every mapped byte was examined.
    pub fn is_complete(&self) -> bool {
        !self.truncated && self.unread_bytes == 0
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "hits": self.hits,
            "bytes_scanned": self.bytes_scanned,
            "unread_bytes": self.unread_bytes,
            "unread_ranges": self.unread_ranges,
            "unread_truncated": self.unread_truncated,
            "truncated": self.truncated,
            "complete": self.is_complete(),
        })
    }
}

/// Everything one sweep recovered, and everything it could not.
#[derive(Debug, Clone)]
pub struct MftScanOutcome {
    /// The records, in ascending physical address order.
    pub records: Vec<MftRecord>,
    /// How many records were found in total, exact even when the list above was
    /// capped.
    pub records_total: usize,
    /// Whether the record cap fired.
    pub truncated: bool,
    /// Candidates that were not records, capped by
    /// [`MftScanConfig::max_recorded_rejections`].
    pub rejected: Vec<Rejected>,
    /// How many candidates were rejected in total.
    pub rejected_total: usize,
    /// How many candidates were rejected because their bytes were not acquired.
    ///
    /// Separate from the total because it is the only kind that counts against
    /// the sweep being complete.
    pub unreadable_total: usize,
    /// What the byte sweep covered.
    pub scan: ScanSummary,
}

impl MftScanOutcome {
    /// Every alternate data stream, as findings in their own right.
    pub fn alternate_data_streams(&self) -> Vec<AdsFinding> {
        let mut out = Vec::new();
        for record in &self.records {
            let host_name = record.longest_name().map(str::to_string);
            for stream in record.alternate_data_streams() {
                let Some(stream_name) = stream.name.clone() else {
                    continue;
                };
                out.push(AdsFinding {
                    record_address: record.address,
                    record_number: record.record_number,
                    host_name: host_name.clone(),
                    stream_name,
                    non_resident: stream.non_resident,
                    size: stream.size,
                    resident_content: stream.resident_content.clone(),
                    content_truncated: stream.content_truncated,
                });
            }
        }
        out
    }

    /// Records carrying a strong timestamp indicator — the verdict, not the
    /// weak observations every moved file carries.
    pub fn timestomp_candidates(&self) -> impl Iterator<Item = &MftRecord> {
        self.records
            .iter()
            .filter(|record| record.timestomp_suspected() == Some(true))
    }

    /// Whether the sweep examined every mapped byte and read every record it
    /// found.
    ///
    /// The question a report must ask before writing "no MFT record for that
    /// file was in memory".
    pub fn is_complete(&self) -> bool {
        self.scan.is_complete()
            && !self.truncated
            && self.unreadable_total == 0
            && self.records.iter().all(MftRecord::is_complete)
    }

    /// Everything a report must declare about this sweep.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if self.scan.truncated {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                "the physical sweep for MFT records stopped at a cap, so part of memory was not \
                 examined"
                    .to_string(),
            ));
        }
        if self.scan.unread_bytes > 0 {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{} byte(s) of physical memory could not be examined for MFT records",
                    self.scan.unread_bytes
                ),
            ));
        }
        if self.truncated {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "{} MFT record(s) were found and the listing stopped at its cap; more remain",
                    self.records_total
                ),
            ));
        }
        if self.unreadable_total > 0 {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{} MFT record signature(s) were found at addresses whose bytes were not \
                     acquired, so those records could not be read",
                    self.unreadable_total
                ),
            ));
        }
        let torn = self
            .records
            .iter()
            .filter(|record| !record.is_complete())
            .count();
        if torn > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{torn} MFT record(s) were read with unverified update-sequence fixups or an \
                     attribute list that could not be walked to its end"
                ),
            ));
        }
        out
    }

    /// Where each record's file sat, reconstructed by chaining `$FILE_NAME`
    /// parent references through the records this sweep recovered.
    ///
    /// A pool sweep finds records scattered, not a directory tree, so a name on
    /// its own does not say where the file was — and "where" is usually the
    /// question. Each record carries its parent's record number and the
    /// sequence that number must still be on, which is enough to walk upward
    /// through the other records the sweep found.
    ///
    /// What it will not do is guess. The sweep is a scan: a parent may simply
    /// not have been recovered, and an MFT slot may since have been reused for
    /// a different file. Both end the walk and are said, so a partial path is
    /// never presented as a whole one:
    ///
    /// * reaching record 5 (the volume root) gives a complete path;
    /// * a parent the sweep did not recover gives the tail that is known, and
    ///   `complete: false` naming the record the trail stops at;
    /// * a parent whose sequence no longer matches the one the child recorded
    ///   means that slot holds a *different* file now, so the rest of the path
    ///   would be another file's — the walk stops and says so.
    pub fn resolve_paths(&self) -> Vec<Option<PathResolution>> {
        use std::collections::HashMap;
        // First occurrence wins: the same record can be in pool at several
        // addresses, and they are copies of one record, not distinct files.
        let mut by_number: HashMap<u32, &MftRecord> = HashMap::new();
        for record in &self.records {
            if let Some(n) = record.record_number {
                by_number.entry(n).or_insert(record);
            }
        }
        self.records
            .iter()
            .map(|record| resolve_one_path(record, &by_number))
            .collect()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        let paths = self.resolve_paths();
        serde_json::json!({
            "records": self
                .records
                .iter()
                .zip(paths.iter())
                .map(|(r, p)| {
                    let mut value = r.to_json();
                    if let (Some(obj), Some(p)) = (value.as_object_mut(), p.as_ref()) {
                        obj.insert("path".to_string(), serde_json::json!(p.path));
                        obj.insert("path_complete".to_string(), serde_json::json!(p.complete));
                        if let Some(note) = &p.note {
                            obj.insert("path_note".to_string(), serde_json::json!(note));
                        }
                    }
                    value
                })
                .collect::<Vec<_>>(),
            "record_count": self.records.len(),
            "records_total": self.records_total,
            "truncated": self.truncated,
            "alternate_data_streams": self
                .alternate_data_streams()
                .iter()
                .map(AdsFinding::to_json)
                .collect::<Vec<_>>(),
            "timestomp_candidates": self.timestomp_candidates().count(),
            "rejected": self.rejected.iter().map(Rejected::to_json).collect::<Vec<_>>(),
            "rejected_total": self.rejected_total,
            "unreadable_total": self.unreadable_total,
            "scan": self.scan.to_json(),
            "complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

// ── The sweep ───────────────────────────────────────────────────────────────

/// Sweep physical memory for MFT records and parse every one that checks out.
///
/// # What an examiner learns
///
/// File names, MACB timestamps and alternate data streams for files whose MFT
/// records were in the cache when the image was taken — including files that
/// have since been deleted from disk, and files whose on-disk records have been
/// overwritten. Because `$FILE_NAME` timestamps cannot be set through the Win32
/// API, comparing them against `$STANDARD_INFORMATION` can detect
/// timestomping; [`MftScanOutcome::timestomp_candidates`] applies the graded
/// comparison and counts only the records with a strong indicator.
///
/// # What a wrong answer looks like
///
/// A five-byte needle matches random memory. A decoder that trusts every hit
/// invents files with names read out of unrelated data and timestamps in the
/// seventeenth century, and those inventions land in a timeline beside real
/// evidence. Every candidate here is checked against the record's own header
/// before any field is read, every offset is bounds-checked against the bytes
/// that were actually acquired, and every timestamp outside 1980–2200 is
/// reported as [`MftTime::Implausible`] rather than rendered as a date.
///
/// # Errors
///
/// Only for failures that make the whole sweep meaningless: a physical layer
/// with nothing mapped in it, or a scanner geometry that cannot produce a
/// correct walk. A region that could not be read is *not* an error — it lands
/// in [`ScanSummary::unread_bytes`], where an examiner can see what was missed.
pub fn scan_mft_records(
    profile: &WindowsProfile,
    symbols: &MftScanSymbols,
    config: &MftScanConfig,
) -> Result<MftScanOutcome, MftScanError> {
    if config.record_bytes < MIN_RECORD_HEADER_BYTES {
        return Err(MftScanError::unsupported(format!(
            "a record size of {} byte(s) cannot hold even an MFT record header, which is \
             {MIN_RECORD_HEADER_BYTES}",
            config.record_bytes
        )));
    }
    let scanner = MultiStringScanner::new("mft-record", RECORD_NEEDLES)?;
    // The sweep is bounded by the extent [`MftScanSymbols::from_profile`]
    // established, so a report can state exactly which range of physical memory
    // the answer covers rather than "the image".
    let sweep = symbols.physical_min..symbols.physical_max.saturating_add(1);
    let scan = scan_range(profile.physical.as_ref(), &scanner, sweep, &config.scan)?;

    let reader = StructReader::new(Arc::clone(&profile.physical), Arc::clone(&profile.symbols));
    let mut outcome = MftScanOutcome {
        records: Vec::new(),
        records_total: 0,
        truncated: false,
        rejected: Vec::new(),
        rejected_total: 0,
        unreadable_total: 0,
        scan: ScanSummary::of(&scan),
    };

    for hit in &scan.hits {
        match read_record(&reader, config, hit.address) {
            Ok(record) => {
                outcome.records_total = outcome.records_total.saturating_add(1);
                if outcome.records.len() >= config.max_records {
                    outcome.truncated = true;
                    continue;
                }
                outcome.records.push(record);
            }
            Err(rejected) => {
                outcome.rejected_total = outcome.rejected_total.saturating_add(1);
                if rejected.reason == RejectionReason::Unreadable {
                    outcome.unreadable_total = outcome.unreadable_total.saturating_add(1);
                }
                if outcome.rejected.len() < config.max_recorded_rejections {
                    outcome.rejected.push(rejected);
                }
            }
        }
    }
    Ok(outcome)
}

/// Read and parse one candidate.
///
/// `Err` is a *rejection*, not a failure: the address held five bytes that
/// matched a needle and either nothing else about it holds up or its bytes were
/// never acquired. The caller counts those; it does not abandon the sweep.
fn read_record(
    reader: &StructReader,
    config: &MftScanConfig,
    address: u64,
) -> Result<MftRecord, Rejected> {
    // A record at the very end of a truncated acquisition still has a readable
    // header and first sector, and that is where the name and the timestamps
    // live. Falling back to one sector recovers it instead of losing it.
    let (mut bytes, bytes_read) = match reader.read_bytes(address, config.record_bytes) {
        Ok(bytes) => {
            let read = bytes.len() as u64;
            (bytes, read)
        }
        Err(_) => match reader.read_bytes(address, SECTOR_BYTES.min(config.record_bytes)) {
            Ok(bytes) => {
                let read = bytes.len() as u64;
                (bytes, read)
            }
            Err(err) => {
                return Err(Rejected {
                    address,
                    reason: RejectionReason::Unreadable,
                    detail: format!(
                        "the {} byte(s) an MFT record occupies were not acquired: {err}",
                        config.record_bytes
                    ),
                })
            }
        },
    };
    let mut notes = Vec::new();
    if bytes_read < config.record_bytes {
        notes.push(format!(
            "only {bytes_read} of the record's {} byte(s) were acquired, so attributes past that \
             point are not listed",
            config.record_bytes
        ));
    }

    let signature = match bytes.get(..4) {
        Some(raw) if raw == SIGNATURE_FILE || raw == SIGNATURE_BAAD => {
            String::from_utf8_lossy(raw).into_owned()
        }
        Some(raw) => {
            return Err(Rejected {
                address,
                reason: RejectionReason::NotARecord,
                detail: format!("the four bytes {raw:02x?} are neither 'FILE' nor 'BAAD'"),
            })
        }
        None => {
            return Err(Rejected {
                address,
                reason: RejectionReason::Unreadable,
                detail: "fewer than four bytes were acquired at the candidate".to_string(),
            })
        }
    };

    let reject = |detail: String| Rejected {
        address,
        reason: RejectionReason::NotARecord,
        detail,
    };

    let usa_offset = u64::from(u16_at(&bytes, 4).ok_or_else(|| {
        reject("the record is too short to hold its update-sequence offset".to_string())
    })?);
    let usa_count = u64::from(u16_at(&bytes, 6).ok_or_else(|| {
        reject("the record is too short to hold its update-sequence count".to_string())
    })?);
    let first_attr_offset = u64::from(u16_at(&bytes, 0x14).ok_or_else(|| {
        reject("the record is too short to hold its first-attribute offset".to_string())
    })?);

    // Three header checks that random memory almost never passes together.
    if usa_offset < MIN_USA_OFFSET || usa_offset >= config.record_bytes {
        return Err(reject(format!(
            "the update-sequence offset {usa_offset:#x} is not inside a {}-byte record",
            config.record_bytes
        )));
    }
    if usa_count == 0 || usa_count > config.record_bytes / SECTOR_BYTES + 1 {
        return Err(reject(format!(
            "an update-sequence count of {usa_count} does not match a {}-byte record of \
             {SECTOR_BYTES}-byte sectors",
            config.record_bytes
        )));
    }
    if first_attr_offset < MIN_USA_OFFSET || first_attr_offset >= config.record_bytes {
        return Err(reject(format!(
            "the first attribute offset {first_attr_offset:#x} is not inside a {}-byte record",
            config.record_bytes
        )));
    }
    if first_attr_offset % 8 != 0 {
        return Err(reject(format!(
            "the first attribute offset {first_attr_offset:#x} is not eight-byte aligned, and \
             every NTFS attribute is"
        )));
    }

    let fixups = apply_fixups(&mut bytes, usa_offset, usa_count);
    if let FixupState::Mismatch {
        sector,
        expected,
        found,
    } = &fixups
    {
        notes.push(format!(
            "sector {sector} ends with {found:#06x} where the record's update sequence is \
             {expected:#06x}, so the record's later sectors are not the ones NTFS wrote; fields \
             read from them are reported with that caveat"
        ));
    }

    let sequence = u16_at(&bytes, 0x10).unwrap_or(0);
    let link_count = u16_at(&bytes, 0x12).unwrap_or(0);
    let flags = u16_at(&bytes, 0x16).unwrap_or(0);
    let used_size = u32_at(&bytes, 0x18).unwrap_or(0);
    let allocated_size = u32_at(&bytes, 0x1C).unwrap_or(0);
    let base_record = u64_at(&bytes, 0x20).unwrap_or(0) & 0x0000_FFFF_FFFF_FFFF;
    let lsn = u64_at(&bytes, 8).unwrap_or(0);
    // `RecordNumber` only exists on NTFS 3.1, whose header is 0x30 bytes.
    // Reading it on an older volume returns whatever the first attribute's type
    // field happens to be, and rendering that as a record number is a claim
    // about which file this is.
    let record_number = if usa_offset >= NTFS31_USA_OFFSET {
        u32_at(&bytes, 0x2C)
    } else {
        notes.push(
            "this volume predates NTFS 3.1, whose header carries the record's own number, so the \
             record number is not recorded"
                .to_string(),
        );
        None
    };
    if u64::from(used_size) > bytes_read && bytes_read == config.record_bytes {
        notes.push(format!(
            "the record declares {used_size} byte(s) in use, more than the {bytes_read} it \
             occupies"
        ));
    }

    let mut record = MftRecord {
        address,
        signature,
        in_use: flags & RECORD_FLAG_IN_USE != 0,
        is_directory: flags & RECORD_FLAG_DIRECTORY != 0,
        flags,
        record_number,
        sequence,
        link_count,
        base_record,
        lsn,
        used_size,
        allocated_size,
        fixups,
        bytes_read,
        standard_information: None,
        file_names: Vec::new(),
        data_streams: Vec::new(),
        attribute_stop: AttributeStop::EndOfRecord,
        notes,
    };
    walk_attributes(&bytes, first_attr_offset, config, &mut record);
    Ok(record)
}

/// Walk a record's attribute chain.
fn walk_attributes(
    bytes: &[u8],
    first_attr_offset: u64,
    config: &MftScanConfig,
    record: &mut MftRecord,
) {
    let mut offset = first_attr_offset as usize;
    let mut seen = 0usize;

    loop {
        if seen >= config.max_attributes {
            record.attribute_stop = AttributeStop::CapReached {
                cap: config.max_attributes,
            };
            return;
        }
        // The end marker is four bytes; a record whose attributes run to the
        // end of the acquired bytes without one simply ends there.
        let Some(attr_type) = u32_at(bytes, offset) else {
            record.attribute_stop = AttributeStop::EndOfRecord;
            return;
        };
        if attr_type == ATTR_END {
            record.attribute_stop = AttributeStop::EndMarker;
            return;
        }
        seen = seen.saturating_add(1);

        let Some(length) = u32_at(bytes, offset.saturating_add(4)).map(|value| value as usize)
        else {
            record.attribute_stop = AttributeStop::Malformed {
                detail: format!("the attribute at {offset:#x} has no readable length"),
            };
            return;
        };
        // A zero or unaligned length cannot locate the next attribute, and a
        // loop that kept going on one would never advance.
        if length == 0 || length % 8 != 0 {
            record.attribute_stop = AttributeStop::Malformed {
                detail: format!(
                    "the attribute at {offset:#x} declares a length of {length}, which cannot \
                     locate the next attribute"
                ),
            };
            return;
        }
        let Some(end) = offset.checked_add(length) else {
            record.attribute_stop = AttributeStop::Malformed {
                detail: format!("the attribute at {offset:#x} ends past the address space"),
            };
            return;
        };
        if end > bytes.len() {
            record.attribute_stop = AttributeStop::Malformed {
                detail: format!(
                    "the attribute at {offset:#x} declares {length} byte(s) and only {} were \
                     acquired",
                    bytes.len().saturating_sub(offset)
                ),
            };
            return;
        }
        let attribute = &bytes[offset..end];
        decode_attribute(attribute, attr_type, offset as u64, config, record);
        offset = end;
    }
}

/// Decode one attribute into the record.
fn decode_attribute(
    attribute: &[u8],
    attr_type: u32,
    offset: u64,
    config: &MftScanConfig,
    record: &mut MftRecord,
) {
    let non_resident = matches!(attribute.get(8), Some(flag) if *flag != 0);
    let name_length = u64::from(attribute.get(9).copied().unwrap_or(0));
    let name_offset = u64::from(u16_at(attribute, 0x0A).unwrap_or(0));

    let name = if name_length == 0 {
        None
    } else {
        match utf16_at(attribute, name_offset, name_length.saturating_mul(2)) {
            Some(name) => Some(name),
            None => {
                record.notes.push(format!(
                    "the attribute at {offset:#x} declares a {name_length}-character name at \
                     {name_offset:#x} that does not fit inside it, so the name is not reported"
                ));
                None
            }
        }
    };

    if non_resident {
        if attr_type == ATTR_DATA {
            // The real size of a non-resident stream, at 0x30 of the
            // non-resident header. `None`, not zero, when the attribute is too
            // short to hold it: an alternate data stream reported as zero bytes
            // reads as one with nothing hidden in it.
            let size = u64_at(attribute, 0x30);
            if size.is_none() {
                record.notes.push(format!(
                    "the non-resident $DATA at {offset:#x} is {} byte(s) long, too short to hold \
                     the field giving the stream's real size, so the size is not reported",
                    attribute.len()
                ));
            }
            record.data_streams.push(DataStream {
                name,
                non_resident: true,
                size,
                resident_content: None,
                content_truncated: false,
                offset,
            });
        }
        return;
    }

    // Both of these have to be *read*, not defaulted. Defaulting them to zero
    // makes a resident attribute too short to hold its own header decode as one
    // with zero bytes of content at offset zero, which every attribute type
    // below then parses as an empty-but-valid stream or a missing timestamp.
    let (Some(content_size), Some(content_offset)) = (
        u32_at(attribute, 0x10).map(u64::from),
        u16_at(attribute, 0x14).map(u64::from),
    ) else {
        record.notes.push(format!(
            "the resident attribute at {offset:#x} is {} byte(s) long, too short to hold the \
             offset and length of its own content, so it was not decoded",
            attribute.len()
        ));
        return;
    };
    let Some(content) = slice_at(attribute, content_offset, content_size) else {
        record.notes.push(format!(
            "the resident attribute at {offset:#x} declares {content_size} byte(s) of content at \
             {content_offset:#x}, which does not fit inside it"
        ));
        return;
    };

    match attr_type {
        ATTR_STANDARD_INFORMATION => match parse_standard_information(content) {
            Some(standard) => {
                if record.standard_information.is_some() {
                    record.notes.push(format!(
                        "a second $STANDARD_INFORMATION attribute at {offset:#x} was ignored; a \
                         record has exactly one"
                    ));
                } else {
                    record.standard_information = Some(standard);
                }
            }
            None => record.notes.push(format!(
                "the $STANDARD_INFORMATION at {offset:#x} holds {} byte(s), fewer than the 32 its \
                 four timestamps need",
                content.len()
            )),
        },
        ATTR_FILE_NAME => match parse_file_name(content) {
            Some(file_name) => record.file_names.push(file_name),
            None => record.notes.push(format!(
                "the $FILE_NAME at {offset:#x} could not be decoded from the {} byte(s) it \
                 declares",
                content.len()
            )),
        },
        ATTR_DATA => {
            let capped = content_size > config.max_resident_bytes;
            let take = content.len().min(config.max_resident_bytes as usize);
            record.data_streams.push(DataStream {
                name,
                non_resident: false,
                size: Some(content_size),
                resident_content: Some(content[..take].to_vec()),
                content_truncated: capped,
                offset,
            });
        }
        _ => {}
    }
}

/// Parse a `$STANDARD_INFORMATION` attribute's content.
///
/// Offsets are the NTFS format's: four FILETIMEs from zero, then the DOS
/// attribute flags. Nothing here comes from a symbol table because nothing
/// declares it; every read is bounds-checked against the content that was
/// actually acquired.
pub fn parse_standard_information(content: &[u8]) -> Option<StandardInformation> {
    let times = MacbTimes::read(content, 0)?;
    Some(StandardInformation {
        times,
        flags: u32_at(content, 0x20).unwrap_or(0),
    })
}

/// Parse a `$FILE_NAME` attribute's content.
///
/// The layout, from zero: the parent directory's file reference (8), four
/// FILETIMEs (32), allocated and real size (16), flags and reparse tag (8), the
/// name's length in **characters** (1), its namespace (1), then the name in
/// UTF-16LE.
///
/// The name length being a character count and not a byte count is the field
/// most often got wrong; reading `NameLength` bytes rather than `NameLength * 2`
/// truncates every name to half its length and can split a surrogate pair.
pub fn parse_file_name(content: &[u8]) -> Option<FileNameAttr> {
    let parent = u64_at(content, 0)?;
    let times = MacbTimes::read(content, 8)?;
    let allocated_size = u64_at(content, 0x28)?;
    let real_size = u64_at(content, 0x30)?;
    let flags = u32_at(content, 0x38)?;
    let name_chars = u64::from(*content.get(0x40)?);
    let namespace_raw = *content.get(0x41)?;
    if name_chars == 0 || name_chars > MAX_NAME_CHARS {
        return None;
    }
    let name = utf16_at(content, 0x42, name_chars.checked_mul(2)?)?;
    Some(FileNameAttr {
        name,
        namespace: NAMESPACES
            .iter()
            .find(|(value, _)| *value == namespace_raw)
            .map(|(_, label)| *label)
            .unwrap_or("unknown"),
        namespace_raw,
        // The low 48 bits are the record number and the high 16 the sequence,
        // which is what makes a reference to a reused record detectable.
        parent_record: parent & 0x0000_FFFF_FFFF_FFFF,
        parent_sequence: (parent >> 48) as u16,
        times,
        allocated_size,
        real_size,
        flags,
    })
}

// ── Byte helpers ────────────────────────────────────────────────────────────

/// Read a `u16` at `offset`, or `None` when it does not fit.
fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let slice = bytes.get(offset..end)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

/// Read a `u32` at `offset`, or `None` when it does not fit.
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = bytes.get(offset..end)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Read a `u64` at `offset`, or `None` when it does not fit.
fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let slice = bytes.get(offset..end)?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(slice);
    Some(u64::from_le_bytes(raw))
}

/// A `length`-byte slice at `offset`, or `None` when it does not fit.
fn slice_at(bytes: &[u8], offset: u64, length: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let len = usize::try_from(length).ok()?;
    let end = start.checked_add(len)?;
    bytes.get(start..end)
}

/// Decode `byte_length` bytes of UTF-16LE at `offset`.
///
/// `None` when the range does not fit, which is what keeps a corrupt name
/// length from reading past the attribute into whatever follows it.
fn utf16_at(bytes: &[u8], offset: u64, byte_length: u64) -> Option<String> {
    let slice = slice_at(bytes, offset, byte_length)?;
    if slice.len() % 2 != 0 {
        return None;
    }
    Some(crate::poolscan::decode_utf16le(slice))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poolscan::test_support::{profile, table, windows64_isf, Image};
    use seance_memory::Architecture;

    /// 2021-06-01T00:00:00Z, as a Windows FILETIME.
    ///
    /// 13 266 979 200 seconds after 1601-01-01, in 100 ns ticks. Subtracting the
    /// 11 644 473 600 second epoch difference gives Unix 1 622 505 600, which is
    /// 2021-06-01T00:00:00Z. The date is written out because the only thing this
    /// value proves is that the FILETIME conversion is right, and a date nobody
    /// can check against the number proves nothing.
    const CREATED: u64 = 132_669_792_000_000_000;
    /// One hour later.
    const MODIFIED: u64 = CREATED + 36_000_000_000;

    /// Where the fixture puts its good record.
    const RECORD_A: u64 = 0x1000;
    /// Where it puts a `BAAD` record whose fixups do not verify.
    const RECORD_B: u64 = 0x2000;
    /// Where it puts five bytes that match a needle and are not a record.
    const FALSE_POSITIVE: u64 = 0x3000;

    /// The long name on the good record.
    const LONG_NAME: &str = "evidence-report.txt";
    /// Its DOS 8.3 name.
    const SHORT_NAME: &str = "EVIDEN~1.TXT";
    /// The alternate data stream's name.
    const ADS_NAME: &str = "secret";
    /// The alternate data stream's resident content.
    const ADS_CONTENT: &[u8] = b"payload";

    /// A physical image holding one good record, one `BAAD` record with a
    /// broken fixup, and one false positive.
    fn fixture() -> WindowsProfile {
        let mut image = Image::new();

        // --- the good record ------------------------------------------------
        image.write(RECORD_A, b"FILE");
        image.put_u16(RECORD_A + 4, 0x30); // UpdateSequenceOffset
        image.put_u16(RECORD_A + 6, 3); // three entries: sequence plus two sectors
        image.put_u64(RECORD_A + 8, 0x1234_5678); // LSN
        image.put_u16(RECORD_A + 0x10, 1); // SequenceValue
        image.put_u16(RECORD_A + 0x12, 2); // LinkCount
        image.put_u16(RECORD_A + 0x14, 0x38); // FirstAttrOffset
        image.put_u16(RECORD_A + 0x16, RECORD_FLAG_IN_USE);
        image.put_u32(RECORD_A + 0x18, 0x1EC); // used size
        image.put_u32(RECORD_A + 0x1C, 0x400); // allocated size
        image.put_u64(RECORD_A + 0x20, 0); // base reference
        image.put_u16(RECORD_A + 0x28, 5); // next attribute id
        image.put_u32(RECORD_A + 0x2C, 42); // record number
                                            // The update-sequence array, and the two sector ends it protects.
        image.put_u16(RECORD_A + 0x30, 0x0001);
        image.put_u16(RECORD_A + 0x32, 0xAAAA);
        image.put_u16(RECORD_A + 0x34, 0xBBBB);
        image.put_u16(RECORD_A + 0x200 - 2, 0x0001);
        image.put_u16(RECORD_A + 0x400 - 2, 0x0001);

        // $STANDARD_INFORMATION at 0x38, 0x60 bytes long.
        put_attr_header(
            &mut image,
            RECORD_A + 0x38,
            ATTR_STANDARD_INFORMATION,
            0x60,
            0,
            0x18,
            0x30,
        );
        put_macb(&mut image, RECORD_A + 0x50, CREATED, MODIFIED);
        image.put_u32(RECORD_A + 0x50 + 0x20, 0x20); // FILE_ATTRIBUTE_ARCHIVE

        // Two $FILE_NAME attributes: the long name and the DOS 8.3 name.
        let long_bytes = (LONG_NAME.chars().count() * 2) as u64;
        put_attr_header(
            &mut image,
            RECORD_A + 0x98,
            ATTR_FILE_NAME,
            0x80,
            0,
            0x18,
            0x42 + long_bytes,
        );
        put_file_name(&mut image, RECORD_A + 0xB0, LONG_NAME, 1, CREATED, MODIFIED);

        let short_bytes = (SHORT_NAME.chars().count() * 2) as u64;
        put_attr_header(
            &mut image,
            RECORD_A + 0x118,
            ATTR_FILE_NAME,
            0x78,
            0,
            0x18,
            0x42 + short_bytes,
        );
        put_file_name(
            &mut image,
            RECORD_A + 0x130,
            SHORT_NAME,
            2,
            CREATED,
            MODIFIED,
        );

        // The unnamed $DATA stream: the file's own contents.
        put_attr_header(&mut image, RECORD_A + 0x190, ATTR_DATA, 0x28, 0, 0x18, 5);
        image.write(RECORD_A + 0x1A8, b"hello");

        // The alternate data stream: a *named* $DATA attribute.
        put_attr_header(
            &mut image,
            RECORD_A + 0x1B8,
            ATTR_DATA,
            0x30,
            ADS_NAME.chars().count() as u8,
            0x28,
            ADS_CONTENT.len() as u64,
        );
        image.put_u16(RECORD_A + 0x1B8 + 0x0A, 0x18); // name offset
        image.put_utf16(RECORD_A + 0x1B8 + 0x18, ADS_NAME);
        image.write(RECORD_A + 0x1B8 + 0x28, ADS_CONTENT);

        image.put_u32(RECORD_A + 0x1E8, ATTR_END);

        // --- the BAAD record with a broken fixup ---------------------------
        image.write(RECORD_B, b"BAAD");
        image.put_u16(RECORD_B + 4, 0x30);
        image.put_u16(RECORD_B + 6, 3);
        image.put_u16(RECORD_B + 0x10, 7); // SequenceValue
        image.put_u16(RECORD_B + 0x14, 0x38);
        image.put_u16(RECORD_B + 0x16, 0); // not in use: a deleted file
        image.put_u32(RECORD_B + 0x2C, 43);
        image.put_u16(RECORD_B + 0x30, 0x1234); // the record's update sequence
                                                // The first sector does not end with it: the page was reused.
        image.put_u16(RECORD_B + 0x200 - 2, 0x9999);
        image.put_u32(RECORD_B + 0x38, ATTR_END);

        // --- five bytes that match a needle and are not a record -----------
        image.write(FALSE_POSITIVE, b"FILE");
        image.put_u16(FALSE_POSITIVE + 4, 0xFF30); // an impossible USA offset

        profile(
            image.layer(),
            table(&windows64_isf(false)),
            Architecture::X64,
            10,
            0,
            Some(19_041),
        )
    }

    /// Write the resident attribute header every fixture attribute shares.
    fn put_attr_header(
        image: &mut Image,
        at: u64,
        attr_type: u32,
        length: u32,
        name_chars: u8,
        content_offset: u16,
        content_size: u64,
    ) {
        image.put_u32(at, attr_type);
        image.put_u32(at + 4, length);
        image.put_u8(at + 8, 0); // resident
        image.put_u8(at + 9, name_chars);
        image.put_u16(at + 0x0A, 0); // name offset, overwritten by named callers
        image.put_u16(at + 0x0C, 0); // flags
        image.put_u16(at + 0x0E, 0); // attribute id
        image.put_u32(at + 0x10, content_size as u32);
        image.put_u16(at + 0x14, content_offset);
    }

    /// Write four FILETIMEs in the on-disk order: created, modified, changed,
    /// accessed.
    fn put_macb(image: &mut Image, at: u64, created: u64, modified: u64) {
        image.put_u64(at, created);
        image.put_u64(at + 8, modified);
        image.put_u64(at + 16, modified);
        image.put_u64(at + 24, modified);
    }

    /// Write one `$FILE_NAME` attribute's content.
    fn put_file_name(
        image: &mut Image,
        at: u64,
        name: &str,
        namespace: u8,
        created: u64,
        modified: u64,
    ) {
        image.put_u64(at, 5 | (1u64 << 48)); // parent record 5, sequence 1
        put_macb(image, at + 8, created, modified);
        image.put_u64(at + 0x28, 0x1000); // allocated size
        image.put_u64(at + 0x30, 0x0C00); // real size
        image.put_u32(at + 0x38, 0x20); // FILE_ATTRIBUTE_ARCHIVE
        image.put_u32(at + 0x3C, 0); // reparse tag
        image.put_u8(at + 0x40, name.chars().count() as u8);
        image.put_u8(at + 0x41, namespace);
        image.put_utf16(at + 0x42, name);
    }

    fn scan(profile: &WindowsProfile) -> MftScanOutcome {
        let symbols = MftScanSymbols::from_profile(profile).expect("the fixture has memory");
        scan_mft_records(profile, &symbols, &MftScanConfig::default())
            .expect("the fixture sweeps cleanly")
    }

    #[test]
    fn the_swept_extent_is_the_one_the_layer_declares_and_travels_with_the_result() {
        let profile = fixture();
        let symbols = MftScanSymbols::from_profile(&profile).expect("the fixture has memory");
        assert_eq!(symbols.physical_min, profile.physical.min_address());
        assert_eq!(symbols.physical_max, profile.physical.max_address());
        assert_eq!(symbols.pointer_size, 8);
        // A sweep of a declared extent must examine it: the byte count is what
        // stops "no records" being read as "no records anywhere in memory".
        let outcome = scan(&profile);
        let span = symbols
            .physical_max
            .saturating_sub(symbols.physical_min)
            .saturating_add(1);
        assert!(outcome.scan.bytes_scanned >= span / 2, "{:?}", outcome.scan);
        assert_eq!(outcome.scan.unread_bytes, 0);
        assert!(outcome.scan.is_complete());
    }

    #[test]
    fn the_sweep_finds_both_record_signatures_and_rejects_what_is_not_a_record() {
        let profile = fixture();
        let outcome = scan(&profile);

        let addresses: Vec<u64> = outcome.records.iter().map(|r| r.address).collect();
        assert_eq!(addresses, vec![RECORD_A, RECORD_B]);
        let signatures: Vec<&str> = outcome
            .records
            .iter()
            .map(|r| r.signature.as_str())
            .collect();
        assert_eq!(signatures, vec!["FILE", "BAAD"]);

        // The false positive is counted rather than dropped, so the ratio of
        // records to matches is visible.
        assert_eq!(outcome.rejected_total, 1);
        assert_eq!(outcome.rejected[0].address, FALSE_POSITIVE);
        assert_eq!(outcome.rejected[0].reason, RejectionReason::NotARecord);
        // A false positive is expected and does not make the sweep incomplete.
        assert_eq!(outcome.unreadable_total, 0);
    }

    #[test]
    fn a_record_yields_its_macb_timestamps_from_standard_information() {
        let profile = fixture();
        let outcome = scan(&profile);
        let record = &outcome.records[0];

        let standard = record
            .standard_information
            .as_ref()
            .expect("the fixture record carries $STANDARD_INFORMATION");
        assert!(standard.times.all_recorded());
        assert_eq!(standard.times.created.filetime(), CREATED);
        assert_eq!(standard.times.modified.filetime(), MODIFIED);
        // Created and modified are stored adjacently in that order, so reading
        // them the other way round is the failure this asserts against.
        assert!(standard.times.created.filetime() < standard.times.modified.filetime());
        match &standard.times.created {
            MftTime::Recorded { rfc3339, .. } => {
                assert!(
                    rfc3339.starts_with("2021-06-01T00:00:00"),
                    "{rfc3339} is not the instant CREATED names"
                )
            }
            other => panic!("a real time was expected: {other:?}"),
        }
    }

    #[test]
    fn both_file_names_are_recovered_and_the_longest_is_the_long_one() {
        let profile = fixture();
        let outcome = scan(&profile);
        let record = &outcome.records[0];

        assert_eq!(record.file_names.len(), 2);
        let names: Vec<&str> = record
            .file_names
            .iter()
            .map(|name| name.name.as_str())
            .collect();
        assert_eq!(names, vec![LONG_NAME, SHORT_NAME]);
        assert_eq!(record.longest_name(), Some(LONG_NAME));
        assert_eq!(record.file_names[0].namespace, "Win32");
        assert_eq!(record.file_names[1].namespace, "DOS");
        // The parent reference splits into a record number and a sequence.
        assert_eq!(record.file_names[0].parent_record, 5);
        assert_eq!(record.file_names[0].parent_sequence, 1);
        assert_eq!(record.file_names[0].real_size, 0x0C00);
        // A name length is a character count: reading it as a byte count would
        // halve every name.
        assert_eq!(record.file_names[0].name.chars().count(), 19);
    }

    #[test]
    fn a_named_data_attribute_is_reported_as_an_alternate_data_stream() {
        let profile = fixture();
        let outcome = scan(&profile);
        let record = &outcome.records[0];

        assert_eq!(record.data_streams.len(), 2);
        assert!(!record.data_streams[0].is_alternate());
        assert_eq!(
            record.data_streams[0].resident_content.as_deref(),
            Some(&b"hello"[..])
        );
        assert!(record.data_streams[1].is_alternate());

        let ads = outcome.alternate_data_streams();
        assert_eq!(ads.len(), 1, "only the named stream is an ADS");
        assert_eq!(ads[0].stream_name, ADS_NAME);
        assert_eq!(ads[0].host_name.as_deref(), Some(LONG_NAME));
        assert_eq!(ads[0].resident_content.as_deref(), Some(ADS_CONTENT));
        assert!(!ads[0].content_truncated);
        assert_eq!(ads[0].record_number, Some(42));
        assert_eq!(
            ads[0].to_json()["full_name"],
            serde_json::json!(format!("{LONG_NAME}:{ADS_NAME}"))
        );
    }

    #[test]
    fn a_record_whose_sectors_were_reused_is_flagged_and_still_parsed() {
        let profile = fixture();
        let outcome = scan(&profile);
        let baad = &outcome.records[1];

        assert_eq!(baad.signature, "BAAD");
        assert!(!baad.in_use, "a BAAD record's file is no longer allocated");
        assert!(matches!(baad.fixups, FixupState::Mismatch { .. }));
        assert!(!baad.fixups.is_applied());
        assert!(!baad.is_complete());
        // The header was still read, which is the point of not treating a
        // mismatch as a parse failure.
        assert_eq!(baad.record_number, Some(43));
        assert_eq!(baad.sequence, 7);
        assert!(baad
            .notes
            .iter()
            .any(|note| note.contains("not the ones NTFS wrote")));
        // And the sweep as a whole declares it.
        assert!(!outcome.is_complete());
        assert!(outcome
            .incomplete()
            .iter()
            .any(|item| item.detail.contains("unverified update-sequence fixups")));
    }

    #[test]
    fn fixups_are_verified_before_any_byte_is_written_back() {
        // Two sectors, the second of which does not carry the sequence number.
        let mut record = vec![0u8; 1024];
        record[..4].copy_from_slice(b"FILE");
        record[0x30..0x32].copy_from_slice(&0x0001u16.to_le_bytes());
        record[0x32..0x34].copy_from_slice(&0xAAAAu16.to_le_bytes());
        record[0x34..0x36].copy_from_slice(&0xBBBBu16.to_le_bytes());
        record[0x1FE..0x200].copy_from_slice(&0x0001u16.to_le_bytes());
        record[0x3FE..0x400].copy_from_slice(&0xDEADu16.to_le_bytes());

        let before = record.clone();
        let state = apply_fixups(&mut record, 0x30, 3);
        assert_eq!(
            state,
            FixupState::Mismatch {
                sector: 2,
                expected: 0x0001,
                found: 0xDEAD,
            }
        );
        // Nothing was written: a half-fixed record is worse than an unfixed
        // one, because nothing downstream could tell which half is which.
        assert_eq!(record, before);

        // With both sectors matching, both are restored.
        record[0x3FE..0x400].copy_from_slice(&0x0001u16.to_le_bytes());
        let state = apply_fixups(&mut record, 0x30, 3);
        assert_eq!(state, FixupState::Applied { sectors: 2 });
        assert_eq!(u16_at(&record, 0x1FE), Some(0xAAAA));
        assert_eq!(u16_at(&record, 0x3FE), Some(0xBBBB));
    }

    #[test]
    fn an_update_sequence_array_that_does_not_fit_is_refused_rather_than_applied() {
        let mut record = vec![0u8; 1024];
        assert!(matches!(
            apply_fixups(&mut record, 0x30, 4096),
            FixupState::Malformed { .. }
        ));
        assert!(matches!(
            apply_fixups(&mut record, 1020, 3),
            FixupState::Malformed { .. }
        ));
        // A record declaring no entries is absent, not malformed, and the two
        // must not render the same.
        assert_eq!(apply_fixups(&mut record, 0x30, 0), FixupState::Absent);
        // A short buffer whose sectors run past its end is malformed rather
        // than half-applied.
        let mut short = vec![0u8; 512];
        assert!(matches!(
            apply_fixups(&mut short, 0x30, 3),
            FixupState::Malformed { .. }
        ));
    }

    #[test]
    fn a_timestamp_outside_the_plausible_window_is_never_rendered_as_a_date() {
        assert_eq!(MftTime::from_filetime(0), MftTime::Unset);
        assert_eq!(
            MftTime::from_filetime(1),
            MftTime::Implausible { filetime: 1 }
        );
        assert_eq!(
            MftTime::from_filetime(u64::MAX),
            MftTime::Implausible { filetime: u64::MAX }
        );
        assert!(MftTime::from_filetime(MIN_PLAUSIBLE_FILETIME).is_recorded());
        assert!(MftTime::from_filetime(MAX_PLAUSIBLE_FILETIME).is_recorded());
        assert!(!MftTime::from_filetime(MIN_PLAUSIBLE_FILETIME - 1).is_recorded());
        assert!(!MftTime::from_filetime(MAX_PLAUSIBLE_FILETIME + 1).is_recorded());
        // Each state renders differently, so a 1601 date can never appear
        // beside a real file name.
        assert_eq!(MftTime::Unset.to_json()["utc"], serde_json::Value::Null);
        assert_eq!(
            MftTime::from_filetime(1).to_json()["utc"],
            serde_json::Value::Null
        );
        assert_eq!(MftTime::from_filetime(1).status(), "implausible");
    }

    #[test]
    fn a_standard_information_creation_time_before_the_directory_entry_is_flagged() {
        let mut record = MftRecord {
            address: 0,
            signature: "FILE".into(),
            in_use: true,
            is_directory: false,
            flags: RECORD_FLAG_IN_USE,
            record_number: Some(1),
            sequence: 1,
            link_count: 1,
            base_record: 0,
            lsn: 0,
            used_size: 0,
            allocated_size: 0,
            fixups: FixupState::Absent,
            bytes_read: 1024,
            standard_information: Some(StandardInformation {
                times: MacbTimes {
                    created: MftTime::from_filetime(MIN_PLAUSIBLE_FILETIME),
                    modified: MftTime::Unset,
                    mft_changed: MftTime::Unset,
                    accessed: MftTime::Unset,
                },
                flags: 0,
            }),
            file_names: vec![FileNameAttr {
                name: "evil.exe".into(),
                namespace: "Win32",
                namespace_raw: 1,
                parent_record: 5,
                parent_sequence: 1,
                times: MacbTimes {
                    created: MftTime::from_filetime(CREATED),
                    modified: MftTime::Unset,
                    mft_changed: MftTime::Unset,
                    accessed: MftTime::Unset,
                },
                allocated_size: 0,
                real_size: 0,
                flags: 0,
            }],
            data_streams: Vec::new(),
            attribute_stop: AttributeStop::EndMarker,
            notes: Vec::new(),
        };
        // $SI Created before $FN Created is what a move or rename leaves: an
        // observation, reported weak, and not a verdict (HUNT-073).
        assert_eq!(record.timestomp_suspected(), Some(false));
        let seen = record.timestamp_indicators();
        assert!(
            seen.iter()
                .any(|i| i.reason == "SI Created precedes FN Created" && !i.strong),
            "{seen:?}"
        );
        assert_eq!(record.to_json()["timestomp_suspected"], false);
        assert_eq!(
            record.to_json()["timestamp_indicators"][0]["strength"],
            "weak"
        );

        // The ordinary case, where the two agree.
        record
            .standard_information
            .as_mut()
            .expect("set above")
            .times
            .created = MftTime::from_filetime(CREATED);
        assert_eq!(record.timestomp_suspected(), Some(false));
        assert!(record.timestamp_indicators().is_empty());

        // And where either time is not a recorded one, the comparison says
        // nothing rather than saying "no".
        record
            .standard_information
            .as_mut()
            .expect("set above")
            .times
            .created = MftTime::Unset;
        assert_eq!(record.timestomp_suspected(), None);
        assert_eq!(
            record.to_json()["timestomp_suspected"],
            serde_json::Value::Null
        );
    }

    /// The record of Case 001's `Beth_Secret.txt` as it sits in the domain
    /// controller's memory: every $SI time whole-second and the evening
    /// before its $FN Created. The memory sweep must reach the same verdict
    /// the disk parser does, from the same rule.
    /// Build a bare record carrying one Win32 `$FILE_NAME`, for the path tests.
    fn named_record(
        number: u32,
        sequence: u16,
        name: &str,
        parent: u64,
        parent_seq: u16,
        dir: bool,
    ) -> MftRecord {
        MftRecord {
            address: u64::from(number) * 1024,
            signature: "FILE".into(),
            in_use: true,
            is_directory: dir,
            flags: RECORD_FLAG_IN_USE,
            record_number: Some(number),
            sequence,
            link_count: 1,
            base_record: 0,
            lsn: 0,
            used_size: 0,
            allocated_size: 0,
            fixups: FixupState::Absent,
            bytes_read: 1024,
            standard_information: None,
            file_names: vec![FileNameAttr {
                name: name.into(),
                namespace: "Win32",
                namespace_raw: 1,
                parent_record: parent,
                parent_sequence: parent_seq,
                times: MacbTimes {
                    created: MftTime::Unset,
                    modified: MftTime::Unset,
                    mft_changed: MftTime::Unset,
                    accessed: MftTime::Unset,
                },
                allocated_size: 0,
                real_size: 0,
                flags: 0,
            }],
            data_streams: Vec::new(),
            attribute_stop: AttributeStop::EndMarker,
            notes: Vec::new(),
        }
    }

    fn outcome_of(records: Vec<MftRecord>) -> MftScanOutcome {
        MftScanOutcome {
            records_total: records.len(),
            records,
            truncated: false,
            rejected: Vec::new(),
            rejected_total: 0,
            unreadable_total: 0,
            scan: ScanSummary::default(),
        }
    }

    /// HUNT-082. A pool sweep finds records scattered, so a recovered name on
    /// its own does not say where the file was — and "where" is the question a
    /// cache file like `13cubed[1].htm` exists to answer. Each record carries
    /// its parent's record number and the sequence that number must still be
    /// on, which is enough to walk up through the other records the sweep
    /// recovered. This is the 13Cubed Mini Memory CTF's question 4, whose
    /// answer is exactly that path.
    #[test]
    fn a_recovered_record_is_placed_by_chaining_its_parents_to_the_root() {
        let outcome = outcome_of(vec![
            named_record(61988, 2, "13cubed[1].htm", 335, 2, false),
            named_record(335, 2, "AHF2COV9", 300, 1, true),
            named_record(300, 1, "Cache", 200, 1, true),
            named_record(200, 1, "CTF", 5, 5, true), // parent is the root
        ]);
        let paths = outcome.resolve_paths();
        let leaf = paths[0].as_ref().expect("the leaf has a name");
        assert_eq!(leaf.path, r"\CTF\Cache\AHF2COV9\13cubed[1].htm");
        assert!(leaf.complete);
        assert!(leaf.note.is_none());
        // The JSON an examiner reads carries it too.
        let json = outcome.to_json();
        let first = &json["records"][0];
        assert_eq!(first["path"], r"\CTF\Cache\AHF2COV9\13cubed[1].htm");
        assert_eq!(first["path_complete"], true);
    }

    /// A sweep is a scan, not a walk: the parent may simply not have been
    /// recovered. What is known is given, and the path is NOT called complete —
    /// a partial path presented as a whole one would put a file in the wrong
    /// directory.
    #[test]
    fn a_parent_the_sweep_did_not_recover_stops_the_path_and_says_so() {
        let outcome = outcome_of(vec![
            named_record(61988, 2, "13cubed[1].htm", 335, 2, false),
            named_record(335, 2, "AHF2COV9", 999, 1, true), // 999 was never found
        ]);
        let leaf = outcome.resolve_paths()[0].clone().expect("named");
        assert_eq!(leaf.path, r"AHF2COV9\13cubed[1].htm");
        assert!(!leaf.complete);
        let note = leaf.note.unwrap();
        assert!(note.contains("999"), "{note}");
        assert!(
            note.contains("not in the evidence") || note.contains("did not recover"),
            "{note}"
        );
    }

    /// An MFT slot gets reused. A parent on a different sequence than the child
    /// recorded is a DIFFERENT file now, and walking through it would build
    /// this file's path out of another file's ancestry.
    #[test]
    fn a_parent_slot_since_reused_stops_the_path_rather_than_borrowing_its_ancestry() {
        let outcome = outcome_of(vec![
            named_record(61988, 2, "13cubed[1].htm", 335, 2, false),
            // The same slot, now on sequence 7 and holding something else.
            named_record(335, 7, "SomeOtherDir", 5, 5, true),
        ]);
        let leaf = outcome.resolve_paths()[0].clone().expect("named");
        assert!(!leaf.complete);
        assert!(!leaf.path.contains("SomeOtherDir"), "{}", leaf.path);
        let note = leaf.note.unwrap();
        assert!(note.contains("sequence 7"), "{note}");
        assert!(note.contains("another file"), "{note}");
    }

    /// A chain that loops is not a directory tree; the walk stops instead of
    /// spinning.
    #[test]
    fn a_looping_parent_chain_is_stopped_and_named_as_a_cycle() {
        let outcome = outcome_of(vec![
            named_record(10, 1, "a.txt", 20, 1, false),
            named_record(20, 1, "B", 30, 1, true),
            named_record(30, 1, "C", 20, 1, true), // back to 20
        ]);
        let leaf = outcome.resolve_paths()[0].clone().expect("named");
        assert!(!leaf.complete);
        assert!(leaf.note.unwrap().contains("cycle"));
    }

    #[test]
    fn the_memory_sweep_reaches_the_disk_parsers_verdict_on_a_stomped_record() {
        // 2020-09-18T23:33:54Z / 23:35:35Z, whole; 2020-09-19T03:34:56.97Z.
        const UNIX_TO_FILETIME: u64 = 116_444_736_000_000_000;
        let stomped_c = UNIX_TO_FILETIME + 1_600_471_634 * 10_000_000;
        let stomped_m = UNIX_TO_FILETIME + 1_600_471_735 * 10_000_000;
        let real_name = UNIX_TO_FILETIME + 1_600_486_096 * 10_000_000 + 9_704_452;
        let record = MftRecord {
            address: 0,
            signature: "FILE".into(),
            in_use: true,
            is_directory: false,
            flags: RECORD_FLAG_IN_USE,
            record_number: Some(87111),
            sequence: 1,
            link_count: 1,
            base_record: 0,
            lsn: 0,
            used_size: 0,
            allocated_size: 0,
            fixups: FixupState::Absent,
            bytes_read: 1024,
            standard_information: Some(StandardInformation {
                times: MacbTimes {
                    created: MftTime::from_filetime(stomped_c),
                    modified: MftTime::from_filetime(stomped_m),
                    mft_changed: MftTime::from_filetime(stomped_m),
                    accessed: MftTime::from_filetime(stomped_c),
                },
                flags: 0,
            }),
            file_names: vec![FileNameAttr {
                name: "Beth_Secret.txt".into(),
                namespace: "Win32",
                namespace_raw: 1,
                parent_record: 5,
                parent_sequence: 1,
                times: MacbTimes {
                    created: MftTime::from_filetime(real_name),
                    modified: MftTime::from_filetime(real_name),
                    mft_changed: MftTime::from_filetime(real_name),
                    accessed: MftTime::from_filetime(real_name),
                },
                allocated_size: 0,
                real_size: 27,
                flags: 0,
            }],
            data_streams: Vec::new(),
            attribute_stop: AttributeStop::EndMarker,
            notes: Vec::new(),
        };
        assert_eq!(record.timestomp_suspected(), Some(true));
        assert!(record
            .timestamp_indicators()
            .iter()
            .any(|i| i.strong && i.reason.contains("MFT-changed is whole-second")));
    }

    #[test]
    fn an_attribute_whose_length_cannot_advance_the_walk_stops_it_with_a_reason() {
        let mut bytes = vec![0u8; 1024];
        // One attribute at 0x38 declaring a zero length: a walk that trusted it
        // would loop for ever.
        bytes[0x38..0x3C].copy_from_slice(&ATTR_DATA.to_le_bytes());
        bytes[0x3C..0x40].copy_from_slice(&0u32.to_le_bytes());
        let mut record = empty_record();
        walk_attributes(&bytes, 0x38, &MftScanConfig::default(), &mut record);
        assert!(matches!(
            record.attribute_stop,
            AttributeStop::Malformed { .. }
        ));
        assert!(!record.attribute_stop.is_complete());

        // An attribute claiming more bytes than were acquired stops the walk
        // rather than reading past the record.
        bytes[0x3C..0x40].copy_from_slice(&0x1000u32.to_le_bytes());
        let mut record = empty_record();
        walk_attributes(&bytes, 0x38, &MftScanConfig::default(), &mut record);
        match &record.attribute_stop {
            AttributeStop::Malformed { detail } => assert!(detail.contains("only"), "{detail}"),
            other => panic!("a malformed stop was expected: {other:?}"),
        }
    }

    #[test]
    fn the_attribute_cap_stops_a_record_that_never_reaches_an_end_marker() {
        let mut bytes = vec![0u8; 1024];
        // Sixty-four 16-byte $DATA attributes and no end marker.
        for index in 0..60usize {
            let at = 0x38 + index * 16;
            bytes[at..at + 4].copy_from_slice(&ATTR_DATA.to_le_bytes());
            bytes[at + 4..at + 8].copy_from_slice(&16u32.to_le_bytes());
        }
        let mut record = empty_record();
        let config = MftScanConfig {
            max_attributes: 8,
            ..MftScanConfig::default()
        };
        walk_attributes(&bytes, 0x38, &config, &mut record);
        assert_eq!(record.attribute_stop, AttributeStop::CapReached { cap: 8 });
        assert!(!record.attribute_stop.is_complete());
    }

    #[test]
    fn a_file_name_with_an_impossible_length_is_refused_rather_than_read_past() {
        let mut content = vec![0u8; 0x50];
        content[0x40] = 0; // no characters at all
        assert!(parse_file_name(&content).is_none());
        content[0x40] = 255; // the format's maximum, but the content is short
        assert!(parse_file_name(&content).is_none());
        // A short attribute cannot hold even the fixed part.
        assert!(parse_file_name(&[0u8; 8]).is_none());
        assert!(parse_standard_information(&[0u8; 8]).is_none());
    }

    #[test]
    fn a_record_size_that_cannot_hold_a_header_is_refused_before_any_sweep() {
        let profile = fixture();
        let symbols = MftScanSymbols::from_profile(&profile).expect("the fixture has memory");
        let config = MftScanConfig {
            record_bytes: 16,
            ..MftScanConfig::default()
        };
        let err = scan_mft_records(&profile, &symbols, &config)
            .expect_err("a 16-byte record cannot hold a header");
        assert_eq!(err.class(), "unsupported_image");
    }

    #[test]
    fn the_record_cap_keeps_the_total_exact_and_says_more_remain() {
        let profile = fixture();
        let symbols = MftScanSymbols::from_profile(&profile).expect("the fixture has memory");
        let config = MftScanConfig {
            max_records: 1,
            ..MftScanConfig::default()
        };
        let outcome = scan_mft_records(&profile, &symbols, &config).expect("the sweep runs");
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records_total, 2);
        assert!(outcome.truncated);
        assert!(!outcome.is_complete());
        assert!(outcome
            .incomplete()
            .iter()
            .any(|item| item.detail.contains("more remain")));
    }

    #[test]
    fn resident_content_is_capped_and_the_cap_is_declared() {
        let profile = fixture();
        let symbols = MftScanSymbols::from_profile(&profile).expect("the fixture has memory");
        let config = MftScanConfig {
            max_resident_bytes: 3,
            ..MftScanConfig::default()
        };
        let outcome = scan_mft_records(&profile, &symbols, &config).expect("the sweep runs");
        let ads = outcome.alternate_data_streams();
        assert_eq!(ads[0].resident_content.as_deref(), Some(&ADS_CONTENT[..3]));
        assert!(
            ads[0].content_truncated,
            "a cut-short stream must never look like the whole stream"
        );
        // The declared size stays the real one, so the shortfall is visible.
        assert_eq!(ads[0].size, Some(ADS_CONTENT.len() as u64));
    }

    #[test]
    fn the_outcome_serialises_with_everything_a_report_has_to_declare() {
        let profile = fixture();
        let outcome = scan(&profile);
        let json = outcome.to_json();
        assert_eq!(json["record_count"], serde_json::json!(2));
        assert_eq!(json["rejected_total"], serde_json::json!(1));
        assert_eq!(json["complete"], serde_json::json!(false));
        assert_eq!(
            json["alternate_data_streams"]
                .as_array()
                .expect("an array")
                .len(),
            1
        );
        assert!(!json["incomplete"].as_array().expect("an array").is_empty());
        assert_eq!(json["scan"]["complete"], serde_json::json!(true));
    }

    /// A resident attribute too short to hold the offset and length of its own
    /// content must not decode as a stream of zero bytes.
    ///
    /// Defaulting those two fields to zero produces a `$DATA` attribute that
    /// says the stream exists and is empty. An examiner reading "alternate data
    /// stream, 0 bytes" concludes nothing was hidden in it; the truth is that
    /// the attribute was never decoded at all.
    #[test]
    fn a_resident_attribute_too_short_for_its_own_header_yields_no_stream() {
        // Sixteen bytes: type, length, non-resident flag and name fields, but
        // nothing at 0x10 or 0x14.
        let mut attribute = vec![0u8; 16];
        attribute[0..4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        attribute[4..8].copy_from_slice(&16u32.to_le_bytes());
        let mut record = empty_record();
        decode_attribute(
            &attribute,
            ATTR_DATA,
            0x38,
            &MftScanConfig::default(),
            &mut record,
        );
        assert!(
            record.data_streams.is_empty(),
            "an undecodable attribute must not become an empty stream: {:?}",
            record.data_streams
        );
        assert!(
            record.notes.iter().any(|note| note.contains("too short")),
            "the reason must reach the record: {:?}",
            record.notes
        );
    }

    /// A non-resident `$DATA` too short to hold its real size reports the size
    /// as unknown rather than as zero.
    #[test]
    fn a_non_resident_stream_of_unknown_size_is_not_reported_as_empty() {
        // 0x38 bytes: the non-resident header up to but not including the real
        // size at 0x30.
        let mut attribute = vec![0u8; 0x30];
        attribute[0..4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        attribute[4..8].copy_from_slice(&0x30u32.to_le_bytes());
        attribute[8] = 1; // non-resident
        let mut record = empty_record();
        decode_attribute(
            &attribute,
            ATTR_DATA,
            0x38,
            &MftScanConfig::default(),
            &mut record,
        );
        assert_eq!(record.data_streams.len(), 1);
        assert_eq!(
            record.data_streams[0].size, None,
            "a size that could not be read must never render as zero bytes"
        );
        assert!(
            record.notes.iter().any(|note| note.contains("real size")),
            "{:?}",
            record.notes
        );
    }

    /// A record with nothing in it, for driving the attribute walk directly.
    fn empty_record() -> MftRecord {
        MftRecord {
            address: 0,
            signature: "FILE".into(),
            in_use: true,
            is_directory: false,
            flags: RECORD_FLAG_IN_USE,
            record_number: None,
            sequence: 0,
            link_count: 0,
            base_record: 0,
            lsn: 0,
            used_size: 0,
            allocated_size: 0,
            fixups: FixupState::Absent,
            bytes_read: 1024,
            standard_information: None,
            file_names: Vec::new(),
            data_streams: Vec::new(),
            attribute_stop: AttributeStop::EndOfRecord,
            notes: Vec::new(),
        }
    }
}
