//! The NTFS `$Secure:$SDS` stream: entry headers, the block layout, the mirror.
//!
//! The **security descriptor** each entry carries is decoded by
//! [`seance_core::secdesc`], because the same NT structure also appears in a
//! registry hive's `sk` cells and one decoder must serve both — two decoders
//! for one structure can disagree with each other about who owned something,
//! on a surface that is quoted under oath. What is left here is what belongs to
//! NTFS alone: the 20-byte entry header, the 256 KiB block alignment, the
//! mirror, and the recovery the scan does when an entry will not read.
//!
//! Split out on 2026-09-15 for `ROADMAP` §2.5. Every descriptor type and
//! decoder is re-exported below, so a caller that reached for `crate::sds::Sid`
//! still finds it and the `$SDS` tests did not have to move.
//!
//! ```text
//! $SDS stream
//!  ├─ SDS entry header (20 bytes): hash, security_id, stream offset, entry size
//!  └─ self-relative SECURITY_DESCRIPTOR (entry_size - 20 bytes)  <- seance_core::secdesc
//! ```

// The descriptor decoder, re-exported so this module's public surface is
// unchanged by the move. `SdsError` keeps its name here: it is what this
// crate's callers and its 1,263 lines of tests already say, and in `seance_core`
// the same type is named `SecDescError` because there it decodes descriptors
// that have nothing to do with `$SDS`.
use std::collections::HashMap;

pub use seance_core::secdesc::wellknown::{
    access_right_names, ace_effect, ace_flag_names, ace_type_is_allow, ace_type_is_deny,
    ace_type_name, control_flag_names, describe_access_mask, describe_mandatory_policy,
    integrity_level_from_sid, registry_composite_name, sid_friendly_name, ObjectKind,
};
pub use seance_core::secdesc::{
    parse_ace, parse_acl, parse_security_descriptor, parse_security_descriptor_on, parse_sid, Ace,
    Acl, AclPresence, SecDescError as SdsError, SecurityDescriptor, Sid, ACE_FLAG_INHERIT_ONLY,
    ACE_HEADER_LEN, ACE_TYPE_MANDATORY_LABEL, ACL_HEADER_LEN, DESCRIPTOR_HEADER_LEN,
    MAX_ACES_PER_ACL, MAX_SUB_AUTHORITIES, SE_DACL_AUTO_INHERITED, SE_DACL_PRESENT,
    SE_DACL_PROTECTED, SE_SACL_PRESENT, SE_SACL_PROTECTED, SE_SELF_RELATIVE,
};

/// Bytes of the SDS entry header that precedes each security descriptor.
pub const SDS_HEADER_LEN: usize = 0x14;
/// Security-block size. `$SDS` is written in blocks of this size and each
/// descriptor is mirrored exactly this far from its primary copy.
pub const SDS_BLOCK_SIZE: usize = 0x40000;
/// Alignment of every entry within the stream.
pub const SDS_ENTRY_ALIGNMENT: usize = 16;
/// Largest entry accepted. Real descriptors are tens to a few hundred bytes;
/// anything past 64 KiB is corruption or a hostile length, and sizing a read
/// from it is how a parser gets turned into an OOM.
pub const MAX_SDS_ENTRY_SIZE: u32 = 64 * 1024;
/// Cap on entries taken from one stream. Hitting it sets
/// [`SdsScan::entry_cap_reached`], which the plugin stamps on the artifact:
/// a truncated store must never be reported as the whole store.
pub const MAX_SDS_ENTRIES: usize = 1_000_000;

/// The 20-byte header that precedes each descriptor in `$SDS`.
///
/// NTFS's, not the descriptor's: `seance_core::secdesc` decodes what follows
/// this header and knows nothing about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SdsHeader {
    hash: u32,
    security_id: u32,
    declared_offset: u64,
    entry_size: u32,
}

/// Where a decoded descriptor's bytes came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryOrigin {
    /// Decoded from the copy found at this position in the linear scan.
    Primary,
    /// The copy at `primary_offset` failed to decode and the descriptor was
    /// recovered from its 256 KiB mirror at `mirror_offset`.
    ///
    /// This is reported on the artifact: the examiner must know the primary
    /// copy on this volume is damaged and that the values shown come from the
    /// backup copy NTFS keeps, not from the record the file system reads.
    MirrorRecovered {
        primary_offset: u64,
        mirror_offset: u64,
        primary_error: String,
    },
}

/// One entry of the `$SDS` store: its header plus the descriptor it wraps.
#[derive(Debug, Clone)]
pub struct SdsEntry {
    /// Hash of the descriptor, as indexed by `$SDH`.
    pub hash: u32,
    /// The volume-unique id that `$STANDARD_INFORMATION` references.
    pub security_id: u32,
    /// Stream offset the header declares for itself.
    pub declared_offset: u64,
    /// Stream offset the entry was actually found at.
    pub stream_offset: u64,
    /// Declared total size of header plus descriptor.
    pub entry_size: u32,
    /// True when `declared_offset` is neither this offset nor its mirror. The
    /// entry is still decoded, but the store is internally inconsistent here.
    pub offset_mismatch: bool,
    /// Whether this came from the primary copy or a mirror recovery.
    pub origin: EntryOrigin,
    /// The descriptor, or the reason it could not be decoded. A failed entry is
    /// still returned so the `security_id` is visible as unresolvable rather
    /// than silently missing from the store.
    pub descriptor: Result<SecurityDescriptor, SdsError>,
}

/// Result of scanning a whole `$SDS` stream.
#[derive(Debug, Clone, Default)]
pub struct SdsScan {
    /// One entry per unique `security_id`, in the order first encountered.
    pub entries: Vec<SdsEntry>,
    /// Bytes of stream examined.
    pub bytes_scanned: usize,
    /// Additional copies of an id that were skipped (the expected mirrors).
    pub duplicate_copies: usize,
    /// Descriptors recovered from a mirror after the primary copy failed.
    pub mirror_recoveries: usize,
    /// Entries whose descriptor could not be decoded from any copy.
    pub failed_entries: usize,
    /// Entry headers whose declared size ran past the end of the stream.
    pub entries_past_end: usize,
    /// Entry headers refused because their declared size exceeded
    /// [`MAX_SDS_ENTRY_SIZE`]. Those descriptors are NOT in `entries`, so a
    /// non-zero count means the store listing is short by that many ids.
    pub oversize_entries: usize,
    /// True when [`MAX_SDS_ENTRIES`] stopped the scan: the store holds more
    /// descriptors than were returned.
    pub entry_cap_reached: bool,
}

impl SdsScan {
    /// True when this scan is known not to be the whole store: a cap bit, or a
    /// header was refused. Callers stamp this on the artifact, because a partial
    /// listing that reads as complete answers "who owned this file?" with
    /// silence.
    pub fn incomplete(&self) -> bool {
        self.entry_cap_reached || self.oversize_entries > 0
    }
}

/// What the 20 bytes at a candidate offset turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderProbe {
    /// A usable entry header.
    Entry(SdsHeader),
    /// Inter-block padding, or bytes that are not an entry header at all. The
    /// scan steps over these.
    Padding,
    /// A header that names a real `security_id` but declares more bytes than
    /// [`MAX_SDS_ENTRY_SIZE`] allows. The descriptor is not decoded — sizing a
    /// read from a hostile length is how a parser becomes an OOM — but the
    /// refusal is counted and reported, because a `security_id` that vanishes
    /// from the store reads as "this volume has no such descriptor".
    Oversize,
}

/// Examine the 20 bytes at `at` and say what they are.
fn probe_header(buf: &[u8], at: usize) -> HeaderProbe {
    let Some(end) = at.checked_add(SDS_HEADER_LEN) else {
        return HeaderProbe::Padding;
    };
    let Some(b) = buf.get(at..end) else {
        return HeaderProbe::Padding;
    };
    let hash = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let security_id = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    let declared_offset =
        u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    let entry_size = u32::from_le_bytes([b[16], b[17], b[18], b[19]]);
    // Security id 0 is never assigned, and an entry must be larger than its own
    // header. Either means we are looking at inter-block padding, not an entry.
    if security_id == 0 || entry_size as usize <= SDS_HEADER_LEN {
        return HeaderProbe::Padding;
    }
    if entry_size > MAX_SDS_ENTRY_SIZE {
        return HeaderProbe::Oversize;
    }
    HeaderProbe::Entry(SdsHeader {
        hash,
        security_id,
        declared_offset,
        entry_size,
    })
}

/// Read an entry header at `at`, returning it only when the fields are
/// self-consistent enough to be an entry rather than padding.
fn read_header(buf: &[u8], at: usize) -> Option<SdsHeader> {
    match probe_header(buf, at) {
        HeaderProbe::Entry(header) => Some(header),
        HeaderProbe::Padding | HeaderProbe::Oversize => None,
    }
}

/// Next 16-byte aligned offset strictly after `at`. Used to step over padding;
/// guarantees the scan always advances, so garbage can never loop.
fn next_alignment(at: usize) -> usize {
    at.saturating_add(SDS_ENTRY_ALIGNMENT) & !(SDS_ENTRY_ALIGNMENT - 1)
}

/// `at` rounded UP to the next 16-byte boundary, leaving an already-aligned
/// offset alone. Used to step from the end of one entry to the start of the
/// next: rounding an aligned offset further would skip the following entry.
fn align_up(at: usize) -> usize {
    at.saturating_add(SDS_ENTRY_ALIGNMENT - 1) & !(SDS_ENTRY_ALIGNMENT - 1)
}

/// Try to decode the same entry from its 256 KiB mirror.
///
/// Both directions are probed because either copy may be the damaged one. The
/// candidate must carry the same hash, id and size, otherwise it is a different
/// descriptor and using it would attribute the wrong permissions to this id.
fn recover_from_mirror(
    buf: &[u8],
    at: usize,
    header: &SdsHeader,
) -> Option<(usize, SecurityDescriptor)> {
    let candidates = [
        at.checked_add(SDS_BLOCK_SIZE),
        at.checked_sub(SDS_BLOCK_SIZE),
    ];
    for candidate in candidates.into_iter().flatten() {
        let Some(mirror) = read_header(buf, candidate) else {
            continue;
        };
        if mirror.security_id != header.security_id
            || mirror.entry_size != header.entry_size
            || mirror.hash != header.hash
        {
            continue;
        }
        let start = candidate + SDS_HEADER_LEN;
        let Some(end) = candidate.checked_add(mirror.entry_size as usize) else {
            continue;
        };
        if end > buf.len() || start > end {
            continue;
        }
        if let Ok(descriptor) = parse_security_descriptor(&buf[start..end]) {
            return Some((candidate, descriptor));
        }
    }
    None
}

/// Scan a whole `$SDS` stream into one entry per unique `security_id`.
///
/// Equivalent to [`parse_sds`] with the production caps; the caps are
/// parameters only so they can be exercised by tests without building a
/// gigabyte of fixture.
///
/// The scan walks 16-byte aligned offsets. Anything that is not a plausible
/// entry header is padding — including the run-out at the end of each 256 KiB
/// block — and the scan steps over it and resumes rather than treating it as
/// the end of the stream, which would drop every descriptor in later blocks.
pub fn parse_sds_with_limits(sds: &[u8], max_entries: usize) -> SdsScan {
    let mut scan = SdsScan {
        bytes_scanned: sds.len(),
        ..SdsScan::default()
    };
    let mut index: HashMap<u32, usize> = HashMap::new();
    let mut offset = 0usize;

    while offset.saturating_add(SDS_HEADER_LEN) <= sds.len() {
        let header = match probe_header(sds, offset) {
            HeaderProbe::Entry(header) => header,
            HeaderProbe::Padding => {
                offset = next_alignment(offset);
                continue;
            }
            HeaderProbe::Oversize => {
                // Counted, not silently skipped: this is a cap refusing an
                // id, not padding.
                scan.oversize_entries = scan.oversize_entries.saturating_add(1);
                offset = next_alignment(offset);
                continue;
            }
        };
        if scan.entries.len() >= max_entries {
            scan.entry_cap_reached = true;
            break;
        }

        // Mirror copies legitimately carry either their own offset or the
        // primary's, so both are consistent; anything else means the store's
        // self-description disagrees with where the entry actually sits.
        let actual = offset as u64;
        let mirror_delta = SDS_BLOCK_SIZE as u64;
        let offset_mismatch = header.declared_offset != actual
            && header.declared_offset.saturating_add(mirror_delta) != actual
            && header.declared_offset != actual.saturating_add(mirror_delta);

        let entry_end = offset.checked_add(header.entry_size as usize);
        let (descriptor, origin) = match entry_end.filter(|e| *e <= sds.len()) {
            Some(end) => {
                let body = &sds[offset + SDS_HEADER_LEN..end];
                match parse_security_descriptor(body) {
                    Ok(d) => (Ok(d), EntryOrigin::Primary),
                    Err(e) => match recover_from_mirror(sds, offset, &header) {
                        Some((mirror_offset, d)) => {
                            scan.mirror_recoveries += 1;
                            (
                                Ok(d),
                                EntryOrigin::MirrorRecovered {
                                    primary_offset: actual,
                                    mirror_offset: mirror_offset as u64,
                                    primary_error: e.to_string(),
                                },
                            )
                        }
                        None => (Err(e), EntryOrigin::Primary),
                    },
                }
            }
            None => {
                // The entry claims bytes the stream does not have (a truncated
                // tail, or a hostile size). The id is still reported, either
                // recovered from the mirror or as an explicit failure.
                scan.entries_past_end += 1;
                let err = SdsError::EntryPastEndOfStream {
                    offset: actual,
                    entry_size: header.entry_size,
                    available: sds.len().saturating_sub(offset),
                };
                match recover_from_mirror(sds, offset, &header) {
                    Some((mirror_offset, d)) => {
                        scan.mirror_recoveries += 1;
                        (
                            Ok(d),
                            EntryOrigin::MirrorRecovered {
                                primary_offset: actual,
                                mirror_offset: mirror_offset as u64,
                                primary_error: err.to_string(),
                            },
                        )
                    }
                    None => (Err(err), EntryOrigin::Primary),
                }
            }
        };

        let entry = SdsEntry {
            hash: header.hash,
            security_id: header.security_id,
            declared_offset: header.declared_offset,
            stream_offset: actual,
            entry_size: header.entry_size,
            offset_mismatch,
            origin,
            descriptor,
        };

        match index.get(&header.security_id).copied() {
            Some(existing) => {
                scan.duplicate_copies += 1;
                // Self-healing in the other direction: the first copy seen was
                // damaged and this later copy (the mirror) decodes. Replace it
                // and record that the value shown came from the mirror.
                let previous_failed = scan.entries[existing].descriptor.is_err();
                if previous_failed && entry.descriptor.is_ok() {
                    let primary_offset = scan.entries[existing].stream_offset;
                    let primary_error = match &scan.entries[existing].descriptor {
                        Err(e) => e.to_string(),
                        Ok(_) => String::new(),
                    };
                    let mut healed = entry;
                    healed.origin = EntryOrigin::MirrorRecovered {
                        primary_offset,
                        mirror_offset: actual,
                        primary_error,
                    };
                    scan.mirror_recoveries += 1;
                    scan.entries[existing] = healed;
                }
            }
            None => {
                index.insert(header.security_id, scan.entries.len());
                scan.entries.push(entry);
            }
        }

        // entry_size is always > SDS_HEADER_LEN, so this advances; the fallback
        // makes forward progress structurally guaranteed even if a saturating
        // add ever clamped, so the loop cannot spin on evidence-derived input.
        let next = align_up(offset.saturating_add(header.entry_size as usize));
        offset = if next > offset {
            next
        } else {
            next_alignment(offset)
        };
    }

    scan.failed_entries = scan
        .entries
        .iter()
        .filter(|e| e.descriptor.is_err())
        .count();
    scan
}

/// Scan a whole `$SDS` stream with the production caps.
///
/// See [`parse_sds_with_limits`]. Terminates in at most `sds.len() / 16` steps
/// on any input, valid or hostile.
pub fn parse_sds(sds: &[u8]) -> SdsScan {
    parse_sds_with_limits(sds, MAX_SDS_ENTRIES)
}
