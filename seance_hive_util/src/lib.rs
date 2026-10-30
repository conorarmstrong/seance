#![forbid(unsafe_code)]
//! Shared recovery-state reporting for the plugins that read Windows registry
//! hives directly.
//!
//! Several plugins (`shimcache`, `amcache`, `shellbags`, …) open a hive's
//! primary file themselves rather than going through
//! `seance_plugin_registry`. Each of them therefore has to answer the same
//! question before it reports anything: *was this hive read in the state it was
//! captured in?* A dirty hive whose `.LOG1`/`.LOG2` were never replayed, or a
//! hive the load cap cut short, yields records that are real but a silence that
//! means nothing.
//!
//! That logic used to be copy-pasted, byte-identical, into each of those
//! crates. It did not stay identical: a fix that stopped
//! [`hive_state::stamp`] erasing an incompleteness reason an earlier stage had
//! already recorded landed in one copy only, so two plugins reporting on the
//! same hive told an examiner different completeness stories — a wrong answer
//! with nothing on the record to reveal it. One home, one story.
//!
//! Keep the stamped key names identical to
//! `seance_plugin_registry::stamp_replay_provenance`; they are an API/frontend
//! contract.

pub mod hive_state;
mod incomplete;

pub use incomplete::add_incomplete_reason;

/// The size of a hive's base block: the header the reader parses before it
/// looks at anything else.
const HIVE_BASE_BLOCK_BYTES: usize = 4096;

/// Open a registry hive the way every plugin that reads one directly must.
///
/// The magic and the base-block length are checked before the reader is handed
/// anything, so a file that is not a hive is an error that says so rather than
/// a fault inside a parser. That check is not ceremony: the GPL-licensed reader
/// this crate used until 2026-09-13 asserted rather than returned on a buffer
/// whose signature was not `regf`, and a `UsrClass.dat` that was not a hive —
/// carved, truncated, or one byte off — panicked it and lost the artifact
/// (HUNT-046). `seance_hive` returns an error for that case by design, and the
/// belt-and-braces `catch_unwind` below stays anyway: a parser fed carved bytes
/// is not the place to find out a bound was missed.
pub fn open_hive(bytes: &[u8]) -> Result<seance_hive::Hive<'_>, String> {
    open_hive_reporting(bytes).map(|opened| opened.hive)
}

/// What [`open_hive_reporting`] found about the header it accepted.
///
/// Both fields are qualifications the caller must carry onto what it emits: a
/// hive that is dirty may be missing its newest writes, and a hive that is
/// short is missing its last cells. Neither is a reason to refuse the hive —
/// see [`open_validated`] — and neither may be silent.
pub struct OpenedHive<'a> {
    pub hive: seance_hive::Hive<'a>,
    /// The sequence numbers did not match: the hive was not cleanly flushed.
    pub dirty: bool,
    /// `(declared, present)` hive-bin bytes when the base block declares more
    /// than the buffer holds; `None` when the hive is whole.
    pub short_by: Option<(usize, usize)>,
}

/// [`open_hive`], reporting what it tolerated.
pub fn open_hive_reporting(bytes: &[u8]) -> Result<OpenedHive<'_>, String> {
    if bytes.len() < HIVE_BASE_BLOCK_BYTES {
        return Err(format!(
            "not a registry hive: {} bytes, shorter than the {}-byte base block",
            bytes.len(),
            HIVE_BASE_BLOCK_BYTES
        ));
    }
    if &bytes[..4] != b"regf" {
        return Err(format!(
            "not a registry hive: signature {:?} is not \"regf\"",
            String::from_utf8_lossy(&bytes[..4])
        ));
    }
    match std::panic::catch_unwind(|| open_validated(bytes)) {
        Ok(Ok(opened)) => Ok(opened),
        Ok(Err(e)) => Err(format!("Failed to parse hive: {e}")),
        Err(_) => Err(
            "Failed to parse hive: the hive reader panicked on this header; the file is not a \
             hive this build can read"
                .to_string(),
        ),
    }
}

/// Validate the header, accepting a hive that was not cleanly flushed.
///
/// A hive lifted off a running Windows system almost always has mismatched
/// sequence numbers, because the newest writes are still only in its
/// `.LOG1`/`.LOG2` transaction logs. A strict reader refuses such a hive
/// outright. That refusal costs the *entire* hive — every key, every value,
/// every install date and USB serial in it — to avoid being stale about the
/// last few writes, and on a live acquisition it is the normal case, not the
/// exception: it is why a domain controller imaged while running produced no
/// registry records at all (HUNT-053).
///
/// So the sequence-number match is one of the two checks dropped here.
/// Everything else the reader validates — signature, version, file type, file
/// format, declared-size alignment, clustering factor, base-block checksum — is
/// still enforced, so a genuinely corrupt header is still an error.
///
/// The dirtiness itself is never swallowed: every caller of this function runs
/// [`hive_state::inspect`] (or, in the registry plugin, the replay engine) and
/// stamps `hive_dirty` plus the replay outcome onto what it emits, so an
/// examiner reading a record parsed out of an unrecovered hive is told that the
/// hive's most recent writes may be missing from it.
///
/// The second tolerance is a base block that declares more hive-bin data than
/// the buffer holds. A volume-shadow copy of a hive taken while it was growing,
/// or a file the acquisition cut short, has every cell up to the cut intact and
/// readable; the reader bounds every cell against the buffer, so nothing past
/// the end is ever read. Refusing the whole hive over the missing tail lost a
/// 48 MB `SOFTWARE` hive to a 216 KB shortfall on the NIST Data Leakage image
/// (HUNT-061). The shortfall is reported so the caller stamps it.
fn open_validated(bytes: &[u8]) -> Result<OpenedHive<'_>, seance_hive::HiveError> {
    let hive = seance_hive::Hive::without_validation(bytes)?;
    // Both tolerances at once, then report what was tolerated. Asking for one
    // at a time loses a hive that is BOTH unflushed and cut short — a shadow
    // copy of a live machine's `SOFTWARE` is routinely both — because the first
    // refusal is returned before the second is ever considered.
    hive.validate_allowing(seance_hive::Tolerances::lenient())?;

    let (primary, secondary) = hive.sequence_numbers();
    let declared = hive.declared_data_size();
    let present = hive.present_data_size();
    Ok(OpenedHive {
        hive,
        dirty: primary != secondary,
        short_by: (declared > present).then_some((declared, present)),
    })
}

#[cfg(test)]
mod open_hive_tests {
    use super::{open_hive, open_hive_reporting};

    /// The bytes the fuzzer found: `reg&`, one bit off the magic, which the
    /// upstream reader answered with a panic rather than an error (HUNT-046).
    #[test]
    fn a_near_miss_signature_is_an_error_not_a_panic() {
        let mut near_miss = vec![0u8; 4689];
        near_miss[..4].copy_from_slice(b"reg&");
        let err = match open_hive(&near_miss) {
            Ok(_) => panic!("a near-miss signature is not a hive"),
            Err(e) => e,
        };
        assert!(
            err.contains("reg&") && err.contains("not a registry hive"),
            "{err}"
        );

        let short = b"regf";
        let err = match open_hive(short) {
            Ok(_) => panic!("four bytes are not a hive"),
            Err(e) => e,
        };
        assert!(err.contains("shorter than"), "{err}");

        // A well-formed magic on an otherwise empty base block reaches the
        // reader, which reports it as an error of its own.
        let mut empty = vec![0u8; 8192];
        empty[..4].copy_from_slice(b"regf");
        assert!(open_hive(&empty).is_err());
    }

    /// A `regf` base block the reader accepts, with the given sequence numbers
    /// and a checksum that verifies. No hbin body: `validate` never looks at
    /// one, and these tests are about the header alone.
    fn base_block(primary_seq: u32, secondary_seq: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 0x2000];
        buf[..4].copy_from_slice(b"regf");
        buf[4..8].copy_from_slice(&primary_seq.to_le_bytes());
        buf[8..12].copy_from_slice(&secondary_seq.to_le_bytes());
        buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // major version
        buf[0x18..0x1C].copy_from_slice(&5u32.to_le_bytes()); // minor version
        buf[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes()); // primary hive
        buf[0x20..0x24].copy_from_slice(&1u32.to_le_bytes()); // direct format
        buf[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes()); // root cell
        buf[0x28..0x2C].copy_from_slice(&0x1000u32.to_le_bytes()); // hbins size
        buf[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes()); // clustering
        let mut sum: u32 = 0;
        for chunk in buf[..0x1FC].as_chunks::<4>().0.iter() {
            sum ^= u32::from_le_bytes(*chunk);
        }
        let sum = match sum {
            0 => 1,
            0xFFFF_FFFF => 0xFFFF_FFFE,
            other => other,
        };
        buf[0x1FC..0x200].copy_from_slice(&sum.to_le_bytes());
        buf
    }

    /// HUNT-053. A hive copied off a running machine has its newest writes only
    /// in the transaction logs, so its two sequence numbers differ. Refusing it
    /// costs every key in the hive to avoid being stale about the last few
    /// writes — on a live acquisition, all of the registry rather than some of
    /// it. Every other header check still has to bite.
    #[test]
    fn an_unflushed_hive_opens_while_a_corrupt_header_still_does_not() {
        assert!(open_hive(&base_block(7, 7)).is_ok(), "a clean hive opens");
        assert!(
            open_hive(&base_block(8, 7)).is_ok(),
            "a dirty hive is structurally intact and must open"
        );

        // The checks that are NOT relaxed.
        let mut bad_version = base_block(8, 7);
        bad_version[0x18..0x1C].copy_from_slice(&9u32.to_le_bytes());
        assert!(
            open_hive(&bad_version).is_err(),
            "an unknown minor version is still refused"
        );

        let mut bad_checksum = base_block(8, 7);
        bad_checksum[0x1FC..0x200].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(
            open_hive(&bad_checksum).is_err(),
            "a base block whose checksum does not verify is still refused"
        );

        let mut bad_type = base_block(8, 7);
        bad_type[0x1C..0x20].copy_from_slice(&6u32.to_le_bytes());
        assert!(
            open_hive(&bad_type).is_err(),
            "a transaction log fed in as a hive is still refused"
        );
    }

    /// HUNT-061. A shadow copy of `SOFTWARE` on the NIST Data Leakage image
    /// holds 48,230,400 bytes of hive bins and declares 48,447,488. Every cell
    /// up to the cut is intact; the reader refused all of them. The shortfall
    /// is a qualification the caller must stamp, not a reason to lose the hive.
    #[test]
    fn a_hive_cut_short_of_its_declared_size_opens_and_says_by_how_much() {
        // Declares 0x2000 of bins; holds 0x1000.
        let mut short = base_block(7, 7);
        short[0x28..0x2C].copy_from_slice(&0x2000u32.to_le_bytes());
        // Re-checksum after the edit so only the size is wrong.
        let mut sum: u32 = 0;
        for chunk in short[..0x1FC].as_chunks::<4>().0.iter() {
            sum ^= u32::from_le_bytes(*chunk);
        }
        let sum = match sum {
            0 => 1,
            0xFFFF_FFFF => 0xFFFF_FFFE,
            other => other,
        };
        short[0x1FC..0x200].copy_from_slice(&sum.to_le_bytes());

        let opened = open_hive_reporting(&short).expect("a short hive opens");
        assert_eq!(opened.short_by, Some((0x2000, 0x1000)));
        assert!(!opened.dirty);

        // Whole and clean: nothing reported.
        let whole_bytes = base_block(7, 7);
        let whole = open_hive_reporting(&whole_bytes).unwrap();
        assert_eq!(whole.short_by, None);
        assert!(!whole.dirty);
        // Dirty: reported as dirty, not as short.
        let dirty_bytes = base_block(8, 7);
        let dirty = open_hive_reporting(&dirty_bytes).unwrap();
        assert!(dirty.dirty);
        assert_eq!(dirty.short_by, None);

        // A declared size that is not 4096-aligned is still a corrupt header.
        let mut misaligned = base_block(7, 7);
        misaligned[0x28..0x2C].copy_from_slice(&0x1234u32.to_le_bytes());
        assert!(open_hive_reporting(&misaligned).is_err());
    }
}
