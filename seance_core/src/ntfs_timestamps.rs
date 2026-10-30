//! NTFS timestamp indicators: the `$STANDARD_INFORMATION` / `$FILE_NAME`
//! comparison, graded. Shared by the on-disk MFT parser and the memory MFT
//! sweep so one rule — and one measured false-positive rate — answers
//! "was this file timestomped?" wherever an MFT record is read (HUNT-051,
//! HUNT-073).

/// Sub-second component of a Windows FILETIME, in 100ns units (0..10_000_000).
pub fn filetime_subsec(ft: u64) -> u64 {
    ft % 10_000_000
}

/// Whole seconds of a Windows FILETIME (since 1601), dropping sub-second precision.
pub fn filetime_seconds(ft: u64) -> u64 {
    ft / 10_000_000
}

/// One thing the SI/FN comparison noticed, and what an ordinary file operation
/// would have to be ruled out before it means tampering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestompIndicator {
    /// What was observed, in the examiner's words.
    pub reason: String,
    /// True when no ordinary file operation produces this pattern.
    pub strong: bool,
    /// The ordinary operation that produces it, when there is one. `None` only
    /// for a strong indicator.
    pub benign_explanation: Option<String>,
}

/// NTFS timestamp indicators from the $SI/$FN comparison, and how much each is
/// worth.
///
/// Compares $STANDARD_INFORMATION (SI) and $FILE_NAME (FN) Windows FILETIMEs.
/// Each argument is `Some` only when the timestamp is present and valid (never
/// zero/epoch), so absent attributes simply mean fewer signals, never a hard
/// error.
///
/// # Why most of these are not evidence of tampering
///
/// FN timestamps are written when the name entry is created and are not updated
/// by normal file operations, whereas SI timestamps are freely rewritten by the
/// Win32 API. That asymmetry is real, and it is also produced by two operations
/// every Windows machine performs constantly:
///
/// * **A copy** keeps the source's Last-Modified in SI while FN records when the
///   copy landed, so `SI Modified < FN Created` is what an installed file looks
///   like — not what a tampered one looks like.
/// * **A move or rename within a volume** writes a fresh FN while SI keeps
///   everything, so `SI Created < FN Created` is what every file in the Recycle
///   Bin looks like.
///
/// Measured on the NIST CFReDS "Hacking Case" image — a stock Windows XP
/// install — the old rule flagged **4,054 of 25,018 files (16%)**, 4,026 of them
/// for `SI Modified < FN Created` alone, concentrated in `WINDOWS\system32`,
/// `WINDOWS\Cursors` and installer directories (`HUNT-051`). An indicator that
/// fires on a sixth of a clean disk teaches its reader to ignore it, and the one
/// file that WAS stomped is then indistinguishable from the four thousand that
/// were not.
///
/// So the weak signals are still reported — an examiner may want to see them,
/// and a combination can matter — but only a **strong** indicator makes
/// `timestomp_suspected` true. Two are strong: the bulk-set signal, which no
/// ordinary operation produces, and a whole-second $SI ChangeTime older than
/// the record's own $FN Created (signal 5). The cost of the trade is stated
/// plainly: a tool that rewrites one $SI field to a full-precision value
/// leaves a weak indicator and no verdict.
pub fn detect_timestomp_indicators(
    si_created: Option<u64>,
    si_modified: Option<u64>,
    si_mft: Option<u64>,
    si_accessed: Option<u64>,
    fn_created: Option<u64>,
) -> Vec<TimestompIndicator> {
    let mut out = Vec::new();

    // Signal 1: SI Created earlier than FN Created.
    //
    // Weak. A move or rename inside the volume writes a new $FN at the moment of
    // the move while $SI keeps the original creation time, so every file in
    // `\RECYCLER` carries this by construction.
    if let (Some(si_c), Some(fn_c)) = (si_created, fn_created) {
        if si_c < fn_c {
            out.push(TimestompIndicator {
                reason: "SI Created precedes FN Created".to_string(),
                strong: false,
                benign_explanation: Some(
                    "a move or rename within the volume, which writes a new $FN while $SI keeps \
                     the original creation time"
                        .to_string(),
                ),
            });
        }
    }

    // Signal 2: SI Modified earlier than FN Created.
    //
    // Weak, and the single largest source of noise. The old comment read "a file
    // cannot be modified before it exists", which is true of the file and false
    // of the NAME: a copy creates a new name entry for content that was modified
    // earlier.
    if let (Some(si_m), Some(fn_c)) = (si_modified, fn_created) {
        if si_m < fn_c {
            out.push(TimestompIndicator {
                reason: "SI Modified precedes FN Created".to_string(),
                strong: false,
                benign_explanation: Some(
                    "a copy, which preserves the source's modification time in $SI while $FN \
                     records when the copy landed"
                        .to_string(),
                ),
            });
        }
    }

    // Signal 3: SI Created truncated to a whole second while FN Created keeps a
    // sub-second fraction.
    //
    // Weak, and only in that direction: tools that write SI with one-second
    // granularity leave this, and so does a copy from a volume whose timestamps
    // are coarser than NTFS's (FAT's two-second granularity). The reverse
    // direction — FN whole, SI fractional — is not something a stomping tool
    // produces, and is no longer reported at all.
    if let (Some(si_c), Some(fn_c)) = (si_created, fn_created) {
        if filetime_subsec(si_c) == 0 && filetime_subsec(fn_c) != 0 {
            out.push(TimestompIndicator {
                reason: "SI Created is whole-second where FN Created is not".to_string(),
                strong: false,
                benign_explanation: Some(
                    "a copy from a volume with coarser timestamps (FAT keeps two-second \
                     granularity), or an installer that sets whole-second times"
                        .to_string(),
                ),
            });
        }
    }

    // Signal 4: all four SI timestamps identical to the second, with an FN
    // Created that differs.
    //
    // STRONG. Ordinary use does not set created, modified, MFT-changed and
    // accessed to one instant: those four diverge the moment a file is written
    // or read. A tool that stamps all four at once does exactly this, and the
    // FN guard keeps a genuinely just-created file out of it.
    if let (Some(c), Some(m), Some(mft), Some(a)) = (si_created, si_modified, si_mft, si_accessed) {
        let sc = filetime_seconds(c);
        let all_equal =
            sc == filetime_seconds(m) && sc == filetime_seconds(mft) && sc == filetime_seconds(a);
        if all_equal {
            if let Some(fn_c) = fn_created {
                if filetime_seconds(fn_c) != sc {
                    out.push(TimestompIndicator {
                        reason: "SI M/A/C/B timestamps identical to the second (bulk-set)"
                            .to_string(),
                        strong: true,
                        benign_explanation: None,
                    });
                }
            }
        }
    }

    // Signal 5: SI MFT-changed (the ChangeTime) whole-second, and earlier than
    // a sub-second FN Created.
    //
    // STRONG. The filesystem writes ChangeTime itself, with full precision, on
    // every change to the record — and writing the name entry is a change to
    // the record, so a ChangeTime older than $FN Created was not written by
    // the filesystem after the name was. Restore semantics (AppX deployment,
    // WinSxS servicing, the driver store) do carry a source's older ChangeTime
    // across, but they carry it at full precision: on the two Windows images
    // of DFIR Madness Case 001 4,231 files have a ChangeTime older than their
    // name entry and exactly one of them has it whole-second — the file the
    // answer key names as timestomped (HUNT-073). Zero of 84,674 on the NIST
    // Data Leakage image. A whole-second value that the filesystem never
    // writes whole, older than an entry the filesystem wrote after it, was
    // set by a tool.
    if let (Some(si_mft), Some(fn_c)) = (si_mft, fn_created) {
        if filetime_subsec(si_mft) == 0
            && filetime_subsec(fn_c) != 0
            && filetime_seconds(si_mft) < filetime_seconds(fn_c)
        {
            out.push(TimestompIndicator {
                reason: "SI MFT-changed is whole-second and precedes FN Created".to_string(),
                strong: true,
                benign_explanation: None,
            });
        }
    }

    out
}
