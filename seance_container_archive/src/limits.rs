//! The decompression-bomb ceiling, and how an examiner changes it.

use std::sync::OnceLock;

/// Environment variable naming the ceiling, in bytes.
pub const MAX_DECOMPRESSED_VAR: &str = "SEANCE_MAX_DECOMPRESSED_BYTES";

/// Default ceiling on a decompressed stream: 10 GiB.
pub const DEFAULT_MAX_DECOMPRESSED: u64 = 10 * 1024 * 1024 * 1024;

/// The ceiling in force for this run, and whether an examiner chose it.
///
/// The number cannot be read on its own. "10 GiB because nobody set anything"
/// and "10 GiB because somebody set 10G" are the same figure and different
/// facts, and only the second is a decision about this examination that a court
/// might want to ask about. The two halves therefore travel together, so
/// nothing downstream has to infer which of them it is holding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ceiling {
    /// Largest decompressed stream this run will materialise, in bytes.
    pub bytes: u64,
    /// Whether [`MAX_DECOMPRESSED_VAR`] carried a value that actually parsed.
    ///
    /// False for a run that never set it *and* for one that set it to something
    /// the parser refused: in both cases the built-in default is what governed
    /// the evidence, and saying otherwise would put a choice on the record that
    /// nobody made.
    pub from_env: bool,
}

/// Work out the ceiling from a raw setting, or the absence of one.
///
/// Kept pure and separate from the read-once cache below so that the decision —
/// which is the part that ends up quoted in a report — can be tested without an
/// environment variable and without test order mattering.
pub fn ceiling_from_env(raw: Option<&str>) -> Ceiling {
    match raw.and_then(parse_cap) {
        Some(bytes) => Ceiling {
            bytes,
            from_env: true,
        },
        None => Ceiling {
            bytes: DEFAULT_MAX_DECOMPRESSED,
            from_env: false,
        },
    }
}

/// The ceiling this run is working under.
///
/// The ceiling exists to stop a decompression bomb, and it must stay: an
/// unbounded expander turns a 400 KB file into a full disk. But it was a
/// compile-time constant, and real evidence outgrows it — a 9.4 GB iPhone
/// backup expands past 10 GiB, so the archive was refused whole and none of the
/// 580,394 artifacts inside it reached the case (LIVE-023). An examiner who
/// knows what they are opening can now raise it for the run without rebuilding.
///
/// Read once: the value is a property of the run, and re-reading per stream
/// would let it change midway through an examination.
pub fn ceiling() -> Ceiling {
    static CAP: OnceLock<Ceiling> = OnceLock::new();
    *CAP.get_or_init(|| ceiling_from_env(std::env::var(MAX_DECOMPRESSED_VAR).ok().as_deref()))
}

/// Largest decompressed stream this run will materialise.
pub fn max_decompressed_bytes() -> u64 {
    ceiling().bytes
}

/// Metadata key on an expanded container's child: the ceiling, in bytes, that
/// admitted the stream.
///
/// Deliberately not named `max_decompressed_bytes`: the fsevents plugin already
/// writes a key of that name for an unrelated 256 MiB cap of its own, and a
/// report that searched on it would quote that plugin's constant as the archive
/// ceiling.
pub const CEILING_BYTES_KEY: &str = "decompression_ceiling_bytes";

/// Metadata key beside [`CEILING_BYTES_KEY`]: where that figure came from.
///
/// Either `"default"` or the name of the variable that set it, so the record
/// names the exact knob that was turned rather than leaving a reader to work
/// out whether a familiar-looking number was chosen or merely inherited.
pub const CEILING_SOURCE_KEY: &str = "decompression_ceiling_source";

/// The value written under [`CEILING_SOURCE_KEY`].
pub fn ceiling_source(c: Ceiling) -> &'static str {
    if c.from_env {
        MAX_DECOMPRESSED_VAR
    } else {
        "default"
    }
}

/// Record the run's ceiling on a metadata object about to become an artifact.
///
/// The figure has to travel on the artifact because it cannot be recovered
/// afterwards: a CLI ingest and the report that quotes it are different
/// processes, and the reporting one caching its own idea of the ceiling would
/// state a number that never governed a byte of this evidence.
///
/// A metadata value that is not an object is left untouched rather than
/// panicking — nothing in the expanders builds one, and a bookkeeping field is
/// not worth taking an ingest down over.
pub fn stamp_ceiling(metadata: &mut serde_json::Value) {
    let c = ceiling();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert(CEILING_BYTES_KEY.to_string(), serde_json::json!(c.bytes));
        obj.insert(
            CEILING_SOURCE_KEY.to_string(),
            serde_json::json!(ceiling_source(c)),
        );
    }
}

/// The suffix form of a byte count, when it is exact.
///
/// Returns `None` for anything that is not a whole multiple of a binary unit:
/// the suffix is a courtesy to a reader scanning the figure, not a second
/// source of truth, and a rounded one would invite a check of the wrong number.
fn binary_suffix(bytes: u64) -> Option<String> {
    const UNITS: [(u64, char); 4] = [
        (1024u64 * 1024 * 1024 * 1024, 'T'),
        (1024 * 1024 * 1024, 'G'),
        (1024 * 1024, 'M'),
        (1024, 'K'),
    ];
    UNITS.iter().find_map(|&(unit, letter)| {
        (bytes >= unit && bytes.is_multiple_of(unit)).then(|| format!("{}{letter}", bytes / unit))
    })
}

/// A ceiling written for a reader: exact bytes, with the suffix the parser
/// accepts alongside it when the figure is a round one.
fn ceiling_figure(bytes: u64) -> String {
    match binary_suffix(bytes) {
        Some(suffix) => format!("{bytes} bytes ({suffix})"),
        None => format!("{bytes} bytes"),
    }
}

/// The sentence a report prints about the ceiling that governed an expansion.
///
/// It lives here, beside [`cap_guidance`], because every sentence this codebase
/// says about the ceiling should be readable in one place — the refusal and the
/// admission have to stay consistent with each other.
///
/// It confines itself to the three single-stream compressors that route through
/// this module. ZIP, 7z, OLE2 and the core btrfs path each enforce a separate
/// cap of their own, so a sentence that read as "the decompression ceiling for
/// this case" would overclaim across four limits it does not govern.
///
/// It states the ceiling as a **bound that held**, never as a refusal that
/// happened. The keys that trigger it are stamped only on a successful
/// expansion, and it is printed in the report's method-qualifications section —
/// the part that says what *was* read. On most runs nothing was refused at all,
/// so "a stream was refused whole" would be a false statement in a document
/// written to be handed to a court. A refusal that really did occur is recorded
/// separately, on the refused container itself, by [`cap_guidance`].
///
/// The same discipline decides how much [`Ceiling::from_env`] is allowed to
/// say. It records that somebody turned the knob, not which way they turned it:
/// an examiner working on a small workstation who sets 512M has *tightened* the
/// guard, and one who sets 10G has moved nothing at all. So the figure is
/// compared against [`DEFAULT_MAX_DECOMPRESSED`] and each direction described as
/// itself, and the comparison stays a comparison of two bounds — the stamp is
/// written on every successful expansion, a 4 KB one included, and cannot
/// evidence that any stream near either figure was ever met.
pub fn ceiling_statement(c: Ceiling) -> String {
    let figure = ceiling_figure(c.bytes);
    let shipped = ceiling_figure(DEFAULT_MAX_DECOMPRESSED);
    // Every arm closes the same way, because the bound and the whereabouts of a
    // real refusal are the same facts however the ceiling came to be set.
    let bound = format!(
        "A stream that would have expanded past {figure} would have been refused whole, with \
         nothing inside it examined, and any such refusal is recorded on the container it \
         refused. This figure does not govern other container formats, which enforce separate \
         limits of their own."
    );
    let opening = format!(
        "Compressed containers in gzip, bzip2 and xz form were expanded under a decompression \
         ceiling of {figure}"
    );
    if !c.from_env {
        // "The figure built into the software that expanded them", not the one
        // built into this build: the stamp travels on the artifact so that a
        // report rendered by a later build quotes the ceiling that governed the
        // evidence rather than its own constant.
        return format!(
            "{opening}, the built-in default: the figure built into the software that expanded \
             them, not a choice anybody recorded for this examination. The ceiling is adjustable \
             per run through {MAX_DECOMPRESSED_VAR}. {bound}"
        );
    }
    // A stock installation is named as the thing running the shipped default, so
    // the comparison carries the figure it is being made against and a reader
    // does not have to take "stock" on trust.
    let comparison = match c.bytes.cmp(&DEFAULT_MAX_DECOMPRESSED) {
        std::cmp::Ordering::Greater => format!(
            "That figure is above the built-in default of {shipped}, so the bound in force was \
             looser than a stock installation's: the streams this examination could expand \
             include ones a stock installation would have refused whole. Whether any such stream \
             was met here is not something the ceiling records."
        ),
        std::cmp::Ordering::Less => format!(
            "That figure is below the built-in default of {shipped}, so the bound in force was \
             tighter than a stock installation's: the streams this examination could expand are \
             a subset of those a stock installation would have expanded. Whether any such stream \
             was met here is not something the ceiling records."
        ),
        // Setting the ceiling to the figure it already had is still a decision
        // somebody made, and the record says so — but nothing moved, and a
        // sentence printing the same number twice as though one had replaced the
        // other contradicts itself in front of a reader who checks the figures.
        std::cmp::Ordering::Equal => "That figure is the built-in default, so the bound in force \
             was the one a stock installation would have applied."
            .to_string(),
    };
    format!("{opening}, set for this run with {MAX_DECOMPRESSED_VAR}. {comparison} {bound}")
}

/// Parse a ceiling. Plain bytes, or a `K`/`M`/`G`/`T` suffix (binary units).
///
/// A value that does not parse, or is zero, is rejected rather than silently
/// treated as "no limit": a typo in a ceiling must not remove the ceiling.
pub fn parse_cap(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (digits, multiplier) = match raw.chars().last()?.to_ascii_uppercase() {
        'K' => (&raw[..raw.len() - 1], 1024u64),
        'M' => (&raw[..raw.len() - 1], 1024 * 1024),
        'G' => (&raw[..raw.len() - 1], 1024 * 1024 * 1024),
        'T' => (&raw[..raw.len() - 1], 1024u64 * 1024 * 1024 * 1024),
        _ => (raw, 1),
    };
    let n: u64 = digits.trim().parse().ok()?;
    let bytes = n.checked_mul(multiplier)?;
    (bytes > 0).then_some(bytes)
}

/// Marker prefix on a decompression-bomb refusal.
///
/// The refusal has to be recognisable to the expanders, which say something
/// different about a ceiling than about a corrupt stream. Matching the prose of
/// the message instead — as three copies of the same branch once did — meant a
/// reworded sentence silently turned every cap refusal back into a bare error,
/// with nothing failing to compile and no test noticing.
const CAP_MARKER: &str = "decompression ceiling reached:";

/// The error a stream gets when it would exceed the run's ceiling.
pub fn cap_exceeded(cap: u64) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("{CAP_MARKER} decompressed stream exceeds the {cap}-byte cap"),
    )
}

/// Whether this error is the ceiling refusing a stream, as opposed to a corrupt
/// or truncated one. Paired with [`cap_exceeded`]; neither is useful alone.
pub fn is_cap_exceeded(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::InvalidData && err.to_string().contains(CAP_MARKER)
}

/// The sentence appended to a cap refusal, so the record says what to do next.
///
/// A refusal that states only the number leaves the examiner to discover, from
/// the source, that the number is adjustable at all.
pub fn cap_guidance(cap: u64) -> String {
    format!(
        "The {cap}-byte decompression ceiling was reached. Nothing inside this stream was \
         examined. Raise it for a run with {MAX_DECOMPRESSED_VAR} (accepts a K/M/G/T suffix) \
         if this archive is known evidence rather than a decompression bomb."
    )
}

/// What to record as the reason a stream could not be expanded.
///
/// A ceiling refusal and a corrupt stream are different stories with different
/// follow-up, and only one of them is something the examiner can act on. This
/// lived as eight byte-identical lines in each of the three expanders; one copy
/// keeps the three tiers saying the same thing.
pub fn expansion_failure_detail(err: &std::io::Error) -> String {
    if is_cap_exceeded(err) {
        format!("{err}. {}", cap_guidance(max_decompressed_bytes()))
    } else {
        err.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_byte_counts_parse() {
        assert_eq!(parse_cap("1024"), Some(1024));
    }

    #[test]
    fn binary_suffixes_parse() {
        assert_eq!(parse_cap("2K"), Some(2048));
        assert_eq!(parse_cap("3M"), Some(3 * 1024 * 1024));
        assert_eq!(parse_cap("64G"), Some(64 * 1024 * 1024 * 1024));
        assert_eq!(parse_cap("1T"), Some(1024u64 * 1024 * 1024 * 1024));
    }

    #[test]
    fn a_lowercase_suffix_is_the_same_unit() {
        assert_eq!(parse_cap("64g"), parse_cap("64G"));
    }

    /// A typo must not silently become "no ceiling at all" — that would turn a
    /// mistyped setting into an unbounded expander.
    #[test]
    fn a_value_that_does_not_parse_is_refused_rather_than_removing_the_limit() {
        for raw in ["", "  ", "lots", "-1", "9G9", "0", "0G"] {
            assert_eq!(parse_cap(raw), None, "{raw:?} must not yield a cap");
        }
    }

    #[test]
    fn an_absurd_value_does_not_overflow_into_a_small_one() {
        assert_eq!(parse_cap("18446744073709551615T"), None);
    }

    #[test]
    fn the_default_is_unchanged_when_nothing_is_set() {
        assert_eq!(DEFAULT_MAX_DECOMPRESSED, 10 * 1024 * 1024 * 1024);
    }

    /// The refusal has to name the variable; the number alone does not tell an
    /// examiner the ceiling can be moved.
    /// The constructor and the predicate are one contract: a refusal built here
    /// must be recognised here, whatever the wording around the marker becomes.
    #[test]
    fn a_cap_refusal_is_recognised_as_one() {
        let err = cap_exceeded(DEFAULT_MAX_DECOMPRESSED);
        assert!(is_cap_exceeded(&err));
        assert!(err.to_string().contains("10737418240"));
    }

    #[test]
    fn only_a_cap_refusal_carries_the_guidance() {
        assert!(expansion_failure_detail(&cap_exceeded(1024)).contains(MAX_DECOMPRESSED_VAR));
        let corrupt = std::io::Error::other("truncated mid-stream");
        let detail = expansion_failure_detail(&corrupt);
        assert!(!detail.contains(MAX_DECOMPRESSED_VAR));
        assert!(detail.contains("truncated mid-stream"));
    }

    #[test]
    fn a_corrupt_stream_is_not_mistaken_for_a_cap_refusal() {
        let other = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "decompression failed after 12 bytes",
        );
        assert!(!is_cap_exceeded(&other));
        assert!(!is_cap_exceeded(&std::io::Error::other("disk fell over")));
    }

    #[test]
    fn the_guidance_names_the_setting_and_says_nothing_was_examined() {
        let text = cap_guidance(DEFAULT_MAX_DECOMPRESSED);
        assert!(text.contains(MAX_DECOMPRESSED_VAR));
        assert!(text.contains("Nothing inside this stream was examined"));
    }

    /// The record has to tell "10 GiB because nobody set anything" apart from
    /// "10 GiB because an examiner set 10G": the same number, but not the same
    /// fact about how the evidence came to be opened.
    #[test]
    fn the_ceiling_remembers_whether_the_examiner_set_it() {
        let unset = ceiling_from_env(None);
        assert_eq!(unset.bytes, DEFAULT_MAX_DECOMPRESSED);
        assert!(!unset.from_env);

        let raised = ceiling_from_env(Some("64G"));
        assert_eq!(raised.bytes, 64 * 1024 * 1024 * 1024);
        assert!(raised.from_env);

        let restated = ceiling_from_env(Some("10G"));
        assert_eq!(restated.bytes, DEFAULT_MAX_DECOMPRESSED);
        assert!(
            restated.from_env,
            "a ceiling an examiner set to the default value is still one they set"
        );
    }

    /// The parse already refuses a typo and falls back to the default. What
    /// this asserts is that the record does not then go on to claim an examiner
    /// chose that number — a false statement about a person, in a document
    /// written to be read in court.
    #[test]
    fn a_typo_is_recorded_as_the_default_not_as_a_setting_the_examiner_made() {
        for raw in ["64GG", "0", "", "lots"] {
            let c = ceiling_from_env(Some(raw));
            assert_eq!(c.bytes, DEFAULT_MAX_DECOMPRESSED, "{raw:?}");
            assert!(!c.from_env, "{raw:?} never took effect, so nobody set it");
        }
    }

    #[test]
    fn the_ceiling_statement_names_the_number_the_units_and_the_variable() {
        let text = ceiling_statement(Ceiling {
            bytes: 68719476736,
            from_env: true,
        });
        assert!(text.contains("68719476736"));
        assert!(text.contains("64G"));
        assert!(text.contains(MAX_DECOMPRESSED_VAR));
        assert!(
            text.contains("set for this run"),
            "a raised ceiling must be stated as a decision somebody made"
        );
        assert!(
            text.contains("10737418240"),
            "the reader cannot weigh the raise without the default it replaced"
        );
    }

    /// The one way this entry could become a false statement about the
    /// examiner: printing the raised wording for a run where nothing was set.
    #[test]
    fn a_default_ceiling_statement_does_not_claim_anybody_set_it() {
        let text = ceiling_statement(Ceiling {
            bytes: DEFAULT_MAX_DECOMPRESSED,
            from_env: false,
        });
        assert!(text.contains("10737418240"));
        assert!(text.contains("10G"));
        assert!(
            text.contains(MAX_DECOMPRESSED_VAR),
            "the reader should know the figure is adjustable at all"
        );
        assert!(!text.contains("set for this run"));
        assert!(text.contains("built-in default"));
    }

    /// The statement must not read as "the decompression ceiling for this
    /// case": ZIP, 7z, OLE2 and the core btrfs path each carry their own
    /// separate cap, and this figure governs none of them.
    /// The statement is triggered by a key stamped only on a SUCCESSFUL
    /// expansion, and it is printed in the report's method-qualifications
    /// section — the part that says what WAS read, the counterpart of the
    /// incompleteness census. So it must not assert that a stream was refused:
    /// on most runs none was, and a court-facing document that says one was is
    /// simply wrong. The ceiling is a bound that held, not an event that
    /// happened, and the wording has to read that way in both branches.
    #[test]
    fn the_ceiling_statement_never_claims_a_stream_was_actually_refused() {
        for (ceiling, _arm) in every_arm() {
            let text = ceiling_statement(ceiling);
            assert!(
                !text.contains("was refused"),
                "the admission wording asserts a refusal that may never have \
                 happened: {text:?}"
            );
            assert!(
                text.contains("would have been refused"),
                "the bound still has to be stated, as the conditional it is: {text:?}"
            );
        }
    }

    /// The four shapes the statement has to tell apart. `from_env` alone does
    /// not decide what happened to the guard: an examiner can set it above the
    /// shipped figure, below it, or to the very same number.
    fn every_arm() -> [(Ceiling, &'static str); 4] {
        [
            (
                Ceiling {
                    bytes: DEFAULT_MAX_DECOMPRESSED,
                    from_env: false,
                },
                "nobody set it",
            ),
            (
                Ceiling {
                    bytes: 64 * 1024 * 1024 * 1024,
                    from_env: true,
                },
                "set above the default",
            ),
            (
                Ceiling {
                    bytes: 512 * 1024 * 1024,
                    from_env: true,
                },
                "set below the default",
            ),
            (
                Ceiling {
                    bytes: DEFAULT_MAX_DECOMPRESSED,
                    from_env: true,
                },
                "set to the default",
            ),
        ]
    }

    /// `from_env` says only that somebody turned the knob, never which way. An
    /// examiner on a small workstation who sets 512M has *tightened* the guard,
    /// and a report that told a court the guard was relaxed for the examination
    /// would state the opposite of what happened. The figure has to be compared
    /// with the shipped default, and each direction described as itself.
    #[test]
    fn a_ceiling_is_compared_with_the_default_in_the_direction_it_actually_moved() {
        let raised = ceiling_statement(Ceiling {
            bytes: 64 * 1024 * 1024 * 1024,
            from_env: true,
        });
        assert!(raised.contains("above the built-in default"), "{raised:?}");
        for wrong in ["below the built-in default", "tighter", "tightened"] {
            assert!(
                !raised.contains(wrong),
                "raised ceiling reads {wrong:?}: {raised:?}"
            );
        }

        let tightened = ceiling_statement(Ceiling {
            bytes: 512 * 1024 * 1024,
            from_env: true,
        });
        assert!(
            tightened.contains("below the built-in default"),
            "{tightened:?}"
        );
        for wrong in ["above the built-in default", "looser", "relaxed"] {
            assert!(
                !tightened.contains(wrong),
                "tightened ceiling reads {wrong:?}: {tightened:?}"
            );
        }

        // A ceiling an examiner set to the shipped figure moved nothing. Saying
        // it was set "instead of" the default, and printing the same number
        // twice as though one had replaced the other, is a sentence that
        // contradicts itself in front of a reader who checks the figures.
        let restated = ceiling_statement(Ceiling {
            bytes: DEFAULT_MAX_DECOMPRESSED,
            from_env: true,
        });
        assert!(
            restated.contains("set for this run"),
            "it was still a decision somebody made: {restated:?}"
        );
        for wrong in [
            "instead of",
            "above the built-in default",
            "below the built-in default",
            "relaxed",
            "tightened",
            "looser",
            "tighter",
        ] {
            assert!(
                !restated.contains(wrong),
                "a ceiling set to the default moved nothing, but reads {wrong:?}: {restated:?}"
            );
        }
    }

    /// The two stamped keys evidence three things and no more: the figure, that
    /// an examiner did or did not set it, and how it compares with the figure
    /// the software ships. They are written on every successful expansion,
    /// including a 4 KB one, so they cannot evidence that any particular stream
    /// was met, expanded or refused because of where the ceiling sat.
    ///
    /// The guard is written against the meaning rather than one turn of phrase.
    /// Its predecessor grepped for "was refused" alone, and a sentence claiming
    /// that "streams that a stock installation would have refused whole were
    /// expanded, and their contents entered the case" walked straight past it.
    #[test]
    fn no_arm_asserts_an_event_the_stamp_cannot_evidence() {
        for (ceiling, arm) in every_arm() {
            let text = ceiling_statement(ceiling);
            for claimed_event in [
                "was refused",
                "were refused",
                "were expanded, and",
                "entered the case",
                "was relaxed",
                "was tightened",
                "did expand",
                "were admitted",
            ] {
                assert!(
                    !text.contains(claimed_event),
                    "the {arm} arm asserts {claimed_event:?}, which the stamp does not \
                     evidence: {text:?}"
                );
            }
            // Anything said about a stock installation is a comparison of two
            // bounds, so every sentence that reaches for one has to stay in the
            // conditional rather than reporting it as something that occurred.
            for sentence in text.split(". ") {
                if sentence.contains("stock installation") {
                    assert!(
                        sentence.contains("would"),
                        "the {arm} arm states a stock installation's behaviour as fact: \
                         {sentence:?}"
                    );
                }
            }
            assert!(
                text.contains("would have been refused"),
                "the bound still has to be stated, as the conditional it is: {text:?}"
            );
        }
    }

    /// This paragraph is read in court, and each clause of it was argued
    /// against what the stamp can support. It is pinned word for word: a
    /// rewording is not a formatting change, and whoever makes one has to come
    /// back here, restate the sentence, and satisfy themselves that the new
    /// wording claims no more than the old one did.
    #[test]
    fn every_arm_is_pinned_word_for_word() {
        assert_eq!(
            ceiling_statement(Ceiling {
                bytes: DEFAULT_MAX_DECOMPRESSED,
                from_env: false,
            }),
            "Compressed containers in gzip, bzip2 and xz form were expanded under a \
             decompression ceiling of 10737418240 bytes (10G), the built-in default: the figure \
             built into the software that expanded them, not a choice anybody recorded for this \
             examination. The ceiling is adjustable per run through SEANCE_MAX_DECOMPRESSED_BYTES. \
             A stream that would have expanded past 10737418240 bytes (10G) would have been \
             refused whole, with nothing inside it examined, and any such refusal is recorded on \
             the container it refused. This figure does not govern other container formats, which \
             enforce separate limits of their own."
        );
        assert_eq!(
            ceiling_statement(Ceiling {
                bytes: 64 * 1024 * 1024 * 1024,
                from_env: true,
            }),
            "Compressed containers in gzip, bzip2 and xz form were expanded under a \
             decompression ceiling of 68719476736 bytes (64G), set for this run with \
             SEANCE_MAX_DECOMPRESSED_BYTES. That figure is above the built-in default of \
             10737418240 bytes (10G), so the bound in force was looser than a stock \
             installation's: the streams this examination could expand include ones a stock \
             installation would have refused whole. Whether any such stream was met here is not \
             something the ceiling records. A stream that would have expanded past 68719476736 \
             bytes (64G) would have been refused whole, with nothing inside it examined, and any \
             such refusal is recorded on the container it refused. This figure does not govern \
             other container formats, which enforce separate limits of their own."
        );
        assert_eq!(
            ceiling_statement(Ceiling {
                bytes: 512 * 1024 * 1024,
                from_env: true,
            }),
            "Compressed containers in gzip, bzip2 and xz form were expanded under a \
             decompression ceiling of 536870912 bytes (512M), set for this run with \
             SEANCE_MAX_DECOMPRESSED_BYTES. That figure is below the built-in default of \
             10737418240 bytes (10G), so the bound in force was tighter than a stock \
             installation's: the streams this examination could expand are a subset of those a \
             stock installation would have expanded. Whether any such stream was met here is not \
             something the ceiling records. A stream that would have expanded past 536870912 \
             bytes (512M) would have been refused whole, with nothing inside it examined, and any \
             such refusal is recorded on the container it refused. This figure does not govern \
             other container formats, which enforce separate limits of their own."
        );
        assert_eq!(
            ceiling_statement(Ceiling {
                bytes: DEFAULT_MAX_DECOMPRESSED,
                from_env: true,
            }),
            "Compressed containers in gzip, bzip2 and xz form were expanded under a \
             decompression ceiling of 10737418240 bytes (10G), set for this run with \
             SEANCE_MAX_DECOMPRESSED_BYTES. That figure is the built-in default, so the bound in \
             force was the one a stock installation would have applied. A stream that would have \
             expanded past 10737418240 bytes (10G) would have been refused whole, with nothing \
             inside it examined, and any such refusal is recorded on the container it refused. \
             This figure does not govern other container formats, which enforce separate limits \
             of their own."
        );
    }

    #[test]
    fn the_ceiling_statement_confines_itself_to_the_three_formats_it_governs() {
        for (ceiling, _arm) in every_arm() {
            let text = ceiling_statement(ceiling);
            for format in ["gzip", "bzip2", "xz"] {
                assert!(text.contains(format), "{format} unnamed in {text:?}");
            }
            assert!(text.contains("other container formats"));
        }
    }

    #[test]
    fn the_stamp_writes_both_keys_and_leaves_a_non_object_alone() {
        let mut metadata = serde_json::json!({});
        stamp_ceiling(&mut metadata);
        assert_eq!(
            metadata[CEILING_BYTES_KEY],
            serde_json::json!(max_decompressed_bytes())
        );
        assert!(metadata[CEILING_SOURCE_KEY].is_string());

        // Nothing in the expanders builds a scalar here, but a stamper that
        // panics on one would take an ingest down over a bookkeeping field.
        let mut scalar = serde_json::json!("not an object");
        stamp_ceiling(&mut scalar);
        assert_eq!(scalar, serde_json::json!("not an object"));
    }

    /// The two source values are the whole of the distinction, so they are
    /// pinned: a reader of the case record who sees the variable's name knows
    /// exactly which knob was turned.
    #[test]
    fn the_source_names_either_the_default_or_the_exact_variable_that_was_set() {
        assert_eq!(
            ceiling_source(Ceiling {
                bytes: DEFAULT_MAX_DECOMPRESSED,
                from_env: false
            }),
            "default"
        );
        assert_eq!(
            ceiling_source(Ceiling {
                bytes: 1024,
                from_env: true
            }),
            MAX_DECOMPRESSED_VAR
        );
    }

    /// The suffix is a courtesy for the reader, not a second source of truth:
    /// it appears only when it is exact, so "68719476736 bytes (64G)" can never
    /// round a figure the examiner is meant to check.
    #[test]
    fn a_ceiling_that_is_not_a_round_binary_multiple_shows_no_suffix() {
        assert_eq!(
            binary_suffix(64 * 1024 * 1024 * 1024),
            Some("64G".to_string())
        );
        assert_eq!(binary_suffix(2048), Some("2K".to_string()));
        assert_eq!(binary_suffix(1023), None);
        assert_eq!(binary_suffix(10 * 1024 * 1024 * 1024 + 1), None);
    }
}
