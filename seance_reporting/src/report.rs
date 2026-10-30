//! Court-defensible forensic report renderer.
//!
//! This module renders a [`ReportData`] value into a self-contained,
//! print-friendly HTML document or into a PDF (via `printpdf`). It surfaces the
//! forensically material facts that a thin data dump omits: acquisition hashes
//! for every evidence source, a full evidence table (size + MD5/SHA1/SHA256),
//! notable hash-set matches, examiner findings, and an embedded chain of custody
//! / audit trail whose hash-chain verification result is stated prominently.
//!
//! The input contract ([`ReportData`] and friends) is built by the API layer
//! and passed to [`render_html`] / [`render_pdf`]; the field names and types are
//! part of that contract and must not drift.

use printpdf::*;

/// Complete input for a forensic report.
///
/// Fields added after the initial contract are appended and default to empty so
/// callers that do not yet populate a section simply omit it from the rendered
/// output. Every new section is optional/empty-tolerant by construction.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ReportData {
    pub case_name: String,
    pub case_reference: Option<String>,
    pub examiner: String,
    pub generated_at: String,
    pub tool_name: String,
    pub tool_version: String,
    /// Auto-generated narrative synthesised from the findings. Rendered at the
    /// top of the report. Neither FTK nor Autopsy produces a prose summary.
    pub executive_summary: Option<String>,
    /// FTK-style File Overview counts (total, deleted, encrypted, alerts...).
    pub file_overview: Option<FileOverview>,
    pub evidence_sources: Vec<EvidenceSource>,
    /// Hash re-verification: acquisition hashes vs later recomputation.
    pub integrity_checks: Vec<IntegrityCheck>,
    pub artifact_counts: Vec<(String, i64)>,
    pub total_artifacts: i64,
    /// Per-artifact-category detail sections (web history, email, chat,
    /// registry, program execution, EXIF, carved, deleted, ...). This is the
    /// bulk of the report body that FTK/Autopsy organise their reports around.
    pub category_sections: Vec<CategorySection>,
    pub bookmarks: Vec<ReportBookmark>,
    /// How many PERSONAL bookmarks exist in the case and are not in
    /// [`Self::bookmarks`] (ROADMAP §3.15). A personal bookmark is an
    /// examiner's private scratch mark and never reaches a report; the count is
    /// stated so that the exclusion is on the record rather than silent. The
    /// notes themselves, and whose they are, are deliberately not reported.
    pub personal_bookmarks_excluded: i64,
    /// Values the examiner traced across the evidence and pinned to the case
    /// (`ROADMAP.md` §5.13).
    ///
    /// Examiner-authored, like [`Self::bookmarks`] and unlike
    /// [`Self::leads`]: the tool answered the question, the examiner decided
    /// the answer belonged in the document. Empty renders nothing.
    pub traced_values: Vec<ReportTracedValue>,
    /// Investigative leads Séance raised itself (`ROADMAP.md` §2.2).
    ///
    /// Kept apart from [`Self::bookmarks`] and from the category sections on
    /// purpose. Everything else in this report is a transcription — the MFT
    /// said this, the registry held that — or an examiner's own mark. A lead is
    /// the tool's claim that a pattern deserves attention, and Part VI of
    /// `ROADMAP.md` forbids rendering that beside a parsed artifact as though
    /// the two were established the same way. Empty renders nothing.
    pub leads: Vec<ReportLead>,
    /// Case-wide lead count; the listing above may be capped. Same contract as
    /// [`Self::full_timeline_total`].
    pub leads_total: i64,
    /// What the build that produced this report could look for at all.
    ///
    /// Rendered with the leads whether or not any were raised, because an
    /// empty section means one of two completely different things — nothing
    /// matched the checks present, or nothing here looks for what the reader is
    /// after — and a report that cannot tell them apart invites the first
    /// reading.
    pub lead_detections: Vec<ReportLeadDetection>,
    /// The sentence the findings surface published about its own coverage: how
    /// many checks this build carries, and whether the whole-case checks could
    /// be run at all. Carried verbatim rather than rebuilt, so the report and
    /// the screen cannot drift.
    pub leads_coverage_note: Option<String>,
    /// GPS points (from EXIF) surfaced in the report and exported as KML.
    pub geolocation: Vec<GeoPoint>,
    /// True when the geolocation query returned its maximum: the points above
    /// are a bounded subset and the case may hold more.
    ///
    /// There is no exact case-wide total to state here — the query stops at the
    /// cap without counting past it — so the renderers say "at least N" rather
    /// than a number they cannot verify. This must never be omitted: a capped
    /// list of GPS fixes is the section that places a person at a scene, and a
    /// silently-truncated one reads as "these are all the places this device
    /// was".
    pub geolocation_truncated: bool,
    pub timeline_highlights: Vec<ReportTimelineEvent>,
    /// The full (bounded) timeline, distinct from the tagged highlights above.
    pub full_timeline: Vec<ReportTimelineEvent>,
    /// Case-wide timeline event count, which may exceed `full_timeline.len()`
    /// because the listing is capped. The renderer states both so the report
    /// never understates how many events the case holds. A value below the
    /// listed length is treated as "no truncation".
    pub full_timeline_total: i64,
    pub audit_entries: Vec<ReportAuditEntry>,
    /// Case-wide audit-entry count; the listing above is capped. Same contract
    /// as `full_timeline_total`.
    pub audit_entries_total: i64,
    pub audit_chain_valid: bool,
    pub audit_chain_checked: i64,
    /// Whether a passing chain verdict is evidence that nothing was altered.
    ///
    /// Mirrors `seance_db::AuditChainStatus::tamper_evident`: true only when the
    /// chain is keyed (`SEANCE_AUDIT_HMAC_KEY` set), because only then does the
    /// digest depend on a secret the database does not hold. An unkeyed chain is
    /// a plain SHA-256 over fields that all live in that same database, so a
    /// `valid` verdict on one means the log is internally consistent and nothing
    /// more (HUNT-011). The renderers must never print the adjective
    /// "tamper-evident" over a report where this is false.
    ///
    /// `Default` is `false`, deliberately: a caller that has not wired the
    /// keying through gets the cautious claim, never the unearned one.
    pub audit_chain_tamper_evident: bool,
    /// Where the tamper-evident part of the chain begins, when it does not
    /// begin at the start.
    ///
    /// Mirrors `seance_db::AuditChainStatus::tamper_evident_from`. A deployment
    /// that set `SEANCE_AUDIT_HMAC_KEY` on an existing log has rows written
    /// unkeyed before that day and keyed rows after it; `audit_chain_tamper_evident`
    /// is then false for the chain as a whole, and this is the id of the first
    /// row from which a passing verification IS evidence of no alteration. The
    /// renderers state it, because "the chain is unkeyed" over such a log
    /// understates what the keyed rows prove, and "the chain is keyed" overstates
    /// what the unkeyed ones do. `None` when no row is keyed, or when the whole
    /// chain is (in which case `audit_chain_tamper_evident` already says so).
    pub audit_chain_tamper_evident_from: Option<i64>,
    /// Whether the server holds an audit key. Mirrors
    /// `seance_db::AuditChainStatus::key_configured`; see it for why an
    /// all-unkeyed chain reads differently on a keyed server (SEC-009).
    pub audit_chain_key_configured: bool,
    /// Why the chain failed to verify, in the verifier's own words, when it did.
    ///
    /// Mirrors `seance_db::AuditChainStatus::break_reason`. Carried because a
    /// failed verdict is not one thing: "row 900 does not recompute under any
    /// configured key — its content or hash has been altered" and "row 1 was
    /// written under a key fingerprint that matches neither the current key nor
    /// any retired one" are different findings, and the second is a
    /// configuration state, not a custody failure. Without this the report
    /// printed *"Evidence handling integrity cannot be attested"* for a rotated
    /// key whose predecessor had not been supplied — asserting, on a court
    /// document, a failure the evidence does not show.
    pub audit_chain_break_reason: Option<String>,
    /// Tool/module execution provenance (which parser produced what, timing).
    pub processing_log: Vec<ProcessingLogEntry>,
    /// Distinct processing-log groups the case holds; the listing above may be
    /// capped below it. Same contract as `full_timeline_total`.
    pub processing_log_total: i64,
    /// Case-wide census of plugin-recorded incompleteness.
    ///
    /// `None` means completeness was NOT assessed for this case, which the
    /// renderers state explicitly. It must never be confused with
    /// `Some(<all zeroes>)`, which means the case was assessed and found
    /// complete. A report that simply omits the question is the failure mode
    /// this field exists to close: the most dangerous reading of a forensic
    /// report is "it did not mention it, so it did not happen".
    pub incompleteness: Option<IncompletenessSummary>,
    pub notable_hash_hits: Vec<ReportHashHit>,
    /// Case-wide count of notable matches, which may exceed
    /// `notable_hash_hits.len()` because the listing is paged. A value below the
    /// listed length is treated as "no truncation".
    pub notable_hash_total: i64,
    /// Known-good (KFF "ignore") matches, reported alongside notable ones so the
    /// report states both directions of hash classification.
    pub known_good_hash_hits: Vec<ReportHashHit>,
    /// Case-wide count of known-good matches; see `notable_hash_total`.
    pub known_good_hash_total: i64,
    /// Who conducted the examination, in the detail a court expects.
    ///
    /// `None` falls back to the bare [`ReportData::examiner`] name, which is
    /// what every existing caller supplies. A report that cannot say who
    /// produced it, in what role, for which organisation, is a report whose
    /// author cannot be put in a witness box.
    pub examiner_details: Option<ExaminerDetails>,
    /// This document's own identity, so two revisions can be told apart.
    pub report_identity: Option<ReportIdentity>,
    /// Terms defined for a reader who is not a forensic practitioner.
    ///
    /// Empty renders nothing. A report that will be read by counsel, a jury or
    /// a judge has to define its own vocabulary: "slack space", "carved",
    /// "MFT" and "unallocated" all carry evidential weight that is lost if the
    /// reader guesses at them.
    pub glossary: Vec<GlossaryEntry>,
    /// Ways the method itself qualifies the findings above.
    ///
    /// Distinct from [`ReportData::incompleteness`], which says what was not
    /// read. These say something was read, and by what means — where a step
    /// rested on a weaker footing than the alternative, or on a source that
    /// nothing independent corroborated.
    ///
    /// Empty renders nothing, and that is the common case: a qualification
    /// invented for every examination is one a reader learns to skip. When one
    /// is present it belongs in the report whether or not it changes a
    /// conclusion, because the question at trial is not only what was found but
    /// what the finding rests on.
    pub method_qualifications: Vec<MethodQualification>,
}

/// One value the examiner pinned after tracing it across the evidence.
///
/// Carries **two** answers on purpose: what the pivot said when the examiner
/// pinned it, and what the same value says at the moment this report was
/// produced. A report that showed only the first would describe a case that has
/// since grown; one that showed only the second would quietly say something
/// different from what the examiner saw, with nothing to show that it had
/// changed. Where they differ, the difference is the fact worth having.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ReportTracedValue {
    /// The value that was traced.
    pub value: String,
    /// Why the examiner pinned it.
    pub note: Option<String>,
    pub examiner: String,
    /// When it was pinned, as written for a reader.
    pub pinned_at: String,
    /// Artifacts the case held for the value **when it was pinned**.
    pub matches_when_pinned: i64,
    /// The per-kind counts below are a sample, not a total: the pivot's cap
    /// bit when the snapshot was taken.
    pub truncated_when_pinned: bool,
    /// `kind` / `count` pairs as the snapshot recorded them.
    pub groups_when_pinned: Vec<(String, i64)>,
    /// Artifacts the case holds for the value **now**, or `None` where the
    /// question could not be re-asked (no search index in this build, or the
    /// re-run failed). Absent is not zero: "we could not look again" and "it
    /// matches nothing now" are different facts.
    pub matches_now: Option<i64>,
    /// Why the re-run gave no answer, when it gave none.
    pub recheck_unavailable_reason: Option<String>,
}

/// One investigative lead, as the report renders it.
///
/// The three text fields are separate because they are different in kind and
/// the report may not merge them: [`Self::observation`] is a fact a reader can
/// check against the artifact it names, [`Self::inference`] is what the pattern
/// may indicate and is opinion, and [`Self::qualification`] states what the
/// lead does **not** establish. A renderer that ran them into one paragraph
/// would undo the distinction the type exists to keep.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ReportLead {
    /// Human label for the row.
    pub title: String,
    /// Stable machine token for the kind of lead, so a lead can be cited.
    pub kind: String,
    /// `Strong`, `Notable` or `Weak` — how much room there is for an innocent
    /// explanation. Never a score: nothing here measures anything.
    pub confidence: String,
    /// **The invariant that broke, as a fact.**
    pub observation: String,
    /// **What the pattern may indicate.** Opinion. `None` where the
    /// observation speaks for itself.
    pub inference: Option<String>,
    /// **What this lead does not establish**, and the ordinary causes that
    /// would produce the same pattern. Never empty.
    pub qualification: String,
    /// The values the observation rests on, as `name = value` pairs.
    pub evidence: Vec<(String, String)>,
    /// The artifact the lead is about, so a reviewer can open it.
    pub subject: String,
    /// Byte offset on the backing device, where the subject has one.
    pub device_offset: Option<u64>,
    /// The code that made the claim.
    pub source_module: String,
    /// Whether the lead is stored as a record in the case.
    ///
    /// The whole-case checks are computed when the list is requested rather
    /// than raised during ingest, so they have no artifact of their own and a
    /// reviewer cannot re-open the lead itself — only the subject it names.
    /// Stated, because a citation that cannot be followed is worse than one
    /// that is labelled as such.
    pub stored_as_a_record: bool,
}

/// One check the build that produced this report can perform.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ReportLeadDetection {
    /// The kind of lead it raises.
    pub kind: String,
    /// What it looks for, in a sentence.
    pub looks_for: String,
}

/// The paragraph that introduces the leads section, in every format.
///
/// Written once because it is the section's whole defence. A reader who takes
/// a lead for a finding of fact has been misled by the report, not by the
/// evidence, and the wording in `documentation/REPORTING_DESIGN.md` is this
/// string.
pub const LEADS_PREAMBLE: &str = "\
    The items in this section were raised by Séance itself, by rule, and are \
    investigative leads — not findings of fact and not transcriptions of the \
    evidence. Each states an observation that can be checked against the \
    artifact it names, separately from any inference drawn from it, and \
    separately again from what it does not establish. None of them has been \
    corroborated by any independent means. Nothing in this section should be \
    read as a conclusion, and a lead not raised here is not evidence that the \
    pattern it would have described is absent: the checks this build can \
    perform are listed below it.";

/// The qualification the leads section puts into Limitations.
///
/// §2.2 of `ROADMAP.md` requires every lead to be "graded, qualified in the
/// report's Limitations, never rendered beside a parsed artifact as though
/// established the same way". This is the second of those three, and it is
/// generated from the presence of the section rather than supplied by the
/// examiner, so it cannot be omitted from a report that carries leads.
pub fn leads_qualification(
    lead_count: i64,
    detection_count: usize,
    coverage_note: Option<&str>,
) -> MethodQualification {
    let mut statement = format!(
        "This report includes {lead_count} investigative lead(s) that Séance raised itself, \
         under Investigative Leads. They are the tool's own claims that a pattern deserves \
         attention, reached by applying {detection_count} fixed rule(s) to artifacts other \
         parts of this examination transcribed from the evidence. They were not produced by an \
         examiner exercising judgement, they have not been corroborated by any independent \
         tool or method, and a grade of Strong on one of them means only that the pattern is \
         hard to produce by ordinary use of the machine — not that anything was established. \
         Each lead carries, in its own entry, the ordinary causes that would produce the same \
         pattern; those qualifications are part of the lead and are not repeated here."
    );
    if let Some(note) = coverage_note {
        let note = note.trim();
        if !note.is_empty() {
            statement.push(' ');
            statement.push_str(note);
        }
    }
    statement.push_str(
        " The absence of a lead about any particular pattern is not evidence that the pattern \
         is absent from this evidence; it means no rule in this build looks for it, or the \
         rule that does was not able to run.",
    );
    MethodQualification {
        subject: "Investigative leads raised by the tool".to_string(),
        statement,
        affects: Some("The Investigative Leads section only.".to_string()),
    }
}

/// A limitation of how the examination was conducted.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct MethodQualification {
    /// What it concerns, e.g. "Symbol source — Linux memory image".
    pub subject: String,
    /// The qualification in full, in terms a non-practitioner can follow.
    ///
    /// Written to be read aloud. It has to say what was done, why it was done
    /// that way, and what a reader should therefore not conclude — a sentence
    /// that only names a technique tells a court nothing about its weight.
    pub statement: String,
    /// Which findings it bears on, when it does not bear on all of them.
    ///
    /// `None` means the examination as a whole.
    pub affects: Option<String>,
}

/// What [`MethodQualification::affects`] means when it is `None`.
pub const QUALIFICATION_SCOPE_WHOLE_EXAMINATION: &str = "The examination as a whole.";

/// The scope a qualification bears on, always in words.
///
/// Shared by the HTML report, the PDF and the XLSX export, because an unscoped
/// qualification is the one that bears on the most and it must not be the one
/// that says the least. In the spreadsheet the reason is sharper still: a blank
/// cell in that workbook means the value was never recorded, which is the
/// opposite of what `None` means here.
pub(crate) fn qualification_scope(entry: &MethodQualification) -> &str {
    match entry.affects.as_deref().map(str::trim) {
        Some(affects) if !affects.is_empty() => affects,
        _ => QUALIFICATION_SCOPE_WHOLE_EXAMINATION,
    }
}

/// Who conducted the examination.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ExaminerDetails {
    pub name: String,
    /// Job title or role, e.g. "Senior Digital Forensic Analyst".
    pub role: Option<String>,
    pub organisation: Option<String>,
    /// How to reach the examiner for questions on the report.
    pub contact: Option<String>,
    /// Relevant qualifications or accreditations.
    ///
    /// Included because admissibility of expert evidence turns on the
    /// examiner's competence as much as on the method — FRE 702 in the US,
    /// CPR Part 35 in England and Wales both require it to be stated.
    pub qualifications: Option<String>,
}

/// The identity of this particular document.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ReportIdentity {
    /// Unique reference for this report, distinct from the case reference.
    pub report_id: String,
    /// Which revision of the report this is, when the caller tracks revisions.
    ///
    /// `None` renders nothing. Deliberately optional rather than defaulting to
    /// 1: Séance does not currently record how many times a case has been
    /// reported on, and a document that calls itself "Revision 1" when it is
    /// the third to leave the building is a false statement about disclosure.
    /// Absent is honest; wrong is not.
    pub revision: Option<u32>,
    /// Handling marking, e.g. "RESTRICTED" or "LEGALLY PRIVILEGED".
    pub classification: Option<String>,
    /// A statement of truth, signed by the examiner.
    ///
    /// `None` renders [`DEFAULT_STATEMENT_OF_TRUTH`], so a report never goes
    /// out without one. The wording is deliberately overridable: the required
    /// form differs by jurisdiction, and a tool that hard-codes one
    /// jurisdiction's wording produces a document that is wrong everywhere
    /// else.
    pub statement_of_truth: Option<String>,
}

/// One defined term.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct GlossaryEntry {
    pub term: String,
    pub definition: String,
}

/// The wording used when a report supplies no statement of its own.
///
/// Modelled on the declaration an expert report carries in England and Wales
/// (CPR Practice Direction 35, paragraph 3.3) and compatible with the
/// equivalent US requirement, but kept generic: it asserts only what this tool
/// can actually support — that the findings are the examiner's own, that the
/// method is stated, and that anything the tool could not read is disclosed
/// rather than omitted.
pub const DEFAULT_STATEMENT_OF_TRUTH: &str =
    "I confirm that I have made clear which facts and matters referred to in this report \
     are within my own knowledge and which are not. Those that are within my own knowledge \
     I confirm to be true. The opinions I have expressed represent my true and complete \
     professional opinions on the matters to which they refer. Where the analysis could not \
     be completed, or where a result is partial, this report states so explicitly rather \
     than omitting the matter.";

/// The statement every report carries about how its times are expressed.
///
/// Not optional and not configurable. An unqualified timestamp in a forensic
/// report is challengeable on its face — the same instant is a different wall
/// clock in every jurisdiction the evidence may have crossed, and daylight
/// saving makes some local times ambiguous twice a year. Séance normalises
/// everything to UTC on ingest, so the report says so once, prominently, rather
/// than leaving a reader to assume their own timezone.
pub const TIMEZONE_STATEMENT: &str =
    "All times in this report are expressed in Coordinated Universal Time (UTC), \
     regardless of the timezone configured on the examined system or on the machine \
     that produced this report. Timestamps recorded by the examined system in local \
     time have been converted; where the original timezone could not be established, \
     the record says so.";

/// The terms this tool's own output uses that a non-practitioner will not know.
///
/// Deliberately short. A glossary that defines everything is one nobody reads,
/// so this covers only terms that (a) appear in Séance's rendered output and
/// (b) carry evidential weight if misread — the difference between a file
/// being *deleted* and being *unrecoverable*, or between a record Séance
/// *found* and one it *reconstructed*, is exactly the sort of thing a reader
/// will otherwise guess at.
pub fn default_glossary() -> Vec<GlossaryEntry> {
    [
        (
            "Symbol file / structure layout",
            "A captured computer's memory is undifferentiated data. Reading it requires a \
             description of the operating system build that produced it — which byte of a \
             process record holds its name, at what address a list of processes begins. That \
             description differs with every build of the operating system, so it is supplied \
             separately from the evidence, as a symbol file. A report that says which \
             description was used, and where it came from, is saying what its findings about \
             memory rest on.",
        ),
        (
            "Symbols recovered from the image",
            "Some operating systems store a description of their own structures in memory, so \
             it is captured along with everything else. Where no separate symbol file \
             describes the captured build, that self-description can be used instead. It has \
             the advantage that it cannot describe any build other than the one captured. It \
             has the limitation that nothing independent confirms it: the usual cross-check \
             compares a symbol file against this same self-description, and cannot be \
             performed when the two are one and the same. Where this was done, it is recorded \
             under Limitations and Qualifications.",
        ),
        (
            "Allocated / unallocated",
            "Allocated space is currently assigned to a file the filesystem knows about. \
             Unallocated space is not, and may still hold the contents of files that were \
             deleted, until the operating system reuses it.",
        ),
        (
            "Slack space",
            "The unused remainder of the last storage block a file occupies. It can retain \
             fragments of whatever previously occupied that block, which is why it is \
             examined separately from the file's own contents.",
        ),
        (
            "Carved",
            "Recovered by searching the raw storage for the signature of a known file type, \
             rather than by reading a filesystem record. A carved file has no filename, path \
             or timestamps from the filesystem, and its recovered length is an estimate.",
        ),
        (
            "Deleted",
            "The filesystem no longer lists the file, but a record of it survives. This does \
             not mean the contents were recovered; where they were not, the entry says so.",
        ),
        (
            "MFT (Master File Table)",
            "The index NTFS keeps of every file on a volume, including entries for files that \
             have since been deleted. It is the primary source for filenames and timestamps \
             on Windows systems.",
        ),
        (
            "Hash / hash value",
            "A fixed-length fingerprint computed from a file's contents (MD5, SHA-1, SHA-256). \
             Two files with the same hash are, for practical purposes, identical; a changed \
             hash proves the contents changed.",
        ),
        (
            "Acquisition hash",
            "A hash computed when the evidence was first taken, before analysis. Comparing it \
             against a later recomputation is what demonstrates the evidence has not altered \
             in custody.",
        ),
        (
            "Incomplete / partial result",
            "A section marked incomplete lists a subset of what the evidence holds, because a \
             parser could not read or decode all of it. The absence of an item from such a \
             listing is NOT evidence that the item was absent from the evidence.",
        ),
        (
            "Pagefile / swap",
            "A file the operating system uses to hold memory contents that do not fit in RAM. \
             Data recovered from it was written at some earlier point and may predate the \
             time the memory was captured.",
        ),
        (
            "Timeline event",
            "A single dated occurrence extracted from the evidence. Several events may derive \
             from one file, and one event may be recorded by more than one source.",
        ),
    ]
    .into_iter()
    .map(|(term, definition)| GlossaryEntry {
        term: term.to_string(),
        definition: definition.to_string(),
    })
    .collect()
}

/// The statement of truth this report should carry.
pub fn statement_of_truth(data: &ReportData) -> &str {
    data.report_identity
        .as_ref()
        .and_then(|i| i.statement_of_truth.as_deref())
        .unwrap_or(DEFAULT_STATEMENT_OF_TRUTH)
}

/// The sentence the Findings / Bookmarks section states when personal
/// bookmarks were excluded from it, or `None` when there were none.
pub fn personal_bookmarks_excluded_note(excluded: i64) -> Option<String> {
    if excluded <= 0 {
        return None;
    }
    let (noun, verb) = if excluded == 1 {
        ("personal bookmark", "exists")
    } else {
        ("personal bookmarks", "exist")
    };
    Some(format!(
        "{excluded} {noun} {verb} in this case and {} not included in this section. \
         A personal bookmark is a private working mark seen only by the examiner who \
         made it; only bookmarks deliberately added to the shared bookmarks of the \
         case are reported.",
        if excluded == 1 { "is" } else { "are" }
    ))
}

/// Format a "Showing N of M" disclosure, or `None` when nothing was withheld.
///
/// An examiner reading a capped listing must be able to see that it was capped;
/// a silent cap is indistinguishable from a complete answer.
pub(crate) fn truncation_note(shown: usize, total: i64) -> Option<String> {
    (total > shown as i64).then(|| format!("Showing {} of {} records.", shown, total))
}

/// One recorded reason that a result in this case is less than everything.
///
/// `reason` is `None` when a plugin flagged the shortfall without recording
/// why. That renders as "reason not recorded" rather than being dropped: an
/// unexplained shortfall is still a shortfall, and hiding it would let the
/// report show a non-zero incomplete count beside an empty reason list.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Default)]
pub struct IncompletenessReason {
    pub reason: Option<String>,
    pub count: i64,
}

impl IncompletenessReason {
    /// The reason as an examiner should read it.
    pub fn text(&self) -> &str {
        match self.reason.as_deref() {
            Some(r) if !r.is_empty() => r,
            _ => "reason not recorded",
        }
    }
}

/// Case-wide census of plugin-recorded incompleteness.
///
/// Parsers across the tree stamp `content_incomplete` (+
/// `content_incomplete_reason`) on an artifact whose bytes could not be read or
/// decoded whole, and `inventory_incomplete` (+ `inventory_incomplete_reason`)
/// on one whose listing is short of what the container holds. This carries
/// those stamps into the report, which is the only place a court ever sees them.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct IncompletenessSummary {
    /// Artifacts whose CONTENT could not be read or decoded whole.
    pub content_incomplete: i64,
    /// Artifacts whose LISTING is short of what the container holds.
    pub inventory_incomplete: i64,
    /// CONTENT reasons recorded case-wide, most frequent first. May be capped;
    /// see `distinct_reasons`.
    pub reasons: Vec<IncompletenessReason>,
    /// Distinct content reasons the case actually holds. Greater than
    /// `reasons.len()` means the reason list is itself truncated and says so.
    pub distinct_reasons: i64,
    /// LISTING (inventory) reasons recorded case-wide, most frequent first.
    /// Held separately from `reasons`: a short listing is the disclosure that
    /// carries "absence of an item here is not evidence it was absent from the
    /// evidence", and the examiner cannot act on that without knowing whether
    /// the listing stopped at a truncated container or an undecodable index.
    pub inventory_reasons: Vec<IncompletenessReason>,
    /// Distinct inventory reasons the case actually holds; see
    /// `distinct_reasons`.
    pub distinct_inventory_reasons: i64,
    /// Earlier statements a later run answered, and which are therefore NOT in
    /// the figures above. Stated rather than silently excluded: "this case once
    /// recorded that it could not read something, and then it could" is a fact
    /// about how the evidence was worked, and a figure that quietly shrank
    /// would read as evidence that was never marked at all.
    pub superseded: i64,
    /// Timeline events kept as artifacts but absent from the timeline because
    /// their timestamp was missing or unparseable.
    pub timeline_omitted: i64,
}

impl IncompletenessSummary {
    /// True when any artifact in the case is marked incomplete in either sense,
    /// or any timeline event is missing from the timeline.
    pub fn any(&self) -> bool {
        self.content_incomplete > 0 || self.inventory_incomplete > 0 || self.timeline_omitted > 0
    }
}

fn timeline_omitted_part(n: i64) -> String {
    format!(
        "{n} timeline event(s) could not be placed on the timeline because their timestamp was missing or unparseable"
    )
}

/// The disclosure the Timeline sections carry when events are missing from it.
/// One sentence, shared by every renderer, `None` when nothing was omitted.
pub(crate) fn timeline_omitted_note(summary: Option<&IncompletenessSummary>) -> Option<String> {
    let n = summary.map(|s| s.timeline_omitted).filter(|n| *n > 0)?;
    Some(format!(
        "{}; the timeline is a subset of the events the evidence contains, and their absence from it is not evidence of absence.",
        timeline_omitted_part(n)
    ))
}

/// The one-line completeness verdict, as (severity, sentence).
///
/// Deliberately has a "not assessed" state. A report whose completeness was
/// never established must not read the same as one established to be complete;
/// that distinction is the whole point of the section.
pub fn completeness_statement(summary: Option<&IncompletenessSummary>) -> (&'static str, String) {
    let Some(s) = summary else {
        return (
            "notice",
            "Result completeness was NOT assessed for this case. Absence of an incompleteness notice below must not be read as evidence that every result is complete."
                .to_string(),
        );
    };
    let superseded = if s.superseded > 0 {
        format!(
            " {} earlier statement(s) of incompleteness were superseded by a later run — the \
             data they said was missing was subsequently recovered — and are not counted here.",
            s.superseded
        )
    } else {
        String::new()
    };
    if !s.any() {
        return (
            "verified",
            format!(
                "No artifact in this case was recorded as incompletely read or incompletely listed by the parsers that produced it.{}",
                superseded
            ),
        );
    }
    let mut parts = Vec::new();
    if s.content_incomplete > 0 {
        parts.push(format!(
            "{} artifact(s) were parsed from content that could not be read or decoded in full",
            s.content_incomplete
        ));
    }
    if s.inventory_incomplete > 0 {
        parts.push(format!(
            "{} artifact(s) carry a listing shorter than what the container holds",
            s.inventory_incomplete
        ));
    }
    if s.timeline_omitted > 0 {
        parts.push(timeline_omitted_part(s.timeline_omitted));
    }
    (
        "notice",
        format!(
            "INCOMPLETE RESULTS: {}. Records derived from them are a subset of what the evidence contains, and their absence from a listing is not evidence of absence.{}",
            parts.join("; "),
            superseded
        ),
    )
}

/// The two incompleteness axes as one table, each row naming the axis it
/// belongs to.
///
/// Scoping "no reason was recorded" per axis is load-bearing. A case whose only
/// shortfall is a short listing must not be told that no reason was recorded,
/// when the reason WAS recorded on the listing axis; and it must never be told
/// that about content that was never incomplete in the first place.
fn incompleteness_reason_rows_html(inc: &IncompletenessSummary) -> String {
    fn add(rows: &mut String, scope: &str, reasons: &[IncompletenessReason], count: i64) {
        if count <= 0 {
            return;
        }
        if reasons.is_empty() {
            rows.push_str(&format!(
                "<tr><td>{}</td><td class=\"muted\">no reason was recorded</td><td>{}</td></tr>\n",
                scope, count
            ));
            return;
        }
        for r in reasons {
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                scope,
                esc(r.text()),
                r.count
            ));
        }
    }

    let mut rows = String::new();
    add(
        &mut rows,
        "Content not read in full",
        &inc.reasons,
        inc.content_incomplete,
    );
    add(
        &mut rows,
        "Listing shorter than the container",
        &inc.inventory_reasons,
        inc.inventory_incomplete,
    );
    if rows.is_empty() {
        return String::new();
    }
    format!(
        "<table>\n<tr><th>Shortfall</th><th>Recorded reason</th><th>Artifacts</th></tr>\n{}</table>\n",
        rows
    )
}

/// The two incompleteness axes as table rows: `(axis, reason, count)`, with
/// the same per-axis "no reason was recorded" fallback as the HTML table.
/// Shared by the DOCX renderer.
pub(crate) fn incompleteness_reason_rows_text(inc: &IncompletenessSummary) -> Vec<Vec<String>> {
    fn add(rows: &mut Vec<Vec<String>>, scope: &str, reasons: &[IncompletenessReason], count: i64) {
        if count <= 0 {
            return;
        }
        if reasons.is_empty() {
            rows.push(vec![
                scope.to_string(),
                "no reason was recorded".to_string(),
                count.to_string(),
            ]);
            return;
        }
        for r in reasons {
            rows.push(vec![
                scope.to_string(),
                r.text().to_string(),
                r.count.to_string(),
            ]);
        }
    }
    let mut rows = Vec::new();
    add(
        &mut rows,
        "Content not read in full",
        &inc.reasons,
        inc.content_incomplete,
    );
    add(
        &mut rows,
        "Listing shorter than the container",
        &inc.inventory_reasons,
        inc.inventory_incomplete,
    );
    rows
}

/// Format a "Showing N of M" disclosure for a capped reason list.
pub(crate) fn reason_truncation_note(shown: usize, distinct: i64) -> Option<String> {
    (distinct > shown as i64).then(|| {
        format!(
            "Showing {} of {} distinct reasons recorded.",
            shown, distinct
        )
    })
}

/// Per-section disclosure: how much of THIS section came from an incomplete
/// read, and why. `None` when the section is wholly derived from complete
/// reads.
pub(crate) fn section_incompleteness_note(section: &CategorySection) -> Option<String> {
    if section.incomplete_records <= 0 {
        return None;
    }
    let reasons: Vec<String> = section
        .incomplete_reasons
        .iter()
        .map(|r| format!("{} ({})", r.text(), r.count))
        .collect();
    let mut note = format!(
        "INCOMPLETE: {} artifact(s) behind this section were parsed from content that could not be read in full, so these records are a subset.",
        section.incomplete_records
    );
    if !reasons.is_empty() {
        note.push_str(&format!(" Recorded reason(s): {}.", reasons.join("; ")));
    }
    Some(note)
}

/// What the audit-chain result actually covers.
///
/// The audit log is ONE hash chain across the whole installation; it is not
/// segmented per case and cannot be verified per case (each entry's hash binds
/// the entry before it, whatever case that entry belongs to). Reporting the
/// result under a case heading without saying so states something false in both
/// directions: a pass reads as "this case's custody record is intact" when it
/// attests every case, and a failure reads as "this case was tampered with"
/// when the break may lie entirely in another case's entries.
///
/// Single point of truth: the HTML report, the PDF report, the spreadsheet and
/// the API endpoint all render this string, so they cannot describe the same
/// check differently.
pub fn audit_chain_scope_note(valid: bool) -> &'static str {
    if valid {
        "Scope: the audit log is a single instance-wide hash chain covering every case in \
         this installation. This result attests that whole log, not this case's entries alone."
    } else {
        "Scope: the audit log is a single instance-wide hash chain covering every case in \
         this installation. A break anywhere in it fails this check, so the altered entries \
         may belong to another case; the entry recorded as the break point identifies where \
         verification stopped."
    }
}

/// The sentence that says what a `valid` audit-chain verdict is actually worth.
///
/// `valid` on its own is ambiguous, and the ambiguity is the dangerous kind. On
/// a KEYED chain (`SEANCE_AUDIT_HMAC_KEY` set, HMAC-SHA256) it means the log has
/// not been altered, because the digests depend on a secret the database does
/// not hold. On an UNKEYED one it means only that the log is internally
/// consistent: the digest is a plain SHA-256 over fields that all live in the
/// same database, so anyone who can write to it can rewrite an entry, recompute
/// every hash after it, and produce a chain that verifies (HUNT-011).
///
/// Single point of truth, for the same reason as [`audit_chain_scope_note`]
/// beside it: the HTML report, the PDF report, the spreadsheet, the executive
/// summary and the verify endpoint all render this string, so no two of them can
/// describe the same check differently. The two notes cover the two halves of
/// the same disclosure — what the verdict is worth, and what it covers — and are
/// meant to be read together.
///
/// This is the whole-chain form. A chain that was keyed part-way through is
/// neither, and [`audit_chain_keying_disclosure`] states that third case; every
/// renderer goes through it so the partial case cannot be flattened into one
/// of the two adjectives here.
pub fn audit_chain_keying_note(tamper_evident: bool) -> &'static str {
    if tamper_evident {
        "The chain is keyed (SEANCE_AUDIT_HMAC_KEY is set): its digests cannot be recomputed \
         from the database alone, so a successful verification is evidence that the entries it \
         HOLDS have not been altered or reordered. It is not, on its own, evidence that the log \
         is COMPLETE: deleting the most recent entries leaves no gap, and the shortened chain \
         still verifies — and a database writer, the very actor keying defends against, is who \
         can do that. To detect a deleted tail, an entry's id and hash must have been recorded \
         outside this database and checked against the log afterwards; the audit-log verify \
         endpoint publishes the head to anchor and performs that comparison. This report does \
         not carry that anchor."
    } else {
        "The chain is UNKEYED: its digests are a plain SHA-256 over fields that all live in this \
         same database, so anyone able to write to it could rewrite an entry, recompute every \
         later hash and produce a chain that verifies. A successful verification here means the \
         log is internally consistent; it is NOT evidence that the log is unaltered, and it is \
         not evidence that it is complete (a deleted tail is undetectable either way). Set \
         SEANCE_AUDIT_HMAC_KEY to make alteration of the entries present detectable, and anchor \
         the chain head outside the database to make deletion of the most recent entries \
         detectable."
    }
}

/// What a chain verdict is worth, including the partially keyed case.
///
/// `tamper_evident` is the whole-chain flag; `tamper_evident_from` is the id of
/// the first row of the keyed run that reaches the chain head, when the chain
/// is not tamper-evident as a whole. A deployment that sets
/// `SEANCE_AUDIT_HMAC_KEY` on an existing log produces exactly that shape, and
/// it must be described as what it is: an unkeyed prefix that is internally
/// consistent only, and a keyed remainder whose verification is evidence
/// (DEPLOY-001). Reduces to [`audit_chain_keying_note`] when there is no
/// boundary to state.
pub fn audit_chain_keying_disclosure(
    tamper_evident: bool,
    tamper_evident_from: Option<i64>,
    key_configured: bool,
) -> String {
    match (tamper_evident, tamper_evident_from) {
        // Wholly unkeyed on a server that HAS a key (SEC-009). The rows cannot
        // say whether this log predates the key or was deleted and rewritten
        // from scratch without it; the disclosure says exactly that, and does
        // not advise setting a key that is already set.
        (false, None) if key_configured => {
            "The chain is UNKEYED although SEANCE_AUDIT_HMAC_KEY IS set on this server: every \
             checked row was written without the key, so its digests are a plain SHA-256 over \
             fields that all live in this same database. That is the shape of a log written \
             before the key was set — and also of a log that an actor with database write \
             access deleted and rewrote from scratch, unkeyed, after it; nothing in the database \
             distinguishes the two. A successful verification here means the log is internally \
             consistent and no more: it is NOT evidence that the entries are the ones originally \
             written, and not evidence that the log is complete. Only an entry id and hash \
             recorded outside this database before now, checked against the log, can tell the \
             two apart; the audit-log verify endpoint performs that comparison when given one. \
             Rows written from now on carry the key."
                .to_string()
        }
        (false, Some(from)) => format!(
            "The chain is PARTIALLY keyed. Rows before entry {from} were written unkeyed: their \
             digests are a plain SHA-256 over fields that all live in this same database, so \
             anyone able to write to it could have rewritten one of them, recomputed every \
             later unkeyed hash and produced a prefix that verifies. For those rows a \
             successful verification means internal consistency only; it is NOT evidence that \
             they are unaltered. From entry {from} the chain is keyed (SEANCE_AUDIT_HMAC_KEY is \
             set): those digests cannot be recomputed from the database alone, so a successful \
             verification is evidence that the entries present from entry {from} onward have not \
             been altered or reordered. As with any hash chain this does not prove the log is \
             complete — deletion of the most recent entries leaves no gap and still verifies — \
             so the chain head must be anchored outside this database to detect a truncated \
             tail."
        ),
        (te, _) => audit_chain_keying_note(te).to_string(),
    }
}

/// How the chain the banner just reported on was actually built.
///
/// Kept to the construction alone, with no verdict in it: the banner names what
/// was computed, and [`audit_chain_keying_disclosure`] says what computing it
/// proves. The partially keyed chain names both constructions and the boundary.
pub(crate) fn audit_chain_construction(
    tamper_evident: bool,
    tamper_evident_from: Option<i64>,
) -> String {
    match (tamper_evident, tamper_evident_from) {
        (true, _) => "keyed HMAC-SHA256 hash chain".to_string(),
        (false, Some(from)) => {
            format!("UNKEYED SHA-256 hash chain before entry {from}, keyed HMAC-SHA256 from it")
        }
        (false, None) => "UNKEYED SHA-256 hash chain".to_string(),
    }
}

/// Disclosure for a geolocation listing that hit the query cap.
///
/// Stated as a lower bound because the capped query never counts past its
/// limit: "at least N" is the strongest claim the data supports, and the one
/// reading this section must not be left to assume the listed fixes are every
/// place the device is known to have been.
pub fn geo_truncation_note(shown: usize) -> String {
    format!(
        "INCOMPLETE: the geolocation query returned its maximum of {} points. \
         This case holds AT LEAST that many GPS fixes and may hold more that are \
         not listed here or in the KML/GeoJSON export. Do not read this list as \
         every location recorded in the evidence.",
        shown
    )
}

/// Caption for the timeline listing. When the listing is capped it states the
/// case-wide total first, so nobody reads the cap as the size of the case.
pub(crate) fn timeline_caption(shown: usize, total: i64) -> String {
    if total > shown as i64 {
        format!(
            "The case contains {} timeline events. This report lists the {} earliest (chronological); the listing is truncated.",
            total, shown
        )
    } else {
        format!("{} events (chronological).", shown)
    }
}

/// Why there is no timeline figure over a non-empty listing.
pub(crate) fn timeline_figure_unavailable(listed: usize) -> String {
    format!(
        "No timeline figure: none of the {listed} listed event(s) carried a timestamp that \
         could be parsed, so there is nothing to plot."
    )
}

/// FTK-style File Overview: high-level counts across the case.
///
/// `carved_files` / `encrypted_files` stay `Option` because a count that was
/// not taken must not render as `0`: "we did not count these" and "there are
/// none" are different statements, and a report that conflates them tells a
/// court there was no carved or encrypted material when nobody looked.
///
/// The case store CAN now answer both — `count_carved_files` and
/// `count_encrypted_files` in `seance_db` — so a `None` here is no longer a
/// standing limitation of the store. It means this particular caller did not
/// supply the figure, and the renderer says exactly that rather than guessing.
/// A store error must propagate and fail the export; it must never arrive here
/// as `Some(0)`.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct FileOverview {
    pub total_files: i64,
    pub directories: i64,
    pub deleted_files: i64,
    pub carved_files: Option<i64>,
    pub encrypted_files: Option<i64>,
    pub known_good_filtered: i64,
    pub notable_alerts: i64,
}

/// What an integrity row actually says about an evidence source.
///
/// This deliberately has more than two states. A row recorded at acquisition is
/// a *baseline*: a hash was taken and stored, and nothing has been compared
/// against it yet. Collapsing that into "not verified" makes a routine case
/// render as "HASH MISMATCH - evidence may have been altered", which is a false
/// chain-of-custody alarm and devalues genuine mismatches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Default)]
pub enum IntegrityOutcome {
    /// A hash was recorded at acquisition. No later recomputation has been
    /// compared against it. Neither a pass nor a failure.
    Baseline,
    /// A recomputed hash was compared against the baseline and matched.
    Verified,
    /// A recomputed hash was compared against the baseline and did NOT match.
    Failed,
    /// A check ran but could not conclude: no baseline to compare against, or
    /// the source could not be read in full. Fail-closed default, so an
    /// unmapped status can never present as a pass.
    #[default]
    Indeterminate,
}

impl IntegrityOutcome {
    /// Map a stored `integrity_checks.status` to an outcome.
    ///
    /// Single point of truth for this mapping: every renderer and the executive
    /// summary go through it, so a new status string cannot be silently read as
    /// "verified" by one consumer and "failed" by another.
    pub fn from_status(status: &str) -> Self {
        match status {
            "baseline" => Self::Baseline,
            "verified" | "match" | "ok" | "passed" => Self::Verified,
            "mismatch" | "integrity_failed" | "failed" => Self::Failed,
            // "no_baseline", "incomplete" and anything unrecognised.
            _ => Self::Indeterminate,
        }
    }

    /// Short cell label for the Result column.
    pub fn label(self) -> &'static str {
        match self {
            Self::Baseline => "BASELINE",
            Self::Verified => "MATCH",
            Self::Failed => "MISMATCH",
            Self::Indeterminate => "NOT DETERMINED",
        }
    }

    /// One-line explanation of what the label means to an examiner.
    pub fn description(self) -> &'static str {
        match self {
            Self::Baseline => "hash recorded at acquisition, not re-verified",
            Self::Verified => "recomputed hash matches the acquisition hash",
            Self::Failed => "recomputed hash does NOT match the acquisition hash",
            Self::Indeterminate => "verification could not be concluded",
        }
    }
}

/// How many integrity rows fall into each outcome.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IntegrityTally {
    pub baseline: usize,
    pub verified: usize,
    pub failed: usize,
    pub indeterminate: usize,
}

impl IntegrityTally {
    pub fn total(&self) -> usize {
        self.baseline + self.verified + self.failed + self.indeterminate
    }
}

/// Count integrity rows by outcome. Shared by the renderers and the API's
/// executive summary so all three narrate the same case from the same numbers.
pub fn tally_integrity(checks: &[IntegrityCheck]) -> IntegrityTally {
    let mut t = IntegrityTally::default();
    for c in checks {
        match c.outcome {
            IntegrityOutcome::Baseline => t.baseline += 1,
            IntegrityOutcome::Verified => t.verified += 1,
            IntegrityOutcome::Failed => t.failed += 1,
            IntegrityOutcome::Indeterminate => t.indeterminate += 1,
        }
    }
    t
}

/// The one-line verdict for the integrity section, as (severity, sentence).
///
/// Severity is `"broken"` only when a re-verification actually failed. A case
/// holding nothing but acquisition baselines is neither intact-by-re-check nor
/// broken, and says so.
pub fn integrity_statement(checks: &[IntegrityCheck]) -> (&'static str, String) {
    let t = tally_integrity(checks);
    if t.failed > 0 {
        return (
            "broken",
            format!(
                "HASH MISMATCH - {} of {} recorded hash(es) failed re-verification. Evidence may have been altered.",
                t.failed,
                t.total()
            ),
        );
    }
    if t.indeterminate > 0 {
        return (
            "notice",
            format!(
                "{} of {} recorded hash(es) could not be re-verified (no baseline to compare, or the source could not be read in full). This is not a pass.",
                t.indeterminate,
                t.total()
            ),
        );
    }
    if t.verified > 0 && t.baseline > 0 {
        return (
            "verified",
            format!(
                "{} re-verified hash(es) match their acquisition hashes. The remaining {} are acquisition baselines that have not been re-verified.",
                t.verified, t.baseline
            ),
        );
    }
    if t.verified > 0 {
        return (
            "verified",
            format!(
                "All {} re-verified hash(es) match their acquisition hashes - evidence integrity intact.",
                t.verified
            ),
        );
    }
    (
        "notice",
        format!(
            "{} acquisition hash baseline(s) recorded at ingest. No re-verification has been performed, so this is neither a pass nor a failure.",
            t.baseline
        ),
    )
}

fn integrity_banner_html(checks: &[IntegrityCheck]) -> String {
    let (class, text) = integrity_statement(checks);
    format!("<div class=\"{}\">{}</div>\n", class, esc(&text))
}

/// One row of the evidence-integrity section: either an acquisition baseline or
/// a later re-verification of it.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct IntegrityCheck {
    pub source_name: String,
    pub algorithm: String,
    pub acquisition_hash: Option<String>,
    pub recomputed_hash: Option<String>,
    /// Baseline / verified / failed / indeterminate. Replaces an earlier
    /// `verified: bool`, which could not distinguish a baseline from a failure.
    pub outcome: IntegrityOutcome,
    pub checked_at: Option<String>,
}

/// A generic, table-shaped detail section for one artifact category.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct CategorySection {
    /// Human title, e.g. "Web History" or "Program Execution (Prefetch)".
    pub title: String,
    /// Column headers.
    pub columns: Vec<String>,
    /// Rows; each inner Vec should have `columns.len()` cells.
    pub rows: Vec<Vec<String>>,
    /// Total records in this category, if more than the rows shown.
    pub total: i64,
    /// Artifacts behind this section whose content was recorded as incomplete.
    /// A section listing records derived from a truncated read asserts a
    /// completeness it cannot support unless it says this.
    pub incomplete_records: i64,
    /// Why those artifacts were incomplete, most frequent first. A 512 MiB hive
    /// cap and a corrupt mid-file record are different stories with different
    /// follow-up, so the reason travels with the count.
    pub incomplete_reasons: Vec<IncompletenessReason>,
}

/// A GPS point extracted from EXIF metadata.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct GeoPoint {
    pub label: String,
    pub path: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub altitude: Option<f64>,
    pub timestamp: Option<String>,
}

/// One module-execution record from the processing log.
///
/// A row aggregates every run of one module in one status, so `runs` is what
/// tells the reader whether `artifacts_produced` came from a single pass or was
/// summed across forty. Without it the totals are unreconcilable against the
/// per-artifact log an opposing expert would ask for.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ProcessingLogEntry {
    pub module_id: String,
    pub status: String,
    /// Individual module executions folded into this row. `0` means the caller
    /// did not record it, and renders as a dash rather than as "never ran".
    pub runs: i64,
    pub artifacts_produced: i64,
    pub duration_ms: Option<i64>,
    pub error_message: Option<String>,
}

/// A single acquired evidence source with acquisition hashes.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct EvidenceSource {
    pub name: String,
    pub source_type: String,
    pub size_bytes: Option<i64>,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub acquired_at: Option<String>,
}

/// An examiner finding / bookmark.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ReportBookmark {
    pub artifact_name: String,
    pub category: Option<String>,
    pub note: Option<String>,
    pub examiner: Option<String>,
    pub created_at: String,
    /// Source path of the finding within the evidence (provenance).
    pub source_path: Option<String>,
    /// Byte offset of the finding within its source evidence, so it can be
    /// independently re-verified (D7 provenance).
    pub source_offset: Option<i64>,
}

/// A timeline event as the report lists it.
///
/// The same struct serves two populations, and only one of them can carry the
/// annotation fields. In the full timeline every event in the case appears
/// whether or not anyone ever looked at it, so `examiner` and `note` are always
/// `None` there and the renderers must not offer columns for them. In the
/// highlights they are the entire justification for the section existing: an
/// event is a highlight because an examiner tagged it, and the note is the only
/// place the reason lives.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ReportTimelineEvent {
    pub timestamp: String,
    pub description: String,
    pub source_module: String,
    /// Who tagged the event. Set for highlights only.
    pub examiner: Option<String>,
    /// Why the examiner tagged it, in their words. Set for highlights only, and
    /// legitimately absent when they tagged the event without writing one.
    pub note: Option<String>,
}

/// A single entry from the hash-chained audit log.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ReportAuditEntry {
    pub timestamp: String,
    pub user: String,
    pub action: String,
    pub resource_type: String,
}

/// A match against a notable hash set (e.g. known-bad / contraband).
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ReportHashHit {
    pub artifact_name: String,
    pub path: Option<String>,
    pub hash_set_name: String,
    pub algorithm: String,
    pub matched_hash: String,
}

/// A participant in the communications network, as the report draws it.
///
/// Mirrors `seance_db::CommNode` field for field so the API layer can copy it
/// across; kept as its own type because the report contract must not follow
/// the store's.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ReportCommNode {
    /// Normalised address or handle; the same peer across records is one node.
    pub id: String,
    /// Human label where one was recorded, else the id.
    pub label: String,
    /// `self` (the examined device), `contact` (messaging peer) or `email`.
    pub kind: String,
    /// Messages and emails this participant is party to.
    pub weight: i64,
}

/// One undirected link between two participants, weighted by how many
/// exchanges it aggregates.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ReportCommEdge {
    pub source: String,
    pub target: String,
    pub weight: i64,
}

/// The communications network computed for a case, as the report carries it.
///
/// Mirrors `seance_db::CommunicationGraph`. Both caps travel with it: a
/// network drawn without them reads as the whole of a person's contacts,
/// which a capped query cannot support.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ReportCommunicationGraph {
    pub nodes: Vec<ReportCommNode>,
    pub edges: Vec<ReportCommEdge>,
    /// True when participants beyond the store's node cap were dropped, or
    /// email rows beyond its row ceiling were never read.
    pub truncated: bool,
    /// Participants the store found before capping.
    pub total_participants: i64,
    /// Email records read that contributed no link (absent metadata,
    /// undecodable content, no sender). A separate failure from
    /// `truncated`: every email in a case can be unusable while nothing was
    /// truncated, and the messaging-only graph that results must not be
    /// presented as the whole contact network.
    pub unusable_email_records: i64,
}

/// One row of a feature histogram's most-common table: a selector kind, the
/// exact bytes it matched, and how many times they recurred.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Default)]
pub struct ReportFeatureValue {
    pub kind: String,
    pub value: String,
    pub count: i64,
}

/// One row of a feature histogram's by-kind table.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Default)]
pub struct ReportFeatureKind {
    pub kind: String,
    /// Every hit of this kind, including any turned away at the histogram's
    /// distinct-value ceiling, so the by-kind hits sum to `total_hits`.
    pub hits: i64,
    /// Distinct values tracked for this kind — a floor when `capped`.
    pub distinct_values: i64,
}

/// The `FeatureHistogramSummary` record `plugin.bulk.features` publishes for
/// one scanned source (ROADMAP §2.1), field for field. The API layer copies
/// the record's fields across; the renderers state every ceiling on it and
/// never present a capped table as the whole of what the scan contained.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Default)]
pub struct ReportFeatureHistogram {
    /// The scanned source, as the report names artifacts elsewhere.
    pub source: String,
    /// Every hit the scan found, dropped ones included.
    pub total_hits: i64,
    /// Distinct values the histogram tracked — a floor when `capped`.
    pub distinct_values: i64,
    /// Hits for values beyond the ceiling that were counted but not tallied.
    pub hits_dropped: i64,
    /// Whether the distinct-value ceiling was hit.
    pub capped: bool,
    /// The ceiling, as the record names it.
    pub max_distinct_values: i64,
    /// The most entries `top` can hold, as the record names it.
    pub top_n: i64,
    /// `distinct_values` minus the entries in `top`: the length of the
    /// table the record did not carry.
    pub top_omitted: i64,
    /// The most-common values, most-common first.
    pub top: Vec<ReportFeatureValue>,
    /// Totals per selector kind, in the record's order.
    pub by_kind: Vec<ReportFeatureKind>,
    /// Bytes the scan read.
    pub bytes_scanned: i64,
    /// Whether the scan stopped at its byte ceiling, so `bytes_scanned` is
    /// a prefix of the source and not its size.
    pub scan_capped: bool,
    /// Whether part of the source would not read, so `bytes_scanned` is what
    /// was read and the rest was never examined (the unreadable ranges are on
    /// the scan's `FeatureSummary`). False on a record published before the
    /// scanner stamped it.
    pub short_read: bool,
    /// The size the scanned source declared, when the record names it
    /// (`0` on a record published before the scanner stamped it).
    pub source_size: i64,
    /// The record's own statement of its ceiling, rendered verbatim.
    pub note: String,
}

/// Data a report carries beyond the fixed [`ReportData`] contract.
///
/// [`ReportData`] is built by the API layer as an exhaustive struct literal,
/// so a field added there changes that contract for every caller at once.
/// This carries the additions beside it instead: every `render_*` function
/// has a `render_*_with(data, extras)` form, and the plain form renders with
/// [`ReportExtras::default()`], in which nothing was supplied — and the
/// renderers say so, rather than treating "not supplied" as "none found".
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ReportExtras {
    /// The communications network. `None` means it was not computed for this
    /// report, which is stated; `Some` with no nodes means it was computed
    /// and found no participants.
    pub communications: Option<ReportCommunicationGraph>,
    /// The feature histograms, one per `FeatureHistogramSummary` record in
    /// the case. `None` means they were not gathered for this report, which
    /// is stated; `Some` and empty means the case holds no such record.
    pub feature_histograms: Option<Vec<ReportFeatureHistogram>>,
    /// Why `feature_histograms` is `None` when the caller asked for them and
    /// was refused — a ceiling, with its numbers. Printed after the
    /// not-gathered statement so a report that asked and was turned away
    /// does not read like one that never asked. `None` when nothing asked.
    pub feature_histograms_not_gathered_reason: Option<String>,
}

const DASH: &str = "&mdash;";

/// Escape a user-supplied string for safe inclusion in HTML text/attributes.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Escape an optional string, falling back to an em-dash placeholder.
fn esc_opt(s: &Option<String>) -> String {
    match s {
        Some(v) if !v.is_empty() => esc(v),
        _ => DASH.to_string(),
    }
}

/// Render a byte count as a human-readable size (e.g. `1.00 GB`).
pub(crate) fn human_size(bytes: i64) -> String {
    if bytes < 0 {
        return format!("{bytes} B");
    }
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut val = bytes as f64;
    let mut i = 0;
    while val >= 1024.0 && i < UNITS.len() - 1 {
        val /= 1024.0;
        i += 1;
    }
    format!("{:.2} {}", val, UNITS[i])
}

/// Word-wrap `text` to at most `width` characters per line, for the fixed-width
/// PDF layout. Never splits mid-word unless a single word exceeds `width`.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if line.is_empty() {
            line.push_str(word);
        } else if line.len() + 1 + word.len() <= width {
            line.push(' ');
            line.push_str(word);
        } else {
            out.push(std::mem::take(&mut line));
            line.push_str(word);
        }
    }
    if !line.is_empty() {
        out.push(line);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

/// What to say for a category section that lists no rows.
///
/// A section can hold a true total and no rows: the detail listings are built
/// from a bounded slice of the timeline, so a category whose every record falls
/// outside that slice is real evidence the report does not enumerate. Rendering
/// the generic "None recorded" over it asserts the case holds no such evidence,
/// which is a false negative in a document written for a court — and it
/// contradicts the "Showing 0 of N records" line printed right above it
/// (LIVE-014). Absence is only claimed when the total agrees it is absent.
pub(crate) fn empty_section_note(section: &CategorySection) -> String {
    if section.total > 0 {
        format!(
            "{} record(s) are held in this category. None of them fall within the slice this \
             report lists, so none are enumerated here; they are present in the case.",
            section.total
        )
    } else {
        "None recorded".to_string()
    }
}

/// A GPS point's Path column, blank when it would merely repeat the File.
///
/// Shared with the XLSX export: the spreadsheet is what gets handed to opposing
/// counsel, so a Path asserted there and suppressed in the HTML would be the
/// worse half of the pair, not the safer one.
///
/// Most EXIF writers record only a file NAME, so the File and Path columns both
/// fall back to it and the row prints the same string twice — which reads in a
/// court document as though a path were established when none was.
pub(crate) fn geo_path_cell(point: &GeoPoint) -> Option<String> {
    match point.path.as_deref() {
        Some(path) if path != point.label => Some(path.to_string()),
        _ => None,
    }
}

/// Render a generic escaped HTML table with the given headers and rows. Cells
/// are HTML-escaped. Returns an empty string if there are no rows.
fn render_html_table(headers: &[String], rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return "<p class=\"muted\">None recorded</p>\n".to_string();
    }
    let mut t = String::from("<table>\n<tr>");
    for hd in headers {
        t.push_str(&format!("<th>{}</th>", esc(hd)));
    }
    t.push_str("</tr>\n");
    for row in rows {
        t.push_str("<tr>");
        for cell in row {
            t.push_str(&format!("<td>{}</td>", esc(cell)));
        }
        t.push_str("</tr>\n");
    }
    t.push_str("</table>\n");
    t
}

/// Render a complete, self-contained, print-friendly HTML forensic report.
///
/// All user-supplied strings are HTML-escaped. Empty sections render a muted
/// "None recorded" placeholder, except Notable Hash Matches, which is omitted
/// entirely when there are no matches.
pub fn render_html(data: &ReportData) -> String {
    render_html_with(data, &ReportExtras::default())
}

/// The sentence every renderer prints when the communications network was
/// not supplied. "Not computed" and "none found" are different facts.
pub const COMMUNICATIONS_NOT_COMPUTED: &str =
    "The communications network was not computed for this report. Nothing here says \
     whether the evidence holds messaging or email exchanges.";

/// What the communications section says when the network was computed and
/// holds no participant.
pub fn communications_empty_statement(graph: &ReportCommunicationGraph) -> String {
    let mut s = String::from(
        "The communications network was computed from the parsed messaging and email \
         records and found no participants.",
    );
    if graph.unusable_email_records > 0 {
        s.push_str(&format!(
            " {} email record(s) were read but contributed no link (absent metadata, \
             undecodable content or no sender); their exchanges are not represented.",
            graph.unusable_email_records
        ));
    }
    if graph.truncated {
        s.push_str(" The source query was truncated before it finished.");
    }
    s
}

/// The most links the communications tables list. The figure draws fewer;
/// the table beside it is the complete listing up to this cap, and says so
/// when the cap bites.
pub(crate) const COMMUNICATION_LINKS_TABLE_CAP: usize = 500;

/// The link table's rows, heaviest first, ties broken by the endpoint ids, so
/// two renders of the same case list the same rows in the same order.
pub(crate) fn communication_link_rows(
    graph: &ReportCommunicationGraph,
) -> (Vec<Vec<String>>, Option<String>) {
    let labels: std::collections::HashMap<&str, &str> = graph
        .nodes
        .iter()
        .map(|n| (n.id.as_str(), n.label.as_str()))
        .collect();
    let mut edges: Vec<&ReportCommEdge> = graph.edges.iter().collect();
    edges.sort_by(|x, y| {
        y.weight
            .cmp(&x.weight)
            .then_with(|| x.source.cmp(&y.source))
            .then_with(|| x.target.cmp(&y.target))
    });
    let total = edges.len();
    edges.truncate(COMMUNICATION_LINKS_TABLE_CAP);
    let rows = edges
        .iter()
        .map(|e| {
            vec![
                labels
                    .get(e.source.as_str())
                    .copied()
                    .unwrap_or(&e.source)
                    .to_string(),
                labels
                    .get(e.target.as_str())
                    .copied()
                    .unwrap_or(&e.target)
                    .to_string(),
                e.weight.to_string(),
            ]
        })
        .collect();
    (rows, truncation_note(edges.len(), total as i64))
}

/// The participant table's rows, heaviest first, ties broken by id.
pub(crate) fn communication_participant_rows(graph: &ReportCommunicationGraph) -> Vec<Vec<String>> {
    let mut nodes: Vec<&ReportCommNode> = graph.nodes.iter().collect();
    nodes.sort_by(|a, b| b.weight.cmp(&a.weight).then_with(|| a.id.cmp(&b.id)));
    nodes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            vec![
                (i + 1).to_string(),
                n.label.clone(),
                crate::figures::kind_words(&n.kind).to_string(),
                n.weight.to_string(),
            ]
        })
        .collect()
}

/// The rank column is the number a crowded figure labels each node with;
/// the same ordering as the figure, so the number resolves to the row.
pub(crate) const COMMUNICATION_PARTICIPANT_COLUMNS: [&str; 4] =
    ["#", "Participant", "Kind", "Exchanges"];
pub(crate) const COMMUNICATION_LINK_COLUMNS: [&str; 3] =
    ["Participant", "Participant", "Exchanges"];

/// The sentence over a communications listing that hit the store's own caps.
pub(crate) fn communications_truncation_note(graph: &ReportCommunicationGraph) -> Option<String> {
    let mut parts = Vec::new();
    if graph.truncated {
        parts.push(format!(
            "INCOMPLETE: the communications query was truncated (participants beyond its cap, \
             or email rows beyond its ceiling, were never read); {} participant(s) were counted \
             before the cap and {} are listed. Do not read this network as the whole of the \
             contacts the evidence holds.",
            graph.total_participants,
            graph.nodes.len()
        ));
    }
    if graph.unusable_email_records > 0 {
        parts.push(format!(
            "{} email record(s) were read but contributed no link (absent metadata, undecodable \
             content or no sender), so the email side of this network is incomplete.",
            graph.unusable_email_records
        ));
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// The sentence every renderer prints when the feature histograms were not
/// supplied. "Not gathered" and "none found" are different facts.
pub const FEATURE_HISTOGRAMS_NOT_GATHERED: &str =
    "Feature histograms were not gathered for this report. Nothing here says whether the \
     feature scanner ran over this case or what it found.";

/// What the section says when the histograms were gathered and the case
/// holds no record. The scanner publishes no record for a scan that found
/// nothing, so the two causes cannot be told apart from the record set.
pub const FEATURE_HISTOGRAMS_NONE_FOUND: &str =
    "No FeatureHistogramSummary record exists in this case: either the feature scanner \
     (plugin.bulk.features) did not run over its artifacts, or it ran and found no hit, \
     since a scan that finds no hit publishes no histogram. This report cannot tell which. \
     A scan that stopped at its byte ceiling or could not read part of its source still \
     publishes a FeatureSummary record stating the bytes it read and the ranges it could \
     not; a scan that read everything and found nothing publishes no record at all.";

/// The section's statement when the histograms were not gathered: the fixed
/// sentence, followed by the reason when the caller recorded one.
pub(crate) fn feature_histograms_not_gathered_text(extras: &ReportExtras) -> String {
    match extras.feature_histograms_not_gathered_reason.as_deref() {
        Some(reason) if !reason.is_empty() => {
            format!("{FEATURE_HISTOGRAMS_NOT_GATHERED} Reason: {reason}")
        }
        _ => FEATURE_HISTOGRAMS_NOT_GATHERED.to_string(),
    }
}

/// What a feature histogram is and is not, printed once above the tables.
pub(crate) const FEATURE_HISTOGRAMS_INTRO: &str =
    "Each histogram below was accumulated by the feature scanner (plugin.bulk.features) \
     over one source as the scan ran. A count is the number of times a selector matched \
     those exact bytes in the source, not the number of files that hold the value, and a \
     match in unallocated space or memory is not evidence that the value was ever used.";

pub(crate) const FEATURE_KIND_COLUMNS: [&str; 3] = ["Kind", "Hits", "Distinct values"];
pub(crate) const FEATURE_VALUE_COLUMNS: [&str; 3] = ["Kind", "Value", "Count"];
pub(crate) const FEATURE_TOP_TITLE: &str = "Most-common feature values";

/// The line over a histogram's tables: its totals, with the distinct count
/// stated as a floor when the record says it is one.
pub(crate) fn feature_histogram_total_line(h: &ReportFeatureHistogram) -> String {
    format!(
        "{} hit(s) over {}{} distinct value(s), from {} bytes scanned.",
        h.total_hits,
        if h.capped { "at least " } else { "" },
        h.distinct_values,
        h.bytes_scanned
    )
}

/// The INCOMPLETE statements a histogram carries: one per ceiling the record
/// says it hit. The record's own `note` is printed beside them verbatim.
pub(crate) fn feature_histogram_incomplete_notes(h: &ReportFeatureHistogram) -> Vec<String> {
    let mut notes = Vec::new();
    if h.short_read {
        // Part of the source would not read: `bytes_scanned` is what was
        // read, not a ceiling, and the ceiling sentence below would misstate
        // it. Since HUNT-218 the sweep steps over an unreadable range and
        // resumes, so what was read is not necessarily a prefix; the sentence
        // holds for records from before that change too.
        let of = if h.source_size > 0 {
            format!(" of the {} the source declared", h.source_size)
        } else {
            String::new()
        };
        notes.push(format!(
            "INCOMPLETE: part of the source could not be read; the scan read {} bytes{of}, \
             and the bytes it could not read were not examined, so these counts cover the \
             bytes read only. The scan's FeatureSummary record lists the unreadable ranges.",
            h.bytes_scanned
        ));
    } else if h.scan_capped {
        notes.push(format!(
            "INCOMPLETE: the scan stopped at its ceiling of {} bytes; bytes beyond it were \
             not read, so these counts cover that prefix of the source only.",
            h.bytes_scanned
        ));
    }
    if h.capped {
        // The scanner counts a hit against its kind before the ceiling turns
        // it away, so the per-kind hit column is complete; the ceiling bounds
        // only the most-common table and the distinct-value counts.
        notes.push(format!(
            "INCOMPLETE: {} hit(s) fell outside the {} distinct values the histogram tracks \
             and were counted but not tallied, so the most-common table below lists tracked \
             values only, the distinct-value counts in total and per kind are floors, and \
             the per-kind hit counts include the untallied hits.",
            h.hits_dropped, h.max_distinct_values
        ));
    }
    notes
}

/// The sentence over the most-common table when the record carried fewer
/// entries than the histogram holds.
pub(crate) fn feature_histogram_top_note(h: &ReportFeatureHistogram) -> Option<String> {
    (h.top_omitted > 0).then(|| {
        format!(
            "Showing the {} most common of {} distinct values (the table lists at most {}); \
             {} distinct value(s) are not listed.",
            h.top.len(),
            h.distinct_values,
            h.top_n,
            h.top_omitted
        )
    })
}

pub(crate) fn feature_kind_rows(h: &ReportFeatureHistogram) -> Vec<Vec<String>> {
    h.by_kind
        .iter()
        .map(|k| {
            vec![
                k.kind.clone(),
                k.hits.to_string(),
                k.distinct_values.to_string(),
            ]
        })
        .collect()
}

pub(crate) fn feature_value_rows(h: &ReportFeatureHistogram) -> Vec<Vec<String>> {
    h.top
        .iter()
        .map(|v| vec![v.kind.clone(), v.value.clone(), v.count.to_string()])
        .collect()
}

/// Render the HTML report with the data [`ReportData`] cannot carry.
pub fn render_html_with(data: &ReportData, extras: &ReportExtras) -> String {
    let mut h = String::with_capacity(16384);
    let mut figure_no = 0usize;

    h.push_str(&format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forensic Report - {title}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #222; line-height: 1.55; padding: 40px; max-width: 1100px; margin: 0 auto; }}
    h1 {{ font-size: 26px; border-bottom: 3px solid #1f2d3d; padding-bottom: 10px; margin-bottom: 8px; color: #1f2d3d; }}
    h2 {{ font-size: 20px; color: #1f2d3d; margin: 30px 0 12px 0; border-bottom: 1px solid #c3ccd6; padding-bottom: 6px; }}
    h3 {{ font-size: 16px; color: #1f2d3d; margin: 18px 0 8px 0; }}
    h4 {{ font-size: 14px; color: #1f2d3d; margin: 12px 0 6px 0; }}
    .subtitle {{ color: #556; font-size: 14px; margin-bottom: 20px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 8px 0 18px 0; font-size: 13px; }}
    th, td {{ padding: 7px 10px; text-align: left; border: 1px solid #d7dde3; vertical-align: top; }}
    th {{ background-color: #1f2d3d; color: #fff; font-weight: 600; }}
    tr:nth-child(even) td {{ background-color: #f6f8fa; }}
    .meta-table td:first-child {{ font-weight: 600; width: 220px; background: #eef1f4; }}
    .mono {{ font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 12px; word-break: break-all; }}
    .muted {{ color: #8a94a0; font-style: italic; }}
    .note {{ color: #444; }}
    .verified {{ background: #e6f4ea; border-left: 5px solid #1e7e34; color: #14522a; padding: 12px 16px; font-weight: 600; margin: 8px 0 14px 0; border-radius: 3px; }}
    .broken {{ background: #fdecea; border-left: 5px solid #dc3545; color: #7a1620; padding: 12px 16px; font-weight: 700; margin: 8px 0 14px 0; border-radius: 3px; }}
    .notice {{ background: #fff8e6; border-left: 5px solid #b8860b; color: #5c4408; padding: 12px 16px; font-weight: 600; margin: 8px 0 14px 0; border-radius: 3px; }}
    .footer {{ margin-top: 40px; padding-top: 16px; border-top: 2px solid #1f2d3d; font-size: 12px; color: #556; }}
    .footer ul {{ margin: 8px 0 0 20px; }}
    .summary {{ background: #f0f4f8; border-left: 5px solid #1f2d3d; padding: 14px 18px; margin: 8px 0 18px 0; border-radius: 3px; white-space: pre-wrap; }}
    .timezone-note {{ background: #fffdf0; border-left: 5px solid #b8860b; padding: 10px 16px; margin: 12px 0 18px 0; font-size: 12px; }}
    .declaration {{ background: #f7f9fb; border: 1px solid #ccd; padding: 16px 20px; margin: 12px 0; border-radius: 3px; }}
    .declaration .signatory {{ margin-top: 18px; padding-top: 12px; border-top: 1px solid #ccd; }}
    dl.glossary dt {{ font-weight: 600; margin-top: 10px; }}
    dl.glossary dd {{ margin: 2px 0 0 24px; color: #334; }}
    .overview {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 10px; margin: 8px 0 18px 0; }}
    .stat {{ background: #f6f8fa; border: 1px solid #d7dde3; border-radius: 4px; padding: 10px 12px; }}
    .stat .num {{ font-size: 22px; font-weight: 700; color: #1f2d3d; }}
    .stat .lbl {{ font-size: 12px; color: #667; text-transform: uppercase; letter-spacing: 0.4px; }}
    .stat.alert .num {{ color: #dc3545; }}
    .cat-total {{ color: #667; font-size: 12px; margin: 0 0 6px 0; }}
    figure.report-figure {{ margin: 12px 0 18px 0; }}
    figure.report-figure svg {{ max-width: 100%; height: auto; border: 1px solid #d7dde3; }}
    figure.report-figure figcaption {{ font-size: 12px; color: #444; margin-top: 6px; }}
    @media print {{
        body {{ padding: 18px; font-size: 11px; }}
        h1 {{ font-size: 20px; }}
        h2 {{ font-size: 16px; page-break-after: avoid; }}
        table {{ page-break-inside: auto; }}
        tr {{ page-break-inside: avoid; }}
    }}
</style>
</head>
<body>
"#,
        title = esc(&data.case_name)
    ));

    // ---- Title / header ----
    h.push_str(&format!(
        "<h1>Forensic Analysis Report: {}</h1>\n",
        esc(&data.case_name)
    ));
    h.push_str("<table class=\"meta-table\">\n");
    h.push_str(&format!(
        "<tr><td>Case Name</td><td>{}</td></tr>\n",
        esc(&data.case_name)
    ));
    h.push_str(&format!(
        "<tr><td>Case Reference</td><td>{}</td></tr>\n",
        esc_opt(&data.case_reference)
    ));
    h.push_str(&format!(
        "<tr><td>Examiner</td><td>{}</td></tr>\n",
        esc(&data.examiner)
    ));
    h.push_str(&format!(
        "<tr><td>Report Generated</td><td>{}</td></tr>\n",
        esc(&data.generated_at)
    ));
    h.push_str(&format!(
        "<tr><td>Tool</td><td>{} {}</td></tr>\n",
        esc(&data.tool_name),
        esc(&data.tool_version)
    ));
    // Report identity: a re-issued report must be distinguishable from the one
    // already disclosed, so the reference and revision sit in the header rather
    // than in a footnote.
    if let Some(identity) = &data.report_identity {
        if !identity.report_id.is_empty() {
            h.push_str(&format!(
                "<tr><td>Report Reference</td><td>{}</td></tr>\n",
                esc(&identity.report_id)
            ));
        }
        if let Some(revision) = identity.revision {
            h.push_str(&format!("<tr><td>Revision</td><td>{revision}</td></tr>\n"));
        }
        if let Some(classification) = &identity.classification {
            h.push_str(&format!(
                "<tr><td>Handling</td><td><strong>{}</strong></td></tr>\n",
                esc(classification)
            ));
        }
    }
    // Examiner detail beyond the bare name, where the caller supplied it.
    if let Some(details) = &data.examiner_details {
        if let Some(role) = &details.role {
            h.push_str(&format!("<tr><td>Role</td><td>{}</td></tr>\n", esc(role)));
        }
        if let Some(org) = &details.organisation {
            h.push_str(&format!(
                "<tr><td>Organisation</td><td>{}</td></tr>\n",
                esc(org)
            ));
        }
        if let Some(quals) = &details.qualifications {
            h.push_str(&format!(
                "<tr><td>Qualifications</td><td>{}</td></tr>\n",
                esc(quals)
            ));
        }
        if let Some(contact) = &details.contact {
            h.push_str(&format!(
                "<tr><td>Contact</td><td>{}</td></tr>\n",
                esc(contact)
            ));
        }
    }
    h.push_str("</table>\n");

    // ---- How times are expressed ----
    //
    // Rendered before any section that contains a timestamp, and never
    // omitted: an unqualified time in a forensic report is challengeable on
    // its face.
    h.push_str(&format!(
        "<div class=\"timezone-note\"><strong>Times:</strong> {}</div>\n",
        esc(TIMEZONE_STATEMENT)
    ));

    // ---- Executive Summary (narrative) ----
    if let Some(summary) = &data.executive_summary {
        if !summary.is_empty() {
            h.push_str("<h2>Executive Summary</h2>\n");
            h.push_str(&format!("<div class=\"summary\">{}</div>\n", esc(summary)));
        }
    }

    // ---- File Overview (FTK-style counts) ----
    if let Some(ov) = &data.file_overview {
        h.push_str("<h2>File Overview</h2>\n");
        h.push_str("<div class=\"overview\">\n");
        let stat = |label: &str, n: i64, alert: bool| {
            format!(
                "<div class=\"stat{}\"><div class=\"num\">{}</div><div class=\"lbl\">{}</div></div>\n",
                if alert { " alert" } else { "" },
                n,
                esc(label)
            )
        };
        // An undetermined count renders as a dash, never as 0: the report must
        // not claim "no carved files" when nothing counted them.
        let stat_opt = |label: &str, n: Option<i64>| {
            format!(
                "<div class=\"stat\"><div class=\"num\">{}</div><div class=\"lbl\">{}</div></div>\n",
                match n {
                    Some(v) => v.to_string(),
                    None => DASH.to_string(),
                },
                esc(label)
            )
        };
        h.push_str(&stat("Total Files", ov.total_files, false));
        h.push_str(&stat("Directories", ov.directories, false));
        h.push_str(&stat("Deleted", ov.deleted_files, false));
        h.push_str(&stat_opt("Carved", ov.carved_files));
        h.push_str(&stat_opt("Encrypted", ov.encrypted_files));
        h.push_str(&stat("Known-Good Filtered", ov.known_good_filtered, false));
        h.push_str(&stat(
            "Notable Alerts",
            ov.notable_alerts,
            ov.notable_alerts > 0,
        ));
        h.push_str("</div>\n");
        if ov.carved_files.is_none() || ov.encrypted_files.is_none() {
            h.push_str("<p class=\"cat-total\">Counts shown as &mdash; were not determined for this report and must not be read as zero.</p>\n");
        }
    }

    // ---- Result Completeness ----
    // Always rendered, including when nothing is incomplete. A section that
    // appears only on bad news teaches the reader that its absence means good
    // news, which is exactly the inference an unassessed case must not support.
    h.push_str("<h2>Result Completeness</h2>\n");
    {
        let (class, text) = completeness_statement(data.incompleteness.as_ref());
        h.push_str(&format!("<div class=\"{}\">{}</div>\n", class, esc(&text)));
    }
    if let Some(inc) = &data.incompleteness {
        if inc.any() {
            if let Some(note) = reason_truncation_note(inc.reasons.len(), inc.distinct_reasons) {
                h.push_str(&format!(
                    "<p class=\"cat-total\">Content not read in full &mdash; {}</p>\n",
                    esc(&note)
                ));
            }
            if let Some(note) =
                reason_truncation_note(inc.inventory_reasons.len(), inc.distinct_inventory_reasons)
            {
                h.push_str(&format!(
                    "<p class=\"cat-total\">Listing shorter than the container &mdash; {}</p>\n",
                    esc(&note)
                ));
            }
            h.push_str(&incompleteness_reason_rows_html(inc));
        }
    }

    // ---- Evidence Sources ----
    h.push_str("<h2>Evidence Sources</h2>\n");
    if data.evidence_sources.is_empty() {
        h.push_str("<p class=\"muted\">None recorded</p>\n");
    } else {
        h.push_str("<table>\n<tr><th>Name</th><th>Type</th><th>Size</th><th>MD5</th><th>SHA1</th><th>SHA256</th><th>Acquired</th></tr>\n");
        for s in &data.evidence_sources {
            let size = s
                .size_bytes
                .map(human_size)
                .unwrap_or_else(|| DASH.to_string());
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td></tr>\n",
                esc(&s.name),
                esc(&s.source_type),
                size,
                esc_opt(&s.md5),
                esc_opt(&s.sha1),
                esc_opt(&s.sha256),
                esc_opt(&s.acquired_at),
            ));
        }
        h.push_str("</table>\n");
    }

    // ---- Evidence Integrity Verification (acquisition vs recomputed) ----
    if !data.integrity_checks.is_empty() {
        h.push_str("<h2>Evidence Integrity</h2>\n");
        h.push_str(&integrity_banner_html(&data.integrity_checks));
        h.push_str("<table>\n<tr><th>Source</th><th>Algorithm</th><th>Acquisition Hash</th><th>Recomputed Hash</th><th>Result</th><th>Meaning</th><th>Recorded</th></tr>\n");
        for c in &data.integrity_checks {
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                esc(&c.source_name),
                esc(&c.algorithm),
                esc_opt(&c.acquisition_hash),
                esc_opt(&c.recomputed_hash),
                c.outcome.label(),
                esc(c.outcome.description()),
                esc_opt(&c.checked_at),
            ));
        }
        h.push_str("</table>\n");
    }

    // ---- Artifact Statistics ----
    h.push_str("<h2>Artifact Statistics</h2>\n");
    if data.artifact_counts.is_empty() && data.total_artifacts == 0 {
        h.push_str("<p class=\"muted\">None recorded</p>\n");
    } else {
        h.push_str("<table>\n<tr><th>Artifact Type</th><th>Count</th></tr>\n");
        for (ty, count) in &data.artifact_counts {
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>\n",
                esc(ty),
                count
            ));
        }
        h.push_str(&format!(
            "<tr><th>Total</th><th>{}</th></tr>\n",
            data.total_artifacts
        ));
        h.push_str("</table>\n");
    }

    // ---- Per-category artifact detail sections ----
    for section in &data.category_sections {
        h.push_str(&format!("<h2>{}</h2>\n", esc(&section.title)));
        if section.total > section.rows.len() as i64 {
            h.push_str(&format!(
                "<p class=\"cat-total\">Showing {} of {} records.</p>\n",
                section.rows.len(),
                section.total
            ));
        }
        if let Some(note) = section_incompleteness_note(section) {
            h.push_str(&format!("<div class=\"notice\">{}</div>\n", esc(&note)));
        }
        if section.rows.is_empty() {
            h.push_str(&format!(
                "<p class=\"muted\">{}</p>\n",
                esc(&empty_section_note(section))
            ));
        } else {
            h.push_str(&render_html_table(&section.columns, &section.rows));
        }
    }

    // ---- Notable Hash Matches (omitted entirely when empty) ----
    if !data.notable_hash_hits.is_empty() {
        h.push_str("<h2>Notable Hash Matches</h2>\n");
        if let Some(note) = truncation_note(data.notable_hash_hits.len(), data.notable_hash_total) {
            h.push_str(&format!("<p class=\"cat-total\">{}</p>\n", note));
        }
        h.push_str("<table>\n<tr><th>Artifact</th><th>Path</th><th>Hash Set</th><th>Algorithm</th><th>Matched Hash</th></tr>\n");
        for hit in &data.notable_hash_hits {
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}</td></tr>\n",
                esc(&hit.artifact_name),
                esc_opt(&hit.path),
                esc(&hit.hash_set_name),
                esc(&hit.algorithm),
                esc(&hit.matched_hash),
            ));
        }
        h.push_str("</table>\n");
    }

    // ---- Known-Good (KFF) Hash Matches ----
    if !data.known_good_hash_hits.is_empty() {
        h.push_str("<h2>Known-Good (KFF) Hash Matches</h2>\n");
        h.push_str("<p class=\"cat-total\">Files matching a known-good hash set (safe to exclude from manual review).</p>\n");
        if let Some(note) =
            truncation_note(data.known_good_hash_hits.len(), data.known_good_hash_total)
        {
            h.push_str(&format!("<p class=\"cat-total\">{}</p>\n", note));
        }
        h.push_str("<table>\n<tr><th>Artifact</th><th>Path</th><th>Hash Set</th><th>Algorithm</th><th>Matched Hash</th></tr>\n");
        for hit in &data.known_good_hash_hits {
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}</td></tr>\n",
                esc(&hit.artifact_name),
                esc_opt(&hit.path),
                esc(&hit.hash_set_name),
                esc(&hit.algorithm),
                esc(&hit.matched_hash),
            ));
        }
        h.push_str("</table>\n");
    }

    // ---- Findings / Bookmarks ----
    h.push_str("<h2>Findings / Bookmarks</h2>\n");
    if let Some(note) = personal_bookmarks_excluded_note(data.personal_bookmarks_excluded) {
        h.push_str(&format!("<p class=\"muted\">{}</p>\n", esc(&note)));
    }
    if data.bookmarks.is_empty() {
        h.push_str("<p class=\"muted\">None recorded</p>\n");
    } else {
        h.push_str("<table>\n<tr><th>Category</th><th>Artifact</th><th>Source location</th><th>Note</th><th>Examiner</th><th>Created</th></tr>\n");
        for b in &data.bookmarks {
            // Source-location provenance: path plus the byte offset within the
            // evidence, so a reviewer can go back to the exact bytes.
            let location = match (&b.source_path, b.source_offset) {
                (Some(p), Some(off)) => format!("{} @ byte {}", esc(p), off),
                (Some(p), None) => esc(p),
                (None, Some(off)) => format!("byte {off}"),
                (None, None) => DASH.to_string(),
            };
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"note\">{}</td><td>{}</td><td>{}</td></tr>\n",
                esc_opt(&b.category),
                esc(&b.artifact_name),
                location,
                esc_opt(&b.note),
                esc_opt(&b.examiner),
                esc(&b.created_at),
            ));
        }
        h.push_str("</table>\n");
    }

    // ---- Communications Network ----
    //
    // Always rendered, in one of three states — not computed, computed and
    // empty, or drawn — because a section that appears only when there is a
    // network teaches the reader that its absence means there were no
    // contacts.
    h.push_str("<h2>Communications Network</h2>\n");
    match &extras.communications {
        None => h.push_str(&format!(
            "<p class=\"muted\">{}</p>\n",
            esc(COMMUNICATIONS_NOT_COMPUTED)
        )),
        Some(graph) if graph.nodes.is_empty() => h.push_str(&format!(
            "<p class=\"muted\">{}</p>\n",
            esc(&communications_empty_statement(graph))
        )),
        Some(graph) => {
            if let Some(note) = communications_truncation_note(graph) {
                h.push_str(&format!("<div class=\"broken\">{}</div>\n", esc(&note)));
            }
            if let Some(fig) = crate::figures::comms_figure(graph) {
                figure_no += 1;
                h.push_str(&format!(
                    "<figure class=\"report-figure\">\n{}<figcaption>Figure {}. {}</figcaption>\n</figure>\n",
                    fig.to_figure().to_svg(),
                    figure_no,
                    esc(&fig.caption())
                ));
            }
            h.push_str("<h3>Participants</h3>\n");
            let cols: Vec<String> = COMMUNICATION_PARTICIPANT_COLUMNS
                .iter()
                .map(|c| c.to_string())
                .collect();
            h.push_str(&render_html_table(
                &cols,
                &communication_participant_rows(graph),
            ));
            h.push_str("<h3>Links</h3>\n");
            let (rows, note) = communication_link_rows(graph);
            if let Some(note) = note {
                h.push_str(&format!("<p class=\"cat-total\">{}</p>\n", esc(&note)));
            }
            let cols: Vec<String> = COMMUNICATION_LINK_COLUMNS
                .iter()
                .map(|c| c.to_string())
                .collect();
            h.push_str(&render_html_table(&cols, &rows));
        }
    }

    // ---- Feature Histograms ----
    //
    // Always rendered, in the same three states as the network above and
    // for the same reason.
    h.push_str("<h2>Feature Histograms</h2>\n");
    match &extras.feature_histograms {
        None => h.push_str(&format!(
            "<p class=\"muted\">{}</p>\n",
            esc(&feature_histograms_not_gathered_text(extras))
        )),
        Some(hists) if hists.is_empty() => h.push_str(&format!(
            "<p class=\"muted\">{}</p>\n",
            esc(FEATURE_HISTOGRAMS_NONE_FOUND)
        )),
        Some(hists) => {
            h.push_str(&format!("<p>{}</p>\n", esc(FEATURE_HISTOGRAMS_INTRO)));
            let kind_cols: Vec<String> =
                FEATURE_KIND_COLUMNS.iter().map(|c| c.to_string()).collect();
            let value_cols: Vec<String> = FEATURE_VALUE_COLUMNS
                .iter()
                .map(|c| c.to_string())
                .collect();
            for hist in hists {
                h.push_str(&format!("<h3>{}</h3>\n", esc(&hist.source)));
                for note in feature_histogram_incomplete_notes(hist) {
                    h.push_str(&format!("<div class=\"broken\">{}</div>\n", esc(&note)));
                }
                h.push_str(&format!(
                    "<p>{}</p>\n",
                    esc(&feature_histogram_total_line(hist))
                ));
                h.push_str(&render_html_table(&kind_cols, &feature_kind_rows(hist)));
                h.push_str(&format!("<p class=\"cat-total\">{}</p>\n", esc(&hist.note)));
                h.push_str(&format!("<h4>{}</h4>\n", FEATURE_TOP_TITLE));
                if let Some(note) = feature_histogram_top_note(hist) {
                    h.push_str(&format!("<p class=\"cat-total\">{}</p>\n", esc(&note)));
                }
                h.push_str(&render_html_table(&value_cols, &feature_value_rows(hist)));
            }
        }
    }

    // ---- Values Traced Across the Evidence ----
    //
    // Examiner-authored, so it sits with the bookmarks rather than with the
    // leads: the tool answered the question and the examiner decided the
    // answer belonged in the document. Both answers are rendered — what the
    // pivot said when it was pinned and what it says now — because a report
    // that showed one of them would either describe a case that has grown or
    // quietly say something different from what the examiner saw.
    if !data.traced_values.is_empty() {
        h.push_str("<h2>Values Traced Across the Evidence</h2>\n");
        h.push_str(
            "<p class=\"cat-total\">Each value below was traced across every parsed artifact in \
             this case and pinned by the named examiner at the time stated. The counts are of \
             artifacts that <em>reference</em> the value; a reference is not a relationship, and \
             what each artifact is remains the question the artifact itself answers.</p>\n",
        );
        for t in &data.traced_values {
            h.push_str("<div class=\"lead\">\n");
            h.push_str(&format!("<h3>{}</h3>\n", esc(&t.value)));
            if let Some(note) = &t.note {
                h.push_str(&format!("<p class=\"note\">{}</p>\n", esc(note)));
            }
            h.push_str(&format!(
                "<p><strong>Pinned by</strong> {} on {}. <strong>{} artifact(s)</strong> \
                 referenced this value at that moment.</p>\n",
                esc(&t.examiner),
                esc(&t.pinned_at),
                t.matches_when_pinned
            ));
            if t.truncated_when_pinned {
                h.push_str(
                    "<div class=\"broken\">The per-kind counts below are a SAMPLE: more \
                     artifacts referenced this value than the pivot groups at once, so they do \
                     not add up to the total above and must not be read as the whole.</div>\n",
                );
            }
            if !t.groups_when_pinned.is_empty() {
                h.push_str("<table>\n<tr><th>Record kind</th><th>Artifacts</th></tr>\n");
                for (kind, count) in &t.groups_when_pinned {
                    h.push_str(&format!(
                        "<tr><td>{}</td><td>{}</td></tr>\n",
                        esc(kind),
                        count
                    ));
                }
                h.push_str("</table>\n");
            }
            // The re-run. Silence here would leave the snapshot reading as
            // current, which it is only until the next ingest.
            match (t.matches_now, &t.recheck_unavailable_reason) {
                (Some(now), _) if now == t.matches_when_pinned => {
                    h.push_str(&format!(
                        "<p class=\"cat-total\">Re-checked when this report was produced: still \
                         {now} artifact(s).</p>\n"
                    ));
                }
                (Some(now), _) => {
                    h.push_str(&format!(
                        "<div class=\"broken\">Re-checked when this report was produced: \
                         {now} artifact(s) now reference this value, against \
                         {} when it was pinned. The case answered this question differently on \
                         the two dates; the figures above are the examiner's snapshot and this \
                         one is current.</div>\n",
                        t.matches_when_pinned
                    ));
                }
                (None, Some(why)) => {
                    h.push_str(&format!(
                        "<div class=\"broken\">This value could NOT be re-checked when the \
                         report was produced: {}. The counts above are the examiner's snapshot \
                         and nothing here says they are still current.</div>\n",
                        esc(why)
                    ));
                }
                (None, None) => {
                    h.push_str(
                        "<div class=\"broken\">This value was not re-checked when the report was \
                         produced, and no reason was recorded. Treat the counts above as the \
                         examiner's snapshot only.</div>\n",
                    );
                }
            }
            h.push_str("</div>\n");
        }
    }

    // ---- Investigative Leads ----    // ---- Investigative Leads ----
    //
    // Rendered whether or not any were raised, because an empty section means
    // one of two different things — nothing matched the checks present, or
    // nothing here looks for what the reader is after — and the checks
    // themselves are listed so a reader can tell which.
    if !data.leads.is_empty() || !data.lead_detections.is_empty() {
        h.push_str("<h2>Investigative Leads</h2>\n");
        h.push_str(&format!(
            "<div class=\"broken\">{}</div>\n",
            esc(LEADS_PREAMBLE)
        ));
        if data.leads.is_empty() {
            h.push_str("<p class=\"muted\">No leads were raised.</p>\n");
        } else {
            if data.leads_total > data.leads.len() as i64 {
                h.push_str(&format!(
                    "<div class=\"broken\">This case holds {} lead(s); the {} listed below are \
                     the most confident. The remainder are not in this report.</div>\n",
                    data.leads_total,
                    data.leads.len()
                ));
            }
            for lead in &data.leads {
                h.push_str("<div class=\"lead\">\n");
                h.push_str(&format!(
                    "<h3>[{}] {}</h3>\n",
                    esc(&lead.confidence),
                    esc(&lead.title)
                ));
                // The three text blocks stay three blocks and keep their
                // labels: a reader who takes the inference for the observation
                // has been misled by the report, not by the evidence.
                h.push_str(&format!(
                    "<p><strong>Observation (checkable against the evidence):</strong> {}</p>\n",
                    esc(&lead.observation)
                ));
                if let Some(inference) = &lead.inference {
                    h.push_str(&format!(
                        "<p><strong>What this may indicate \u{2014} S\u{e9}ance's reading, not a \
                         fact:</strong> {}</p>\n",
                        esc(inference)
                    ));
                }
                h.push_str(&format!(
                    "<p><strong>What it does not establish:</strong> {}</p>\n",
                    esc(&lead.qualification)
                ));
                if !lead.evidence.is_empty() {
                    h.push_str("<table>\n<tr><th>Value</th><th>As recorded</th></tr>\n");
                    for (name, value) in &lead.evidence {
                        h.push_str(&format!(
                            "<tr><td>{}</td><td>{}</td></tr>\n",
                            esc(name),
                            esc(value)
                        ));
                    }
                    h.push_str("</table>\n");
                }
                let location = match lead.device_offset {
                    Some(off) => format!("{} @ byte {}", esc(&lead.subject), off),
                    None => esc(&lead.subject),
                };
                h.push_str(&format!(
                    "<p class=\"cat-total\">Subject: {location}. Raised by {}. {}</p>\n",
                    esc(&lead.source_module),
                    if lead.stored_as_a_record {
                        "Recorded in the case as its own artifact."
                    } else {
                        "Computed when this report was produced; it is not stored as an \
                         artifact, so only the subject above can be re-opened."
                    }
                ));
                h.push_str("</div>\n");
            }
        }
        if !data.lead_detections.is_empty() {
            h.push_str("<h3>What this build can look for</h3>\n");
            h.push_str("<table>\n<tr><th>Check</th><th>What it looks for</th></tr>\n");
            for d in &data.lead_detections {
                h.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td></tr>\n",
                    esc(&d.kind),
                    esc(&d.looks_for)
                ));
            }
            h.push_str("</table>\n");
        }
    }

    // ---- Geolocation (EXIF GPS) ----
    if !data.geolocation.is_empty() || data.geolocation_truncated {
        h.push_str("<h2>Geolocation</h2>\n");
        h.push_str("<p class=\"cat-total\">GPS points extracted from EXIF metadata. Exportable as KML/GeoJSON for mapping.</p>\n");
        if data.geolocation_truncated {
            h.push_str(&format!(
                "<div class=\"broken\">{}</div>\n",
                esc(&geo_truncation_note(data.geolocation.len()))
            ));
        }
        h.push_str("<table>\n<tr><th>File</th><th>Path</th><th>Latitude</th><th>Longitude</th><th>Altitude</th><th>Timestamp</th></tr>\n");
        for g in &data.geolocation {
            let alt = g
                .altitude
                .map(|a| format!("{:.1} m", a))
                .unwrap_or_else(|| DASH.to_string());
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{:.6}</td><td>{:.6}</td><td>{}</td><td>{}</td></tr>\n",
                esc(&g.label),
                esc_opt(&geo_path_cell(g)),
                g.latitude,
                g.longitude,
                alt,
                esc_opt(&g.timestamp),
            ));
        }
        h.push_str("</table>\n");
    }

    // ---- Timeline Highlights ----
    h.push_str("<h2>Timeline Highlights</h2>\n");
    if let Some(note) = timeline_omitted_note(data.incompleteness.as_ref()) {
        h.push_str(&format!("<p class=\"cat-total\">{}</p>\n", esc(&note)));
    }
    if data.timeline_highlights.is_empty() {
        h.push_str("<p class=\"muted\">None recorded</p>\n");
    } else {
        // Note and Examiner are what separate this table from the full timeline
        // below it. Without them the section asserts that these events matter
        // and withholds the only evidence for the assertion.
        h.push_str(
            "<table>\n<tr><th>Timestamp</th><th>Description</th><th>Source Module</th>\
             <th>Note</th><th>Examiner</th></tr>\n",
        );
        for e in &data.timeline_highlights {
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                esc(&e.timestamp),
                esc(&e.description),
                esc(&e.source_module),
                esc_opt(&e.note),
                esc_opt(&e.examiner),
            ));
        }
        h.push_str("</table>\n");
        h.push_str(
            "<p class=\"muted\">Every event above was tagged by an examiner. The note is \
             their own words on why it matters; an em-dash means they tagged the event \
             without writing one.</p>\n",
        );
    }

    // ---- Full Timeline (bounded) ----
    if !data.full_timeline.is_empty() {
        h.push_str("<h2>Timeline</h2>\n");
        if let Some(note) = timeline_omitted_note(data.incompleteness.as_ref()) {
            h.push_str(&format!("<p class=\"cat-total\">{}</p>\n", esc(&note)));
        }
        h.push_str(&format!(
            "<p class=\"cat-total\">{}</p>\n",
            timeline_caption(data.full_timeline.len(), data.full_timeline_total)
        ));
        match crate::figures::timeline_figure(&data.full_timeline, data.full_timeline_total) {
            Some(fig) => {
                figure_no += 1;
                h.push_str(&format!(
                    "<figure class=\"report-figure\">\n{}<figcaption>Figure {}. {}</figcaption>\n</figure>\n",
                    fig.to_figure().to_svg(),
                    figure_no,
                    esc(&fig.caption())
                ));
            }
            None => h.push_str(&format!(
                "<p class=\"cat-total\">{}</p>\n",
                esc(&timeline_figure_unavailable(data.full_timeline.len()))
            )),
        }
        h.push_str(
            "<table>\n<tr><th>Timestamp</th><th>Description</th><th>Source Module</th></tr>\n",
        );
        for e in &data.full_timeline {
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                esc(&e.timestamp),
                esc(&e.description),
                esc(&e.source_module),
            ));
        }
        h.push_str("</table>\n");
    }

    // ---- Chain of Custody & Audit ----
    h.push_str("<h2>Chain of Custody &amp; Audit</h2>\n");
    if data.audit_chain_valid {
        // The banner names the construction, not a conclusion. "tamper-evident"
        // used to be printed here unconditionally; over an unkeyed chain that
        // asserted in a court report exactly what the evidence cannot support
        // (HUNT-011). The keying note below carries the conclusion.
        h.push_str(&format!(
            "<div class=\"verified\">Audit chain verified - {} entries ({}).</div>\n",
            data.audit_chain_checked,
            audit_chain_construction(
                data.audit_chain_tamper_evident,
                data.audit_chain_tamper_evident_from
            )
        ));
    } else {
        // The reason travels with the verdict. A broken chain and a chain the
        // server holds no key for are both "not verified", and only the first
        // is a statement about the evidence; one sentence over both asserted a
        // custody failure for a missing retired key.
        h.push_str(&format!(
            "<div class=\"broken\">AUDIT CHAIN NOT VERIFIED - hash-chain verification FAILED after checking {} entries: {}. Until this is resolved, evidence-handling integrity is not attested by this report.</div>\n",
            data.audit_chain_checked,
            esc(data
                .audit_chain_break_reason
                .as_deref()
                .unwrap_or("the verifier gave no reason"))
        ));
    }
    // What the verdict is worth, then what it covers. Both are stated for a
    // failure too: a reader of a broken chain still has to be told that an
    // unkeyed one would not have shown a competent rewrite in the first place.
    h.push_str(&format!(
        "<p class=\"cat-total\">{}</p>\n",
        esc(&audit_chain_keying_disclosure(
            data.audit_chain_tamper_evident,
            data.audit_chain_tamper_evident_from,
            data.audit_chain_key_configured,
        ))
    ));
    h.push_str(&format!(
        "<p class=\"cat-total\">{}</p>\n",
        esc(audit_chain_scope_note(data.audit_chain_valid))
    ));
    if data.audit_entries.is_empty() {
        h.push_str("<p class=\"muted\">None recorded</p>\n");
    } else {
        if let Some(note) = truncation_note(data.audit_entries.len(), data.audit_entries_total) {
            h.push_str(&format!("<p class=\"cat-total\">{}</p>\n", note));
        }
        h.push_str("<table>\n<tr><th>Timestamp</th><th>User</th><th>Action</th><th>Resource Type</th></tr>\n");
        for a in &data.audit_entries {
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                esc(&a.timestamp),
                esc(&a.user),
                esc(&a.action),
                esc(&a.resource_type),
            ));
        }
        h.push_str("</table>\n");
    }

    // ---- Processing Log (tool provenance) ----
    if !data.processing_log.is_empty() {
        h.push_str("<h2>Processing Log</h2>\n");
        h.push_str("<p class=\"cat-total\">Module execution provenance: which parser produced what, and how long it took. Each row aggregates every run of that module in this case.</p>\n");
        if let Some(note) = truncation_note(data.processing_log.len(), data.processing_log_total) {
            h.push_str(&format!("<p class=\"cat-total\">{}</p>\n", esc(&note)));
        }
        h.push_str("<table>\n<tr><th>Module</th><th>Status</th><th>Runs</th><th>Artifacts</th><th>Duration</th><th>Error</th></tr>\n");
        for p in &data.processing_log {
            let dur = p
                .duration_ms
                .map(|d| format!("{} ms", d))
                .unwrap_or_else(|| DASH.to_string());
            // An unrecorded run count is a dash, not "0": a row that exists
            // proves the module ran at least once, so printing 0 would state
            // something the log contradicts.
            let runs = if p.runs > 0 {
                p.runs.to_string()
            } else {
                DASH.to_string()
            };
            h.push_str(&format!(
                "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                esc(&p.module_id),
                esc(&p.status),
                runs,
                p.artifacts_produced,
                dur,
                esc_opt(&p.error_message),
            ));
        }
        h.push_str("</table>\n");
    }

    // ---- Limitations and qualifications ----
    //
    // Before the glossary and the declaration, and after the findings: a reader
    // has to have seen what was found before being told what it rests on, and
    // has to have been told before being asked to rely on it.
    if !data.method_qualifications.is_empty() {
        h.push_str("<h2>Limitations and Qualifications of the Examination</h2>\n");
        h.push_str(
            "<p>The findings above were produced by the methods described below. Each entry \
             states a respect in which the method qualifies what may be concluded.</p>\n",
        );
        for entry in &data.method_qualifications {
            h.push_str(&format!("<h3>{}</h3>\n", esc(&entry.subject)));
            h.push_str(&format!("<p>{}</p>\n", esc(&entry.statement)));
            // Always stated. An entry with no recorded scope used to render no
            // "Bears on" line at all, and sitting beside a sibling that has one
            // that silence reads as a scope nobody established — when what it
            // actually means is the widest scope there is.
            h.push_str(&format!(
                "<p><em>Bears on:</em> {}</p>\n",
                esc(qualification_scope(entry))
            ));
        }
    }

    // ---- Glossary ----
    //
    // Placed before the declaration so a reader meets the vocabulary before
    // being asked to rely on the conclusions drawn in it.
    if !data.glossary.is_empty() {
        h.push_str("<h2>Glossary</h2>\n");
        h.push_str("<dl class=\"glossary\">\n");
        for entry in &data.glossary {
            h.push_str(&format!(
                "<dt>{}</dt><dd>{}</dd>\n",
                esc(&entry.term),
                esc(&entry.definition)
            ));
        }
        h.push_str("</dl>\n");
    }

    // ---- Declaration ----
    //
    // Last substantive section, as it attests to everything above it. Always
    // rendered: a report issued without a statement of truth is one whose
    // author has not put their name to its contents.
    h.push_str("<h2>Declaration</h2>\n");
    h.push_str(&format!(
        "<div class=\"declaration\"><p>{}</p>\n",
        esc(statement_of_truth(data))
    ));
    let signatory = data
        .examiner_details
        .as_ref()
        .filter(|d| !d.name.is_empty())
        .map(|d| d.name.clone())
        .unwrap_or_else(|| data.examiner.clone());
    h.push_str(&format!(
        "<p class=\"signatory\"><strong>{}</strong>",
        esc(&signatory)
    ));
    if let Some(details) = &data.examiner_details {
        if let Some(role) = &details.role {
            h.push_str(&format!("<br>{}", esc(role)));
        }
        if let Some(org) = &details.organisation {
            h.push_str(&format!("<br>{}", esc(org)));
        }
    }
    h.push_str(&format!("<br>{}</p>\n</div>\n", esc(&data.generated_at)));

    // ---- Methodology / Notes footer ----
    h.push_str(&format!(
        r#"<div class="footer">
<strong>Methodology &amp; Notes</strong>
<ul>
<li>Acquisition hashes (MD5/SHA1/SHA256) shown above were computed at ingest over each evidence source and recorded before analysis.</li>
<li>In the Evidence Integrity section, BASELINE means a hash was recorded at acquisition and has not since been recomputed and compared. It is neither a pass nor a failure: only MATCH and MISMATCH state the result of a re-verification.</li>
<li>The audit log is a hash-chained record; each entry commits to its predecessor. The verification banner above reflects a full re-computation of that chain. {chain_method}</li>
<li>Result Completeness reports flags the parsers themselves recorded: a parser that could not read or decode its input in full marks the artifact it produced, and a listing shorter than what the container holds is marked separately. Where a section carries an INCOMPLETE notice, its records are a subset and the absence of an item from that listing is not evidence that the item was absent from the evidence.</li>
<li>Report generated by {tool} {ver} at {generated}. All findings should be independently verified against source evidence.</li>
</ul>
</div>
"#,
        // Was an unconditional "making undetected modification computationally
        // infeasible", which is untrue of an unkeyed chain against anyone with
        // database write access (HUNT-011). Same sentence as the banner's, from
        // the same function, so the footer cannot contradict it.
        chain_method = esc(&audit_chain_keying_disclosure(
            data.audit_chain_tamper_evident,
            data.audit_chain_tamper_evident_from,
            data.audit_chain_key_configured,
        )),
        tool = esc(&data.tool_name),
        ver = esc(&data.tool_version),
        generated = esc(&data.generated_at),
    ));

    h.push_str("</body>\n</html>\n");
    h
}

// ---------------------------------------------------------------------------
// PDF rendering
// ---------------------------------------------------------------------------

const PAGE_W: f32 = 210.0;
const PAGE_H: f32 = 297.0;
const MARGIN: f32 = 18.0;
const BOTTOM: f32 = 18.0;
const LINE_H: f32 = 5.2;
/// Where a `Line::Field` value is set, in mm from the left margin.
const FIELD_VALUE_X: f32 = 55.0;
/// Clear space kept between a field's label and its value, in mm.
const FIELD_GAP: f32 = 2.0;

/// Helvetica-Bold advance widths for ASCII 0x20..=0x7E, in 1/1000 em, from
/// Adobe's core-font metrics (`Helvetica-Bold.afm`). The PDF's labels are set
/// in that built-in font, so these are the widths the viewer draws.
const HELVETICA_BOLD_WIDTHS: [u16; 95] = [
    278, 333, 474, 556, 556, 889, 722, 278, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667,
    611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
    667, 611, 333, 278, 333, 584, 556, 278, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556,
    278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
];

/// The width `text` occupies set in Helvetica-Bold at `size_pt`, in mm. A
/// character outside printable ASCII is counted at a full em, wider than any
/// glyph in the table, so the estimate errs towards "does not fit".
fn helvetica_bold_width_mm(text: &str, size_pt: f32) -> f32 {
    let units: u32 = text
        .chars()
        .map(|c| match c as u32 {
            cp @ 0x20..=0x7E => u32::from(HELVETICA_BOLD_WIDTHS[(cp - 0x20) as usize]),
            _ => 1000,
        })
        .sum();
    units as f32 / 1000.0 * size_pt * 25.4 / 72.0
}

/// Whether a field's label, as printed (10 pt bold), reaches the value column.
/// Such a label gets its value on the line below instead of underneath it.
fn field_label_overruns(label: &str) -> bool {
    helvetica_bold_width_mm(&pdf_safe(label), 10.0) + FIELD_GAP > FIELD_VALUE_X
}

/// One drawable line in the PDF layout.
enum Line {
    Title(String),
    Heading(String),
    Field(String, String),
    Mono(String),
    Text(String),
    /// A laid-out figure, scaled to the content width and drawn with the
    /// page's own vector primitives.
    Figure(Box<crate::figures::Figure>),
    Gap,
}

/// Width available to a figure, in mm.
const CONTENT_W: f32 = PAGE_W - 2.0 * MARGIN;

/// Height a figure takes on the page, in mm.
fn figure_height_mm(fig: &crate::figures::Figure) -> f32 {
    let scale = CONTENT_W / fig.width as f32;
    fig.height as f32 * scale
}

/// Parse `#rrggbb` into a PDF colour. Unparseable input draws black, and the
/// only colours that reach here are the figure module's own constants.
fn pdf_color(hex: &str) -> Color {
    let h = hex.trim_start_matches('#');
    let chan = |i: usize| {
        u8::from_str_radix(h.get(i..i + 2).unwrap_or("00"), 16).unwrap_or(0) as f32 / 255.0
    };
    Color::Rgb(Rgb::new(chan(0), chan(2), chan(4), None))
}

/// Draw a figure whose top-left corner sits at (`MARGIN`, `top`) on the page.
///
/// Figure units are scaled uniformly to the content width; the y axis is
/// flipped because PDF measures from the bottom of the page. Text anchoring
/// is approximated from Helvetica's average glyph width, which is all a
/// figure's short labels need.
fn draw_figure_pdf(
    layer: &PdfLayerReference,
    fig: &crate::figures::Figure,
    top: f32,
    font: &IndirectFontRef,
    font_bold: &IndirectFontRef,
) {
    use crate::figures::Shape;
    let scale = CONTENT_W / fig.width as f32;
    let x_of = |x: f64| Mm(MARGIN + x as f32 * scale);
    let y_of = |y: f64| Mm(top - y as f32 * scale);
    // Figure units to points: units -> mm (scale) -> pt (72 / 25.4).
    let pt = |u: f64| u as f32 * scale * 72.0 / 25.4;

    for shape in &fig.shapes {
        match shape {
            Shape::Rect {
                x,
                y,
                w,
                h,
                fill,
                stroke,
            } => {
                layer.set_fill_color(pdf_color(fill));
                let mode = match stroke {
                    Some(stroke) => {
                        layer.set_outline_color(pdf_color(stroke));
                        layer.set_outline_thickness(pt(1.0));
                        printpdf::path::PaintMode::FillStroke
                    }
                    None => printpdf::path::PaintMode::Fill,
                };
                layer.add_rect(
                    Rect::new(x_of(*x), y_of(*y + *h), x_of(*x + *w), y_of(*y)).with_mode(mode),
                );
            }
            Shape::Line {
                x1,
                y1,
                x2,
                y2,
                stroke,
                width,
            } => {
                layer.set_outline_color(pdf_color(stroke));
                layer.set_outline_thickness(pt(*width));
                layer.add_line(printpdf::Line {
                    points: vec![
                        (Point::new(x_of(*x1), y_of(*y1)), false),
                        (Point::new(x_of(*x2), y_of(*y2)), false),
                    ],
                    is_closed: false,
                });
            }
            Shape::Circle {
                cx,
                cy,
                r,
                fill,
                stroke,
            } => {
                layer.set_fill_color(pdf_color(fill));
                layer.set_outline_color(pdf_color(stroke));
                layer.set_outline_thickness(pt(2.0));
                let points = printpdf::utils::calculate_points_for_circle(
                    Mm(*r as f32 * scale),
                    x_of(*cx),
                    y_of(*cy),
                );
                layer.add_polygon(Polygon {
                    rings: vec![points],
                    mode: printpdf::path::PaintMode::FillStroke,
                    winding_order: printpdf::path::WindingOrder::NonZero,
                });
            }
            Shape::Text {
                x,
                y,
                text,
                size,
                anchor,
                bold,
                fill,
            } => {
                let approx_w = text.chars().count() as f64 * size * 0.5;
                let x = match anchor.as_str() {
                    "middle" => x - approx_w / 2.0,
                    "end" => x - approx_w,
                    _ => *x,
                };
                layer.set_fill_color(pdf_color(fill));
                layer.use_text(
                    pdf_safe(text),
                    pt(*size),
                    x_of(x),
                    y_of(*y),
                    if *bold { font_bold } else { font },
                );
            }
        }
    }
    // Leave the ink black for the text that follows.
    layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
}

/// Render the same report content as a PDF document.
///
/// Returns the raw PDF bytes (beginning with `%PDF`). Signing, if desired, is
/// applied separately by the caller via [`crate::sign_pdf`]; this keeps the
/// renderer independent of key material.
pub fn render_pdf(data: &ReportData) -> anyhow::Result<Vec<u8>> {
    render_pdf_with(data, &ReportExtras::default())
}

/// Render the PDF report with the data [`ReportData`] cannot carry.
pub fn render_pdf_with(data: &ReportData, extras: &ReportExtras) -> anyhow::Result<Vec<u8>> {
    let lines = build_pdf_lines(data, extras);

    let (doc, page1, layer1) = crate::create_pdf_document(
        &format!("Forensic Report - {}", data.case_name),
        PAGE_W,
        PAGE_H,
    );
    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    let font_mono = doc.add_builtin_font(BuiltinFont::Courier)?;

    let mut cur_page = page1;
    let mut cur_layer = layer1;
    let mut y = PAGE_H - MARGIN;

    for line in &lines {
        let advance = match line {
            Line::Title(_) => 11.0,
            Line::Heading(_) => 8.0,
            Line::Figure(fig) => figure_height_mm(fig) + LINE_H,
            Line::Field(label, _) if field_label_overruns(label) => 2.0 * LINE_H,
            Line::Gap => LINE_H,
            _ => LINE_H,
        };

        if y < BOTTOM + advance {
            let (p, l) = crate::add_page(&doc, PAGE_W, PAGE_H);
            cur_page = p;
            cur_layer = l;
            y = PAGE_H - MARGIN;
        }

        let layer = doc.get_page(cur_page).get_layer(cur_layer);
        match line {
            Line::Title(t) => {
                layer.use_text(pdf_safe(t), 18.0, Mm(MARGIN), Mm(y), &font_bold);
            }
            Line::Heading(t) => {
                layer.use_text(pdf_safe(t), 13.0, Mm(MARGIN), Mm(y), &font_bold);
            }
            Line::Field(label, value) => {
                layer.use_text(pdf_safe(label), 10.0, Mm(MARGIN), Mm(y), &font_bold);
                // A label that reaches the value column would be overprinted
                // by its value; the value goes on the next line instead.
                let value_y = if field_label_overruns(label) {
                    y - LINE_H
                } else {
                    y
                };
                layer.use_text(
                    pdf_safe(value),
                    10.0,
                    Mm(MARGIN + FIELD_VALUE_X),
                    Mm(value_y),
                    &font,
                );
            }
            Line::Mono(t) => {
                layer.use_text(pdf_safe(t), 8.0, Mm(MARGIN + 4.0), Mm(y), &font_mono);
            }
            Line::Text(t) => {
                layer.use_text(pdf_safe(t), 10.0, Mm(MARGIN), Mm(y), &font);
            }
            Line::Figure(fig) => {
                draw_figure_pdf(&layer, fig, y, &font, &font_bold);
            }
            Line::Gap => {}
        }
        y -= advance;
    }

    let bytes = doc.save_to_bytes()?;
    Ok(bytes)
}

/// Flatten a [`ReportData`] into an ordered list of PDF lines.
fn build_pdf_lines(data: &ReportData, extras: &ReportExtras) -> Vec<Line> {
    let mut figure_no = 0usize;
    let mut l = Vec::new();
    let dash = "-".to_string();
    let opt = |o: &Option<String>| {
        o.clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| dash.clone())
    };

    // Header
    l.push(Line::Title(format!(
        "Forensic Analysis Report: {}",
        data.case_name
    )));
    l.push(Line::Gap);
    l.push(Line::Field("Case Name:".into(), data.case_name.clone()));
    l.push(Line::Field(
        "Case Reference:".into(),
        opt(&data.case_reference),
    ));
    l.push(Line::Field("Examiner:".into(), data.examiner.clone()));
    l.push(Line::Field(
        "Report Generated:".into(),
        data.generated_at.clone(),
    ));
    l.push(Line::Field(
        "Tool:".into(),
        format!("{} {}", data.tool_name, data.tool_version),
    ));
    if let Some(identity) = &data.report_identity {
        if !identity.report_id.is_empty() {
            l.push(Line::Field(
                "Report Reference:".into(),
                identity.report_id.clone(),
            ));
        }
        if let Some(revision) = identity.revision {
            l.push(Line::Field("Revision:".into(), revision.to_string()));
        }
        if let Some(classification) = &identity.classification {
            l.push(Line::Field("Handling:".into(), classification.clone()));
        }
    }
    if let Some(details) = &data.examiner_details {
        if let Some(role) = &details.role {
            l.push(Line::Field("Role:".into(), role.clone()));
        }
        if let Some(org) = &details.organisation {
            l.push(Line::Field("Organisation:".into(), org.clone()));
        }
        if let Some(quals) = &details.qualifications {
            l.push(Line::Field("Qualifications:".into(), quals.clone()));
        }
        if let Some(contact) = &details.contact {
            l.push(Line::Field("Contact:".into(), contact.clone()));
        }
    }
    l.push(Line::Gap);

    // How times are expressed. Before any section carrying a timestamp, and
    // never omitted — see `TIMEZONE_STATEMENT`.
    for chunk in wrap_text(TIMEZONE_STATEMENT, 95) {
        l.push(Line::Text(chunk));
    }
    l.push(Line::Gap);

    // Executive Summary
    if let Some(summary) = &data.executive_summary {
        if !summary.is_empty() {
            l.push(Line::Heading("Executive Summary".into()));
            for para in summary.split('\n') {
                for chunk in wrap_text(para, 95) {
                    l.push(Line::Text(chunk));
                }
            }
            l.push(Line::Gap);
        }
    }

    // File Overview
    if let Some(ov) = &data.file_overview {
        l.push(Line::Heading("File Overview".into()));
        l.push(Line::Field(
            "Total Files:".into(),
            ov.total_files.to_string(),
        ));
        l.push(Line::Field(
            "Directories:".into(),
            ov.directories.to_string(),
        ));
        l.push(Line::Field("Deleted:".into(), ov.deleted_files.to_string()));
        // "not determined" is printed literally; an undetermined count must
        // never be rendered as 0.
        let opt_count = |n: Option<i64>| match n {
            Some(v) => v.to_string(),
            None => "not determined".to_string(),
        };
        l.push(Line::Field("Carved:".into(), opt_count(ov.carved_files)));
        l.push(Line::Field(
            "Encrypted:".into(),
            opt_count(ov.encrypted_files),
        ));
        l.push(Line::Field(
            "Known-Good Filtered:".into(),
            ov.known_good_filtered.to_string(),
        ));
        l.push(Line::Field(
            "Notable Alerts:".into(),
            ov.notable_alerts.to_string(),
        ));
        l.push(Line::Gap);
    }

    // Result Completeness (always stated, see the HTML renderer)
    l.push(Line::Heading("Result Completeness".into()));
    {
        let (_, text) = completeness_statement(data.incompleteness.as_ref());
        for chunk in wrap_text(&text, 95) {
            l.push(Line::Text(chunk));
        }
    }
    if let Some(inc) = &data.incompleteness {
        // Each axis states its own reasons under its own heading. A shared
        // "no reason was recorded" line would attach a content statement to a
        // listing shortfall, or to an axis with nothing wrong on it at all.
        if inc.content_incomplete > 0 {
            l.push(Line::Text("Content not read in full:".into()));
            if let Some(note) = reason_truncation_note(inc.reasons.len(), inc.distinct_reasons) {
                l.push(Line::Text(note));
            }
            if inc.reasons.is_empty() {
                l.push(Line::Field(
                    "no reason was recorded:".into(),
                    inc.content_incomplete.to_string(),
                ));
            }
            for r in &inc.reasons {
                l.push(Line::Field(format!("{}:", r.text()), r.count.to_string()));
            }
        }
        if inc.inventory_incomplete > 0 {
            l.push(Line::Text("Listing shorter than the container:".into()));
            if let Some(note) =
                reason_truncation_note(inc.inventory_reasons.len(), inc.distinct_inventory_reasons)
            {
                l.push(Line::Text(note));
            }
            if inc.inventory_reasons.is_empty() {
                l.push(Line::Field(
                    "no reason was recorded:".into(),
                    inc.inventory_incomplete.to_string(),
                ));
            }
            for r in &inc.inventory_reasons {
                l.push(Line::Field(format!("{}:", r.text()), r.count.to_string()));
            }
        }
    }
    l.push(Line::Gap);

    // Evidence Sources
    l.push(Line::Heading("Evidence Sources".into()));
    if data.evidence_sources.is_empty() {
        l.push(Line::Text("None recorded".into()));
    } else {
        for s in &data.evidence_sources {
            let size = s.size_bytes.map(human_size).unwrap_or_else(|| dash.clone());
            l.push(Line::Field(
                s.name.clone(),
                format!("{} | {}", s.source_type, size),
            ));
            l.push(Line::Mono(format!("MD5    {}", opt(&s.md5))));
            l.push(Line::Mono(format!("SHA1   {}", opt(&s.sha1))));
            l.push(Line::Mono(format!("SHA256 {}", opt(&s.sha256))));
            l.push(Line::Mono(format!("Acquired {}", opt(&s.acquired_at))));
        }
    }
    l.push(Line::Gap);

    // Evidence Integrity
    if !data.integrity_checks.is_empty() {
        l.push(Line::Heading("Evidence Integrity".into()));
        let (_, statement) = integrity_statement(&data.integrity_checks);
        for chunk in wrap_text(&statement, 95) {
            l.push(Line::Text(chunk));
        }
        for c in &data.integrity_checks {
            l.push(Line::Field(
                format!("{} ({})", c.source_name, c.algorithm),
                format!("{} - {}", c.outcome.label(), c.outcome.description()),
            ));
            l.push(Line::Mono(format!("acq  {}", opt(&c.acquisition_hash))));
            l.push(Line::Mono(format!(
                "recomputed {}",
                opt(&c.recomputed_hash)
            )));
        }
        l.push(Line::Gap);
    }

    // Statistics
    l.push(Line::Heading("Artifact Statistics".into()));
    for (ty, count) in &data.artifact_counts {
        l.push(Line::Field(format!("{}:", ty), count.to_string()));
    }
    l.push(Line::Field(
        "Total Artifacts:".into(),
        data.total_artifacts.to_string(),
    ));
    l.push(Line::Gap);

    // Per-category artifact detail sections
    for section in &data.category_sections {
        l.push(Line::Heading(section.title.clone()));
        if section.total > section.rows.len() as i64 {
            l.push(Line::Text(format!(
                "Showing {} of {} records.",
                section.rows.len(),
                section.total
            )));
        }
        if let Some(note) = section_incompleteness_note(section) {
            for chunk in wrap_text(&note, 95) {
                l.push(Line::Text(chunk));
            }
        }
        if section.rows.is_empty() {
            for chunk in wrap_text(&empty_section_note(section), 95) {
                l.push(Line::Text(chunk));
            }
        } else {
            if !section.columns.is_empty() {
                l.push(Line::Mono(section.columns.join(" | ")));
            }
            for row in &section.rows {
                l.push(Line::Mono(row.join(" | ")));
            }
        }
        l.push(Line::Gap);
    }

    // Notable Hash Matches (omit when empty)
    if !data.notable_hash_hits.is_empty() {
        l.push(Line::Heading("Notable Hash Matches".into()));
        if let Some(note) = truncation_note(data.notable_hash_hits.len(), data.notable_hash_total) {
            l.push(Line::Text(note));
        }
        for hit in &data.notable_hash_hits {
            l.push(Line::Field(
                hit.artifact_name.clone(),
                format!("{} / {}", hit.hash_set_name, hit.algorithm),
            ));
            l.push(Line::Mono(format!(
                "{}  {}",
                hit.matched_hash,
                opt(&hit.path)
            )));
        }
        l.push(Line::Gap);
    }

    // Known-Good (KFF) Hash Matches (omit when empty)
    if !data.known_good_hash_hits.is_empty() {
        l.push(Line::Heading("Known-Good (KFF) Hash Matches".into()));
        if let Some(note) =
            truncation_note(data.known_good_hash_hits.len(), data.known_good_hash_total)
        {
            l.push(Line::Text(note));
        }
        for hit in &data.known_good_hash_hits {
            l.push(Line::Field(
                hit.artifact_name.clone(),
                format!("{} / {}", hit.hash_set_name, hit.algorithm),
            ));
            l.push(Line::Mono(format!(
                "{}  {}",
                hit.matched_hash,
                opt(&hit.path)
            )));
        }
        l.push(Line::Gap);
    }

    // Findings / Bookmarks
    l.push(Line::Heading("Findings / Bookmarks".into()));
    if let Some(note) = personal_bookmarks_excluded_note(data.personal_bookmarks_excluded) {
        l.push(Line::Text(note));
    }
    if data.bookmarks.is_empty() {
        l.push(Line::Text("None recorded".into()));
    } else {
        for b in &data.bookmarks {
            let cat = opt(&b.category);
            l.push(Line::Field(
                format!("[{}] {}", cat, b.artifact_name),
                opt(&b.examiner),
            ));
            l.push(Line::Mono(format!("{}  ({})", opt(&b.note), b.created_at)));
        }
    }
    l.push(Line::Gap);

    // Communications Network: always present, in one of three states.
    l.push(Line::Heading("Communications Network".into()));
    match &extras.communications {
        None => {
            for chunk in wrap_text(COMMUNICATIONS_NOT_COMPUTED, 95) {
                l.push(Line::Text(chunk));
            }
        }
        Some(graph) if graph.nodes.is_empty() => {
            for chunk in wrap_text(&communications_empty_statement(graph), 95) {
                l.push(Line::Text(chunk));
            }
        }
        Some(graph) => {
            if let Some(note) = communications_truncation_note(graph) {
                for chunk in wrap_text(&note, 95) {
                    l.push(Line::Text(chunk));
                }
            }
            if let Some(fig) = crate::figures::comms_figure(graph) {
                figure_no += 1;
                l.push(Line::Figure(Box::new(fig.to_figure())));
                for chunk in wrap_text(&format!("Figure {figure_no}. {}", fig.caption()), 95) {
                    l.push(Line::Text(chunk));
                }
            }
            // Exchange counts lead each row: a participant label can be
            // longer than the field column, and a count that lands under a
            // long label is a count nobody can read.
            l.push(Line::Text(
                "Participants (rank, exchanges, kind, participant):".into(),
            ));
            for row in communication_participant_rows(graph) {
                l.push(Line::Mono(format!(
                    "{:>3}  {:>6}  {:<20}  {}",
                    row[0], row[3], row[2], row[1]
                )));
            }
            l.push(Line::Text("Links (exchanges, participants):".into()));
            let (rows, note) = communication_link_rows(graph);
            if let Some(note) = note {
                l.push(Line::Text(note));
            }
            for row in rows {
                l.push(Line::Mono(format!(
                    "{:>6}  {} <-> {}",
                    row[2], row[0], row[1]
                )));
            }
        }
    }
    l.push(Line::Gap);

    // Feature Histograms: always present, in one of three states.
    l.push(Line::Heading("Feature Histograms".into()));
    match &extras.feature_histograms {
        None => {
            for chunk in wrap_text(&feature_histograms_not_gathered_text(extras), 95) {
                l.push(Line::Text(chunk));
            }
        }
        Some(hists) if hists.is_empty() => {
            for chunk in wrap_text(FEATURE_HISTOGRAMS_NONE_FOUND, 95) {
                l.push(Line::Text(chunk));
            }
        }
        Some(hists) => {
            for chunk in wrap_text(FEATURE_HISTOGRAMS_INTRO, 95) {
                l.push(Line::Text(chunk));
            }
            for hist in hists {
                l.push(Line::Gap);
                l.push(Line::Field("Source".into(), hist.source.clone()));
                for note in feature_histogram_incomplete_notes(hist) {
                    for chunk in wrap_text(&note, 95) {
                        l.push(Line::Text(chunk));
                    }
                }
                l.push(Line::Text(feature_histogram_total_line(hist)));
                l.push(Line::Text("By kind (hits, distinct values, kind):".into()));
                for row in feature_kind_rows(hist) {
                    l.push(Line::Mono(format!(
                        "{:>8}  {:>8}  {}",
                        row[1], row[2], row[0]
                    )));
                }
                for chunk in wrap_text(&hist.note, 95) {
                    l.push(Line::Text(chunk));
                }
                // The count leads each row: a matched value can be longer
                // than the line, and a count that lands after a long value
                // is a count nobody can read.
                l.push(Line::Text(format!(
                    "{FEATURE_TOP_TITLE} (count, kind, value):"
                )));
                if let Some(note) = feature_histogram_top_note(hist) {
                    for chunk in wrap_text(&note, 95) {
                        l.push(Line::Text(chunk));
                    }
                }
                for row in feature_value_rows(hist) {
                    l.push(Line::Mono(format!(
                        "{:>8}  {:<12}  {}",
                        row[2], row[0], row[1]
                    )));
                }
            }
        }
    }
    l.push(Line::Gap);

    // Values Traced Across the Evidence
    if !data.traced_values.is_empty() {
        l.push(Line::Heading("Values Traced Across the Evidence".into()));
        for chunk in wrap_text(
            "Each value below was traced across every parsed artifact in this case and pinned \
             by the named examiner at the time stated. The counts are of artifacts that \
             reference the value; a reference is not a relationship.",
            95,
        ) {
            l.push(Line::Text(chunk));
        }
        l.push(Line::Gap);
        for t in &data.traced_values {
            l.push(Line::Field(t.value.clone(), t.examiner.clone()));
            if let Some(note) = &t.note {
                for chunk in wrap_text(note, 95) {
                    l.push(Line::Text(chunk));
                }
            }
            for chunk in wrap_text(
                &format!(
                    "Pinned on {}. {} artifact(s) referenced this value at that moment.",
                    t.pinned_at, t.matches_when_pinned
                ),
                95,
            ) {
                l.push(Line::Text(chunk));
            }
            if t.truncated_when_pinned {
                for chunk in wrap_text(
                    "The per-kind counts below are a SAMPLE: more artifacts referenced this \
                     value than the pivot groups at once, so they do not add up to the total \
                     above and must not be read as the whole.",
                    95,
                ) {
                    l.push(Line::Text(chunk));
                }
            }
            for (kind, count) in &t.groups_when_pinned {
                l.push(Line::Mono(format!("{kind}  {count}")));
            }
            let recheck = match (t.matches_now, &t.recheck_unavailable_reason) {
                (Some(now), _) if now == t.matches_when_pinned => {
                    format!("Re-checked when this report was produced: still {now} artifact(s).")
                }
                (Some(now), _) => format!(
                    "Re-checked when this report was produced: {now} artifact(s) now reference \
                     this value, against {} when it was pinned. The case answered this question \
                     differently on the two dates.",
                    t.matches_when_pinned
                ),
                (None, Some(why)) => format!(
                    "This value could NOT be re-checked when the report was produced: {why}. The \
                     counts above are the examiner's snapshot only."
                ),
                (None, None) => "This value was not re-checked when the report was produced, and \
                                 no reason was recorded. Treat the counts above as the \
                                 examiner's snapshot only."
                    .to_string(),
            };
            for chunk in wrap_text(&recheck, 95) {
                l.push(Line::Text(chunk));
            }
            l.push(Line::Gap);
        }
    }

    // Investigative Leads
    //
    // Same rule as the HTML: present whenever the build carries any check, so
    // an empty section can be told from a build that looks for nothing.
    if !data.leads.is_empty() || !data.lead_detections.is_empty() {
        l.push(Line::Heading("Investigative Leads".into()));
        for chunk in wrap_text(LEADS_PREAMBLE, 95) {
            l.push(Line::Text(chunk));
        }
        l.push(Line::Gap);
        if data.leads.is_empty() {
            l.push(Line::Text("No leads were raised.".into()));
        } else {
            if data.leads_total > data.leads.len() as i64 {
                for chunk in wrap_text(
                    &format!(
                        "This case holds {} lead(s); the {} below are the most confident. The \
                         remainder are not in this report.",
                        data.leads_total,
                        data.leads.len()
                    ),
                    95,
                ) {
                    l.push(Line::Text(chunk));
                }
            }
            for lead in &data.leads {
                l.push(Line::Field(
                    format!("[{}] {}", lead.confidence, lead.title),
                    lead.kind.clone(),
                ));
                // Three labelled blocks, never merged: see the HTML renderer.
                for chunk in wrap_text(
                    &format!(
                        "Observation (checkable against the evidence): {}",
                        lead.observation
                    ),
                    95,
                ) {
                    l.push(Line::Text(chunk));
                }
                if let Some(inference) = &lead.inference {
                    for chunk in wrap_text(
                        &format!(
                            "What this may indicate \u{2014} S\u{e9}ance's reading, not a fact: {inference}"
                        ),
                        95,
                    ) {
                        l.push(Line::Text(chunk));
                    }
                }
                for chunk in wrap_text(
                    &format!("What it does not establish: {}", lead.qualification),
                    95,
                ) {
                    l.push(Line::Text(chunk));
                }
                for (name, value) in &lead.evidence {
                    l.push(Line::Mono(format!("{name} = {value}")));
                }
                let location = match lead.device_offset {
                    Some(off) => format!("{} @ byte {}", lead.subject, off),
                    None => lead.subject.clone(),
                };
                l.push(Line::Mono(format!(
                    "subject {location}  raised by {}  {}",
                    lead.source_module,
                    if lead.stored_as_a_record {
                        "recorded in the case"
                    } else {
                        "computed for this report; not stored as an artifact"
                    }
                )));
                l.push(Line::Gap);
            }
        }
        if !data.lead_detections.is_empty() {
            l.push(Line::Text("What this build can look for:".into()));
            for d in &data.lead_detections {
                for chunk in wrap_text(&format!("{}: {}", d.kind, d.looks_for), 95) {
                    l.push(Line::Text(chunk));
                }
            }
        }
        l.push(Line::Gap);
    }

    // Geolocation (EXIF GPS)
    if !data.geolocation.is_empty() || data.geolocation_truncated {
        l.push(Line::Heading("Geolocation".into()));
        if data.geolocation_truncated {
            for chunk in wrap_text(&geo_truncation_note(data.geolocation.len()), 95) {
                l.push(Line::Text(chunk));
            }
        }
        for g in &data.geolocation {
            l.push(Line::Field(
                g.label.clone(),
                format!("{:.6}, {:.6}", g.latitude, g.longitude),
            ));
        }
        l.push(Line::Gap);
    }

    // Timeline Highlights
    l.push(Line::Heading("Timeline Highlights".into()));
    if let Some(note) = timeline_omitted_note(data.incompleteness.as_ref()) {
        for chunk in wrap_text(&note, 95) {
            l.push(Line::Text(chunk));
        }
    }
    if data.timeline_highlights.is_empty() {
        l.push(Line::Text("None recorded".into()));
    } else {
        for e in &data.timeline_highlights {
            l.push(Line::Field(
                e.timestamp.clone(),
                format!("{} [{}]", e.description, e.source_module),
            ));
            // The note carries the examiner's reasoning and is the reason the
            // event is in this section at all, so it is printed even though it
            // costs a second line per highlight. Attribution rides with it:
            // "who says this matters" is the first question asked of it.
            if let Some(note) = e.note.as_deref().filter(|n| !n.is_empty()) {
                let attributed = match e.examiner.as_deref().filter(|x| !x.is_empty()) {
                    Some(who) => format!("{note} — {who}"),
                    None => note.to_string(),
                };
                for chunk in wrap_text(&attributed, 88) {
                    l.push(Line::Text(format!("    {chunk}")));
                }
            } else if let Some(who) = e.examiner.as_deref().filter(|x| !x.is_empty()) {
                l.push(Line::Text(format!(
                    "    Tagged by {who}; no note recorded."
                )));
            }
        }
    }
    l.push(Line::Gap);

    // Full Timeline (bounded)
    if !data.full_timeline.is_empty() {
        l.push(Line::Heading("Timeline".into()));
        if let Some(note) = timeline_omitted_note(data.incompleteness.as_ref()) {
            for chunk in wrap_text(&note, 95) {
                l.push(Line::Text(chunk));
            }
        }
        for chunk in wrap_text(
            &timeline_caption(data.full_timeline.len(), data.full_timeline_total),
            95,
        ) {
            l.push(Line::Text(chunk));
        }
        match crate::figures::timeline_figure(&data.full_timeline, data.full_timeline_total) {
            Some(fig) => {
                figure_no += 1;
                l.push(Line::Figure(Box::new(fig.to_figure())));
                for chunk in wrap_text(&format!("Figure {figure_no}. {}", fig.caption()), 95) {
                    l.push(Line::Text(chunk));
                }
            }
            None => {
                for chunk in wrap_text(&timeline_figure_unavailable(data.full_timeline.len()), 95) {
                    l.push(Line::Text(chunk));
                }
            }
        }
        for e in &data.full_timeline {
            l.push(Line::Field(
                e.timestamp.clone(),
                format!("{} [{}]", e.description, e.source_module),
            ));
        }
        l.push(Line::Gap);
    }

    // Chain of Custody & Audit
    l.push(Line::Heading("Chain of Custody & Audit".into()));
    if data.audit_chain_valid {
        // See the HTML banner: the adjective "tamper-evident" is only earned by
        // a keyed chain, so the line states the construction and leaves the
        // conclusion to the keying note (HUNT-011).
        l.push(Line::Text(format!(
            "Audit chain verified - {} entries ({}).",
            data.audit_chain_checked,
            audit_chain_construction(
                data.audit_chain_tamper_evident,
                data.audit_chain_tamper_evident_from
            )
        )));
    } else {
        l.push(Line::Text(format!(
            "AUDIT CHAIN NOT VERIFIED - verification FAILED after {} entries: {}. Until this is \
             resolved, evidence-handling integrity is not attested by this report.",
            data.audit_chain_checked,
            data.audit_chain_break_reason
                .as_deref()
                .unwrap_or("the verifier gave no reason")
        )));
    }
    for chunk in wrap_text(
        &audit_chain_keying_disclosure(
            data.audit_chain_tamper_evident,
            data.audit_chain_tamper_evident_from,
            data.audit_chain_key_configured,
        ),
        95,
    ) {
        l.push(Line::Text(chunk));
    }
    for chunk in wrap_text(audit_chain_scope_note(data.audit_chain_valid), 95) {
        l.push(Line::Text(chunk));
    }
    if data.audit_entries.is_empty() {
        l.push(Line::Text("None recorded".into()));
    } else {
        if let Some(note) = truncation_note(data.audit_entries.len(), data.audit_entries_total) {
            l.push(Line::Text(note));
        }
        for a in &data.audit_entries {
            l.push(Line::Field(
                a.timestamp.clone(),
                format!("{} | {} | {}", a.user, a.action, a.resource_type),
            ));
        }
    }
    l.push(Line::Gap);

    // Processing Log (tool provenance)
    if !data.processing_log.is_empty() {
        l.push(Line::Heading("Processing Log".into()));
        if let Some(note) = truncation_note(data.processing_log.len(), data.processing_log_total) {
            l.push(Line::Text(note));
        }
        for p in &data.processing_log {
            let dur = p
                .duration_ms
                .map(|d| format!("{} ms", d))
                .unwrap_or_else(|| dash.clone());
            let runs = if p.runs > 0 {
                format!("{} run(s)", p.runs)
            } else {
                dash.clone()
            };
            l.push(Line::Field(
                p.module_id.clone(),
                format!(
                    "{} | {} | {} artifacts | {}",
                    p.status, runs, p.artifacts_produced, dur
                ),
            ));
            if let Some(err) = &p.error_message {
                if !err.is_empty() {
                    l.push(Line::Mono(format!("error: {}", err)));
                }
            }
        }
        l.push(Line::Gap);
    }

    // Methodology
    // What the findings rest on, then the glossary, then the declaration that
    // attests to everything above it.
    if !data.method_qualifications.is_empty() {
        l.push(Line::Heading(
            "Limitations and Qualifications of the Examination".into(),
        ));
        for chunk in wrap_text(
            "The findings above were produced by the methods described below. Each entry states \
             a respect in which the method qualifies what may be concluded.",
            95,
        ) {
            l.push(Line::Text(chunk));
        }
        for entry in &data.method_qualifications {
            l.push(Line::Gap);
            l.push(Line::Field("Subject:".into(), entry.subject.clone()));
            for chunk in wrap_text(&entry.statement, 95) {
                l.push(Line::Text(chunk));
            }
            for chunk in wrap_text(&format!("Bears on: {}", qualification_scope(entry)), 95) {
                l.push(Line::Text(chunk));
            }
        }
        l.push(Line::Gap);
    }

    if !data.glossary.is_empty() {
        l.push(Line::Heading("Glossary".into()));
        for entry in &data.glossary {
            for chunk in wrap_text(&format!("{} — {}", entry.term, entry.definition), 95) {
                l.push(Line::Text(chunk));
            }
        }
        l.push(Line::Gap);
    }

    l.push(Line::Heading("Declaration".into()));
    for chunk in wrap_text(statement_of_truth(data), 95) {
        l.push(Line::Text(chunk));
    }
    l.push(Line::Gap);
    let signatory = data
        .examiner_details
        .as_ref()
        .filter(|d| !d.name.is_empty())
        .map(|d| d.name.clone())
        .unwrap_or_else(|| data.examiner.clone());
    l.push(Line::Field("Signed:".into(), signatory));
    if let Some(details) = &data.examiner_details {
        if let Some(role) = &details.role {
            l.push(Line::Field("Role:".into(), role.clone()));
        }
        if let Some(org) = &details.organisation {
            l.push(Line::Field("Organisation:".into(), org.clone()));
        }
    }
    l.push(Line::Field("Date:".into(), data.generated_at.clone()));
    l.push(Line::Gap);

    l.push(Line::Heading("Methodology & Notes".into()));
    l.push(Line::Text(
        "Acquisition hashes computed at ingest over each evidence source.".into(),
    ));
    // Was "Audit log is a SHA-256 hash-chained, tamper-evident record." — the
    // adjective is only earned by a keyed chain (HUNT-011).
    l.push(Line::Text(format!(
        "Audit log is a hash-chained record ({}).",
        audit_chain_construction(
            data.audit_chain_tamper_evident,
            data.audit_chain_tamper_evident_from
        )
    )));
    for chunk in wrap_text(
        &audit_chain_keying_disclosure(
            data.audit_chain_tamper_evident,
            data.audit_chain_tamper_evident_from,
            data.audit_chain_key_configured,
        ),
        95,
    ) {
        l.push(Line::Text(chunk));
    }
    for chunk in wrap_text(
        "Result Completeness reports flags the parsers recorded. Where a section carries an INCOMPLETE notice its records are a subset, and the absence of an item from that listing is not evidence it was absent from the evidence.",
        95,
    ) {
        l.push(Line::Text(chunk));
    }
    l.push(Line::Text(format!(
        "Generated by {} {} at {}.",
        data.tool_name, data.tool_version, data.generated_at
    )));

    l
}

/// Strip characters the WinAnsi builtin fonts cannot encode, so `use_text`
/// never emits control bytes. Keeps printable ASCII and common Latin-1.
fn pdf_safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if (c as u32) < 0x20 {
                // control chars (incl. \n, \t) -> space
                ' '
            } else if (c as u32) > 0xFF {
                '?'
            } else {
                c
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// RTF rendering
// ---------------------------------------------------------------------------
//
// Same input, same set of sections as `render_html`, in the same order. RTF
// has no equivalent of an HTML `<table>`, so a table becomes a bold header
// line followed by one paragraph per row with cells separated by "  |  ";
// that keeps every renderer's group-brace bookkeeping trivial (a table adds
// no `{`/`}` of its own) rather than trading a small layout win for a much
// larger chance of an unbalanced group in a document meant to open cleanly in
// a court's copy of Word.

/// Escape `s` for literal inclusion in the body of an RTF document.
///
/// RTF reserves three ASCII bytes as control syntax: backslash introduces a
/// control word, and `{`/`}` delimit groups. Any of the three appearing in
/// case data (an examiner's name, a file path, a carved filename) must not be
/// allowed to inject RTF structure into a document meant to be read as
/// court-facing prose -- the same class of failure as an unescaped `<` in the
/// HTML renderer, and worse here: a stray unescaped brace desynchronises
/// every group boundary that follows it, corrupting the rest of the document
/// rather than one field of it.
///
/// Non-ASCII text is emitted as `\uN?` escapes, per the Unicode RTF extension
/// (Rich Text Format Specification, version 1.9.1, section 2.1 "Unicode
/// RTF"): `N` is the UTF-16 code unit as a SIGNED 16-bit decimal integer --
/// values from 0x8000 upward are written as their negative two's-complement
/// form, i.e. `unit as i32 - 65536` -- and each `\uN` is followed by exactly
/// one ASCII fallback character for readers with no Unicode support, which is
/// what `\uc1` in the document header declares. A character outside the
/// Basic Multilingual Plane has no single RTF escape; it is written as its
/// two UTF-16 surrogate units, each with its own `\uN?`.
fn rtf_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut units = [0u16; 2];
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '{' => out.push_str("\\{"),
            '}' => out.push_str("\\}"),
            '\n' => out.push_str("\\par\n"),
            '\r' => {}
            '\t' => out.push_str("\\tab "),
            c if (c as u32) < 0x80 => out.push(c),
            c => {
                for unit in c.encode_utf16(&mut units) {
                    let v = *unit as i32;
                    let signed = if v > 32767 { v - 65536 } else { v };
                    out.push_str(&format!("\\u{signed}?"));
                }
            }
        }
    }
    out
}

/// A plain-text placeholder for a possibly-absent value, escaped later at the
/// point it is emitted (mirrors `esc_opt`, but RTF has no HTML entity, so the
/// placeholder is a literal em dash character run through `rtf_escape` like
/// any other text).
fn rtf_opt(s: &Option<String>) -> String {
    match s {
        Some(v) if !v.is_empty() => v.clone(),
        _ => "\u{2014}".to_string(),
    }
}

fn rtf_par(text: &str) -> String {
    format!("{}\\par\n", rtf_escape(text))
}

fn rtf_bold_par(text: &str) -> String {
    format!("\\b {}\\b0\\par\n", rtf_escape(text))
}

fn rtf_italic_par(text: &str) -> String {
    format!("\\i {}\\i0\\par\n", rtf_escape(text))
}

fn rtf_heading(text: &str) -> String {
    format!("\\par\\b\\fs28 {}\\b0\\fs22\\par\n", rtf_escape(text))
}

fn rtf_subheading(text: &str) -> String {
    format!("\\b\\fs24 {}\\b0\\fs22\\par\n", rtf_escape(text))
}

fn rtf_field(label: &str, value: &str) -> String {
    format!(
        "\\b {}:\\b0  {}\\par\n",
        rtf_escape(label),
        rtf_escape(value)
    )
}

/// A table as a bold header line followed by one row per line, cells
/// separated by "  |  ". `rtf_escape` runs over the whole joined line, which
/// is safe: the separator carries no character `rtf_escape` treats specially.
fn rtf_table(headers: &[String], rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return rtf_italic_par("None recorded");
    }
    let mut out = String::new();
    out.push_str(&rtf_bold_par(&headers.join("  |  ")));
    for row in rows {
        out.push_str(&rtf_par(&row.join("  |  ")));
    }
    out
}

/// RTF form of `incompleteness_reason_rows_html`: same two axes, same
/// per-axis "no reason was recorded" fallback, as paragraphs rather than an
/// HTML table.
fn rtf_incompleteness_reason_rows(inc: &IncompletenessSummary) -> String {
    fn add(out: &mut String, scope: &str, reasons: &[IncompletenessReason], count: i64) {
        if count <= 0 {
            return;
        }
        if reasons.is_empty() {
            out.push_str(&rtf_par(&format!(
                "{scope}: no reason was recorded ({count} artifact(s))"
            )));
            return;
        }
        for r in reasons {
            out.push_str(&rtf_par(&format!("{scope}: {} ({})", r.text(), r.count)));
        }
    }
    let mut out = String::new();
    add(
        &mut out,
        "Content not read in full",
        &inc.reasons,
        inc.content_incomplete,
    );
    add(
        &mut out,
        "Listing shorter than the container",
        &inc.inventory_reasons,
        inc.inventory_incomplete,
    );
    out
}

/// Render the same report content as a Rich Text Format document.
///
/// Every section `render_html` renders unconditionally (Evidence Sources,
/// Result Completeness, Artifact Statistics, Findings/Bookmarks, Timeline
/// Highlights, Chain of Custody & Audit, Declaration, the methodology
/// footer) is rendered unconditionally here too, with the same "None
/// recorded" fallback text. Every section `render_html` omits entirely when
/// its data is empty (Evidence Integrity, Notable/Known-Good Hash Matches,
/// Values Traced Across the Evidence, Investigative Leads, Geolocation, the
/// full Timeline, Processing Log, Limitations and Qualifications, Glossary,
/// Executive Summary, File Overview) is omitted here under the identical
/// condition, so a reader comparing the two documents finds the same
/// sections in the same order, never a silently thinner RTF.
pub fn render_rtf(data: &ReportData) -> String {
    render_rtf_with(data, &ReportExtras::default())
}

/// Render the RTF report with the data [`ReportData`] cannot carry.
///
/// RTF carries no figure. Where the HTML, PDF and DOCX draw one, this
/// renders the figure's own data — the histogram's buckets, the network's
/// participants and links — as tables under the same caption, so the
/// numbers a reader of the other formats sees in a picture are here in
/// full.
pub fn render_rtf_with(data: &ReportData, extras: &ReportExtras) -> String {
    let mut r = String::with_capacity(16384);
    let mut figure_no = 0usize;

    // Header: one open group for the whole document (`{\rtf1`), one nested
    // group for the font table that opens and closes within this literal
    // (`{\fonttbl{...}}`). No other group is opened anywhere in this
    // function; the only closing brace still owed by the time the body is
    // built is the outer one, pushed at the very end.
    r.push_str(
        "{\\rtf1\\ansi\\ansicpg1252\\uc1\\deff0\n\
         {\\fonttbl{\\f0\\fswiss\\fcharset0 Helvetica;}}\n\
         \\deflang1033\\f0\\fs22\n",
    );

    // ---- Title / meta ----
    r.push_str(&format!(
        "\\b\\fs32 Forensic Analysis Report: {}\\b0\\fs22\\par\\par\n",
        rtf_escape(&data.case_name)
    ));
    r.push_str(&rtf_field("Case Name", &data.case_name));
    r.push_str(&rtf_field("Case Reference", &rtf_opt(&data.case_reference)));
    r.push_str(&rtf_field("Examiner", &data.examiner));
    r.push_str(&rtf_field("Report Generated", &data.generated_at));
    r.push_str(&rtf_field(
        "Tool",
        &format!("{} {}", data.tool_name, data.tool_version),
    ));
    if let Some(identity) = &data.report_identity {
        if !identity.report_id.is_empty() {
            r.push_str(&rtf_field("Report Reference", &identity.report_id));
        }
        if let Some(revision) = identity.revision {
            r.push_str(&rtf_field("Revision", &revision.to_string()));
        }
        if let Some(classification) = &identity.classification {
            r.push_str(&rtf_field("Handling", classification));
        }
    }
    if let Some(details) = &data.examiner_details {
        if let Some(role) = &details.role {
            r.push_str(&rtf_field("Role", role));
        }
        if let Some(org) = &details.organisation {
            r.push_str(&rtf_field("Organisation", org));
        }
        if let Some(quals) = &details.qualifications {
            r.push_str(&rtf_field("Qualifications", quals));
        }
        if let Some(contact) = &details.contact {
            r.push_str(&rtf_field("Contact", contact));
        }
    }

    // ---- How times are expressed ----
    r.push_str(&rtf_heading("Times"));
    r.push_str(&rtf_par(TIMEZONE_STATEMENT));

    // ---- Executive Summary ----
    if let Some(summary) = &data.executive_summary {
        if !summary.is_empty() {
            r.push_str(&rtf_heading("Executive Summary"));
            r.push_str(&rtf_par(summary));
        }
    }

    // ---- File Overview ----
    if let Some(ov) = &data.file_overview {
        r.push_str(&rtf_heading("File Overview"));
        r.push_str(&rtf_par(&format!("Total Files: {}", ov.total_files)));
        r.push_str(&rtf_par(&format!("Directories: {}", ov.directories)));
        r.push_str(&rtf_par(&format!("Deleted: {}", ov.deleted_files)));
        r.push_str(&rtf_par(&format!(
            "Carved: {}",
            ov.carved_files
                .map(|v| v.to_string())
                .unwrap_or_else(|| "\u{2014}".to_string())
        )));
        r.push_str(&rtf_par(&format!(
            "Encrypted: {}",
            ov.encrypted_files
                .map(|v| v.to_string())
                .unwrap_or_else(|| "\u{2014}".to_string())
        )));
        r.push_str(&rtf_par(&format!(
            "Known-Good Filtered: {}",
            ov.known_good_filtered
        )));
        r.push_str(&rtf_par(&format!("Notable Alerts: {}", ov.notable_alerts)));
        if ov.carved_files.is_none() || ov.encrypted_files.is_none() {
            r.push_str(&rtf_italic_par(
                "Counts shown as \u{2014} were not determined for this report and must not be read as zero.",
            ));
        }
    }

    // ---- Result Completeness ----
    r.push_str(&rtf_heading("Result Completeness"));
    {
        let (severity, text) = completeness_statement(data.incompleteness.as_ref());
        r.push_str(&rtf_bold_par(&format!(
            "[{}] {}",
            severity.to_uppercase(),
            text
        )));
    }
    if let Some(inc) = &data.incompleteness {
        if inc.any() {
            if let Some(note) = reason_truncation_note(inc.reasons.len(), inc.distinct_reasons) {
                r.push_str(&rtf_par(&format!(
                    "Content not read in full \u{2014} {}",
                    note
                )));
            }
            if let Some(note) =
                reason_truncation_note(inc.inventory_reasons.len(), inc.distinct_inventory_reasons)
            {
                r.push_str(&rtf_par(&format!(
                    "Listing shorter than the container \u{2014} {}",
                    note
                )));
            }
            r.push_str(&rtf_incompleteness_reason_rows(inc));
        }
    }

    // ---- Evidence Sources ----
    r.push_str(&rtf_heading("Evidence Sources"));
    if data.evidence_sources.is_empty() {
        r.push_str(&rtf_italic_par("None recorded"));
    } else {
        let headers: Vec<String> = ["Name", "Type", "Size", "MD5", "SHA1", "SHA256", "Acquired"]
            .into_iter()
            .map(String::from)
            .collect();
        let rows: Vec<Vec<String>> = data
            .evidence_sources
            .iter()
            .map(|s| {
                vec![
                    s.name.clone(),
                    s.source_type.clone(),
                    s.size_bytes
                        .map(human_size)
                        .unwrap_or_else(|| "\u{2014}".to_string()),
                    rtf_opt(&s.md5),
                    rtf_opt(&s.sha1),
                    rtf_opt(&s.sha256),
                    rtf_opt(&s.acquired_at),
                ]
            })
            .collect();
        r.push_str(&rtf_table(&headers, &rows));
    }

    // ---- Evidence Integrity ----
    if !data.integrity_checks.is_empty() {
        r.push_str(&rtf_heading("Evidence Integrity"));
        let (severity, text) = integrity_statement(&data.integrity_checks);
        r.push_str(&rtf_bold_par(&format!(
            "[{}] {}",
            severity.to_uppercase(),
            text
        )));
        let headers: Vec<String> = [
            "Source",
            "Algorithm",
            "Acquisition Hash",
            "Recomputed Hash",
            "Result",
            "Meaning",
            "Recorded",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let rows: Vec<Vec<String>> = data
            .integrity_checks
            .iter()
            .map(|c| {
                vec![
                    c.source_name.clone(),
                    c.algorithm.clone(),
                    rtf_opt(&c.acquisition_hash),
                    rtf_opt(&c.recomputed_hash),
                    c.outcome.label().to_string(),
                    c.outcome.description().to_string(),
                    rtf_opt(&c.checked_at),
                ]
            })
            .collect();
        r.push_str(&rtf_table(&headers, &rows));
    }

    // ---- Artifact Statistics ----
    r.push_str(&rtf_heading("Artifact Statistics"));
    if data.artifact_counts.is_empty() && data.total_artifacts == 0 {
        r.push_str(&rtf_italic_par("None recorded"));
    } else {
        let headers: Vec<String> = ["Artifact Type", "Count"]
            .into_iter()
            .map(String::from)
            .collect();
        let mut rows: Vec<Vec<String>> = data
            .artifact_counts
            .iter()
            .map(|(ty, count)| vec![ty.clone(), count.to_string()])
            .collect();
        rows.push(vec!["Total".to_string(), data.total_artifacts.to_string()]);
        r.push_str(&rtf_table(&headers, &rows));
    }

    // ---- Per-category artifact detail sections ----
    for section in &data.category_sections {
        r.push_str(&rtf_heading(&section.title));
        if section.total > section.rows.len() as i64 {
            r.push_str(&rtf_par(&format!(
                "Showing {} of {} records.",
                section.rows.len(),
                section.total
            )));
        }
        if let Some(note) = section_incompleteness_note(section) {
            r.push_str(&rtf_bold_par(&note));
        }
        if section.rows.is_empty() {
            r.push_str(&rtf_italic_par(&empty_section_note(section)));
        } else {
            r.push_str(&rtf_table(&section.columns, &section.rows));
        }
    }

    // ---- Notable Hash Matches ----
    if !data.notable_hash_hits.is_empty() {
        r.push_str(&rtf_heading("Notable Hash Matches"));
        if let Some(note) = truncation_note(data.notable_hash_hits.len(), data.notable_hash_total) {
            r.push_str(&rtf_par(&note));
        }
        let headers: Vec<String> = ["Artifact", "Path", "Hash Set", "Algorithm", "Matched Hash"]
            .into_iter()
            .map(String::from)
            .collect();
        let rows: Vec<Vec<String>> = data
            .notable_hash_hits
            .iter()
            .map(|h| {
                vec![
                    h.artifact_name.clone(),
                    rtf_opt(&h.path),
                    h.hash_set_name.clone(),
                    h.algorithm.clone(),
                    h.matched_hash.clone(),
                ]
            })
            .collect();
        r.push_str(&rtf_table(&headers, &rows));
    }

    // ---- Known-Good (KFF) Hash Matches ----
    if !data.known_good_hash_hits.is_empty() {
        r.push_str(&rtf_heading("Known-Good (KFF) Hash Matches"));
        r.push_str(&rtf_par(
            "Files matching a known-good hash set (safe to exclude from manual review).",
        ));
        if let Some(note) =
            truncation_note(data.known_good_hash_hits.len(), data.known_good_hash_total)
        {
            r.push_str(&rtf_par(&note));
        }
        let headers: Vec<String> = ["Artifact", "Path", "Hash Set", "Algorithm", "Matched Hash"]
            .into_iter()
            .map(String::from)
            .collect();
        let rows: Vec<Vec<String>> = data
            .known_good_hash_hits
            .iter()
            .map(|h| {
                vec![
                    h.artifact_name.clone(),
                    rtf_opt(&h.path),
                    h.hash_set_name.clone(),
                    h.algorithm.clone(),
                    h.matched_hash.clone(),
                ]
            })
            .collect();
        r.push_str(&rtf_table(&headers, &rows));
    }

    // ---- Findings / Bookmarks ----
    r.push_str(&rtf_heading("Findings / Bookmarks"));
    if let Some(note) = personal_bookmarks_excluded_note(data.personal_bookmarks_excluded) {
        r.push_str(&rtf_italic_par(&note));
    }
    if data.bookmarks.is_empty() {
        r.push_str(&rtf_italic_par("None recorded"));
    } else {
        let headers: Vec<String> = [
            "Category",
            "Artifact",
            "Source location",
            "Note",
            "Examiner",
            "Created",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let rows: Vec<Vec<String>> = data
            .bookmarks
            .iter()
            .map(|b| {
                let location = match (&b.source_path, b.source_offset) {
                    (Some(p), Some(off)) => format!("{} @ byte {}", p, off),
                    (Some(p), None) => p.clone(),
                    (None, Some(off)) => format!("byte {off}"),
                    (None, None) => "\u{2014}".to_string(),
                };
                vec![
                    rtf_opt(&b.category),
                    b.artifact_name.clone(),
                    location,
                    rtf_opt(&b.note),
                    rtf_opt(&b.examiner),
                    b.created_at.clone(),
                ]
            })
            .collect();
        r.push_str(&rtf_table(&headers, &rows));
    }

    // ---- Communications Network ----
    r.push_str(&rtf_heading("Communications Network"));
    match &extras.communications {
        None => r.push_str(&rtf_italic_par(COMMUNICATIONS_NOT_COMPUTED)),
        Some(graph) if graph.nodes.is_empty() => {
            r.push_str(&rtf_italic_par(&communications_empty_statement(graph)))
        }
        Some(graph) => {
            if let Some(note) = communications_truncation_note(graph) {
                r.push_str(&rtf_bold_par(&note));
            }
            if let Some(fig) = crate::figures::comms_figure(graph) {
                figure_no += 1;
                r.push_str(&rtf_par(&format!(
                    "Figure {figure_no} (data; this format carries no drawing). {}",
                    fig.caption()
                )));
            }
            r.push_str(&rtf_subheading("Participants"));
            let cols: Vec<String> = COMMUNICATION_PARTICIPANT_COLUMNS
                .iter()
                .map(|c| c.to_string())
                .collect();
            r.push_str(&rtf_table(&cols, &communication_participant_rows(graph)));
            r.push_str(&rtf_subheading("Links"));
            let (rows, note) = communication_link_rows(graph);
            if let Some(note) = note {
                r.push_str(&rtf_par(&note));
            }
            let cols: Vec<String> = COMMUNICATION_LINK_COLUMNS
                .iter()
                .map(|c| c.to_string())
                .collect();
            r.push_str(&rtf_table(&cols, &rows));
        }
    }

    // ---- Feature Histograms ----
    r.push_str(&rtf_heading("Feature Histograms"));
    match &extras.feature_histograms {
        None => r.push_str(&rtf_italic_par(&feature_histograms_not_gathered_text(
            extras,
        ))),
        Some(hists) if hists.is_empty() => {
            r.push_str(&rtf_italic_par(FEATURE_HISTOGRAMS_NONE_FOUND))
        }
        Some(hists) => {
            r.push_str(&rtf_par(FEATURE_HISTOGRAMS_INTRO));
            let kind_cols: Vec<String> =
                FEATURE_KIND_COLUMNS.iter().map(|c| c.to_string()).collect();
            let value_cols: Vec<String> = FEATURE_VALUE_COLUMNS
                .iter()
                .map(|c| c.to_string())
                .collect();
            for hist in hists {
                r.push_str(&rtf_subheading(&hist.source));
                for note in feature_histogram_incomplete_notes(hist) {
                    r.push_str(&rtf_bold_par(&note));
                }
                r.push_str(&rtf_par(&feature_histogram_total_line(hist)));
                r.push_str(&rtf_table(&kind_cols, &feature_kind_rows(hist)));
                r.push_str(&rtf_par(&hist.note));
                r.push_str(&rtf_bold_par(FEATURE_TOP_TITLE));
                if let Some(note) = feature_histogram_top_note(hist) {
                    r.push_str(&rtf_par(&note));
                }
                r.push_str(&rtf_table(&value_cols, &feature_value_rows(hist)));
            }
        }
    }

    // ---- Values Traced Across the Evidence ----
    if !data.traced_values.is_empty() {
        r.push_str(&rtf_heading("Values Traced Across the Evidence"));
        r.push_str(&rtf_par(
            "Each value below was traced across every parsed artifact in this case and pinned \
             by the named examiner at the time stated. The counts are of artifacts that \
             reference the value; a reference is not a relationship.",
        ));
        for t in &data.traced_values {
            r.push_str(&rtf_subheading(&t.value));
            if let Some(note) = &t.note {
                r.push_str(&rtf_italic_par(note));
            }
            r.push_str(&rtf_par(&format!(
                "Pinned by {} on {}. {} artifact(s) referenced this value at that moment.",
                t.examiner, t.pinned_at, t.matches_when_pinned
            )));
            if t.truncated_when_pinned {
                r.push_str(&rtf_bold_par(
                    "The per-kind counts below are a SAMPLE: more artifacts referenced this \
                     value than the pivot groups at once, and they do not add up to the total \
                     above.",
                ));
            }
            if !t.groups_when_pinned.is_empty() {
                let headers: Vec<String> = ["Record kind", "Artifacts"]
                    .into_iter()
                    .map(String::from)
                    .collect();
                let rows: Vec<Vec<String>> = t
                    .groups_when_pinned
                    .iter()
                    .map(|(kind, count)| vec![kind.clone(), count.to_string()])
                    .collect();
                r.push_str(&rtf_table(&headers, &rows));
            }
            match (t.matches_now, &t.recheck_unavailable_reason) {
                (Some(now), _) if now == t.matches_when_pinned => {
                    r.push_str(&rtf_par(&format!(
                        "Re-checked when this report was produced: still {now} artifact(s)."
                    )));
                }
                (Some(now), _) => {
                    r.push_str(&rtf_bold_par(&format!(
                        "Re-checked when this report was produced: {now} artifact(s) now \
                         reference this value, against {} when it was pinned. The figures above \
                         are the examiner's snapshot and this one is current.",
                        t.matches_when_pinned
                    )));
                }
                (None, Some(why)) => {
                    r.push_str(&rtf_bold_par(&format!(
                        "This value could NOT be re-checked when the report was produced: {}. \
                         The counts above are the examiner's snapshot only.",
                        why
                    )));
                }
                (None, None) => {
                    r.push_str(&rtf_bold_par(
                        "This value was not re-checked when the report was produced, and no \
                         reason was recorded. Treat the counts above as the examiner's snapshot \
                         only.",
                    ));
                }
            }
        }
    }

    // ---- Investigative Leads ----
    if !data.leads.is_empty() || !data.lead_detections.is_empty() {
        r.push_str(&rtf_heading("Investigative Leads"));
        r.push_str(&rtf_par(LEADS_PREAMBLE));
        if data.leads.is_empty() {
            r.push_str(&rtf_italic_par("No leads were raised."));
        } else {
            if data.leads_total > data.leads.len() as i64 {
                r.push_str(&rtf_bold_par(&format!(
                    "This case holds {} lead(s); the {} listed below are the most confident. \
                     The remainder are not in this report.",
                    data.leads_total,
                    data.leads.len()
                )));
            }
            for lead in &data.leads {
                r.push_str(&rtf_subheading(&format!(
                    "[{}] {}",
                    lead.confidence, lead.title
                )));
                r.push_str(&rtf_par(&format!(
                    "Observation (checkable against the evidence): {}",
                    lead.observation
                )));
                if let Some(inference) = &lead.inference {
                    r.push_str(&rtf_par(&format!(
                        "What this may indicate \u{2014} S\u{e9}ance's reading, not a fact: {}",
                        inference
                    )));
                }
                r.push_str(&rtf_par(&format!(
                    "What it does not establish: {}",
                    lead.qualification
                )));
                if !lead.evidence.is_empty() {
                    let headers: Vec<String> = ["Value", "As recorded"]
                        .into_iter()
                        .map(String::from)
                        .collect();
                    let rows: Vec<Vec<String>> = lead
                        .evidence
                        .iter()
                        .map(|(name, value)| vec![name.clone(), value.clone()])
                        .collect();
                    r.push_str(&rtf_table(&headers, &rows));
                }
                let location = match lead.device_offset {
                    Some(off) => format!("{} @ byte {}", lead.subject, off),
                    None => lead.subject.clone(),
                };
                r.push_str(&rtf_par(&format!(
                    "Subject: {location}. Raised by {}. {}",
                    lead.source_module,
                    if lead.stored_as_a_record {
                        "Recorded in the case as its own artifact."
                    } else {
                        "Computed when this report was produced; it is not stored as an \
                         artifact, so only the subject above can be re-opened."
                    }
                )));
            }
        }
        if !data.lead_detections.is_empty() {
            r.push_str(&rtf_subheading("What this build can look for"));
            let headers: Vec<String> = ["Check", "What it looks for"]
                .into_iter()
                .map(String::from)
                .collect();
            let rows: Vec<Vec<String>> = data
                .lead_detections
                .iter()
                .map(|d| vec![d.kind.clone(), d.looks_for.clone()])
                .collect();
            r.push_str(&rtf_table(&headers, &rows));
        }
    }

    // ---- Geolocation (EXIF GPS) ----
    if !data.geolocation.is_empty() || data.geolocation_truncated {
        r.push_str(&rtf_heading("Geolocation"));
        r.push_str(&rtf_par(
            "GPS points extracted from EXIF metadata. Exportable as KML/GeoJSON for mapping.",
        ));
        if data.geolocation_truncated {
            r.push_str(&rtf_bold_par(&geo_truncation_note(data.geolocation.len())));
        }
        let headers: Vec<String> = [
            "File",
            "Path",
            "Latitude",
            "Longitude",
            "Altitude",
            "Timestamp",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let rows: Vec<Vec<String>> = data
            .geolocation
            .iter()
            .map(|g| {
                vec![
                    g.label.clone(),
                    rtf_opt(&geo_path_cell(g)),
                    format!("{:.6}", g.latitude),
                    format!("{:.6}", g.longitude),
                    g.altitude
                        .map(|a| format!("{:.1} m", a))
                        .unwrap_or_else(|| "\u{2014}".to_string()),
                    rtf_opt(&g.timestamp),
                ]
            })
            .collect();
        r.push_str(&rtf_table(&headers, &rows));
    }

    // ---- Timeline Highlights ----
    r.push_str(&rtf_heading("Timeline Highlights"));
    if let Some(note) = timeline_omitted_note(data.incompleteness.as_ref()) {
        r.push_str(&rtf_par(&note));
    }
    if data.timeline_highlights.is_empty() {
        r.push_str(&rtf_italic_par("None recorded"));
    } else {
        let headers: Vec<String> = [
            "Timestamp",
            "Description",
            "Source Module",
            "Note",
            "Examiner",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let rows: Vec<Vec<String>> = data
            .timeline_highlights
            .iter()
            .map(|e| {
                vec![
                    e.timestamp.clone(),
                    e.description.clone(),
                    e.source_module.clone(),
                    rtf_opt(&e.note),
                    rtf_opt(&e.examiner),
                ]
            })
            .collect();
        r.push_str(&rtf_table(&headers, &rows));
        r.push_str(&rtf_italic_par(
            "Every event above was tagged by an examiner. The note is their own words on why \
             it matters; an em dash means they tagged the event without writing one.",
        ));
    }

    // ---- Full Timeline (bounded) ----
    if !data.full_timeline.is_empty() {
        r.push_str(&rtf_heading("Timeline"));
        if let Some(note) = timeline_omitted_note(data.incompleteness.as_ref()) {
            r.push_str(&rtf_par(&note));
        }
        r.push_str(&rtf_par(&timeline_caption(
            data.full_timeline.len(),
            data.full_timeline_total,
        )));
        match crate::figures::timeline_figure(&data.full_timeline, data.full_timeline_total) {
            Some(fig) => {
                figure_no += 1;
                r.push_str(&rtf_par(&format!(
                    "Figure {figure_no} (data; this format carries no drawing). {}",
                    fig.caption()
                )));
                let headers: Vec<String> = ["Bucket start (UTC)", "Events"]
                    .into_iter()
                    .map(String::from)
                    .collect();
                let rows: Vec<Vec<String>> = fig
                    .buckets
                    .iter()
                    .map(|b| vec![b.start.clone(), b.count.to_string()])
                    .collect();
                r.push_str(&rtf_table(&headers, &rows));
            }
            None => r.push_str(&rtf_italic_par(&timeline_figure_unavailable(
                data.full_timeline.len(),
            ))),
        }
        let headers: Vec<String> = ["Timestamp", "Description", "Source Module"]
            .into_iter()
            .map(String::from)
            .collect();
        let rows: Vec<Vec<String>> = data
            .full_timeline
            .iter()
            .map(|e| {
                vec![
                    e.timestamp.clone(),
                    e.description.clone(),
                    e.source_module.clone(),
                ]
            })
            .collect();
        r.push_str(&rtf_table(&headers, &rows));
    }

    // ---- Chain of Custody & Audit ----
    r.push_str(&rtf_heading("Chain of Custody & Audit"));
    if data.audit_chain_valid {
        r.push_str(&rtf_bold_par(&format!(
            "Audit chain verified - {} entries ({}).",
            data.audit_chain_checked,
            audit_chain_construction(
                data.audit_chain_tamper_evident,
                data.audit_chain_tamper_evident_from
            )
        )));
    } else {
        r.push_str(&rtf_bold_par(&format!(
            "AUDIT CHAIN NOT VERIFIED - hash-chain verification FAILED after checking {} \
             entries: {}. Until this is resolved, evidence-handling integrity is not attested \
             by this report.",
            data.audit_chain_checked,
            data.audit_chain_break_reason
                .as_deref()
                .unwrap_or("the verifier gave no reason")
        )));
    }
    r.push_str(&rtf_par(&audit_chain_keying_disclosure(
        data.audit_chain_tamper_evident,
        data.audit_chain_tamper_evident_from,
        data.audit_chain_key_configured,
    )));
    r.push_str(&rtf_par(audit_chain_scope_note(data.audit_chain_valid)));
    if data.audit_entries.is_empty() {
        r.push_str(&rtf_italic_par("None recorded"));
    } else {
        if let Some(note) = truncation_note(data.audit_entries.len(), data.audit_entries_total) {
            r.push_str(&rtf_par(&note));
        }
        let headers: Vec<String> = ["Timestamp", "User", "Action", "Resource Type"]
            .into_iter()
            .map(String::from)
            .collect();
        let rows: Vec<Vec<String>> = data
            .audit_entries
            .iter()
            .map(|a| {
                vec![
                    a.timestamp.clone(),
                    a.user.clone(),
                    a.action.clone(),
                    a.resource_type.clone(),
                ]
            })
            .collect();
        r.push_str(&rtf_table(&headers, &rows));
    }

    // ---- Processing Log ----
    if !data.processing_log.is_empty() {
        r.push_str(&rtf_heading("Processing Log"));
        r.push_str(&rtf_par(
            "Module execution provenance: which parser produced what, and how long it took. \
             Each row aggregates every run of that module in this case.",
        ));
        if let Some(note) = truncation_note(data.processing_log.len(), data.processing_log_total) {
            r.push_str(&rtf_par(&note));
        }
        let headers: Vec<String> = ["Module", "Status", "Runs", "Artifacts", "Duration", "Error"]
            .into_iter()
            .map(String::from)
            .collect();
        let rows: Vec<Vec<String>> = data
            .processing_log
            .iter()
            .map(|p| {
                vec![
                    p.module_id.clone(),
                    p.status.clone(),
                    if p.runs > 0 {
                        p.runs.to_string()
                    } else {
                        "\u{2014}".to_string()
                    },
                    p.artifacts_produced.to_string(),
                    p.duration_ms
                        .map(|d| format!("{d} ms"))
                        .unwrap_or_else(|| "\u{2014}".to_string()),
                    rtf_opt(&p.error_message),
                ]
            })
            .collect();
        r.push_str(&rtf_table(&headers, &rows));
    }

    // ---- Limitations and qualifications ----
    if !data.method_qualifications.is_empty() {
        r.push_str(&rtf_heading(
            "Limitations and Qualifications of the Examination",
        ));
        r.push_str(&rtf_par(
            "The findings above were produced by the methods described below. Each entry \
             states a respect in which the method qualifies what may be concluded.",
        ));
        for entry in &data.method_qualifications {
            r.push_str(&rtf_subheading(&entry.subject));
            r.push_str(&rtf_par(&entry.statement));
            r.push_str(&rtf_italic_par(&format!(
                "Bears on: {}",
                qualification_scope(entry)
            )));
        }
    }

    // ---- Glossary ----
    if !data.glossary.is_empty() {
        r.push_str(&rtf_heading("Glossary"));
        for entry in &data.glossary {
            r.push_str(&rtf_bold_par(&entry.term));
            r.push_str(&rtf_par(&entry.definition));
        }
    }

    // ---- Declaration ----
    r.push_str(&rtf_heading("Declaration"));
    r.push_str(&rtf_par(statement_of_truth(data)));
    let signatory = data
        .examiner_details
        .as_ref()
        .filter(|d| !d.name.is_empty())
        .map(|d| d.name.clone())
        .unwrap_or_else(|| data.examiner.clone());
    r.push_str(&rtf_bold_par(&signatory));
    if let Some(details) = &data.examiner_details {
        if let Some(role) = &details.role {
            r.push_str(&rtf_par(role));
        }
        if let Some(org) = &details.organisation {
            r.push_str(&rtf_par(org));
        }
    }
    r.push_str(&rtf_par(&data.generated_at));

    // ---- Methodology / Notes footer ----
    r.push_str(&rtf_heading("Methodology & Notes"));
    r.push_str(&rtf_par(
        "Acquisition hashes (MD5/SHA1/SHA256) shown above were computed at ingest over each \
         evidence source and recorded before analysis.",
    ));
    r.push_str(&rtf_par(
        "In the Evidence Integrity section, BASELINE means a hash was recorded at acquisition \
         and has not since been recomputed and compared. It is neither a pass nor a failure: \
         only MATCH and MISMATCH state the result of a re-verification.",
    ));
    r.push_str(&rtf_par(&format!(
        "The audit log is a hash-chained record; each entry commits to its predecessor. The \
         verification banner above reflects a full re-computation of that chain. {}",
        audit_chain_keying_disclosure(
            data.audit_chain_tamper_evident,
            data.audit_chain_tamper_evident_from,
            data.audit_chain_key_configured,
        )
    )));
    r.push_str(&rtf_par(
        "Result Completeness reports flags the parsers themselves recorded: a parser that \
         could not read or decode its input in full marks the artifact it produced, and a \
         listing shorter than what the container holds is marked separately. Where a section \
         carries an INCOMPLETE notice, its records are a subset and the absence of an item \
         from that listing is not evidence that the item was absent from the evidence.",
    ));
    r.push_str(&rtf_par(&format!(
        "Report generated by {} {} at {}. All findings should be independently verified \
         against source evidence.",
        data.tool_name, data.tool_version, data.generated_at
    )));

    r.push_str("}\n");
    r
}

// ---------------------------------------------------------------------------
// XML rendering
// ---------------------------------------------------------------------------

/// Escape `s` for inclusion as XML text or attribute content.
///
/// Escapes the five ASCII characters XML 1.0 reserves (`&`, `<`, `>`, `"`,
/// `'`) and drops the C0 control characters XML 1.0 (section 2.2, the
/// `Char` production) does not allow to appear AT ALL, tab/LF/CR excepted.
/// Those code points have no legal numeric character reference either -- an
/// XML 1.0 document cannot contain `&#x1;` any more than it can contain the
/// raw byte -- so there is no escape that keeps them: they are stripped
/// rather than passed through and left to break every downstream parser
/// this export exists to feed. Evidence text can legitimately contain such
/// bytes (a corrupted field, a carved fragment used as a bookmark note); this
/// is the one class of input that a "must not drop anything" report renderer
/// drops, because emitting it raw would not produce a document at all.
pub(crate) fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(ch),
            c if (c as u32) < 0x20 => {}
            c => out.push(c),
        }
    }
    out
}

fn xml_el(tag: &str, text: &str) -> String {
    format!("<{tag}>{}</{tag}>\n", xml_escape(text))
}

fn xml_el_i64(tag: &str, n: i64) -> String {
    format!("<{tag}>{n}</{tag}>\n")
}

fn xml_el_bool(tag: &str, b: bool) -> String {
    format!("<{tag}>{b}</{tag}>\n")
}

fn xml_el_opt(tag: &str, s: &Option<String>) -> String {
    match s {
        Some(v) => xml_el(tag, v),
        None => String::new(),
    }
}

fn xml_hash_hit(hit: &ReportHashHit) -> String {
    format!(
        "<match>\n<artifact_name>{}</artifact_name>\n{}<hash_set_name>{}</hash_set_name>\n\
         <algorithm>{}</algorithm>\n<matched_hash>{}</matched_hash>\n</match>\n",
        xml_escape(&hit.artifact_name),
        xml_el_opt("path", &hit.path),
        xml_escape(&hit.hash_set_name),
        xml_escape(&hit.algorithm),
        xml_escape(&hit.matched_hash),
    )
}

fn xml_timeline_event(e: &ReportTimelineEvent, with_annotation: bool) -> String {
    let mut s = String::from("<event>\n");
    s.push_str(&xml_el("timestamp", &e.timestamp));
    s.push_str(&xml_el("description", &e.description));
    s.push_str(&xml_el("source_module", &e.source_module));
    if with_annotation {
        s.push_str(&xml_el_opt("examiner", &e.examiner));
        s.push_str(&xml_el_opt("note", &e.note));
    }
    s.push_str("</event>\n");
    s
}

/// XML form of `incompleteness_reason_rows_html`: same two axes (content vs.
/// listing), same per-axis "no reason was recorded" fallback -- carried as an
/// explicit `recorded="false"` attribute rather than a text placeholder, since
/// a data consumer of this export should not have to string-match prose to
/// tell "no reason given" from a reason that happens to read that way.
fn xml_incompleteness_reasons(inc: &IncompletenessSummary) -> String {
    fn add(out: &mut String, scope: &str, reasons: &[IncompletenessReason], count: i64) {
        if count <= 0 {
            return;
        }
        out.push_str(&format!(
            "<shortfall scope=\"{}\" artifacts=\"{}\">\n",
            xml_escape(scope),
            count
        ));
        if reasons.is_empty() {
            out.push_str("<reason recorded=\"false\"></reason>\n");
        } else {
            for r in reasons {
                out.push_str(&format!(
                    "<reason recorded=\"true\" count=\"{}\">{}</reason>\n",
                    r.count,
                    xml_escape(r.text())
                ));
            }
        }
        out.push_str("</shortfall>\n");
    }
    let mut out = String::new();
    add(
        &mut out,
        "content_not_read_in_full",
        &inc.reasons,
        inc.content_incomplete,
    );
    add(
        &mut out,
        "listing_shorter_than_container",
        &inc.inventory_reasons,
        inc.inventory_incomplete,
    );
    out
}

/// Render the same report content as a structured XML document, for tools
/// that consume the report as data rather than as a document -- the
/// full-report analogue of the CSV/KML/GeoJSON exports, which each serve one
/// narrower slice of the same case.
///
/// Follows the same section presence/absence rules as `render_html` and
/// `render_rtf`: see the doc comment on [`render_rtf`], which states them
/// once for all three renderers rather than three times.
///
/// A hand-rolled writer, not `quick-xml`: everything this function emits is
/// produced here, under this crate's own escaping, and quick-xml's writer
/// API buys nothing over string concatenation for output-only use -- the
/// dependency earns its place in `seance_xml_util` for *reading* untrusted
/// evidence XML under a bound, which is a different problem. See this
/// crate's dev-dependency on quick-xml (test-only) for the round-trip check.
pub fn render_xml(data: &ReportData) -> String {
    render_xml_with(data, &ReportExtras::default())
}

/// Render the XML report with the data [`ReportData`] cannot carry.
///
/// The figures the document formats draw appear here as the data they were
/// computed from: `<histogram>` under `<timeline>`, and the participants and
/// links under `<communications_network>`, each with the caption's
/// disclosures as attributes so a machine reader sees the same caps.
pub fn render_xml_with(data: &ReportData, extras: &ReportExtras) -> String {
    let mut x = String::with_capacity(16384);
    x.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    x.push_str("<forensic_report>\n");

    // ---- Meta ----
    x.push_str("<meta>\n");
    x.push_str(&xml_el("case_name", &data.case_name));
    x.push_str(&xml_el_opt("case_reference", &data.case_reference));
    x.push_str(&xml_el("examiner", &data.examiner));
    x.push_str(&xml_el("generated_at", &data.generated_at));
    x.push_str(&xml_el("tool_name", &data.tool_name));
    x.push_str(&xml_el("tool_version", &data.tool_version));
    if let Some(identity) = &data.report_identity {
        x.push_str("<report_identity>\n");
        x.push_str(&xml_el("report_id", &identity.report_id));
        if let Some(revision) = identity.revision {
            x.push_str(&xml_el_i64("revision", revision as i64));
        }
        x.push_str(&xml_el_opt("classification", &identity.classification));
        x.push_str("</report_identity>\n");
    }
    if let Some(details) = &data.examiner_details {
        x.push_str("<examiner_details>\n");
        x.push_str(&xml_el("name", &details.name));
        x.push_str(&xml_el_opt("role", &details.role));
        x.push_str(&xml_el_opt("organisation", &details.organisation));
        x.push_str(&xml_el_opt("contact", &details.contact));
        x.push_str(&xml_el_opt("qualifications", &details.qualifications));
        x.push_str("</examiner_details>\n");
    }
    x.push_str("</meta>\n");

    x.push_str(&xml_el("timezone_statement", TIMEZONE_STATEMENT));

    // ---- Executive Summary ----
    if let Some(summary) = &data.executive_summary {
        if !summary.is_empty() {
            x.push_str(&xml_el("executive_summary", summary));
        }
    }

    // ---- File Overview ----
    if let Some(ov) = &data.file_overview {
        x.push_str("<file_overview>\n");
        x.push_str(&xml_el_i64("total_files", ov.total_files));
        x.push_str(&xml_el_i64("directories", ov.directories));
        x.push_str(&xml_el_i64("deleted_files", ov.deleted_files));
        if let Some(c) = ov.carved_files {
            x.push_str(&xml_el_i64("carved_files", c));
        }
        if let Some(c) = ov.encrypted_files {
            x.push_str(&xml_el_i64("encrypted_files", c));
        }
        x.push_str(&xml_el_i64("known_good_filtered", ov.known_good_filtered));
        x.push_str(&xml_el_i64("notable_alerts", ov.notable_alerts));
        // HTML and RTF both carry a sentence for this; XML is read by code,
        // not by an examiner's eye, and a tool that treats a missing element
        // as absent-equals-zero (the common default for XML-to-JSON and
        // XPath tooling) would silently report zero carved or encrypted
        // files for a count that was actually never determined. A caught-by-
        // review gap: the element was simply omitted with no equivalent.
        if ov.carved_files.is_none() || ov.encrypted_files.is_none() {
            x.push_str(&xml_el_bool("counts_not_determined", true));
        }
        x.push_str("</file_overview>\n");
    }

    // ---- Result Completeness ----
    {
        let (severity, text) = completeness_statement(data.incompleteness.as_ref());
        x.push_str("<result_completeness>\n");
        x.push_str(&format!(
            "<statement severity=\"{}\">{}</statement>\n",
            xml_escape(severity),
            xml_escape(&text)
        ));
        if let Some(inc) = &data.incompleteness {
            if inc.any() {
                x.push_str(&xml_incompleteness_reasons(inc));
            }
        }
        x.push_str("</result_completeness>\n");
    }

    // ---- Evidence Sources ----
    x.push_str("<evidence_sources>\n");
    for s in &data.evidence_sources {
        x.push_str("<source>\n");
        x.push_str(&xml_el("name", &s.name));
        x.push_str(&xml_el("source_type", &s.source_type));
        if let Some(sz) = s.size_bytes {
            x.push_str(&xml_el_i64("size_bytes", sz));
        }
        x.push_str(&xml_el_opt("md5", &s.md5));
        x.push_str(&xml_el_opt("sha1", &s.sha1));
        x.push_str(&xml_el_opt("sha256", &s.sha256));
        x.push_str(&xml_el_opt("acquired_at", &s.acquired_at));
        x.push_str("</source>\n");
    }
    x.push_str("</evidence_sources>\n");

    // ---- Evidence Integrity ----
    if !data.integrity_checks.is_empty() {
        let (severity, text) = integrity_statement(&data.integrity_checks);
        x.push_str("<evidence_integrity>\n");
        x.push_str(&format!(
            "<statement severity=\"{}\">{}</statement>\n",
            xml_escape(severity),
            xml_escape(&text)
        ));
        for c in &data.integrity_checks {
            x.push_str("<check>\n");
            x.push_str(&xml_el("source_name", &c.source_name));
            x.push_str(&xml_el("algorithm", &c.algorithm));
            x.push_str(&xml_el_opt("acquisition_hash", &c.acquisition_hash));
            x.push_str(&xml_el_opt("recomputed_hash", &c.recomputed_hash));
            x.push_str(&xml_el("outcome", c.outcome.label()));
            x.push_str(&xml_el("meaning", c.outcome.description()));
            x.push_str(&xml_el_opt("checked_at", &c.checked_at));
            x.push_str("</check>\n");
        }
        x.push_str("</evidence_integrity>\n");
    }

    // ---- Artifact Statistics ----
    x.push_str("<artifact_statistics>\n");
    for (ty, count) in &data.artifact_counts {
        x.push_str(&format!(
            "<artifact_type name=\"{}\">{}</artifact_type>\n",
            xml_escape(ty),
            count
        ));
    }
    x.push_str(&xml_el_i64("total_artifacts", data.total_artifacts));
    x.push_str("</artifact_statistics>\n");

    // ---- Per-category artifact detail sections ----
    if !data.category_sections.is_empty() {
        x.push_str("<category_sections>\n");
        for section in &data.category_sections {
            x.push_str(&format!(
                "<section title=\"{}\">\n",
                xml_escape(&section.title)
            ));
            x.push_str(&xml_el_i64("total", section.total));
            if section.rows.is_empty() {
                x.push_str(&xml_el("note", &empty_section_note(section)));
            } else {
                x.push_str("<rows>\n");
                for row in &section.rows {
                    x.push_str("<row>\n");
                    for (col, val) in section.columns.iter().zip(row.iter()) {
                        x.push_str(&format!(
                            "<field name=\"{}\">{}</field>\n",
                            xml_escape(col),
                            xml_escape(val)
                        ));
                    }
                    x.push_str("</row>\n");
                }
                x.push_str("</rows>\n");
            }
            if let Some(note) = section_incompleteness_note(section) {
                x.push_str(&xml_el("incompleteness_note", &note));
            }
            x.push_str("</section>\n");
        }
        x.push_str("</category_sections>\n");
    }

    // ---- Notable Hash Matches ----
    if !data.notable_hash_hits.is_empty() {
        x.push_str("<notable_hash_matches>\n");
        if let Some(note) = truncation_note(data.notable_hash_hits.len(), data.notable_hash_total) {
            x.push_str(&xml_el("truncation_note", &note));
        }
        for hit in &data.notable_hash_hits {
            x.push_str(&xml_hash_hit(hit));
        }
        x.push_str("</notable_hash_matches>\n");
    }

    // ---- Known-Good (KFF) Hash Matches ----
    if !data.known_good_hash_hits.is_empty() {
        x.push_str("<known_good_hash_matches>\n");
        if let Some(note) =
            truncation_note(data.known_good_hash_hits.len(), data.known_good_hash_total)
        {
            x.push_str(&xml_el("truncation_note", &note));
        }
        for hit in &data.known_good_hash_hits {
            x.push_str(&xml_hash_hit(hit));
        }
        x.push_str("</known_good_hash_matches>\n");
    }

    // ---- Findings / Bookmarks ----
    x.push_str("<findings_bookmarks>\n");
    // Always emitted, 0 included: a machine reader must be able to tell "none
    // excluded" from "this build did not say".
    x.push_str(&xml_el_i64(
        "personal_bookmarks_excluded",
        data.personal_bookmarks_excluded,
    ));
    for b in &data.bookmarks {
        x.push_str("<bookmark>\n");
        x.push_str(&xml_el_opt("category", &b.category));
        x.push_str(&xml_el("artifact_name", &b.artifact_name));
        x.push_str(&xml_el_opt("source_path", &b.source_path));
        if let Some(off) = b.source_offset {
            x.push_str(&xml_el_i64("source_offset", off));
        }
        x.push_str(&xml_el_opt("note", &b.note));
        x.push_str(&xml_el_opt("examiner", &b.examiner));
        x.push_str(&xml_el("created_at", &b.created_at));
        x.push_str("</bookmark>\n");
    }
    x.push_str("</findings_bookmarks>\n");

    // ---- Communications Network ----
    match &extras.communications {
        None => {
            x.push_str("<communications_network computed=\"false\">\n");
            x.push_str(&xml_el("statement", COMMUNICATIONS_NOT_COMPUTED));
            x.push_str("</communications_network>\n");
        }
        Some(graph) => {
            x.push_str(&format!(
                "<communications_network computed=\"true\" truncated=\"{}\" \
                 total_participants=\"{}\" unusable_email_records=\"{}\">\n",
                graph.truncated, graph.total_participants, graph.unusable_email_records
            ));
            if graph.nodes.is_empty() {
                x.push_str(&xml_el("statement", &communications_empty_statement(graph)));
            } else {
                if let Some(note) = communications_truncation_note(graph) {
                    x.push_str(&xml_el("incompleteness_note", &note));
                }
                if let Some(fig) = crate::figures::comms_figure(graph) {
                    x.push_str(&xml_el("figure_caption", &fig.caption()));
                }
                x.push_str("<participants>\n");
                let mut nodes: Vec<&ReportCommNode> = graph.nodes.iter().collect();
                nodes.sort_by(|a, b| b.weight.cmp(&a.weight).then_with(|| a.id.cmp(&b.id)));
                for node in nodes {
                    x.push_str(&format!(
                        "<participant id=\"{}\" kind=\"{}\" exchanges=\"{}\">{}</participant>\n",
                        xml_escape(&node.id),
                        xml_escape(&node.kind),
                        node.weight,
                        xml_escape(&node.label)
                    ));
                }
                x.push_str("</participants>\n");
                let mut edges: Vec<&ReportCommEdge> = graph.edges.iter().collect();
                edges.sort_by(|a, b| {
                    b.weight
                        .cmp(&a.weight)
                        .then_with(|| a.source.cmp(&b.source))
                        .then_with(|| a.target.cmp(&b.target))
                });
                x.push_str("<links>\n");
                for e in edges {
                    x.push_str(&format!(
                        "<link source=\"{}\" target=\"{}\" exchanges=\"{}\"/>\n",
                        xml_escape(&e.source),
                        xml_escape(&e.target),
                        e.weight
                    ));
                }
                x.push_str("</links>\n");
            }
            x.push_str("</communications_network>\n");
        }
    }

    // ---- Feature Histograms ----
    match &extras.feature_histograms {
        None => {
            x.push_str("<feature_histograms gathered=\"false\">\n");
            x.push_str(&xml_el("statement", FEATURE_HISTOGRAMS_NOT_GATHERED));
            if let Some(reason) = extras
                .feature_histograms_not_gathered_reason
                .as_deref()
                .filter(|r| !r.is_empty())
            {
                x.push_str(&xml_el("reason", reason));
            }
            x.push_str("</feature_histograms>\n");
        }
        Some(hists) => {
            x.push_str("<feature_histograms gathered=\"true\">\n");
            if hists.is_empty() {
                x.push_str(&xml_el("statement", FEATURE_HISTOGRAMS_NONE_FOUND));
            }
            for hist in hists {
                x.push_str(&format!(
                    "<feature_histogram source=\"{}\" total_hits=\"{}\" distinct_values=\"{}\" \
                     hits_dropped=\"{}\" capped=\"{}\" max_distinct_values=\"{}\" top_n=\"{}\" \
                     top_omitted=\"{}\" bytes_scanned=\"{}\" scan_capped=\"{}\" \
                     short_read=\"{}\" source_size=\"{}\">\n",
                    xml_escape(&hist.source),
                    hist.total_hits,
                    hist.distinct_values,
                    hist.hits_dropped,
                    hist.capped,
                    hist.max_distinct_values,
                    hist.top_n,
                    hist.top_omitted,
                    hist.bytes_scanned,
                    hist.scan_capped,
                    hist.short_read,
                    hist.source_size
                ));
                for note in feature_histogram_incomplete_notes(hist) {
                    x.push_str(&xml_el("incompleteness_note", &note));
                }
                x.push_str(&xml_el("note", &hist.note));
                x.push_str("<by_kind>\n");
                for k in &hist.by_kind {
                    x.push_str(&format!(
                        "<kind name=\"{}\" hits=\"{}\" distinct_values=\"{}\"/>\n",
                        xml_escape(&k.kind),
                        k.hits,
                        k.distinct_values
                    ));
                }
                x.push_str("</by_kind>\n");
                if let Some(note) = feature_histogram_top_note(hist) {
                    x.push_str(&xml_el("top_note", &note));
                }
                x.push_str("<top>\n");
                for v in &hist.top {
                    x.push_str(&format!(
                        "<value kind=\"{}\" count=\"{}\">{}</value>\n",
                        xml_escape(&v.kind),
                        v.count,
                        xml_escape(&v.value)
                    ));
                }
                x.push_str("</top>\n");
                x.push_str("</feature_histogram>\n");
            }
            x.push_str("</feature_histograms>\n");
        }
    }

    // ---- Values Traced Across the Evidence ----
    if !data.traced_values.is_empty() {
        x.push_str("<traced_values>\n");
        for t in &data.traced_values {
            x.push_str("<traced_value>\n");
            x.push_str(&xml_el("value", &t.value));
            x.push_str(&xml_el_opt("note", &t.note));
            x.push_str(&xml_el("examiner", &t.examiner));
            x.push_str(&xml_el("pinned_at", &t.pinned_at));
            x.push_str(&xml_el_i64("matches_when_pinned", t.matches_when_pinned));
            x.push_str(&xml_el_bool(
                "truncated_when_pinned",
                t.truncated_when_pinned,
            ));
            if !t.groups_when_pinned.is_empty() {
                x.push_str("<groups_when_pinned>\n");
                for (kind, count) in &t.groups_when_pinned {
                    x.push_str(&format!(
                        "<group kind=\"{}\">{}</group>\n",
                        xml_escape(kind),
                        count
                    ));
                }
                x.push_str("</groups_when_pinned>\n");
            }
            if let Some(now) = t.matches_now {
                x.push_str(&xml_el_i64("matches_now", now));
            }
            x.push_str(&xml_el_opt(
                "recheck_unavailable_reason",
                &t.recheck_unavailable_reason,
            ));
            x.push_str("</traced_value>\n");
        }
        x.push_str("</traced_values>\n");
    }

    // ---- Investigative Leads ----
    if !data.leads.is_empty() || !data.lead_detections.is_empty() {
        x.push_str("<investigative_leads>\n");
        x.push_str(&xml_el("preamble", LEADS_PREAMBLE));
        x.push_str(&xml_el_i64("leads_total", data.leads_total));
        for lead in &data.leads {
            x.push_str("<lead>\n");
            x.push_str(&xml_el("title", &lead.title));
            x.push_str(&xml_el("kind", &lead.kind));
            x.push_str(&xml_el("confidence", &lead.confidence));
            x.push_str(&xml_el("observation", &lead.observation));
            x.push_str(&xml_el_opt("inference", &lead.inference));
            x.push_str(&xml_el("qualification", &lead.qualification));
            if !lead.evidence.is_empty() {
                x.push_str("<evidence>\n");
                for (name, value) in &lead.evidence {
                    x.push_str(&format!(
                        "<item name=\"{}\">{}</item>\n",
                        xml_escape(name),
                        xml_escape(value)
                    ));
                }
                x.push_str("</evidence>\n");
            }
            x.push_str(&xml_el("subject", &lead.subject));
            if let Some(off) = lead.device_offset {
                x.push_str(&format!("<device_offset>{}</device_offset>\n", off));
            }
            x.push_str(&xml_el("source_module", &lead.source_module));
            x.push_str(&xml_el_bool("stored_as_a_record", lead.stored_as_a_record));
            x.push_str("</lead>\n");
        }
        if !data.lead_detections.is_empty() {
            x.push_str("<lead_detections>\n");
            for d in &data.lead_detections {
                x.push_str(&format!(
                    "<detection kind=\"{}\">{}</detection>\n",
                    xml_escape(&d.kind),
                    xml_escape(&d.looks_for)
                ));
            }
            x.push_str("</lead_detections>\n");
        }
        x.push_str("</investigative_leads>\n");
    }

    // ---- Geolocation (EXIF GPS) ----
    if !data.geolocation.is_empty() || data.geolocation_truncated {
        x.push_str("<geolocation>\n");
        if data.geolocation_truncated {
            x.push_str(&xml_el(
                "truncation_note",
                &geo_truncation_note(data.geolocation.len()),
            ));
        }
        for g in &data.geolocation {
            x.push_str("<point>\n");
            x.push_str(&xml_el("label", &g.label));
            x.push_str(&xml_el_opt("path", &geo_path_cell(g)));
            x.push_str(&format!("<latitude>{}</latitude>\n", g.latitude));
            x.push_str(&format!("<longitude>{}</longitude>\n", g.longitude));
            if let Some(a) = g.altitude {
                x.push_str(&format!("<altitude>{}</altitude>\n", a));
            }
            x.push_str(&xml_el_opt("timestamp", &g.timestamp));
            x.push_str("</point>\n");
        }
        x.push_str("</geolocation>\n");
    }

    // ---- Timeline Highlights ----
    if let Some(note) = timeline_omitted_note(data.incompleteness.as_ref()) {
        x.push_str(&xml_el("timeline_omitted_note", &note));
    }
    x.push_str("<timeline_highlights>\n");
    for e in &data.timeline_highlights {
        x.push_str(&xml_timeline_event(e, true));
    }
    x.push_str("</timeline_highlights>\n");

    // ---- Full Timeline (bounded) ----
    if !data.full_timeline.is_empty() {
        x.push_str(&format!(
            "<timeline total=\"{}\">\n",
            data.full_timeline_total
        ));
        match crate::figures::timeline_figure(&data.full_timeline, data.full_timeline_total) {
            Some(fig) => {
                x.push_str(&format!(
                    "<histogram bucket_seconds=\"{}\" bucket_label=\"{}\" plotted=\"{}\" \
                     unparseable=\"{}\" listed=\"{}\" case_total=\"{}\">\n",
                    fig.bucket_seconds,
                    xml_escape(&fig.bucket_label),
                    fig.plotted,
                    fig.unparseable,
                    fig.listed,
                    fig.case_total
                ));
                x.push_str(&xml_el("caption", &fig.caption()));
                for b in &fig.buckets {
                    x.push_str(&format!(
                        "<bucket start=\"{}\" count=\"{}\"/>\n",
                        xml_escape(&b.start),
                        b.count
                    ));
                }
                x.push_str("</histogram>\n");
            }
            None => x.push_str(&xml_el(
                "histogram_unavailable",
                &timeline_figure_unavailable(data.full_timeline.len()),
            )),
        }
        for e in &data.full_timeline {
            x.push_str(&xml_timeline_event(e, false));
        }
        x.push_str("</timeline>\n");
    }

    // ---- Chain of Custody & Audit ----
    x.push_str("<chain_of_custody>\n");
    x.push_str(&xml_el_bool("audit_chain_valid", data.audit_chain_valid));
    x.push_str(&xml_el_i64("audit_chain_checked", data.audit_chain_checked));
    x.push_str(&xml_el_opt("break_reason", &data.audit_chain_break_reason));
    x.push_str(&xml_el(
        "keying_disclosure",
        &audit_chain_keying_disclosure(
            data.audit_chain_tamper_evident,
            data.audit_chain_tamper_evident_from,
            data.audit_chain_key_configured,
        ),
    ));
    x.push_str(&xml_el(
        "scope_note",
        audit_chain_scope_note(data.audit_chain_valid),
    ));
    x.push_str("<audit_entries>\n");
    for a in &data.audit_entries {
        x.push_str("<entry>\n");
        x.push_str(&xml_el("timestamp", &a.timestamp));
        x.push_str(&xml_el("user", &a.user));
        x.push_str(&xml_el("action", &a.action));
        x.push_str(&xml_el("resource_type", &a.resource_type));
        x.push_str("</entry>\n");
    }
    x.push_str("</audit_entries>\n");
    x.push_str("</chain_of_custody>\n");

    // ---- Processing Log ----
    if !data.processing_log.is_empty() {
        x.push_str("<processing_log>\n");
        for p in &data.processing_log {
            x.push_str("<module>\n");
            x.push_str(&xml_el("module_id", &p.module_id));
            x.push_str(&xml_el("status", &p.status));
            x.push_str(&xml_el_i64("runs", p.runs));
            x.push_str(&xml_el_i64("artifacts_produced", p.artifacts_produced));
            if let Some(d) = p.duration_ms {
                x.push_str(&xml_el_i64("duration_ms", d));
            }
            x.push_str(&xml_el_opt("error_message", &p.error_message));
            x.push_str("</module>\n");
        }
        x.push_str("</processing_log>\n");
    }

    // ---- Limitations and qualifications ----
    if !data.method_qualifications.is_empty() {
        x.push_str("<limitations_and_qualifications>\n");
        for q in &data.method_qualifications {
            x.push_str("<qualification>\n");
            x.push_str(&xml_el("subject", &q.subject));
            x.push_str(&xml_el("statement", &q.statement));
            x.push_str(&xml_el("bears_on", qualification_scope(q)));
            x.push_str("</qualification>\n");
        }
        x.push_str("</limitations_and_qualifications>\n");
    }

    // ---- Glossary ----
    if !data.glossary.is_empty() {
        x.push_str("<glossary>\n");
        for entry in &data.glossary {
            x.push_str(&format!(
                "<term name=\"{}\">{}</term>\n",
                xml_escape(&entry.term),
                xml_escape(&entry.definition)
            ));
        }
        x.push_str("</glossary>\n");
    }

    // ---- Declaration ----
    x.push_str("<declaration>\n");
    x.push_str(&xml_el("statement_of_truth", statement_of_truth(data)));
    let signatory = data
        .examiner_details
        .as_ref()
        .filter(|d| !d.name.is_empty())
        .map(|d| d.name.clone())
        .unwrap_or_else(|| data.examiner.clone());
    x.push_str(&xml_el("signatory", &signatory));
    x.push_str(&xml_el("signed_at", &data.generated_at));
    x.push_str("</declaration>\n");

    x.push_str("</forensic_report>\n");
    x
}

#[cfg(test)]
mod tests {
    /// A wholly unkeyed chain on a KEYED server is described as what the rows
    /// cannot tell apart — a legacy prefix or a full unkeyed rewrite — and is
    /// not told to set a key that is already set (SEC-009).
    #[test]
    fn an_unkeyed_chain_on_a_keyed_server_names_the_rewrite_it_cannot_rule_out() {
        let keyed_server = audit_chain_keying_disclosure(false, None, true);
        assert!(
            keyed_server.contains("IS set on this server"),
            "{keyed_server}"
        );
        assert!(
            keyed_server.contains("rewrote from scratch"),
            "{keyed_server}"
        );
        assert!(
            !keyed_server.contains("Set SEANCE_AUDIT_HMAC_KEY"),
            "advice to set a key that is set is false: {keyed_server}"
        );
        // An unkeyed server keeps the advice, which is right there.
        let unkeyed_server = audit_chain_keying_disclosure(false, None, false);
        assert!(
            unkeyed_server.contains("Set SEANCE_AUDIT_HMAC_KEY"),
            "{unkeyed_server}"
        );
        // The partially keyed and fully keyed cases are unchanged by the flag.
        assert!(audit_chain_keying_disclosure(false, Some(9), true).contains("PARTIALLY keyed"));
        assert_eq!(
            audit_chain_keying_disclosure(true, None, true),
            audit_chain_keying_note(true)
        );
    }

    use super::*;

    /// HUNT-090. A statement a later run answered stops counting as missing
    /// data — and the report has to say that it did, in both of its states.
    /// Silently smaller figures are indistinguishable from evidence that was
    /// never marked at all.
    /// CR-048: timeline events dropped for want of a timestamp are disclosed in
    /// the completeness verdict and make "verified" impossible.
    #[test]
    fn omitted_timeline_events_are_stated_and_defeat_the_verified_verdict() {
        let omitted = IncompletenessSummary {
            timeline_omitted: 1,
            ..Default::default()
        };
        let (class, text) = completeness_statement(Some(&omitted));
        assert_eq!(class, "notice");
        assert!(text.contains("1 timeline event(s)"), "{text}");
        assert!(timeline_omitted_note(Some(&omitted))
            .unwrap()
            .contains("not evidence of absence"));

        let none = IncompletenessSummary::default();
        assert_eq!(completeness_statement(Some(&none)).0, "verified");
        assert!(!completeness_statement(Some(&none))
            .1
            .contains("timeline event"));
        assert!(timeline_omitted_note(Some(&none)).is_none());
        assert!(timeline_omitted_note(None).is_none());
    }

    #[test]
    fn a_report_says_when_an_earlier_shortfall_was_answered() {
        let answered = IncompletenessSummary {
            content_incomplete: 0,
            inventory_incomplete: 0,
            reasons: vec![],
            distinct_reasons: 0,
            inventory_reasons: vec![],
            distinct_inventory_reasons: 0,
            superseded: 2,
            timeline_omitted: 0,
        };
        let (class, text) = completeness_statement(Some(&answered));
        assert_eq!(class, "verified");
        assert!(
            text.contains("2 earlier statement(s) of incompleteness were superseded"),
            "the answered shortfall must be stated: {text}"
        );

        // And where something IS still incomplete, both facts are carried.
        let mixed = IncompletenessSummary {
            content_incomplete: 3,
            superseded: 1,
            ..answered
        };
        let (class, text) = completeness_statement(Some(&mixed));
        assert_eq!(class, "notice");
        assert!(text.contains("INCOMPLETE RESULTS"));
        assert!(text.contains("1 earlier statement(s) of incompleteness were superseded"));

        // A case that never superseded anything says nothing about it.
        let plain = IncompletenessSummary {
            superseded: 0,
            ..mixed
        };
        assert!(!completeness_statement(Some(&plain))
            .1
            .contains("superseded"));
    }

    #[test]
    fn human_size_units() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1073741824), "1.00 GB");
        assert_eq!(human_size(512_000_000), "488.28 MB");
    }

    #[test]
    fn escapes_script_tags() {
        assert_eq!(esc("<script>"), "&lt;script&gt;");
        assert!(!esc("a<b>c").contains('<'));
    }

    /// A failed verification prints the verifier's reason, not one sentence
    /// over every failure.
    ///
    /// "row 1 was written under a key fingerprint that matches neither the
    /// current key nor any retired one" is a configuration state — a rotated
    /// key whose predecessor was not supplied — and the report printed
    /// *"Evidence handling integrity cannot be attested"* over it: a custody
    /// failure asserted on a court document for a missing environment
    /// variable. The reason now travels with the verdict, in both renderings.
    #[test]
    fn a_failed_chain_verdict_carries_the_verifiers_reason() {
        let reason = "row 1 was written under key fingerprint ab12cd34, which matches neither \
                      SEANCE_AUDIT_HMAC_KEY nor any key in SEANCE_AUDIT_HMAC_KEY_PREVIOUS; add \
                      the retired key there to verify it";
        let data = ReportData {
            audit_chain_valid: false,
            audit_chain_checked: 0,
            audit_chain_break_reason: Some(reason.to_string()),
            ..data_with_sections()
        };

        let html = render_html(&data);
        assert!(html.contains("AUDIT CHAIN NOT VERIFIED"), "{html}");
        assert!(
            html.contains("add the retired key there"),
            "the reason is printed: {html}"
        );
        assert!(
            !html.contains("cannot be attested") && !html.contains("has been altered"),
            "no sentence asserting a custody failure the verifier did not find: {html}"
        );
        assert!(
            html.contains("not attested by this report"),
            "and it still says what the failed verdict costs: {html}"
        );

        let pdf_text: String = build_pdf_lines(&data, &ReportExtras::default())
            .into_iter()
            .filter_map(|line| match line {
                Line::Text(t) | Line::Heading(t) | Line::Title(t) | Line::Mono(t) => Some(t),
                Line::Field(k, v) => Some(format!("{k}: {v}")),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(pdf_text.contains("add the retired key there"), "{pdf_text}");
        assert!(!pdf_text.contains("cannot be attested"), "{pdf_text}");
    }

    fn data_with_sections() -> ReportData {
        ReportData {
            case_name: "Case Z".into(),
            examiner: "E".into(),
            executive_summary: Some("Two evidence sources ingested.\nAudit chain verified.".into()),
            file_overview: Some(FileOverview {
                total_files: 1200,
                directories: 80,
                deleted_files: 14,
                carved_files: Some(6),
                encrypted_files: None,
                known_good_filtered: 900,
                notable_alerts: 2,
            }),
            integrity_checks: vec![IntegrityCheck {
                source_name: "disk.e01".into(),
                algorithm: "SHA256".into(),
                acquisition_hash: Some("aaa".into()),
                recomputed_hash: Some("aaa".into()),
                outcome: IntegrityOutcome::Verified,
                checked_at: Some("2026-07-15".into()),
            }],
            category_sections: vec![CategorySection {
                title: "Web History".into(),
                columns: vec!["URL".into(), "Visits".into()],
                rows: vec![vec!["http://example.com".into(), "5".into()]],
                total: 1,
                ..Default::default()
            }],
            known_good_hash_hits: vec![ReportHashHit {
                artifact_name: "kernel32.dll".into(),
                path: None,
                hash_set_name: "NSRL".into(),
                algorithm: "SHA1".into(),
                matched_hash: "bbb".into(),
            }],
            geolocation: vec![GeoPoint {
                label: "IMG_1.jpg".into(),
                path: Some("/DCIM/IMG_1.jpg".into()),
                latitude: 51.5,
                longitude: -0.14,
                altitude: Some(10.0),
                timestamp: Some("2023".into()),
            }],
            full_timeline: vec![ReportTimelineEvent {
                timestamp: "2026-07-01".into(),
                description: "event".into(),
                source_module: "mft".into(),
                ..Default::default()
            }],
            processing_log: vec![ProcessingLogEntry {
                module_id: "plugin.filesystem.ntfs".into(),
                status: "ok".into(),
                runs: 1,
                artifacts_produced: 500,
                duration_ms: Some(1234),
                error_message: None,
            }],
            ..Default::default()
        }
    }

    /// A qualification recorded against the examination reaches both renderers.
    ///
    /// This is the whole point of the field. A limitation that lives only in an
    /// artifact's metadata is one the court never sees, and the reading a report
    /// invites when it stays silent — "the method was the usual one" — is the
    /// reading that would be wrong.
    #[test]
    fn a_method_qualification_reaches_the_report_and_the_pdf() {
        let mut data = data_with_sections();
        data.method_qualifications = vec![MethodQualification {
            subject: "Symbol source — Linux memory image".into(),
            statement: "No symbol file described this kernel, so the layouts were read out of \
                        the image itself and nothing independent corroborates them."
                .into(),
            affects: Some("Every finding read out of the memory image.".into()),
        }];

        let html = render_html(&data);
        for needle in [
            "Limitations and Qualifications of the Examination",
            "Symbol source",
            "nothing independent corroborates them",
            "Bears on:",
        ] {
            assert!(html.contains(needle), "HTML missing: {needle}");
        }

        // The test's name promises the PDF, so the PDF is read: non-empty bytes
        // say only that some document was written, not that the qualification
        // reached it.
        let pdf = render_pdf(&data).expect("the PDF renders");
        let rendered = pdf_rendered_text(&pdf);
        for needle in [
            "Limitations and Qualifications of the Examination",
            "Bears on: Every finding read out of the memory image.",
        ] {
            assert!(
                rendered.contains(needle),
                "the PDF must carry the qualification too; missing {needle:?} from: {rendered}"
            );
        }
        assert!(
            !pdf.is_empty(),
            "a report carrying a qualification must still produce a PDF"
        );

        // Absent, the section is not invented: a heading with nothing under it
        // teaches a reader to skip the one that matters.
        let quiet = render_html(&data_with_sections());
        assert!(
            !quiet.contains("Limitations and Qualifications"),
            "an examination with no qualifications must render no such section"
        );
    }

    /// A qualification that names no `affects` bears on everything, and beside a
    /// sibling that does name one, rendering no "Bears on" line at all read as a
    /// scope nobody had established. The widest scope there is must not be the
    /// one the report says least about.
    #[test]
    fn a_qualification_that_names_no_scope_is_reported_as_bearing_on_the_whole_examination() {
        let mut data = data_with_sections();
        data.method_qualifications = vec![MethodQualification {
            subject: "Decompression ceiling".into(),
            statement: "Compressed members above the configured ceiling were listed but never \
                        decompressed, so their contents were not searched."
                .into(),
            affects: None,
        }];

        let html = render_html(&data);
        assert!(
            html.contains(QUALIFICATION_SCOPE_WHOLE_EXAMINATION),
            "an unscoped qualification must still state the scope it bears on"
        );
        // The PDF is asserted on its own text, not merely on rendering without
        // error: `render_pdf` can only fail on font loading and serialisation,
        // so `is_ok()` would hold just as well over a PDF that printed no scope
        // line at all — the silence this test exists to forbid.
        let pdf = render_pdf(&data).expect("the PDF renders");
        let rendered = pdf_rendered_text(&pdf);
        assert!(
            rendered.contains(QUALIFICATION_SCOPE_WHOLE_EXAMINATION),
            "the PDF of an unscoped qualification must state the scope it bears on; its text was: \
             {rendered}"
        );
    }

    #[test]
    fn html_renders_all_new_sections() {
        let html = render_html(&data_with_sections());
        for needle in [
            "Executive Summary",
            "File Overview",
            "Evidence Integrity",
            "Web History",
            "http://example.com",
            "Known-Good (KFF) Hash Matches",
            "kernel32.dll",
            "Geolocation",
            "Timeline",
            "Processing Log",
            "plugin.filesystem.ntfs",
        ] {
            assert!(html.contains(needle), "HTML missing section: {needle}");
        }
    }

    /// LIVE-014: a category whose records all fell outside the listed timeline
    /// slice carries a true total and no rows. Rendering "None recorded" under
    /// it asserts the case holds no such evidence, which is a false negative in
    /// a document written to be handed to a court — and it contradicts the
    /// "Showing 0 of N records" line printed directly above it.
    #[test]
    fn a_category_with_records_but_no_listed_rows_never_says_none_recorded() {
        let mut d = data_with_sections();
        d.category_sections = vec![CategorySection {
            title: "Web History".into(),
            columns: vec!["URL".into(), "Visits".into()],
            rows: Vec::new(),
            total: 281,
            ..Default::default()
        }];
        let html = render_html(&d);
        let section = section_html(&html, "Web History");

        assert!(
            !section.contains("None recorded"),
            "281 records exist; the section must not report absence. Got: {section}"
        );
        assert!(
            section.contains("281"),
            "the count the case holds must still be stated. Got: {section}"
        );
    }

    /// A path column that only repeats the file name asserts a path that was
    /// never established.
    #[test]
    fn a_gps_path_that_merely_repeats_the_file_name_is_left_blank() {
        let same = GeoPoint {
            label: "IMG.JPG".into(),
            path: Some("IMG.JPG".into()),
            ..Default::default()
        };
        assert_eq!(super::geo_path_cell(&same), None);

        let real = GeoPoint {
            label: "IMG.JPG".into(),
            path: Some("/DCIM/100APPLE/IMG.JPG".into()),
            ..Default::default()
        };
        assert_eq!(
            super::geo_path_cell(&real).as_deref(),
            Some("/DCIM/100APPLE/IMG.JPG")
        );
    }

    /// The slice of rendered HTML belonging to one `<h2>` section.
    fn section_html<'a>(html: &'a str, title: &str) -> &'a str {
        let head = format!("<h2>{title}</h2>");
        let start = html.find(&head).expect("section present");
        let rest = &html[start + head.len()..];
        match rest.find("<h2>") {
            Some(end) => &rest[..end],
            None => rest,
        }
    }

    /// The other half of the same decision: a category that genuinely holds
    /// nothing must still say so plainly.
    #[test]
    fn a_category_that_is_genuinely_empty_still_reports_none_recorded() {
        let mut d = data_with_sections();
        d.category_sections = vec![CategorySection {
            title: "Web History".into(),
            columns: vec!["URL".into(), "Visits".into()],
            rows: Vec::new(),
            total: 0,
            ..Default::default()
        }];
        let html = render_html(&d);
        assert!(section_html(&html, "Web History").contains("None recorded"));
    }

    #[test]
    fn html_new_section_content_is_escaped() {
        let mut d = data_with_sections();
        d.category_sections[0].rows[0][0] = "<script>alert(1)</script>".into();
        let html = render_html(&d);
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn pdf_renders_with_new_sections_without_panicking() {
        let bytes = render_pdf(&data_with_sections()).expect("pdf render");
        assert!(bytes.starts_with(b"%PDF"));
        assert!(bytes.len() > 1000);
    }

    #[test]
    fn empty_new_sections_are_omitted() {
        let base = ReportData {
            case_name: "Bare".into(),
            examiner: "E".into(),
            ..Default::default()
        };
        let html = render_html(&base);
        assert!(!html.contains("Executive Summary"));
        assert!(!html.contains("Web History"));
        assert!(!html.contains("Geolocation"));
        assert!(!html.contains("Processing Log"));
    }

    /// B4-018: a report whose GPS listing hit the query cap must say so. Before
    /// the fix the Geolocation section rendered identically at 100 points and at
    /// the 100,000-point ceiling, so a capped list read as every fix in the case.
    #[test]
    fn capped_geolocation_is_disclosed_in_html_and_pdf() {
        let mut d = data_with_sections();
        d.geolocation_truncated = true;
        let html = render_html(&d);
        assert!(html.contains("Geolocation"));
        assert!(
            html.contains("AT LEAST"),
            "capped geolocation not disclosed: {html}"
        );
        let pdf = render_pdf(&d).expect("pdf render");
        assert!(pdf.starts_with(b"%PDF"));
    }

    /// The disclosure must not appear on a complete listing.
    #[test]
    fn complete_geolocation_carries_no_cap_notice() {
        let html = render_html(&data_with_sections());
        assert!(html.contains("Geolocation"));
        assert!(!html.contains("AT LEAST"));
    }

    /// B6-028: the audit hash chain spans every case in the installation, so
    /// neither a pass nor a failure may be presented as a statement about this
    /// case alone. Before the fix the section said only "Audit chain verified"
    /// under a case heading.
    #[test]
    fn audit_chain_result_states_its_instance_wide_scope() {
        let mut d = data_with_sections();
        d.audit_chain_valid = true;
        d.audit_chain_checked = 12;
        let html = render_html(&d);
        assert!(
            html.contains("instance-wide hash chain"),
            "valid chain lacks scope statement: {html}"
        );

        d.audit_chain_valid = false;
        let html = render_html(&d);
        assert!(html.contains("instance-wide hash chain"));
        assert!(
            html.contains("may belong to another case"),
            "broken chain does not say the break may be elsewhere: {html}"
        );
        let pdf = render_pdf(&d).expect("pdf render");
        assert!(pdf.starts_with(b"%PDF"));
    }

    /// The PDF layout flattened back to searchable text.
    ///
    /// `Line::Text` is emitted pre-wrapped at 95 characters, so the lines are
    /// re-joined with single spaces — the same separator `wrap_text` split on —
    /// and a sentence that straddles a wrap boundary still matches.
    fn pdf_text(data: &ReportData) -> String {
        build_pdf_lines(data, &ReportExtras::default())
            .iter()
            .map(|line| match line {
                Line::Title(t) | Line::Heading(t) | Line::Mono(t) | Line::Text(t) => t.clone(),
                Line::Field(label, value) => format!("{label} {value}"),
                Line::Gap | Line::Figure(_) => String::new(),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    // --- Values Traced Across the Evidence (ROADMAP §5.13) ------------------

    fn traced() -> ReportTracedValue {
        ReportTracedValue {
            value: "10.0.0.7".into(),
            note: Some("the address the exfil connected to".into()),
            examiner: "Analyst A".into(),
            pinned_at: "2026-09-14T11:00:00+00:00".into(),
            matches_when_pinned: 11,
            truncated_when_pinned: false,
            groups_when_pinned: vec![("NetworkFlow".into(), 6), ("DnsResolution".into(), 5)],
            matches_now: Some(11),
            recheck_unavailable_reason: None,
        }
    }

    /// The whole point of the section: the answer the examiner got survives
    /// into the document instead of being re-derived by hand while writing it.
    #[test]
    fn a_traced_value_reaches_both_formats_with_its_counts_and_its_author() {
        let data = ReportData {
            traced_values: vec![traced()],
            ..ReportData::default()
        };
        for (format, text) in [("html", render_html(&data)), ("pdf", pdf_text(&data))] {
            assert!(
                text.contains("Values Traced Across the Evidence"),
                "{format}: {text}"
            );
            assert!(text.contains("10.0.0.7"), "{format}");
            assert!(text.contains("Analyst A"), "{format}");
            assert!(text.contains("2026-09-14T11:00:00"), "{format}");
            assert!(
                text.contains("the address the exfil connected to"),
                "{format}"
            );
            assert!(text.contains("NetworkFlow"), "{format}");
            // A reference is not a relationship, and the preamble says so.
            assert!(
                text.contains("a reference is not a relationship"),
                "{format}"
            );
        }
    }

    /// A report that showed only the snapshot would describe a case that has
    /// since grown. Where the two answers differ, the difference is the fact
    /// worth having.
    #[test]
    fn a_value_the_case_now_answers_differently_says_so_in_both_formats() {
        let data = ReportData {
            traced_values: vec![ReportTracedValue {
                matches_now: Some(19),
                ..traced()
            }],
            ..ReportData::default()
        };
        for (format, text) in [("html", render_html(&data)), ("pdf", pdf_text(&data))] {
            assert!(
                text.contains("19 artifact(s) now reference this value"),
                "{format}: {text}"
            );
            assert!(
                text.contains("differently on the two dates") || text.contains("differently on"),
                "{format}"
            );
        }
        // And an unchanged one says that too, rather than staying silent: a
        // silent section leaves the snapshot reading as current.
        let same = render_html(&ReportData {
            traced_values: vec![traced()],
            ..ReportData::default()
        });
        assert!(same.contains("still 11 artifact(s)"), "{same}");
    }

    /// "We could not look again" and "it matches nothing now" are different
    /// facts, and the second must never stand in for the first.
    #[test]
    fn a_value_that_could_not_be_rechecked_is_not_reported_as_matching_nothing() {
        let data = ReportData {
            traced_values: vec![ReportTracedValue {
                matches_now: None,
                recheck_unavailable_reason: Some(
                    "this build has no search index, so the case could not be searched again"
                        .into(),
                ),
                ..traced()
            }],
            ..ReportData::default()
        };
        for (format, text) in [("html", render_html(&data)), ("pdf", pdf_text(&data))] {
            assert!(text.contains("could NOT be re-checked"), "{format}: {text}");
            assert!(text.contains("no search index"), "{format}");
            assert!(
                !text.contains("0 artifact(s) now reference"),
                "{format}: an unanswered question must not render as a zero"
            );
        }

        // A re-check that simply did not happen, with no reason recorded, is
        // reported as that rather than passed over.
        let silent = render_html(&ReportData {
            traced_values: vec![ReportTracedValue {
                matches_now: None,
                recheck_unavailable_reason: None,
                ..traced()
            }],
            ..ReportData::default()
        });
        assert!(silent.contains("no reason was recorded"), "{silent}");
    }

    /// A capped pivot's per-kind counts do not add up to its total, and a
    /// sample presented as a total on a court-facing surface is the defect
    /// class this project treats as HIGH.
    #[test]
    fn a_capped_snapshot_says_its_per_kind_counts_are_a_sample() {
        let data = ReportData {
            traced_values: vec![ReportTracedValue {
                matches_when_pinned: 84_000,
                truncated_when_pinned: true,
                matches_now: Some(84_000),
                ..traced()
            }],
            ..ReportData::default()
        };
        for (format, text) in [("html", render_html(&data)), ("pdf", pdf_text(&data))] {
            assert!(text.contains("are a SAMPLE"), "{format}: {text}");
            assert!(text.contains("do not add up to the total"), "{format}");
        }
    }

    /// No pinned values, no section. A heading with nothing under it teaches a
    /// reader to skip the section, and the section that matters is the one they
    /// skip.
    #[test]
    fn a_report_with_no_traced_values_renders_no_such_section() {
        let data = ReportData::default();
        for (format, text) in [("html", render_html(&data)), ("pdf", pdf_text(&data))] {
            assert!(
                !text.contains("Values Traced Across the Evidence"),
                "{format}: {text}"
            );
        }
    }

    // --- Investigative Leads (ROADMAP §2.2) ---------------------------------
    //
    // The section carries an obligation none of the others do. Everything else
    // in this report is a transcription of the evidence or an examiner's own
    // mark; every row here is Séance's own claim, and Part VI forbids
    // presenting one as the other. The three assertions below are that
    // obligation, not a rendering check.

    fn lead() -> ReportLead {
        ReportLead {
            title: "Timestamps reordered on svchost.exe".into(),
            kind: "timestomp".into(),
            confidence: "Notable".into(),
            observation: "The $SI and $FN timestamps of svchost.exe are inconsistent.".into(),
            inference: Some("Rewriting $SI is how the time of an action is hidden.".into()),
            qualification: "It is also what a restore from backup looks like.".into(),
            evidence: vec![("si_modified".into(), "2019-03-02T11:14:08Z".into())],
            subject: "11111111-1111-1111-1111-111111111111".into(),
            device_offset: Some(4096),
            source_module: "plugin.findings.timestomp".into(),
            stored_as_a_record: true,
        }
    }

    fn detection() -> ReportLeadDetection {
        ReportLeadDetection {
            kind: "timestomp".into(),
            looks_for: "NTFS $SI timestamps inconsistent with $FN.".into(),
        }
    }

    /// The observation, the inference and the qualification reach both formats
    /// as three labelled things. A renderer that ran them into one paragraph
    /// would undo the distinction the type exists to keep, and a reader who
    /// took the inference for the observation would have been misled by the
    /// report rather than by the evidence.
    #[test]
    fn a_lead_reaches_both_formats_with_its_three_parts_kept_apart() {
        let data = ReportData {
            leads: vec![lead()],
            leads_total: 1,
            lead_detections: vec![detection()],
            ..ReportData::default()
        };

        for (format, text) in [("html", render_html(&data)), ("pdf", pdf_text(&data))] {
            assert!(text.contains("Investigative Leads"), "{format}: {text}");
            // The preamble: the section's whole defence.
            assert!(
                text.contains("investigative leads \u{2014} not findings of fact"),
                "{format}: the preamble must be present"
            );
            assert!(
                text.contains("has been corroborated by any independent means")
                    || text.contains("corroborated by any independent means"),
                "{format}: {text}"
            );
            // Three labels, three blocks.
            assert!(
                text.contains("Observation (checkable against the evidence)"),
                "{format}"
            );
            assert!(
                text.contains("S\u{e9}ance's reading, not a fact"),
                "{format}"
            );
            assert!(text.contains("What it does not establish"), "{format}");
            assert!(text.contains("restore from backup"), "{format}");
            // The grade, the values it rests on, and where to look.
            assert!(text.contains("Notable"), "{format}");
            assert!(text.contains("si_modified"), "{format}");
            assert!(text.contains("4096"), "{format}");
            // And what the build can look for at all, so an empty section can
            // be told from a build that looks for nothing.
            assert!(text.contains("What this build can look for"), "{format}");
            assert!(
                text.contains("NTFS $SI timestamps inconsistent"),
                "{format}"
            );
        }
    }

    /// A lead with no inference renders no inference heading. A heading with
    /// nothing under it teaches a reader to skip the section, and an invented
    /// reading is exactly what the observation/inference split prevents.
    #[test]
    fn a_lead_with_no_inference_renders_no_inference_label() {
        let data = ReportData {
            leads: vec![ReportLead {
                inference: None,
                ..lead()
            }],
            leads_total: 1,
            lead_detections: vec![detection()],
            ..ReportData::default()
        };
        for (format, text) in [("html", render_html(&data)), ("pdf", pdf_text(&data))] {
            assert!(
                !text.contains("S\u{e9}ance's reading, not a fact"),
                "{format}: {text}"
            );
            // The qualification is not optional and is still there.
            assert!(text.contains("What it does not establish"), "{format}");
        }
    }

    /// A build that carries no checks renders no section at all, rather than a
    /// heading with nothing under it.
    #[test]
    fn a_report_with_no_leads_and_no_checks_renders_no_section() {
        let data = ReportData::default();
        for (format, text) in [("html", render_html(&data)), ("pdf", pdf_text(&data))] {
            assert!(!text.contains("Investigative Leads"), "{format}: {text}");
        }
    }

    /// A build that carries checks and raised nothing says so, and still lists
    /// the checks: "no leads" and "nothing here looks for that" are different
    /// statements about the case, and the second is usually the truth.
    #[test]
    fn a_build_that_raised_nothing_still_says_what_it_looked_for() {
        let data = ReportData {
            leads: vec![],
            leads_total: 0,
            lead_detections: vec![detection()],
            ..ReportData::default()
        };
        for (format, text) in [("html", render_html(&data)), ("pdf", pdf_text(&data))] {
            assert!(text.contains("Investigative Leads"), "{format}");
            assert!(text.contains("No leads were raised"), "{format}");
            assert!(text.contains("What this build can look for"), "{format}");
        }
    }

    /// A lead that is not stored as an artifact cannot be re-opened, and a
    /// citation nobody can follow is worse than one labelled as such.
    #[test]
    fn a_computed_lead_says_it_cannot_be_reopened() {
        let data = ReportData {
            leads: vec![ReportLead {
                stored_as_a_record: false,
                device_offset: None,
                ..lead()
            }],
            leads_total: 1,
            lead_detections: vec![detection()],
            ..ReportData::default()
        };
        for (format, text) in [("html", render_html(&data)), ("pdf", pdf_text(&data))] {
            assert!(
                text.contains("not stored as an artifact"),
                "{format}: {text}"
            );
        }
    }

    /// A capped listing must never read as the whole of what the case holds.
    #[test]
    fn a_capped_lead_listing_states_the_case_wide_total() {
        let data = ReportData {
            leads: vec![lead()],
            leads_total: 87,
            lead_detections: vec![detection()],
            ..ReportData::default()
        };
        for (format, text) in [("html", render_html(&data)), ("pdf", pdf_text(&data))] {
            assert!(text.contains("87 lead(s)"), "{format}: {text}");
            assert!(text.contains("most confident"), "{format}");
        }
    }

    /// §2.2: every lead is "graded, qualified in the report's Limitations,
    /// never rendered beside a parsed artifact as though established the same
    /// way". This is the Limitations half, and it is generated rather than
    /// supplied so it cannot be left out of a report that carries leads.
    #[test]
    fn the_leads_qualification_states_what_a_rule_generated_claim_is_worth() {
        let q = leads_qualification(3, 9, None);
        assert_eq!(q.subject, "Investigative leads raised by the tool");
        assert_eq!(
            q.affects.as_deref(),
            Some("The Investigative Leads section only.")
        );
        assert!(q.statement.contains("3 investigative lead(s)"));
        assert!(q.statement.contains("9 fixed rule(s)"));
        // What a court most needs to be told about a rule-generated claim.
        assert!(
            q.statement.contains("not corroborated")
                || q.statement.contains("have not been corroborated")
        );
        assert!(
            q.statement.contains("not that anything was established"),
            "a Strong grade must not read as a conclusion: {}",
            q.statement
        );
        // And that a missing lead is not an absence.
        assert!(q
            .statement
            .contains("is not evidence that the pattern is absent"));

        // A coverage note from the findings surface is carried verbatim, so
        // the report and the screen cannot drift.
        let with_note = leads_qualification(1, 9, Some("No file entries were recovered."));
        assert!(with_note
            .statement
            .contains("No file entries were recovered."));

        // And it reaches the rendered Limitations section, in both formats.
        let data = ReportData {
            leads: vec![lead()],
            leads_total: 1,
            lead_detections: vec![detection()],
            method_qualifications: vec![leads_qualification(1, 9, None)],
            ..ReportData::default()
        };
        for (format, text) in [("html", render_html(&data)), ("pdf", pdf_text(&data))] {
            assert!(
                text.contains("Limitations and Qualifications"),
                "{format}: {text}"
            );
            assert!(
                text.contains("Investigative leads raised by the tool"),
                "{format}"
            );
        }
    }

    /// The text of a rendered PDF, read back out of the bytes that were written.
    ///
    /// `pdf_text` above flattens the layout the renderer is *handed*, which
    /// leaves the drawing itself unwitnessed; this parses the finished document
    /// and returns what a reader would see. `lopdf` does the parsing because the
    /// crate already depends on it for signing, so nothing is added to the
    /// dependency graph to check what we hand to a court.
    ///
    /// Extraction concatenates the text-showing operators, so a sentence that
    /// `wrap_text` split across two lines will not match as one string. Assert
    /// on a phrase short enough to sit on a single rendered line.
    fn pdf_rendered_text(pdf: &[u8]) -> String {
        let doc = lopdf::Document::load_mem(pdf).expect("the rendered PDF parses");
        let pages: Vec<u32> = doc.get_pages().keys().copied().collect();
        assert!(!pages.is_empty(), "a rendered report has at least one page");
        doc.extract_text(&pages)
            .expect("the rendered PDF's text is extractable")
    }

    /// HUNT-011: an UNKEYED chain hashes fields that all live in the same
    /// database, so anyone who can write to it can rewrite an entry, recompute
    /// every later hash and hand over a chain that verifies. Before the fix both
    /// renderers printed "Audit chain verified - N entries, tamper-evident
    /// (SHA-256 hash chain)." over exactly that chain, and the methodology
    /// footer went further and called undetected modification "computationally
    /// infeasible". That is a claim the evidence does not support, in the two
    /// documents most likely to be quoted in court.
    #[test]
    fn an_unkeyed_chain_verdict_is_never_presented_as_tamper_evident() {
        let mut d = data_with_sections();
        d.audit_chain_valid = true;
        d.audit_chain_checked = 12;
        d.audit_chain_tamper_evident = false;

        let html = render_html(&d);
        assert!(
            html.contains("Audit chain verified"),
            "the pass verdict itself must still be stated: {html}"
        );
        assert!(
            !html.contains("entries, tamper-evident"),
            "an unkeyed chain must not be credited with tamper-evidence: {html}"
        );
        assert!(
            !html.contains("computationally infeasible"),
            "the methodology footer must not claim what an unkeyed chain cannot: {html}"
        );
        assert!(
            html.contains("UNKEYED"),
            "the report must disclose that the chain is unkeyed: {html}"
        );
        assert!(
            html.contains("NOT evidence that the log is unaltered"),
            "the report must say what the passing verdict is worth: {html}"
        );

        // The same disclosure, in the same words, in the PDF.
        let pdf = pdf_text(&d);
        assert!(
            pdf.contains("Audit chain verified - 12 entries (UNKEYED SHA-256 hash chain)."),
            "pdf banner still claims more than the chain proves: {pdf}"
        );
        assert!(
            pdf.contains("NOT evidence that the log is unaltered"),
            "pdf omits what the passing verdict is worth: {pdf}"
        );
        assert!(
            !pdf.contains("tamper-evident record"),
            "pdf methodology still asserts a tamper-evident record: {pdf}"
        );
        assert!(render_pdf(&d).expect("pdf render").starts_with(b"%PDF"));
    }

    /// The other direction, so the fix does not simply delete the assurance: a
    /// KEYED chain's digests depend on a secret the database does not hold, and
    /// a pass on one really is evidence the log was not altered. That has to
    /// still be said, or setting SEANCE_AUDIT_HMAC_KEY buys the examiner nothing
    /// in the report.
    #[test]
    fn a_keyed_chain_verdict_is_credited_with_what_it_proves() {
        let mut d = data_with_sections();
        d.audit_chain_valid = true;
        d.audit_chain_checked = 12;
        d.audit_chain_tamper_evident = true;

        let html = render_html(&d);
        assert!(
            html.contains("keyed HMAC-SHA256 hash chain"),
            "the keyed construction must be named: {html}"
        );
        assert!(
            html.contains("have not been altered or reordered"),
            "a keyed chain must still be credited with what it proves: {html}"
        );
        assert!(
            !html.contains("UNKEYED"),
            "a keyed chain must not be described as unkeyed: {html}"
        );

        let pdf = pdf_text(&d);
        assert!(pdf.contains("keyed HMAC-SHA256 hash chain"), "{pdf}");
        assert!(!pdf.contains("UNKEYED"), "{pdf}");
    }

    /// A broken chain must disclose its keying too. An unkeyed chain that fails
    /// verification is the one case where the reader most needs to know that a
    /// competent rewrite would not have failed at all — so the break is evidence
    /// of corruption or a partial edit, not of the absence of a skilled one.
    #[test]
    fn a_broken_chain_still_discloses_its_keying() {
        let mut d = data_with_sections();
        d.audit_chain_valid = false;
        d.audit_chain_checked = 4;
        d.audit_chain_tamper_evident = false;

        let html = render_html(&d);
        assert!(html.contains("AUDIT CHAIN NOT VERIFIED"), "{html}");
        assert!(
            html.contains("UNKEYED"),
            "a failure verdict must disclose the keying as well: {html}"
        );
    }

    /// DEPLOY-001: a deployment that sets SEANCE_AUDIT_HMAC_KEY on an existing
    /// log has an unkeyed prefix and a keyed remainder. Calling that chain
    /// "UNKEYED" throws away what the keyed rows prove; calling it "keyed"
    /// credits the prefix with a property it never had. The report must name
    /// the boundary.
    #[test]
    fn a_partially_keyed_chain_names_the_row_from_which_it_is_tamper_evident() {
        let mut d = data_with_sections();
        d.audit_chain_valid = true;
        d.audit_chain_checked = 12;
        d.audit_chain_tamper_evident = false;
        d.audit_chain_tamper_evident_from = Some(9);

        let html = render_html(&d);
        assert!(html.contains("PARTIALLY keyed"), "{html}");
        assert!(
            html.contains("Rows before entry 9 were written unkeyed"),
            "{html}"
        );
        assert!(
            html.contains("from entry 9 onward have not been altered or reordered"),
            "the keyed remainder must be credited with what it proves: {html}"
        );
        assert!(
            html.contains("UNKEYED SHA-256 hash chain before entry 9, keyed HMAC-SHA256 from it"),
            "the banner must name both constructions and the boundary: {html}"
        );
        assert!(
            !html.contains("The chain is keyed (SEANCE_AUDIT_HMAC_KEY is set)"),
            "the whole-chain keyed claim must not appear over a partially keyed log: {html}"
        );

        let pdf = pdf_text(&d);
        assert!(pdf.contains("PARTIALLY keyed"), "{pdf}");
        assert!(pdf.contains("before entry 9"), "{pdf}");
    }

    #[test]
    fn wrap_text_respects_width_and_keeps_words() {
        let w = wrap_text("the quick brown fox jumps", 9);
        assert!(w.iter().all(|l| l.len() <= 9));
        assert_eq!(w.join(" "), "the quick brown fox jumps");
    }

    fn check(outcome: IntegrityOutcome) -> IntegrityCheck {
        IntegrityCheck {
            source_name: "disk.e01".into(),
            algorithm: "SHA256".into(),
            acquisition_hash: Some("aaa".into()),
            recomputed_hash: Some("aaa".into()),
            outcome,
            checked_at: Some("2026-07-15".into()),
        }
    }

    /// B3-061. Ingest records every acquisition hash with status "baseline".
    /// Before the fix that mapped to `verified: false`, and a case that had done
    /// nothing wrong exported a court report headed "HASH MISMATCH - Evidence
    /// may have been altered."
    #[test]
    fn baseline_only_case_is_not_reported_as_a_mismatch() {
        assert_eq!(
            IntegrityOutcome::from_status("baseline"),
            IntegrityOutcome::Baseline
        );
        let data = ReportData {
            case_name: "Routine".into(),
            integrity_checks: vec![check(IntegrityOutcome::Baseline)],
            ..Default::default()
        };
        let html = render_html(&data);
        assert!(
            !html.contains("HASH MISMATCH"),
            "an acquisition baseline must never render as a mismatch"
        );
        // The only MISMATCH text left is the methodology note explaining the
        // vocabulary; no row and no banner asserts one.
        assert!(!html.contains("<td>MISMATCH</td>"));
        assert!(
            html.contains("BASELINE") && html.contains("not re-verified"),
            "the report must say the hash was recorded, not re-verified"
        );
        assert!(
            !html.contains("evidence integrity intact"),
            "a baseline is not a pass either"
        );
    }

    /// A genuine failed re-verification must still raise the alarm.
    #[test]
    fn failed_reverification_still_raises_the_mismatch_banner() {
        let data = ReportData {
            integrity_checks: vec![
                check(IntegrityOutcome::Verified),
                check(IntegrityOutcome::Failed),
            ],
            ..Default::default()
        };
        let html = render_html(&data);
        assert!(html.contains("HASH MISMATCH"));
        assert!(html.contains("Evidence may have been altered"));
    }

    /// A status the mapping does not know must not be read as a pass.
    #[test]
    fn unknown_and_no_baseline_statuses_are_indeterminate() {
        for s in ["no_baseline", "incomplete", "something_new"] {
            assert_eq!(
                IntegrityOutcome::from_status(s),
                IntegrityOutcome::Indeterminate,
                "status {s} must not be treated as verified"
            );
        }
        let html = render_html(&ReportData {
            integrity_checks: vec![check(IntegrityOutcome::Indeterminate)],
            ..Default::default()
        });
        assert!(html.contains("could not be re-verified"));
        assert!(!html.contains("integrity intact"));
    }

    /// B3-002. A capped hash-hit listing must state the case-wide total.
    #[test]
    fn capped_hash_hit_listing_discloses_the_case_total() {
        let hit = ReportHashHit {
            artifact_name: "bad.exe".into(),
            path: None,
            hash_set_name: "Contraband".into(),
            algorithm: "SHA256".into(),
            matched_hash: "deadbeef".into(),
        };
        let data = ReportData {
            notable_hash_hits: vec![hit.clone()],
            notable_hash_total: 1200,
            known_good_hash_hits: vec![hit],
            known_good_hash_total: 900,
            ..Default::default()
        };
        let html = render_html(&data);
        assert!(html.contains("Showing 1 of 1200 records."));
        assert!(html.contains("Showing 1 of 900 records."));
        assert!(render_pdf(&data).expect("pdf render").starts_with(b"%PDF"));
    }

    /// An event becomes a highlight because an examiner tagged it, and the note
    /// they wrote is the only record of WHY. Both the note and the examiner who
    /// wrote it were discarded on the way here, so the court read a bare MFT
    /// description under a heading that promised significance and had no way to
    /// learn what the significance was. The reasoning has to survive into the
    /// document, in both renderers, or it exists only inside the application.
    #[test]
    fn a_timeline_highlight_carries_its_note_and_its_examiner() {
        let data = ReportData {
            timeline_highlights: vec![ReportTimelineEvent {
                timestamp: "2026-07-01T03:12:00Z".into(),
                description: "USB device inserted".into(),
                source_module: "registry".into(),
                examiner: Some("Analyst A".into()),
                note: Some("matches CCTV entry time".into()),
            }],
            ..Default::default()
        };

        let html = render_html(&data);
        assert!(
            html.contains("matches CCTV entry time"),
            "the tag note is missing from the report: {html}"
        );
        assert!(
            html.contains("Analyst A"),
            "the examiner who tagged the event is missing from the report"
        );

        let pdf = render_pdf(&data).expect("the PDF renders");
        let rendered = pdf_rendered_text(&pdf);
        assert!(
            rendered.contains("matches CCTV entry time"),
            "the tag note is missing from the PDF; its text was: {rendered}"
        );
        assert!(
            rendered.contains("Analyst A"),
            "the examiner who tagged the event is missing from the PDF; its text was: {rendered}"
        );
    }

    /// A tagged event whose examiner wrote no note is a different fact from an
    /// untagged one, and the highlights table must not present the absence as
    /// though the column did not exist: the row still appears, with the note
    /// cell explicitly empty.
    #[test]
    fn a_highlight_without_a_note_still_renders_its_row() {
        let html = render_html(&ReportData {
            timeline_highlights: vec![ReportTimelineEvent {
                timestamp: "2026-07-01T03:12:00Z".into(),
                description: "USB device inserted".into(),
                source_module: "registry".into(),
                examiner: Some("Analyst A".into()),
                note: None,
            }],
            ..Default::default()
        });
        assert!(html.contains("USB device inserted"));
        assert!(html.contains("<th>Note</th>"));
    }

    /// The full timeline is every event in the case, tagged or not, so it has no
    /// note to show. Giving it the highlights' columns would print two empty
    /// columns down hundreds of pages and invite the reading that every one of
    /// those events was examined and found unremarkable.
    #[test]
    fn the_full_timeline_table_grows_no_annotation_columns() {
        let html = render_html(&ReportData {
            full_timeline: vec![ReportTimelineEvent {
                timestamp: "2026-07-01".into(),
                description: "event".into(),
                source_module: "mft".into(),
                ..Default::default()
            }],
            full_timeline_total: 1,
            ..Default::default()
        });
        let timeline = html
            .split("<h2>Timeline</h2>")
            .nth(1)
            .expect("full timeline section");
        assert!(!timeline.contains("<th>Note</th>"));
        assert!(!timeline.contains("<th>Examiner</th>"));
    }

    /// B3-003. The timeline listing is capped; the caption must lead with the
    /// case-wide total rather than presenting the cap as the case size.
    #[test]
    fn capped_timeline_states_case_total_not_the_cap() {
        let ev = ReportTimelineEvent {
            timestamp: "2026-07-01".into(),
            description: "event".into(),
            source_module: "mft".into(),
            ..Default::default()
        };
        let html = render_html(&ReportData {
            full_timeline: vec![ev.clone(), ev],
            full_timeline_total: 412_000,
            ..Default::default()
        });
        assert!(html.contains("The case contains 412000 timeline events"));
        assert!(html.contains("truncated"));
    }

    /// Same class as the timeline cap: the chain-of-custody listing is bounded
    /// at AUDIT_REPORT_CAP and must say so.
    #[test]
    fn capped_audit_listing_discloses_the_case_total() {
        let entry = ReportAuditEntry {
            timestamp: "2026-07-20".into(),
            user: "Analyst A".into(),
            action: "case_created".into(),
            resource_type: "case".into(),
        };
        let html = render_html(&ReportData {
            audit_entries: vec![entry],
            audit_entries_total: 24_000,
            ..Default::default()
        });
        assert!(html.contains("Showing 1 of 24000 records."));
    }

    /// An uncapped listing must not grow a spurious truncation notice.
    #[test]
    fn uncapped_listings_carry_no_truncation_notice() {
        let ev = ReportTimelineEvent {
            timestamp: "2026-07-01".into(),
            description: "event".into(),
            source_module: "mft".into(),
            ..Default::default()
        };
        let html = render_html(&ReportData {
            full_timeline: vec![ev],
            full_timeline_total: 1,
            ..Default::default()
        });
        assert!(html.contains("1 events (chronological)."));
        assert!(!html.contains("truncated"));
        assert!(!html.contains("Showing"));
    }

    fn reason(text: &str, count: i64) -> IncompletenessReason {
        IncompletenessReason {
            reason: Some(text.into()),
            count,
        }
    }

    /// THE consumer gap. ~809 sites across the plugin tree stamp
    /// `content_incomplete` / `content_incomplete_reason`, and the report read
    /// none of them: a truncated result and a complete one exported the same
    /// document. The reason must travel with the fact -- a 512 MiB hive cap and
    /// a corrupt mid-file record are different stories.
    #[test]
    fn plugin_recorded_incompleteness_reaches_the_report() {
        let data = ReportData {
            case_name: "Truncated".into(),
            incompleteness: Some(IncompletenessSummary {
                content_incomplete: 37,
                inventory_incomplete: 2,
                reasons: vec![
                    reason("registry hive exceeded the 512 MiB read cap", 30),
                    reason("corrupt record at offset 4096", 7),
                ],
                distinct_reasons: 2,
                inventory_reasons: vec![reason("archive structure could not be resolved", 2)],
                distinct_inventory_reasons: 1,
                superseded: 0,
                timeline_omitted: 0,
            }),
            ..Default::default()
        };
        let html = render_html(&data);
        assert!(html.contains("Result Completeness"));
        assert!(html.contains("INCOMPLETE RESULTS"));
        assert!(
            html.contains("37 artifact(s) were parsed from content that could not be read"),
            "the count must be stated"
        );
        assert!(
            html.contains("2 artifact(s) carry a listing shorter"),
            "a short listing is a separate disclosure"
        );
        assert!(
            html.contains("registry hive exceeded the 512 MiB read cap"),
            "the reason must be given, not just the fact"
        );
        assert!(html.contains("corrupt record at offset 4096"));
        assert!(html.contains("not evidence of absence"));
        assert!(render_pdf(&data).expect("pdf render").starts_with(b"%PDF"));
    }

    /// The listing axis has its own recorded reason key,
    /// `inventory_incomplete_reason`, written at 43 sites across the plugin
    /// tree. The first pass at this section read only
    /// `content_incomplete_reason`, so a short listing reached the report as a
    /// bare count -- and a case whose ONLY shortfall was a short listing was
    /// told "No reason was recorded for any of them" when the reason had in
    /// fact been recorded. That is the same defect this whole effort exists to
    /// close, one key over.
    #[test]
    fn a_short_listing_states_the_recorded_reason_it_is_short() {
        let data = ReportData {
            case_name: "ShortListing".into(),
            incompleteness: Some(IncompletenessSummary {
                content_incomplete: 0,
                inventory_incomplete: 6,
                reasons: Vec::new(),
                distinct_reasons: 0,
                inventory_reasons: vec![reason("archive structure could not be resolved", 6)],
                distinct_inventory_reasons: 1,
                superseded: 0,
                timeline_omitted: 0,
            }),
            ..Default::default()
        };
        let html = render_html(&data);
        assert!(html.contains("6 artifact(s) carry a listing shorter"));
        assert!(
            html.contains("archive structure could not be resolved"),
            "the recorded reason for a short listing must reach the report"
        );
        assert!(
            html.contains("Listing shorter than the container"),
            "the reason must be attributed to the listing axis, not to content"
        );
        assert!(
            !html.contains("Content not read in full"),
            "an axis with nothing wrong on it must not appear in the table"
        );
        assert!(render_pdf(&data).expect("pdf render").starts_with(b"%PDF"));
    }

    /// A shortfall on one axis must not drag an unexplained-shortfall sentence
    /// onto the other. Before the axes were separated, an inventory-only case
    /// printed "No reason was recorded for any of them" because the CONTENT
    /// reason list was empty.
    #[test]
    fn an_unrecorded_reason_on_one_axis_does_not_speak_for_the_other() {
        let html = render_html(&ReportData {
            incompleteness: Some(IncompletenessSummary {
                content_incomplete: 3,
                inventory_incomplete: 2,
                reasons: Vec::new(),
                distinct_reasons: 0,
                inventory_reasons: vec![reason("volume index could not be decoded", 2)],
                distinct_inventory_reasons: 1,
                superseded: 0,
                timeline_omitted: 0,
            }),
            ..Default::default()
        });
        // The content axis genuinely recorded nothing and says so, scoped.
        assert!(html.contains("<td>Content not read in full</td>"));
        assert!(html.contains("no reason was recorded"));
        // The listing axis recorded a reason and it is not overwritten by it.
        assert!(html.contains("volume index could not be decoded"));
    }

    /// "Nobody assessed completeness" and "everything is complete" must never
    /// render as the same document. Before this section existed, every report
    /// was the former presented as the latter.
    #[test]
    fn an_unassessed_case_says_so_rather_than_implying_completeness() {
        let html = render_html(&ReportData {
            case_name: "Unassessed".into(),
            incompleteness: None,
            ..Default::default()
        });
        assert!(
            html.contains("Result completeness was NOT assessed"),
            "an unassessed case must say so"
        );
        assert!(!html.contains("No artifact in this case was recorded as incompletely read"));
    }

    /// A case genuinely found complete gets a positive statement, so the
    /// section is not one that only ever appears on bad news.
    #[test]
    fn an_assessed_and_complete_case_states_that_positively() {
        let html = render_html(&ReportData {
            incompleteness: Some(IncompletenessSummary::default()),
            ..Default::default()
        });
        assert!(html.contains("No artifact in this case was recorded as incompletely read"));
        assert!(!html.contains("INCOMPLETE RESULTS"));
        assert!(!html.contains("NOT assessed"));
    }

    /// A flag set with no reason is still a shortfall. Dropping it would let a
    /// non-zero incomplete count sit beside an empty reason table.
    #[test]
    fn an_unexplained_shortfall_is_still_disclosed() {
        let html = render_html(&ReportData {
            incompleteness: Some(IncompletenessSummary {
                content_incomplete: 4,
                reasons: vec![IncompletenessReason {
                    reason: None,
                    count: 4,
                }],
                distinct_reasons: 1,
                ..Default::default()
            }),
            ..Default::default()
        });
        assert!(html.contains("INCOMPLETE RESULTS"));
        assert!(html.contains("reason not recorded"));
    }

    /// The reason list is itself capped; the same "Showing N of M" vocabulary
    /// every other capped listing uses must apply to it.
    #[test]
    fn a_capped_reason_list_discloses_the_distinct_total() {
        let html = render_html(&ReportData {
            incompleteness: Some(IncompletenessSummary {
                content_incomplete: 900,
                reasons: vec![reason("short read", 900)],
                distinct_reasons: 64,
                ..Default::default()
            }),
            ..Default::default()
        });
        assert!(html.contains("Showing 1 of 64 distinct reasons recorded."));
    }

    /// A section listing records derived from a truncated read must say so in
    /// the place the examiner is looking, not only in a case-level statement
    /// several pages away.
    #[test]
    fn a_section_discloses_its_own_share_of_the_incompleteness() {
        let data = ReportData {
            category_sections: vec![CategorySection {
                title: "Registry".into(),
                columns: vec!["Timestamp".into(), "Description".into()],
                rows: vec![vec!["2026-07-01".into(), "run key".into()]],
                total: 1,
                incomplete_records: 3,
                incomplete_reasons: vec![reason("hive exceeded the 512 MiB read cap", 3)],
            }],
            incompleteness: Some(IncompletenessSummary {
                content_incomplete: 3,
                reasons: vec![reason("hive exceeded the 512 MiB read cap", 3)],
                distinct_reasons: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        let html = render_html(&data);
        assert!(
            html.contains("3 artifact(s) behind this section were parsed from content that could not be read in full"),
            "the section itself must carry the disclosure"
        );
        assert!(html.contains("hive exceeded the 512 MiB read cap (3)"));
        assert!(render_pdf(&data).expect("pdf render").starts_with(b"%PDF"));
    }

    /// A complete section must not grow a spurious incompleteness notice.
    #[test]
    fn a_complete_section_carries_no_incompleteness_notice() {
        let html = render_html(&ReportData {
            category_sections: vec![CategorySection {
                title: "Web History".into(),
                columns: vec!["URL".into()],
                rows: vec![vec!["http://example.com".into()]],
                total: 1,
                ..Default::default()
            }],
            incompleteness: Some(IncompletenessSummary::default()),
            ..Default::default()
        });
        assert!(!html.contains("behind this section"));
    }

    /// B3-063. The Processing Log section was hard-coded empty. It now renders,
    /// and a capped group listing discloses the shortfall the same way every
    /// other capped listing does.
    #[test]
    fn processing_log_renders_and_discloses_its_cap() {
        let data = ReportData {
            processing_log: vec![ProcessingLogEntry {
                module_id: "plugin.filesystem.ntfs".into(),
                status: "complete".into(),
                runs: 7,
                artifacts_produced: 120_000,
                duration_ms: Some(45_000),
                error_message: None,
            }],
            processing_log_total: 40,
            ..Default::default()
        };
        let html = render_html(&data);
        assert!(html.contains("Processing Log"));
        assert!(html.contains("plugin.filesystem.ntfs"));
        assert!(html.contains("Showing 1 of 40 records."));
        // The DB aggregates every run of a module into one row and counts them.
        // That count was computed, stored and then dropped on the way to the
        // renderer, so a row summed over 7 passes read exactly like a single
        // pass and nothing could be reconciled against the per-artifact log.
        assert!(
            html.contains("<th>Runs</th>"),
            "the aggregation must state how many runs it folded together"
        );
        assert!(html.contains("<td>7</td>"), "{html}");
        assert!(render_pdf(&data).expect("pdf render").starts_with(b"%PDF"));
    }

    /// An unrecorded run count must render as a dash. A row exists only because
    /// the module ran, so printing 0 would state something the log contradicts.
    #[test]
    fn an_unrecorded_run_count_is_a_dash_not_zero() {
        let html = render_html(&ReportData {
            processing_log: vec![ProcessingLogEntry {
                module_id: "plugin.evtx".into(),
                status: "complete".into(),
                runs: 0,
                artifacts_produced: 12,
                duration_ms: None,
                error_message: None,
            }],
            ..Default::default()
        });
        assert!(!html.contains("<td>0</td>"), "{html}");
        assert!(html.contains(&format!("<td>{DASH}</td>")));
    }

    /// An undetermined File Overview count must render as a dash, never as 0.
    #[test]
    fn undetermined_overview_counts_are_not_rendered_as_zero() {
        let html = render_html(&ReportData {
            file_overview: Some(FileOverview {
                total_files: 10,
                directories: 2,
                deleted_files: 1,
                carved_files: None,
                encrypted_files: None,
                known_good_filtered: 0,
                notable_alerts: 0,
            }),
            ..Default::default()
        });
        assert!(html.contains("were not determined for this report"));
        assert!(
            html.contains(&format!(
                "<div class=\"num\">{DASH}</div><div class=\"lbl\">Carved</div>"
            )),
            "an undetermined Carved count must render as a dash, not 0"
        );
        assert!(
            html.contains(&format!(
                "<div class=\"num\">{DASH}</div><div class=\"lbl\">Encrypted</div>"
            )),
            "an undetermined Encrypted count must render as a dash, not 0"
        );
    }

    // -----------------------------------------------------------------
    // RTF / XML renderers (ROADMAP §2.10)
    // -----------------------------------------------------------------

    /// One populated instance of every major section render_html renders,
    /// including at least one FAILED integrity check, a completeness
    /// shortfall, bookmarks, leads and traced values -- the sections
    /// `data_with_sections()` above deliberately leaves out. Shared by the
    /// RTF and XML tests so both are checked against the same case.
    ///
    /// Carries adversarial text in two places on purpose, not clean names:
    /// the examiner's name holds a literal backslash and both RTF group
    /// delimiters (one `{`, one `}`, so the raw brace count in the whole
    /// document stays balanced regardless of how `rtf_escape` renders them),
    /// and a bookmark's artifact name holds `<`, `&` and a `"` for the XML
    /// round-trip check.
    fn full_report_fixture() -> ReportData {
        ReportData {
            case_name: "Case Omega".into(),
            case_reference: Some("REF-2026-042".into()),
            examiner: "Backup Examiner".into(),
            generated_at: "2026-09-18T10:00:00Z".into(),
            tool_name: "Seance".into(),
            tool_version: "1.2.0".into(),
            executive_summary: Some(
                "One evidence source ingested.\nOne hash mismatch found.".into(),
            ),
            file_overview: Some(FileOverview {
                total_files: 500,
                directories: 40,
                deleted_files: 6,
                carved_files: Some(3),
                encrypted_files: None,
                known_good_filtered: 200,
                notable_alerts: 1,
            }),
            evidence_sources: vec![EvidenceSource {
                name: "disk.e01".into(),
                source_type: "EWF".into(),
                size_bytes: Some(1_000_000),
                md5: Some("d41d8cd98f00b204e9800998ecf8427e".into()),
                sha1: Some("aaa1".into()),
                sha256: Some("aaa256".into()),
                acquired_at: Some("2026-09-01".into()),
            }],
            integrity_checks: vec![
                IntegrityCheck {
                    source_name: "disk.e01".into(),
                    algorithm: "SHA256".into(),
                    acquisition_hash: Some("aaa256".into()),
                    recomputed_hash: Some("bbb256".into()),
                    outcome: IntegrityOutcome::Failed,
                    checked_at: Some("2026-09-18".into()),
                },
                IntegrityCheck {
                    source_name: "disk2.e01".into(),
                    algorithm: "SHA256".into(),
                    acquisition_hash: Some("ccc256".into()),
                    recomputed_hash: None,
                    outcome: IntegrityOutcome::Baseline,
                    checked_at: None,
                },
            ],
            artifact_counts: vec![("web_history".into(), 12), ("registry".into(), 4)],
            total_artifacts: 16,
            category_sections: vec![CategorySection {
                title: "Web History".into(),
                columns: vec!["URL".into(), "Visits".into()],
                rows: vec![vec!["http://example.com".into(), "5".into()]],
                total: 1,
                ..Default::default()
            }],
            personal_bookmarks_excluded: 2,
            bookmarks: vec![ReportBookmark {
                artifact_name: "Report<Name>&\"Quote\"".into(),
                category: Some("Web".into()),
                note: Some("Adversarial XML content for the round-trip test".into()),
                examiner: Some("Backup Examiner".into()),
                created_at: "2026-09-10".into(),
                source_path: Some("/C/Users/x".into()),
                source_offset: Some(4096),
            }],
            traced_values: vec![ReportTracedValue {
                value: "user@example.com".into(),
                note: Some("Pinned because it recurs across web and email artifacts".into()),
                examiner: "Backup Examiner".into(),
                pinned_at: "2026-09-05".into(),
                matches_when_pinned: 3,
                truncated_when_pinned: false,
                groups_when_pinned: vec![("web_history".into(), 2), ("email".into(), 1)],
                matches_now: Some(4),
                recheck_unavailable_reason: None,
            }],
            leads: vec![ReportLead {
                title: "Timestamp precedes install date".into(),
                kind: "anachronous_timestamp".into(),
                confidence: "Notable".into(),
                observation: "A file's modified time predates the OS install record.".into(),
                inference: Some("May indicate a copied or restored file.".into()),
                qualification: "Clock drift or a restored backup would produce the same pattern."
                    .into(),
                evidence: vec![("modified".into(), "2020-01-01".into())],
                subject: "C:\\Users\\x\\file.txt".into(),
                device_offset: Some(2048),
                source_module: "leads.timestamp".into(),
                stored_as_a_record: false,
            }],
            leads_total: 1,
            lead_detections: vec![ReportLeadDetection {
                kind: "anachronous_timestamp".into(),
                looks_for: "Files modified before the recorded OS install date.".into(),
            }],
            leads_coverage_note: None,
            geolocation: vec![GeoPoint {
                label: "IMG_1.jpg".into(),
                path: Some("/DCIM/IMG_1.jpg".into()),
                latitude: 51.5,
                longitude: -0.14,
                altitude: Some(10.0),
                timestamp: Some("2023-01-01".into()),
            }],
            geolocation_truncated: false,
            timeline_highlights: vec![ReportTimelineEvent {
                timestamp: "2026-07-01".into(),
                description: "Suspicious login".into(),
                source_module: "auth_log".into(),
                examiner: Some("Backup Examiner".into()),
                note: Some("Flagged for follow-up".into()),
            }],
            full_timeline: vec![ReportTimelineEvent {
                timestamp: "2026-07-01".into(),
                description: "event".into(),
                source_module: "mft".into(),
                ..Default::default()
            }],
            full_timeline_total: 1,
            audit_entries: vec![ReportAuditEntry {
                timestamp: "2026-09-01".into(),
                user: "admin".into(),
                action: "case_created".into(),
                resource_type: "case".into(),
            }],
            audit_entries_total: 1,
            audit_chain_valid: true,
            audit_chain_checked: 10,
            audit_chain_tamper_evident: true,
            audit_chain_tamper_evident_from: None,
            audit_chain_key_configured: true,
            audit_chain_break_reason: None,
            processing_log: vec![ProcessingLogEntry {
                module_id: "plugin.filesystem.ntfs".into(),
                status: "ok".into(),
                runs: 1,
                artifacts_produced: 500,
                duration_ms: Some(1234),
                error_message: None,
            }],
            processing_log_total: 1,
            incompleteness: Some(IncompletenessSummary {
                content_incomplete: 2,
                inventory_incomplete: 1,
                reasons: vec![IncompletenessReason {
                    reason: Some("hive exceeded the 512 MiB cap".into()),
                    count: 2,
                }],
                distinct_reasons: 1,
                inventory_reasons: vec![],
                distinct_inventory_reasons: 0,
                superseded: 0,
                timeline_omitted: 0,
            }),
            notable_hash_hits: vec![ReportHashHit {
                artifact_name: "malware.exe".into(),
                path: Some("/tmp/malware.exe".into()),
                hash_set_name: "NSRL-Bad".into(),
                algorithm: "SHA1".into(),
                matched_hash: "eee1".into(),
            }],
            notable_hash_total: 1,
            known_good_hash_hits: vec![ReportHashHit {
                artifact_name: "kernel32.dll".into(),
                path: None,
                hash_set_name: "NSRL".into(),
                algorithm: "SHA1".into(),
                matched_hash: "bbb1".into(),
            }],
            known_good_hash_total: 1,
            // The adversarial name: a literal backslash and one matched pair
            // of RTF group delimiters, so the RTF brace-balance assertion
            // holds regardless of how the escaper renders them.
            examiner_details: Some(ExaminerDetails {
                name: "Backup\\Examiner {Lead}".into(),
                role: Some("Senior Analyst".into()),
                organisation: Some("Example Forensics Ltd".into()),
                contact: Some("examiner@example.com".into()),
                qualifications: Some("CFCE".into()),
            }),
            report_identity: Some(ReportIdentity {
                report_id: "RPT-001".into(),
                revision: Some(2),
                classification: Some("RESTRICTED".into()),
                statement_of_truth: None,
            }),
            glossary: default_glossary(),
            method_qualifications: vec![MethodQualification {
                subject: "Symbol source".into(),
                statement: "Symbols were recovered from the image itself.".into(),
                affects: Some("Every finding read out of memory.".into()),
            }],
        }
    }

    /// A code-review pass on 2026-09-18 caught the XML export omitting
    /// `<carved_files>`/`<encrypted_files>` with no equivalent to HTML's and
    /// RTF's "were not determined... must not be read as zero" sentence. XML
    /// is read by code, and a tool that treats a missing element as
    /// absent-equals-zero (the common default for XML-to-JSON/XPath
    /// tooling) would silently report zero for a count that was never
    /// determined — the automated-ingestion version of the exact
    /// misrepresentation the sentence exists to prevent in the other two
    /// formats.
    #[test]
    fn xml_states_when_carved_or_encrypted_counts_were_not_determined() {
        let mut data = ReportData {
            file_overview: Some(FileOverview {
                total_files: 10,
                directories: 2,
                deleted_files: 1,
                carved_files: Some(3),
                encrypted_files: None,
                known_good_filtered: 0,
                notable_alerts: 0,
            }),
            ..Default::default()
        };
        let xml = render_xml(&data);
        assert!(
            xml.contains("<carved_files>3</carved_files>"),
            "a determined count must still render: {xml}"
        );
        assert!(
            !xml.contains("<encrypted_files>"),
            "an undetermined count must not render as an element at all: {xml}"
        );
        assert!(
            xml.contains("<counts_not_determined>true</counts_not_determined>"),
            "the undetermined count must be stated machine-readably: {xml}"
        );

        // The counterweight: both counts determined, nothing flagged.
        data.file_overview = Some(FileOverview {
            total_files: 10,
            directories: 2,
            deleted_files: 1,
            carved_files: Some(3),
            encrypted_files: Some(0),
            known_good_filtered: 0,
            notable_alerts: 0,
        });
        let xml = render_xml(&data);
        assert!(!xml.contains("counts_not_determined"), "{xml}");
    }

    /// The RTF document opens and closes as one balanced group, and an
    /// adversarial examiner name (backslash + a matched brace pair) survives
    /// escaped rather than corrupting the document from that point on.
    #[test]
    fn rtf_is_syntactically_balanced_and_escapes_adversarial_text() {
        let data = full_report_fixture();
        let rtf = render_rtf(&data);

        assert!(
            rtf.starts_with("{\\rtf1"),
            "must open with {{\\rtf1: {}",
            &rtf[..40.min(rtf.len())]
        );
        assert!(
            rtf.trim_end().ends_with('}'),
            "must close with a matching close-brace"
        );
        let opens = rtf.matches('{').count();
        let closes = rtf.matches('}').count();
        assert_eq!(
            opens, closes,
            "unbalanced RTF braces: {opens} opens vs {closes} closes"
        );

        // The name contains one literal backslash and a matched `{`/`}`
        // pair; each must appear escaped, never as raw RTF control syntax.
        assert!(
            rtf.contains("Backup\\\\Examiner"),
            "the backslash in the examiner's name must be escaped as \\\\\\\\: {rtf}"
        );
        assert!(
            rtf.contains("\\{Lead\\}"),
            "the braces in the examiner's name must be escaped as \\\\{{ and \\\\}}: {rtf}"
        );
        // And the raw (unescaped) name must never appear -- that would mean
        // it leaked through as live RTF control syntax instead.
        assert!(!rtf.contains("Backup\\Examiner {Lead}"));

        // Sections render_html always renders must appear here too.
        for needle in [
            "Evidence Sources",
            "Result Completeness",
            "Artifact Statistics",
            "Findings / Bookmarks",
            "Timeline Highlights",
            "Chain of Custody",
            "Declaration",
            "Methodology",
        ] {
            assert!(
                rtf.contains(needle),
                "RTF missing always-on section: {needle}"
            );
        }
        // And every populated optional section.
        for needle in [
            "Executive Summary",
            "File Overview",
            "Evidence Integrity",
            "Web History",
            "Notable Hash Matches",
            "Known-Good",
            "Values Traced Across the Evidence",
            "Investigative Leads",
            "Geolocation",
            "Timeline",
            "Processing Log",
            "Limitations and Qualifications",
            "Glossary",
        ] {
            assert!(
                rtf.contains(needle),
                "RTF missing populated section: {needle}"
            );
        }
        // A FAILED integrity check must say so, not just BASELINE.
        assert!(rtf.contains("MISMATCH"), "{rtf}");
        // A completeness shortfall must be stated.
        assert!(rtf.contains("INCOMPLETE"), "{rtf}");
    }

    /// The XML output parses with a real parser (not string-matched) and
    /// round-trips a name containing `<`, `&` and `"` correctly.
    #[test]
    fn xml_parses_and_round_trips_adversarial_text() {
        let data = full_report_fixture();
        let xml = render_xml(&data);

        use quick_xml::events::Event;
        use quick_xml::reader::Reader;

        let mut reader = Reader::from_str(&xml);
        reader.trim_text(true);
        let mut found_artifact_name = None;
        let mut in_artifact_name = false;
        let mut depth = 0i32;
        loop {
            match reader
                .read_event()
                .expect("the XML must parse with a real parser")
            {
                Event::Eof => break,
                Event::Start(e) => {
                    depth += 1;
                    if e.name().as_ref() == b"artifact_name" {
                        in_artifact_name = true;
                    }
                }
                Event::End(e) => {
                    depth -= 1;
                    if e.name().as_ref() == b"artifact_name" {
                        in_artifact_name = false;
                    }
                }
                Event::Text(t) if in_artifact_name => {
                    found_artifact_name = Some(t.unescape().expect("valid XML text").into_owned());
                }
                _ => {}
            }
        }
        assert_eq!(depth, 0, "every opened element must be closed");
        assert_eq!(
            found_artifact_name.as_deref(),
            Some("Report<Name>&\"Quote\""),
            "the bookmark's artifact_name must round-trip through XML escaping exactly"
        );

        // Sections render_html always renders must appear here too.
        for tag in [
            "<evidence_sources>",
            "<result_completeness>",
            "<artifact_statistics>",
            "<findings_bookmarks>",
            "<timeline_highlights>",
            "<chain_of_custody>",
            "<declaration>",
        ] {
            assert!(xml.contains(tag), "XML missing always-on section: {tag}");
        }
        // And every populated optional section.
        for tag in [
            "<executive_summary>",
            "<file_overview>",
            "<evidence_integrity>",
            "<category_sections>",
            "<notable_hash_matches>",
            "<known_good_hash_matches>",
            "<traced_values>",
            "<investigative_leads>",
            "<geolocation>",
            "<timeline total=",
            "<processing_log>",
            "<limitations_and_qualifications>",
            "<glossary>",
        ] {
            assert!(xml.contains(tag), "XML missing populated section: {tag}");
        }
        assert!(xml.contains("MISMATCH"), "{xml}");
        assert!(xml.contains("INCOMPLETE"), "{xml}");
    }

    /// An empty `ReportData` omits the same sections `render_html` omits for
    /// one (no bookmarks, no leads, no traced values, ...) -- and, just as
    /// importantly, does NOT omit the sections `render_html` renders
    /// unconditionally. `render_html` prints "Findings / Bookmarks" with
    /// "None recorded" even when `bookmarks` is empty (it does not omit the
    /// heading), so the new renderers must match that, not the more
    /// intuitive-sounding "omit when empty" for every section alike.
    #[test]
    fn empty_report_omits_optional_sections_in_both_new_formats() {
        let data = ReportData::default();
        let rtf = render_rtf(&data);
        let xml = render_xml(&data);

        for needle in [
            "Executive Summary",
            "File Overview",
            // Not the bare phrase: the always-on Methodology footer mentions
            // "the Evidence Integrity section" in its BASELINE explanation
            // regardless of whether the section itself renders, so the
            // check has to target the heading specifically.
            "\\fs28 Evidence Integrity\\b0",
            "Notable Hash Matches",
            "Known-Good (KFF) Hash Matches",
            "Values Traced Across the Evidence",
            "Investigative Leads",
            "Geolocation",
            "Processing Log",
            "Limitations and Qualifications",
            "Glossary",
        ] {
            assert!(
                !rtf.contains(needle),
                "RTF must omit empty section: {needle}"
            );
        }
        // "Timeline" (the full, unbounded listing) is distinct from "Timeline
        // Highlights" (always rendered) -- checked as an exact heading, since
        // "Timeline Highlights" contains "Timeline" as a substring.
        assert!(
            !rtf.contains("\\fs28 Timeline\\b0"),
            "RTF must omit the empty full Timeline section: {rtf}"
        );

        for tag in [
            "<executive_summary>",
            "<file_overview>",
            "<evidence_integrity>",
            "<category_sections>",
            "<notable_hash_matches>",
            "<known_good_hash_matches>",
            "<traced_values>",
            "<investigative_leads>",
            "<geolocation>",
            "<timeline total=",
            "<processing_log>",
            "<limitations_and_qualifications>",
            "<glossary>",
        ] {
            assert!(!xml.contains(tag), "XML must omit empty section: {tag}");
        }

        // Sections render_html renders even when empty must still appear.
        assert!(rtf.contains("Findings / Bookmarks"), "{rtf}");
        assert!(rtf.contains("None recorded"));
        assert!(xml.contains("<findings_bookmarks>"), "{xml}");
        assert!(xml.contains("<evidence_sources>"), "{xml}");
        assert!(xml.contains("<result_completeness>"), "{xml}");
        assert!(xml.contains("<timeline_highlights>"), "{xml}");
        assert!(xml.contains("<chain_of_custody>"), "{xml}");
        assert!(xml.contains("<declaration>"), "{xml}");

        // And the XML must still parse even though most sections are absent.
        use quick_xml::events::Event;
        use quick_xml::reader::Reader;
        let mut reader = Reader::from_str(&xml);
        reader.trim_text(true);
        while reader
            .read_event()
            .expect("empty-report XML must still parse")
            != Event::Eof
        {}
        // And the empty RTF must still be a balanced document.
        let opens = rtf.matches('{').count();
        let closes = rtf.matches('}').count();
        assert_eq!(
            opens, closes,
            "unbalanced RTF braces on empty data: {opens} vs {closes}"
        );
    }
}
