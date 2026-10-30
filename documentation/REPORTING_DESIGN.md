# Reporting

The report is the only part of Séance a court sees. Everything else — the
parsers, the layers, the admission gates — exists so that this document can say
something a witness can be cross-examined on and have it hold.

That framing decides the design. A report is not a dump of findings with
formatting applied. It is a statement about what was examined, by what method,
with what limitations, by whom, and it has to survive an opponent reading it
line by line looking for a claim that outruns its evidence.

---

## The principle everything else follows from

**A report must never be silent about a limitation that would change how a
finding is read.**

The most dangerous sentence in a forensic report is the one that is not there.
When a listing is truncated, a parser gave up halfway, or a layout came from a
source nothing corroborated, a reader who is not told assumes the ordinary case
— that the listing is complete, the parse succeeded, the method was the usual
one. That assumption is invited by the silence, and it is the tool's fault, not
the reader's.

So limitations are **gathered, not authored**. A qualification an examiner has
to remember to write down is one that goes missing from the report where it
mattered most. Modules record what they did while they were doing it; the report
collects those records. Nobody has to notice.

---

## What the document contains, in order

The order is an argument, not a layout. A reader meets the summary, then the
evidence, then the findings, then what qualifies them, then the vocabulary, and
finally the declaration that attests to all of it.

| Section | What it establishes | Omitted when |
|---|---|---|
| Executive Summary | A synthesised narrative of the examination | never (auto-generated) |
| File Overview | FTK-style counts: total, deleted, encrypted | no filesystem data |
| **Result Completeness** | What was *not* read, and why | nothing incomplete |
| Evidence Sources | What was examined, with acquisition hashes | never |
| Evidence Integrity | Acquisition hashes vs. later recomputation | no checks recorded |
| Artifact Statistics | Counts by category | never |
| Notable / Known-Good Hash Matches | Both directions of hash classification | no matches |
| Findings / Bookmarks | What the examiners placed in the case's **shared** bookmarks, each naming its folder by the whole path (`Parent / Child`; a chain that cannot be followed to the top is marked `…/`). Personal bookmarks (§3.15) are never listed; when any exist and are not in the shared set, the section states how many were excluded (in XML always, as `<personal_bookmarks_excluded>`, 0 included; in the XLSX workbook always as the Summary row `Personal Bookmarks Excluded`, 0 included, and, when any were excluded, as the last row of the Bookmarks sheet, which is then kept even with no shared bookmark) — never their notes or whose they are | none marked |
| Communications Network | Who exchanged messages with whom, as a figure and two tables | never — one of three states is always printed (below) |
| Feature Histograms | The most-common values each feature scan found, with every ceiling stated | never — the same three states |
| **Values Traced Across the Evidence** | Values the examiner pinned, with both answers | none pinned |
| **Investigative Leads** | What *Séance* flagged, by rule | the build carries no checks |
| Geolocation | GPS fixes, with a truncation flag | no points |
| Timeline Highlights / Timeline | Dated occurrences, with case-wide totals | no events |
| Chain of Custody & Audit | The tamper-evident action log | no entries |
| Processing Log | Which modules ran, what they produced, what failed | no runs |
| **Limitations and Qualifications** | How the method qualifies the findings | nothing to qualify |
| Glossary | Terms a non-practitioner will not know | empty |
| **Declaration** | Statement of truth, signed | **never** |

Five of those carry most of the evidential weight, and all five are about
honesty rather than content.

### Values Traced Across the Evidence, and why it carries two answers

The pivot — "show me everything that touches this address" — is the move an
examiner makes constantly, and its answer is a transient panel.
Nothing else carries it into the report, so it would be either re-run while writing or
transcribed into prose, where nothing could check it. §5.13 closed that: an
examiner pins the answer, and the section renders it.

**Two answers travel with every pinned value**, and that is the whole design of
the section:

* **what the pivot said when it was pinned** — the snapshot, stored verbatim
  with the examiner's name and the moment; and
* **what the same value says at the time the report was produced** — re-run
  through the same code path the screen uses.

A section showing only the first would describe a case that has since grown. A
section showing only the second would quietly say something different from what
the examiner saw, with nothing to show that it had changed. Where the two
differ, the difference is the fact worth having, and the section states it:
*"19 artifact(s) now reference this value, against 11 when it was pinned. The
case answered this question differently on the two dates."*

Three further rules:

1. **An unchanged value says so.** Silence would leave the snapshot reading as
   current, which it is only until the next ingest.
2. **A re-check that could not run is reported as that, never as a zero.** A
   build with no search index cannot ask the question again; "we could not look
   again" and "it matches nothing now" are different facts, and the second must
   never stand in for the first. A pin whose re-check failed still reaches the
   report — the snapshot is the examiner's assertion either way.
3. **A capped snapshot says its per-kind counts are a sample.** The pivot
   groups at most 5,000 matches, so a common value's per-kind figures do not add
   up to its total. A sample presented as a total is the defect class this
   project treats as HIGH.

It is **not** the same section as `Findings / Bookmarks`, and not the same as
`Investigative Leads` either: the tool answered the question, the examiner
decided the answer belonged in the document. The XLSX export carries a `Traced
Values` sheet with one row per (value, record kind), so the workbook can be
sorted by either.

### Investigative Leads, and why they are not "Findings"

`Findings / Bookmarks` is what the **examiner** marked. `Investigative Leads`
is what **Séance** flagged, by rule, and the two are separate sections because
they are separate kinds of claim. Part VI of [`ROADMAP.md`](../ROADMAP.md) sets
the condition: a lead may not be rendered beside a parsed artifact as though
the two were established the same way. Everything else in this document is a
transcription of the evidence or an examiner's own judgement; a lead is the
tool's own assertion that a pattern deserves attention.

Four rules follow, and none of them is presentation:

1. **The observation, the inference and the qualification are three labelled
   blocks, in every format.** The observation is a fact a reader can check
   against the artifact it names. The inference is what the pattern *may*
   indicate and is opinion, labelled "Séance's reading, not a fact". The
   qualification states what the lead does **not** establish. A renderer that
   ran them into one paragraph would undo the distinction, and a reader who
   took the second for the first would have been misled by the report rather
   than by the evidence. `seance_reporting::ReportLead` keeps them apart as
   three fields so a renderer cannot merge them by accident.
2. **The section opens with `LEADS_PREAMBLE`**, which is a constant and not a
   per-format string. It says the items were raised by rule, are not findings
   of fact, and have not been corroborated by any independent means.
3. **Every lead is graded** — Strong, Notable or Weak — and the grade is about
   how much room there is for an innocent explanation, never a score. "Strong"
   means the pattern is hard to produce by ordinary use of the machine. It does
   not mean anything was established, and the Limitations entry says so in
   those words.
4. **The checks the build carries are listed under the leads, whether or not
   any fired.** An empty section means one of two completely different things —
   nothing matched the checks present, or nothing here looks for what the
   reader is after — and while §2.2 is being built out the second is usually
   the truth. A report that cannot tell them apart invites the first reading.

The Limitations entry is **generated from the presence of the section**, by
`seance_reporting::leads_qualification`, rather than supplied by the examiner:
there is no code path that produces the leads without qualifying them. It
states how many leads there are, how many rules produced them, that no
independent method corroborated any of them, that a Strong grade establishes
nothing, and that the absence of a lead about a pattern is not evidence the
pattern is absent. Where a whole-case check could not be run — the two that
compare the case against itself need a filesystem — the reason is carried into
that entry verbatim from the findings surface, so the report and the screen
cannot drift.

The XLSX export carries both an `Investigative Leads` sheet and a `Lead Checks`
sheet, separate from `Bookmarks`. A spreadsheet is the easiest place to lose
the distinction — a reader sorts the rows and the provenance is gone — so the
three text fields are three columns and each header says which kind it holds.

One asymmetry is stated rather than left to be found: the two whole-case leads
are **computed when the report is produced**, not raised during ingest, so they
have no artifact of their own and a reviewer can re-open only the subject each
names. Each such row says so on its face ("computed for this report; not
stored as an artifact"), because a citation nobody can follow is worse than one
labelled as such.

### Result Completeness

States what could not be read. A section marked incomplete lists a *subset* of
what the evidence holds, and the glossary says so in as many words: *the absence
of an item from such a listing is NOT evidence that the item was absent from the
evidence.*

Truncation is tracked per source rather than globally, because "the geolocation
list is capped" and "the timeline is capped" are different disclosures and a
reader needs to know which findings each one touches. Capped listings state
"at least N" rather than a total nobody counted.

**A source whose processing never finished is listed here too.**
An ingest a stopped server or a cancellation cut short leaves the source
artifact stamped with the same incompleteness pair a parser writes
(`inventory_incomplete` / `content_incomplete`, reason `ingest_interrupted`)
and a sentence saying how many artifacts were recorded before it stopped and
that what the walk had not reached is absent from the case, not from the
evidence. It is gathered like every other shortfall, so a report over such a
case cannot present the partial count as the source's contents. The stamp is
written by the next server start, which is the first moment anything can know
the walk did not end.

**A timeline event that could not be placed is counted and disclosed.**
A `TimelineEvent` whose timestamp is missing or unparseable is kept as an artifact
but has no row on the timeline. The census counts these (`timeline_omitted`,
superseded records excluded), the completeness statement names the count and cannot
read "verified" while any exist, and the Timeline Highlights and
Timeline sections say that the timeline is a subset of the events the evidence
contains and that an event's absence from it is not evidence of absence. The XLSX
Summary sheet carries a "Timeline Events Omitted" row when the count is above
zero.

**A shortfall a later run answered is excluded, and the exclusion is stated.**
A record can be settled after it was written: a password opens a backup that was
recorded as unreadable, a symbol pack arrives after a memory pass gave up. The
earlier record is kept — that the refusal happened is part of the case — and
marked superseded, which takes it out of every figure in this section. The
section then says how many statements were answered that way, so a reader can
tell "nothing was ever incomplete" from "something was, and it was resolved".
Without that line a report generated after a successful decryption would count a
backup the case holds thousands of artifacts from among the evidence that was
never recovered.

The same marking covers a **module run again on an artifact**. Re-running a
parser — after a password, a fetched symbol pack, or a fixed parser — writes a
second set of records beside the first, which would make every count drawn
from that case the sum of both runs. What the earlier run of the same module
wrote under the same artifact, of the same kind, is marked superseded by the
run that answered it: kept as history, excluded from the figures, and shown in
record tables under a `Status` column whose badge names the re-run.

**A carve that ended short of its minimum size** is published, not
dropped, and the carving summary counts it as `total_below_minimum` (with a
`below_minimum_breakdown` by signature), apart from `total_carved`. The record
carries `carving_below_minimum: true` and `carving_validated: false`, and claims
only that a header of that format was found and the bytes after it ended before
the length the format expects. It is not a recovered file, and a section that
counts recovered files must not include it.

### Limitations and Qualifications of the Examination

Distinct from completeness, which says what was *not read*. These say something
**was** read, and by what means — where a step rested on a weaker footing than
the alternative, or on a source nothing independent corroborated.

Each entry carries a subject, a statement written to be read aloud, and what it
bears on. The statement has to say what was done, why it was done that way, and
what a reader should therefore not conclude; a sentence that only names a
technique tells a court nothing about its weight.

Empty renders nothing, and that is the common case. A qualification invented for
every examination is one a reader learns to skip, and then the one that matters
is skipped too.

**The first source is symbol provenance on Linux memory images.** When no symbol
file describes the captured kernel, Séance recovers the layouts from the image
itself (see [LINUX_DESIGN.md](LINUX_DESIGN.md)). That is a sound way to analyse
an image nobody has symbols for, and it is *not* the same footing as a matched
file: the cross-check that would normally test the layouts compares them against
the very information they were built from, so it is not performed. The report
says exactly that, names the offsets the structures were found at, and gives the
SHA-256 of the generated symbol document — which stands in for the file path a
defence expert would otherwise be handed, and is reproducible from the same
image.

**The evidence-loss qualification is worded per cause.** `seance_core::evidence_loss` counts three losses
separately and the statement names each in its own words: artifacts the writer could not persist ("could not be
written to the case database"), artifacts found but never processed because the task queue could not read them
back (no mention of the database, and the re-ingest sentence is conditional on the fault not recurring), and
processing-log rows that could not be saved (the artifacts those modules produced are unaffected, but the account
of which modules ran is incomplete). A report must not state one cause in another's words.

### Timeline Highlights carry the note and the examiner; the full timeline does not

A highlight is in the report **because an examiner tagged it**, and the note they
wrote is the only place the reason lives. Both were being dropped: the tagged
events were mapped through a closure that discarded the note and the author, so
the section listed occurrences with their justification removed. HTML, PDF and
the workbook carry both, with a caption saying that an em dash means the
event was tagged with no note written — otherwise a blank cell reads as a note
that was lost rather than one that was never made.

**The full timeline deliberately does not gain those columns.** Every event in
the case appears there whether or not anyone ever looked at it, so a blank note
beside each one would read as *examined, nothing to say* — a claim nobody made.
`ReportTimelineEvent` serves both populations and its `examiner` / `note` fields
are always absent in the full listing; the renderers must not offer columns for
them there. This is the general rule in a specific case: a field that is
meaningful for one population and vacuous for another must not be rendered
identically for both.

### The Declaration

**Always rendered.** A report issued without a statement of truth is one whose
author has not put their name to its contents.

The default wording follows the form English civil procedure expects of an
expert (CPR Part 35 PD 35 §3.3): a confirmation that the author has made clear
which matters are within their own knowledge, that those are true, and that the
opinions are their true and complete professional opinions. It closes with a
clause specific to this tool — *where the analysis could not be completed, or
where a result is partial, this report states so explicitly rather than omitting
the matter* — which is the principle above, made an undertaking.

**The wording is overridable and deliberately so.** The required form differs by
jurisdiction. A tool that hard-codes one jurisdiction's statement produces a
document that is wrong everywhere else, which is worse than producing none,
because it looks right.

---

## Things that are not configurable

A short list, and each entry is there because making it optional would let a
report go out that a court should not accept.

**Times are UTC, stated.** `TIMEZONE_STATEMENT` renders in every report and
cannot be turned off. An unqualified timestamp is challengeable on its face: the
same instant is a different wall clock in every jurisdiction the evidence may
have crossed, and daylight saving moves it again. A report that does not say
which clock it is using has not stated its times.

**A skip is never a pass.** This runs from the test harness
([VALIDATION.md](VALIDATION.md)) through to the report. A check that did not run
is reported as not having run, never folded into the successes.

**The examiner is named.** `ExaminerDetails` carries role, organisation, contact
and qualifications, because admissibility of expert evidence turns on the
examiner's competence as much as on the method — FRE 702 in the United States,
CPR Part 35 in England and Wales both require it stated. Absent fields stay
absent rather than defaulting: a stated qualification the examiner does not hold
is far worse than a missing one.

**Revision numbers are absent rather than guessed.** Séance does not track how
many times a case has been reported on, so `ReportIdentity::revision` is
optional and renders nothing when unset. A document calling itself "Revision 1"
when it is the third to leave the building is a false statement about
disclosure.

---

## Output formats

`render_html`, `render_pdf`, `render_rtf`, `render_xml` and `render_docx` render the same `ReportData`, the same sections
under the same conditions in the same order, from the same statement helpers.
All five are exercised by the same tests, because a section that reaches one
and not the other is a disclosure that exists for whoever opened the right
file. Each has a `render_*_with(data, extras)` form that takes the
`ReportExtras` the API gathers beside the report (the communications network
and the feature histograms); the plain form renders those sections in their
"not gathered" state. `GET /cases/{id}/export/{html,pdf,rtf,xml,docx}` all use
the `_with` form (`CORE_DESIGN.md` §4.4a).

**DOCX.** A deterministic ZIP of `[Content_Types].xml`, `_rels/.rels`,
`word/document.xml`, `word/_rels/document.xml.rels`, `word/styles.xml` and one
`word/media/figureN.svg` per figure, with the WordprocessingML written by hand
rather than through a document library. User text goes through `xml_escape`
(the five reserved characters escaped, the C0 controls XML cannot carry
stripped rather than emitted) and newlines become `<w:br/>`. Two renders of the
same case are byte-identical (`figures_test.rs`). It opens and renders both
figures in LibreOffice and reads under `pandoc`; **Microsoft Word has not been
tried here**. The one known limitation is the figure: it is embedded as an
SVG-only picture (`svgBlip`, read by Word 2016+ and LibreOffice 7.4+), so an
older Word shows an empty picture frame. The figure's data table beneath it
carries the numbers regardless, so no reader is left with a frame and nothing
else.

**No EML report, deliberately.** No report is rendered as
an email container (`message/rfc822`), because wrapping the report in an `.eml`
adds nothing that attaching the PDF does not, and a report in the same file type
as recovered mail invites someone to treat the container as evidence. The other
reading, downloading one recovered message as a native `.eml`, is evidence
export and not report generation. It is not a report format and this document
does not cover it. An `.eml` file found on the evidence is a file like any
other: its original bytes download unchanged through
`GET /cases/{id}/artifacts/{artifact_id}/content`. Séance has no `.eml` download
for a message parsed out of PST, OST, MSG, mbox or Apple Mail. Building one
would mean reconstructing RFC 5322 from the parsed fields, and a reconstruction
would have to be labelled as one so nobody hashes it as the original. That work
is not scheduled and is not claimed.

### Figures, and what a caption may claim

Two figures are computed from the report's own data, never from anything the
report does not also list: the communications network, drawn in the
Communications Network section, and events over time, drawn in the Timeline
section from the listed (bounded) timeline events. They are numbered in order
of appearance, so a report whose network was not computed or is empty carries
the timeline figure as Figure 1. HTML carries them as
inline SVG, DOCX as the SVG picture with the data table beneath, PDF as vector
drawing; RTF and XML carry no drawing and print the caption under the heading
"Figure N (data; this format carries no drawing)" beside the same tables, so a
reader of those formats has every number the drawing shows.

**Every caption states what the figure was computed from and what it omits**,
and is emitted verbatim under the figure in every format, so a caption is a
claim about what the figure carries and is held to the same standard as a
section:

* The timeline figure names the number of listed events it was computed from,
  the number plotted, the bucket count and width (epoch-aligned, not calendar
  months, and the caption says so), the span, the events not plotted because
  their timestamp would not parse, and — when the listing was capped — the
  events the case holds beyond the listed slice. The bucket width is the
  coarsest on a ladder (hours to years) that still gives at least twelve bars,
  which bounds the figure at 135 bars below the ladder's top rung — a number
  derived from the ladder by a test, not chosen — and the caption states the
  bucket count it actually has.
* The communications figure draws at most 40 participants (those party to the
  most exchanges, out of the total the caption names); with 16 or fewer drawn
  it names each of them, and above that every drawn participant is numbered by
  its rank in the Participants table instead, because forty names round a ring
  overwrite one another. It **labels a link
  with its exchange count only when the figure has 24 links or fewer**
  (`MAX_LABELLED_LINKS`). Above that no link carries a count, width scales with
  exchanges, and the caption says exactly that and points at the Links table —
  it does not say "each link is labelled". The caption is
  written from the same branch that decides the labelling. A link is "a record
  that two parties exchanged a message, not a relationship", and the caption
  says so.
* An empty graph makes no figure; a graph that was not computed prints the
  "not computed" sentence and no figure.

### The most-common-values section, and the capped-note rule

The Feature Histograms section renders the `FeatureHistogramSummary` records
`plugin.bulk.features` publishes (`CORE_DESIGN.md` §2.3), one block per record,
in three states that are always told apart: **not gathered** (the extras
carried none — "nothing here says whether the scanner ran" — followed, when the
API asked and was refused, by `Reason:` and the refusal in words; a case holding more than the 1,000 records a report
carries says so on the page, with the count and the ceiling, in every format,
and the XML carries it as a `<reason>` element), **gathered and
none found** (the case holds no such record — which cannot be told from "ran
and found nothing", because a scan that finds no hit publishes no histogram, and
the sentence says so — and that a scan that was capped or
could not read part of its source still publishes a `FeatureSummary` stating
what it read, while one that read everything and found nothing publishes no
record at all), and one or more histograms. Each histogram prints, in
this order: its `INCOMPLETE` statements, one per ceiling the record says it hit
(the byte ceiling with the bytes scanned; a short read — part of the source
would not read — with the bytes read and the size the source declared, in place
of the byte-ceiling sentence. The sweep
resumes past an unreadable range, so the sentence does not call the bytes read
a prefix and points at the `FeatureSummary` that lists the unreadable ranges;
the distinct-value ceiling with the
exact number of hits counted but not tallied), the record's own `note`
verbatim beside them; the totals line, with the distinct count prefixed "at
least" when the record is capped; the by-kind table (kind, hits, distinct
values); and the **Most-common feature values** table (kind, value, count),
preceded — when the record holds more distinct values than it lists — by
"Showing the N most common of M distinct values (the table lists at most 100);
K distinct value(s) are not listed." The rule the tests pin
(`feature_histogram_test.rs`): **a capped histogram is never rendered as
exhaustive** — its note is printed, its distinct total is a floor, and a longer
table than shown is disclosed with its numbers, in every format. A count is
also introduced for what it is: the number of times a selector matched those
bytes in the source, not the number of files holding the value, and a match in
unallocated space or memory is not evidence the value was used.

### PDF field lines

A PDF field line prints its label in bold at the margin and its value 55 mm
in. A label whose printed width (measured with Helvetica-Bold's own glyph
widths) reaches the value column — a bookmark on an artifact with a long name,
a lead title, a long traced value — has its value set on the line below
instead, at the same column, so a value is never printed over its label
(pinned by `pdf_never_prints_a_field_value_over_a_long_label`). A
label wider than the whole text column is not wrapped and can still run past
the right margin.

### PDF signing

`pdf_signing` attaches an X.509 signature when a certificate and key are
supplied. Two facts about the signed file are worth stating (`ROADMAP`
§5.10): the signer rewrites the document with **one complete cross-reference
section** — the source trailer's `Prev` / `XRefStm` chain is dropped, because in
the rewritten file those offsets point at nothing and a reader following them
found no xref there (qpdf reported the signed copy damaged; lopdf refused to
reopen it) — and it signs in place, so the serialised PDF is no longer held
twice while the signature is computed. The `ByteRange` hole is exactly the
`Contents` string object, both delimiters included, as PDF 32000-1 §12.8.1
expects.

### Quoting a recovered record

A report that quotes a record recovered from space the live structure no
longer vouches for quotes its provenance with it, or does not quote it. The
record types exist for this (`CORE_DESIGN.md` §2.3), and the rule per type:

* An **`EvtxRecoveredLogEntry`** is quoted with its `recovery_source`
  (`carved_chunk` / `chunk_slack` / `loose_record`), its `chunk_header` state,
  both checksum states and, when set, the `borrowed_template` block and the
  `incomplete_substitutions` list — a partial record is a partial record in the
  report too. It is never counted among, or listed beside, `EvtxLogEntry`
  records as though the log's own directory reached it.
* A **`RecoveredRegistryKey`** is quoted with `key_path_is_inference`,
  `key_path_complete` and, when present, `live_namesake`; its subkey and value
  counts are "as declared", never "as found". A **`RecoveredRegistryValue`** is
  quoted with its `data_basis`.
* A **message read from a PST or OST** is quoted with what the record says it
  lacks. Four things on the record change what may be claimed, and none is
  dropped from the quotation: `content_incomplete` with its reason (a message
  published from the eight-property fallback read says `read_fallback` and names
  the failed full read, and has no body, recipients or attachment inventory to
  quote; an HTML body decoded with replacement characters says
  `body_decoding_lossy` and its text is not the stored text; a body past 64 KiB
  in either form says `body_truncated`); `sent_on_behalf_of`, which names the
  principal when the sender and the party represented are different people, so
  `from` and `from_name` are the sender's and the principal is never quoted as
  the author; `deletion_status` (`undecided` is not "deleted"); and, on a
  recovered record, its `recovery_gaps` and each `recovery_other_versions`
  entry's `read_error` (every version that was tried and failed carries its
  own). A summary that says `content_incomplete` for `cap_reached` on the
  recovery listing means deleted messages beyond the cap were not listed, not
  that the live walk was short. A summary's `unreferenced_pages_unvalidated`,
  `unreferenced_blocks_unvalidated` and `property_contexts_not_decoded` count
  what the scan matched and could not read: "no more deleted messages were
  found" may not be quoted past a non-zero one. A folder path beginning
  `(path truncated at depth limit)` or `(parent node 0x… not found)` is a path
  whose chain did not reach the store's root.
* A **schema-support disclosure** (`ParserStaleWarning` and the per-app
  `<App>Incomplete` records) is two different things and the Result
  Completeness section keeps them apart: a schema version outside or absent
  from the parser's validated range is a **disclosure** — "this store's schema
  version N is outside the range this parser was validated against (R),
  validated on <files>" — and never a claim that records were missed when every
  required field resolved; a required logical field no column resolved, or an
  absent table, **is** an incompleteness claim, stated by the logical field and
  table, not by the physical columns tried. Neither says the parser is current
  with the app: there is no tracking cadence, only a declaration of being
  behind. **Two paths produce these records, and a report says only what the
  record's path recorded.** The app-store parsers (the chat apps, Android SMS
  and call log, the contacts family) carry schema support (one shared
  `seance_sqlite_util::adopt` module per record shape): they
  read the version as found / not recorded (a `PRAGMA user_version` of 0) /
  undetermined, resolve each logical field to a column, and their warning names
  the table, the unresolved fields and the records recovered. The iOS Safari
  and HealthKit parsers use the shared `seance_sqlite_util::stale`
  `check_schema_version` instead: the same three answers (`SchemaOutsideValidated`
  and `SchemaVersionNotRecorded` with no incompleteness claim,
  `SchemaVersionUndetermined` under `unresolved_structure`), each naming the
  file the range was read from, but no
  table, field list or record count, because those parsers resolve no columns —
  a renamed column makes the store `DatabaseUnreadable` instead. The
  shared path ranks a version of 0 as not recorded, never as older than the
  range, and files a record for a pragma that would not read. A version outside
  the range is a disclosure and not a claim of incompleteness. The one
  out-of-range case that claims is a Chromium store whose own `meta.last_compatible_version`
  is past the validated maximum.
  Every path files these records under one vocabulary
  (`ROADMAP` §5.11): `subtype` `parser_stale`, `warning_class`
  `ParserStaleWarning`, and the same `status` for the same finding
  (`SchemaOutsideValidated`, `SchemaVersionNotRecorded`,
  `SchemaVersionUndetermined`, `SchemaFieldsUnresolved`, `SchemaNotRanged`,
  `SchemaOptionalFieldsUnresolved`, `SchemaTableAbsent`); the chat apps still
  file under their own `<App>Incomplete` type. Whether a record is a
  disclosure or a claim is read from its `content_incomplete` pair, never from
  its subtype. `SchemaUndetermined` is emitted only as the separate
  catalogue-probe marker (`seance_sqlite_util::SchemaProbe`: a table or column
  probe would not answer; `subtype` `parse_incomplete`, both incompleteness
  pairs). It is a claim that the store's structure could not be read, not a
  version finding, and a report must not read it as one.
  **What the unified status deliberately gives up:** `SchemaOutsideValidated`
  does not say which side of the range the store fell on, so a filter on
  `status` cannot separate a newer app from an older one. The direction survives only in the record's prose
  `detail` sentence (and in the recorded version beside the validated range),
  so a report or export that needs "newer app" versus "older app" must compare
  the recorded version against the range, not read the status.
* A **byte-sweep result** (`seance_search::sweep`, `POST /cases/{id}/search/sweep`) may be
  reported as "not found" only when its `complete` flag is true; otherwise the
  report quotes its `coverage_statement`. A hit's encodings are the list on the
  hit, an ASCII hit is not reported as "UTF-8" alone, a UTF-16 hit's folded
  opposite-endian twin is reported as the alias it is, the hit's region
  (live / slack / unallocated / recovered / raw) is stated, and grouped counts
  are shown beside ungrouped ones. The route offers as `slack` only the file-slack
  regions the NTFS, FAT, exFAT, ext4, HFS+ and APFS parsers publish, and its
  `slack_statement` says what that leaves out — slack on other file systems, all-zero
  tails, files past the per-volume ceiling; a report quoting a sweep says that too,
  and says that a slack scope searched no slack on a volume with no slack regions.

Timeline, KML, XLSX and body-file exports are separate products of
the same data (`timeline_report`, `kml`, `xlsx`, `body_file`) — KML for mapping
tools, and a body file for `mactime` interoperability. Each of the four is
reachable: the XLSX report from the dashboard's **Export XLSX** and the REPL's
`/export report xlsx` (`GET /cases/{id}/export/xlsx`), and the body file from
`GET /cases/{id}/timeline/export/body`, the REPL's `/export timeline body`
and the Files page's **Export whole case as
mactime body file** (`ROADMAP` §5.12). That button sits above the Files page's
toolbar rather than among the timeline's exports, because every timeline export
honours the filters on screen and this one cannot; the sentence beside it says
the file is every file in the case, from every source, and ignores the page's
filters. The client reports the download saved only when its last line is the
verdict comment and that verdict is `COMPLETE`, quoting the line on screen; a
whole file whose verdict is `INCOMPLETE` and a file cut short before its verdict
are both shown as errors, and a cancelled save dialog is said to have written
nothing.

### The timeline exports, and what each states on its face

The timeline view exports its filtered set three ways. Each is an exhibit on
its own, so each states its population, its order, its timezone convention and
its rendering rules inside the file, not only in the HTTP response.

**Timeline PDF** (`timeline_report`, bounded to `TIMELINE_PDF_EXPORT_LIMIT`
newest events, laid out in memory):

* Its population line is `Events in this export: N of M matching this case and
  filter (newest first; …)`, where M is a `COUNT(*)` taken with the same
  filters, separately from the bounded fetch and immediately AFTER it.
* **Completeness is stated from the fetch, never re-derived from N and M.** The
  fetch asks for one row past the ceiling, so it knows with certainty whether it
  returned a slice, and that verdict decides the claim. Comparing the two
  figures instead was wrong, because they are two observations of a case that
  may have changed between them: a deletion landing in the gap brings M down to
  meet a slice it does not describe, and a truncated 50,000-row export whose
  count came back at exactly 50,000 printed "complete — every matching event is
  listed" three lines above a filter line saying it was truncated.
* When the fetch was truncated the line says so however the counts land, and
  names the **oldest** end as the one missing. When it was not truncated and
  N = M it says the export is complete. It never labels the slice a total — a
  400k-event case is never described as "Total Events: 50000".
* Where the two figures disagree, the line reports both, says they were taken at
  different moments, and states the direction of the change from the figures
  rather than assuming it. It never reconciles them silently, and never prints a
  negative difference.
* It states that timestamps are UTC to the second, and that sub-second
  precision and the source's own offset are carried by the CSV and JSON
  exports, not by the PDF.
* Source and Description are **wrapped, never shortened**, and the PDF says so
  in a line above the table. A value longer than the column is broken at word
  boundaries, or at character boundaries when a single token (a path) is
  wider than the column, so every character is on the page. A row that fits on
  a page is kept whole; a row taller than a page continues onto the next,
  marked `(continued)`.
* The truncation notice, when it applies, leads the filter line, and
  the filter line wraps rather than running off the page.

**Timeline CSV and JSON** (streamed, one shared drain, no row limit):

* A preamble before the first row states the case, every filter in force, the
  matching-event count taken just before the walk began, the order (newest
  first), that no row limit applies, when the export was taken, and how to read
  the file. In the CSV these are `# name,value` lines above the header, each
  padded with empty fields to the table's column count so the file is
  rectangular for a reader that does not treat `#` as a comment (`#` is not a
  comment in RFC 4180; `pandas.read_csv` without `comment='#'` raised on the
  two-field lines, and a spreadsheet import mis-columned the sheet).
  A value carrying a comma or a newline is CSV-quoted and stays one field. In
  the JSON they are the members of the top-level object, with `events` and
  then `completeness` deliberately last so a file cut short fails to parse.
* The timezone and epoch convention is stated in the file (`# timezone,…` /
  `"timezone"`): `Timestamp` is Unix epoch seconds in UTC with no offset
  applied; `Timestamp (ISO-8601 UTC)` (JSON: `timestamp_iso8601_utc`) is the
  same instant as RFC 3339 in UTC; `Subsecond Nanoseconds`
  (`timestamp_subsec_nanos`) is the sub-second part, 0 for whole-second sources;
  `Source UTC Offset Seconds` (`source_utc_offset_seconds`) is the offset the
  source itself recorded, empty in the CSV and absent in the JSON where the
  source supplied a bare Unix timestamp. The raw epoch column stays, because it
  is the evidence; the ISO column is a rendering of it.
* Every export ends with a verdict row whose first cell begins
  `### END OF EXPORT ### VERDICT:` — the same marker the search export uses, so
  one check covers both. **The row is always quoted**, whether or not its text
  needs it, and that quote is the test: the last line of a whole CSV begins
  `"### END OF EXPORT ### VERDICT:`. A hit row cannot begin a line that way —
  its first column is a UUID, and a quote inside a quoted field is doubled — so
  an evidence file named for the marker cannot forge the row, and the
  marker's appearance in the preamble's own reading note, which a download cut
  off after two kilobytes still contains, is not mistaken for it.
  In the JSON the test is the `completeness` object's `statement` beginning
  with the marker, as an unescaped member, and the file ending with its closing
  brace. Each format's `how_to_read` note states its own test in these terms,
  and the web client's download check (`frontend/src/lib/download.ts`,
  `endsWithVerdict`) applies exactly that test. `COMPLETE`
  means the walk reached the end of the store's result set and the row count
  equals the count in the preamble; `COMPLETE, COUNT MOVED` means the walk
  reached the end but the two figures differ (events added or removed between
  the count and the walk); `INCOMPLETE` names the row the export failed after
  and the error, and the transfer is then aborted so a client waiting on the
  status also learns of it. The JSON carries the same facts as
  `completeness.{complete, rows, walk_reached_end, stopped_because, statement}`.
* The response also carries `X-Export-Total` and
  `X-Export-Completeness: stated-in-final-row`; as with the search export, no
  header promises completeness, because none can.

**The `mactime` body file** (`body_file`, `GET /cases/{id}/timeline/export/body`,
streamed, no row limit) is a **file** export beside the three event exports, not
a fourth format of them: one row per `FileEntry` artifact in the case,
`MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime`, the
Sleuth Kit 3.x intermediate that `mactime`, log2timeline and Timesketch read.

* It takes **none of the timeline filters**. A body file narrowed to the events
  on screen would be a file list with files missing and nothing on its face to
  say so. Its `# population` line states
  that it holds every `FileEntry` in the case, in artifact-id order, whether or
  not the file carries a timestamp.
* Each row is built from the entry's own metadata by
  `BodyFileEntry::from_file_entry_metadata`: `path` (else `relative_path`, else
  `name`), `size`, `inode` (else NTFS `record_number`), `mode` rendered in TSK's
  `r/rrw-r--r--` shape when it is a numeric POSIX mode, `uid`, `gid`, the `md5`
  the hasher merged in, and `atime`=`accessed`, `mtime`=`modified`,
  `ctime`=`changed` (else NTFS `mft_modified`), `crtime`=`created`. A deleted
  file's name carries TSK's ` (deleted)` suffix. **Nothing absent is guessed**:
  a missing, null, empty or unparseable time is `0`, which is TSK's own
  "unknown", and `mactime` skips a row whose four times are all `0`. Pipes and
  newlines in a name are replaced with spaces so a row cannot gain a field.
* `mactime`'s reader skips every line beginning `#` (`next if /^#/`, in the TSK
  4.x script) and nothing else, so `#` lines are where the export states what
  it is, the case, the `file_entries` count taken before the first row, the
  timezone convention (Unix epoch seconds, UTC, nothing shifted), which
  metadata key feeds each column, and how to read the file. The last line is
  `# ### END OF EXPORT ### VERDICT: …` — the same marker as the CSV and JSON.
  No row can begin with `#` (its first field is an MD5 or empty), so the
  verdict is unforgeable by content, and a file whose last line is not that
  verdict is a fragment. `COMPLETE` means every counted entry was written;
  `INCOMPLETE` names either the count that moved during the walk or the store
  error the walk stopped on, and in the latter case the transfer is aborted so
  a client waiting on the status also learns of it. The REPL applies the test
  to the saved file. The response carries `X-Export-Total` and
  `X-Export-Completeness: stated-in-final-row`, as the other exports do.
* There is no button for it in the web interface. The timeline page's export
  controls all honour the filters on screen and this export would be the one
  that did not; the Files page is the honest home for it and is a separate
  design.

**Timeline sheets in the XLSX case report** carry full text in every cell and
the Summary sheet states `Timeline Events (case total)` beside the listed count
when the sheet is capped; the HTML and PDF case reports caption the timeline
with `timeline_caption`, which states the case-wide total first. Those three
were already right and are unchanged.

HTML output is escaped at every interpolation. Evidence contains attacker-chosen
strings — a filename, a registry value, a process name — and a report is a
document other people open.

### Streamed exports invert the silence rule, and why they must

Everything above rests on a file that is assembled and then sent: it is either
delivered whole or not delivered at all, so **silence can safely mean
"complete"** and a report speaks only on bad news. A **streamed** export — the
search exports and the timeline CSV/JSON exports, which walk the whole match set
row by row — cannot borrow that convention. It can stop at any byte, and a connection dropped mid-download leaves
the examiner a file that is byte-for-byte a shorter *complete* one. Silence there
means nothing at all.

So a streamed export **ends with a verdict row every time, including when it is
complete**, and the absence of that row is the signal. It is the only signal that
survives the file being saved to disk and opened a week later, long after the
HTTP status has gone. A note before the first row tells the reader to look for
it, because a warning that appears only at the bottom cannot warn about a
download that never reached the bottom.

Three things follow, and each is a rule for any streamed exhibit added later:

* **The population is stated at the top and the completeness at the bottom**,
  because that is when each is known. The snapshot the rows were read from and
  the size of the match set are knowable before the first row; whether the file
  holds all of them is not, and no header may promise it.
* **A bounded count and a missing row are different claims.** A search's total
  can be a floor for reasons that do not skip a single row — a scan stopping at
  its per-page budget, a full candidate window — so a walk that reached the end
  states its row count as the exact figure and says the preamble's "at least N"
  was the lower bound it stood in for. Only an index known to be missing
  documents, or a walk that did not finish, may say rows are absent. Merging the
  two had been stamping whole exhibits INCOMPLETE with a cause that was untrue of
  them, which is the same class of error as the silence this document exists to
  prevent, pointing the other way.
* **The record of the outcome does not live only in the file.** The request is
  audited before the first byte; a second record carries how the export ended,
  written before the verdict row goes out. An export abandoned mid-download still
  leaves that record, because otherwise the only evidence of the interruption is
  in a file the examiner may discard.

The bounded, in-memory exports keep the older convention and speak only on bad
news: the records CSV carries a notice row when the filtered set is larger than
the file, and a **second, separate** notice for records whose metadata would not
parse and which were therefore never tested against the term. Two shortfalls
repaired by two different actions are two notices — narrowing the query recovers
the first and nothing recovers the second.

---

## Adding a section

1. Add the field to `ReportData`. Make it `Vec` or `Option` so that "nothing to
   say" is expressible and renders nothing.
2. Render it in **all five** renderers — `render_html`, `render_pdf`,
   `render_rtf`, `render_xml` and `render_docx` — in the same position.
3. Add a test asserting it reaches every one, *and* that an empty value renders no
   heading. A heading with nothing under it teaches a reader to skip the section,
   and the section that matters is the one they skip.
4. If it is a disclosure, gather it from what the modules recorded rather than
   requiring the examiner to supply it — see
   `seance_api::gather_method_qualifications`.

---

## What is not yet covered

Stated here rather than left to be discovered.

- **The report has no per-finding provenance chain.** A record says which module
  produced it and, on some memory stages, which structure layout it was read
  through ([MEMORY_BUILD_BINDING.md](MEMORY_BUILD_BINDING.md)); it does not carry
  that through to the rendered report, so a reader cannot ask of an individual
  line what it rests on. `MethodQualification::affects` names affected findings
  in prose, which is a coarser instrument.
- **Only five qualification sources are wired.** `gather_method_qualifications`
  publishes: evidence this process could not persist, symbol provenance on Linux
  memory, the symbol census gap when some image-derived captures carry no
  provenance statement, the decompression ceilings that governed gzip, bzip2 and
  xz containers, and the ceiling census gap when some containers were not read or
  record a ceiling with no recognised source. Other stages take weaker routes
  under some conditions — inferred layouts, carved records with no filesystem
  reference — and do not yet publish a qualification.
- **The review ledger does not reach the report.** Séance records, per
  examiner, which artifacts were opened and which were cleared, with an
  append-only history and a named denominator
  ([CORE_DESIGN.md](CORE_DESIGN.md) §4.5) — and no report section states any of
  it. A report therefore says what was found and not what was *looked at*, which
  is a different question and one a court may well ask. Deliberately not
  improvised in the meantime: a coverage figure rendered without the population
  it is counted against, or one that let opened and reviewed be added together,
  would be worse than its absence. When it is wired, the section must carry the
  ledger's own disclosure that the case-wide denominator includes rows nobody
  opens individually, so a ratio against it is a floor on coverage rather than a
  measure of it.
