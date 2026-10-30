//! CFTT Forensic String Search: the published answer key, parsed.
//!
//! # The data set, as measured
//!
//! Two raw images of exactly 2,098,028,544 bytes, each verifying against all
//! three of the publisher's hash lists, and an answer key of 921 rows.
//!
//! **The published offsets are absolute byte offsets into the whole raw image**
//! — not file-relative and not partition-relative. That was established rather
//! than assumed: fifteen occurrences of three target strings were located in
//! `ss-win-07-25-18.dd` with `grep -abo` and every one of the fifteen equalled
//! the published offset exactly. One of them, `SecretKey` at byte 15427, lies
//! *before* the first partition begins, inside the GPT partition-table region —
//! an offset that could not exist in any file-relative or partition-relative
//! scheme. The publisher's own hit dump confirms the frame independently, by
//! giving a `dd ... bs=1 skip=<offset - window>` command per hit.
//!
//! So a grader can compare the key directly against byte offsets measured on
//! the image, which is the fact the whole run rests on.
//!
//! # The row format
//!
//! `ID:term:BYTE:SECTOR:filename:fs:encoding`, seven colon-separated fields on
//! all 921 rows. The sector is `floor(byte / 512)` and is therefore redundant —
//! which makes it a free cross-check, so this parser computes it and reports a
//! row where the two disagree rather than trusting either.
//!
//! **A term may itself contain a colon.** No row in the measured file does, but
//! a parser that split on every colon and demanded exactly seven fields would
//! silently drop such a row — so the ID is taken from the left, the last five
//! fields from the right, and whatever is between them is the term.
//!
//! # `fs: unalloc` is the row that decides the grader's honesty
//!
//! Some expected hits are in **unallocated space**: row 7000 is `SecretKey` at
//! byte 15427, in `unalloc`, before any partition. A tool that searches parsed
//! records and allocated file content cannot find those, and grading them as
//! misses would report a defect where the answer is that the expectation is
//! **outside the declared search universe**. They are separated here so the
//! runner can record them as `NotAssessed` with the reason, which is exactly
//! what `CaseStatus::NotAssessed` was added for.

use std::collections::BTreeMap;

/// The filesystem field's value, which decides whether an expectation is
/// inside a tool's reach at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Locus {
    /// A named filesystem — the hit is in allocated content this tool could
    /// reach.
    Allocated(String),
    /// **Unallocated space.** Outside the universe of a tool that searches
    /// parsed records and allocated files, and graded as not-assessed rather
    /// than as a miss.
    Unallocated,
    /// A locus this build does not recognise. Reported as stored: a value the
    /// parser cannot classify must not be silently folded into either of the
    /// two above, because one of them is "gradeable" and the other is not.
    Unrecognised(String),
}

impl Locus {
    fn of(field: &str) -> Self {
        match field.trim().to_ascii_lowercase().as_str() {
            "unalloc" | "unallocated" => Self::Unallocated,
            "" => Self::Unrecognised(String::new()),
            other => Self::Allocated(other.to_string()),
        }
    }

    /// Whether an expectation at this locus can be graded against a tool that
    /// searches allocated content.
    pub fn is_gradeable(&self) -> bool {
        matches!(self, Self::Allocated(_))
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Allocated(fs) => fs,
            Self::Unallocated => "unalloc",
            Self::Unrecognised(raw) => raw,
        }
    }
}

/// Where the publisher says the term is.
///
/// Three states, all three real in the measured files:
///
/// * one byte offset, which is 914 of the 921 rows;
/// * **two or more**, comma-separated — row 6006 states
///   `4305916,7758848` for `Washington` in `FRAG-UNKNOWN`, a term whose
///   occurrence is fragmented across two locations;
/// * **none published** — four rows state the literal word `zipped`, because
///   the term is inside a compressed `.docx` and the publisher gives no offset
///   for it.
///
/// The third is why this is not an `Option<u64>` and why such a row is not
/// rejected as malformed: it is a real assertion — the term is in the image and
/// a tool that reads inside compressed formats should find it — with no
/// position to compare against. Rejecting it would lose four assertions and
/// report a higher pass rate over the remainder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Position {
    /// One absolute byte offset into the raw image.
    At(u64),
    /// Several, for a fragmented occurrence.
    Fragmented(Vec<u64>),
    /// The publisher states no offset, and what it states instead.
    NotPublished { stated: String },
}

impl Position {
    fn of(field: &str) -> Self {
        let raw = field.trim();
        if raw.contains(',') {
            let parts: Vec<u64> = raw
                .split(',')
                .filter_map(|p| p.trim().parse::<u64>().ok())
                .collect();
            // Only when EVERY part parsed: a list with one unreadable member
            // is a list this build cannot compare against, and silently
            // grading the readable half would grade a fragment as the whole.
            if parts.len() == raw.split(',').count() && !parts.is_empty() {
                return Self::Fragmented(parts);
            }
            return Self::NotPublished {
                stated: raw.to_string(),
            };
        }
        match raw.parse::<u64>() {
            Ok(n) => Self::At(n),
            Err(_) => Self::NotPublished {
                stated: raw.to_string(),
            },
        }
    }

    /// Every offset this position names, for comparison against measured ones.
    pub fn offsets(&self) -> Vec<u64> {
        match self {
            Self::At(n) => vec![*n],
            Self::Fragmented(v) => v.clone(),
            Self::NotPublished { .. } => Vec::new(),
        }
    }

    /// Whether an offset comparison is possible at all.
    pub fn is_comparable(&self) -> bool {
        !matches!(self, Self::NotPublished { .. })
    }
}

/// One expected hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectation {
    /// The publisher's hit id. **Not unique**: one location can carry several
    /// terms, so several rows share an id — measured on the real file, where
    /// id 2944 carries `panda tiger fox`, `tiger` and `fox` at three adjacent
    /// offsets.
    pub id: String,
    pub term: String,
    /// Where the publisher says it is. See [`Position`]: one offset, several,
    /// or none published.
    pub position: Position,
    /// The sector field as stated, kept so it can be cross-checked. Not parsed
    /// into a number, because a fragmented row states several and a `zipped`
    /// row states none.
    pub sector: String,
    /// The file the publisher says the term is in, or `None` where it states
    /// `UNKNOWN` — which it does on 77 rows, all of them real hits at real
    /// offsets in real filesystems whose containing file it does not name —
    /// or `FRAG-UNKNOWN`, on two more (rows 6000 and 6006, VAL-002).
    pub file_name: Option<String>,
    /// The file field exactly as the publisher wrote it, kept for the report
    /// even where [`Self::file_name`] is `None` -- `FRAG-UNKNOWN` says which
    /// recovery technique the row tests, which a reader should still see.
    pub file_label: String,
    pub locus: Locus,
    /// `utf-8`, `utf-16-le`, `utf-16-be` and the rest, as stored.
    pub encoding: String,
    /// Whether the image's own bytes bear the row out, when the grader was
    /// given the image ([`verify_row`]). `None` when no check was made, which
    /// is not the same as a check that passed.
    pub image_check: Option<RowVerdict>,
    /// The file an independent reference tool (Sleuth Kit's `ifind`/`ffind`)
    /// places at the row's byte offset, when that resolution was run. `None`
    /// when it was not run or found no file there -- never a guess.
    pub image_file: Option<String>,
}

/// What the image's own bytes say about one row of the key (VAL-002).
///
/// The key is the publisher's claim that a term's bytes, in a stated
/// encoding, are at a stated offset. That claim is checkable by plain byte
/// comparison, and a row the image contradicts is a fault in the key -- it
/// must not be counted as a failure of the tool being graded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowVerdict {
    /// The term's encoded bytes are at the published offset (for a
    /// fragmented row, split across the published offsets at sector
    /// boundaries).
    Verified,
    /// The offset holds the publisher's own hit marker for this row --
    /// `<id> <====` (or `<id> &lt;====` in HTML), in the row's encoding --
    /// rather than the term. Measured on the Windows image: rows 7015 and
    /// 9000-9007 (and their unallocated copies 9508-9515) point there. The
    /// marker is the publisher's label for the hit, so the row's claim about
    /// which file holds it is not contradicted, and it grades as before.
    AtItsMarker,
    /// They are not. `at` is the offset where the comparison failed and
    /// `found` the bytes the image holds there.
    BytesDiffer { at: u64, found: Vec<u8> },
    /// No comparison was possible, and why: no published offset, an encoding
    /// this check does not encode, or the image could not be read there.
    NotChecked(String),
}

/// The bytes `term` is stored as in `encoding`, for the encodings the key
/// uses. `None` for any other -- including the key's `UTF` label on the
/// `zipped` rows, which states no byte form.
pub fn encode_term(term: &str, encoding: &str) -> Option<Vec<u8>> {
    match encoding.trim().to_ascii_lowercase().as_str() {
        "utf-8" => Some(term.as_bytes().to_vec()),
        "utf-16-le" => Some(term.encode_utf16().flat_map(u16::to_le_bytes).collect()),
        "utf-16-be" => Some(term.encode_utf16().flat_map(u16::to_be_bytes).collect()),
        _ => None,
    }
}

/// Whether `at` holds this row's own hit marker, `<id> <====` or its HTML
/// escape `<id> &lt;====`, in the row's encoding.
fn at_its_marker<R: std::io::Read + std::io::Seek>(e: &Expectation, at: u64, img: &mut R) -> bool {
    ["<====", "&lt;===="].iter().any(|arrow| {
        let Some(marker) = encode_term(&format!("{} {arrow}", e.id), &e.encoding) else {
            return false;
        };
        let mut got = vec![0u8; marker.len()];
        img.seek(std::io::SeekFrom::Start(at))
            .and_then(|_| img.read_exact(&mut got))
            .is_ok()
            && got == marker
    })
}

/// Check one row of the key against the image's bytes.
///
/// A single-offset row verifies when the encoded term is at that offset. A
/// fragmented row verifies when each fragment holds the next part of the
/// encoded term and every fragment but the last ends on a 512-byte sector
/// boundary -- a fragment of a file ends where its cluster does, so a match
/// that stops short mid-sector is not a fragment boundary but a mismatch.
pub fn verify_row<R: std::io::Read + std::io::Seek>(e: &Expectation, img: &mut R) -> RowVerdict {
    let offsets = e.position.offsets();
    if offsets.is_empty() {
        return RowVerdict::NotChecked("the key publishes no offset for this row".to_string());
    }
    let Some(want) = encode_term(&e.term, &e.encoding) else {
        return RowVerdict::NotChecked(format!(
            "the key's encoding label {:?} states no byte form this check can compare",
            e.encoding
        ));
    };
    let mut rest: &[u8] = &want;
    let last = offsets.len() - 1;
    for (i, &at) in offsets.iter().enumerate() {
        // Read the whole remainder at every fragment: the bytes after a
        // fragment boundary are whatever follows on disk, and the comparison
        // below decides how much of the term this fragment holds.
        let mut got = vec![0u8; rest.len()];
        if let Err(err) = img
            .seek(std::io::SeekFrom::Start(at))
            .and_then(|_| img.read_exact(&mut got))
        {
            return RowVerdict::NotChecked(format!(
                "the image could not be read at byte {at}: {err}"
            ));
        }
        let matched = rest.iter().zip(&got).take_while(|(a, b)| a == b).count();
        if matched == rest.len() {
            // The whole remainder is here. For a non-final fragment that
            // leaves a later offset holding none of the term, which the key
            // does not claim -- but the bytes do not contradict the term
            // being here, so the row stands.
            return RowVerdict::Verified;
        }
        let boundary = (at + matched as u64).is_multiple_of(512);
        if i == last || matched == 0 || !boundary {
            if i == 0 && at_its_marker(e, at, img) {
                return RowVerdict::AtItsMarker;
            }
            return RowVerdict::BytesDiffer { at, found: got };
        }
        rest = &rest[matched..];
    }
    unreachable!("the last fragment always returns")
}

impl Expectation {
    /// Whether the publisher's sector field agrees with its own byte offsets.
    ///
    /// A free cross-check: a sector is `floor(byte / 512)`, so a row where they
    /// disagree is a row one of whose numbers is wrong, and a grader that
    /// trusted either would grade the wrong position. `None` when there is
    /// nothing to compare — a row with no published offset, which is a
    /// different answer from a row that disagrees.
    pub fn sector_agrees(&self) -> Option<bool> {
        let offsets = self.position.offsets();
        if offsets.is_empty() {
            return None;
        }
        let stated: Vec<&str> = self.sector.split(',').map(str::trim).collect();
        if stated.len() != offsets.len() {
            return Some(false);
        }
        Some(
            offsets
                .iter()
                .zip(stated)
                .all(|(byte, s)| s.parse::<u64>() == Ok(byte / 512)),
        )
    }

    /// Whether this expectation can be graded on position.
    pub fn has_position(&self) -> bool {
        self.position.is_comparable()
    }
}

/// Why a row was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedRow {
    pub line: usize,
    pub raw: String,
    pub why: String,
}

/// The parsed answer key.
///
/// # The `META` id is not metadata
///
/// Seventy-seven rows carry the id `META`, and an earlier version of this
/// parser held them apart as "the set's own metadata assertions". Measured,
/// they are nothing of the kind: `META:cañón:1000741041:1954572:UNKNOWN:exfat:utf-16-be`
/// is a hit at a real offset in a real filesystem whose **containing file** the
/// publisher does not name. Holding them apart excluded 77 gradeable
/// expectations from the run. They are content expectations with an unknown
/// file, and that is all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnswerKey {
    pub expectations: Vec<Expectation>,
    /// Rows this parser would not read, each with the reason. **Counted, never
    /// dropped**: a key silently missing rows grades fewer expectations and
    /// reports a higher pass rate.
    pub rejected: Vec<RejectedRow>,
}

impl AnswerKey {
    /// Expectations a tool searching allocated content can be graded against.
    pub fn gradeable(&self) -> impl Iterator<Item = &Expectation> {
        self.expectations.iter().filter(|e| e.locus.is_gradeable())
    }

    /// Expectations outside that universe, which are `NotAssessed` and not
    /// misses.
    pub fn outside_universe(&self) -> impl Iterator<Item = &Expectation> {
        self.expectations.iter().filter(|e| !e.locus.is_gradeable())
    }

    /// Rows whose stated sector contradicts their stated byte offset.
    pub fn self_contradicting(&self) -> impl Iterator<Item = &Expectation> {
        self.expectations
            .iter()
            // `None` means there was nothing to compare, which is not a
            // contradiction.
            .filter(|e| e.sector_agrees() == Some(false))
    }

    /// Distinct hit ids, so a count can be compared with the publisher's.
    pub fn distinct_ids(&self) -> usize {
        self.expectations
            .iter()
            .map(|e| e.id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }

    /// Expectations the publisher gives no offset for — real, and a different
    /// kind of question: the term is inside a compressed container, so finding
    /// it at all tests whether the tool reads inside such formats.
    pub fn without_position(&self) -> impl Iterator<Item = &Expectation> {
        self.expectations.iter().filter(|e| !e.has_position())
    }

    /// **An expectation is identified by `(id, term)`, never by id alone.**
    ///
    /// Seven Windows ids and eight Unix ids appear on three rows each, with
    /// three DIFFERENT and OVERLAPPING targets. Measured, verbatim:
    ///
    /// ```text
    /// 2944:fox:9692350:18930:LIVE-triple-fat-ascii.txt:fat32:utf-8
    /// 2944:panda tiger fox:9692338:18930:LIVE-triple-fat-ascii.txt:fat32:utf-8
    /// 2944:tiger:9692344:18930:LIVE-triple-fat-ascii.txt:fat32:utf-8
    /// ```
    ///
    /// The published answer key lists id 2944 under `FT-SS-04` ("Panda and
    /// fox") **and** under `FT-SS-10-Hex` ("panda"), and neither of those cases
    /// wants a hit on `tiger`. So a grader that looks an id up in the answer
    /// key and expands it to every matching row produces three expectations
    /// where the case wants one, and then grades the tool against a hit nobody
    /// asked for.
    pub fn resolve(&self, id: &str, term: &str) -> Vec<&Expectation> {
        self.expectations
            .iter()
            .filter(|e| e.id == id && e.term == term)
            .collect()
    }

    /// Ids carrying more than one distinct term, which are the ones a grader
    /// must not resolve by id.
    pub fn ids_with_several_terms(&self) -> BTreeMap<&str, Vec<&str>> {
        let mut by_id: BTreeMap<&str, std::collections::BTreeSet<&str>> = BTreeMap::new();
        for e in &self.expectations {
            by_id
                .entry(e.id.as_str())
                .or_default()
                .insert(e.term.as_str());
        }
        by_id
            .into_iter()
            .filter(|(_, terms)| terms.len() > 1)
            .map(|(id, terms)| (id, terms.into_iter().collect()))
            .collect()
    }

    /// Expectations by term, for a grader that searches one term at a time.
    pub fn by_term(&self) -> BTreeMap<&str, Vec<&Expectation>> {
        let mut out: BTreeMap<&str, Vec<&Expectation>> = BTreeMap::new();
        for e in &self.expectations {
            out.entry(e.term.as_str()).or_default().push(e);
        }
        out
    }

    /// The sentence a report needs about what this key does and does not ask.
    pub fn describe(&self) -> String {
        let gradeable = self.gradeable().count();
        let outside = self.outside_universe().count();
        let contradicting = self.self_contradicting().count();
        let mut s = format!(
            "{} expected hits across {} distinct hit ids, of which {gradeable} are in allocated \
             content and {outside} are in unallocated space.",
            self.expectations.len(),
            self.distinct_ids()
        );
        if outside > 0 {
            s.push_str(
                " Those in unallocated space are OUTSIDE the universe of a search over parsed \
                 records and allocated content: they are recorded as not assessed, with the \
                 reason, and are not counted as misses.",
            );
        }
        let unknown_file = self
            .expectations
            .iter()
            .filter(|e| e.file_name.is_none())
            .count();
        if unknown_file > 0 {
            s.push_str(&format!(
                " {unknown_file} of them are at a stated offset in a stated filesystem whose \
                 containing FILE the publisher does not name; they are graded on the offset, \
                 which is what they state."
            ));
        }
        if contradicting > 0 {
            s.push_str(&format!(
                " {contradicting} row(s) state a sector that does not equal their own byte offset \
                 divided by 512; both numbers are reported and neither is trusted."
            ));
        }
        let no_position = self.without_position().count();
        if no_position > 0 {
            s.push_str(&format!(
                " {no_position} expectation(s) carry no published offset -- the publisher states \
                 the term is inside a compressed container and gives no position -- so they can \
                 be graded on whether the term is found and not on where."
            ));
        }
        if !self.rejected.is_empty() {
            s.push_str(&format!(
                " {} row(s) were not read at all, each with its reason: a key silently missing \
                 rows grades fewer expectations and reports a higher pass rate.",
                self.rejected.len()
            ));
        }
        s
    }
}

/// Whether a key's file field is the publisher saying it does not know the
/// file: `UNKNOWN`, or `UNKNOWN` with a technique prefixed (`FRAG-UNKNOWN`),
/// case-insensitively.
fn names_no_file(field: &str) -> bool {
    let upper = field.trim().to_ascii_uppercase();
    upper == "UNKNOWN" || upper.ends_with("-UNKNOWN")
}

/// Parse `win_string_doc.txt` / `unix_string_doc.txt`.
pub fn parse_answer_key(text: &str) -> AnswerKey {
    let mut out = AnswerKey::default();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim_end_matches(['\r', '\n']);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // The ID from the left, the last five fields from the right, and
        // whatever is between them is the term -- so a term containing a colon
        // is read rather than silently dropped by a seven-field demand.
        let Some((id, rest)) = line.split_once(':') else {
            out.rejected.push(RejectedRow {
                line: i + 1,
                raw: line.to_string(),
                why: "no colon: this is not a row of the ID:term:byte:sector:file:fs:encoding \
                      form"
                    .to_string(),
            });
            continue;
        };
        let tail: Vec<&str> = rest.rsplitn(6, ':').collect();
        if tail.len() < 6 {
            out.rejected.push(RejectedRow {
                line: i + 1,
                raw: line.to_string(),
                why: format!(
                    "{} field(s) after the id, where the form has six (term, byte, sector, file, \
                     fs, encoding)",
                    tail.len()
                ),
            });
            continue;
        }
        // `rsplitn` yields from the right.
        let encoding = tail[0].trim();
        let fs = tail[1].trim();
        let file_name = tail[2].trim();
        let sector_raw = tail[3].trim();
        let byte_raw = tail[4].trim();
        let term = tail[5];

        // A non-numeric offset is NOT a malformed row: four real rows state
        // the literal word `zipped`, because the term is inside a compressed
        // `.docx` and the publisher gives no offset for it. Rejecting them
        // would lose four assertions and raise the pass rate over the rest.
        let position = Position::of(byte_raw);
        if term.is_empty() {
            out.rejected.push(RejectedRow {
                line: i + 1,
                raw: line.to_string(),
                why: "the term is empty, so there is nothing to search for".to_string(),
            });
            continue;
        }
        let e = Expectation {
            id: id.trim().to_string(),
            // NOT trimmed. Thirty-five measured terms carry a leading or
            // trailing space -- `plan ` is one -- and searching for the
            // trimmed form finds different offsets, or none.
            term: term.to_string(),
            position,
            sector: sector_raw.to_string(),
            // `UNKNOWN` is the publisher saying it does not know which file,
            // not a file called UNKNOWN -- and `FRAG-UNKNOWN` is the same
            // statement with the technique under test prefixed (VAL-002).
            file_name: (!names_no_file(file_name)).then(|| file_name.to_string()),
            file_label: file_name.to_string(),
            image_check: None,
            image_file: None,
            locus: Locus::of(fs),
            encoding: encoding.to_ascii_lowercase(),
        };
        out.expectations.push(e);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real rows, quoted from `win_string_doc.txt`.
    const REAL: &str = "\
7000:SecretKey:15427:30:LIVE-MFT-Hidden-mft-ascii.txt:unalloc:utf-8\n\
7003:SecretKey:2005118650:3916247:LIVE-MFT-Hidden-mft-utf-16-be.txt:unalloc:utf-16-be\n\
1280:berlin@deutchland.net:9127090:17826:live-fat32.txt:fat32:utf-8\n\
1024:987-65-4321:9573557:18698:live-fat32.txt:fat32:utf-8\n\
2944:panda tiger fox:9692338:18930:live-fat32.txt:fat32:utf-8\n\
2944:tiger:9692344:18930:live-fat32.txt:fat32:utf-8\n\
2944:fox:9692350:18930:live-fat32.txt:fat32:utf-8\n";

    #[test]
    fn the_real_row_format_parses_into_its_seven_fields() {
        let key = parse_answer_key(REAL);
        assert!(key.rejected.is_empty(), "{:?}", key.rejected);
        assert_eq!(key.expectations.len(), 7);
        let first = &key.expectations[0];
        assert_eq!(first.id, "7000");
        assert_eq!(first.term, "SecretKey");
        assert_eq!(
            first.position,
            Position::At(15427),
            "the offset whose fifteen-of-fifteen agreement with grep -abo established that \
             these are absolute image byte offsets"
        );
        assert_eq!(first.sector, "30");
        assert_eq!(
            first.file_name.as_deref(),
            Some("LIVE-MFT-Hidden-mft-ascii.txt")
        );
        assert_eq!(first.locus, Locus::Unallocated);
        assert_eq!(first.encoding, "utf-8");
    }

    /// **`unalloc` is the field that decides the grader's honesty.** A hit in
    /// unallocated space is outside the universe of a search over parsed
    /// records and allocated content, and grading it as a miss would report a
    /// defect where the answer is that the question was not asked.
    #[test]
    fn an_unallocated_expectation_is_separated_from_the_gradeable_ones() {
        let key = parse_answer_key(REAL);
        assert_eq!(key.gradeable().count(), 5);
        assert_eq!(key.outside_universe().count(), 2);
        for e in key.outside_universe() {
            assert_eq!(e.locus, Locus::Unallocated);
            assert!(!e.locus.is_gradeable());
        }
        let said = key.describe();
        assert!(
            said.contains("OUTSIDE the universe") && said.contains("not counted as misses"),
            "got {said}"
        );
    }

    /// **A hit id is not unique**, and a parser that keyed on it would lose
    /// two of these three. Real: id 2944 carries three terms at three adjacent
    /// offsets.
    #[test]
    fn one_hit_id_carrying_several_terms_keeps_all_of_them() {
        let key = parse_answer_key(REAL);
        let same: Vec<&Expectation> = key.expectations.iter().filter(|e| e.id == "2944").collect();
        assert_eq!(same.len(), 3, "one location, three terms");
        assert_eq!(
            same.iter()
                .flat_map(|e| e.position.offsets())
                .collect::<Vec<_>>(),
            vec![9692338, 9692344, 9692350]
        );
        assert_eq!(
            key.distinct_ids(),
            5,
            "7000, 7003, 1280, 1024 and 2944 — five ids across seven rows"
        );
    }

    /// **A `META` row is a content expectation**, not metadata.
    ///
    /// An earlier version of this parser held the 77 `META` rows apart as "the
    /// set's own metadata assertions", which excluded 77 gradeable
    /// expectations from the run. Measured, each is a hit at a real offset in
    /// a real filesystem whose containing FILE the publisher does not name —
    /// `META:cañón:1000741041:1954572:UNKNOWN:exfat:utf-16-be`. The two rows
    /// below are the real pair: the same term in both UTF-16 byte orders, one
    /// byte apart.
    #[test]
    fn a_meta_row_is_a_content_expectation_whose_file_is_unknown() {
        let key = parse_answer_key(
            "META:cañón:1000741041:1954572:UNKNOWN:exfat:utf-16-be\n\
             META:cañón:1000741042:1954572:UNKNOWN:exfat:utf-16-le\n",
        );
        assert!(key.rejected.is_empty(), "{:?}", key.rejected);
        assert_eq!(key.expectations.len(), 2);
        for e in &key.expectations {
            assert_eq!(
                e.file_name, None,
                "`UNKNOWN` is the publisher saying it does not know which file, not a file \
                 called UNKNOWN"
            );
            assert!(e.locus.is_gradeable(), "exfat is allocated content");
            assert!(e.has_position());
        }
        assert_eq!(key.expectations[0].position, Position::At(1000741041));
        assert_eq!(key.expectations[1].position, Position::At(1000741042));
        assert!(
            key.describe()
                .contains("containing FILE the publisher does not name"),
            "got {}",
            key.describe()
        );
    }

    /// **A term containing a colon is read**, not dropped. No row in the
    /// measured file has one, and a parser that demanded exactly seven
    /// colon-separated fields would silently lose a row that did — which is
    /// the failure this parser is shaped against.
    #[test]
    fn a_term_containing_a_colon_is_read_whole() {
        let key =
            parse_answer_key("42:http://example.com:8080/x:4096:8:live-ntfs.txt:ntfs:utf-8\n");
        assert!(key.rejected.is_empty(), "{:?}", key.rejected);
        assert_eq!(key.expectations.len(), 1);
        assert_eq!(key.expectations[0].term, "http://example.com:8080/x");
        assert_eq!(key.expectations[0].position, Position::At(4096));
        assert_eq!(key.expectations[0].encoding, "utf-8");
    }

    /// The sector is `floor(byte / 512)`, so a row where they disagree is a row
    /// one of whose numbers is wrong. Both are reported and neither trusted.
    ///
    /// **Every real row measured agrees**, including the three id-2944 rows: an
    /// earlier version of this test expected them to contradict, on the guess
    /// that the publisher wrote the location's sector rather than each term's.
    /// It does not matter which it wrote, because 9692338, 9692344 and 9692350
    /// all fall inside sector 18930 (18930 × 512 = 9,692,160). The check is
    /// kept because a row that did disagree would otherwise grade a position
    /// one of whose two numbers is wrong.
    #[test]
    fn a_row_whose_sector_contradicts_its_own_offset_is_reported() {
        let real = parse_answer_key(REAL);
        assert_eq!(
            real.self_contradicting().count(),
            0,
            "every measured row agrees: {:?}",
            real.self_contradicting().collect::<Vec<_>>()
        );
        assert_eq!(real.expectations[0].sector_agrees(), Some(true));
        assert_eq!(15427 / 512, 30);

        // A row that does disagree, which is what the check is for.
        let bad = parse_answer_key("1:x:9692344:99999:f:ntfs:utf-8\n");
        assert_eq!(bad.self_contradicting().count(), 1);
        assert_eq!(bad.expectations[0].sector_agrees(), Some(false));
        assert!(
            bad.describe()
                .contains("does not equal their own byte offset"),
            "got {}",
            bad.describe()
        );
        // And both numbers survive on the record, so a reader can see which to
        // distrust rather than being handed one of them.
        assert_eq!(bad.expectations[0].position, Position::At(9692344));
        assert_eq!(bad.expectations[0].sector, "99999");
    }

    /// **A row this parser will not read is counted, with its reason.** A key
    /// silently missing rows grades fewer expectations and reports a higher
    /// pass rate.
    #[test]
    fn an_unreadable_row_is_counted_with_its_reason_and_never_dropped() {
        let key = parse_answer_key(
            "1:ok:512:1:f:ntfs:utf-8\n\
             not-a-row-at-all\n\
             2:missing-fields:512\n\
             5::512:1:f:ntfs:utf-8\n",
        );
        assert_eq!(key.expectations.len(), 1, "only the well-formed row");
        assert_eq!(key.rejected.len(), 3, "{:?}", key.rejected);
        let reasons: Vec<&str> = key.rejected.iter().map(|r| r.why.as_str()).collect();
        assert!(
            reasons.iter().any(|w| w.contains("no colon")),
            "{reasons:?}"
        );
        assert!(
            reasons.iter().any(|w| w.contains("field(s) after the id")),
            "{reasons:?}"
        );
        assert!(
            reasons.iter().any(|w| w.contains("term is empty")),
            "{reasons:?}"
        );
        // Every rejection carries the line number and the raw row, so it can
        // be looked at rather than guessed at.
        for r in &key.rejected {
            assert!(r.line > 0);
            assert!(!r.raw.is_empty());
        }
        assert!(key.describe().contains("were not read at all"));
    }

    /// A locus this build does not recognise is neither gradeable nor
    /// unallocated: it is reported as stored, because one of those two answers
    /// would be a guess with a grade attached.
    #[test]
    fn an_unrecognised_locus_is_not_folded_into_either_answer() {
        let key = parse_answer_key("1:x:512:1:f::utf-8\n");
        assert_eq!(key.expectations.len(), 1);
        assert_eq!(
            key.expectations[0].locus,
            Locus::Unrecognised(String::new())
        );
        assert!(!key.expectations[0].locus.is_gradeable());
    }

    /// Grouping by term, which is how a grader drives one search per term
    /// rather than one per expected hit.
    #[test]
    fn expectations_group_by_term_for_one_search_each() {
        let key = parse_answer_key(REAL);
        let by_term = key.by_term();
        assert_eq!(by_term.get("SecretKey").map(Vec::len), Some(2));
        assert_eq!(by_term.get("berlin@deutchland.net").map(Vec::len), Some(1));
        assert_eq!(by_term.len(), 6, "{:?}", by_term.keys().collect::<Vec<_>>());
    }
}

#[cfg(test)]
mod real_shapes {
    use super::*;

    /// **A term with a trailing space, which 35 measured rows carry.**
    ///
    /// Row 0144 is `0144:plan :9438368:18434:LIVE-plot-fat-ascii.txt:fat32:utf-8`
    /// — the term is `plan `, with the space. A parser that trimmed it would
    /// search for `plan` and find different offsets, or find hits the key does
    /// not list and grade them as false positives.
    #[test]
    fn a_term_with_a_trailing_space_keeps_it() {
        let key =
            parse_answer_key("0144:plan :9438368:18434:LIVE-plot-fat-ascii.txt:fat32:utf-8\n");
        assert!(key.rejected.is_empty(), "{:?}", key.rejected);
        assert_eq!(
            key.expectations[0].term, "plan ",
            "the trailing space is part of what the publisher asks to be searched for"
        );
    }

    /// **Four real rows publish no offset at all**, because the term is inside
    /// a compressed `.docx`. They are expectations, not malformed rows.
    ///
    /// Verbatim: `9004:peroxide:zipped:zipped:FMT-explosive-docx-win.docx:fat32:UTF`
    #[test]
    fn a_row_with_no_published_offset_is_an_expectation_and_not_a_rejection() {
        let key =
            parse_answer_key("9004:peroxide:zipped:zipped:FMT-explosive-docx-win.docx:fat32:UTF\n");
        assert!(
            key.rejected.is_empty(),
            "rejecting this would lose a real assertion: {:?}",
            key.rejected
        );
        assert_eq!(key.expectations.len(), 1);
        let e = &key.expectations[0];
        assert_eq!(
            e.position,
            Position::NotPublished {
                stated: "zipped".to_string()
            },
            "and what the publisher stated instead is kept, not discarded"
        );
        assert!(!e.has_position());
        assert!(e.position.offsets().is_empty());
        // There is nothing to cross-check, which is not the same as a
        // disagreement.
        assert_eq!(e.sector_agrees(), None);
        assert_eq!(key.without_position().count(), 1);
        assert!(
            key.describe().contains("no published offset"),
            "got {}",
            key.describe()
        );
    }

    /// **One real row publishes two offsets**, for a fragmented occurrence:
    /// `6006:Washington:4305916,7758848:8409,15154:FRAG-UNKNOWN:fat32:utf-8`
    #[test]
    fn a_fragmented_occurrence_keeps_both_of_its_offsets() {
        let key = parse_answer_key(
            "6006:Washington:4305916,7758848:8409,15154:FRAG-UNKNOWN:fat32:utf-8\n",
        );
        assert!(key.rejected.is_empty(), "{:?}", key.rejected);
        let e = &key.expectations[0];
        assert_eq!(e.position, Position::Fragmented(vec![4305916, 7758848]));
        assert_eq!(e.position.offsets(), vec![4305916, 7758848]);
        // Both sectors cross-check against both offsets, pairwise.
        assert_eq!(4305916 / 512, 8409);
        assert_eq!(7758848 / 512, 15154);
        assert_eq!(e.sector_agrees(), Some(true));
    }

    /// **`FRAG-UNKNOWN` names no file either** (VAL-002). Rows 6000 and 6006
    /// state it; it is the publisher's `UNKNOWN` with the technique the row
    /// tests prefixed, not a file called that. Read as a name it was looked up
    /// in the inventory, not found, and graded a file-recovery failure for a
    /// file that never existed. Row 6000 has ONE offset, so it is not the
    /// fragmented pair that makes these rows unusual.
    #[test]
    fn a_frag_unknown_row_names_no_file() {
        let key = parse_answer_key(
            "6000:California:4232700:8266:FRAG-UNKNOWN:fat32:utf-8\n\
             6006:Washington:4305916,7758848:8409,15154:frag-unknown:fat32:utf-8\n",
        );
        for e in &key.expectations {
            assert_eq!(e.file_name, None, "row {} names no file", e.id);
        }
        assert_eq!(key.expectations[0].file_label, "FRAG-UNKNOWN");
        assert_eq!(key.expectations[0].position, Position::At(4232700));
        assert_eq!(
            key.expectations[1].position,
            Position::Fragmented(vec![4305916, 7758848])
        );
    }

    /// A list with one unreadable member is not half-graded.
    #[test]
    fn a_partly_unreadable_offset_list_is_not_graded_on_its_readable_half() {
        let key = parse_answer_key("1:x:4305916,zipped:8409,0:f:fat32:utf-8\n");
        assert_eq!(
            key.expectations[0].position,
            Position::NotPublished {
                stated: "4305916,zipped".to_string()
            },
            "grading the readable half would grade a fragment as the whole"
        );
    }

    /// A sector list of the wrong length disagrees, rather than being compared
    /// pairwise against a shorter list of offsets.
    #[test]
    fn a_sector_list_that_does_not_pair_with_the_offsets_disagrees() {
        let key = parse_answer_key("1:x:4305916,7758848:8409:f:fat32:utf-8\n");
        assert_eq!(key.expectations[0].sector_agrees(), Some(false));
    }
}

#[cfg(test)]
mod against_the_real_key {
    use super::*;

    /// The parser over the real 921-row key.
    ///
    /// Corpus-gated on `SEANCE_CFTT_SS`: the set is a 9 MB download that
    /// unpacks to 4 GB and is not in the repository.
    #[test]
    fn the_real_answer_key_parses_every_one_of_its_rows() {
        let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_CFTT_SS") else {
            return;
        };
        let path = dir
            .join("string-search-federated-testing-data-set-version-1-1-revised-september-27-2019")
            .join("win_string_doc.txt");
        let Ok(text) = std::fs::read_to_string(&path) else {
            eprintln!("skipped: {} is not present", path.display());
            return;
        };
        let key = parse_answer_key(&text);

        assert!(
            key.rejected.is_empty(),
            "every row of the published key must be read, and these were not: {:?}",
            key.rejected
        );
        assert_eq!(
            key.expectations.len(),
            921,
            "every one of the file's 921 rows is a content expectation, measured with \
             `grep -c ''`"
        );
        assert_eq!(
            key.expectations
                .iter()
                .filter(|e| e.file_name.is_none())
                .count(),
            79,
            "the 77 `META` rows, whose containing file the publisher does not name — held \
             apart as \"metadata\" they would have been 77 gradeable expectations excluded \
             from the run — and the two `FRAG-UNKNOWN` rows, 6000 and 6006 (VAL-002)"
        );
        assert_eq!(
            key.expectations
                .iter()
                .filter(|e| e.file_label.eq_ignore_ascii_case("FRAG-UNKNOWN"))
                .map(|e| e.id.as_str())
                .collect::<Vec<_>>(),
            ["6000", "6006"]
        );

        // The measured loci: ntfs 308, fat32 247, exfat 232, unalloc 134.
        assert_eq!(key.outside_universe().count(), 134);
        assert_eq!(key.gradeable().count(), 921 - 134);

        // The three shapes the file taught, all present.
        assert_eq!(key.without_position().count(), 4, "the four `zipped` rows");
        assert_eq!(
            key.expectations
                .iter()
                .filter(|e| matches!(e.position, Position::Fragmented(_)))
                .count(),
            1,
            "row 6006, Washington, fragmented across two locations"
        );
        assert_eq!(
            key.expectations
                .iter()
                .filter(|e| e.term.starts_with(' ') || e.term.ends_with(' '))
                .count(),
            35,
            "terms whose leading or trailing space is part of the search"
        );

        // Every row that has offsets cross-checks against its own sectors.
        let contradicting: Vec<&Expectation> = key.self_contradicting().collect();
        assert!(
            contradicting.is_empty(),
            "the publisher's sectors and offsets must agree, and these did not: {:?}",
            contradicting
                .iter()
                .map(|e| (&e.id, &e.term, &e.sector))
                .collect::<Vec<_>>()
        );

        // And the one offset whose agreement with `grep -abo` established the
        // frame of reference at all.
        let secret = key
            .expectations
            .iter()
            .find(|e| e.id == "7000")
            .expect("hit 7000 is in this key");
        assert_eq!(secret.term, "SecretKey");
        assert_eq!(secret.position, Position::At(15427));
        assert_eq!(
            secret.locus,
            Locus::Unallocated,
            "and it is in unallocated space, before the first partition begins"
        );
    }
}

/// The unallocated region of the Windows image, **measured from its own GPT**
/// rather than taken from the answer key's label.
///
/// The second of the image's four partitions holds no filesystem: its first
/// sector is raw text, and it is the region the answer key calls `unalloc`. The
/// bounds below were read from the GPT entry array at LBA 2 of
/// `ss-win-07-25-18.dd`:
///
/// ```text
/// p1  bytes         17408 ..   499999743   FAT32
/// p2  bytes     499999744 ..   999999487   no filesystem  <- `unalloc`
/// p3  bytes     999999488 ..  1499999231   exFAT
/// p4  bytes    1499999232 ..  1999998975   NTFS
/// unpartitioned:  0..17407 and 1999998976..2098028543
/// ```
///
/// Having the range means a grader can classify a **reported** offset
/// arithmetically instead of trusting the key's label — which matters because
/// the label says where the publisher put the term, and the question a grade
/// asks is where the tool says it found one.
pub const WIN_UNALLOCATED: std::ops::RangeInclusive<u64> = 499_999_744..=999_999_487;

/// The Windows image's length, so an offset past it can be rejected.
pub const WIN_IMAGE_BYTES: u64 = 2_098_028_544;

/// Where in the image an offset falls, from the measured layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageRegion {
    /// Before the first partition — the GPT area, where `SecretKey` at byte
    /// 15427 sits.
    BeforeFirstPartition,
    Fat32,
    /// The region with no filesystem, which the key calls `unalloc`.
    Unallocated,
    ExFat,
    Ntfs,
    /// After the last partition.
    AfterLastPartition,
    /// Past the end of the image, which is not an offset in it at all.
    PastEnd,
}

impl ImageRegion {
    /// Whether a search over a filesystem's **allocated content** could reach
    /// this region at all.
    ///
    /// The three real filesystems, and nothing else. The key's `unalloc` label
    /// covers more than the no-filesystem partition: row 7000 puts `SecretKey`
    /// at byte 15427, which is **before the first partition begins**, in the
    /// GPT area — so `unalloc` there means "outside any filesystem", not "in
    /// partition 2". Both are equally out of a filesystem walker's reach, and
    /// that is the property a grade turns on.
    pub fn is_inside_a_filesystem(&self) -> bool {
        matches!(self, Self::Fat32 | Self::ExFat | Self::Ntfs)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BeforeFirstPartition => "before the first partition (the GPT area)",
            Self::Fat32 => "the FAT32 partition",
            Self::Unallocated => "the partition holding no filesystem",
            Self::ExFat => "the exFAT partition",
            Self::Ntfs => "the NTFS partition",
            Self::AfterLastPartition => "after the last partition",
            Self::PastEnd => "past the end of the image",
        }
    }
}

/// Classify an offset in `ss-win-07-25-18.dd` from its measured GPT.
pub fn win_region_of(offset: u64) -> ImageRegion {
    match offset {
        o if o >= WIN_IMAGE_BYTES => ImageRegion::PastEnd,
        0..=17_407 => ImageRegion::BeforeFirstPartition,
        17_408..=499_999_743 => ImageRegion::Fat32,
        499_999_744..=999_999_487 => ImageRegion::Unallocated,
        999_999_488..=1_499_999_231 => ImageRegion::ExFat,
        1_499_999_232..=1_999_998_975 => ImageRegion::Ntfs,
        _ => ImageRegion::AfterLastPartition,
    }
}

/// **Where a grader's search terms come from, and what that costs.**
///
/// The answer key gives the expected hit **ids** and never the query. Every
/// search string and every search option — match case, whole words, Unicode,
/// stemming, the hex expression, the regular expression — comes only from
/// `copy-to-test-computer/string-search-test-cases.html`, and that file
/// **fails all three of the publisher's hash algorithms**: measured md5
/// `1a28389f…` against a published `c7a5afbb…`, sha1 `1bf3c703…` against
/// `283806b6…`, sha256 `1766226f…` against `a7aa0177…`. Its modification time
/// is 2019-09-05 and the hash lists are dated 2019-06-18, so it was revised
/// after they were written.
///
/// A grader that hard-codes the queries is hard-coding **unverified** data, and
/// must say so on its own result rather than presenting a pass as though the
/// question it asked were the published one. This constant is the sentence it
/// says.
pub const QUERY_PROVENANCE: &str =
    "The search terms and options graded here come only from the data set's \
     `string-search-test-cases.html`, which FAILS all three of the publisher's own hash \
     algorithms (md5, sha1 and sha256) and was modified after the hash lists were written. The \
     answer key gives the expected hit identifiers and never the query. So the expectations \
     below are verified against the publisher and the QUESTIONS ARE NOT: a pass here means the \
     tool found what this file asked for, which may not be what the published methodology asks \
     for.";

#[cfg(test)]
mod resolution_and_layout {
    use super::*;

    /// **The three rows that break id-based resolution.** Verbatim from
    /// `win_string_doc.txt` lines 603-605.
    const TRIPLE: &str = "\
2944:fox:9692350:18930:LIVE-triple-fat-ascii.txt:fat32:utf-8\n\
2944:panda tiger fox:9692338:18930:LIVE-triple-fat-ascii.txt:fat32:utf-8\n\
2944:tiger:9692344:18930:LIVE-triple-fat-ascii.txt:fat32:utf-8\n";

    #[test]
    fn an_expectation_resolves_by_id_and_term_and_never_by_id_alone() {
        let key = parse_answer_key(TRIPLE);
        assert_eq!(key.expectations.len(), 3);
        // The answer key lists id 2944 under FT-SS-04 ("Panda and fox") and
        // under FT-SS-10-Hex ("panda"). Neither wants a hit on `tiger`.
        let fox = key.resolve("2944", "fox");
        assert_eq!(fox.len(), 1);
        assert_eq!(fox[0].position, Position::At(9692350));
        let tiger = key.resolve("2944", "tiger");
        assert_eq!(tiger.len(), 1);
        assert_eq!(tiger[0].position, Position::At(9692344));
        assert!(
            key.resolve("2944", "panda").is_empty(),
            "the term is `panda tiger fox`, not `panda` — a prefix is not the term"
        );
    }

    /// And the ids that carry several terms are enumerable, so a grader can
    /// refuse to resolve one by id rather than doing it wrongly.
    #[test]
    fn the_ids_carrying_several_terms_are_named() {
        let key = parse_answer_key(TRIPLE);
        let multi = key.ids_with_several_terms();
        assert_eq!(multi.len(), 1);
        assert_eq!(
            multi.get("2944").map(Vec::len),
            Some(3),
            "three overlapping targets on one id: {multi:?}"
        );
    }

    /// The image layout, from its own GPT — so a REPORTED offset is classified
    /// arithmetically rather than by trusting the key's label.
    #[test]
    fn an_offset_is_classified_from_the_measured_partition_table() {
        // `SecretKey` at 15427, before the first partition begins.
        assert_eq!(win_region_of(15_427), ImageRegion::BeforeFirstPartition);
        // The three real filesystems.
        assert_eq!(win_region_of(9_438_368), ImageRegion::Fat32);
        assert_eq!(win_region_of(1_001_879_732), ImageRegion::ExFat);
        assert_eq!(win_region_of(1_505_152_171), ImageRegion::Ntfs);
        // The region with no filesystem, which the key calls `unalloc`.
        assert_eq!(win_region_of(500_761_776), ImageRegion::Unallocated);
        assert!(WIN_UNALLOCATED.contains(&500_761_776));
        // The boundaries themselves.
        assert_eq!(win_region_of(499_999_743), ImageRegion::Fat32);
        assert_eq!(win_region_of(499_999_744), ImageRegion::Unallocated);
        assert_eq!(win_region_of(999_999_487), ImageRegion::Unallocated);
        assert_eq!(win_region_of(999_999_488), ImageRegion::ExFat);
        // And past the end is not an offset in the image at all.
        assert_eq!(win_region_of(WIN_IMAGE_BYTES), ImageRegion::PastEnd);
        assert_eq!(
            win_region_of(1_999_998_976),
            ImageRegion::AfterLastPartition
        );
    }

    /// **Where the key's 134 `unalloc` expectations actually are**, measured
    /// against the image's own partition table.
    ///
    /// This test was first written to assert that every one of them lies in
    /// the no-filesystem partition. It does not, and what it found is worth
    /// more than the assertion would have been. The label spans **five**
    /// distinct places:
    ///
    /// ```text
    /// 128  the partition holding no filesystem
    ///   2  no offset published at all
    ///   1  before the first partition — the GPT area (`SecretKey`, byte 15427)
    ///   1  after the last partition
    ///   1  inside the NTFS partition   (row 7016, `disconnected`)
    ///   1  inside the exFAT partition
    /// ```
    ///
    /// So `unalloc` means **unallocated**, not "in partition 2": three of
    /// those rows are unallocated *clusters inside a live filesystem*, which a
    /// partition table cannot see. A grader therefore cannot decide the
    /// allocation state of a reported offset arithmetically — that needs the
    /// filesystem's own allocation bitmap — and `win_region_of` is honest
    /// about what it answers: which partition, and nothing about allocation.
    #[test]
    fn the_unalloc_expectations_span_five_regions_not_one() {
        let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_CFTT_SS") else {
            return;
        };
        let path = dir
            .join("string-search-federated-testing-data-set-version-1-1-revised-september-27-2019")
            .join("win_string_doc.txt");
        let Ok(text) = std::fs::read_to_string(&path) else {
            return;
        };
        let key = parse_answer_key(&text);
        let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut no_offset = 0usize;
        for e in key.outside_universe() {
            if e.position.offsets().is_empty() {
                no_offset += 1;
                continue;
            }
            for offset in e.position.offsets() {
                *counts.entry(win_region_of(offset).as_str()).or_default() += 1;
            }
        }
        assert_eq!(
            counts.get(ImageRegion::Unallocated.as_str()).copied(),
            Some(128),
            "the great majority are in the no-filesystem partition: {counts:?}"
        );
        assert_eq!(no_offset, 2, "and two publish no offset at all");
        // The three that are inside a live filesystem, which is the finding.
        assert_eq!(
            counts.get(ImageRegion::Ntfs.as_str()).copied(),
            Some(1),
            "row 7016 `disconnected` is unallocated space INSIDE NTFS: {counts:?}"
        );
        assert_eq!(counts.get(ImageRegion::ExFat.as_str()).copied(), Some(1));
        assert_eq!(
            counts
                .get(ImageRegion::BeforeFirstPartition.as_str())
                .copied(),
            Some(1),
            "`SecretKey` at 15427, in the GPT area"
        );
        assert_eq!(
            counts
                .get(ImageRegion::AfterLastPartition.as_str())
                .copied(),
            Some(1)
        );
        assert_eq!(counts.values().sum::<usize>() + no_offset, 134);
        // And the honest consequence: three of them are in a region a
        // partition table calls a filesystem, so allocation state is NOT
        // decidable from the layout alone.
        let inside_a_filesystem: usize = counts
            .iter()
            .filter(|(k, _)| {
                [
                    ImageRegion::Fat32.as_str(),
                    ImageRegion::ExFat.as_str(),
                    ImageRegion::Ntfs.as_str(),
                ]
                .contains(k)
            })
            .map(|(_, v)| *v)
            .sum();
        assert_eq!(
            inside_a_filesystem, 2,
            "unallocated clusters inside a live filesystem, which `win_region_of` cannot \
             distinguish from allocated ones and does not claim to"
        );
    }

    /// The query provenance is a sentence, not a flag, and it names all three
    /// algorithms — because "the file does not verify" invites the reading
    /// that one list is stale.
    #[test]
    fn the_query_provenance_names_what_is_unverified() {
        assert!(QUERY_PROVENANCE.contains("FAILS all three"));
        assert!(QUERY_PROVENANCE.contains("never the query"));
        assert!(
            QUERY_PROVENANCE.contains("QUESTIONS ARE NOT"),
            "the distinction is between verified expectations and unverified questions"
        );
    }
}

#[cfg(test)]
mod image_verification {
    use super::*;
    use std::io::Cursor;

    fn one(row: &str) -> Expectation {
        parse_answer_key(row).expectations.remove(0)
    }

    /// A 4 KiB image with `bytes` at `at`. Synthetic: it pins the comparison
    /// mechanism, which is plain byte equality; it is not validation on real
    /// evidence (that is `against_the_real_image`).
    fn image_with(parts: &[(usize, &[u8])]) -> Cursor<Vec<u8>> {
        let mut v = vec![0u8; 4096];
        for (at, bytes) in parts {
            v[*at..*at + bytes.len()].copy_from_slice(bytes);
        }
        Cursor::new(v)
    }

    #[test]
    fn a_row_whose_bytes_are_at_its_offset_verifies() {
        let e = one("7011:bear:1000:1:f.txt:ntfs:utf-16-be\n");
        let mut img = image_with(&[(1000, b"\0b\0e\0a\0r")]);
        assert_eq!(verify_row(&e, &mut img), RowVerdict::Verified);
    }

    /// Row 9000's shape: the offset holds `9000 <====`, the publisher's own
    /// marker for the hit, and the term is elsewhere in the file (inside
    /// document formatting). That is not a fault in the row.
    #[test]
    fn a_row_pointing_at_its_own_hit_marker_is_not_a_fault() {
        let e = one("9000:rifle:100:0:FMT-winchester-doc-utf8-win.doc:fat32:utf-8\n");
        let mut img = image_with(&[(100, b"9000 <==== SEA. Island")]);
        assert_eq!(verify_row(&e, &mut img), RowVerdict::AtItsMarker);
        let e = one("9006:longbow:100:0:FMT-arrow-html-win.html:fat32:utf-8\n");
        let mut img = image_with(&[(100, b"9006 &lt;==== Bl")]);
        assert_eq!(verify_row(&e, &mut img), RowVerdict::AtItsMarker);
        let e = one("7015:bear:100:0:f.txt:ntfs:utf-16-be\n");
        let marker = encode_term("7015 <==== mft", "utf-16-be").unwrap();
        let mut img = image_with(&[(100, &marker)]);
        assert_eq!(verify_row(&e, &mut img), RowVerdict::AtItsMarker);
        // Another row's marker is not this row's.
        let e = one("7010:bear:100:0:f.txt:ntfs:utf-16-le\n");
        let mut img = image_with(&[(100, b"7011 <==== x")]);
        assert!(matches!(
            verify_row(&e, &mut img),
            RowVerdict::BytesDiffer { .. }
        ));
    }

    /// Row 7010's shape: the offset holds zeros, so the key is wrong there.
    #[test]
    fn a_row_pointing_at_zeros_does_not_verify() {
        let e = one("7010:bear:1000:1:f.txt:ntfs:utf-16-le\n");
        let mut img = image_with(&[]);
        match verify_row(&e, &mut img) {
            RowVerdict::BytesDiffer { at, found } => {
                assert_eq!(at, 1000);
                assert_eq!(found, vec![0u8; 8]);
            }
            other => panic!("expected BytesDiffer, got {other:?}"),
        }
    }

    #[test]
    fn each_encoding_is_checked_in_its_own_bytes() {
        assert_eq!(encode_term("cañón", "utf-8").unwrap(), "cañón".as_bytes());
        assert_eq!(
            encode_term("añ", "utf-16-le").unwrap(),
            vec![b'a', 0, 0xF1, 0]
        );
        assert_eq!(
            encode_term("añ", "UTF-16-BE").unwrap(),
            vec![0, b'a', 0, 0xF1]
        );
        assert_eq!(
            encode_term("x", "UTF"),
            None,
            "the zipped rows' label states no byte form"
        );
        // The same bytes in the wrong byte order do not verify.
        let le = one("1:bear:100:0:f.txt:ntfs:utf-16-le\n");
        let mut img = image_with(&[(100, b"\0b\0e\0a\0r")]);
        assert!(matches!(
            verify_row(&le, &mut img),
            RowVerdict::BytesDiffer { at: 100, .. }
        ));
        let u8row = one("1:cañón:200:0:f.txt:fat32:utf-8\n");
        let mut img = image_with(&[(200, "cañón".as_bytes())]);
        assert_eq!(verify_row(&u8row, &mut img), RowVerdict::Verified);
    }

    /// Row 6006's shape: `Wash` in the last four bytes of a sector, `ington`
    /// at the start of another.
    #[test]
    fn a_fragmented_row_checks_each_fragment_in_turn() {
        let e = one("6006:Washington:1532,2048:2,4:FRAG-UNKNOWN:fat32:utf-8\n");
        let mut img = image_with(&[(1532, b"Wash"), (2048, b"ington")]);
        assert_eq!(verify_row(&e, &mut img), RowVerdict::Verified);
        // A first fragment that stops matching mid-sector is a mismatch, not
        // a fragment boundary.
        let e = one("6006:Washington:1500,2048:2,4:FRAG-UNKNOWN:fat32:utf-8\n");
        let mut img = image_with(&[(1500, b"Wash"), (2048, b"ington")]);
        assert!(matches!(
            verify_row(&e, &mut img),
            RowVerdict::BytesDiffer { .. }
        ));
    }

    #[test]
    fn a_row_with_no_offset_or_past_the_image_is_not_checked() {
        let e = one("9004:peroxide:zipped:zipped:x.docx:fat32:UTF\n");
        assert!(matches!(
            verify_row(&e, &mut image_with(&[])),
            RowVerdict::NotChecked(_)
        ));
        let e = one("1:bear:4094:7:f.txt:ntfs:utf-8\n");
        assert!(
            matches!(
                verify_row(&e, &mut image_with(&[])),
                RowVerdict::NotChecked(_)
            ),
            "a read past the end is could-not-look, not a contradiction"
        );
    }
}

#[cfg(test)]
mod against_the_real_image {
    use super::*;

    /// Every row of the real key checked against the real image's bytes.
    ///
    /// Corpus-gated on `SEANCE_CFTT_SS`. This is the validation on real
    /// evidence the synthetic `image_verification` tests do not stand for.
    #[test]
    fn the_real_key_rows_that_do_not_verify_are_counted() {
        let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_CFTT_SS") else {
            return;
        };
        let set = dir
            .join("string-search-federated-testing-data-set-version-1-1-revised-september-27-2019");
        let (Ok(text), Ok(mut img)) = (
            std::fs::read_to_string(set.join("win_string_doc.txt")),
            std::fs::File::open(set.join("copy-to-test-computer").join("ss-win-07-25-18.dd")),
        ) else {
            eprintln!("skipped: the key or the image is not present");
            return;
        };
        let key = parse_answer_key(&text);
        let mut differ = Vec::new();
        let mut unchecked = Vec::new();
        for e in &key.expectations {
            match verify_row(e, &mut img) {
                RowVerdict::Verified | RowVerdict::AtItsMarker => {}
                RowVerdict::BytesDiffer { at, .. } => differ.push(format!(
                    "{}:{}@{at} {} {:?}",
                    e.id, e.term, e.encoding, e.locus
                )),
                RowVerdict::NotChecked(why) => unchecked.push(format!("{}:{} {why}", e.id, e.term)),
            }
        }
        // Measured 2026-09-26: ONE row of 921 is contradicted by the image.
        // Row 7010 points at NTFS cluster 43456, which Sleuth Kit's `blkstat`
        // reports unallocated and whose bytes are all zero.
        assert_eq!(
            differ,
            ["7010:bear@1677997552 utf-16-le Allocated(\"ntfs\")"],
            "rows the image contradicts"
        );
        // The four `zipped` rows publish no offset: could not look.
        assert_eq!(unchecked.len(), 4, "{unchecked:?}");
        // Thirteen rows point at the publisher's own `<id> <====` marker
        // rather than the term: 7015, the six FMT rows 9000-9003/9006-9007
        // and their six unallocated copies 9508-9511/9514-9515.
        let mut marker: Vec<&str> = key
            .expectations
            .iter()
            .filter(|e| verify_row(e, &mut img) == RowVerdict::AtItsMarker)
            .map(|e| e.id.as_str())
            .collect();
        marker.sort();
        assert_eq!(
            marker,
            [
                "7015", "9000", "9001", "9002", "9003", "9006", "9007", "9508", "9509", "9510",
                "9511", "9514", "9515"
            ]
        );
        // And 7011 -- the other `LIVE-MFT-Ursa-mft-utf-16-be.txt` row --
        // checks out: `bear` in UTF-16BE inside MFT entry 301's resident data.
        let r7011 = key.expectations.iter().find(|e| e.id == "7011").unwrap();
        assert_eq!(verify_row(r7011, &mut img), RowVerdict::Verified);
        assert_eq!(
            key.expectations.len() - differ.len() - unchecked.len() - marker.len(),
            903,
            "the rows whose term is at the published offset"
        );
    }
}
