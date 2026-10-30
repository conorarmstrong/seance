//! NIST CFTT Mobile Device Data population, run in-house (`ROADMAP` §5.2).
//!
//! **Not third-party validation.** NIST has not tested this tool.
//!
//! # What the truth is here
//!
//! NIST publishes the handset population (`Mobile_Device_Data_Population_*.pdf`)
//! as "an example/template" with placeholders and prose instructions to the
//! populator. It is not an itemised answer key. By owner decision of
//! 2026-10-03 only four assertions are graded, and everything else says so:
//!
//! * `MDT-CA-02` PIM data present: one row per address-book entry.
//! * `MDT-CA-11` correct glyphs: exact Unicode text for the non-ASCII and
//!   special-character entries.
//! * `MDT-CA-12` the image is unchanged by the run.
//! * `MDT-CA-13` (notify on modification) is not applicable when `CA-12` holds.
//!
//! The expectations are the handset's own stored values, decoded independently
//! of Séance (`scripts/cftt/mdt-extract-key.sh`), each compared with the PDF.
//! A row records whether the PDF agrees; the PDF is a template, so a typed
//! difference (`Go Out` against the handset's `GoOut`) is stated, not graded
//! as a tool failure.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::CaseStatus;

/// One address-book entry as the handset's own database holds it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyContact {
    pub raw_id: i64,
    pub display_name: String,
    pub numbers: Vec<String>,
    pub emails: Vec<String>,
    pub deleted: bool,
    /// The PDF's label for the entry; `None` for an entry the PDF does not itemise.
    pub pdf_label: Option<String>,
    /// Whether the PDF's text for the entry equals what the handset stored.
    pub pdf_agrees: Option<bool>,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MdtKey {
    pub source: String,
    pub image: String,
    pub image_sha256: String,
    pub contacts: Vec<KeyContact>,
}

/// A Contact record as Séance published it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ReportedContact {
    pub rowid: i64,
    pub display_name: String,
    #[serde(default)]
    pub phone_numbers: Vec<String>,
    #[serde(default)]
    pub emails: Vec<String>,
    /// `None` when the record states no deleted flag at all.
    #[serde(default)]
    pub deleted: Option<bool>,
}

/// What the runner collected for the image.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ReportedMdt {
    pub image: String,
    #[serde(default)]
    pub ingest_complete: bool,
    #[serde(default)]
    pub contacts: Vec<ReportedContact>,
}

/// The image's identity before and after the whole run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImageState {
    pub sha256_before: Option<String>,
    pub sha256_after: Option<String>,
    /// Opaque `size mtime` strings, compared for equality.
    pub stat_before: Option<String>,
    pub stat_after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MdtGraded {
    pub assertion: String,
    pub subject: String,
    pub status: CaseStatus,
    pub expected: String,
    pub actual: String,
    pub note: String,
}

const TEMPLATE_REASON: &str = "the published population document is an example/template with \
placeholders and prose populator instructions (VALIDATION.md, owner decision 2026-10-03); the \
handset database was not used to grade a category the key does not itemise";

const AO_REASON: &str =
    "an acquisition objective: Séance performs no acquisition from a device or UICC";

fn nfc(s: &str) -> String {
    s.nfc().collect()
}

fn digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

fn sorted_digits(v: &[String]) -> Vec<String> {
    let mut d: Vec<String> = v.iter().map(|s| digits(s)).collect();
    d.sort();
    d
}

fn sorted_text(v: &[String]) -> Vec<String> {
    let mut d: Vec<String> = v.iter().map(|s| nfc(s)).collect();
    d.sort();
    d
}

fn row(
    assertion: &str,
    subject: String,
    status: CaseStatus,
    expected: String,
    actual: String,
    note: &str,
) -> MdtGraded {
    MdtGraded {
        assertion: assertion.to_string(),
        subject,
        status,
        expected,
        actual,
        note: note.to_string(),
    }
}

fn find<'a>(run: &'a ReportedMdt, k: &KeyContact) -> Option<&'a ReportedContact> {
    run.contacts.iter().find(|c| c.rowid == k.raw_id)
}

/// Subjects `MDT-CA-11` grades: the entries whose text is not plain ASCII
/// letters, or is a special character. Chosen by content, not by name.
fn is_glyph_subject(k: &KeyContact) -> bool {
    let n = &k.display_name;
    !n.is_ascii() || n.chars().count() > 50 || n.chars().all(|c| c.is_ascii_punctuation())
}

fn contact_expected(k: &KeyContact) -> String {
    format!(
        "name {:?}, digits {:?}, emails {:?}, deleted {}",
        k.display_name,
        sorted_digits(&k.numbers),
        k.emails,
        k.deleted
    )
}

fn contact_actual(c: Option<&ReportedContact>) -> String {
    match c {
        None => "no Contact record with this rowid".to_string(),
        Some(c) => format!(
            "name {:?}, digits {:?}, emails {:?}, deleted {}",
            c.display_name,
            sorted_digits(&c.phone_numbers),
            c.emails,
            c.deleted
                .map_or("not stated".to_string(), |d| d.to_string())
        ),
    }
}

fn pdf_note(k: &KeyContact) -> String {
    let mut parts = vec![
        "expectation is the handset's stored value (icat+sqlite3), phone numbers compared as digits"
            .to_string(),
    ];
    match (&k.pdf_label, k.pdf_agrees) {
        (None, _) => parts.push("entry is not itemised in the population PDF".into()),
        (Some(l), Some(true)) => parts.push(format!("PDF entry '{l}' agrees")),
        (Some(l), _) => parts.push(format!("PDF entry '{l}' differs: {}", k.note)),
    }
    parts.join("; ")
}

/// Grade one run. Pure: the same inputs give the same rows in the same order.
pub fn grade(key: &MdtKey, run: &ReportedMdt, image: &ImageState) -> Vec<MdtGraded> {
    use CaseStatus::*;
    let mut out = Vec::new();
    let complete = run.ingest_complete;
    let unfinished = "ingest was not seen to settle; nothing is graded from a partial result";

    // CA-01 and CA-03..CA-10: the template categories.
    for id in ["MDT-CA-01", "MDT-CA-03", "MDT-CA-04", "MDT-CA-05"]
        .into_iter()
        .chain([
            "MDT-CA-06",
            "MDT-CA-07",
            "MDT-CA-08",
            "MDT-CA-09",
            "MDT-CA-10",
        ])
    {
        out.push(row(
            id,
            "category".into(),
            NotAssessed,
            "-".into(),
            "-".into(),
            TEMPLATE_REASON,
        ));
    }

    // CA-02: one row per address-book entry.
    for k in &key.contacts {
        let got = find(run, k);
        let (status, note) = if !complete {
            (NotAssessed, unfinished.to_string())
        } else {
            let ok = got.is_some_and(|c| {
                nfc(&c.display_name) == nfc(&k.display_name)
                    && sorted_digits(&c.phone_numbers) == sorted_digits(&k.numbers)
                    && sorted_text(&c.emails) == sorted_text(&k.emails)
                    && c.deleted == Some(k.deleted)
            });
            (if ok { Pass } else { Fail }, pdf_note(k))
        };
        out.push(row(
            "MDT-CA-02",
            format!("contact {} (raw_contacts._id {})", k.display_name, k.raw_id),
            status,
            contact_expected(k),
            contact_actual(got),
            &note,
        ));
    }
    // Attributes of the PDF's entries that the contacts parser does not read.
    for what in [
        "website and picture (Jimi Hendrix)",
        "deleted picture, postal address and birthday (Stevie Ray Vaughn)",
        "group '27 Club' membership",
    ] {
        out.push(row(
            "MDT-CA-02",
            what.into(),
            NotAssessed,
            "-".into(),
            "-".into(),
            "the contacts parser does not read this attribute and says so (unmapped values are \
             counted on the record); it is not graded",
        ));
    }

    // CA-11: exact text, no normalisation applied to the tool's side beyond NFC.
    for k in key.contacts.iter().filter(|k| is_glyph_subject(k)) {
        let got = find(run, k);
        let (status, note) = if !complete {
            (NotAssessed, unfinished.to_string())
        } else {
            let ok = got.is_some_and(|c| nfc(&c.display_name) == nfc(&k.display_name));
            (
                if ok { Pass } else { Fail },
                "exact Unicode scalar equality after NFC on both sides; the expectation is the \
                 handset's stored text"
                    .to_string()
                    + &match (&k.pdf_label, k.pdf_agrees) {
                        (_, Some(false)) => format!("; the PDF's typed text differs ({})", k.note),
                        _ => String::new(),
                    },
            )
        };
        out.push(row(
            "MDT-CA-11",
            format!("glyphs of raw_contacts._id {}", k.raw_id),
            status,
            format!("{:?}", k.display_name),
            got.map_or("no Contact record".to_string(), |c| {
                format!("{:?}", c.display_name)
            }),
            &note,
        ));
    }

    // CA-12: the image is unchanged.
    let (s12, e12, a12, n12) = match (
        &image.sha256_before,
        &image.sha256_after,
        &image.stat_before,
        &image.stat_after,
    ) {
        (Some(b), Some(a), Some(sb), Some(sa)) => {
            if !b.eq_ignore_ascii_case(&key.image_sha256) {
                (
                    NotAssessed,
                    key.image_sha256.clone(),
                    b.clone(),
                    "the image examined is not the one the key was extracted from".to_string(),
                )
            } else if b.eq_ignore_ascii_case(a) && sb == sa {
                (
                    Pass,
                    format!("{b} {sb}"),
                    format!("{a} {sa}"),
                    "SHA-256, size and mtime equal before and after ingest and grading".to_string(),
                )
            } else {
                (
                    Fail,
                    format!("{b} {sb}"),
                    format!("{a} {sa}"),
                    "the image changed during the run".to_string(),
                )
            }
        }
        _ => (
            NotAssessed,
            "-".into(),
            "-".into(),
            "before/after digests or stat were not supplied".to_string(),
        ),
    };
    out.push(row("MDT-CA-12", "image".into(), s12, e12, a12, &n12));

    // CA-13: only reachable when CA-12 holds.
    let (s13, n13) = if s12 == Pass {
        (
            NotApplicable,
            "the tool did not modify the image (CA-12 passes) and has no write path to evidence; \
             a notification path is not exercised",
        )
    } else {
        (
            NotAssessed,
            "CA-12 did not pass, so whether the tool notified is a question this run did not examine",
        )
    };
    out.push(row(
        "MDT-CA-13",
        "image".into(),
        s13,
        "-".into(),
        "-".into(),
        n13,
    ));

    // Acquisition objectives.
    for n in 1..=17 {
        out.push(row(
            &format!("MDT-AO-{n:02}"),
            "acquisition".into(),
            NotApplicable,
            "-".into(),
            "-".into(),
            AO_REASON,
        ));
    }
    out
}

/// Counts by status, keyed by assertion id.
pub fn summarise(rows: &[MdtGraded]) -> BTreeMap<String, [usize; 4]> {
    let mut m: BTreeMap<String, [usize; 4]> = BTreeMap::new();
    for r in rows {
        let slot = m.entry(r.assertion.clone()).or_default();
        slot[match r.status {
            CaseStatus::Pass => 0,
            CaseStatus::Fail => 1,
            CaseStatus::NotApplicable => 2,
            _ => 3,
        }] += 1;
    }
    m
}

/// SHA-256 over the canonical JSON of the graded rows. Same inputs, same digest.
pub fn results_digest(rows: &[MdtGraded]) -> String {
    let json = serde_json::to_string(rows).expect("rows serialise");
    format!("{:x}", Sha256::digest(json.as_bytes()))
}

#[cfg(test)]
mod tests {
    //! Every input here is SYNTHETIC. These tests exercise the grader's logic
    //! and grade nothing about real-world evidence.
    use super::*;

    const IMG: &str = "9bba24c280d13658754b0dfc841a49ebf1379cf26490f73f5836f06a96f3239d";

    fn kc(id: i64, name: &str, nums: &[&str], deleted: bool) -> KeyContact {
        KeyContact {
            raw_id: id,
            display_name: name.into(),
            numbers: nums.iter().map(|s| s.to_string()).collect(),
            emails: vec![],
            deleted,
            pdf_label: Some("x".into()),
            pdf_agrees: Some(true),
            note: String::new(),
        }
    }

    fn key() -> MdtKey {
        MdtKey {
            source: "synthetic".into(),
            image: "synthetic.bin".into(),
            image_sha256: IMG.into(),
            contacts: vec![
                kc(1, "Aurélien", &["+33 22 6 555 20 20"], false),
                kc(2, "Gone", &["(987) 876-7654"], true),
            ],
        }
    }

    fn rc(id: i64, name: &str, nums: &[&str], deleted: Option<bool>) -> ReportedContact {
        ReportedContact {
            rowid: id,
            display_name: name.into(),
            phone_numbers: nums.iter().map(|s| s.to_string()).collect(),
            emails: vec![],
            deleted,
        }
    }

    fn good_run() -> ReportedMdt {
        ReportedMdt {
            image: "synthetic.bin".into(),
            ingest_complete: true,
            contacts: vec![
                rc(1, "Aurélien", &["+33 22 6 555 20 20"], Some(false)),
                rc(2, "Gone", &["9878767654"], Some(true)),
            ],
        }
    }

    fn state(after: &str) -> ImageState {
        ImageState {
            sha256_before: Some(IMG.into()),
            sha256_after: Some(after.into()),
            stat_before: Some("10 1".into()),
            stat_after: Some("10 1".into()),
        }
    }

    fn status_of(rows: &[MdtGraded], id: &str, subject_has: &str) -> CaseStatus {
        rows.iter()
            .find(|r| r.assertion == id && r.subject.contains(subject_has))
            .unwrap_or_else(|| panic!("no {id} row for {subject_has}"))
            .status
    }

    #[test]
    fn a_matching_run_passes_ca02_ca11_and_ca12() {
        let g = grade(&key(), &good_run(), &state(IMG));
        assert_eq!(status_of(&g, "MDT-CA-02", "Aurélien"), CaseStatus::Pass);
        assert_eq!(status_of(&g, "MDT-CA-02", "Gone"), CaseStatus::Pass);
        assert_eq!(status_of(&g, "MDT-CA-11", "_id 1"), CaseStatus::Pass);
        assert_eq!(status_of(&g, "MDT-CA-12", "image"), CaseStatus::Pass);
        assert_eq!(
            status_of(&g, "MDT-CA-13", "image"),
            CaseStatus::NotApplicable
        );
    }

    #[test]
    fn mojibake_fails_ca02_and_ca11() {
        let mut run = good_run();
        run.contacts[0].display_name = "Aur?lien".into();
        let g = grade(&key(), &run, &state(IMG));
        assert_eq!(status_of(&g, "MDT-CA-02", "Aur"), CaseStatus::Fail);
        assert_eq!(status_of(&g, "MDT-CA-11", "_id 1"), CaseStatus::Fail);
    }

    #[test]
    fn nfd_text_equals_nfc_text() {
        let mut run = good_run();
        run.contacts[0].display_name = "Aure\u{301}lien".into(); // e + combining acute
        let g = grade(&key(), &run, &state(IMG));
        assert_eq!(status_of(&g, "MDT-CA-11", "_id 1"), CaseStatus::Pass);
    }

    #[test]
    fn a_missing_deleted_flag_fails_and_a_wrong_one_fails() {
        let mut run = good_run();
        run.contacts[1].deleted = None;
        let g = grade(&key(), &run, &state(IMG));
        assert_eq!(status_of(&g, "MDT-CA-02", "Gone"), CaseStatus::Fail);
        run.contacts[1].deleted = Some(false);
        let g = grade(&key(), &run, &state(IMG));
        assert_eq!(status_of(&g, "MDT-CA-02", "Gone"), CaseStatus::Fail);
    }

    #[test]
    fn a_missing_record_fails() {
        let mut run = good_run();
        run.contacts.pop();
        let g = grade(&key(), &run, &state(IMG));
        assert_eq!(status_of(&g, "MDT-CA-02", "Gone"), CaseStatus::Fail);
    }

    #[test]
    fn a_changed_image_fails_ca12_and_leaves_ca13_unassessed() {
        let g = grade(&key(), &good_run(), &state(&"0".repeat(64)));
        assert_eq!(status_of(&g, "MDT-CA-12", "image"), CaseStatus::Fail);
        assert_eq!(status_of(&g, "MDT-CA-13", "image"), CaseStatus::NotAssessed);
    }

    #[test]
    fn a_different_image_than_the_key_is_not_assessed() {
        let mut s = state(&"1".repeat(64));
        s.sha256_before = Some("1".repeat(64));
        let g = grade(&key(), &good_run(), &s);
        assert_eq!(status_of(&g, "MDT-CA-12", "image"), CaseStatus::NotAssessed);
    }

    #[test]
    fn an_unsettled_ingest_grades_nothing() {
        let mut run = good_run();
        run.ingest_complete = false;
        let g = grade(&key(), &run, &state(IMG));
        assert_eq!(status_of(&g, "MDT-CA-02", "Gone"), CaseStatus::NotAssessed);
        assert_eq!(status_of(&g, "MDT-CA-11", "_id 1"), CaseStatus::NotAssessed);
    }

    #[test]
    fn template_categories_are_not_assessed_and_objectives_not_applicable() {
        let g = grade(&key(), &good_run(), &state(IMG));
        for id in [
            "MDT-CA-01",
            "MDT-CA-03",
            "MDT-CA-04",
            "MDT-CA-05",
            "MDT-CA-10",
        ] {
            assert_eq!(
                status_of(&g, id, "category"),
                CaseStatus::NotAssessed,
                "{id}"
            );
        }
        let ao: Vec<_> = g
            .iter()
            .filter(|r| r.assertion.starts_with("MDT-AO-"))
            .collect();
        assert_eq!(ao.len(), 17);
        assert!(ao.iter().all(|r| r.status == CaseStatus::NotApplicable));
    }

    #[test]
    fn the_digest_is_reproducible_and_sensitive() {
        let a = results_digest(&grade(&key(), &good_run(), &state(IMG)));
        let b = results_digest(&grade(&key(), &good_run(), &state(IMG)));
        assert_eq!(a, b);
        let mut run = good_run();
        run.contacts[0].display_name = "Aur?lien".into();
        assert_ne!(a, results_digest(&grade(&key(), &run, &state(IMG))));
    }

    /// The committed expectation file parses and is internally consistent.
    #[test]
    fn the_committed_key_parses() {
        let key: MdtKey = serde_json::from_str(include_str!(
            "../../tests/fixtures/cftt_mdt/htc_desire_s_contacts.json"
        ))
        .unwrap();
        assert_eq!(key.contacts.len(), 10);
        assert_eq!(key.contacts.iter().filter(|c| c.deleted).count(), 1);
        assert_eq!(key.image_sha256, IMG);
        // 4 glyph subjects: the star, the Chinese name, the long name, Aurélien.
        assert_eq!(
            key.contacts.iter().filter(|c| is_glyph_subject(c)).count(),
            4
        );
    }
}
