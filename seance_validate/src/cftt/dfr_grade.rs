//! Grade a Deleted File Recovery run against NIST's layout-derived truth
//! (`ROADMAP` §5.2; the truth is [`super::dfr_layout`]).
//!
//! The four core assertions of the CFTT DFR specification (Draft 1 of
//! Version 1.1, 2009), **paraphrased here because the specification is not
//! held on disk** -- only `DFR-CR-04`'s wording is quoted in the plan, and the
//! rest are this grader's reading of it:
//!
//! | Assertion | What is checked here |
//! |---|---|
//! | `DFR-CR-01` | every deleted file that residual metadata still describes is listed, as deleted, by its name |
//! | `DFR-CR-02` | a recovered object (content) is produced for each of them |
//! | `DFR-CR-03` | that object includes every sector NIST's layout gives the file, when the file was not overwritten |
//! | `DFR-CR-04` | ("each Recovered Object shall consist only of data blocks from the Deleted Block Pool") no recovered sector is one NIST lists for an active file |
//!
//! The optional `DFR-RO-01`…`08` are **not graded**: their text is not held,
//! and grading assertions nobody here has read would be inventing them.
//!
//! What the grader will not do:
//!
//! * **A file NIST says has no metadata is not expected.** The layout names
//!   the deleted files "without metadata (cannot be found)"; the
//!   core assertions are conditional on residual metadata, so those files are
//!   graded "not applicable" with that reason. Where that list is elided, a
//!   file off the visible part is "not assessed". A list entry that is only a
//!   placeholder name is not taken as a statement about the real file (see
//!   [`metadata`]).
//! * **A file NIST's document elides is not graded by name.** 8,979 of the
//!   10,085 deleted files the layout declares are in rows it prints as
//!   `<N> omitted`; they are counted and graded "not assessed".
//! * **No inventory, or an ingest that did not finish, is not a failure.**
//!   Every row is then "not assessed".
//! * **Names are compared by canonical equivalence (NFC)**, so HFS+'s
//!   decomposed storage of `Gefäß` is the same name, and a transliteration
//!   (`BeiJing.txt` for `北京.txt`) is not.
//!
//! **Every failure carries exactly one non-conformance class** -- real
//! defect, declared gap, corpus divergence or grader artifact -- from the
//! caller's [`ClassRule`]s. A failure no rule explains is classed a real
//! defect until someone shows otherwise: the conservative default for a
//! report that may be read in court.

use unicode_normalization::UnicodeNormalization;

use super::dfr_layout::{DfrDeleted, DfrImageTruth};
use crate::CaseStatus;

/// One entry the tool reported for an image.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReportedEntry {
    /// The file's name as the tool presents it.
    pub name: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub size: Option<u64>,
    /// Whether the tool reports it as deleted.
    #[serde(default)]
    pub deleted: bool,
    /// Whether the tool produced content for it (a recovered object).
    #[serde(default)]
    pub has_content: bool,
    /// The image-absolute 512-byte sectors its content came from, when the
    /// tool reports them. `None` is "not reported", never "none".
    #[serde(default)]
    pub sectors: Option<Vec<(u64, u64)>>,
}

/// What the tool reported for one image.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReportedDfr {
    /// `dfr-01-ext.dd`.
    pub image: String,
    /// Whether the ingest was seen to complete. A run that did not is graded
    /// "not assessed" throughout (plan: idle is not committed).
    #[serde(default)]
    pub ingest_complete: bool,
    /// `None` when no inventory was collected.
    #[serde(default)]
    pub entries: Option<Vec<ReportedEntry>>,
}

/// Why a failure is a failure.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Nonconformance {
    RealDefect,
    DeclaredGap,
    CorpusDivergence,
    GraderArtifact,
}

/// A caller's explanation for a set of failures. Every set field must
/// match; the first matching rule wins.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct ClassRule {
    #[serde(default)]
    pub fs: Option<String>,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub assertion: Option<String>,
    #[serde(default)]
    pub file: Option<String>,
    pub class: Nonconformance,
    pub reason: String,
}

/// One graded assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfrGraded {
    pub image: String,
    pub assertion: &'static str,
    /// The file it concerns, as the image holds its name; `None` for a row
    /// about the image as a whole.
    pub file: Option<String>,
    pub status: CaseStatus,
    pub expected: String,
    pub actual: String,
    /// Set on every failure and on nothing else.
    pub class: Option<(Nonconformance, String)>,
}

/// Grade one image.
pub fn grade_dfr(
    truth: &DfrImageTruth,
    reported: &ReportedDfr,
    rules: &[ClassRule],
) -> Vec<DfrGraded> {
    let mut out = Vec::new();
    let mut push = |assertion: &'static str,
                    file: Option<String>,
                    status: CaseStatus,
                    expected: String,
                    actual: String| {
        let class = (status == CaseStatus::Fail)
            .then(|| classify(truth, assertion, file.as_deref(), rules));
        out.push(DfrGraded {
            image: truth.image.clone(),
            assertion,
            file,
            status,
            expected,
            actual,
            class,
        });
    };

    if truth.scenario.is_none() {
        push(
            "DFR-RO",
            None,
            CaseStatus::NotAssessed,
            "an active-file listing section (no DFR scenario line)".into(),
            "the optional listing assertions DFR-RO-01…08 are not graded: their text is not \
             held here"
                .into(),
        );
        return out;
    }
    if truth.omitted_deleted > 0 {
        push(
            "DFR-CR-01",
            None,
            CaseStatus::NotAssessed,
            format!(
                "{} deleted files NIST's layout declares",
                truth.declared_deleted
            ),
            format!(
                "{} of them are in rows NIST's own document elides (`omitted`), so they have no \
                 name or sectors to grade against",
                truth.omitted_deleted
            ),
        );
    }

    let not_assessed_why = if !reported.ingest_complete {
        Some(
            "the ingest was not seen to complete, so an absence may be something not yet processed",
        )
    } else if reported.entries.is_none() {
        Some("no inventory was collected for this image, so nothing about it was established")
    } else {
        None
    };
    let entries = reported.entries.as_deref().unwrap_or(&[]);
    let deleted_bases: Vec<&str> = truth.deleted.iter().map(|d| base_name(&d.name)).collect();
    let active: Vec<(&String, &Vec<(u64, u64)>)> = truth
        .sectors
        .iter()
        .filter(|(n, _)| !deleted_bases.contains(&n.as_str()))
        .collect();
    let active_incomplete = truth
        .incomplete_sectors
        .iter()
        .filter(|n| !deleted_bases.contains(&n.as_str()))
        .count();

    for d in &truth.deleted {
        let name = truth.real_name(d);
        let file = Some(name.clone());
        let truth_sectors = truth.sectors_of(&d.name);
        let crs = ["DFR-CR-01", "DFR-CR-02", "DFR-CR-03", "DFR-CR-04"];

        let meta = metadata(truth, d);
        if meta == Meta::Unknown {
            for a in crs {
                push(
                    a,
                    file.clone(),
                    CaseStatus::NotAssessed,
                    name.to_string(),
                    format!(
                        "whether residual metadata describes this file is not known: NIST's list \
                         of files without metadata elides {} entries",
                        truth.without_metadata_omitted
                    ),
                );
            }
            continue;
        }
        if meta == Meta::No {
            for a in crs {
                push(
                    a,
                    file.clone(),
                    CaseStatus::NotApplicable,
                    format!("{name}: NIST's layout says no residual metadata describes this file"),
                    "the assertion is conditional on residual metadata, which NIST says is not \
                     there; not expected, and not a pass"
                        .into(),
                );
            }
            continue;
        }
        if let Some(why) = not_assessed_why {
            for a in crs {
                push(
                    a,
                    file.clone(),
                    CaseStatus::NotAssessed,
                    name.to_string(),
                    why.into(),
                );
            }
            continue;
        }

        let want = nfc(&name);
        let fat = truth.fs() == "fat";
        let mut first_char_lost = false;
        let mut candidates: Vec<&ReportedEntry> = entries
            .iter()
            .filter(|e| e.deleted && nfc(base_name(&e.name)) == want)
            .collect();
        if candidates.is_empty() && fat {
            candidates = entries
                .iter()
                .filter(|e| e.deleted && fat_first_char_lost(base_name(&e.name), &name))
                .collect();
            first_char_lost = !candidates.is_empty();
        }
        let found = candidates
            .iter()
            .find(|e| match (&e.sectors, truth_sectors) {
                (Some(r), Some(t)) => overlaps(r, t),
                _ => false,
            })
            .or(candidates.first())
            .copied();

        // CR-01: listed, as deleted, by its name.
        let expect01 = format!("{name} ({} bytes) listed as deleted", d.size);
        match found {
            Some(e) => push(
                "DFR-CR-01",
                file.clone(),
                CaseStatus::Pass,
                expect01,
                format!(
                    "listed as {}{}{}",
                    e.path,
                    e.size.map(|s| format!(", {s} bytes")).unwrap_or_default(),
                    if first_char_lost {
                        "; matched without the first character, which FAT overwrites (0xE5) \
                         when it deletes a short-name entry"
                    } else {
                        ""
                    }
                ),
            ),
            None => {
                let near: Vec<&str> = entries
                    .iter()
                    .filter(|e| nfc(base_name(&e.name)) == want)
                    .map(|e| e.path.as_str())
                    .collect();
                push(
                    "DFR-CR-01",
                    file.clone(),
                    CaseStatus::Fail,
                    expect01,
                    if near.is_empty() {
                        "not listed".into()
                    } else {
                        format!("listed only as not deleted: {}", near.join(", "))
                    },
                )
            }
        }
        let Some(e) = found else {
            push(
                "DFR-CR-02",
                file.clone(),
                CaseStatus::Fail,
                format!("a recovered object for {name}"),
                "the file is not listed, so no object was produced for it".into(),
            );
            for a in ["DFR-CR-03", "DFR-CR-04"] {
                push(
                    a,
                    file.clone(),
                    CaseStatus::NotAssessed,
                    format!("{name}'s recovered object"),
                    "there is no recovered object to examine".into(),
                );
            }
            continue;
        };

        // CR-02: a recovered object exists.
        push(
            "DFR-CR-02",
            file.clone(),
            if e.has_content {
                CaseStatus::Pass
            } else {
                CaseStatus::Fail
            },
            format!("a recovered object for {name}"),
            if e.has_content {
                "content was produced".into()
            } else {
                "listed, but no content was produced".into()
            },
        );

        // CR-03: the object includes every sector NIST gives the file.
        let status = truth.file_status.get(base_name(&d.name)).copied();
        let cr03 = match (truth_sectors, &e.sectors, status) {
            (_, _, Some((total, intact))) if intact < total => (
                CaseStatus::NotAssessed,
                format!(
                    "NIST's layout says {intact} of its {total} sectors survive; which of the \
                     rest are still unallocated it does not state per sector"
                ),
            ),
            (None, _, _) => (
                CaseStatus::NotAssessed,
                "NIST's layout does not give this file's sectors in full".into(),
            ),
            (_, None, _) => (
                CaseStatus::NotAssessed,
                "the tool did not report which sectors the content came from".into(),
            ),
            (Some(t), Some(r), _) => {
                let missing = uncovered(t, r);
                if missing.is_empty() {
                    (CaseStatus::Pass, format!("all of {}", runs_str(t)))
                } else {
                    (CaseStatus::Fail, format!("missing {}", runs_str(&missing)))
                }
            }
        };
        push(
            "DFR-CR-03",
            file.clone(),
            cr03.0,
            format!(
                "every sector of {name}: {}",
                truth_sectors
                    .map(runs_str)
                    .unwrap_or_else(|| "not stated".into())
            ),
            cr03.1,
        );

        // CR-04: nothing from an active file.
        let cr04 = match &e.sectors {
            None => (
                CaseStatus::NotAssessed,
                "the tool did not report which sectors the content came from".to_string(),
            ),
            Some(r) => {
                let hits: Vec<String> = active
                    .iter()
                    .filter(|(_, a)| overlaps(r, a))
                    .map(|(n, _)| n.to_string())
                    .collect();
                if !hits.is_empty() {
                    (
                        CaseStatus::Fail,
                        format!(
                            "includes sectors NIST lists for active file(s) {}",
                            hits.join(", ")
                        ),
                    )
                } else if active_incomplete > 0 {
                    (
                        CaseStatus::NotAssessed,
                        format!(
                            "no overlap with the active files NIST lists in full, but {active_incomplete} \
                             active file(s) have sectors its document elides"
                        ),
                    )
                } else {
                    (CaseStatus::Pass, "no sector of any active file".into())
                }
            }
        };
        push(
            "DFR-CR-04",
            file,
            cr04.0,
            format!("{name}'s object holds only deleted-pool sectors"),
            cr04.1,
        );
    }
    out
}

/// Grade a whole run: every reported image against its truth section. An
/// image with no truth section is one "not assessed" row, never dropped.
pub fn grade_run(
    layout: &super::dfr_layout::DfrLayout,
    run: &[ReportedDfr],
    rules: &[ClassRule],
) -> Vec<DfrGraded> {
    let mut out = Vec::new();
    for r in run {
        match layout.for_dd(base_name(&r.image)) {
            Some(t) => out.extend(grade_dfr(t, r, rules)),
            None => out.push(DfrGraded {
                image: r.image.clone(),
                assertion: "DFR-CR-01",
                file: None,
                status: CaseStatus::NotAssessed,
                expected: "a section of NIST's layout document for this image".into(),
                actual: "the layout has no section for this image, so there is nothing to grade \
                         it against"
                    .into(),
                class: None,
            }),
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Meta {
    Yes,
    No,
    Unknown,
}

/// Whether NIST's layout says residual metadata describes this file, from
/// its "without metadata (cannot be found)" list.
///
/// A list entry that is a **placeholder** name (`BeiJing.txt` where the image
/// holds `北京.txt`) is not taken as a statement about the real file: on
/// `ntfs-04` and `xfat-04` the list is exactly the twelve placeholder names,
/// and on `ext-04`, `fat-04` and `osx-04` the same count reads "found 0"
/// beside "Metadata available for all deleted files". It is NIST's script
/// failing to find names that were never on the image, and excusing a tool
/// on it would excuse a miss nobody measured.
fn metadata(truth: &DfrImageTruth, d: &DfrDeleted) -> Meta {
    let real = truth.real_name(d);
    let base = base_name(&d.name);
    let placeholder = base != real;
    if truth.is_without_metadata(&real) || (!placeholder && truth.is_without_metadata(base)) {
        Meta::No
    } else if truth.without_metadata_omitted > 0 {
        Meta::Unknown
    } else {
        Meta::Yes
    }
}

fn classify(
    truth: &DfrImageTruth,
    assertion: &str,
    file: Option<&str>,
    rules: &[ClassRule],
) -> (Nonconformance, String) {
    let ok =
        |want: &Option<String>, have: Option<&str>| want.as_deref().is_none_or(|w| Some(w) == have);
    rules
        .iter()
        .find(|r| {
            ok(&r.fs, Some(truth.fs()))
                && ok(&r.image, Some(&truth.image))
                && ok(&r.assertion, Some(assertion))
                && ok(&r.file, file)
        })
        .map(|r| (r.class, r.reason.clone()))
        .unwrap_or((
            Nonconformance::RealDefect,
            "not yet explained, so presumed a defect until shown otherwise".into(),
        ))
}

/// Whether `reported` is `expected` with its first character lost the way
/// FAT loses it: a short-name entry's first byte becomes 0xE5 on deletion,
/// which a tool shows as a placeholder. Only for 8.3 names (an LFN keeps the
/// whole name), and the rest must match exactly, ignoring ASCII case as FAT
/// short names do.
fn fat_first_char_lost(reported: &str, expected: &str) -> bool {
    let is_83 = |n: &str| {
        let (stem, ext) = n.rsplit_once('.').unwrap_or((n, ""));
        (1..=8).contains(&stem.len()) && ext.len() <= 3 && n.is_ascii()
    };
    let mut r = reported.chars();
    let mut e = expected.chars();
    match (r.next(), e.next()) {
        (Some('_' | '?' | '\u{e5}' | '\u{3c3}'), Some(_)) => {
            is_83(expected) && r.as_str().eq_ignore_ascii_case(e.as_str())
        }
        _ => false,
    }
}

fn nfc(s: &str) -> String {
    s.nfc().collect()
}

fn base_name(p: &str) -> &str {
    p.rsplit(['/', '\\']).next().unwrap_or(p)
}

fn overlaps(a: &[(u64, u64)], b: &[(u64, u64)]) -> bool {
    a.iter()
        .any(|&(s1, e1)| b.iter().any(|&(s2, e2)| s1 <= e2 && s2 <= e1))
}

/// The parts of `want` that `have` does not cover.
fn uncovered(want: &[(u64, u64)], have: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for &(s, e) in want {
        let mut cur = s;
        let mut covering: Vec<(u64, u64)> = have
            .iter()
            .copied()
            .filter(|&(hs, he)| hs <= e && he >= s)
            .collect();
        covering.sort_unstable();
        for (hs, he) in covering {
            if hs > cur {
                out.push((cur, hs - 1));
            }
            cur = cur.max(he.saturating_add(1));
            if cur > e {
                break;
            }
        }
        if cur <= e {
            out.push((cur, e));
        }
    }
    out
}

fn runs_str(r: &[(u64, u64)]) -> String {
    r.iter()
        .map(|(s, e)| {
            if s == e {
                s.to_string()
            } else {
                format!("{s}-{e}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    //! The truth here is NIST's own text (the fixtures quote its layout
    //! document); the tool reports are synthetic, which is honest for a
    //! grader -- it is pure logic over the two -- and says nothing about how
    //! Séance does on the real images.
    use super::*;
    use crate::cftt::dfr_layout::parse_layout;

    const EXT_01: &str = include_str!("../../tests/fixtures/cftt_dfr/ext-01.txt");
    const EXT_04: &str = include_str!("../../tests/fixtures/cftt_dfr/ext-04.txt");
    const EXT_07: &str = include_str!("../../tests/fixtures/cftt_dfr/ext-07.txt");
    const OSX: &str = include_str!("../../tests/fixtures/cftt_dfr/osx-01-04.txt");

    fn truth(text: &str, image: &str) -> DfrImageTruth {
        parse_layout(text).image(image).unwrap().clone()
    }

    fn entry(name: &str, sectors: &[(u64, u64)]) -> ReportedEntry {
        ReportedEntry {
            name: name.into(),
            path: format!("/{name}"),
            size: Some(712),
            deleted: true,
            has_content: true,
            sectors: Some(sectors.to_vec()),
        }
    }

    fn run(entries: Vec<ReportedEntry>) -> ReportedDfr {
        ReportedDfr {
            image: "x.dd".into(),
            ingest_complete: true,
            entries: Some(entries),
        }
    }

    fn row<'a>(g: &'a [DfrGraded], a: &str, file: &str) -> &'a DfrGraded {
        g.iter()
            .find(|r| r.assertion == a && r.file.as_deref() == Some(file))
            .unwrap_or_else(|| panic!("no {a} row for {file}: {g:#?}"))
    }

    fn ext01_all_found() -> ReportedDfr {
        run(vec![
            entry("Bellatrix.txt", &[(7231, 7232)]),
            entry("Bunda.txt", &[(658406, 658407)]),
            entry("Botein.txt", &[(1319378, 1319379)]),
        ])
    }

    #[test]
    fn a_deleted_file_listed_with_correct_size_passes_dfr_cr_01() {
        let g = grade_dfr(&truth(EXT_01, "ext-01"), &ext01_all_found(), &[]);
        for f in ["Bellatrix.txt", "Bunda.txt", "Botein.txt"] {
            for a in ["DFR-CR-01", "DFR-CR-02", "DFR-CR-03", "DFR-CR-04"] {
                assert_eq!(row(&g, a, f).status, CaseStatus::Pass, "{a} {f}: {g:#?}");
            }
        }
    }

    #[test]
    fn a_missing_deleted_file_fails_cr_01_with_its_name() {
        let mut r = ext01_all_found();
        r.entries
            .as_mut()
            .unwrap()
            .retain(|e| e.name != "Bunda.txt");
        let g = grade_dfr(&truth(EXT_01, "ext-01"), &r, &[]);
        let cr01 = row(&g, "DFR-CR-01", "Bunda.txt");
        assert_eq!(cr01.status, CaseStatus::Fail);
        assert!(cr01.expected.contains("Bunda.txt"));
        assert_eq!(
            row(&g, "DFR-CR-01", "Bellatrix.txt").status,
            CaseStatus::Pass
        );
    }

    #[test]
    fn an_active_file_is_not_a_deleted_listing() {
        let mut r = ext01_all_found();
        r.entries.as_mut().unwrap()[0].deleted = false;
        let g = grade_dfr(&truth(EXT_01, "ext-01"), &r, &[]);
        assert_eq!(
            row(&g, "DFR-CR-01", "Bellatrix.txt").status,
            CaseStatus::Fail
        );
    }

    #[test]
    fn recovered_sectors_outside_the_deleted_pool_fail_cr_04() {
        let mut r = ext01_all_found();
        // Algol.txt, an active file, sits at 6207.
        r.entries.as_mut().unwrap()[0].sectors = Some(vec![(6207, 6207), (7231, 7232)]);
        let g = grade_dfr(&truth(EXT_01, "ext-01"), &r, &[]);
        let cr04 = row(&g, "DFR-CR-04", "Bellatrix.txt");
        assert_eq!(cr04.status, CaseStatus::Fail);
        assert!(cr04.actual.contains("Algol.txt"), "{}", cr04.actual);
    }

    #[test]
    fn a_recovered_object_missing_a_sector_fails_cr_03() {
        let mut r = ext01_all_found();
        r.entries.as_mut().unwrap()[0].sectors = Some(vec![(7231, 7231)]);
        let g = grade_dfr(&truth(EXT_01, "ext-01"), &r, &[]);
        assert_eq!(
            row(&g, "DFR-CR-03", "Bellatrix.txt").status,
            CaseStatus::Fail
        );
    }

    #[test]
    fn unreported_sectors_are_not_assessed_not_failed() {
        let mut r = ext01_all_found();
        r.entries.as_mut().unwrap()[0].sectors = None;
        let g = grade_dfr(&truth(EXT_01, "ext-01"), &r, &[]);
        assert_eq!(
            row(&g, "DFR-CR-03", "Bellatrix.txt").status,
            CaseStatus::NotAssessed
        );
        assert_eq!(
            row(&g, "DFR-CR-04", "Bellatrix.txt").status,
            CaseStatus::NotAssessed
        );
    }

    /// NIST's layout says two of osx-01's four deleted files keep metadata
    /// and names the other two. Recovering nothing therefore fails for the
    /// two it expects and is not applicable for the two it does not.
    #[test]
    fn osx_01_files_nist_says_have_no_metadata_are_not_expected() {
        let t = truth(OSX, "osx-01");
        let g = grade_dfr(&t, &run(vec![]), &[]);
        for f in ["Bellatrix.TXT", "xBellatrix.txt"] {
            assert_eq!(row(&g, "DFR-CR-01", f).status, CaseStatus::NotApplicable);
        }
        for f in ["Beid.txt", "Betelgeuse.txt"] {
            assert_eq!(row(&g, "DFR-CR-01", f).status, CaseStatus::Fail);
        }
    }

    /// osx-04's count reads "Metadata found 0 files" beside "Metadata
    /// available for all deleted files": the count is NIST's script failing
    /// to match placeholder names. It does not excuse the real files.
    #[test]
    fn osx_04_placeholder_counts_do_not_excuse_the_real_names() {
        let t = truth(OSX, "osx-04");
        assert_eq!(t.metadata_found, Some(0));
        let g = grade_dfr(&t, &run(vec![]), &[]);
        let cr01: Vec<&DfrGraded> = g.iter().filter(|r| r.assertion == "DFR-CR-01").collect();
        assert_eq!(cr01.len(), 48);
        assert!(cr01.iter().all(|r| r.status == CaseStatus::Fail));
        assert!(cr01.iter().any(|r| r.file.as_deref() == Some("北京.txt")));
    }

    /// ntfs-04's without-metadata list is the twelve placeholder names.
    #[test]
    fn a_without_metadata_list_of_placeholders_is_not_about_the_real_files() {
        let t = parse_layout(
            "\
49 Test Image ntfs-04
DFR-04.   Recover several non-fragmented files with non-ASCII file names.
1 files deleted
             Deleted files (1)
/tmp/dfr-04/BeiJing.txt 4096 (8+0) 1 7
1      create          /tmp/BeiJing.txt => 北京.txt)
No overwrites
ntfs-04 Metadata found 0 files, not found 1, total 1 deleted files
Deleted files without metadata (cannot be found)
BeiJing.txt

",
        )
        .image("ntfs-04")
        .unwrap()
        .clone();
        let g = grade_dfr(&t, &run(vec![]), &[]);
        assert_eq!(row(&g, "DFR-CR-01", "北京.txt").status, CaseStatus::Fail);
    }

    #[test]
    fn an_elided_without_metadata_list_leaves_unlisted_files_not_assessed() {
        let t = parse_layout(
            "\
37 Test Image fat-10
DFR-10.   Recover large number of files, with some overwritten.
2 files deleted
             Deleted files (2)
xB0000-1.txt 4096 (8+0) 1 7
xB0009-1.txt 4096 (8+0) 1 7
No overwrites
Deleted files without metadata (cannot be found)
xB0000-1.txt
  ...
5 omitted

",
        )
        .image("fat-10")
        .unwrap()
        .clone();
        let g = grade_dfr(&t, &run(vec![]), &[]);
        assert_eq!(
            row(&g, "DFR-CR-01", "xB0000-1.txt").status,
            CaseStatus::NotApplicable
        );
        assert_eq!(
            row(&g, "DFR-CR-01", "xB0009-1.txt").status,
            CaseStatus::NotAssessed
        );
    }

    #[test]
    fn non_latin_names_pass_only_when_they_match_by_canonical_equivalence() {
        let t = truth(EXT_04, "ext-04");
        let d = t
            .deleted
            .iter()
            .find(|d| d.name.ends_with("/BeiJing.txt3"))
            .unwrap();
        assert_eq!(t.real_name(d), "北京.txt3");
        let v = t
            .deleted
            .iter()
            .find(|d| d.name.ends_with("/Vessel.txt3"))
            .unwrap();
        let sectors_of =
            |d: &DfrDeleted| t.sectors_of(&d.name).map(<[_]>::to_vec).unwrap_or_default();
        let g = grade_dfr(
            &t,
            &run(vec![
                // A transliteration is not the name.
                entry("BeiJing.txt3", &sectors_of(d)),
                // Decomposed ä is the same name as precomposed.
                entry("Gefa\u{308}ß.txt3", &sectors_of(v)),
            ]),
            &[],
        );
        assert_eq!(row(&g, "DFR-CR-01", "北京.txt3").status, CaseStatus::Fail);
        assert_eq!(row(&g, "DFR-CR-01", "Gefäß.txt3").status, CaseStatus::Pass);
    }

    /// FAT marks a deleted short-name entry by overwriting its first byte
    /// (0xE5), so an 8.3-only name like `XBEID.TXT` loses its first
    /// character for good, and a tool shows `_BEID.TXT`. Measured on
    /// `dfr-01-fat.dd`, 2026-09-27. Matching the rest is the honest reading;
    /// anything else would fail every tool on a byte the disk no longer has.
    #[test]
    fn a_fat_short_name_matches_without_its_lost_first_character() {
        let t = parse_layout(
            "\
23 Test Image fat-01
DFR-01.    Recover one non-fragmented file.
1 files deleted
                  Deleted files (1)
XBEID.TXT     712 (1+200)  1  0
No overwrites
",
        )
        .image("fat-01")
        .unwrap()
        .clone();
        let g = grade_dfr(&t, &run(vec![entry("_BEID.TXT", &[(298, 299)])]), &[]);
        let r = row(&g, "DFR-CR-01", "XBEID.TXT");
        assert_eq!(r.status, CaseStatus::Pass, "{r:#?}");
        assert!(r.actual.contains("first character"), "{}", r.actual);
        // Not on exFAT or anywhere else, and not when the rest differs.
        let g = grade_dfr(&t, &run(vec![entry("_BEIX.TXT", &[(298, 299)])]), &[]);
        assert_eq!(row(&g, "DFR-CR-01", "XBEID.TXT").status, CaseStatus::Fail);
        let mut ext = t.clone();
        ext.image = "ext-01".into();
        let g = grade_dfr(&ext, &run(vec![entry("_BEID.TXT", &[(298, 299)])]), &[]);
        assert_eq!(row(&g, "DFR-CR-01", "XBEID.TXT").status, CaseStatus::Fail);
    }

    #[test]
    fn no_inventory_is_not_assessed_never_fail() {
        let t = truth(EXT_01, "ext-01");
        for r in [
            ReportedDfr {
                image: "x".into(),
                ingest_complete: true,
                entries: None,
            },
            ReportedDfr {
                ingest_complete: false,
                ..ext01_all_found()
            },
        ] {
            let g = grade_dfr(&t, &r, &[]);
            assert!(!g.is_empty());
            assert!(
                g.iter().all(|r| r.status == CaseStatus::NotAssessed),
                "{g:#?}"
            );
        }
    }

    #[test]
    fn every_fail_carries_exactly_one_nonconformance_class() {
        let t = truth(EXT_07, "ext-07");
        let rules = [ClassRule {
            fs: Some("ext".into()),
            image: None,
            assertion: Some("DFR-CR-02".into()),
            file: None,
            class: Nonconformance::DeclaredGap,
            reason: "a stated gap, for the test".into(),
        }];
        let g = grade_dfr(&t, &run(vec![]), &rules);
        assert!(g.iter().any(|r| r.status == CaseStatus::Fail));
        for r in &g {
            assert_eq!(r.status == CaseStatus::Fail, r.class.is_some(), "{r:#?}");
        }
        assert!(g
            .iter()
            .filter(|r| r.assertion == "DFR-CR-02" && r.status == CaseStatus::Fail)
            .all(|r| r.class.as_ref().unwrap().0 == Nonconformance::DeclaredGap));
        assert!(g
            .iter()
            .filter(|r| r.assertion == "DFR-CR-01" && r.status == CaseStatus::Fail)
            .all(|r| r.class.as_ref().unwrap().0 == Nonconformance::RealDefect));
    }

    #[test]
    fn elided_files_are_one_not_assessed_row_with_the_count() {
        let t = parse_layout(
            "\
14 Test Image ext-09
DFR-09.   Recover large number of files no overwrite.
3 files deleted
             Deleted files (3)
xB0001-3.txt 4096 (8+0) 1         7
  ...
2 omitted
No overwrites
",
        )
        .image("ext-09")
        .unwrap()
        .clone();
        let g = grade_dfr(&t, &run(vec![]), &[]);
        let elided: Vec<&DfrGraded> = g.iter().filter(|r| r.file.is_none()).collect();
        assert_eq!(elided.len(), 1);
        assert_eq!(elided[0].status, CaseStatus::NotAssessed);
        assert!(elided[0].actual.contains('2'));
    }
}
