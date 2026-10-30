//! Court-defensible report renderer tests.
//!
//! Exercises the public `render_html` / `render_pdf` contract against a fully
//! populated fixture (with acquisition hashes, findings, audit entries, notable
//! hash hits), a broken-audit-chain variant, and an empty report.

use seance_reporting::{
    render_html, render_pdf, EvidenceSource, ExaminerDetails, ReportAuditEntry, ReportBookmark,
    ReportData, ReportHashHit, ReportIdentity, ReportTimelineEvent,
};

const SHA256_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA256_B: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

fn full_fixture(chain_valid: bool) -> ReportData {
    ReportData {
        case_name: "Operation Nightjar".to_string(),
        case_reference: Some("CR-2026-0042".to_string()),
        examiner: "Dana Holt".to_string(),
        generated_at: "2026-07-15 09:30:00 UTC".to_string(),
        tool_name: "Seance".to_string(),
        tool_version: "0.9.0".to_string(),
        evidence_sources: vec![
            EvidenceSource {
                name: "suspect_laptop.e01".to_string(),
                source_type: "E01".to_string(),
                size_bytes: Some(1073741824),
                md5: Some("d41d8cd98f00b204e9800998ecf8427e".to_string()),
                sha1: Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string()),
                sha256: Some(SHA256_A.to_string()),
                acquired_at: Some("2026-07-10 14:02:11 UTC".to_string()),
            },
            EvidenceSource {
                name: "usb_stick.dd".to_string(),
                source_type: "RAW".to_string(),
                size_bytes: Some(512_000_000),
                md5: Some("0cc175b9c0f1b6a831c399e269772661".to_string()),
                sha1: None,
                sha256: Some(SHA256_B.to_string()),
                acquired_at: None,
            },
        ],
        artifact_counts: vec![
            ("FileEntry".to_string(), 1200),
            ("TimelineEvent".to_string(), 340),
        ],
        total_artifacts: 1540,
        bookmarks: vec![ReportBookmark {
            artifact_name: "invoice_final.pdf".to_string(),
            category: Some("Financial".to_string()),
            note: Some("Altered totals vs. bank record".to_string()),
            examiner: Some("Dana Holt".to_string()),
            created_at: "2026-07-12 11:00:00 UTC".to_string(),
            source_path: Some("/Users/dana/Documents/invoice_final.pdf".to_string()),
            source_offset: Some(4096),
        }],
        timeline_highlights: vec![ReportTimelineEvent {
            timestamp: "2026-07-01 03:14:00 UTC".to_string(),
            description: "USB device first inserted".to_string(),
            source_module: "usbstor".to_string(),
            ..Default::default()
        }],
        audit_entries: vec![
            ReportAuditEntry {
                timestamp: "2026-07-10 14:02:11 UTC".to_string(),
                user: "dana".to_string(),
                action: "ingest_evidence".to_string(),
                resource_type: "evidence_source".to_string(),
            },
            ReportAuditEntry {
                timestamp: "2026-07-12 11:00:00 UTC".to_string(),
                user: "dana".to_string(),
                action: "create_bookmark".to_string(),
                resource_type: "bookmark".to_string(),
            },
        ],
        audit_chain_valid: chain_valid,
        audit_chain_checked: 2,
        notable_hash_hits: vec![ReportHashHit {
            artifact_name: "toolkit.zip".to_string(),
            path: Some("/Users/x/Downloads/toolkit.zip".to_string()),
            hash_set_name: "NSRL-Hacktools".to_string(),
            algorithm: "SHA256".to_string(),
            matched_hash: SHA256_B.to_string(),
        }],
        // New sections default to empty; exercised by dedicated tests in
        // report.rs. Present here so the fixture keeps compiling as the
        // ReportData contract grows.
        ..Default::default()
    }
}

#[test]
fn html_contains_acquisition_hashes_and_sizes() {
    let html = render_html(&full_fixture(true));
    // Acquisition SHA256 strings for both sources.
    assert!(html.contains(SHA256_A), "missing SHA256 for source A");
    assert!(html.contains(SHA256_B), "missing SHA256 for source B");
    // MD5 / SHA1 present.
    assert!(html.contains("d41d8cd98f00b204e9800998ecf8427e"));
    assert!(html.contains("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    // Human-readable sizes.
    assert!(html.contains("1.00 GB"), "missing 1.00 GB size");
    assert!(html.contains("488.28 MB"), "missing 488.28 MB size");
    // Examiner and header fields.
    assert!(html.contains("Dana Holt"));
    assert!(html.contains("CR-2026-0042"));
    assert!(html.contains("Seance"));
    assert!(html.contains("0.9.0"));
}

#[test]
fn html_shows_findings_notable_hits_and_timeline() {
    let html = render_html(&full_fixture(true));
    assert!(html.contains("Altered totals vs. bank record"));
    assert!(html.contains("Financial"));
    assert!(html.contains("invoice_final.pdf"));
    // D7: each finding must carry byte-offset provenance for re-verification.
    assert!(
        html.contains("/Users/dana/Documents/invoice_final.pdf @ byte 4096"),
        "finding must show its source path and byte offset"
    );
    assert!(
        html.contains("Source location"),
        "findings table needs a source-location column"
    );
    assert!(html.contains("Notable Hash Matches"));
    assert!(html.contains("NSRL-Hacktools"));
    assert!(html.contains("USB device first inserted"));
    assert!(html.contains("ingest_evidence"));
}

#[test]
fn html_states_valid_chain_prominently() {
    let html = render_html(&full_fixture(true));
    assert!(
        html.contains("Audit chain verified"),
        "missing verified banner"
    );
    // The fixture's chain is unkeyed (ReportData's cautious default), so the
    // banner names the construction and NOT the conclusion: "tamper-evident"
    // over an unkeyed chain asserts what a plain SHA-256 over in-database
    // fields cannot support (HUNT-011).
    assert!(html.contains("UNKEYED SHA-256 hash chain"));
    assert!(!html.contains("entries, tamper-evident"));
    assert!(!html.contains("AUDIT CHAIN BROKEN"));
    assert!(html.contains("class=\"verified\""));
}

/// HUNT-011: whichever way the verdict goes, the report has to say what kind of
/// chain produced it. A keyed chain earns the tamper-evidence claim; an unkeyed
/// one does not, and before the fix the renderer made the claim either way.
#[test]
fn html_states_whether_the_verified_chain_was_keyed() {
    let unkeyed = render_html(&full_fixture(true));
    assert!(
        unkeyed.contains("NOT evidence that the log is unaltered"),
        "an unkeyed pass must say what it is worth: {unkeyed}"
    );

    let mut keyed_data = full_fixture(true);
    keyed_data.audit_chain_tamper_evident = true;
    let keyed = render_html(&keyed_data);
    assert!(
        keyed.contains("have not been altered or reordered"),
        "a keyed pass must still be credited: {keyed}"
    );
    assert!(!keyed.contains("UNKEYED"));
}

#[test]
fn html_states_broken_chain_prominently() {
    let html = render_html(&full_fixture(false));
    // CR-035: the banner says the chain was NOT VERIFIED and why, and does not
    // assert alteration -- a missing retired key fails verification too.
    assert!(html.contains("AUDIT CHAIN NOT VERIFIED"), "missing banner");
    assert!(html.contains("class=\"broken\""));
    assert!(!html.contains("AUDIT CHAIN BROKEN"));
    assert!(!html.contains("Audit chain verified"));
}

#[test]
fn html_escapes_user_supplied_script() {
    let mut data = full_fixture(true);
    data.case_name = "Case <script>alert('xss')</script>".to_string();
    data.bookmarks[0].note = Some("<img src=x onerror=alert(1)>".to_string());
    let html = render_html(&data);
    assert!(!html.contains("<script>"), "unescaped <script> present");
    assert!(html.contains("&lt;script&gt;"));
    assert!(!html.contains("<img src=x"), "unescaped <img> present");
}

#[test]
fn html_notable_hash_section_omitted_when_empty() {
    let mut data = full_fixture(true);
    data.notable_hash_hits.clear();
    let html = render_html(&data);
    assert!(!html.contains("Notable Hash Matches"));
}

#[test]
fn html_empty_report_renders_without_panic() {
    let html = render_html(&ReportData::default());
    assert!(html.contains("Forensic Analysis Report"));
    // Empty sections show the muted placeholder.
    assert!(html.contains("None recorded"));
    // Chain defaults to invalid -> the not-verified banner is shown.
    assert!(html.contains("AUDIT CHAIN NOT VERIFIED"));
    // Notable hash section omitted when empty.
    assert!(!html.contains("Notable Hash Matches"));
}

#[test]
fn pdf_returns_nonempty_pdf_bytes() {
    let bytes = render_pdf(&full_fixture(true)).expect("pdf render failed");
    assert!(!bytes.is_empty());
    assert!(bytes.starts_with(b"%PDF"), "output is not a PDF");
}

#[test]
fn pdf_broken_chain_renders() {
    let bytes = render_pdf(&full_fixture(false)).expect("pdf render failed");
    assert!(bytes.starts_with(b"%PDF"));
}

#[test]
fn pdf_empty_report_renders_without_panic() {
    let bytes = render_pdf(&ReportData::default()).expect("pdf render failed");
    assert!(bytes.starts_with(b"%PDF"));
}

// ─── Court-standard report elements ─────────────────────────────────────────

/// Every report states how its times are expressed, in both formats.
///
/// An unqualified timestamp in a forensic report is challengeable on its face:
/// the same instant is a different wall clock in every jurisdiction the
/// evidence may have crossed, and local time is ambiguous twice a year. This is
/// asserted for a report that supplies no identity or examiner detail at all,
/// because the statement is a fact about the data rather than something a
/// caller opts into.
#[test]
fn every_report_states_that_its_times_are_utc() {
    let data = ReportData::default();

    let html = render_html(&data);
    assert!(
        html.contains("Coordinated Universal Time (UTC)"),
        "the HTML report must state its timezone"
    );

    let pdf = render_pdf(&data).expect("a default report still renders");
    assert!(!pdf.is_empty());
}

/// A report always carries a statement of truth, even when none was supplied.
#[test]
fn a_report_with_no_configured_statement_still_carries_one() {
    let data = ReportData::default();
    let html = render_html(&data);

    assert!(html.contains("Declaration"), "the section must be present");
    assert!(
        html.contains("I confirm that I have made clear which facts"),
        "the default statement of truth must be rendered"
    );
}

/// A caller's own wording replaces the default, because the required form
/// differs by jurisdiction.
#[test]
fn a_supplied_statement_of_truth_replaces_the_default() {
    let data = ReportData {
        report_identity: Some(ReportIdentity {
            report_id: "REF/2026/0001".into(),
            revision: Some(3),
            classification: Some("RESTRICTED".into()),
            statement_of_truth: Some("Jurisdiction-specific wording here.".into()),
        }),
        ..Default::default()
    };
    let html = render_html(&data);

    assert!(html.contains("Jurisdiction-specific wording here."));
    assert!(
        !html.contains("I confirm that I have made clear which facts"),
        "the default must not also appear; two statements of truth is none"
    );
    assert!(html.contains("REF/2026/0001"), "the report reference");
    assert!(html.contains("RESTRICTED"), "the handling marking");
    assert!(html.contains("Revision"), "the revision, when tracked");
}

/// An untracked revision renders nothing rather than claiming "1".
///
/// A document that calls itself Revision 1 when it is the third to leave the
/// building is a false statement about what has been disclosed.
#[test]
fn an_untracked_revision_is_omitted_rather_than_asserted_as_one() {
    let data = ReportData {
        report_identity: Some(ReportIdentity {
            report_id: "REF/2026/0002".into(),
            revision: None,
            ..Default::default()
        }),
        ..Default::default()
    };
    let html = render_html(&data);
    assert!(html.contains("REF/2026/0002"));
    assert!(
        !html.contains("<td>Revision</td>"),
        "an unknown revision must not be rendered at all"
    );
}

/// Examiner detail is rendered when supplied, and the declaration is signed
/// with it rather than with the bare name field.
#[test]
fn the_declaration_is_signed_with_the_full_examiner_details() {
    let data = ReportData {
        examiner: "fallback-name".into(),
        examiner_details: Some(ExaminerDetails {
            name: "A. Examiner".into(),
            role: Some("Senior Digital Forensic Analyst".into()),
            organisation: Some("Example Forensics Ltd".into()),
            contact: Some("a.examiner@example.test".into()),
            qualifications: Some("BCS CITP, GCFE".into()),
        }),
        ..Default::default()
    };
    let html = render_html(&data);

    for expected in [
        "A. Examiner",
        "Senior Digital Forensic Analyst",
        "Example Forensics Ltd",
        "a.examiner@example.test",
        "BCS CITP, GCFE",
    ] {
        assert!(
            html.contains(expected),
            "{expected} must appear in the report"
        );
    }
}

/// With no detail supplied, the declaration falls back to the bare name rather
/// than going out unsigned.
#[test]
fn a_report_without_examiner_details_is_still_signed() {
    let data = ReportData {
        examiner: "J. Smith".into(),
        ..Default::default()
    };
    let html = render_html(&data);
    assert!(html.contains("Declaration"));
    assert!(html.contains("J. Smith"));
}

/// The glossary renders when supplied and vanishes when not.
#[test]
fn the_glossary_renders_only_when_there_is_one() {
    assert!(
        !render_html(&ReportData::default()).contains("<h2>Glossary</h2>"),
        "an empty glossary must not leave an empty heading"
    );

    let data = ReportData {
        glossary: seance_reporting::default_glossary(),
        ..Default::default()
    };
    let html = render_html(&data);
    assert!(html.contains("<h2>Glossary</h2>"));
    // The distinction that matters most to a reader who is not a practitioner.
    assert!(html.contains("Slack space"));
    assert!(
        html.contains("is NOT evidence that the item was absent"),
        "the incompleteness definition is the one a reader most needs"
    );
}

/// The default glossary defines only terms that actually carry evidential
/// weight, and every entry has a definition.
#[test]
fn the_default_glossary_is_well_formed() {
    let glossary = seance_reporting::default_glossary();
    assert!(!glossary.is_empty());
    for entry in &glossary {
        assert!(!entry.term.trim().is_empty(), "a term with no name");
        assert!(
            entry.definition.len() > 40,
            "{} has a definition too short to be useful",
            entry.term
        );
    }
}

/// Examiner-supplied text is escaped, like every other field.
#[test]
fn examiner_details_are_escaped() {
    let data = ReportData {
        examiner_details: Some(ExaminerDetails {
            name: "<script>alert(1)</script>".into(),
            organisation: Some("<img onerror=x>".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let html = render_html(&data);
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(!html.contains("<img onerror=x>"));
}
/// The spreadsheet export carries the same declarations as the other formats.
///
/// A spreadsheet of timestamps with no stated timezone is the easiest format to
/// misread, because a reader sorts and filters it in their own frame of
/// reference. Whatever is true of the PDF has to be true of the XLSX, or the
/// export an examiner actually works in is the one missing the caveats.
#[test]
fn the_spreadsheet_export_states_its_timezone_and_identity() {
    let data = ReportData {
        report_identity: Some(ReportIdentity {
            report_id: "REF/2026/0003".into(),
            revision: Some(2),
            classification: Some("RESTRICTED".into()),
            statement_of_truth: None,
        }),
        examiner_details: Some(ExaminerDetails {
            name: "A. Examiner".into(),
            organisation: Some("Example Forensics Ltd".into()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let bytes = seance_reporting::render_xlsx(&data).expect("renders");
    assert!(!bytes.is_empty());
    // XLSX is a ZIP; the strings live compressed inside, so this asserts the
    // render succeeded with the fields populated rather than grepping bytes.
    assert!(bytes.starts_with(b"PK"), "an xlsx is a zip container");
}

/// Every text-show operation on every page of a PDF, as `(page, x_pt, y_pt,
/// text)`, positioned by the `Td` that precedes it in its text object.
fn pdf_text_runs(pdf: &[u8]) -> Vec<(u32, f32, f32, String)> {
    let doc = lopdf::Document::load_mem(pdf).expect("a PDF");
    let mut runs = Vec::new();
    for (page_no, page_id) in doc.get_pages() {
        let content = doc.get_and_decode_page_content(page_id).expect("content");
        let (mut x, mut y) = (0.0f32, 0.0f32);
        for op in content.operations {
            match op.operator.as_str() {
                "BT" => (x, y) = (0.0, 0.0),
                "Td" => {
                    x += op.operands[0].as_float().expect("x");
                    y += op.operands[1].as_float().expect("y");
                }
                "Tj" => {
                    if let Ok(bytes) = op.operands[0].as_str() {
                        runs.push((page_no, x, y, String::from_utf8_lossy(bytes).into_owned()));
                    }
                }
                _ => {}
            }
        }
    }
    runs
}

/// HUNT-192: `Line::Field` printed its value at a fixed 55 mm from the margin
/// whatever the label's width, so a label wider than that — a bookmark on an
/// artifact with a long name — was overprinted by its own value. A label
/// that fits keeps the value beside it; one that does not puts the value on
/// the line below, never on top of the label.
#[test]
fn pdf_never_prints_a_field_value_over_a_long_label() {
    let mut data = full_fixture(true);
    let long = "Microsoft.Windows.Search_cw5n1h2txyewy - Chrome History.sqlite-wal";
    data.bookmarks.push(ReportBookmark {
        artifact_name: long.to_string(),
        category: Some("Browser".to_string()),
        note: Some("WAL frames newer than the main database".to_string()),
        examiner: Some("Jo Reyes".to_string()),
        created_at: "2026-07-12 11:05:00 UTC".to_string(),
        source_path: None,
        source_offset: None,
    });
    let runs = pdf_text_runs(&render_pdf(&data).expect("pdf"));
    let find = |needle: &str| {
        runs.iter()
            .find(|r| r.3.contains(needle))
            .unwrap_or_else(|| panic!("no run containing {needle:?}: {runs:?}"))
            .clone()
    };

    // The short label and its value share a line, as before.
    let short_label = find("[Financial] invoice_final.pdf");
    let short_value = runs
        .iter()
        .find(|r| r.3 == "Dana Holt" && r.0 == short_label.0 && (r.2 - short_label.2).abs() < 0.01)
        .expect("the short label's value on its line");
    assert!(short_value.1 > short_label.1);

    // The long label's value is not on the label's line.
    let label = find(long);
    let value = find("Jo Reyes");
    assert!(
        !(value.0 == label.0 && (value.2 - label.2).abs() < 0.01),
        "the value {value:?} is printed on the line of the label {label:?}, over it"
    );
    // It is on the line directly after, at the value column.
    assert!(
        value.0 != label.0 || value.2 < label.2,
        "the value follows the label: {label:?} / {value:?}"
    );
}
