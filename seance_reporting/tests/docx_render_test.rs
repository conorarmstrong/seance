//! `render_docx` (ROADMAP §2.10): the report as a Word document, checked by
//! unzipping the bytes and parsing the parts with a real XML reader rather
//! than by string-matching the archive.

use std::collections::HashSet;
use std::io::{Cursor, Read};

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use seance_reporting::{
    default_glossary, render_docx, render_docx_with, statement_of_truth, ExaminerDetails,
    IncompletenessReason, IncompletenessSummary, IntegrityCheck, IntegrityOutcome,
    MethodQualification, ReportBookmark, ReportCommEdge, ReportCommNode, ReportCommunicationGraph,
    ReportData, ReportExtras, ReportIdentity, ReportTimelineEvent, TIMEZONE_STATEMENT,
};

fn fixture() -> ReportData {
    ReportData {
        case_name: "Case <Omega> & \"Co\"".into(),
        case_reference: Some("REF-2026-042".into()),
        examiner: "Backup Examiner".into(),
        generated_at: "2026-09-19T10:00:00Z".into(),
        tool_name: "Seance".into(),
        tool_version: "1.2.0".into(),
        executive_summary: Some("One source.\nOne mismatch.".into()),
        integrity_checks: vec![IntegrityCheck {
            source_name: "disk.e01".into(),
            algorithm: "SHA256".into(),
            acquisition_hash: Some("aaa".into()),
            recomputed_hash: Some("bbb".into()),
            outcome: IntegrityOutcome::Failed,
            checked_at: None,
        }],
        artifact_counts: vec![("web_history".into(), 12)],
        total_artifacts: 12,
        bookmarks: vec![ReportBookmark {
            artifact_name: "Report<Name>&\"Quote\"".into(),
            category: Some("Web".into()),
            note: Some("line one\nline two".into()),
            examiner: Some("Backup Examiner".into()),
            created_at: "2026-09-10".into(),
            source_path: Some("/C/Users/x".into()),
            source_offset: Some(4096),
        }],
        full_timeline: vec![
            ReportTimelineEvent {
                timestamp: "2026-07-01T08:00:00+00:00".into(),
                description: "event".into(),
                source_module: "mft".into(),
                ..Default::default()
            },
            ReportTimelineEvent {
                timestamp: "2026-07-02T08:00:00+00:00".into(),
                description: "event".into(),
                source_module: "mft".into(),
                ..Default::default()
            },
        ],
        full_timeline_total: 2,
        audit_chain_valid: true,
        audit_chain_checked: 3,
        incompleteness: Some(IncompletenessSummary {
            content_incomplete: 1,
            reasons: vec![IncompletenessReason {
                reason: Some("hive exceeded the cap".into()),
                count: 1,
            }],
            distinct_reasons: 1,
            ..Default::default()
        }),
        examiner_details: Some(ExaminerDetails {
            name: "Backup Examiner".into(),
            role: Some("Senior Analyst".into()),
            organisation: Some("Example Forensics Ltd".into()),
            contact: None,
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
            affects: None,
        }],
        ..Default::default()
    }
}

fn extras() -> ReportExtras {
    ReportExtras {
        communications: Some(ReportCommunicationGraph {
            nodes: vec![
                ReportCommNode {
                    id: "\u{1}self".into(),
                    label: "This device".into(),
                    kind: "self".into(),
                    weight: 4,
                },
                ReportCommNode {
                    id: "alice".into(),
                    label: "Alice".into(),
                    kind: "contact".into(),
                    weight: 4,
                },
            ],
            edges: vec![ReportCommEdge {
                source: "\u{1}self".into(),
                target: "alice".into(),
                weight: 4,
            }],
            truncated: false,
            total_participants: 2,
            unusable_email_records: 0,
        }),
        ..Default::default()
    }
}

fn part(bytes: &[u8], name: &str) -> String {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).expect("a ZIP archive");
    let mut file = zip
        .by_name(name)
        .unwrap_or_else(|e| panic!("part {name} missing: {e}"));
    let mut s = String::new();
    file.read_to_string(&mut s).expect("utf-8 part");
    s
}

/// Every `<w:t>` text node in a WordprocessingML part, in document order,
/// concatenated per paragraph.
fn paragraphs(xml: &str) -> Vec<String> {
    let mut reader = Reader::from_str(xml);
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_t = false;
    let mut depth = 0i32;
    loop {
        match reader.read_event().expect("the part must parse as XML") {
            Event::Eof => break,
            Event::Start(e) => {
                depth += 1;
                match e.name().as_ref() {
                    b"w:t" => in_t = true,
                    b"w:p" => current.clear(),
                    _ => {}
                }
            }
            Event::End(e) => {
                depth -= 1;
                match e.name().as_ref() {
                    b"w:t" => in_t = false,
                    b"w:p" => out.push(std::mem::take(&mut current)),
                    _ => {}
                }
            }
            Event::Empty(e) if e.name().as_ref() == b"w:br" => current.push('\n'),
            Event::Text(t) if in_t => current.push_str(&t.unescape().expect("valid text")),
            _ => {}
        }
    }
    assert_eq!(depth, 0, "every opened element must be closed");
    out
}

#[test]
fn the_docx_is_a_zip_whose_content_types_declare_the_main_document_part() {
    let bytes = render_docx_with(&fixture(), &extras()).expect("docx");
    assert_eq!(&bytes[..2], b"PK", "a DOCX is a ZIP archive");
    let ct = part(&bytes, "[Content_Types].xml");
    assert!(
        ct.contains("PartName=\"/word/document.xml\"")
            && ct.contains(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
            ),
        "{ct}"
    );
    let rels = part(&bytes, "_rels/.rels");
    assert!(rels.contains("Target=\"word/document.xml\""), "{rels}");
    for name in [
        "word/document.xml",
        "word/_rels/document.xml.rels",
        "word/styles.xml",
    ] {
        part(&bytes, name);
    }
}

#[test]
fn every_section_heading_and_the_statement_of_truth_are_present() {
    let data = fixture();
    let bytes = render_docx_with(&data, &extras()).expect("docx");
    let doc = part(&bytes, "word/document.xml");
    let paras = paragraphs(&doc);
    let set: HashSet<&str> = paras.iter().map(String::as_str).collect();

    for heading in [
        "Times",
        "Executive Summary",
        "Result Completeness",
        "Evidence Sources",
        "Evidence Integrity",
        "Artifact Statistics",
        "Findings / Bookmarks",
        "Communications Network",
        "Feature Histograms",
        "Timeline Highlights",
        "Timeline",
        "Chain of Custody & Audit",
        "Limitations and Qualifications of the Examination",
        "Glossary",
        "Declaration",
        "Methodology & Notes",
    ] {
        assert!(
            set.contains(heading),
            "DOCX missing section heading {heading:?}; paragraphs were {paras:#?}"
        );
    }
    assert!(
        set.contains(statement_of_truth(&data)),
        "statement of truth"
    );
    assert!(set.contains(TIMEZONE_STATEMENT), "timezone statement");
    // Examiner detail and identity reach the header and the signature block.
    let joined = paras.join("\n");
    for needle in [
        "RPT-001",
        "RESTRICTED",
        "Senior Analyst",
        "Example Forensics Ltd",
        "CFCE",
        "MISMATCH",
        "INCOMPLETE",
        "hive exceeded the cap",
        "Symbol source",
        "The examination as a whole.",
        "Slack space",
    ] {
        assert!(joined.contains(needle), "DOCX missing {needle:?}");
    }
}

#[test]
fn xml_special_characters_in_user_data_are_escaped_and_round_trip() {
    let bytes = render_docx_with(&fixture(), &extras()).expect("docx");
    let doc = part(&bytes, "word/document.xml");
    // Raw, unescaped user text must never reach the part.
    assert!(!doc.contains("Report<Name>"), "{doc}");
    assert!(!doc.contains("Case <Omega>"), "{doc}");
    let paras = paragraphs(&doc);
    assert!(
        paras.iter().any(|p| p.contains("Report<Name>&\"Quote\"")),
        "the bookmark's name must round-trip exactly through XML escaping: {paras:#?}"
    );
    assert!(
        paras
            .iter()
            .any(|p| p == "Forensic Analysis Report: Case <Omega> & \"Co\""),
        "{paras:#?}"
    );
    // A newline in user text becomes a line break, not a dropped character.
    assert!(
        paras.iter().any(|p| p == "line one\nline two"),
        "{paras:#?}"
    );
}

#[test]
fn control_characters_that_xml_cannot_carry_are_stripped_not_emitted() {
    let mut data = fixture();
    data.bookmarks[0].note = Some("bad\u{1}byte".into());
    let bytes = render_docx_with(&data, &extras()).expect("docx");
    let doc = part(&bytes, "word/document.xml");
    assert!(!doc.contains('\u{1}'));
    let paras = paragraphs(&doc);
    assert!(paras.iter().any(|p| p == "badbyte"), "{paras:#?}");
}

#[test]
fn the_figures_are_embedded_as_images_with_captions() {
    let bytes = render_docx_with(&fixture(), &extras()).expect("docx");
    let doc = part(&bytes, "word/document.xml");
    assert_eq!(
        doc.matches("<w:drawing>").count(),
        2,
        "one drawing per figure: {doc}"
    );
    let rels = part(&bytes, "word/_rels/document.xml.rels");
    assert!(rels.contains("Target=\"media/figure1.svg\""), "{rels}");
    assert!(rels.contains("Target=\"media/figure2.svg\""), "{rels}");
    let ct = part(&bytes, "[Content_Types].xml");
    assert!(ct.contains("image/svg+xml"), "{ct}");
    let svg = part(&bytes, "word/media/figure1.svg");
    assert!(svg.starts_with("<svg"), "{svg}");
    let paras = paragraphs(&doc);
    assert!(
        paras.iter().any(|p| p.starts_with("Figure 1")),
        "{paras:#?}"
    );
    assert!(
        paras.iter().any(|p| p.starts_with("Figure 2")),
        "{paras:#?}"
    );
}

#[test]
fn an_empty_report_still_renders_the_always_on_sections() {
    let bytes = render_docx(&ReportData::default()).expect("docx");
    let doc = part(&bytes, "word/document.xml");
    let paras = paragraphs(&doc);
    let set: HashSet<&str> = paras.iter().map(String::as_str).collect();
    for heading in [
        "Evidence Sources",
        "Result Completeness",
        "Findings / Bookmarks",
        "Communications Network",
        "Feature Histograms",
        "Timeline Highlights",
        "Chain of Custody & Audit",
        "Declaration",
    ] {
        assert!(set.contains(heading), "{heading}: {paras:#?}");
    }
    for absent in ["Executive Summary", "Glossary", "Evidence Integrity"] {
        assert!(!set.contains(absent), "{absent} must be omitted when empty");
    }
    assert!(!doc.contains("<w:drawing>"), "no data, no figures");
    assert!(set.contains("None recorded"));
}
