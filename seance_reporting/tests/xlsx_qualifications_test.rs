//! The method-qualifications section, as the spreadsheet carries it.
//!
//! The XLSX is the export that actually leaves the lab, so a qualification that
//! reaches only the HTML and PDF reports is one the recipient of the workbook
//! never meets.
//!
//! These tests read the produced workbook back as the ZIP of XML it is and
//! resolve the cells the way Excel does — sheet name to relationship id, to the
//! worksheet part, to the shared-string table — rather than trusting that the
//! renderer returned `Ok` or that a string turned up somewhere in the archive.
//! A tab that is not named in `xl/workbook.xml`, and a statement that is in no
//! cell of it, is a section nobody will ever be shown.

use seance_reporting::{render_xlsx, MethodQualification, ReportData};
use std::collections::HashMap;
use std::io::Read;

/// The tab an examiner is meant to find the section on.
const SHEET_NAME: &str = "Limitations and Qualifications";

const SYMBOL_STATEMENT: &str = "No symbol file described this kernel, so the layouts were read \
                                out of the image itself and nothing independent corroborates them.";

fn case_with_qualifications() -> ReportData {
    ReportData {
        case_name: "Operation Kestrel".to_string(),
        examiner: "Dana Holt".to_string(),
        generated_at: "2026-08-20 11:00:00 UTC".to_string(),
        tool_name: "Seance".to_string(),
        tool_version: "0.9.0".to_string(),
        method_qualifications: vec![
            MethodQualification {
                subject: "Symbol source - Linux memory image".to_string(),
                statement: SYMBOL_STATEMENT.to_string(),
                affects: Some("Every finding read out of the memory image.".to_string()),
            },
            MethodQualification {
                subject: "Decompression ceiling".to_string(),
                statement: "Compressed members above the configured ceiling were listed but not \
                            decompressed, so their contents were never searched."
                    .to_string(),
                affects: None,
            },
        ],
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Just enough of the SpreadsheetML reading path to see what Excel would see
// ---------------------------------------------------------------------------

/// A parsed workbook: its parts, plus the shared-string table they index into.
struct Workbook {
    parts: HashMap<String, String>,
    shared_strings: Vec<String>,
}

impl Workbook {
    fn open(bytes: Vec<u8>) -> Self {
        let mut zip =
            zip::ZipArchive::new(std::io::Cursor::new(bytes)).expect("a valid ZIP archive");
        let mut parts = HashMap::new();
        for i in 0..zip.len() {
            let mut file = zip.by_index(i).expect("archive member");
            let name = file.name().unwrap().to_string();
            let mut body = String::new();
            // Every part this exporter writes is XML; anything that will not
            // decode as UTF-8 is not a part these tests read.
            if file.read_to_string(&mut body).is_ok() {
                parts.insert(name, body);
            }
        }
        let shared_strings = parts
            .get("xl/sharedStrings.xml")
            .map(|sst| {
                sst.split("<si>")
                    .skip(1)
                    .map(|si| unescape(&inner_text(si)))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            parts,
            shared_strings,
        }
    }

    fn part(&self, name: &str) -> &str {
        self.parts
            .get(name)
            .unwrap_or_else(|| panic!("workbook has no part {name}"))
    }

    /// The names of the workbook's tabs, in the order Excel shows them.
    fn sheet_names(&self) -> Vec<String> {
        self.part("xl/workbook.xml")
            .split("<sheet ")
            .skip(1)
            .filter_map(|s| attribute(s, "name"))
            .map(|n| unescape(&n))
            .collect()
    }

    /// One sheet's cells, keyed by their Excel reference ("A1", "B2", ...).
    ///
    /// Resolved through the same chain Excel walks, so a sheet wired to the
    /// wrong part or a cell pointing at the wrong shared string shows up here as
    /// the wrong text rather than passing unnoticed.
    fn cells(&self, sheet_name: &str) -> HashMap<String, String> {
        let sheet_tag = self
            .part("xl/workbook.xml")
            .split("<sheet ")
            .skip(1)
            .find(|s| attribute(s, "name").as_deref() == Some(sheet_name))
            .unwrap_or_else(|| panic!("no tab named {sheet_name}"))
            .to_string();
        let rel_id = attribute(&sheet_tag, "r:id").expect("sheet relationship id");
        let rels = self.part("xl/_rels/workbook.xml.rels");
        let target = rels
            .split("<Relationship ")
            .skip(1)
            .find(|r| attribute(r, "Id").as_deref() == Some(rel_id.as_str()))
            .and_then(|r| attribute(r, "Target"))
            .unwrap_or_else(|| panic!("no relationship {rel_id}"));
        let xml = self.part(&format!("xl/{}", target.trim_start_matches('/')));

        let mut cells = HashMap::new();
        for chunk in xml.split("<c ").skip(1) {
            let Some(reference) = attribute(chunk, "r") else {
                continue;
            };
            let Some(body) = chunk
                .split_once("<v>")
                .and_then(|(_, rest)| rest.split_once("</v>").map(|(value, _)| value.to_string()))
            else {
                continue;
            };
            let value = if attribute(chunk, "t").as_deref() == Some("s") {
                let idx: usize = body.parse().expect("shared-string index");
                self.shared_strings
                    .get(idx)
                    .unwrap_or_else(|| panic!("shared string {idx} is not in the table"))
                    .clone()
            } else {
                body
            };
            cells.insert(reference, value);
        }
        cells
    }
}

/// The value of an XML attribute in an element's opening tag.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')? + start;
    Some(tag[start..end].to_string())
}

/// The text of every `<t>` run inside a shared-string element.
fn inner_text(si: &str) -> String {
    let mut out = String::new();
    for run in si.split("<t").skip(1) {
        let Some((_, rest)) = run.split_once('>') else {
            continue;
        };
        if let Some((text, _)) = rest.split_once("</t>") {
            out.push_str(text);
        }
    }
    out
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn a_recorded_qualification_is_a_readable_sheet_in_the_saved_workbook() {
    let wb = Workbook::open(render_xlsx(&case_with_qualifications()).expect("the workbook"));

    let names = wb.sheet_names();
    assert!(
        names.iter().any(|n| n == SHEET_NAME),
        "no such tab in the workbook: {names:?}"
    );
    // After the findings, as in the HTML report: a reader has to have seen what
    // was found before being told what it rests on.
    assert_eq!(
        names.last().map(String::as_str),
        Some(SHEET_NAME),
        "the qualifications belong after the sections they qualify: {names:?}"
    );

    let cells = wb.cells(SHEET_NAME);
    assert_eq!(cells.get("A1").map(String::as_str), Some("Subject"));
    assert_eq!(cells.get("B1").map(String::as_str), Some("Qualification"));
    assert_eq!(cells.get("C1").map(String::as_str), Some("Bears on"));

    assert_eq!(
        cells.get("A2").map(String::as_str),
        Some("Symbol source - Linux memory image")
    );
    assert_eq!(cells.get("B2").map(String::as_str), Some(SYMBOL_STATEMENT));
    assert_eq!(
        cells.get("C2").map(String::as_str),
        Some("Every finding read out of the memory image.")
    );
    assert_eq!(
        cells.get("A3").map(String::as_str),
        Some("Decompression ceiling"),
        "every recorded qualification is listed, not just the first"
    );
}

/// `affects: None` means the qualification bears on the examination as a whole.
/// An empty cell in this workbook means the value was never recorded, which is
/// the opposite claim, so the sheet has to say which it is in words.
#[test]
fn a_qualification_bearing_on_everything_says_so_rather_than_leaving_a_blank() {
    let wb = Workbook::open(render_xlsx(&case_with_qualifications()).expect("the workbook"));
    let cells = wb.cells(SHEET_NAME);
    assert_eq!(
        cells.get("C3").map(String::as_str),
        Some(seance_reporting::QUALIFICATION_SCOPE_WHOLE_EXAMINATION),
        "an unscoped qualification must name its scope: {cells:?}"
    );
}

/// A reader who opens the Summary tab and stops there still has to be told the
/// section exists and where to find it.
#[test]
fn the_summary_tab_points_at_the_qualifications_sheet() {
    let wb = Workbook::open(render_xlsx(&case_with_qualifications()).expect("the workbook"));
    let cells = wb.cells("Summary");
    let pointer = cells
        .iter()
        .find(|(_, v)| v.as_str() == SHEET_NAME)
        .map(|(reference, _)| reference.replace('A', "B"))
        .and_then(|value_ref| cells.get(&value_ref).cloned())
        .expect("a Summary row naming the section");
    assert!(
        pointer.contains(SHEET_NAME) && pointer.contains('2'),
        "the pointer must name the sheet and how many were recorded: {pointer}"
    );
}

/// A report with no qualifications must not grow a tab that reads as "nothing
/// was qualified". An empty vector cannot tell an examination that raised no
/// qualification from one where nothing populated the field, so the workbook
/// asserts neither — exactly as the HTML and PDF renderers assert neither.
#[test]
fn an_examination_with_no_qualifications_grows_no_such_sheet() {
    let quiet = ReportData {
        case_name: "Operation Kestrel".to_string(),
        examiner: "Dana Holt".to_string(),
        ..Default::default()
    };
    let wb = Workbook::open(render_xlsx(&quiet).expect("the workbook"));
    let names = wb.sheet_names();
    assert!(
        !names.iter().any(|n| n.contains("Limitations")),
        "an empty qualifications section must not become a tab: {names:?}"
    );

    let strings = wb.shared_strings.join(" | ");
    for claim in ["None recorded", "No limitation", "no qualification"] {
        assert!(
            !strings.contains(claim),
            "the workbook must not assert that nothing qualified the method: {claim}"
        );
    }
}
