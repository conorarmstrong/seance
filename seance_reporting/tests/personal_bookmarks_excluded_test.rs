//! ROADMAP §3.15, owner decision 2026-09-26: personal bookmarks never reach a
//! report, and the report states how many were excluded so the exclusion is on
//! the record. Synthetic `ReportData`; this pins the wording, not evidence.

use seance_reporting::{
    personal_bookmarks_excluded_note, render_html, render_rtf, render_xml, ReportData,
};

fn data(excluded: i64) -> ReportData {
    ReportData {
        case_name: "Case".into(),
        personal_bookmarks_excluded: excluded,
        ..Default::default()
    }
}

#[test]
fn the_note_names_the_count_and_says_they_are_not_reported() {
    let note = personal_bookmarks_excluded_note(3).expect("three were excluded");
    assert!(note.contains('3'), "{note}");
    assert!(note.contains("personal"), "{note}");
    assert!(note.contains("not included"), "{note}");
    assert_eq!(personal_bookmarks_excluded_note(0), None);
    let one = personal_bookmarks_excluded_note(1).unwrap();
    assert!(one.contains("1 personal bookmark "), "singular: {one}");
}

#[test]
fn every_text_renderer_states_the_exclusion() {
    let note = personal_bookmarks_excluded_note(2).unwrap();
    assert!(render_html(&data(2)).contains(&note), "html");
    assert!(render_rtf(&data(2)).contains("personal bookmarks"), "rtf");
    let xml = render_xml(&data(2));
    assert!(
        xml.contains("<personal_bookmarks_excluded>2</personal_bookmarks_excluded>"),
        "xml"
    );
}

#[test]
fn no_exclusion_sentence_when_there_are_none() {
    assert!(!render_html(&data(0)).contains("personal bookmark"));
}
