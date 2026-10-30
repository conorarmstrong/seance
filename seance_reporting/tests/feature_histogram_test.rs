//! The feature histograms baked into generated reports (ROADMAP §2.1): the
//! `FeatureHistogramSummary` record `plugin.bulk.features` publishes per scan,
//! rendered as the by-kind totals and the most-common values, with every cap
//! the record states carried onto the page.
//!
//! The section is always present, in one of three states — not gathered,
//! gathered and no record found, or rendered — because a section that
//! appears only when there is a histogram teaches the reader that its
//! absence means the scan found nothing.

use std::io::{Cursor, Read};

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use seance_reporting::{
    render_docx_with, render_html, render_html_with, render_pdf_with, render_rtf_with,
    render_xml_with, ReportData, ReportExtras, ReportFeatureHistogram, ReportFeatureKind,
    ReportFeatureValue, FEATURE_HISTOGRAMS_NOT_GATHERED,
};

fn histogram() -> ReportFeatureHistogram {
    ReportFeatureHistogram {
        source: "unallocated <sda1> & slack".into(),
        total_hits: 1_234,
        distinct_values: 3,
        hits_dropped: 0,
        capped: false,
        max_distinct_values: 100_000,
        top_n: 100,
        top_omitted: 0,
        top: vec![
            ReportFeatureValue {
                kind: "email".into(),
                value: "alice@example.com".into(),
                count: 900,
            },
            ReportFeatureValue {
                kind: "url".into(),
                value: "http://x.test/?a=1&b=<2>".into(),
                count: 300,
            },
            ReportFeatureValue {
                kind: "email".into(),
                value: "bob@example.com".into(),
                count: 34,
            },
        ],
        by_kind: vec![
            ReportFeatureKind {
                kind: "email".into(),
                hits: 934,
                distinct_values: 2,
            },
            ReportFeatureKind {
                kind: "url".into(),
                hits: 300,
                distinct_values: 1,
            },
        ],
        bytes_scanned: 21_883,
        scan_capped: false,
        short_read: false,
        source_size: 21_883,
        note: "Every distinct value the scan found is tracked (3 of at most 100000); counts \
               are exact."
            .into(),
    }
}

fn with(histograms: Vec<ReportFeatureHistogram>) -> ReportExtras {
    ReportExtras {
        feature_histograms: Some(histograms),
        ..Default::default()
    }
}

/// The slice of rendered HTML belonging to one `<h2>` section.
fn html_section<'a>(html: &'a str, title: &str) -> &'a str {
    let head = format!("<h2>{title}</h2>");
    let start = html
        .find(&head)
        .unwrap_or_else(|| panic!("no section {title}"));
    let rest = &html[start + head.len()..];
    match rest.find("<h2>") {
        Some(end) => &rest[..end],
        None => rest,
    }
}

fn docx_part(bytes: &[u8], name: &str) -> String {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).expect("a ZIP archive");
    let mut file = zip
        .by_name(name)
        .unwrap_or_else(|e| panic!("part {name} missing: {e}"));
    let mut s = String::new();
    file.read_to_string(&mut s).expect("utf-8 part");
    s
}

/// Every `<w:t>` text node in a WordprocessingML part, concatenated per
/// paragraph, in document order.
fn docx_paragraphs(xml: &str) -> Vec<String> {
    let mut reader = Reader::from_str(xml);
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_t = false;
    loop {
        match reader.read_event().expect("the part must parse as XML") {
            Event::Eof => break,
            Event::Start(e) => match e.name().as_ref() {
                b"w:t" => in_t = true,
                b"w:p" => current.clear(),
                _ => {}
            },
            Event::End(e) => match e.name().as_ref() {
                b"w:t" => in_t = false,
                b"w:p" => out.push(std::mem::take(&mut current)),
                _ => {}
            },
            Event::Text(t) if in_t => current.push_str(&t.unescape().expect("valid text")),
            _ => {}
        }
    }
    out
}

fn parses_as_xml(xml: &str) {
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);
    while reader.read_event().expect("the XML must parse") != Event::Eof {}
}

#[test]
fn a_report_without_the_histograms_says_they_were_not_gathered_not_that_none_exist() {
    let data = ReportData::default();
    let html = render_html(&data);
    let section = html_section(&html, "Feature Histograms");
    assert!(
        section.contains(FEATURE_HISTOGRAMS_NOT_GATHERED),
        "the plain render says the histograms were not supplied: {section}"
    );
    assert!(FEATURE_HISTOGRAMS_NOT_GATHERED.contains("not gathered"));
    assert!(!section.contains("<table"), "nothing to table: {section}");

    // Gathered and nothing found is a different statement: the scanner
    // publishes no record when it finds no hit, and a case it never ran on
    // has none either, so the report says both and claims neither.
    let html = render_html_with(&data, &with(vec![]));
    let section = html_section(&html, "Feature Histograms");
    assert!(
        section.contains("No FeatureHistogramSummary record"),
        "gathered and empty must be stated as such: {section}"
    );
    assert!(
        section.contains("did not run") && section.contains("found no hit"),
        "absence of a record is either of two things and the report must say so: {section}"
    );
    assert!(!section.contains("not gathered"), "{section}");

    for (name, out) in [
        ("rtf", render_rtf_with(&data, &ReportExtras::default())),
        ("xml", render_xml_with(&data, &ReportExtras::default())),
    ] {
        assert!(
            out.contains("not gathered"),
            "{name} must say the histograms were not gathered: {out}"
        );
    }
    let xml = render_xml_with(&data, &with(vec![]));
    assert!(
        xml.contains("<feature_histograms gathered=\"true\">"),
        "{xml}"
    );
    assert!(xml.contains("No FeatureHistogramSummary record"), "{xml}");
    let xml = render_xml_with(&data, &ReportExtras::default());
    assert!(
        xml.contains("<feature_histograms gathered=\"false\">"),
        "{xml}"
    );
}

#[test]
fn the_totals_and_by_kind_table_precede_the_most_common_values() {
    let data = ReportData::default();
    let html = render_html_with(&data, &with(vec![histogram()]));
    let section = html_section(&html, "Feature Histograms");

    // The scanned source names the sub-section, escaped.
    assert!(
        section.contains("unallocated &lt;sda1&gt; &amp; slack"),
        "{section}"
    );
    assert!(!section.contains("<sda1>"), "{section}");

    // The total line, then the by-kind table, then the most-common table.
    let total = section
        .find("1234 hit(s) over 3 distinct value(s)")
        .expect("the total line");
    let by_kind = section
        .find("<th>Kind</th><th>Hits</th><th>Distinct values</th>")
        .expect("by-kind table");
    let top = section
        .find("Most-common feature values")
        .expect("most-common table");
    assert!(total < by_kind && by_kind < top, "order: {section}");
    assert!(
        section.contains("<td>email</td><td>934</td><td>2</td>"),
        "{section}"
    );
    assert!(
        section.contains("<td>url</td><td>300</td><td>1</td>"),
        "{section}"
    );
    assert!(section.contains("21883 bytes"), "{section}");

    // The most-common table: kind / value / count, most-common first, the
    // value escaped rather than passed raw.
    assert!(
        section.contains("<th>Kind</th><th>Value</th><th>Count</th>"),
        "{section}"
    );
    let first = section
        .find("<td>email</td><td>alice@example.com</td><td>900</td>")
        .expect("row 1");
    let second = section
        .find("<td>url</td><td>http://x.test/?a=1&amp;b=&lt;2&gt;</td><td>300</td>")
        .expect("row 2, escaped");
    let third = section
        .find("<td>email</td><td>bob@example.com</td><td>34</td>")
        .expect("row 3");
    assert!(first < second && second < third, "{section}");
    assert!(!section.contains("b=<2>"), "{section}");

    // The record's own statement of its ceiling is carried verbatim.
    assert!(section.contains("counts are exact"), "{section}");
    // Nothing is missing, so nothing says so.
    assert!(!section.contains("Showing the"), "{section}");
    assert!(!section.contains("INCOMPLETE"), "{section}");
}

#[test]
fn a_longer_table_than_shown_is_disclosed_with_its_numbers() {
    let mut h = histogram();
    h.distinct_values = 2_345;
    h.top_omitted = 2_342;
    h.by_kind[0].distinct_values = 2_000;
    h.by_kind[1].distinct_values = 345;
    let data = ReportData::default();
    let html = render_html_with(&data, &with(vec![h.clone()]));
    let section = html_section(&html, "Feature Histograms");
    assert!(
        section.contains(
            "Showing the 3 most common of 2345 distinct values (the table lists at most 100); \
             2342 distinct value(s) are not listed."
        ),
        "{section}"
    );
    for out in [
        render_rtf_with(&data, &with(vec![h.clone()])),
        render_xml_with(&data, &with(vec![h.clone()])),
    ] {
        assert!(
            out.contains("2342 distinct value(s) are not listed"),
            "{out}"
        );
    }
    let xml = render_xml_with(&data, &with(vec![h]));
    assert!(xml.contains("top_omitted=\"2342\""), "{xml}");
}

#[test]
fn a_capped_histogram_carries_its_note_verbatim_and_is_never_rendered_as_exhaustive() {
    let mut h = histogram();
    h.capped = true;
    h.hits_dropped = 77;
    h.distinct_values = 100_000;
    h.top_omitted = 99_997;
    h.note = "Capped: the histogram tracks at most 100000 distinct values, and 77 hits for \
              values beyond that were not tallied. Counts for the tracked values are exact; \
              the distinct-value total is a floor, not the number the scan contained."
        .into();
    let data = ReportData::default();
    let extras = with(vec![h.clone()]);

    let html = render_html_with(&data, &extras);
    let section = html_section(&html, "Feature Histograms");
    assert!(section.contains(&h.note), "verbatim: {section}");
    assert!(
        section.contains("INCOMPLETE"),
        "a capped histogram is marked as such: {section}"
    );
    assert!(
        section.contains("at least 100000 distinct value(s)"),
        "a floor is stated as a floor: {section}"
    );
    assert!(
        !section.contains("over 100000 distinct value(s)"),
        "a floor must not be stated as a total: {section}"
    );
    assert!(!section.contains("counts are exact."), "{section}");
    // The scanner counts a turned-away hit against its kind before it is
    // dropped, so the per-kind hit column is complete even when capped; only
    // the most-common table and the distinct-value counts are bounded by the
    // ceiling. The INCOMPLETE line must draw that distinction, not describe
    // every table as covering the tracked values only.
    assert!(
        section.contains(
            "the most-common table below lists tracked values only, the distinct-value \
             counts in total and per kind are floors, and the per-kind hit counts include \
             the untallied hits"
        ),
        "{section}"
    );
    assert!(
        !section.contains("the tables below cover the tracked values only"),
        "{section}"
    );

    let rtf = render_rtf_with(&data, &extras);
    assert!(
        rtf.contains("77 hits for values beyond that were not tallied"),
        "{rtf}"
    );
    assert!(rtf.contains("INCOMPLETE"), "{rtf}");

    let xml = render_xml_with(&data, &extras);
    parses_as_xml(&xml);
    assert!(xml.contains("capped=\"true\""), "{xml}");
    assert!(xml.contains("hits_dropped=\"77\""), "{xml}");
    assert!(
        xml.contains("<note>Capped: the histogram tracks at most 100000"),
        "{xml}"
    );

    let docx = render_docx_with(&data, &extras).expect("docx");
    let paras = docx_paragraphs(&docx_part(&docx, "word/document.xml"));
    assert!(
        paras.iter().any(|p| p == &h.note),
        "the DOCX carries the note as one paragraph: {paras:?}"
    );
    assert!(paras.iter().any(|p| p.contains("INCOMPLETE")), "{paras:?}");
}

#[test]
fn a_scan_that_stopped_at_its_byte_ceiling_says_so_in_every_format() {
    let mut h = histogram();
    h.scan_capped = true;
    h.bytes_scanned = 8_589_934_592;
    let data = ReportData::default();
    let extras = with(vec![h]);
    let needle = "the scan stopped at its ceiling of 8589934592 bytes";
    let html = render_html_with(&data, &extras);
    let section = html_section(&html, "Feature Histograms");
    assert!(section.contains("INCOMPLETE"), "{section}");
    assert!(section.contains(needle), "{section}");
    assert!(
        section.contains("bytes beyond it were not read"),
        "{section}"
    );
    assert!(render_rtf_with(&data, &extras).contains(needle));
    let xml = render_xml_with(&data, &extras);
    assert!(xml.contains("scan_capped=\"true\""), "{xml}");
    assert!(xml.contains(needle), "{xml}");
    let docx = render_docx_with(&data, &extras).expect("docx");
    assert!(docx_part(&docx, "word/document.xml").contains(needle));
    let pdf = render_pdf_with(&data, &extras).expect("pdf");
    let doc = lopdf::Document::load_mem(&pdf).expect("a PDF");
    let pages: Vec<u32> = doc.get_pages().keys().copied().collect();
    let text = doc.extract_text(&pages).expect("text");
    assert!(text.contains("8589934592"), "{text}");
    assert!(text.contains("INCOMPLETE"), "{text}");
}

/// HUNT-193: a report that asked for the histograms and was refused at a
/// ceiling says so, with the reason, in every format — it must not read like
/// a report that never asked.
#[test]
fn a_refused_section_carries_its_reason_in_every_format() {
    let reason = "the case holds 1001 FeatureHistogramSummary records, more than the 1000 a \
                  report carries, so none is printed rather than a partial set; they remain \
                  in the case and can be read there.";
    let data = ReportData::default();
    let extras = ReportExtras {
        feature_histograms: None,
        feature_histograms_not_gathered_reason: Some(reason.into()),
        ..Default::default()
    };
    let html = render_html_with(&data, &extras);
    let section = html_section(&html, "Feature Histograms");
    assert!(
        section.contains(FEATURE_HISTOGRAMS_NOT_GATHERED),
        "{section}"
    );
    assert!(section.contains(&format!("Reason: {reason}")), "{section}");
    assert!(render_rtf_with(&data, &extras).contains("more than the 1000 a report carries"));
    let xml = render_xml_with(&data, &extras);
    parses_as_xml(&xml);
    assert!(
        xml.contains("<feature_histograms gathered=\"false\">"),
        "{xml}"
    );
    assert!(xml.contains(&format!("<reason>{reason}</reason>")), "{xml}");
    let docx = render_docx_with(&data, &extras).expect("docx");
    let paras = docx_paragraphs(&docx_part(&docx, "word/document.xml"));
    assert!(
        paras
            .iter()
            .any(|p| p.contains("Reason: the case holds 1001")),
        "{paras:?}"
    );
    let pdf = render_pdf_with(&data, &extras).expect("pdf");
    let doc = lopdf::Document::load_mem(&pdf).expect("a PDF");
    let pages: Vec<u32> = doc.get_pages().keys().copied().collect();
    let text = doc.extract_text(&pages).expect("text");
    assert!(text.contains("1001"), "{text}");

    // Nothing asked: the fixed sentence alone, with no reason invented.
    let html = render_html_with(&data, &ReportExtras::default());
    assert!(!html_section(&html, "Feature Histograms").contains("Reason:"));
    assert!(!render_xml_with(&data, &ReportExtras::default()).contains("<reason>"));
}

/// HUNT-194: a scan the source cut short says so — not that it stopped at its
/// own ceiling. HUNT-218: and it does not call what it read a prefix.
#[test]
fn a_short_read_is_stated_as_one_and_not_as_the_ceiling() {
    let mut h = histogram();
    h.short_read = true;
    h.bytes_scanned = 9_437_184;
    h.source_size = 20_971_520;
    let data = ReportData::default();
    let extras = with(vec![h]);
    // HUNT-218: since the sweep steps over an unreadable range and resumes,
    // `bytes_scanned` is the bytes read, not a prefix; the sentence must not
    // call it one, and it points at the FeatureSummary that lists the ranges.
    let needle = "the scan read 9437184 bytes of the 20971520 the source declared";
    let html = render_html_with(&data, &extras);
    let section = html_section(&html, "Feature Histograms");
    assert!(section.contains("INCOMPLETE"), "{section}");
    assert!(section.contains(needle), "{section}");
    assert!(section.contains("FeatureSummary"), "{section}");
    assert!(
        !section.contains("prefix"),
        "a scan that resumed past a gap did not read a prefix: {section}"
    );
    assert!(!section.contains("stopped at its ceiling"), "{section}");
    assert!(render_rtf_with(&data, &extras).contains(needle));
    let xml = render_xml_with(&data, &extras);
    assert!(
        xml.contains("short_read=\"true\" source_size=\"20971520\""),
        "{xml}"
    );
    assert!(xml.contains(needle), "{xml}");
    let docx = render_docx_with(&data, &extras).expect("docx");
    assert!(docx_part(&docx, "word/document.xml").contains(needle));
}

#[test]
fn every_format_carries_the_same_tables() {
    let data = ReportData::default();
    let extras = with(vec![histogram()]);

    let rtf = render_rtf_with(&data, &extras);
    assert!(rtf.contains("Feature Histograms"), "{rtf}");
    assert!(rtf.contains("Most-common feature values"), "{rtf}");
    assert!(rtf.contains("alice@example.com"), "{rtf}");
    assert!(
        rtf.contains("1234 hit(s) over 3 distinct value(s)"),
        "{rtf}"
    );
    assert_eq!(rtf.matches('{').count(), rtf.matches('}').count());

    let xml = render_xml_with(&data, &extras);
    parses_as_xml(&xml);
    assert!(
        xml.contains(
            "<feature_histogram source=\"unallocated &lt;sda1&gt; &amp; slack\" \
             total_hits=\"1234\" distinct_values=\"3\" hits_dropped=\"0\" capped=\"false\" \
             max_distinct_values=\"100000\" top_n=\"100\" top_omitted=\"0\" \
             bytes_scanned=\"21883\" scan_capped=\"false\" short_read=\"false\" \
             source_size=\"21883\">"
        ),
        "{xml}"
    );
    assert!(
        xml.contains("<kind name=\"email\" hits=\"934\" distinct_values=\"2\"/>"),
        "{xml}"
    );
    assert!(
        xml.contains(
            "<value kind=\"url\" count=\"300\">http://x.test/?a=1&amp;b=&lt;2&gt;</value>"
        ),
        "{xml}"
    );

    let docx = render_docx_with(&data, &extras).expect("docx");
    let paras = docx_paragraphs(&docx_part(&docx, "word/document.xml"));
    assert!(paras.iter().any(|p| p == "Feature Histograms"), "{paras:?}");
    assert!(
        paras.iter().any(|p| p == "unallocated <sda1> & slack"),
        "{paras:?}"
    );
    assert!(
        paras.iter().any(|p| p == "Most-common feature values"),
        "{paras:?}"
    );
    assert!(
        paras.iter().any(|p| p == "http://x.test/?a=1&b=<2>"),
        "the value round-trips through the DOCX escaping: {paras:?}"
    );
    assert!(paras.iter().any(|p| p == "900"), "{paras:?}");

    let pdf = render_pdf_with(&data, &extras).expect("pdf");
    let doc = lopdf::Document::load_mem(&pdf).expect("a PDF");
    let pages: Vec<u32> = doc.get_pages().keys().copied().collect();
    let text = doc.extract_text(&pages).expect("text");
    assert!(text.contains("Feature Histograms"), "{text}");
    assert!(text.contains("alice@example.com"), "{text}");
    assert!(text.contains("900"), "{text}");

    // The plain (extras-less) HTML and the extras-carrying HTML differ only
    // in this section: two renders of the same input are byte-identical.
    assert_eq!(
        render_html_with(&data, &extras),
        render_html_with(&data, &extras)
    );
}

/// HUNT-219: "gathered and none found" must not say every scan that found
/// nothing is silent. A scan that was capped or could not read part of its
/// source publishes a `FeatureSummary` saying so, and the sentence points the
/// reader at it.
#[test]
fn the_none_found_sentence_names_the_feature_summary_a_short_scan_publishes() {
    let html = render_html_with(&ReportData::default(), &with(vec![]));
    let section = html_section(&html, "Feature Histograms");
    assert!(section.contains("FeatureSummary"), "{section}");
    assert!(
        section.contains("could not read part of its source"),
        "{section}"
    );
    assert!(
        !section.contains("a scan that finds nothing publishes no record"),
        "the old absolute claim is gone: {section}"
    );
}
