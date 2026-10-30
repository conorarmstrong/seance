//! The report as a Word document (ROADMAP §2.10).
//!
//! A DOCX is a ZIP archive of Office Open XML parts. This writes the five a
//! reader needs — `[Content_Types].xml`, `_rels/.rels`, `word/document.xml`,
//! `word/_rels/document.xml.rels`, `word/styles.xml` — plus one SVG part per
//! figure, by hand: the WordprocessingML this report uses is a title, two
//! heading levels, paragraphs, tables and inline pictures, and a dependency
//! that generated it would be larger than the markup.
//!
//! Section for section it follows [`render_html`](crate::render_html), the
//! way `render_rtf` does: every section the HTML renders unconditionally is
//! rendered unconditionally here, every section it omits when empty is omitted
//! under the same condition, and the statements (timezone, completeness,
//! integrity, chain keying, declaration) come from the same functions so the
//! two documents cannot say different things about the same case.
//!
//! Figures are embedded as SVG through the `svgBlip` extension that Word
//! 2016+ and LibreOffice 7.4+ read. There is no PNG fallback for older
//! readers, which show an empty picture frame; the figure's own data is
//! written as a table beneath it in every case, so the numbers are in the
//! document whether or not the picture renders.
//!
//! The archive is deterministic: fixed member order, fixed timestamps, no
//! per-run identifiers. Two renders of the same case are byte-identical.

use std::io::Write;

use zip::write::SimpleFileOptions;
use zip::CompressionMethod;

use crate::figures::{comms_figure, timeline_figure, Figure};
use crate::report::{
    audit_chain_construction, audit_chain_keying_disclosure, audit_chain_scope_note,
    communication_link_rows, communication_participant_rows, communications_empty_statement,
    communications_truncation_note, completeness_statement, empty_section_note,
    feature_histogram_incomplete_notes, feature_histogram_top_note, feature_histogram_total_line,
    feature_histograms_not_gathered_text, feature_kind_rows, feature_value_rows, geo_path_cell,
    geo_truncation_note, human_size, incompleteness_reason_rows_text, integrity_statement,
    qualification_scope, reason_truncation_note, section_incompleteness_note, statement_of_truth,
    timeline_caption, timeline_figure_unavailable, truncation_note, xml_escape, ReportData,
    ReportExtras, COMMUNICATIONS_NOT_COMPUTED, COMMUNICATION_LINK_COLUMNS,
    COMMUNICATION_PARTICIPANT_COLUMNS, FEATURE_HISTOGRAMS_INTRO, FEATURE_HISTOGRAMS_NONE_FOUND,
    FEATURE_KIND_COLUMNS, FEATURE_TOP_TITLE, FEATURE_VALUE_COLUMNS, LEADS_PREAMBLE,
    TIMEZONE_STATEMENT,
};

/// Content width in EMUs: A4 (11906 twips) less two 1134-twip margins, at
/// 635 EMU per twip.
const CONTENT_WIDTH_EMU: i64 = (11_906 - 2 * 1_134) * 635;
/// Content width in twips, for table grids.
const CONTENT_WIDTH_TWIPS: i64 = 11_906 - 2 * 1_134;

const NS_W: &str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const NS_R: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const NS_WP: &str = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing";
const NS_A: &str = "http://schemas.openxmlformats.org/drawingml/2006/main";
const NS_PIC: &str = "http://schemas.openxmlformats.org/drawingml/2006/picture";
const NS_ASVG: &str = "http://schemas.microsoft.com/office/drawing/2016/SVG/main";

/// The document body under construction, plus the media parts it references.
struct Doc {
    body: String,
    /// `(part name under word/media, svg)` in the order they were added; the
    /// nth entry is relationship `rIdImg{n+1}`.
    media: Vec<(String, String)>,
    figure_no: usize,
}

fn dash(s: &Option<String>) -> String {
    match s {
        Some(v) if !v.is_empty() => v.clone(),
        _ => "\u{2014}".to_string(),
    }
}

/// A run of text. Newlines become `<w:br/>` so a multi-line note keeps its
/// lines; every other character goes through the XML escaper, which also
/// strips the control characters XML 1.0 cannot carry.
fn run(text: &str, bold: bool, italic: bool) -> String {
    let mut r = String::from("<w:r>");
    if bold || italic {
        r.push_str("<w:rPr>");
        if bold {
            r.push_str("<w:b/>");
        }
        if italic {
            r.push_str("<w:i/>");
        }
        r.push_str("</w:rPr>");
    }
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            r.push_str("<w:br/>");
        }
        let line = line.trim_end_matches('\r');
        r.push_str(&format!(
            "<w:t xml:space=\"preserve\">{}</w:t>",
            xml_escape(line)
        ));
    }
    r.push_str("</w:r>");
    r
}

impl Doc {
    fn styled_para(&mut self, style: &str, runs: &str) {
        self.body.push_str(&format!(
            "<w:p><w:pPr><w:pStyle w:val=\"{style}\"/></w:pPr>{runs}</w:p>\n"
        ));
    }

    fn title(&mut self, text: &str) {
        self.styled_para("Title", &run(text, false, false));
    }

    fn heading(&mut self, text: &str) {
        self.styled_para("Heading1", &run(text, false, false));
    }

    fn subheading(&mut self, text: &str) {
        self.styled_para("Heading2", &run(text, false, false));
    }

    fn para(&mut self, text: &str) {
        self.body
            .push_str(&format!("<w:p>{}</w:p>\n", run(text, false, false)));
    }

    fn bold(&mut self, text: &str) {
        self.body
            .push_str(&format!("<w:p>{}</w:p>\n", run(text, true, false)));
    }

    fn italic(&mut self, text: &str) {
        self.body
            .push_str(&format!("<w:p>{}</w:p>\n", run(text, false, true)));
    }

    fn field(&mut self, label: &str, value: &str) {
        self.body.push_str(&format!(
            "<w:p>{}{}</w:p>\n",
            run(&format!("{label}: "), true, false),
            run(value, false, false)
        ));
    }

    /// A bordered table with a bold header row. Empty `rows` renders the
    /// same italic "None recorded" the HTML's table helper does.
    fn table(&mut self, headers: &[String], rows: &[Vec<String>]) {
        if rows.is_empty() {
            self.italic("None recorded");
            return;
        }
        let cols = headers.len().max(1);
        let col_w = CONTENT_WIDTH_TWIPS / cols as i64;
        let mut t = String::from(
            "<w:tbl><w:tblPr><w:tblStyle w:val=\"TableGrid\"/>\
             <w:tblW w:w=\"5000\" w:type=\"pct\"/></w:tblPr><w:tblGrid>",
        );
        for _ in 0..cols {
            t.push_str(&format!("<w:gridCol w:w=\"{col_w}\"/>"));
        }
        t.push_str("</w:tblGrid>");
        let cell = |text: &str, bold: bool| {
            format!(
                "<w:tc><w:tcPr><w:tcW w:w=\"{col_w}\" w:type=\"dxa\"/></w:tcPr><w:p>{}</w:p></w:tc>",
                run(text, bold, false)
            )
        };
        t.push_str("<w:tr>");
        for h in headers {
            t.push_str(&cell(h, true));
        }
        t.push_str("</w:tr>");
        for row in rows {
            t.push_str("<w:tr>");
            for i in 0..cols {
                t.push_str(&cell(row.get(i).map(String::as_str).unwrap_or(""), false));
            }
            t.push_str("</w:tr>");
        }
        t.push_str("</w:tbl>\n");
        self.body.push_str(&t);
    }

    /// An inline picture holding the figure as SVG, followed by its caption.
    fn figure(&mut self, fig: &Figure, caption: &str) {
        self.figure_no += 1;
        let n = self.figure_no;
        let name = format!("figure{n}.svg");
        self.media.push((name.clone(), fig.to_svg()));
        let rid = format!("rIdImg{n}");
        let cx = CONTENT_WIDTH_EMU;
        let cy = (CONTENT_WIDTH_EMU as f64 * fig.height / fig.width).round() as i64;
        self.body.push_str(&format!(
            "<w:p><w:r><w:drawing><wp:inline distT=\"0\" distB=\"0\" distL=\"0\" distR=\"0\">\
             <wp:extent cx=\"{cx}\" cy=\"{cy}\"/>\
             <wp:docPr id=\"{n}\" name=\"Figure {n}\"/>\
             <a:graphic><a:graphicData uri=\"{NS_PIC}\">\
             <pic:pic><pic:nvPicPr><pic:cNvPr id=\"{n}\" name=\"{name}\"/><pic:cNvPicPr/></pic:nvPicPr>\
             <pic:blipFill><a:blip r:embed=\"{rid}\"><a:extLst>\
             <a:ext uri=\"{{96DAC541-7B7A-43D3-8B79-37D633B846F1}}\"><asvg:svgBlip r:embed=\"{rid}\"/></a:ext>\
             </a:extLst></a:blip><a:stretch><a:fillRect/></a:stretch></pic:blipFill>\
             <pic:spPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"{cx}\" cy=\"{cy}\"/></a:xfrm>\
             <a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></pic:spPr></pic:pic>\
             </a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>\n"
        ));
        self.italic(&format!("Figure {n}. {caption}"));
    }
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// Render the report as a DOCX with no data beyond [`ReportData`].
pub fn render_docx(data: &ReportData) -> anyhow::Result<Vec<u8>> {
    render_docx_with(data, &ReportExtras::default())
}

/// Render the report as a DOCX, with the data [`ReportData`] cannot carry.
pub fn render_docx_with(data: &ReportData, extras: &ReportExtras) -> anyhow::Result<Vec<u8>> {
    let mut d = Doc {
        body: String::with_capacity(32768),
        media: Vec::new(),
        figure_no: 0,
    };

    // ---- Title / meta ----
    d.title(&format!("Forensic Analysis Report: {}", data.case_name));
    d.field("Case Name", &data.case_name);
    d.field("Case Reference", &dash(&data.case_reference));
    d.field("Examiner", &data.examiner);
    d.field("Report Generated", &data.generated_at);
    d.field("Tool", &format!("{} {}", data.tool_name, data.tool_version));
    if let Some(identity) = &data.report_identity {
        if !identity.report_id.is_empty() {
            d.field("Report Reference", &identity.report_id);
        }
        if let Some(revision) = identity.revision {
            d.field("Revision", &revision.to_string());
        }
        if let Some(classification) = &identity.classification {
            d.field("Handling", classification);
        }
    }
    if let Some(details) = &data.examiner_details {
        if let Some(role) = &details.role {
            d.field("Role", role);
        }
        if let Some(org) = &details.organisation {
            d.field("Organisation", org);
        }
        if let Some(quals) = &details.qualifications {
            d.field("Qualifications", quals);
        }
        if let Some(contact) = &details.contact {
            d.field("Contact", contact);
        }
    }

    // ---- How times are expressed ----
    d.heading("Times");
    d.para(TIMEZONE_STATEMENT);

    // ---- Executive Summary ----
    if let Some(summary) = &data.executive_summary {
        if !summary.is_empty() {
            d.heading("Executive Summary");
            d.para(summary);
        }
    }

    // ---- File Overview ----
    if let Some(ov) = &data.file_overview {
        d.heading("File Overview");
        let und = |v: Option<i64>| {
            v.map(|v| v.to_string())
                .unwrap_or_else(|| "\u{2014}".to_string())
        };
        d.table(
            &strings(&["Count", "Value"]),
            &[
                strings(&["Total Files", &ov.total_files.to_string()]),
                strings(&["Directories", &ov.directories.to_string()]),
                strings(&["Deleted", &ov.deleted_files.to_string()]),
                strings(&["Carved", &und(ov.carved_files)]),
                strings(&["Encrypted", &und(ov.encrypted_files)]),
                strings(&["Known-Good Filtered", &ov.known_good_filtered.to_string()]),
                strings(&["Notable Alerts", &ov.notable_alerts.to_string()]),
            ],
        );
        if ov.carved_files.is_none() || ov.encrypted_files.is_none() {
            d.italic(
                "Counts shown as \u{2014} were not determined for this report and must not be read as zero.",
            );
        }
    }

    // ---- Result Completeness ----
    d.heading("Result Completeness");
    {
        let (severity, text) = completeness_statement(data.incompleteness.as_ref());
        d.bold(&format!("[{}] {}", severity.to_uppercase(), text));
    }
    if let Some(inc) = &data.incompleteness {
        if inc.any() {
            if let Some(note) = reason_truncation_note(inc.reasons.len(), inc.distinct_reasons) {
                d.para(&format!("Content not read in full \u{2014} {note}"));
            }
            if let Some(note) =
                reason_truncation_note(inc.inventory_reasons.len(), inc.distinct_inventory_reasons)
            {
                d.para(&format!(
                    "Listing shorter than the container \u{2014} {note}"
                ));
            }
            let rows = incompleteness_reason_rows_text(inc);
            if !rows.is_empty() {
                d.table(
                    &strings(&["Shortfall", "Recorded reason", "Artifacts"]),
                    &rows,
                );
            }
        }
    }

    // ---- Evidence Sources ----
    d.heading("Evidence Sources");
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
                dash(&s.md5),
                dash(&s.sha1),
                dash(&s.sha256),
                dash(&s.acquired_at),
            ]
        })
        .collect();
    d.table(
        &strings(&["Name", "Type", "Size", "MD5", "SHA1", "SHA256", "Acquired"]),
        &rows,
    );

    // ---- Evidence Integrity ----
    if !data.integrity_checks.is_empty() {
        d.heading("Evidence Integrity");
        let (severity, text) = integrity_statement(&data.integrity_checks);
        d.bold(&format!("[{}] {}", severity.to_uppercase(), text));
        let rows: Vec<Vec<String>> = data
            .integrity_checks
            .iter()
            .map(|c| {
                vec![
                    c.source_name.clone(),
                    c.algorithm.clone(),
                    dash(&c.acquisition_hash),
                    dash(&c.recomputed_hash),
                    c.outcome.label().to_string(),
                    c.outcome.description().to_string(),
                    dash(&c.checked_at),
                ]
            })
            .collect();
        d.table(
            &strings(&[
                "Source",
                "Algorithm",
                "Acquisition Hash",
                "Recomputed Hash",
                "Result",
                "Meaning",
                "Recorded",
            ]),
            &rows,
        );
    }

    // ---- Artifact Statistics ----
    d.heading("Artifact Statistics");
    if data.artifact_counts.is_empty() && data.total_artifacts == 0 {
        d.italic("None recorded");
    } else {
        let mut rows: Vec<Vec<String>> = data
            .artifact_counts
            .iter()
            .map(|(ty, count)| vec![ty.clone(), count.to_string()])
            .collect();
        rows.push(vec!["Total".to_string(), data.total_artifacts.to_string()]);
        d.table(&strings(&["Artifact Type", "Count"]), &rows);
    }

    // ---- Per-category artifact detail sections ----
    for section in &data.category_sections {
        d.heading(&section.title);
        if section.total > section.rows.len() as i64 {
            d.para(&format!(
                "Showing {} of {} records.",
                section.rows.len(),
                section.total
            ));
        }
        if let Some(note) = section_incompleteness_note(section) {
            d.bold(&note);
        }
        if section.rows.is_empty() {
            d.italic(&empty_section_note(section));
        } else {
            d.table(&section.columns, &section.rows);
        }
    }

    // ---- Notable / Known-Good Hash Matches ----
    let hash_rows = |hits: &[crate::report::ReportHashHit]| -> Vec<Vec<String>> {
        hits.iter()
            .map(|h| {
                vec![
                    h.artifact_name.clone(),
                    dash(&h.path),
                    h.hash_set_name.clone(),
                    h.algorithm.clone(),
                    h.matched_hash.clone(),
                ]
            })
            .collect()
    };
    let hash_cols = strings(&["Artifact", "Path", "Hash Set", "Algorithm", "Matched Hash"]);
    if !data.notable_hash_hits.is_empty() {
        d.heading("Notable Hash Matches");
        if let Some(note) = truncation_note(data.notable_hash_hits.len(), data.notable_hash_total) {
            d.para(&note);
        }
        d.table(&hash_cols, &hash_rows(&data.notable_hash_hits));
    }
    if !data.known_good_hash_hits.is_empty() {
        d.heading("Known-Good (KFF) Hash Matches");
        d.para("Files matching a known-good hash set (safe to exclude from manual review).");
        if let Some(note) =
            truncation_note(data.known_good_hash_hits.len(), data.known_good_hash_total)
        {
            d.para(&note);
        }
        d.table(&hash_cols, &hash_rows(&data.known_good_hash_hits));
    }

    // ---- Findings / Bookmarks ----
    d.heading("Findings / Bookmarks");
    if let Some(note) =
        crate::report::personal_bookmarks_excluded_note(data.personal_bookmarks_excluded)
    {
        d.para(&note);
    }
    let rows: Vec<Vec<String>> = data
        .bookmarks
        .iter()
        .map(|b| {
            let location = match (&b.source_path, b.source_offset) {
                (Some(p), Some(off)) => format!("{p} @ byte {off}"),
                (Some(p), None) => p.clone(),
                (None, Some(off)) => format!("byte {off}"),
                (None, None) => "\u{2014}".to_string(),
            };
            vec![
                dash(&b.category),
                b.artifact_name.clone(),
                location,
                dash(&b.note),
                dash(&b.examiner),
                b.created_at.clone(),
            ]
        })
        .collect();
    d.table(
        &strings(&[
            "Category",
            "Artifact",
            "Source location",
            "Note",
            "Examiner",
            "Created",
        ]),
        &rows,
    );

    // ---- Communications Network ----
    d.heading("Communications Network");
    match &extras.communications {
        None => d.italic(COMMUNICATIONS_NOT_COMPUTED),
        Some(graph) if graph.nodes.is_empty() => d.italic(&communications_empty_statement(graph)),
        Some(graph) => {
            if let Some(note) = communications_truncation_note(graph) {
                d.bold(&note);
            }
            if let Some(fig) = comms_figure(graph) {
                d.figure(&fig.to_figure(), &fig.caption());
            }
            d.subheading("Participants");
            d.table(
                &strings(&COMMUNICATION_PARTICIPANT_COLUMNS),
                &communication_participant_rows(graph),
            );
            d.subheading("Links");
            let (rows, note) = communication_link_rows(graph);
            if let Some(note) = note {
                d.para(&note);
            }
            d.table(&strings(&COMMUNICATION_LINK_COLUMNS), &rows);
        }
    }

    // ---- Feature Histograms ----
    d.heading("Feature Histograms");
    match &extras.feature_histograms {
        None => d.italic(&feature_histograms_not_gathered_text(extras)),
        Some(hists) if hists.is_empty() => d.italic(FEATURE_HISTOGRAMS_NONE_FOUND),
        Some(hists) => {
            d.para(FEATURE_HISTOGRAMS_INTRO);
            for hist in hists {
                d.subheading(&hist.source);
                for note in feature_histogram_incomplete_notes(hist) {
                    d.bold(&note);
                }
                d.para(&feature_histogram_total_line(hist));
                d.table(&strings(&FEATURE_KIND_COLUMNS), &feature_kind_rows(hist));
                d.para(&hist.note);
                d.bold(FEATURE_TOP_TITLE);
                if let Some(note) = feature_histogram_top_note(hist) {
                    d.para(&note);
                }
                d.table(&strings(&FEATURE_VALUE_COLUMNS), &feature_value_rows(hist));
            }
        }
    }

    // ---- Values Traced Across the Evidence ----
    if !data.traced_values.is_empty() {
        d.heading("Values Traced Across the Evidence");
        d.para(
            "Each value below was traced across every parsed artifact in this case and pinned \
             by the named examiner at the time stated. The counts are of artifacts that \
             reference the value; a reference is not a relationship.",
        );
        for t in &data.traced_values {
            d.subheading(&t.value);
            if let Some(note) = &t.note {
                d.italic(note);
            }
            d.para(&format!(
                "Pinned by {} on {}. {} artifact(s) referenced this value at that moment.",
                t.examiner, t.pinned_at, t.matches_when_pinned
            ));
            if t.truncated_when_pinned {
                d.bold(
                    "The per-kind counts below are a SAMPLE: more artifacts referenced this \
                     value than the pivot groups at once, and they do not add up to the total \
                     above.",
                );
            }
            if !t.groups_when_pinned.is_empty() {
                let rows: Vec<Vec<String>> = t
                    .groups_when_pinned
                    .iter()
                    .map(|(kind, count)| vec![kind.clone(), count.to_string()])
                    .collect();
                d.table(&strings(&["Record kind", "Artifacts"]), &rows);
            }
            match (t.matches_now, &t.recheck_unavailable_reason) {
                (Some(now), _) if now == t.matches_when_pinned => d.para(&format!(
                    "Re-checked when this report was produced: still {now} artifact(s)."
                )),
                (Some(now), _) => d.bold(&format!(
                    "Re-checked when this report was produced: {now} artifact(s) now reference \
                     this value, against {} when it was pinned. The figures above are the \
                     examiner's snapshot and this one is current.",
                    t.matches_when_pinned
                )),
                (None, Some(why)) => d.bold(&format!(
                    "This value could NOT be re-checked when the report was produced: {why}. \
                     The counts above are the examiner's snapshot only."
                )),
                (None, None) => d.bold(
                    "This value was not re-checked when the report was produced, and no reason \
                     was recorded. Treat the counts above as the examiner's snapshot only.",
                ),
            }
        }
    }

    // ---- Investigative Leads ----
    if !data.leads.is_empty() || !data.lead_detections.is_empty() {
        d.heading("Investigative Leads");
        d.para(LEADS_PREAMBLE);
        if data.leads.is_empty() {
            d.italic("No leads were raised.");
        } else {
            if data.leads_total > data.leads.len() as i64 {
                d.bold(&format!(
                    "This case holds {} lead(s); the {} listed below are the most confident. \
                     The remainder are not in this report.",
                    data.leads_total,
                    data.leads.len()
                ));
            }
            for lead in &data.leads {
                d.subheading(&format!("[{}] {}", lead.confidence, lead.title));
                d.para(&format!(
                    "Observation (checkable against the evidence): {}",
                    lead.observation
                ));
                if let Some(inference) = &lead.inference {
                    d.para(&format!(
                        "What this may indicate \u{2014} S\u{e9}ance's reading, not a fact: {inference}"
                    ));
                }
                d.para(&format!(
                    "What it does not establish: {}",
                    lead.qualification
                ));
                if !lead.evidence.is_empty() {
                    let rows: Vec<Vec<String>> = lead
                        .evidence
                        .iter()
                        .map(|(name, value)| vec![name.clone(), value.clone()])
                        .collect();
                    d.table(&strings(&["Value", "As recorded"]), &rows);
                }
                let location = match lead.device_offset {
                    Some(off) => format!("{} @ byte {}", lead.subject, off),
                    None => lead.subject.clone(),
                };
                d.para(&format!(
                    "Subject: {location}. Raised by {}. {}",
                    lead.source_module,
                    if lead.stored_as_a_record {
                        "Recorded in the case as its own artifact."
                    } else {
                        "Computed when this report was produced; it is not stored as an \
                         artifact, so only the subject above can be re-opened."
                    }
                ));
            }
        }
        if !data.lead_detections.is_empty() {
            d.subheading("What this build can look for");
            let rows: Vec<Vec<String>> = data
                .lead_detections
                .iter()
                .map(|det| vec![det.kind.clone(), det.looks_for.clone()])
                .collect();
            d.table(&strings(&["Check", "What it looks for"]), &rows);
        }
    }

    // ---- Geolocation ----
    if !data.geolocation.is_empty() || data.geolocation_truncated {
        d.heading("Geolocation");
        d.para("GPS points extracted from EXIF metadata. Exportable as KML/GeoJSON for mapping.");
        if data.geolocation_truncated {
            d.bold(&geo_truncation_note(data.geolocation.len()));
        }
        let rows: Vec<Vec<String>> = data
            .geolocation
            .iter()
            .map(|g| {
                vec![
                    g.label.clone(),
                    dash(&geo_path_cell(g)),
                    format!("{:.6}", g.latitude),
                    format!("{:.6}", g.longitude),
                    g.altitude
                        .map(|a| format!("{a:.1} m"))
                        .unwrap_or_else(|| "\u{2014}".to_string()),
                    dash(&g.timestamp),
                ]
            })
            .collect();
        d.table(
            &strings(&[
                "File",
                "Path",
                "Latitude",
                "Longitude",
                "Altitude",
                "Timestamp",
            ]),
            &rows,
        );
    }

    // ---- Timeline Highlights ----
    d.heading("Timeline Highlights");
    if let Some(note) = crate::report::timeline_omitted_note(data.incompleteness.as_ref()) {
        d.para(&note);
    }
    if data.timeline_highlights.is_empty() {
        d.italic("None recorded");
    } else {
        let rows: Vec<Vec<String>> = data
            .timeline_highlights
            .iter()
            .map(|e| {
                vec![
                    e.timestamp.clone(),
                    e.description.clone(),
                    e.source_module.clone(),
                    dash(&e.note),
                    dash(&e.examiner),
                ]
            })
            .collect();
        d.table(
            &strings(&[
                "Timestamp",
                "Description",
                "Source Module",
                "Note",
                "Examiner",
            ]),
            &rows,
        );
        d.italic(
            "Every event above was tagged by an examiner. The note is their own words on why \
             it matters; an em dash means they tagged the event without writing one.",
        );
    }

    // ---- Full Timeline (bounded) ----
    if !data.full_timeline.is_empty() {
        d.heading("Timeline");
        if let Some(note) = crate::report::timeline_omitted_note(data.incompleteness.as_ref()) {
            d.para(&note);
        }
        d.para(&timeline_caption(
            data.full_timeline.len(),
            data.full_timeline_total,
        ));
        match timeline_figure(&data.full_timeline, data.full_timeline_total) {
            Some(fig) => {
                d.figure(&fig.to_figure(), &fig.caption());
                let rows: Vec<Vec<String>> = fig
                    .buckets
                    .iter()
                    .map(|b| vec![b.start.clone(), b.count.to_string()])
                    .collect();
                d.table(&strings(&["Bucket start (UTC)", "Events"]), &rows);
            }
            None => d.italic(&timeline_figure_unavailable(data.full_timeline.len())),
        }
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
        d.table(
            &strings(&["Timestamp", "Description", "Source Module"]),
            &rows,
        );
    }

    // ---- Chain of Custody & Audit ----
    d.heading("Chain of Custody & Audit");
    if data.audit_chain_valid {
        d.bold(&format!(
            "Audit chain verified - {} entries ({}).",
            data.audit_chain_checked,
            audit_chain_construction(
                data.audit_chain_tamper_evident,
                data.audit_chain_tamper_evident_from
            )
        ));
    } else {
        d.bold(&format!(
            "AUDIT CHAIN NOT VERIFIED - hash-chain verification FAILED after checking {} \
             entries: {}. Until this is resolved, evidence-handling integrity is not attested \
             by this report.",
            data.audit_chain_checked,
            data.audit_chain_break_reason
                .as_deref()
                .unwrap_or("the verifier gave no reason")
        ));
    }
    d.para(&audit_chain_keying_disclosure(
        data.audit_chain_tamper_evident,
        data.audit_chain_tamper_evident_from,
        data.audit_chain_key_configured,
    ));
    d.para(audit_chain_scope_note(data.audit_chain_valid));
    if data.audit_entries.is_empty() {
        d.italic("None recorded");
    } else {
        if let Some(note) = truncation_note(data.audit_entries.len(), data.audit_entries_total) {
            d.para(&note);
        }
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
        d.table(
            &strings(&["Timestamp", "User", "Action", "Resource Type"]),
            &rows,
        );
    }

    // ---- Processing Log ----
    if !data.processing_log.is_empty() {
        d.heading("Processing Log");
        d.para(
            "Module execution provenance: which parser produced what, and how long it took. \
             Each row aggregates every run of that module in this case.",
        );
        if let Some(note) = truncation_note(data.processing_log.len(), data.processing_log_total) {
            d.para(&note);
        }
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
                        .map(|ms| format!("{ms} ms"))
                        .unwrap_or_else(|| "\u{2014}".to_string()),
                    dash(&p.error_message),
                ]
            })
            .collect();
        d.table(
            &strings(&["Module", "Status", "Runs", "Artifacts", "Duration", "Error"]),
            &rows,
        );
    }

    // ---- Limitations and qualifications ----
    if !data.method_qualifications.is_empty() {
        d.heading("Limitations and Qualifications of the Examination");
        d.para(
            "The findings above were produced by the methods described below. Each entry \
             states a respect in which the method qualifies what may be concluded.",
        );
        for entry in &data.method_qualifications {
            d.subheading(&entry.subject);
            d.para(&entry.statement);
            d.italic(&format!("Bears on: {}", qualification_scope(entry)));
        }
    }

    // ---- Glossary ----
    if !data.glossary.is_empty() {
        d.heading("Glossary");
        for entry in &data.glossary {
            d.bold(&entry.term);
            d.para(&entry.definition);
        }
    }

    // ---- Declaration ----
    d.heading("Declaration");
    d.para(statement_of_truth(data));
    let signatory = data
        .examiner_details
        .as_ref()
        .filter(|e| !e.name.is_empty())
        .map(|e| e.name.clone())
        .unwrap_or_else(|| data.examiner.clone());
    d.bold(&signatory);
    if let Some(details) = &data.examiner_details {
        if let Some(role) = &details.role {
            d.para(role);
        }
        if let Some(org) = &details.organisation {
            d.para(org);
        }
    }
    d.para(&data.generated_at);

    // ---- Methodology / Notes footer ----
    d.heading("Methodology & Notes");
    d.para(
        "Acquisition hashes (MD5/SHA1/SHA256) shown above were computed at ingest over each \
         evidence source and recorded before analysis.",
    );
    d.para(
        "In the Evidence Integrity section, BASELINE means a hash was recorded at acquisition \
         and has not since been recomputed and compared. It is neither a pass nor a failure: \
         only MATCH and MISMATCH state the result of a re-verification.",
    );
    d.para(&format!(
        "The audit log is a hash-chained record; each entry commits to its predecessor. The \
         verification banner above reflects a full re-computation of that chain. {}",
        audit_chain_keying_disclosure(
            data.audit_chain_tamper_evident,
            data.audit_chain_tamper_evident_from,
            data.audit_chain_key_configured,
        )
    ));
    d.para(
        "Result Completeness reports flags the parsers themselves recorded: a parser that \
         could not read or decode its input in full marks the artifact it produced, and a \
         listing shorter than what the container holds is marked separately. Where a section \
         carries an INCOMPLETE notice, its records are a subset and the absence of an item \
         from that listing is not evidence that the item was absent from the evidence.",
    );
    d.para(&format!(
        "Report generated by {} {} at {}. All findings should be independently verified \
         against source evidence.",
        data.tool_name, data.tool_version, data.generated_at
    ));

    package(d)
}

/// Write the parts into a ZIP, in a fixed order with fixed timestamps.
fn package(d: Doc) -> anyhow::Result<Vec<u8>> {
    let document = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
         <w:document xmlns:w=\"{NS_W}\" xmlns:r=\"{NS_R}\" xmlns:wp=\"{NS_WP}\" \
         xmlns:a=\"{NS_A}\" xmlns:pic=\"{NS_PIC}\" xmlns:asvg=\"{NS_ASVG}\">\n<w:body>\n{}\
         <w:sectPr><w:pgSz w:w=\"11906\" w:h=\"16838\"/>\
         <w:pgMar w:top=\"1134\" w:right=\"1134\" w:bottom=\"1134\" w:left=\"1134\" \
         w:header=\"708\" w:footer=\"708\" w:gutter=\"0\"/></w:sectPr>\n\
         </w:body>\n</w:document>\n",
        d.body
    );

    let mut content_types = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
         <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n\
         <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\n\
         <Default Extension=\"xml\" ContentType=\"application/xml\"/>\n",
    );
    if !d.media.is_empty() {
        content_types.push_str("<Default Extension=\"svg\" ContentType=\"image/svg+xml\"/>\n");
    }
    content_types.push_str(
        "<Override PartName=\"/word/document.xml\" \
         ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\n\
         <Override PartName=\"/word/styles.xml\" \
         ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml\"/>\n\
         </Types>\n",
    );

    let root_rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
        <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n\
        <Relationship Id=\"rId1\" \
        Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" \
        Target=\"word/document.xml\"/>\n\
        </Relationships>\n";

    let mut doc_rels = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
         <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n\
         <Relationship Id=\"rIdStyles\" \
         Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" \
         Target=\"styles.xml\"/>\n",
    );
    for (i, (name, _)) in d.media.iter().enumerate() {
        doc_rels.push_str(&format!(
            "<Relationship Id=\"rIdImg{}\" \
             Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" \
             Target=\"media/{name}\"/>\n",
            i + 1
        ));
    }
    doc_rels.push_str("</Relationships>\n");

    let styles = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
         <w:styles xmlns:w=\"{NS_W}\">\n\
         <w:docDefaults><w:rPrDefault><w:rPr>\
         <w:rFonts w:ascii=\"Helvetica\" w:hAnsi=\"Helvetica\" w:cs=\"Helvetica\"/>\
         <w:sz w:val=\"22\"/><w:szCs w:val=\"22\"/><w:lang w:val=\"en-GB\"/>\
         </w:rPr></w:rPrDefault>\
         <w:pPrDefault><w:pPr><w:spacing w:after=\"120\" w:line=\"276\" w:lineRule=\"auto\"/></w:pPr></w:pPrDefault>\
         </w:docDefaults>\n\
         <w:style w:type=\"paragraph\" w:default=\"1\" w:styleId=\"Normal\"><w:name w:val=\"Normal\"/><w:qFormat/></w:style>\n\
         <w:style w:type=\"paragraph\" w:styleId=\"Title\"><w:name w:val=\"Title\"/><w:basedOn w:val=\"Normal\"/>\
         <w:pPr><w:spacing w:after=\"240\"/></w:pPr><w:rPr><w:b/><w:sz w:val=\"40\"/><w:szCs w:val=\"40\"/></w:rPr></w:style>\n\
         <w:style w:type=\"paragraph\" w:styleId=\"Heading1\"><w:name w:val=\"heading 1\"/><w:basedOn w:val=\"Normal\"/>\
         <w:pPr><w:keepNext/><w:spacing w:before=\"360\" w:after=\"120\"/><w:outlineLvl w:val=\"0\"/></w:pPr>\
         <w:rPr><w:b/><w:sz w:val=\"30\"/><w:szCs w:val=\"30\"/></w:rPr></w:style>\n\
         <w:style w:type=\"paragraph\" w:styleId=\"Heading2\"><w:name w:val=\"heading 2\"/><w:basedOn w:val=\"Normal\"/>\
         <w:pPr><w:keepNext/><w:spacing w:before=\"240\" w:after=\"80\"/><w:outlineLvl w:val=\"1\"/></w:pPr>\
         <w:rPr><w:b/><w:sz w:val=\"24\"/><w:szCs w:val=\"24\"/></w:rPr></w:style>\n\
         <w:style w:type=\"table\" w:styleId=\"TableGrid\"><w:name w:val=\"Table Grid\"/>\
         <w:tblPr><w:tblBorders>\
         <w:top w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"D7DDE3\"/>\
         <w:left w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"D7DDE3\"/>\
         <w:bottom w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"D7DDE3\"/>\
         <w:right w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"D7DDE3\"/>\
         <w:insideH w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"D7DDE3\"/>\
         <w:insideV w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"D7DDE3\"/>\
         </w:tblBorders><w:tblCellMar>\
         <w:left w:w=\"80\" w:type=\"dxa\"/><w:right w:w=\"80\" w:type=\"dxa\"/>\
         </w:tblCellMar></w:tblPr></w:style>\n\
         </w:styles>\n"
    );

    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default());
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::with_capacity(65536)));
    let mut add = |name: &str, bytes: &[u8]| -> anyhow::Result<()> {
        zip.start_file(name, options)?;
        zip.write_all(bytes)?;
        Ok(())
    };
    add("[Content_Types].xml", content_types.as_bytes())?;
    add("_rels/.rels", root_rels.as_bytes())?;
    add("word/document.xml", document.as_bytes())?;
    add("word/_rels/document.xml.rels", doc_rels.as_bytes())?;
    add("word/styles.xml", styles.as_bytes())?;
    for (name, svg) in &d.media {
        add(&format!("word/media/{name}"), svg.as_bytes())?;
    }
    Ok(zip.finish()?.into_inner())
}
