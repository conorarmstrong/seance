use crate::{add_page, create_pdf_document, format_timestamp, PdfStyle};
use anyhow::Result;
use printpdf::*;
use seance_core::models::TimelineEventResponse;
use seance_db::SqliteConnection;
use std::fs::File;
use std::io::BufWriter;
use tracing::info;
use uuid::Uuid;

/// Timeline Report Generator
pub struct TimelineReportGenerator {
    style: PdfStyle,
}

impl TimelineReportGenerator {
    pub fn new() -> Self {
        Self {
            style: PdfStyle::default(),
        }
    }

    /// Generate a timeline PDF report with filtered events.
    ///
    /// `events` is the slice this PDF lays out; `matching_total` is the number
    /// of events that matched the same case and filter when the export was
    /// taken, counted separately from the bounded fetch. The two are printed
    /// together, because a PDF that prints the size of its own slice under a
    /// label like "Total Events" describes a 400k-event case as a 50k one
    /// (SHIP-035).
    ///
    /// `truncated` is the fetch's own verdict on whether it returned a slice.
    /// The report states completeness from it and never re-derives it by
    /// comparing the two counts; see [`timeline_export_population_line`].
    #[allow(clippy::too_many_arguments)]
    pub async fn generate_timeline_report(
        &self,
        _db: &SqliteConnection,
        _case_id: Uuid,
        case_name: &str,
        events: Vec<TimelineEventResponse>,
        matching_total: i64,
        truncated: bool,
        output_path: &str,
        filter_description: Option<String>,
    ) -> Result<()> {
        info!(
            "Generating timeline report with {} of {} matching events",
            events.len(),
            matching_total
        );
        render_timeline_pdf(
            &self.style,
            case_name,
            events,
            matching_total,
            truncated,
            output_path,
            filter_description,
        )?;
        info!("Timeline report saved to: {}", output_path);
        Ok(())
    }
}

/// The page, as the layout code sees it: where the pen is, and where a fresh
/// page would put it.
///
/// Every vertical advance in this report goes through [`Cursor::advance`], which
/// is what makes the two pagination faults `CR-026` recorded impossible to
/// reintroduce by adding a line. The header block used to decrement `y` with no
/// page-break check at all — a `Filter:` line over ~700 characters pushed the
/// rest of the header to a negative offset, where `printpdf` draws it outside
/// the MediaBox and it does not render, so the exhibit stated only part of the
/// filter that produced it. And the row loop's capacity test compared against
/// the whole page height rather than the room left under a redrawn table
/// header, so a row of about 42 lines "did not fit" even at the top of a fresh
/// page and emitted a blank page ahead of itself.
struct Cursor {
    page: PdfPageIndex,
    layer: PdfLayerIndex,
    y: f32,
    page_height: f32,
    top_margin: f32,
    bottom_margin: f32,
}

impl Cursor {
    /// Whether `needed` mm of content will not fit above the bottom margin.
    ///
    /// `fresh_page_room` is what a new page offers once whatever a new page
    /// repeats (the table header) has been drawn; a block taller than that can
    /// never fit whole, so it is placed where the pen is and continued rather
    /// than pushed to a page it will not fit on either — breaking only if not
    /// even its first `piece` (one line) fits here.
    fn needs_break(&self, needed: f32, fresh_page_room: f32, piece: f32) -> bool {
        needs_page_break(self.y, self.bottom_margin, needed, fresh_page_room, piece)
    }

    /// Start a new page and put the pen at its top.
    fn new_page(&mut self, doc: &PdfDocumentReference) {
        let (page, layer) = add_page(doc, 210.0, 297.0);
        self.page = page;
        self.layer = layer;
        self.y = self.page_height - self.top_margin;
    }

    fn layer(&self, doc: &PdfDocumentReference) -> PdfLayerReference {
        doc.get_page(self.page).get_layer(self.layer)
    }

    /// Room a fresh page offers below its top margin, before anything is
    /// repeated on it.
    fn fresh_page_room(&self) -> f32 {
        self.page_height - self.top_margin - self.bottom_margin
    }
}

/// The pure form of the page-break test, kept separate so it can be pinned.
///
/// A block that fits on a fresh page is kept whole: it breaks when it will not
/// fit above the bottom margin. A block that could not fit on a fresh page
/// either is continued from where the pen is, and breaks only when not even
/// its first `piece` fits — pushing it to a new page would gain nothing and,
/// tested against the wrong height, is what emitted the blank pages `CR-026`
/// recorded.
fn needs_page_break(
    y: f32,
    bottom_margin: f32,
    needed: f32,
    fresh_page_room: f32,
    piece: f32,
) -> bool {
    let must_fit = if needed <= fresh_page_room {
        needed
    } else {
        piece.min(fresh_page_room)
    };
    y < bottom_margin + must_fit
}

/// Lay the timeline PDF out and write it. Synchronous and free of the database,
/// so a test can render one and read it back.
#[allow(clippy::too_many_arguments)]
fn render_timeline_pdf(
    style: &PdfStyle,
    case_name: &str,
    events: Vec<TimelineEventResponse>,
    matching_total: i64,
    truncated: bool,
    output_path: &str,
    filter_description: Option<String>,
) -> Result<()> {
    // Create PDF document (A4 size: 210mm x 297mm)
    let (doc, first_page, first_layer) =
        create_pdf_document(&format!("{} - Timeline Report", case_name), 210.0, 297.0);

    // Get fonts
    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    let font_mono = doc.add_builtin_font(BuiltinFont::Courier)?;

    let page_height = 297.0;
    let mut cur = Cursor {
        page: first_page,
        layer: first_layer,
        y: page_height - style.margin,
        page_height,
        top_margin: style.margin,
        bottom_margin: 30.0,
    };

    // Title
    cur.layer(&doc).use_text(
        format!("{} - Timeline Report", case_name),
        style.title_font_size,
        Mm(style.margin),
        Mm(cur.y),
        &font_bold,
    );
    cur.y -= style.title_font_size + 10.0;

    // Report metadata
    cur.layer(&doc).use_text(
        format!(
            "Generated: {}",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ),
        style.body_font_size,
        Mm(style.margin),
        Mm(cur.y),
        &font,
    );
    cur.y -= style.line_height;

    // The header statements, each wrapped and each written through the same
    // break test the rows use, so a long one runs onto a second page rather
    // than off the bottom of the first (CR-026).
    let mut header_lines: Vec<String> = Vec::new();
    // The population, stated as a slice of a named whole. Wrapped, because
    // the sentence that says the listing is truncated must not itself be
    // clipped at the page edge.
    header_lines.extend(wrap_cell(
        &timeline_export_population_line(events.len(), matching_total, truncated),
        HEADER_LINE_CHARS,
    ));
    // The timezone convention the Timestamp column follows.
    header_lines.extend(wrap_cell(TIMELINE_PDF_TIMEZONE_NOTE, HEADER_LINE_CHARS));
    // The rendering rule for the two free-text columns.
    header_lines.extend(wrap_cell(TIMELINE_PDF_WRAP_NOTE, HEADER_LINE_CHARS));
    if let Some(filter_desc) = filter_description {
        header_lines.extend(wrap_cell(
            &format!("Filter: {}", filter_desc),
            HEADER_LINE_CHARS,
        ));
    }
    for chunk in header_lines {
        if cur.needs_break(
            HEADER_WRAP_ADVANCE,
            cur.fresh_page_room(),
            HEADER_WRAP_ADVANCE,
        ) {
            cur.new_page(&doc);
        }
        cur.layer(&doc).use_text(
            chunk,
            style.body_font_size,
            Mm(style.margin),
            Mm(cur.y),
            &font,
        );
        cur.y -= HEADER_WRAP_ADVANCE;
    }

    cur.y -= 10.0;

    // Table columns. The table uses its own, narrower left margin so the
    // description column has room to wrap instead of being cut off.
    let col_timestamp = TABLE_LEFT_MM;
    let col_source = TABLE_LEFT_MM + 50.0;
    let col_description = col_source + SOURCE_COL_MM;
    let table_header_advance = style.line_height + 2.0;

    let draw_header = |layer: &PdfLayerReference, y: f32| {
        layer.use_text(
            "Timestamp",
            style.body_font_size,
            Mm(col_timestamp),
            Mm(y),
            &font_bold,
        );
        layer.use_text(
            "Source",
            style.body_font_size,
            Mm(col_source),
            Mm(y),
            &font_bold,
        );
        layer.use_text(
            "Description",
            style.body_font_size,
            Mm(col_description),
            Mm(y),
            &font_bold,
        );
    };

    // The "Timeline Events" heading and the first table header travel
    // together: a heading stranded at the foot of a page above an empty table
    // says nothing.
    let heading_block = style.heading_font_size + 5.0 + table_header_advance + style.line_height;
    if cur.needs_break(heading_block, cur.fresh_page_room(), heading_block) {
        cur.new_page(&doc);
    }
    cur.layer(&doc).use_text(
        "Timeline Events",
        style.heading_font_size,
        Mm(style.margin),
        Mm(cur.y),
        &font_bold,
    );
    cur.y -= style.heading_font_size + 5.0;
    draw_header(&cur.layer(&doc), cur.y);
    cur.y -= table_header_advance;

    // What a fresh page offers a row once the table header has been redrawn on
    // it. This — not the whole page — is what a row's height is compared
    // against: a row that would not fit even here is continued, not pushed.
    let fresh_row_room = cur.fresh_page_room() - table_header_advance;

    // Draw events. Source and description are wrapped onto as many lines
    // as they need; nothing is shortened (SHIP-037).
    for event in events {
        let source_lines = wrap_cell(&event.source_module, SOURCE_COL_CHARS);
        let desc_lines = wrap_cell(&event.short_desc, DESCRIPTION_COL_CHARS);
        let row_lines = source_lines.len().max(desc_lines.len()).max(1);
        let row_height = style.line_height + ROW_WRAP_ADVANCE * (row_lines as f32 - 1.0);

        // A row that fits on a page is kept whole: it moves to a new
        // page rather than being split. A row taller than a page — a
        // description running to thousands of characters — is continued
        // across pages, with each continuation marked, rather than drawn
        // off the bottom edge where it would be lost.
        if cur.needs_break(row_height, fresh_row_room, ROW_WRAP_ADVANCE) {
            cur.new_page(&doc);
            // Redraw table header on new page
            draw_header(&cur.layer(&doc), cur.y);
            cur.y -= table_header_advance;
        }

        let timestamp_str = format_timestamp(event.timestamp);
        for i in 0..row_lines {
            if i > 0 && cur.needs_break(ROW_WRAP_ADVANCE, fresh_row_room, ROW_WRAP_ADVANCE) {
                cur.new_page(&doc);
                draw_header(&cur.layer(&doc), cur.y);
                cur.y -= table_header_advance;
                cur.layer(&doc).use_text(
                    "(continued)",
                    style.small_font_size,
                    Mm(col_timestamp),
                    Mm(cur.y),
                    &font_mono,
                );
            }
            let layer = cur.layer(&doc);
            if i == 0 {
                layer.use_text(
                    &timestamp_str,
                    style.small_font_size,
                    Mm(col_timestamp),
                    Mm(cur.y),
                    &font_mono,
                );
            }
            if let Some(line) = source_lines.get(i) {
                layer.use_text(
                    line,
                    style.small_font_size,
                    Mm(col_source),
                    Mm(cur.y),
                    &font,
                );
            }
            if let Some(line) = desc_lines.get(i) {
                layer.use_text(
                    line,
                    style.small_font_size,
                    Mm(col_description),
                    Mm(cur.y),
                    &font,
                );
            }
            cur.y -= ROW_WRAP_ADVANCE;
        }
        // The gap between rows, over and above the last wrapped line.
        cur.y -= style.line_height - ROW_WRAP_ADVANCE;
    }

    // Footer on last page
    let footer_text = format!(
        "Generated by Seance Digital Forensics Platform on {}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    cur.layer(&doc).use_text(
        &footer_text,
        style.small_font_size,
        Mm(style.margin),
        Mm(15.0),
        &font,
    );

    // Save PDF
    doc.save(&mut BufWriter::new(File::create(output_path)?))?;
    Ok(())
}

/// Left edge of the event table, in mm. Narrower than the page margin the
/// headings use, so the description column has width to wrap into.
const TABLE_LEFT_MM: f32 = 15.0;
/// Width of the Source column, in mm.
const SOURCE_COL_MM: f32 = 45.0;
/// Characters per line in the Source column at the small font size.
const SOURCE_COL_CHARS: usize = 22;
/// Characters per line in the Description column at the small font size
/// (the column runs from `TABLE_LEFT_MM + 50 + SOURCE_COL_MM` to a 15 mm
/// right margin, about 85 mm).
const DESCRIPTION_COL_CHARS: usize = 42;
/// Characters per line for the wrapped header statements at the body size.
const HEADER_LINE_CHARS: usize = 70;
/// Vertical advance between wrapped lines inside one table row, in mm.
const ROW_WRAP_ADVANCE: f32 = 4.5;
/// Vertical advance between wrapped lines of a header statement, in mm.
const HEADER_WRAP_ADVANCE: f32 = 5.5;

/// The timezone convention the PDF's Timestamp column follows, printed on the
/// PDF's face. The CSV and JSON exports carry the source's own offset where the
/// source recorded one; this rendering does not, and says so.
pub const TIMELINE_PDF_TIMEZONE_NOTE: &str =
    "Timestamps are shown in Coordinated Universal Time (UTC), to the second. \
     Sub-second precision and the source's own UTC offset, where the source \
     recorded them, are carried by the CSV and JSON timeline exports and are \
     not shown here.";

/// The rendering rule for the Source and Description columns, printed on the
/// PDF's face so that nobody has to wonder whether a long value was cut.
pub const TIMELINE_PDF_WRAP_NOTE: &str =
    "Source and Description values are wrapped onto as many lines as they \
     need; no value in this rendering is shortened.";

/// The population line at the top of the timeline PDF.
///
/// Same pattern as `timeline_caption` in the case report: when the listing is
/// capped the matching total is stated in the same sentence as the slice, so
/// nobody reads the cap as the size of the case. The PDF's rows come back
/// newest first, so what a truncated export is missing is the OLDEST end of
/// the range, and the sentence says which end.
///
/// `truncated` is the fetch's own verdict — it asks for one row past the
/// ceiling, so it knows with certainty whether it returned a slice or the whole
/// matching set — and it is what decides the completeness claim. Completeness is
/// NEVER re-derived by comparing `shown` with `matching_total`: those two
/// figures are taken at two different moments, and a deletion landing between
/// them can bring a count down to meet a slice it does not describe. That is not
/// hypothetical arithmetic — a truncated 50,000-row export whose count came back
/// at exactly 50,000 printed "complete - every matching event is listed" on an
/// exhibit, beside a filter line that said it was truncated.
///
/// `matching_total` is counted immediately AFTER the rows are fetched, so it is
/// a second observation of a case that may have changed, not a denominator the
/// slice was cut from. Where the two disagree, the disagreement is stated and
/// its direction is not guessed at: the line reports both figures and says they
/// were taken at different moments.
pub fn timeline_export_population_line(
    shown: usize,
    matching_total: i64,
    truncated: bool,
) -> String {
    let shown_i = shown as i64;
    if truncated {
        // The fetch hit the ceiling. Whatever the later count says, this export
        // is a slice and the oldest matching events are not in it.
        if matching_total > shown_i {
            format!(
                "Events in this export: {} of {} matching this case and filter (newest first; \
                 the listing is truncated - the oldest {} matching events are NOT in it).",
                shown,
                matching_total,
                matching_total - shown_i
            )
        } else {
            format!(
                "Events in this export: {} (newest first; the listing is truncated at this \
                 server's ceiling, so the oldest matching events are NOT in it). A count taken \
                 immediately after the rows were fetched returned {}, which is not more than \
                 the rows fetched, so events were being removed from the case while this export \
                 was made; the two figures were taken at different moments.",
                shown, matching_total
            )
        }
    } else if matching_total == shown_i {
        format!(
            "Events in this export: {} of {} matching this case and filter (newest first; \
             complete - every matching event is listed).",
            shown, matching_total
        )
    } else {
        // The fetch was NOT capped, so it returned every row matching at the
        // moment it ran. The count disagrees because the case changed between
        // the two, and which way it changed is stated from the figures rather
        // than assumed.
        format!(
            "Events in this export: {} (newest first). The fetch was not capped, so it \
             returned every event matching this case and filter at the moment it ran. A count \
             taken immediately afterwards returned {}, so the case was {} while this export was \
             made; the two figures were taken at different moments.",
            shown,
            matching_total,
            if matching_total > shown_i {
                "gaining matching events"
            } else {
                "losing matching events"
            }
        )
    }
}

/// Word-wrap `s` to lines of at most `width` characters, breaking a single
/// word that is itself longer than `width` at character boundaries.
///
/// Nothing is dropped: joining the lines with single spaces (or nothing, for
/// a hard-broken word) recovers every character of the input. The hard break
/// is what makes that true for evidence-derived values — a 300-character path
/// with no spaces in it is one word, and a wrapper that "never splits a word"
/// would have let it run off the page, which is truncation by another name.
/// Character-based, not byte-based, so multi-byte input cannot be split
/// mid-character.
pub fn wrap_cell(s: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out: Vec<String> = Vec::new();
    let mut line = String::new();
    let mut line_chars = 0usize;
    for word in s.split_whitespace() {
        let word_chars = word.chars().count();
        if word_chars > width {
            // Flush what is pending, then hard-break the long word.
            if line_chars > 0 {
                out.push(std::mem::take(&mut line));
                line_chars = 0;
            }
            let chars: Vec<char> = word.chars().collect();
            for piece in chars.chunks(width) {
                out.push(piece.iter().collect());
            }
            continue;
        }
        if line_chars == 0 {
            line.push_str(word);
            line_chars = word_chars;
        } else if line_chars + 1 + word_chars <= width {
            line.push(' ');
            line.push_str(word);
            line_chars += 1 + word_chars;
        } else {
            out.push(std::mem::take(&mut line));
            line.push_str(word);
            line_chars = word_chars;
        }
    }
    if line_chars > 0 {
        out.push(line);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

impl Default for TimelineReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The completeness claim comes from the fetch, never from arithmetic on two
    /// counts taken at different moments.
    ///
    /// The case that forced this: the bounded fetch asks for one row past the
    /// ceiling, so it KNOWS it returned a slice. The count is taken afterwards,
    /// and a deletion landing in between can bring it down to exactly the size
    /// of the slice. The old line compared the two numbers, found them equal and
    /// printed "complete - every matching event is listed" on an exhibit whose
    /// filter line, three lines below, said the listing was truncated. A false
    /// completeness claim on a court-facing surface is a defect whether or not
    /// every byte in the rows above it is correct.
    #[test]
    fn a_truncated_export_never_claims_completeness_however_the_counts_land() {
        // Events deleted between the fetch and the count: the two figures meet.
        let met = timeline_export_population_line(50_000, 50_000, true);
        assert!(
            !met.contains("complete"),
            "a truncated listing must never read as complete: {met}"
        );
        assert!(met.contains("truncated"), "{met}");
        assert!(
            met.contains("oldest matching events are NOT in it"),
            "the missing end must still be named: {met}"
        );
        assert!(
            met.contains("removed") && met.contains("different moments"),
            "the disagreement and its direction must be stated: {met}"
        );

        // More deleted still, so the count is now BELOW the slice. No negative
        // arithmetic, and still no completeness claim.
        let below = timeline_export_population_line(50_000, 12, true);
        assert!(!below.contains("complete"), "{below}");
        assert!(
            !below.contains('-'),
            "no negative difference is printed: {below}"
        );

        // An uncapped fetch whose count disagrees is not "truncated" either: it
        // returned everything that matched when it ran, and says so.
        let grew = timeline_export_population_line(9, 11, false);
        assert!(!grew.contains("truncated"), "{grew}");
        assert!(grew.contains("gaining matching events"), "{grew}");
        let shrank = timeline_export_population_line(9, 8, false);
        assert!(shrank.contains("losing matching events"), "{shrank}");
        assert!(shrank.contains("returned 8"), "{shrank}");
    }

    #[test]
    fn the_timeline_pdf_states_the_case_wide_population_not_the_slice() {
        let capped = timeline_export_population_line(50_000, 412_000, true);
        assert!(
            capped.contains("50000 of 412000 matching"),
            "the slice must be stated against the matching total: {capped}"
        );
        assert!(capped.contains("truncated"), "{capped}");
        assert!(
            capped.contains("oldest 362000 matching events are NOT in it"),
            "the missing end and its size must be named: {capped}"
        );
        assert!(
            !capped.contains("Total Events"),
            "the slice must never be labelled as a total: {capped}"
        );

        let whole = timeline_export_population_line(7, 7, false);
        assert!(whole.contains("7 of 7 matching"), "{whole}");
        assert!(whole.contains("complete"), "{whole}");
        assert!(!whole.contains("truncated"), "{whole}");

        // Count taken after the fetch, and the case changed in between: the
        // disagreement is stated, not papered over.
        let grew = timeline_export_population_line(9, 8, false);
        assert!(grew.contains("losing matching events"), "{grew}");
        assert!(grew.contains("returned 8"), "{grew}");
    }

    #[test]
    fn the_timeline_pdf_wraps_long_values_rather_than_shortening_them() {
        // A description well past the old 40-character cut, made of words.
        let desc = "Process created: C:\\Users\\examiner\\AppData\\Local\\Temp\\update.exe \
                    spawned by explorer.exe with a command line that runs on and on";
        let lines = wrap_cell(desc, DESCRIPTION_COL_CHARS);
        assert!(lines.len() > 1, "a long value takes more than one line");
        assert!(lines
            .iter()
            .all(|l| l.chars().count() <= DESCRIPTION_COL_CHARS));
        // The path token is wider than the column and is hard-broken, so
        // compare with whitespace removed: every non-space character survives.
        let strip = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
        assert_eq!(
            strip(&lines.join(" ")),
            strip(desc),
            "every character of the value survives wrapping"
        );
        assert!(
            lines.iter().all(|l| !l.ends_with("...")),
            "no ellipsis, ever"
        );

        // A single word longer than the column: hard-broken, never dropped.
        let path: String = "a".repeat(3 * SOURCE_COL_CHARS + 5);
        let lines = wrap_cell(&path, SOURCE_COL_CHARS);
        assert_eq!(lines.len(), 4);
        assert_eq!(lines.concat(), path);

        // Multi-byte input is split on character boundaries.
        let s: String = "\u{20AC}".repeat(41);
        let lines = wrap_cell(&s, 40);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines.concat(), s);

        // The face of the PDF says what the rule is.
        assert!(TIMELINE_PDF_WRAP_NOTE.contains("no value in this rendering is shortened"));
    }

    #[test]
    fn the_timeline_pdf_states_its_timezone_convention() {
        assert!(TIMELINE_PDF_TIMEZONE_NOTE.contains("UTC"));
        assert!(TIMELINE_PDF_TIMEZONE_NOTE.contains("CSV and JSON"));
        // The per-row rendering agrees with the statement.
        assert!(format_timestamp(0).ends_with(" UTC"));
    }

    /// Count the pages in a saved PDF: printpdf writes one `/Type/Page/…`
    /// dictionary per page (the `/Type/Pages` tree node has no slash after it).
    fn page_count(bytes: &[u8]) -> usize {
        String::from_utf8_lossy(bytes)
            .matches("/Type/Page/")
            .count()
    }

    fn event(short_desc: &str) -> TimelineEventResponse {
        TimelineEventResponse {
            id: Uuid::nil(),
            case_id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            timestamp: 1_700_000_000,
            timestamp_subsec_nanos: 0,
            source_utc_offset_seconds: None,
            timestamp_desc: "modified".to_string(),
            source_module: "plugin.mft".to_string(),
            short_desc: short_desc.to_string(),
            full_details: String::new(),
            is_tagged: None,
            tag_note: None,
            dynamic_fields: None,
        }
    }

    /// The two pagination faults CR-026 recorded, pinned on the test both
    /// paths now share.
    #[test]
    fn the_page_break_test_measures_the_room_actually_left() {
        let h = HEADER_WRAP_ADVANCE;
        // A header line near the foot of the page breaks; the header block
        // used to have no test at all and drew below the MediaBox.
        assert!(needs_page_break(31.0, 30.0, h, 240.0, h));
        assert!(!needs_page_break(60.0, 30.0, h, 240.0, h));
        // A row that fits a fresh page is kept whole: it breaks when the room
        // left is short of it, and not otherwise.
        let fresh_row_room = 297.0 - 50.0 - 30.0 - 16.0;
        assert!(needs_page_break(
            100.0,
            30.0,
            120.0,
            fresh_row_room,
            ROW_WRAP_ADVANCE
        ));
        assert!(!needs_page_break(
            160.0,
            30.0,
            120.0,
            fresh_row_room,
            ROW_WRAP_ADVANCE
        ));
        // A row taller than a fresh page is continued from where the pen is
        // rather than pushed: at the top of a fresh page — where comparing
        // against the whole page height made it "not fit" and emitted a blank
        // page ahead of it — and half-way down one alike.
        let top_of_fresh_page = 297.0 - 50.0 - 16.0;
        let tall = fresh_row_room + 11.0;
        assert!(!needs_page_break(
            top_of_fresh_page,
            30.0,
            tall,
            fresh_row_room,
            ROW_WRAP_ADVANCE
        ));
        assert!(!needs_page_break(
            120.0,
            30.0,
            tall,
            fresh_row_room,
            ROW_WRAP_ADVANCE
        ));
        // It breaks only when not even one line of it fits here.
        assert!(needs_page_break(
            33.0,
            30.0,
            tall,
            fresh_row_room,
            ROW_WRAP_ADVANCE
        ));
    }

    /// A run of page-tall rows yields one page per row, not two (CR-026).
    #[test]
    fn a_row_taller_than_a_page_does_not_emit_a_blank_page_ahead_of_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tall = "word ".repeat(42 * 9); // ~42 wrapped lines at 42 chars
        let events: Vec<TimelineEventResponse> = (0..4).map(|_| event(&tall)).collect();
        let path = dir.path().join("tall.pdf");
        render_timeline_pdf(
            &PdfStyle::default(),
            "Case",
            events,
            4,
            false,
            path.to_str().unwrap(),
            None,
        )
        .expect("render");
        let bytes = std::fs::read(&path).expect("read back");
        let pages = page_count(&bytes);
        // Four rows of roughly a page each, continued rather than each pushed
        // to a fresh page it cannot fit on either: the content is ~850 mm
        // against ~200 mm of room per page, so five or six pages, not the nine
        // that pushing produced.
        assert!(
            (5..=6).contains(&pages),
            "four page-tall rows should take five or six pages, not {pages}"
        );
    }

    /// A long filter description runs onto a second page rather than off the
    /// bottom of the first, where it did not render (CR-026).
    #[test]
    fn a_long_filter_description_breaks_onto_a_new_page_rather_than_off_the_page() {
        let dir = tempfile::tempdir().expect("tempdir");
        let filter = "module ".repeat(400); // ~2,800 characters, ~40 header lines
        let path = dir.path().join("filter.pdf");
        render_timeline_pdf(
            &PdfStyle::default(),
            "Case",
            vec![event("one event")],
            1,
            false,
            path.to_str().unwrap(),
            Some(filter),
        )
        .expect("render");
        let bytes = std::fs::read(&path).expect("read back");
        assert!(
            page_count(&bytes) >= 2,
            "a header block taller than the page must spill onto a second page"
        );
        // Every text position is `x y Td` in points. A negative y is drawn outside the
        // MediaBox and never renders — which is where the tail of a long filter line went
        // before CR-026. The content streams are read through a PDF parser: printpdf
        // compresses them in a release build and leaves them plain in a debug one, so
        // reading the file as text passed in one profile and found nothing in the other
        // (GATE-011).
        let doc = lopdf::Document::load_mem(&bytes).expect("a well-formed PDF");
        let mut content = String::new();
        for page_id in doc.get_pages().values() {
            let stream = doc.get_page_content(*page_id).expect("a page's content");
            content.push_str(&String::from_utf8_lossy(&stream));
            content.push('\n');
        }
        let mut positions = 0;
        for line in content.lines() {
            let Some(rest) = line.strip_suffix(" Td") else {
                continue;
            };
            let Some((_, y)) = rest.rsplit_once(' ') else {
                continue;
            };
            let y: f32 = y.parse().expect("a Td operand is a number");
            positions += 1;
            assert!(y >= 0.0, "text placed below the page: `{line}`");
        }
        assert!(
            positions > 40,
            "the fixture must place many header lines: {positions}"
        );
    }

    /// The header block itself never runs below the bottom margin: every
    /// header line is written through the same break test as the rows.
    #[test]
    fn header_lines_are_never_placed_below_the_bottom_margin() {
        // Simulate the header walk with the report's own constants: however
        // many lines the filter takes, the pen never goes under the margin.
        let style = PdfStyle::default();
        let bottom = 30.0_f32;
        let top = 297.0 - style.margin;
        let mut y = top - (style.title_font_size + 10.0) - style.line_height;
        let mut pages = 1;
        let room = 297.0 - style.margin - bottom;
        for _ in 0..500 {
            if needs_page_break(y, bottom, HEADER_WRAP_ADVANCE, room, HEADER_WRAP_ADVANCE) {
                pages += 1;
                y = top;
            }
            assert!(
                y >= bottom,
                "a header line was placed at y={y}, below the margin"
            );
            y -= HEADER_WRAP_ADVANCE;
        }
        assert!(pages > 1, "500 header lines must have spilled");
    }

    #[test]
    fn short_values_are_unchanged_by_wrapping() {
        assert_eq!(wrap_cell("plugin.mft", 15), vec!["plugin.mft".to_string()]);
        assert_eq!(wrap_cell("", 15), vec![String::new()]);
    }
}
