//! XLSX (Excel) exporter for forensic reports.
//!
//! Renders the same [`ReportData`] that [`crate::render_html`] /
//! [`crate::render_pdf`] consume into a real `.xlsx` workbook (a ZIP of XML).
//! Each logical report section becomes its own worksheet with a bold, frozen
//! header row and autofit columns, so an analyst can filter and pivot the
//! tabular data directly in Excel.
//!
//! Numeric fields (counts, sizes, offsets, coordinates, durations) are written
//! as Excel numbers so aggregations/pivots work; timestamps and every other
//! value are written as strings. Excel date types are intentionally avoided
//! (the report's timestamps are already pre-formatted strings), matching the
//! string data model used by [`crate::report::CategorySection`].

use crate::report::ReportData;
use rust_xlsxwriter::{Format, Workbook, Worksheet, XlsxError};

/// The tab carrying the method qualifications.
///
/// The HTML heading is "Limitations and Qualifications of the Examination";
/// Excel allows 31 characters, so the tab keeps the leading words that name the
/// section and stops short of the limit rather than being cut at it.
const QUALIFICATIONS_SHEET: &str = "Limitations and Qualifications";

/// A single cell value. Numbers are written as Excel numbers (pivot-friendly);
/// everything else, including pre-formatted timestamps, is written as a string.
#[derive(Clone)]
enum Cell {
    Text(String),
    Num(f64),
}

/// One worksheet-worth of tabular data: a name, a header row, and data rows.
struct Sheet {
    name: String,
    headers: Vec<String>,
    rows: Vec<Vec<Cell>>,
}

/// Render a [`ReportData`] as a complete `.xlsx` workbook, returned as raw bytes
/// (a ZIP archive whose first bytes are `PK\x03\x04`).
///
/// Mirrors [`crate::render_pdf`]'s signature so wiring an HTTP route is trivial.
/// One worksheet is emitted per non-empty report section; a `Summary` sheet with
/// case metadata is always present, so the workbook always has at least one
/// sheet.
/// The report-wide timezone statement, as the spreadsheet renders it.
fn seance_reporting_timezone_statement() -> &'static str {
    crate::report::TIMEZONE_STATEMENT
}

pub fn render_xlsx(data: &ReportData) -> anyhow::Result<Vec<u8>> {
    let sheets = build_sheets(data);

    let mut workbook = Workbook::new();
    let header_fmt = Format::new().set_bold();
    let mut used_names: Vec<String> = Vec::new();

    for sheet in &sheets {
        let name = unique_sheet_name(&sheet.name, &mut used_names);
        let ws = workbook.add_worksheet();
        ws.set_name(&name)?;
        write_sheet(ws, sheet, &header_fmt)?;
    }

    let bytes = workbook.save_to_buffer()?;
    Ok(bytes)
}

/// Write one [`Sheet`] onto a worksheet: bold header row, data rows, a frozen
/// header (`set_freeze_panes(1, 0)`), and autofit column widths.
fn write_sheet(ws: &mut Worksheet, sheet: &Sheet, header_fmt: &Format) -> Result<(), XlsxError> {
    for (c, header) in sheet.headers.iter().enumerate() {
        ws.write_string_with_format(0, c as u16, header, header_fmt)?;
    }
    for (r, row) in sheet.rows.iter().enumerate() {
        let row_num = (r + 1) as u32;
        for (c, cell) in row.iter().enumerate() {
            let col = c as u16;
            match cell {
                Cell::Text(t) => {
                    ws.write_string(row_num, col, t)?;
                }
                Cell::Num(v) => {
                    ws.write_number(row_num, col, *v)?;
                }
            }
        }
    }
    if !sheet.headers.is_empty() {
        // Freeze the header row so it stays visible while scrolling.
        ws.set_freeze_panes(1, 0)?;
    }
    ws.autofit();
    Ok(())
}

// ---------------------------------------------------------------------------
// Section -> Sheet flattening
// ---------------------------------------------------------------------------

/// Flatten a [`ReportData`] into an ordered list of worksheets, one per
/// non-empty section (mirrors the section order of the HTML/PDF renderers).
fn build_sheets(data: &ReportData) -> Vec<Sheet> {
    let mut sheets = Vec::new();

    // ---- Summary (always present) ----
    let mut summary_rows: Vec<Vec<Cell>> = vec![
        kv("Case Name", text(&data.case_name)),
        kv("Case Reference", opt(&data.case_reference)),
        kv("Examiner", text(&data.examiner)),
        kv("Report Generated", text(&data.generated_at)),
        kv("Tool", text(&data.tool_name)),
        kv("Tool Version", text(&data.tool_version)),
        // Never omitted. A spreadsheet of timestamps with no stated timezone is
        // the easiest of all the report formats to misread, because a reader
        // will sort and filter it in their own local frame of reference.
        kv("Times", text(seance_reporting_timezone_statement())),
    ];
    if let Some(identity) = &data.report_identity {
        if !identity.report_id.is_empty() {
            summary_rows.push(kv("Report Reference", text(&identity.report_id)));
        }
        if let Some(revision) = identity.revision {
            summary_rows.push(kv("Revision", num(revision as i64)));
        }
        if let Some(classification) = &identity.classification {
            summary_rows.push(kv("Handling", text(classification)));
        }
    }
    if let Some(details) = &data.examiner_details {
        if let Some(role) = &details.role {
            summary_rows.push(kv("Examiner Role", text(role)));
        }
        if let Some(org) = &details.organisation {
            summary_rows.push(kv("Organisation", text(org)));
        }
        if let Some(quals) = &details.qualifications {
            summary_rows.push(kv("Qualifications", text(quals)));
        }
        if let Some(contact) = &details.contact {
            summary_rows.push(kv("Contact", text(contact)));
        }
    }
    if let Some(summary) = &data.executive_summary {
        if !summary.is_empty() {
            summary_rows.push(kv("Executive Summary", text(summary)));
        }
    }
    summary_rows.push(kv("Total Artifacts", num(data.total_artifacts)));
    // Always stated, including 0, as the XML does: the reader of the workbook
    // is told the Bookmarks sheet is the shared set, not everything marked.
    summary_rows.push(kv(
        "Personal Bookmarks Excluded",
        num(data.personal_bookmarks_excluded),
    ));
    summary_rows.push(kv(
        "Audit Chain Valid",
        Cell::Text(data.audit_chain_valid.to_string()),
    ));
    summary_rows.push(kv(
        "Audit Chain Entries Checked",
        num(data.audit_chain_checked),
    ));
    // "Audit Chain Valid: true" on its own reads as "the log is unaltered", and
    // over an unkeyed chain that is a claim the evidence cannot support. The
    // keying travels with the verdict, on the row immediately beneath it, in the
    // same words the HTML/PDF reports and the verify endpoint use (HUNT-011).
    summary_rows.push(kv(
        "Audit Chain Tamper-Evident",
        Cell::Text(data.audit_chain_tamper_evident.to_string()),
    ));
    summary_rows.push(kv(
        "Audit Chain Tamper Evidence",
        text(&crate::report::audit_chain_keying_disclosure(
            data.audit_chain_tamper_evident,
            data.audit_chain_tamper_evident_from,
            data.audit_chain_key_configured,
        )),
    ));
    // The chain spans the whole installation, not this case. Stated on the sheet
    // so a spreadsheet reader cannot take the row above as a per-case verdict.
    summary_rows.push(kv(
        "Audit Chain Scope",
        text(crate::report::audit_chain_scope_note(
            data.audit_chain_valid,
        )),
    ));
    if let Some(ov) = &data.file_overview {
        summary_rows.push(kv("Total Files", num(ov.total_files)));
        summary_rows.push(kv("Directories", num(ov.directories)));
        summary_rows.push(kv("Deleted Files", num(ov.deleted_files)));
        // opt_i renders an undetermined count as blank, never as 0.
        summary_rows.push(kv("Carved Files", opt_i(ov.carved_files)));
        summary_rows.push(kv("Encrypted Files", opt_i(ov.encrypted_files)));
        summary_rows.push(kv("Known-Good Filtered", num(ov.known_good_filtered)));
        summary_rows.push(kv("Notable Alerts", num(ov.notable_alerts)));
    }
    // Capped listings state both figures on the Summary sheet: a spreadsheet
    // reader counting rows on a sheet must not conclude that is the case total.
    let mut capped = |label: &str, listed: usize, total: i64| {
        if total > listed as i64 {
            summary_rows.push(kv(&format!("{label} (case total)"), num(total)));
            summary_rows.push(kv(
                &format!("{label} (listed in this export)"),
                num(listed as i64),
            ));
        }
    };
    capped(
        "Timeline Events",
        data.full_timeline.len(),
        data.full_timeline_total,
    );
    capped(
        "Notable Hash Matches",
        data.notable_hash_hits.len(),
        data.notable_hash_total,
    );
    capped(
        "Known-Good Hash Matches",
        data.known_good_hash_hits.len(),
        data.known_good_hash_total,
    );
    capped(
        "Audit Entries",
        data.audit_entries.len(),
        data.audit_entries_total,
    );
    // Each per-category sheet is capped too, and a sheet carries no room for a
    // caption: the HTML and PDF renderers print "Showing N of M records." above
    // the table, but a spreadsheet reader would otherwise have nothing but the
    // row count. Disclose the same two figures here.
    for section in &data.category_sections {
        capped(&section.title, section.rows.len(), section.total);
    }
    capped(
        "Processing Log",
        data.processing_log.len(),
        data.processing_log_total,
    );
    // Completeness belongs on the Summary sheet as well as its own: a reader who
    // opens only Summary must still meet the statement. Rendered whether or not
    // anything is incomplete, so its absence can never be read as good news.
    {
        let (_, statement) = crate::report::completeness_statement(data.incompleteness.as_ref());
        summary_rows.push(kv("Result Completeness", text(&statement)));
        if let Some(inc) = &data.incompleteness {
            summary_rows.push(kv(
                "Content-Incomplete Artifacts",
                num(inc.content_incomplete),
            ));
            summary_rows.push(kv(
                "Inventory-Incomplete Artifacts",
                num(inc.inventory_incomplete),
            ));
            if inc.timeline_omitted > 0 {
                summary_rows.push(kv("Timeline Events Omitted", num(inc.timeline_omitted)));
            }
        }
    }
    // The counterpart of the completeness statement above: that one says what
    // was not read, this one says something was read and by what means. A reader
    // who opens Summary and stops there is told the section exists and where it
    // is; silence when nothing was recorded is deliberate, and the sheet itself
    // explains why.
    if !data.method_qualifications.is_empty() {
        summary_rows.push(kv(
            QUALIFICATIONS_SHEET,
            text(&format!(
                "{} qualification(s) are recorded against the method used in this examination. \
                 Each states a respect in which the method qualifies what may be concluded, and \
                 is set out in full on the '{}' sheet.",
                data.method_qualifications.len(),
                QUALIFICATIONS_SHEET,
            )),
        ));
    }
    // A capped GPS list on its own sheet has nothing but rows to read, so the
    // disclosure goes on the Summary sheet, where a reader meets it before the
    // Geolocation tab.
    if data.geolocation_truncated {
        summary_rows.push(kv(
            "Geolocation",
            text(&crate::report::geo_truncation_note(data.geolocation.len())),
        ));
    }
    sheets.push(Sheet {
        name: "Summary".into(),
        headers: vec!["Field".into(), "Value".into()],
        rows: summary_rows,
    });

    // ---- Evidence Sources ----
    if !data.evidence_sources.is_empty() {
        let rows = data
            .evidence_sources
            .iter()
            .map(|s| {
                vec![
                    text(&s.name),
                    text(&s.source_type),
                    opt_i(s.size_bytes),
                    opt(&s.md5),
                    opt(&s.sha1),
                    opt(&s.sha256),
                    opt(&s.acquired_at),
                ]
            })
            .collect();
        sheets.push(Sheet {
            name: "Evidence Sources".into(),
            headers: cols(&[
                "Name",
                "Type",
                "Size (bytes)",
                "MD5",
                "SHA1",
                "SHA256",
                "Acquired",
            ]),
            rows,
        });
    }

    // ---- Evidence Integrity Verification ----
    if !data.integrity_checks.is_empty() {
        let rows = data
            .integrity_checks
            .iter()
            .map(|c| {
                vec![
                    text(&c.source_name),
                    text(&c.algorithm),
                    opt(&c.acquisition_hash),
                    opt(&c.recomputed_hash),
                    Cell::Text(c.outcome.label().into()),
                    Cell::Text(c.outcome.description().into()),
                    opt(&c.checked_at),
                ]
            })
            .collect();
        sheets.push(Sheet {
            name: "Integrity Checks".into(),
            headers: cols(&[
                "Source",
                "Algorithm",
                "Acquisition Hash",
                "Recomputed Hash",
                "Result",
                "Meaning",
                "Recorded",
            ]),
            rows,
        });
    }

    // ---- Artifact Statistics ----
    if !data.artifact_counts.is_empty() || data.total_artifacts != 0 {
        let mut rows: Vec<Vec<Cell>> = data
            .artifact_counts
            .iter()
            .map(|(ty, count)| vec![text(ty), num(*count)])
            .collect();
        rows.push(vec![Cell::Text("Total".into()), num(data.total_artifacts)]);
        sheets.push(Sheet {
            name: "Artifact Statistics".into(),
            headers: cols(&["Artifact Type", "Count"]),
            rows,
        });
    }

    // ---- Result Completeness ----
    // One sheet naming every recorded shortfall and the section it belongs to.
    // A per-category sheet carries no room for a caption, so without this an
    // analyst pivoting the workbook would see a listing with nothing to say it
    // was a subset.
    {
        let mut rows: Vec<Vec<Cell>> = Vec::new();
        if let Some(inc) = &data.incompleteness {
            for r in &inc.reasons {
                rows.push(vec![
                    Cell::Text("Case (content)".into()),
                    text(r.text()),
                    num(r.count),
                ]);
            }
            // The listing axis carries its OWN recorded reasons
            // (`inventory_incomplete_reason`, written across the plugin tree).
            // Restating the axis name in place of them would tell an analyst
            // only what the count already said.
            if inc.inventory_incomplete > 0 {
                if inc.inventory_reasons.is_empty() {
                    rows.push(vec![
                        Cell::Text("Case (inventory)".into()),
                        Cell::Text("no reason was recorded".into()),
                        num(inc.inventory_incomplete),
                    ]);
                }
                for r in &inc.inventory_reasons {
                    rows.push(vec![
                        Cell::Text("Case (inventory)".into()),
                        text(r.text()),
                        num(r.count),
                    ]);
                }
            }
            if inc.content_incomplete > 0 && inc.reasons.is_empty() {
                rows.push(vec![
                    Cell::Text("Case (content)".into()),
                    Cell::Text("no reason was recorded".into()),
                    num(inc.content_incomplete),
                ]);
            }
            if inc.distinct_reasons > inc.reasons.len() as i64 {
                rows.push(vec![
                    Cell::Text("Case (content)".into()),
                    Cell::Text("distinct reasons recorded in the case".into()),
                    num(inc.distinct_reasons),
                ]);
            }
            if inc.distinct_inventory_reasons > inc.inventory_reasons.len() as i64 {
                rows.push(vec![
                    Cell::Text("Case (inventory)".into()),
                    Cell::Text("distinct reasons recorded in the case".into()),
                    num(inc.distinct_inventory_reasons),
                ]);
            }
        }
        for section in &data.category_sections {
            for r in &section.incomplete_reasons {
                rows.push(vec![text(&section.title), text(r.text()), num(r.count)]);
            }
            if section.incomplete_reasons.is_empty() && section.incomplete_records > 0 {
                rows.push(vec![
                    text(&section.title),
                    Cell::Text("reason not recorded".into()),
                    num(section.incomplete_records),
                ]);
            }
        }
        if rows.is_empty() {
            // "Nothing was found incomplete" and "nobody looked" must not render
            // as the same empty sheet.
            let (_, statement) =
                crate::report::completeness_statement(data.incompleteness.as_ref());
            rows.push(vec![Cell::Text("Case".into()), text(&statement), num(0)]);
        }
        sheets.push(Sheet {
            name: "Result Completeness".into(),
            headers: cols(&["Scope", "Recorded reason", "Artifacts"]),
            rows,
        });
    }

    // ---- Per-category artifact detail sections (one sheet each) ----
    for section in &data.category_sections {
        let rows = section
            .rows
            .iter()
            .map(|row| row.iter().map(|cell| text(cell)).collect())
            .collect();
        sheets.push(Sheet {
            name: section.title.clone(),
            headers: section.columns.clone(),
            rows,
        });
    }

    // ---- Notable Hash Matches ----
    if !data.notable_hash_hits.is_empty() {
        sheets.push(hash_hits_sheet(
            "Notable Hash Matches",
            &data.notable_hash_hits,
        ));
    }

    // ---- Known-Good (KFF) Hash Matches ----
    if !data.known_good_hash_hits.is_empty() {
        sheets.push(hash_hits_sheet(
            "Known-Good Hashes",
            &data.known_good_hash_hits,
        ));
    }

    // ---- Findings / Bookmarks ----
    //
    // The shared set only. Personal bookmarks never reach a report (owner
    // decision 2026-09-26), and the sheet says how many were excluded in its
    // own last row, so it is kept even when no shared bookmark exists: an
    // absent tab would make the exclusion silent in the export that leaves the
    // lab. The count is also always on the Summary sheet.
    let excluded_note =
        crate::report::personal_bookmarks_excluded_note(data.personal_bookmarks_excluded);
    if !data.bookmarks.is_empty() || excluded_note.is_some() {
        let mut rows: Vec<Vec<Cell>> = data
            .bookmarks
            .iter()
            .map(|b| {
                vec![
                    opt(&b.category),
                    text(&b.artifact_name),
                    opt(&b.source_path),
                    opt_i(b.source_offset),
                    opt(&b.note),
                    opt(&b.examiner),
                    text(&b.created_at),
                ]
            })
            .collect();
        if let Some(note) = excluded_note {
            rows.push(vec![text(&note)]);
        }
        sheets.push(Sheet {
            name: "Bookmarks".into(),
            headers: cols(&[
                "Category",
                "Artifact",
                "Source Path",
                "Source Offset",
                "Note",
                "Examiner",
                "Created",
            ]),
            rows,
        });
    }

    // ---- Values Traced Across the Evidence (ROADMAP §5.13) ----
    //
    // One row per (value, record kind), so the workbook can be sorted and
    // filtered by either — which is the reason to have it in a spreadsheet at
    // all. Both counts travel on every row: the total when the value was
    // pinned and the total now. A row whose per-kind counts are a sample says
    // so in its own column, because a sample presented as a total in the
    // export that leaves the lab is the defect this project treats as HIGH.
    if !data.traced_values.is_empty() {
        let mut rows: Vec<Vec<Cell>> = Vec::new();
        for t in &data.traced_values {
            let recheck = match (t.matches_now, &t.recheck_unavailable_reason) {
                (Some(now), _) => num(now),
                // Blank in this workbook means "never recorded", which is
                // exactly right: the question could not be re-asked.
                (None, _) => Cell::Text(String::new()),
            };
            let recheck_note = match (t.matches_now, &t.recheck_unavailable_reason) {
                (Some(now), _) if now == t.matches_when_pinned => text("re-checked: unchanged"),
                (Some(_), _) => text("re-checked: the case answers differently now"),
                (None, Some(why)) => text(&format!("not re-checked: {why}")),
                (None, None) => text("not re-checked; no reason recorded"),
            };
            let sample = text(if t.truncated_when_pinned {
                "SAMPLE - the per-kind counts do not add up to the total"
            } else {
                "complete"
            });
            if t.groups_when_pinned.is_empty() {
                rows.push(vec![
                    text(&t.value),
                    text(""),
                    Cell::Text(String::new()),
                    num(t.matches_when_pinned),
                    sample.clone(),
                    recheck.clone(),
                    recheck_note.clone(),
                    text(&t.examiner),
                    text(&t.pinned_at),
                    opt(&t.note),
                ]);
                continue;
            }
            for (kind, count) in &t.groups_when_pinned {
                rows.push(vec![
                    text(&t.value),
                    text(kind),
                    num(*count),
                    num(t.matches_when_pinned),
                    sample.clone(),
                    recheck.clone(),
                    recheck_note.clone(),
                    text(&t.examiner),
                    text(&t.pinned_at),
                    opt(&t.note),
                ]);
            }
        }
        sheets.push(Sheet {
            name: "Traced Values".into(),
            headers: cols(&[
                "Value",
                "Record kind",
                "Artifacts of that kind",
                "Artifacts when pinned",
                "Are the per-kind counts complete?",
                "Artifacts now",
                "Re-check",
                "Pinned by",
                "Pinned at",
                "Note",
            ]),
            rows,
        });
    }

    // ---- Investigative Leads (ROADMAP §2.2) ----
    //
    // Its own sheet, never merged into Bookmarks: those are what an examiner
    // marked and these are what the tool claimed, and a spreadsheet is the
    // easiest place in the world to lose that distinction — a reader sorts the
    // rows and the provenance is gone. The three text columns are three
    // columns for the same reason the HTML has three blocks: an observation, a
    // reading of it, and what it does not establish are different in kind.
    //
    // The preamble cannot be laid over a grid, so the first column of every
    // row carries the grade and the last two carry the provenance, and the
    // Summary sheet's Qualifications cell carries the qualification that
    // `leads_qualification` generates.
    if !data.leads.is_empty() {
        let rows = data
            .leads
            .iter()
            .map(|l| {
                vec![
                    text(&l.confidence),
                    text(&l.title),
                    text(&l.kind),
                    text(&l.observation),
                    // An empty cell in this workbook means "never recorded",
                    // which is exactly what `None` means here: the observation
                    // spoke for itself and no reading was drawn from it.
                    opt(&l.inference),
                    text(&l.qualification),
                    text(
                        &l.evidence
                            .iter()
                            .map(|(k, v)| format!("{k} = {v}"))
                            .collect::<Vec<_>>()
                            .join("; "),
                    ),
                    text(&l.subject),
                    opt_i(l.device_offset.and_then(|o| i64::try_from(o).ok())),
                    text(&l.source_module),
                    text(if l.stored_as_a_record {
                        "recorded in the case"
                    } else {
                        "computed for this report; not stored as an artifact"
                    }),
                ]
            })
            .collect();
        sheets.push(Sheet {
            name: "Investigative Leads".into(),
            headers: cols(&[
                "Grade",
                "Lead",
                "Check",
                "Observation (checkable against the evidence)",
                "What this may indicate (Seance's reading, not a fact)",
                "What it does not establish",
                "Values it rests on",
                "Subject artifact",
                "Device offset",
                "Raised by",
                "Provenance",
            ]),
            rows,
        });
    }

    // ---- What the build could look for at all ----
    //
    // Present whenever the build carries any check, including when nothing was
    // raised: a workbook with no Leads sheet means either "nothing matched" or
    // "nothing here looks for that", and without this sheet the two are
    // indistinguishable.
    if !data.lead_detections.is_empty() {
        let rows = data
            .lead_detections
            .iter()
            .map(|d| vec![text(&d.kind), text(&d.looks_for)])
            .collect();
        sheets.push(Sheet {
            name: "Lead Checks".into(),
            headers: cols(&["Check", "What it looks for"]),
            rows,
        });
    }

    // ---- Geolocation (EXIF GPS) ----
    if !data.geolocation.is_empty() {
        let rows = data
            .geolocation
            .iter()
            .map(|g| {
                vec![
                    text(&g.label),
                    // Same suppression as the HTML report: a Path that merely
                    // repeats the File asserts a path that was never
                    // established, and this is the export that leaves the lab.
                    opt(&crate::report::geo_path_cell(g)),
                    Cell::Num(g.latitude),
                    Cell::Num(g.longitude),
                    opt_f(g.altitude),
                    opt(&g.timestamp),
                ]
            })
            .collect();
        sheets.push(Sheet {
            name: "Geolocation".into(),
            headers: cols(&[
                "File",
                "Path",
                "Latitude",
                "Longitude",
                "Altitude",
                "Timestamp",
            ]),
            rows,
        });
    }

    // ---- Timeline Highlights ----
    if !data.timeline_highlights.is_empty() {
        sheets.push(timeline_sheet(
            "Timeline Highlights",
            &data.timeline_highlights,
            true,
        ));
    }

    // ---- Full Timeline ----
    if !data.full_timeline.is_empty() {
        sheets.push(timeline_sheet("Timeline", &data.full_timeline, false));
    }

    // ---- Chain of Custody & Audit ----
    if !data.audit_entries.is_empty() {
        let rows = data
            .audit_entries
            .iter()
            .map(|a| {
                vec![
                    text(&a.timestamp),
                    text(&a.user),
                    text(&a.action),
                    text(&a.resource_type),
                ]
            })
            .collect();
        sheets.push(Sheet {
            name: "Audit Log".into(),
            headers: cols(&["Timestamp", "User", "Action", "Resource Type"]),
            rows,
        });
    }

    // ---- Processing Log ----
    if !data.processing_log.is_empty() {
        let rows = data
            .processing_log
            .iter()
            .map(|p| {
                vec![
                    text(&p.module_id),
                    text(&p.status),
                    // Blank, not 0, when the run count was not recorded: the
                    // row's existence proves at least one run happened.
                    opt_i((p.runs > 0).then_some(p.runs)),
                    num(p.artifacts_produced),
                    opt_i(p.duration_ms),
                    opt(&p.error_message),
                ]
            })
            .collect();
        sheets.push(Sheet {
            name: "Processing Log".into(),
            headers: cols(&[
                "Module",
                "Status",
                "Runs",
                "Artifacts",
                "Duration (ms)",
                "Error",
            ]),
            rows,
        });
    }

    // ---- Limitations and Qualifications of the Examination ----
    //
    // Last, for the reason the HTML report puts the section after the findings
    // and the processing log: a reader has to have seen what was found before
    // being told what it rests on. The Summary sheet points at it, so a reader
    // who never scrolls the tab strip still meets it.
    //
    // Absent, no sheet is emitted at all. An empty vector cannot tell an
    // examination that raised no qualification from one whose caller never
    // populated the field, so a tab reading "None recorded" would assert the
    // first and the export cannot ground that; and a section invented for every
    // examination is one a reader learns to skip, which is the failure mode that
    // costs the section its force when it does have something to say. The HTML
    // and PDF renderers stay silent here for the same reason.
    if !data.method_qualifications.is_empty() {
        let rows = data
            .method_qualifications
            .iter()
            .map(|q| {
                vec![
                    text(&q.subject),
                    text(&q.statement),
                    // Never blank: an empty cell in this workbook means the
                    // value was never recorded, and an unrecorded scope is the
                    // opposite of the whole-examination scope `affects: None`
                    // stands for.
                    text(crate::report::qualification_scope(q)),
                ]
            })
            .collect();
        sheets.push(Sheet {
            name: QUALIFICATIONS_SHEET.into(),
            headers: cols(&["Subject", "Qualification", "Bears on"]),
            rows,
        });
    }

    sheets
}

/// Build a hash-hit sheet (used for both notable and known-good matches).
fn hash_hits_sheet(name: &str, hits: &[crate::report::ReportHashHit]) -> Sheet {
    let rows = hits
        .iter()
        .map(|h| {
            vec![
                text(&h.artifact_name),
                opt(&h.path),
                text(&h.hash_set_name),
                text(&h.algorithm),
                text(&h.matched_hash),
            ]
        })
        .collect();
    Sheet {
        name: name.into(),
        headers: cols(&["Artifact", "Path", "Hash Set", "Algorithm", "Matched Hash"]),
        rows,
    }
}

/// Build a timeline sheet.
///
/// `annotated` distinguishes the two populations that share
/// [`crate::report::ReportTimelineEvent`]. The highlights are events an examiner
/// tagged, and their note and attribution are the point of the sheet. The full
/// timeline is every event in the case, tagged or not, where those columns would
/// be empty on every row — and a column of empty cells beside hundreds of
/// thousands of events reads as "examined, nothing to say", which is a claim
/// nobody made.
fn timeline_sheet(
    name: &str,
    events: &[crate::report::ReportTimelineEvent],
    annotated: bool,
) -> Sheet {
    let rows = events
        .iter()
        .map(|e| {
            let mut row = vec![
                text(&e.timestamp),
                text(&e.description),
                text(&e.source_module),
            ];
            if annotated {
                row.push(text(e.note.as_deref().unwrap_or("")));
                row.push(text(e.examiner.as_deref().unwrap_or("")));
            }
            row
        })
        .collect();
    let headers = if annotated {
        cols(&[
            "Timestamp",
            "Description",
            "Source Module",
            "Note",
            "Examiner",
        ])
    } else {
        cols(&["Timestamp", "Description", "Source Module"])
    };
    Sheet {
        name: name.into(),
        headers,
        rows,
    }
}

// ---------------------------------------------------------------------------
// Cell / column helpers
// ---------------------------------------------------------------------------

fn text(s: &str) -> Cell {
    Cell::Text(s.to_string())
}

/// A `Field`/`Value` row for the key/value Summary sheet.
fn kv(field: &str, value: Cell) -> Vec<Cell> {
    vec![Cell::Text(field.to_string()), value]
}

/// Largest magnitude an `i64` represents exactly as `f64` (2^53). Forensic
/// values above this (byte offsets, sizes) must be written as text so Excel does
/// not silently round them.
const MAX_EXACT_IN_F64: i64 = 1 << 53;

fn num(v: i64) -> Cell {
    if v.abs() <= MAX_EXACT_IN_F64 {
        Cell::Num(v as f64)
    } else {
        Cell::Text(v.to_string())
    }
}

/// An optional string: `None` becomes an empty cell.
fn opt(o: &Option<String>) -> Cell {
    Cell::Text(o.clone().unwrap_or_default())
}

/// An optional integer: `None` becomes an empty cell, `Some` a number (as text
/// when too large to represent exactly as an Excel number).
fn opt_i(o: Option<i64>) -> Cell {
    match o {
        Some(v) => num(v),
        None => Cell::Text(String::new()),
    }
}

/// An optional float: `None` becomes an empty cell, `Some` a number.
fn opt_f(o: Option<f64>) -> Cell {
    match o {
        Some(v) => Cell::Num(v),
        None => Cell::Text(String::new()),
    }
}

fn cols(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| s.to_string()).collect()
}

// ---------------------------------------------------------------------------
// Sheet-name sanitisation
// ---------------------------------------------------------------------------

/// Sanitise a proposed worksheet name to satisfy Excel's rules: at most 31
/// characters, none of `[ ] : * ? / \`, no leading/trailing apostrophe or
/// whitespace, and not blank.
fn sanitize_sheet_name(raw: &str) -> String {
    let escaped: String = raw
        .chars()
        .map(|c| match c {
            '[' | ']' | ':' | '*' | '?' | '/' | '\\' => '_',
            _ => c,
        })
        .collect();
    // Excel allows 31 characters, and a report section's disambiguator — the
    // "(Whatsapp)" that tells one "Chat / Messages" from another — sits at the
    // END of the title. Truncating from the right therefore removed exactly the
    // part that made the tab identifiable, handing the reader two tabs they
    // could not attribute. When the name is too long the trailing qualifier is
    // kept and the middle of the base title gives way instead.
    let cleaned = if escaped.chars().count() <= 31 {
        escaped
    } else {
        shorten_keeping_qualifier(&escaped, 31)
    };
    let trimmed = cleaned.trim().trim_matches('\'').trim();
    if trimmed.is_empty() {
        "Sheet".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Shorten to `max` characters while preserving a trailing `(qualifier)`.
///
/// Elides the middle of the base name rather than the end, because the end is
/// where the thing that makes two sibling sections distinguishable lives.
fn shorten_keeping_qualifier(name: &str, max: usize) -> String {
    let chars: Vec<char> = name.chars().collect();
    let qualifier_start = name.rfind(" (").filter(|_| name.ends_with(')'));
    let Some(byte_idx) = qualifier_start else {
        return chars.into_iter().take(max).collect();
    };
    let qualifier: String = name[byte_idx..].to_string();
    let qual_len = qualifier.chars().count();
    // No room to keep both: the qualifier alone is the more useful half.
    if qual_len >= max {
        return qualifier.chars().skip(qual_len - max).collect();
    }
    let base: String = name[..byte_idx].to_string();
    let keep = max - qual_len - 1; // room for the ellipsis
    let head: String = base.chars().take(keep).collect();
    format!("{head}\u{2026}{qualifier}")
}

/// Sanitise `raw` and make it unique (case-insensitively) against `used`,
/// appending a ` (n)` suffix if needed while staying within 31 characters.
/// Records the chosen name in `used`.
fn unique_sheet_name(raw: &str, used: &mut Vec<String>) -> String {
    let base = sanitize_sheet_name(raw);
    let mut candidate = base.clone();
    let mut i = 2;
    while used.iter().any(|u| u.eq_ignore_ascii_case(&candidate)) {
        let suffix = format!(" ({i})");
        let keep = 31usize.saturating_sub(suffix.chars().count());
        let trunc: String = base.chars().take(keep).collect();
        candidate = format!("{}{}", trunc.trim_end(), suffix);
        i += 1;
    }
    used.push(candidate.clone());
    candidate
}

#[cfg(test)]
mod tests {

    /// Review finding: sheet names truncate at 31 characters from the END,
    /// which is exactly where a section's disambiguator sits — so two SRUM-family
    /// tabs both became "Application Resource Usage (SRU" and the reader was
    /// back to tabs they could not attribute.
    #[test]
    fn a_long_sheet_name_keeps_the_part_that_tells_it_from_its_sibling() {
        let a = sanitize_sheet_name("Application Resource Usage (SRUM) (Srum)");
        let b = sanitize_sheet_name("Application Resource Usage (SRUM) (Srumdb)");

        assert!(a.chars().count() <= 31, "{a:?}");
        assert!(b.chars().count() <= 31, "{b:?}");
        assert_ne!(a, b, "the qualifier is what distinguishes them");
        assert!(a.ends_with("(Srum)"), "got {a:?}");
        assert!(b.ends_with("(Srumdb)"), "got {b:?}");
    }

    #[test]
    fn a_short_sheet_name_is_untouched() {
        assert_eq!(sanitize_sheet_name("Web History"), "Web History");
    }

    /// Review finding: the geolocation Path suppression was wired into the HTML
    /// renderer only, so the spreadsheet — the export that actually leaves the
    /// lab — still printed File and Path as the same string, asserting a path
    /// that was never established.
    #[test]
    fn the_geolocation_sheet_leaves_a_path_that_repeats_the_file_blank() {
        let mut data = fixture();
        data.geolocation = vec![
            GeoPoint {
                label: "IMG.JPG".into(),
                path: Some("IMG.JPG".into()),
                latitude: 1.0,
                longitude: 2.0,
                ..Default::default()
            },
            GeoPoint {
                label: "OTHER.JPG".into(),
                path: Some("/DCIM/OTHER.JPG".into()),
                latitude: 3.0,
                longitude: 4.0,
                ..Default::default()
            },
        ];
        let sheets = build_sheets(&data);
        let geo = sheets
            .iter()
            .find(|s| s.name == "Geolocation")
            .expect("geolocation sheet");

        assert_eq!(
            cell_text(&geo.rows[0][1]),
            "",
            "a path repeating the file must be blank"
        );
        assert_eq!(
            cell_text(&geo.rows[1][1]),
            "/DCIM/OTHER.JPG",
            "a real path is still written"
        );
    }

    use super::*;
    use crate::report::{
        CategorySection, EvidenceSource, FileOverview, GeoPoint, IntegrityCheck,
        MethodQualification, ProcessingLogEntry, ReportAuditEntry, ReportBookmark, ReportHashHit,
        ReportTimelineEvent,
    };

    /// A cell's text, with numbers rendered the way a reader would see them.
    /// One row per (value, record kind), so the workbook can be sorted and
    /// filtered by either — the reason to have it in a spreadsheet at all. Both
    /// counts travel on every row, and a capped snapshot says so in its own
    /// column: a sample presented as a total in the export that leaves the lab
    /// is the defect this project treats as HIGH.
    #[test]
    fn the_traced_values_sheet_carries_both_counts_and_flags_a_sample() {
        let mut data = fixture();
        data.traced_values = vec![crate::report::ReportTracedValue {
            value: "10.0.0.7".into(),
            note: Some("the address the exfil connected to".into()),
            examiner: "Analyst A".into(),
            pinned_at: "2026-09-14T11:00:00+00:00".into(),
            matches_when_pinned: 11,
            truncated_when_pinned: false,
            groups_when_pinned: vec![("NetworkFlow".into(), 6), ("DnsResolution".into(), 5)],
            matches_now: Some(19),
            recheck_unavailable_reason: None,
        }];

        let sheets = build_sheets(&data);
        let sheet = sheets
            .iter()
            .find(|s| s.name == "Traced Values")
            .unwrap_or_else(|| {
                panic!(
                    "no traced-values sheet: {:?}",
                    sheets.iter().map(|s| &s.name).collect::<Vec<_>>()
                )
            });
        assert_eq!(sanitize_sheet_name("Traced Values"), "Traced Values");
        assert_eq!(sheet.rows.len(), 2, "one row per record kind");
        assert_eq!(cell_text(&sheet.rows[0][0]), "10.0.0.7");
        assert_eq!(cell_text(&sheet.rows[0][1]), "NetworkFlow");
        assert_eq!(cell_text(&sheet.rows[0][2]), "6");
        assert_eq!(cell_text(&sheet.rows[0][3]), "11");
        assert_eq!(cell_text(&sheet.rows[0][4]), "complete");
        assert_eq!(cell_text(&sheet.rows[0][5]), "19");
        assert!(cell_text(&sheet.rows[0][6]).contains("answers differently"));
        assert_eq!(cell_text(&sheet.rows[0][7]), "Analyst A");
        assert!(cell_text(&sheet.rows[0][9]).contains("exfil"));

        // A capped snapshot says so on every row it produced.
        data.traced_values[0].truncated_when_pinned = true;
        let sheets = build_sheets(&data);
        let sheet = sheets
            .iter()
            .find(|s| s.name == "Traced Values")
            .expect("sheet");
        assert!(cell_text(&sheet.rows[0][4]).starts_with("SAMPLE"));
    }

    /// A blank cell in this workbook means "never recorded", which is exactly
    /// what an un-re-checked value is. It must not become a zero.
    #[test]
    fn a_value_that_could_not_be_rechecked_leaves_the_count_blank_and_says_why() {
        let mut data = fixture();
        data.traced_values = vec![crate::report::ReportTracedValue {
            value: "10.0.0.7".into(),
            note: None,
            examiner: "Analyst A".into(),
            pinned_at: "2026-09-14T11:00:00+00:00".into(),
            matches_when_pinned: 11,
            truncated_when_pinned: false,
            groups_when_pinned: vec![("NetworkFlow".into(), 11)],
            matches_now: None,
            recheck_unavailable_reason: Some("this build has no search index".into()),
        }];
        let sheets = build_sheets(&data);
        let sheet = sheets
            .iter()
            .find(|s| s.name == "Traced Values")
            .expect("sheet");
        assert_eq!(cell_text(&sheet.rows[0][5]), "");
        assert!(cell_text(&sheet.rows[0][6]).contains("not re-checked"));
        assert!(cell_text(&sheet.rows[0][6]).contains("no search index"));
    }

    /// A value the pivot grouped into nothing still gets a row: the pin, the
    /// total and the examiner are the assertion, and losing the row would lose
    /// that too.
    #[test]
    fn a_value_with_no_groups_still_gets_a_row() {
        let mut data = fixture();
        data.traced_values = vec![crate::report::ReportTracedValue {
            value: "nothing@example.com".into(),
            note: None,
            examiner: "Analyst A".into(),
            pinned_at: "2026-09-14T11:00:00+00:00".into(),
            matches_when_pinned: 0,
            truncated_when_pinned: false,
            groups_when_pinned: vec![],
            matches_now: Some(0),
            recheck_unavailable_reason: None,
        }];
        let sheet = build_sheets(&data)
            .into_iter()
            .find(|s| s.name == "Traced Values")
            .expect("sheet");
        assert_eq!(sheet.rows.len(), 1);
        assert_eq!(cell_text(&sheet.rows[0][0]), "nothing@example.com");
        assert_eq!(cell_text(&sheet.rows[0][1]), "");
    }

    #[test]
    fn a_workbook_with_no_traced_values_grows_no_such_sheet() {
        let names: Vec<String> = build_sheets(&fixture())
            .iter()
            .map(|s| s.name.clone())
            .collect();
        assert!(!names.contains(&"Traced Values".to_string()), "{names:?}");
    }

    /// The leads keep their own sheet and are never merged into Bookmarks.
    ///
    /// A spreadsheet is the easiest place in the world to lose the distinction
    /// between what an examiner marked and what the tool claimed: a reader
    /// sorts the rows and the provenance is gone. So they are separate sheets,
    /// and the three text fields stay three columns for the same reason the
    /// HTML keeps three blocks.
    #[test]
    fn the_leads_get_their_own_sheet_and_keep_their_three_parts_apart() {
        let mut data = fixture();
        data.leads = vec![crate::report::ReportLead {
            title: "Timestamps reordered on svchost.exe".into(),
            kind: "timestomp".into(),
            confidence: "Notable".into(),
            observation: "The $SI and $FN timestamps are inconsistent.".into(),
            inference: Some("Rewriting $SI is how the time of an action is hidden.".into()),
            qualification: "It is also what a restore from backup looks like.".into(),
            evidence: vec![("si_modified".into(), "2019-03-02T11:14:08Z".into())],
            subject: "11111111-1111-1111-1111-111111111111".into(),
            device_offset: Some(4096),
            source_module: "plugin.findings.timestomp".into(),
            stored_as_a_record: true,
        }];
        data.leads_total = 1;
        data.lead_detections = vec![crate::report::ReportLeadDetection {
            kind: "timestomp".into(),
            looks_for: "NTFS $SI timestamps inconsistent with $FN.".into(),
        }];

        let sheets = build_sheets(&data);
        let names: Vec<&str> = sheets.iter().map(|s| s.name.as_str()).collect();
        let leads = sheets
            .iter()
            .find(|s| s.name == "Investigative Leads")
            .unwrap_or_else(|| panic!("no leads sheet: {names:?}"));
        assert!(
            names.contains(&"Lead Checks"),
            "what the build looked for must travel with what it found: {names:?}"
        );
        // Both tab names survive Excel's 31-character truncation intact, which
        // is what put two unattributable tabs in front of a reader once.
        for name in ["Investigative Leads", "Lead Checks"] {
            assert_eq!(sanitize_sheet_name(name), name);
        }

        assert_eq!(leads.rows.len(), 1);
        let row = &leads.rows[0];
        assert_eq!(cell_text(&row[0]), "Notable");
        assert_eq!(cell_text(&row[1]), "Timestamps reordered on svchost.exe");
        assert!(cell_text(&row[3]).contains("timestamps are inconsistent"));
        assert!(cell_text(&row[4]).contains("how the time of an action is hidden"));
        assert!(cell_text(&row[5]).contains("restore from backup"));
        assert!(cell_text(&row[6]).contains("si_modified = 2019-03-02T11:14:08Z"));
        assert_eq!(cell_text(&row[10]), "recorded in the case");
        // The headers are what a reader without the HTML in front of them has
        // to go on, so each says which of the three kinds its column holds.
        assert!(leads.headers[3].contains("checkable against the evidence"));
        assert!(leads.headers[4].contains("not a fact"));
        assert!(leads.headers[5].contains("does not establish"));

        // And a lead that cannot be re-opened says so in the workbook too.
        data.leads[0].stored_as_a_record = false;
        let sheets = build_sheets(&data);
        let leads = sheets
            .iter()
            .find(|s| s.name == "Investigative Leads")
            .expect("leads sheet");
        assert!(cell_text(&leads.rows[0][10]).contains("not stored as an artifact"));
    }

    /// A build that raised nothing still ships the list of checks, because a
    /// workbook with no leads sheet means either "nothing matched" or "nothing
    /// here looks for that" and those are different statements about the case.
    #[test]
    fn a_workbook_with_no_leads_still_says_what_the_build_looked_for() {
        let mut data = fixture();
        data.lead_detections = vec![crate::report::ReportLeadDetection {
            kind: "timestomp".into(),
            looks_for: "NTFS $SI timestamps inconsistent with $FN.".into(),
        }];
        let names: Vec<String> = build_sheets(&data).iter().map(|s| s.name.clone()).collect();
        assert!(!names.contains(&"Investigative Leads".to_string()));
        assert!(names.contains(&"Lead Checks".to_string()), "{names:?}");
    }

    /// A build carrying no checks at all grows neither sheet, rather than a tab
    /// with nothing under it.
    #[test]
    fn a_workbook_from_a_build_with_no_checks_grows_neither_sheet() {
        let names: Vec<String> = build_sheets(&fixture())
            .iter()
            .map(|s| s.name.clone())
            .collect();
        assert!(!names.contains(&"Investigative Leads".to_string()));
        assert!(!names.contains(&"Lead Checks".to_string()), "{names:?}");
    }

    fn cell_text(c: &Cell) -> String {
        match c {
            Cell::Text(t) => t.clone(),
            Cell::Num(n) => n.to_string(),
        }
    }

    /// A report fixture exercising every section type, kept deterministic.
    fn fixture() -> ReportData {
        ReportData {
            case_name: "Case Z".into(),
            case_reference: Some("REF-42".into()),
            examiner: "Analyst A".into(),
            generated_at: "2026-07-24 10:00:00 UTC".into(),
            tool_name: "Seance".into(),
            tool_version: "0.9.0".into(),
            executive_summary: Some("Two evidence sources ingested.".into()),
            file_overview: Some(FileOverview {
                total_files: 1200,
                directories: 80,
                deleted_files: 14,
                carved_files: Some(6),
                encrypted_files: None,
                known_good_filtered: 900,
                notable_alerts: 2,
            }),
            evidence_sources: vec![EvidenceSource {
                name: "disk.e01".into(),
                source_type: "E01".into(),
                size_bytes: Some(1024),
                md5: Some("md5hash".into()),
                sha1: Some("sha1hash".into()),
                sha256: Some("sha256hash".into()),
                acquired_at: Some("2026-07-15".into()),
            }],
            integrity_checks: vec![IntegrityCheck {
                source_name: "disk.e01".into(),
                algorithm: "SHA256".into(),
                acquisition_hash: Some("aaa".into()),
                recomputed_hash: Some("aaa".into()),
                outcome: crate::report::IntegrityOutcome::Verified,
                checked_at: Some("2026-07-15".into()),
            }],
            artifact_counts: vec![("FileEntry".into(), 500), ("ParsedRecord".into(), 42)],
            total_artifacts: 542,
            category_sections: vec![CategorySection {
                title: "Web History".into(),
                columns: vec!["URL".into(), "Visits".into()],
                rows: vec![vec!["http://example.com".into(), "5".into()]],
                total: 1,
                ..Default::default()
            }],
            bookmarks: vec![ReportBookmark {
                artifact_name: "note.txt".into(),
                category: Some("Findings".into()),
                note: Some("suspicious".into()),
                examiner: Some("Analyst A".into()),
                created_at: "2026-07-20".into(),
                source_path: Some("/root/note.txt".into()),
                source_offset: Some(4096),
            }],
            geolocation: vec![GeoPoint {
                label: "IMG_1.jpg".into(),
                path: Some("/DCIM/IMG_1.jpg".into()),
                latitude: 51.5,
                longitude: -0.14,
                altitude: Some(10.0),
                timestamp: Some("2023".into()),
            }],
            timeline_highlights: vec![ReportTimelineEvent {
                timestamp: "2026-07-01".into(),
                description: "highlight".into(),
                source_module: "mft".into(),
                ..Default::default()
            }],
            full_timeline: vec![ReportTimelineEvent {
                timestamp: "2026-07-01".into(),
                description: "event".into(),
                source_module: "mft".into(),
                ..Default::default()
            }],
            notable_hash_hits: vec![ReportHashHit {
                artifact_name: "bad.exe".into(),
                path: Some("/tmp/bad.exe".into()),
                hash_set_name: "Contraband".into(),
                algorithm: "SHA256".into(),
                matched_hash: "deadbeef".into(),
            }],
            known_good_hash_hits: vec![ReportHashHit {
                artifact_name: "kernel32.dll".into(),
                path: None,
                hash_set_name: "NSRL".into(),
                algorithm: "SHA1".into(),
                matched_hash: "bbb".into(),
            }],
            processing_log: vec![ProcessingLogEntry {
                module_id: "plugin.filesystem.ntfs".into(),
                status: "ok".into(),
                runs: 3,
                artifacts_produced: 500,
                duration_ms: Some(1234),
                error_message: None,
            }],
            audit_entries: vec![ReportAuditEntry {
                timestamp: "2026-07-20 09:00:00 UTC".into(),
                user: "Analyst A".into(),
                action: "case_report_exported".into(),
                resource_type: "case".into(),
            }],
            audit_chain_valid: true,
            audit_chain_checked: 3,
            ..Default::default()
        }
    }

    #[test]
    fn produces_nonempty_zip_workbook() {
        let bytes = render_xlsx(&fixture()).expect("xlsx render");
        // XLSX is a ZIP archive: the local-file-header magic is PK\x03\x04.
        assert!(bytes.starts_with(b"PK\x03\x04"), "not a ZIP archive");
        assert!(bytes.len() > 1000, "workbook implausibly small");
    }

    #[test]
    fn roundtrips_via_zip_reader() {
        // Round-trip: re-open the produced bytes as a ZIP and confirm the
        // expected worksheet parts exist and a written value survives. The `zip`
        // crate is pulled in transitively by rust_xlsxwriter.
        let bytes = render_xlsx(&fixture()).expect("xlsx render");
        let reader = std::io::Cursor::new(bytes);
        let mut zip = zip::ZipArchive::new(reader).expect("valid zip");

        // A workbook part and at least the first sheet part must be present.
        let names: Vec<String> = (0..zip.len())
            .map(|i| zip.by_index(i).unwrap().name().unwrap().to_string())
            .collect();
        assert!(
            names.iter().any(|n| n == "xl/workbook.xml"),
            "missing workbook.xml, parts: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "xl/worksheets/sheet1.xml"),
            "missing sheet1.xml, parts: {names:?}"
        );

        // Strings are stored in the shared-strings table; confirm a distinctive
        // value round-tripped into the workbook.
        use std::io::Read;
        let mut sst = String::new();
        zip.by_name("xl/sharedStrings.xml")
            .expect("sharedStrings.xml")
            .read_to_string(&mut sst)
            .unwrap();
        assert!(sst.contains("Case Z"), "case name not found in workbook");
        assert!(
            sst.contains("http://example.com"),
            "category row value not found in workbook"
        );
    }

    #[test]
    fn one_sheet_per_section_plus_summary() {
        let sheets = build_sheets(&fixture());
        let names: Vec<&str> = sheets.iter().map(|s| s.name.as_str()).collect();
        // Summary is always first; each populated section follows.
        assert_eq!(names[0], "Summary");
        for expected in [
            "Evidence Sources",
            "Integrity Checks",
            "Artifact Statistics",
            "Web History",
            "Notable Hash Matches",
            "Known-Good Hashes",
            "Bookmarks",
            "Geolocation",
            "Timeline Highlights",
            "Timeline",
            "Audit Log",
            "Processing Log",
        ] {
            assert!(names.contains(&expected), "missing sheet: {expected}");
        }
    }

    /// The workbook is the copy an examiner filters and sorts, so the tag note
    /// has to reach it too — a highlight sheet without the note is a list of
    /// timestamps with the reasoning stripped out. The full-timeline sheet, by
    /// contrast, lists events nobody tagged and must not grow columns that would
    /// be empty for every row.
    #[test]
    fn the_highlights_sheet_carries_the_note_and_the_timeline_sheet_does_not() {
        let mut data = fixture();
        data.timeline_highlights = vec![ReportTimelineEvent {
            timestamp: "2026-07-01".into(),
            description: "highlight".into(),
            source_module: "mft".into(),
            examiner: Some("Analyst A".into()),
            note: Some("matches CCTV entry time".into()),
        }];
        let sheets = build_sheets(&data);

        let highlights = sheets
            .iter()
            .find(|s| s.name == "Timeline Highlights")
            .expect("highlights sheet");
        assert!(
            highlights.headers.iter().any(|h| h == "Note"),
            "headers: {:?}",
            highlights.headers
        );
        assert!(
            highlights.headers.iter().any(|h| h == "Examiner"),
            "headers: {:?}",
            highlights.headers
        );
        assert!(
            highlights.rows[0]
                .iter()
                .any(|c| matches!(c, Cell::Text(t) if t == "matches CCTV entry time")),
            "the note is missing from the highlights sheet"
        );

        let timeline = sheets
            .iter()
            .find(|s| s.name == "Timeline")
            .expect("timeline sheet");
        assert!(
            !timeline.headers.iter().any(|h| h == "Note"),
            "headers: {:?}",
            timeline.headers
        );
        assert!(
            !timeline.headers.iter().any(|h| h == "Examiner"),
            "headers: {:?}",
            timeline.headers
        );
    }

    /// A per-category sheet is capped the same way the timeline and audit
    /// listings are, and a worksheet has nowhere to put the caption the HTML and
    /// PDF renderers print above the table. Without the Summary disclosure a
    /// spreadsheet reader counts the rows on the sheet and concludes that is how
    /// many records the case holds for that module.
    #[test]
    fn capped_category_sheets_are_disclosed_on_the_summary_sheet() {
        let mut data = fixture();
        data.category_sections = vec![CategorySection {
            title: "Web History".into(),
            columns: vec!["URL".into(), "Visits".into()],
            rows: vec![vec!["http://example.com".into(), "5".into()]],
            total: 90_000,
            ..Default::default()
        }];
        let sheets = build_sheets(&data);
        let summary = sheets
            .iter()
            .find(|s| s.name == "Summary")
            .expect("summary");
        let labels: Vec<&str> = summary
            .rows
            .iter()
            .filter_map(|r| match r.first() {
                Some(Cell::Text(t)) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            labels.contains(&"Web History (case total)"),
            "capped category must state its case-wide total: {labels:?}"
        );
        assert!(
            labels.contains(&"Web History (listed in this export)"),
            "capped category must state how many rows this export lists: {labels:?}"
        );
    }

    /// Values from the Summary sheet, keyed by their label.
    fn summary_value(sheets: &[Sheet], label: &str) -> Option<String> {
        let summary = sheets.iter().find(|s| s.name == "Summary")?;
        summary
            .rows
            .iter()
            .find_map(|r| match (r.first(), r.get(1)) {
                (Some(Cell::Text(k)), Some(Cell::Text(v))) if k == label => Some(v.clone()),
                _ => None,
            })
    }

    /// B6-028 / B4-018: the spreadsheet is read on its own, so it has to carry
    /// the same two disclosures the HTML and PDF reports do — what the audit
    /// chain result covers, and whether the GPS list was capped.
    #[test]
    fn summary_sheet_states_audit_scope_and_a_capped_gps_list() {
        let sheets = build_sheets(&fixture());
        assert!(
            summary_value(&sheets, "Audit Chain Scope")
                .expect("audit scope row")
                .contains("instance-wide hash chain"),
            "the audit result must name what it covers"
        );
        assert!(
            summary_value(&sheets, "Geolocation").is_none(),
            "an uncapped GPS list must not carry a cap notice"
        );

        let mut capped = fixture();
        capped.geolocation_truncated = true;
        let sheets = build_sheets(&capped);
        assert!(
            summary_value(&sheets, "Geolocation")
                .expect("geolocation cap row")
                .contains("AT LEAST"),
            "a capped GPS list must be disclosed on the Summary sheet"
        );
    }

    /// HUNT-011: the Summary sheet used to carry "Audit Chain Valid: true" with
    /// nothing beside it, and a spreadsheet reader takes that for "the log is
    /// unaltered". Over an unkeyed chain it means only "internally consistent":
    /// the digests are a plain SHA-256 over fields that all live in the same
    /// database, so a DB writer can rewrite a row and re-hash the rest. The
    /// keying travels with the verdict on every surface, this one included.
    #[test]
    fn summary_sheet_says_whether_a_passing_chain_is_tamper_evident() {
        // The fixture's chain is valid and (by ReportData's cautious default)
        // unkeyed — the shape this bug is about.
        let sheets = build_sheets(&fixture());
        assert_eq!(
            summary_value(&sheets, "Audit Chain Valid").as_deref(),
            Some("true"),
            "the verdict itself must still be stated"
        );
        assert_eq!(
            summary_value(&sheets, "Audit Chain Tamper-Evident").as_deref(),
            Some("false"),
            "an unkeyed chain must never be exported as tamper-evident"
        );
        let note = summary_value(&sheets, "Audit Chain Tamper Evidence").expect("note row");
        assert!(
            note.contains("UNKEYED"),
            "the note does not disclose the keying: {note}"
        );
        assert!(
            note.contains("NOT evidence that the log is unaltered"),
            "note does not say what the verdict is worth: {note}"
        );

        let mut keyed = fixture();
        keyed.audit_chain_tamper_evident = true;
        let sheets = build_sheets(&keyed);
        assert_eq!(
            summary_value(&sheets, "Audit Chain Tamper-Evident").as_deref(),
            Some("true")
        );
        assert!(
            summary_value(&sheets, "Audit Chain Tamper Evidence")
                .expect("tamper-evidence note row")
                .contains("have not been altered or reordered"),
            "a keyed chain must still be credited with what it proves"
        );
    }

    #[test]
    fn bare_report_still_produces_valid_workbook() {
        let bare = ReportData {
            case_name: "Bare".into(),
            examiner: "E".into(),
            ..Default::default()
        };
        let sheets = build_sheets(&bare);
        // The two always-present sheets: Summary, and Result Completeness --
        // which must appear even on a bare report, because a completeness sheet
        // that shows up only when something is wrong teaches a reader that its
        // absence is an assurance.
        assert_eq!(sheets.len(), 2);
        assert_eq!(sheets[0].name, "Summary");
        assert_eq!(sheets[1].name, "Result Completeness");
        let bytes = render_xlsx(&bare).expect("xlsx render");
        assert!(bytes.starts_with(b"PK\x03\x04"));
    }

    /// The workbook is the analyst-pivotable product; a sheet of records that
    /// came from a truncated read must carry the same disclosure the HTML and
    /// PDF renderers print above the table.
    #[test]
    fn incompleteness_reaches_the_workbook() {
        let mut data = fixture();
        data.incompleteness = Some(crate::report::IncompletenessSummary {
            content_incomplete: 12,
            inventory_incomplete: 1,
            reasons: vec![crate::report::IncompletenessReason {
                reason: Some("hive exceeded the 512 MiB read cap".into()),
                count: 12,
            }],
            distinct_reasons: 1,
            inventory_reasons: vec![crate::report::IncompletenessReason {
                reason: Some("archive structure could not be resolved".into()),
                count: 1,
            }],
            distinct_inventory_reasons: 1,
            superseded: 0,
            timeline_omitted: 0,
        });
        data.category_sections[0].incomplete_records = 12;
        data.category_sections[0].incomplete_reasons =
            data.incompleteness.as_ref().unwrap().reasons.clone();

        let sheets = build_sheets(&data);
        let sheet = sheets
            .iter()
            .find(|s| s.name == "Result Completeness")
            .expect("completeness sheet");
        let cells: Vec<&str> = sheet
            .rows
            .iter()
            .flat_map(|r| r.iter())
            .filter_map(|c| match c {
                Cell::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            cells.contains(&"hive exceeded the 512 MiB read cap"),
            "the reason must be given, not just the fact: {cells:?}"
        );
        assert!(
            cells.contains(&"Web History"),
            "the shortfall must be attributed to the section it affects: {cells:?}"
        );
        assert!(
            cells.contains(&"Case (inventory)"),
            "a short inventory is a separate disclosure: {cells:?}"
        );
        // The listing axis has its OWN recorded reason key
        // (`inventory_incomplete_reason`, written at 43 sites across the plugin
        // tree). Before this, the workbook restated the axis name in its place,
        // so an analyst learned only what the count already told them.
        assert!(
            cells.contains(&"archive structure could not be resolved"),
            "the recorded reason for a short listing must reach the workbook: {cells:?}"
        );

        // A Summary-only reader must meet the statement too.
        let summary = sheets
            .iter()
            .find(|s| s.name == "Summary")
            .expect("summary");
        let labels: Vec<&str> = summary
            .rows
            .iter()
            .filter_map(|r| match r.first() {
                Some(Cell::Text(t)) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        assert!(labels.contains(&"Result Completeness"));
        assert!(labels.contains(&"Content-Incomplete Artifacts"));
    }

    /// An unassessed case must not export a workbook indistinguishable from a
    /// clean one.
    #[test]
    fn an_unassessed_workbook_says_completeness_was_not_assessed() {
        let mut data = fixture();
        data.incompleteness = None;
        let sheets = build_sheets(&data);
        let sheet = sheets
            .iter()
            .find(|s| s.name == "Result Completeness")
            .expect("completeness sheet");
        let joined: String = sheet
            .rows
            .iter()
            .flat_map(|r| r.iter())
            .filter_map(|c| match c {
                Cell::Text(t) => Some(t.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(" | ");
        assert!(joined.contains("NOT assessed"), "{joined}");
    }

    /// Review finding: the whole `method_qualifications` vector reached the HTML
    /// and PDF renderers only. This is the same asymmetry as the geolocation
    /// Path cell above, one section wider — and the spreadsheet is the export
    /// that leaves the lab.
    ///
    /// The sheet sits after the findings for the reason the HTML section sits
    /// after them: a reader has to have seen what was found before being told
    /// what it rests on.
    #[test]
    fn recorded_qualifications_become_their_own_sheet_after_the_findings() {
        let mut data = fixture();
        data.method_qualifications = vec![MethodQualification {
            subject: "Symbol source — Linux memory image".into(),
            statement: "No symbol file described this kernel, so the layouts were read out of \
                        the image itself and nothing independent corroborates them."
                .into(),
            affects: Some("Every finding read out of the memory image.".into()),
        }];

        let sheets = build_sheets(&data);
        let names: Vec<&str> = sheets.iter().map(|s| s.name.as_str()).collect();
        let at = names
            .iter()
            .position(|n| *n == QUALIFICATIONS_SHEET)
            .unwrap_or_else(|| panic!("no qualifications sheet: {names:?}"));
        let findings = names
            .iter()
            .position(|n| *n == "Web History")
            .expect("category sheet");
        assert!(
            at > findings,
            "the qualifications belong after the findings they qualify: {names:?}"
        );
        // Excel truncates a sheet name at 31 characters, and truncation is what
        // put two unattributable tabs in front of a reader once already.
        assert!(
            sanitize_sheet_name(QUALIFICATIONS_SHEET) == QUALIFICATIONS_SHEET,
            "the tab name must survive Excel's 31-character limit intact"
        );

        let sheet = &sheets[at];
        assert_eq!(
            sheet.headers,
            cols(&["Subject", "Qualification", "Bears on"])
        );
        assert_eq!(sheet.rows.len(), 1);
        assert_eq!(
            cell_text(&sheet.rows[0][0]),
            "Symbol source — Linux memory image"
        );
        assert!(cell_text(&sheet.rows[0][1]).contains("nothing independent corroborates them"));
        assert_eq!(
            cell_text(&sheet.rows[0][2]),
            "Every finding read out of the memory image."
        );
    }

    /// `affects: None` is documented to mean the examination as a whole. The
    /// HTML report can leave that implicit under its introductory paragraph; a
    /// spreadsheet row cannot, because a blank cell in this workbook means the
    /// value was never recorded.
    #[test]
    fn a_qualification_bearing_on_everything_names_that_scope() {
        let mut data = fixture();
        data.method_qualifications = vec![MethodQualification {
            subject: "Decompression ceiling".into(),
            statement: "Compressed members above the configured ceiling were listed but never \
                        decompressed."
                .into(),
            affects: None,
        }];
        let sheets = build_sheets(&data);
        let sheet = sheets
            .iter()
            .find(|s| s.name == QUALIFICATIONS_SHEET)
            .expect("qualifications sheet");
        assert_eq!(
            cell_text(&sheet.rows[0][2]),
            crate::report::QUALIFICATION_SCOPE_WHOLE_EXAMINATION,
            "an unscoped qualification must not read as one whose scope went unrecorded"
        );
    }

    /// A reader who opens Summary and stops there still has to be told the
    /// section exists — the same treatment completeness and a capped GPS list
    /// already get.
    #[test]
    fn the_summary_sheet_points_at_the_qualifications() {
        let mut data = fixture();
        data.method_qualifications = vec![MethodQualification {
            subject: "Symbol source".into(),
            statement: "Read out of the image itself.".into(),
            affects: None,
        }];
        let sheets = build_sheets(&data);
        let value = summary_value(&sheets, QUALIFICATIONS_SHEET).expect("a summary pointer row");
        assert!(
            value.contains(QUALIFICATIONS_SHEET),
            "the pointer must name the sheet: {value}"
        );
        assert!(
            value.contains('1'),
            "the pointer must say how many were recorded: {value}"
        );
    }

    /// An examination that recorded no qualification and one whose caller never
    /// populated the field are indistinguishable in `ReportData`. A sheet — even
    /// one saying "none" — would assert the first, so the workbook stays silent,
    /// as the HTML and PDF renderers do.
    #[test]
    fn no_qualifications_means_no_sheet_and_no_claim_that_there_were_none() {
        let sheets = build_sheets(&fixture());
        assert!(
            !sheets.iter().any(|s| s.name == QUALIFICATIONS_SHEET),
            "an empty section must not become an empty sheet"
        );
        assert!(
            summary_value(&sheets, QUALIFICATIONS_SHEET).is_none(),
            "silence, not a claim that nothing qualified the method"
        );
    }

    #[test]
    fn sheet_names_sanitised_and_unique() {
        let mut used = Vec::new();
        // Illegal characters replaced, length capped at 31.
        let a = unique_sheet_name("Web/History: 2024 [full]?*", &mut used);
        assert!(a.chars().count() <= 31);
        for bad in ['/', ':', '[', ']', '?', '*', '\\'] {
            assert!(!a.contains(bad), "illegal char {bad} left in {a}");
        }
        // A colliding name gets a numeric suffix rather than duplicating.
        let b = unique_sheet_name("Summary", &mut used);
        let c = unique_sheet_name("Summary", &mut used);
        assert_ne!(b.to_lowercase(), c.to_lowercase());
        // Blank input falls back to a placeholder.
        let d = unique_sheet_name("   ", &mut used);
        assert!(!d.is_empty());
    }

    /// Review finding (ROADMAP §3.15): the workbook is built from the same
    /// ReportData as the HTML report, but its Bookmarks sheet listed the shared
    /// set only and was omitted outright when there were none, so the exclusion
    /// of personal bookmarks was silent in the one export that leaves the lab.
    /// Synthetic ReportData; this pins the mechanism, not evidence.
    #[test]
    fn the_workbook_states_how_many_personal_bookmarks_were_excluded() {
        let mut data = fixture();
        data.bookmarks.clear();
        data.personal_bookmarks_excluded = 3;
        let sheets = build_sheets(&data);
        let note = crate::report::personal_bookmarks_excluded_note(3).unwrap();

        let bookmarks = sheets
            .iter()
            .find(|s| s.name == "Bookmarks")
            .expect("the Bookmarks sheet is kept to carry the exclusion");
        assert!(
            bookmarks
                .rows
                .iter()
                .flatten()
                .any(|c| cell_text(c) == note),
            "the exclusion sentence is in a cell of the Bookmarks sheet"
        );

        // The count is always on the Summary, including 0, as in the XML.
        for n in [0_i64, 3] {
            data.personal_bookmarks_excluded = n;
            let sheets = build_sheets(&data);
            let summary = sheets.iter().find(|s| s.name == "Summary").unwrap();
            let row = summary
                .rows
                .iter()
                .find(|r| cell_text(&r[0]) == "Personal Bookmarks Excluded")
                .expect("a Summary row for the count");
            assert_eq!(cell_text(&row[1]), n.to_string());
        }
        // No shared bookmarks and no exclusions: no empty sheet.
        data.personal_bookmarks_excluded = 0;
        assert!(!build_sheets(&data).iter().any(|s| s.name == "Bookmarks"));
    }
}
