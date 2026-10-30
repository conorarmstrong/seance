#![forbid(unsafe_code)]
use chrono::{DateTime, Utc};
use printpdf::*;
use uuid::Uuid;

pub mod body_file;
pub mod docx;
pub mod figures;
pub mod kml;
pub mod pdf_signing;
pub mod report;
pub mod timeline_report;
pub mod xlsx;

pub use body_file::{
    mode_as_string, render_body_file, render_body_file_preamble, render_body_file_verdict,
    render_event_body_file_preamble, render_event_body_file_verdict, BodyFileEntry,
    BODY_FILE_COLUMNS, BODY_FILE_VERDICT_MARKER,
};
pub use docx::{render_docx, render_docx_with};
pub use kml::{render_geojson, render_kml};
pub use pdf_signing::{sign_pdf, SigningConfig, SigningError};
pub use report::{
    audit_chain_keying_disclosure, audit_chain_keying_note, audit_chain_scope_note,
    completeness_statement, default_glossary, geo_truncation_note, integrity_statement,
    leads_qualification, personal_bookmarks_excluded_note, render_html, render_html_with,
    render_pdf, render_pdf_with, render_rtf, render_rtf_with, render_xml, render_xml_with,
    statement_of_truth, tally_integrity, CategorySection, EvidenceSource, ExaminerDetails,
    FileOverview, GeoPoint, GlossaryEntry, IncompletenessReason, IncompletenessSummary,
    IntegrityCheck, IntegrityOutcome, IntegrityTally, MethodQualification, ProcessingLogEntry,
    ReportAuditEntry, ReportBookmark, ReportCommEdge, ReportCommNode, ReportCommunicationGraph,
    ReportData, ReportExtras, ReportFeatureHistogram, ReportFeatureKind, ReportFeatureValue,
    ReportHashHit, ReportIdentity, ReportLead, ReportLeadDetection, ReportTimelineEvent,
    ReportTracedValue, DEFAULT_STATEMENT_OF_TRUTH, FEATURE_HISTOGRAMS_NONE_FOUND,
    FEATURE_HISTOGRAMS_NOT_GATHERED, LEADS_PREAMBLE, QUALIFICATION_SCOPE_WHOLE_EXAMINATION,
    TIMEZONE_STATEMENT,
};
pub use timeline_report::TimelineReportGenerator;
pub use xlsx::render_xlsx;

/// Common PDF styling and utilities
pub struct PdfStyle {
    pub title_font_size: f32,
    pub heading_font_size: f32,
    pub body_font_size: f32,
    pub small_font_size: f32,
    pub margin: f32,
    pub line_height: f32,
}

impl Default for PdfStyle {
    fn default() -> Self {
        Self {
            title_font_size: 24.0,
            heading_font_size: 16.0,
            body_font_size: 12.0,
            small_font_size: 10.0,
            margin: 50.0,
            line_height: 14.0,
        }
    }
}

/// Report metadata
#[derive(Debug, Clone)]
pub struct ReportMetadata {
    pub title: String,
    pub case_name: String,
    pub case_id: Uuid,
    pub generated_at: DateTime<Utc>,
    pub generated_by: String,
    pub description: Option<String>,
}

impl ReportMetadata {
    pub fn new(title: String, case_name: String, case_id: Uuid) -> Self {
        Self {
            title,
            case_name,
            case_id,
            generated_at: Utc::now(),
            generated_by: "Seance Digital Forensics Platform".to_string(),
            description: None,
        }
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }
}

/// Helper to create a new PDF document
pub fn create_pdf_document(
    title: &str,
    width_mm: f32,
    height_mm: f32,
) -> (PdfDocumentReference, PdfPageIndex, PdfLayerIndex) {
    let (doc, page1, layer1) = PdfDocument::new(title, Mm(width_mm), Mm(height_mm), "Layer 1");
    (doc, page1, layer1)
}

/// Helper to add a new page to a PDF
pub fn add_page(
    doc: &PdfDocumentReference,
    width_mm: f32,
    height_mm: f32,
) -> (PdfPageIndex, PdfLayerIndex) {
    let (page, layer) = doc.add_page(Mm(width_mm), Mm(height_mm), "Layer 1");
    (page, layer)
}

/// Format a timestamp for display
pub fn format_timestamp(ts: i64) -> String {
    match DateTime::from_timestamp(ts, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "Invalid timestamp".to_string(),
    }
}

/// Format a date for display
pub fn format_date(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_timestamp() {
        let ts = 1609459200; // 2021-01-01 00:00:00 UTC
        let formatted = format_timestamp(ts);
        assert!(formatted.contains("2021-01-01"));
    }

    #[test]
    fn test_report_metadata() {
        let case_id = Uuid::new_v4();
        let metadata =
            ReportMetadata::new("Test Report".to_string(), "Test Case".to_string(), case_id);
        assert_eq!(metadata.title, "Test Report");
        assert_eq!(metadata.case_name, "Test Case");
        assert_eq!(metadata.case_id, case_id);
    }
}
