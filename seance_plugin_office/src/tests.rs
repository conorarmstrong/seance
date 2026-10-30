use super::*;
use seance_core::data_source::DataSource;
use std::io::Write;
use std::sync::Arc;

use seance_core::data_source::ByteSliceDataSource;

/// Build a ZIP from (name, bytes) parts.
fn zip_of(parts: &[(&str, &str)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in parts {
        w.start_file(*name, opts).unwrap();
        w.write_all(data.as_bytes()).unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// Run the parser over a named blob and return the artifacts.
fn run(name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let a = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    OfficeParser.process(&a).unwrap()
}

fn text_of(rec: &Artifact) -> &str {
    rec.metadata
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

const CONTENT_TYPES_WORD: &str = r#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#;

fn docx_bytes() -> Vec<u8> {
    let document = r#"<?xml version="1.0"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p><w:r><w:t>Hello forensic world</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">exfiltration evidence</w:t></w:r></w:p>
</w:body></w:document>"#;
    let core = r#"<?xml version="1.0"?>
<cp:coreProperties xmlns:cp="x" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">
<dc:title>Quarterly Plan</dc:title>
<dc:creator>Investigator Jones</dc:creator>
<dcterms:created>2026-01-02T09:00:00Z</dcterms:created>
</cp:coreProperties>"#;
    zip_of(&[
        ("[Content_Types].xml", CONTENT_TYPES_WORD),
        ("word/document.xml", document),
        ("docProps/core.xml", core),
    ])
}

#[test]
fn docx_extracts_text_and_core_props() {
    let arts = run("plan.docx", docx_bytes());
    assert_eq!(arts.len(), 1);
    let rec = &arts[0];
    assert_eq!(rec.metadata["format"], "Word");
    assert_eq!(rec.metadata["container"], "OOXML");
    let text = text_of(rec);
    assert!(text.contains("Hello forensic world"), "got: {text:?}");
    assert!(text.contains("exfiltration evidence"), "got: {text:?}");
    // Paragraph break between the two runs.
    assert!(text.contains('\n'));
    assert_eq!(rec.metadata["title"], "Quarterly Plan");
    assert_eq!(rec.metadata["author"], "Investigator Jones");
    assert_eq!(rec.metadata["created"], "2026-01-02T09:00:00Z");
    // Name uses the document title, not the filename.
    assert_eq!(rec.metadata["name"], "Word document: Quarterly Plan");
    assert!(rec.metadata["word_count"].as_u64().unwrap() >= 4);
}

#[test]
fn xlsx_resolves_shared_and_inline_strings() {
    let shared = r#"<?xml version="1.0"?><sst count="2" uniqueCount="2"><si><t>Ledger</t></si><si><t>Amount</t></si></sst>"#;
    let sheet = r#"<?xml version="1.0"?><worksheet><sheetData>
<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>
<row r="2"><c r="A2"><v>42</v></c><c r="B2" t="inlineStr"><is><t>wire transfer</t></is></c></row>
</sheetData></worksheet>"#;
    let bytes = zip_of(&[
        ("xl/sharedStrings.xml", shared),
        ("xl/worksheets/sheet1.xml", sheet),
    ]);
    let arts = run("book.xlsx", bytes);
    assert_eq!(arts.len(), 1);
    let text = text_of(&arts[0]);
    assert_eq!(arts[0].metadata["format"], "Excel");
    for needle in ["Ledger", "Amount", "42", "wire transfer"] {
        assert!(text.contains(needle), "missing {needle:?} in {text:?}");
    }
    // Cells tab-joined, rows newline-separated.
    assert!(text.contains("Ledger\tAmount"), "got: {text:?}");
}

#[test]
fn pptx_reads_every_slide_in_order() {
    let slide = |body: &str| {
        format!(
            r#"<?xml version="1.0"?><p:sld xmlns:p="p" xmlns:a="a"><p:cSld><p:spTree>
<p:sp><p:txBody><a:p><a:r><a:t>{body}</a:t></a:r></a:p></p:txBody></p:sp>
</p:spTree></p:cSld></p:sld>"#
        )
    };
    let s1 = slide("Attack timeline");
    let s2 = slide("Second slide payload");
    let bytes = zip_of(&[
        ("ppt/slides/slide1.xml", &s1),
        ("ppt/slides/slide2.xml", &s2),
    ]);
    let arts = run("deck.pptx", bytes);
    let text = text_of(&arts[0]);
    assert_eq!(arts[0].metadata["format"], "PowerPoint");
    assert!(text.contains("Attack timeline"), "got: {text:?}");
    assert!(text.contains("Second slide payload"), "got: {text:?}");
    assert!(
        text.find("Attack timeline").unwrap() < text.find("Second slide payload").unwrap(),
        "slides out of order: {text:?}"
    );
}

#[test]
fn odt_extracts_body_text() {
    let content = r#"<?xml version="1.0"?>
<office:document-content xmlns:office="urn:o" xmlns:text="urn:t">
<office:automatic-styles><style:style xmlns:style="urn:s"><style:text-properties/></style:style></office:automatic-styles>
<office:body><office:text>
<text:p>OpenDocument body text</text:p>
<text:p>ransom note draft</text:p>
</office:text></office:body>
</office:document-content>"#;
    let meta = r#"<?xml version="1.0"?><office:document-meta xmlns:office="urn:o" xmlns:dc="urn:dc"><office:meta><dc:title>Note</dc:title><dc:creator>Suspect</dc:creator></office:meta></office:document-meta>"#;
    let bytes = zip_of(&[
        ("mimetype", "application/vnd.oasis.opendocument.text"),
        ("content.xml", content),
        ("meta.xml", meta),
    ]);
    let arts = run("note.odt", bytes);
    assert_eq!(arts.len(), 1);
    let rec = &arts[0];
    assert_eq!(rec.metadata["container"], "OpenDocument");
    let text = text_of(rec);
    assert!(text.contains("OpenDocument body text"), "got: {text:?}");
    assert!(text.contains("ransom note draft"), "got: {text:?}");
    assert_eq!(rec.metadata["author"], "Suspect");
}

#[test]
fn detects_extensionless_container_by_content() {
    // No filename extension: must be identified from [Content_Types].xml.
    let arts = run("", docx_bytes());
    assert_eq!(arts.len(), 1);
    assert_eq!(arts[0].metadata["format"], "Word");
}

#[test]
fn plain_zip_is_not_an_office_document() {
    // A .zip extension is skipped outright (never mistaken for a document)...
    let z = zip_of(&[("readme.txt", "just a zip")]);
    assert!(run("bundle.zip", z.clone()).is_empty());
    // ...and even extension-less, an archive with no office parts is ignored.
    assert!(run("", z).is_empty());
}

#[test]
fn non_office_and_corrupt_inputs_yield_nothing() {
    // Right extension, but the bytes aren't a ZIP at all.
    assert!(run("fake.docx", b"not a zip file".to_vec()).is_empty());
    // A plain text file is skipped without reading.
    assert!(run("notes.txt", b"hello".to_vec()).is_empty());
}

/// B6-011: the PK magic matched, so this file claims to be a ZIP container —
/// and with a `.docx` name it claims to be a document. When the archive
/// directory will not open, returning nothing files it beside the `.txt`s: an
/// examiner sees no office record and no reason to look again. A damaged
/// exhibit and a file that is not a document must not read the same.
#[test]
fn a_zip_magic_file_that_will_not_open_reports_itself_as_unreadable() {
    let out = run("x.docx", b"PK\x03\x04garbage".to_vec());
    assert_eq!(out.len(), 1, "a corrupt .docx must not vanish");
    let md = &out[0].metadata;
    assert_eq!(md["status"], "container_unreadable");
    assert_eq!(md["content_incomplete"], json!(true));
    assert_eq!(md["inventory_incomplete"], json!(true));
    assert_eq!(md["file_name"], "x.docx");
    assert_eq!(md["format"], "Word");
    assert!(md.get("open_error").is_some());
    assert_eq!(text_of(&out[0]), "");
}

#[test]
fn read_entry_rejects_oversized_member_and_records_the_skip() {
    // A member whose decompressed size exceeds the cap must be skipped entirely
    // (returns None), never returned as truncated content — and the skip has to
    // be recorded, or the caller's `.unwrap_or_default()` turns it into an empty
    // part with nothing to say a part was lost (B2-164).
    let bytes = zip_of(&[("big.xml", "0123456789abcdef")]); // 16 bytes decompressed
    let mut archive = ZipArchive::new(Cursor::new(bytes.as_slice())).unwrap();

    let mut skipped = SkippedParts::default();
    assert!(read_entry_capped(&mut archive, "big.xml", 8, &mut skipped).is_none());
    assert_eq!(skipped.parts.len(), 1);
    assert_eq!(skipped.parts[0].0, "big.xml");
    assert_eq!(skipped.parts[0].1, IncompleteReason::CapReached);

    // Cap above the member size: read in full, nothing recorded.
    let mut ok = SkippedParts::default();
    assert_eq!(
        read_entry_capped(&mut archive, "big.xml", 1024, &mut ok).as_deref(),
        Some("0123456789abcdef")
    );
    assert!(!ok.has_issues());

    // A part that simply is not in the archive is not a loss and is not
    // recorded; otherwise every optional part would raise a false alarm.
    let mut absent = SkippedParts::default();
    assert!(read_entry_capped(&mut archive, "no/such.xml", 1024, &mut absent).is_none());
    assert!(!absent.has_issues());
}

#[test]
fn module_metadata() {
    let p = OfficeParser;
    assert_eq!(p.id(), "plugin.documents.office");
    assert!(p.subscribes_to().contains(&ArtifactType::FileEntry));
}

// --- Partial archive honesty (B2-049) ----------------------------------------

use seance_core::test_support::TruncatedSource;

/// A document read in full must not claim its archive was cut short.
#[test]
fn a_fully_read_document_is_not_marked_incomplete() {
    let out = run("report.docx", docx_bytes());
    assert_eq!(out.len(), 1);
    assert!(out[0].metadata.get("content_incomplete").is_none());
}

/// A document whose archive was only partly read still yields text and
/// properties; without the flag that partial parse reads as the whole document.
#[test]
fn a_partially_read_document_is_marked_incomplete() {
    let bytes = docx_bytes();
    let declared = bytes.len() as u64 + 8192;
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(bytes, declared));
    let a = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "report.docx" }),
    );
    let out = OfficeParser.process(&a).unwrap();
    assert_eq!(out.len(), 1);
    let md = &out[0].metadata;
    assert_eq!(md["content_incomplete"], json!(true));
    assert_eq!(md["content_incomplete_reason"], "short_read");
    assert_eq!(md["declared_size"], json!(declared));
}

// --- B2-164: a part that could not be read is not an empty part --------------
//
// `read_entry` returned `None` for an over-cap or unreadable ZIP member and
// every caller wrote `.unwrap_or_default()`. A `.docx` whose `word/document.xml`
// would not inflate therefore produced an `OfficeDocument` with empty text,
// zero word count, and no field anywhere saying a part had been skipped — the
// archive-level `content_incomplete` only ever covered the OUTER read. An
// examiner searching this document's text for a term would find nothing and
// have no reason to doubt it.

/// Build a ZIP whose members are STORED (uncompressed), so a single flipped
/// content byte reproduces the CRC failure a damaged part raises on read.
fn stored_zip_of(parts: &[(&str, &str)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in parts {
        w.start_file(*name, opts).unwrap();
        w.write_all(data.as_bytes()).unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// Flip one byte of `needle` where it appears verbatim in `bytes`.
fn corrupt_first(bytes: &mut [u8], needle: &[u8]) {
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("needle must appear in the stored archive");
    bytes[at] ^= 0xff;
}

#[test]
fn a_part_that_will_not_read_is_reported_not_silently_blank() {
    let document =
        "<w:document><w:body><w:p><w:r><w:t>SECRET PAYLOAD</w:t></w:r></w:p></w:body></w:document>";
    let core = r#"<?xml version="1.0"?><cp:coreProperties xmlns:cp="x" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Damaged</dc:title></cp:coreProperties>"#;
    let mut bytes = stored_zip_of(&[
        ("[Content_Types].xml", CONTENT_TYPES_WORD),
        ("word/document.xml", document),
        ("docProps/core.xml", core),
    ]);
    // Break the body so its stored CRC no longer matches: the member exists and
    // is declared, but cannot be read.
    corrupt_first(&mut bytes, b"SECRET PAYLOAD");

    let arts = run("damaged.docx", bytes);
    assert_eq!(arts.len(), 1);
    let rec = &arts[0];

    assert_eq!(
        text_of(rec),
        "",
        "no text can be claimed from a part that would not read"
    );
    assert_eq!(rec.metadata["content_incomplete"], true);
    assert_eq!(rec.metadata["parts_incomplete"], true);
    assert_eq!(
        rec.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    let skipped = rec.metadata["skipped_parts"].as_array().unwrap();
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0]["part"], "word/document.xml");
    assert_eq!(skipped[0]["reason"], "unresolved_structure");
    // The parts that DID read are still reported.
    assert_eq!(rec.metadata["title"], "Damaged");
}

#[test]
fn a_document_whose_parts_all_read_is_not_flagged() {
    // The counterweight: if a clean parse carried `parts_incomplete`, the flag
    // on the damaged ones would mean nothing.
    let arts = run("plan.docx", docx_bytes());
    let rec = &arts[0];
    assert!(rec.metadata.get("parts_incomplete").is_none());
    assert!(rec.metadata.get("skipped_parts").is_none());
    assert!(rec.metadata.get("content_incomplete").is_none());
}

#[test]
fn an_over_cap_part_marks_the_document_cap_reached() {
    // The zip-bomb refusal path, driven through `read_entry_capped` with a small
    // cap so the 128 MiB constant does not have to be materialised. The record
    // this feeds must distinguish "part refused as too large" from "part
    // damaged", because only one of them is a deliberate parser limit.
    let bytes = zip_of(&[("word/document.xml", "0123456789abcdef")]);
    let mut archive = ZipArchive::new(Cursor::new(bytes.as_slice())).unwrap();
    let mut skipped = SkippedParts::default();
    assert!(read_entry_capped(&mut archive, "word/document.xml", 4, &mut skipped).is_none());

    let read = ContentRead {
        incomplete: false,
        bytes_read: bytes.len() as u64,
        declared_size: bytes.len() as u64,
        skipped_parts: skipped,
    };
    let rec = build_record(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "bomb.docx",
        Format::Word,
        false,
        String::new(),
        Map::new(),
        read,
    );
    assert_eq!(rec.metadata["content_incomplete"], true);
    assert_eq!(rec.metadata["parts_incomplete"], true);
    assert_eq!(rec.metadata["content_incomplete_reason"], "cap_reached");
    assert_eq!(rec.metadata["max_entry_bytes"], MAX_ENTRY_BYTES);
    assert_eq!(
        rec.metadata["skipped_parts"][0]["part"],
        "word/document.xml"
    );
}

// --- B6-012: the stored-text cap is a shortfall, and must say so -------------

/// `text_truncated` is a key this crate invented and nothing reads. A document
/// whose body was clipped at the storage cap reached the artifact viewer, the
/// search index and the completeness census looking whole.
#[test]
fn text_clipped_at_the_storage_cap_carries_the_standard_pair() {
    let read = ContentRead {
        incomplete: false,
        bytes_read: 10,
        declared_size: 10,
        skipped_parts: SkippedParts::default(),
    };
    let long = "x".repeat(MAX_TEXT_BYTES + 4096);
    let rec = build_record(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "long.docx",
        Format::Word,
        false,
        long,
        Map::new(),
        read,
    );
    assert_eq!(rec.metadata["text_truncated"], true);
    assert_eq!(rec.metadata["content_incomplete"], json!(true));
    assert_eq!(rec.metadata["content_incomplete_reason"], "cap_reached");
    assert_eq!(rec.metadata["max_text_bytes"], json!(MAX_TEXT_BYTES));
    assert!(text_of(&rec).len() <= MAX_TEXT_BYTES);
}

/// The counterweight: a document under the cap must not be flagged.
#[test]
fn text_under_the_cap_is_not_flagged() {
    let read = ContentRead {
        incomplete: false,
        bytes_read: 10,
        declared_size: 10,
        skipped_parts: SkippedParts::default(),
    };
    let rec = build_record(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "short.docx",
        Format::Word,
        false,
        "hello".into(),
        Map::new(),
        read,
    );
    assert_eq!(rec.metadata["text_truncated"], false);
    assert!(rec.metadata.get("content_incomplete").is_none());
}

// --- B6-013: an XML walk that stops on a parse error yields a prefix ---------

/// A `document.xml` that inflates cleanly but is cut off mid-element stops the
/// quick-xml walk. The text gathered so far is a prefix; unflagged it reads as
/// the whole document, and a search over it comes back empty with nothing to
/// say the parse ended early.
#[test]
fn a_document_whose_xml_ends_mid_element_is_reported_as_truncated() {
    // Well-formed prefix, then EOF in the middle of a start tag: quick-xml
    // raises a syntax error rather than reaching `Eof`.
    let document = "<w:document><w:body><w:p><w:r><w:t>FIRST PART</w:t></w:r></w:p>\
                    <w:p><w:r><w:t";
    let bytes = zip_of(&[
        ("[Content_Types].xml", CONTENT_TYPES_WORD),
        ("word/document.xml", document),
    ]);

    let arts = run("cut.docx", bytes);
    assert_eq!(arts.len(), 1);
    let md = &arts[0].metadata;
    assert!(
        text_of(&arts[0]).contains("FIRST PART"),
        "what was recovered is still published"
    );
    assert_eq!(md["content_incomplete"], json!(true));
    assert_eq!(md["parts_incomplete"], json!(true));
    let truncated = md["xml_truncated_parts"].as_array().unwrap();
    assert_eq!(truncated.len(), 1);
    assert_eq!(truncated[0]["part"], "word/document.xml");
}

/// The counterweight for B6-013: a well-formed document must not be flagged.
#[test]
fn a_well_formed_document_has_no_xml_truncation_flag() {
    let arts = run("clean.docx", docx_bytes());
    assert!(arts[0].metadata.get("xml_truncated_parts").is_none());
    assert!(arts[0].metadata.get("parts_incomplete").is_none());
}

/// RUSTSEC-2026-0194 regression at the plugin boundary.
///
/// A `.xlsx` is an everyday email attachment, and the worksheet part is the one
/// place this parser reads attributes — so it is the one place a crafted
/// document can reach quick-xml's quadratic duplicate-name check.
#[test]
fn a_worksheet_with_a_hostile_attribute_count_parses_in_bounded_time() {
    let mut sheet = String::from("<worksheet><sheetData><row><c");
    for i in 0..200_000 {
        sheet.push_str(&format!(" a{i}=\"v\""));
    }
    sheet.push_str("><v>1</v></c></row></sheetData></worksheet>");

    let start = std::time::Instant::now();
    let walk = extract_worksheet(&sheet, &[]);
    let elapsed = start.elapsed();

    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "parsing took {elapsed:?}; unguarded this worksheet costs ~29 s, so the \
         bounded reader is not in this path"
    );
    assert!(walk.stopped.is_none(), "the sheet is well-formed");
    assert!(
        !walk.anomalies.is_empty(),
        "a worksheet whose attributes were refused must carry an anomaly for \
         `take` to record against the part"
    );
}

/// An ordinary worksheet reads normally and reports nothing.
#[test]
fn an_ordinary_worksheet_reports_no_anomaly() {
    let sheet = r#"<worksheet><sheetData><row><c t="s"><v>0</v></c></row></sheetData></worksheet>"#;
    let walk = extract_worksheet(sheet, &["hello".to_string()]);
    assert!(walk.value.contains("hello"), "shared string resolves");
    assert!(walk.anomalies.is_empty(), "clean input reports nothing");
}

/// Slides and sheets come out in the order they were presented in.
///
/// `names.sort()` put `slide10.xml` before `slide2.xml`, so a deck of ten or
/// more slides was extracted as 1, 10, 11, …, 2, 20 — text in an order nobody
/// presented it in.
#[test]
fn slides_and_sheets_are_ordered_naturally_not_lexicographically() {
    let mut names = vec![
        "ppt/slides/slide10.xml".to_string(),
        "ppt/slides/slide2.xml".to_string(),
        "ppt/slides/slide1.xml".to_string(),
        "ppt/slides/slide20.xml".to_string(),
        "ppt/slides/slide3.xml".to_string(),
    ];
    names.sort_by_key(|n| natural_key(n));
    assert_eq!(
        names,
        vec![
            "ppt/slides/slide1.xml",
            "ppt/slides/slide2.xml",
            "ppt/slides/slide3.xml",
            "ppt/slides/slide10.xml",
            "ppt/slides/slide20.xml",
        ]
    );
    // A name with no number keeps its place by text rather than panicking or
    // sorting to the front by accident.
    assert_eq!(natural_key("xl/worksheets/sheet.xml").1, 0);
    assert!(natural_key("xl/worksheets/sheet9.xml") < natural_key("xl/worksheets/sheet10.xml"));
}
