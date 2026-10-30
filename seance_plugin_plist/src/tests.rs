use super::*;
use seance_core::data_source::DataSource;
use seance_core::test_support::TruncatedSource;
use std::sync::Arc;
use uuid::Uuid;

fn home(rel: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
}

/// Mock data source for testing
#[derive(Debug)]
struct MockDataSource {
    data: Vec<u8>,
}

impl MockDataSource {
    fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl DataSource for MockDataSource {
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<usize> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return Ok(0);
        }

        let to_read = std::cmp::min(buffer.len(), self.data.len() - offset);
        buffer[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

#[test]
fn test_plist_parser_module_metadata() {
    let parser = PlistParser;

    assert_eq!(parser.id(), "plugin.macos.plist_parser");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));

    let subscriptions = parser.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileEntry));
    assert!(subscriptions.contains(&ArtifactType::SystemArtifact));

    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_plist_parser_skips_no_data_source() {
    let parser = PlistParser;
    let case_id = Uuid::new_v4();

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None, // No data source
        json!({"name": "test.plist"}),
    );

    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_plist_parser_skips_non_plist_file() {
    let parser = PlistParser;
    let case_id = Uuid::new_v4();

    // Random data that isn't a plist
    let data = vec![0u8; 100];
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "random.bin"}),
    );

    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_plist_parser_detects_binary_plist() {
    let parser = PlistParser;

    // Binary plist signature
    let data = b"bplist00";
    assert!(parser.is_plist(data));
}

#[test]
fn test_plist_parser_detects_xml_plist() {
    let parser = PlistParser;

    // XML plist
    let xml_plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>TestKey</key>
    <string>TestValue</string>
</dict>
</plist>"#;

    assert!(parser.is_plist(xml_plist.as_bytes()));
}

#[test]
fn test_plist_parser_detects_plist_without_xml_declaration() {
    let parser = PlistParser;

    // Plist without XML declaration
    let plist = r#"<plist version="1.0">
<dict>
    <key>Key</key>
    <string>Value</string>
</dict>
</plist>"#;

    assert!(parser.is_plist(plist.as_bytes()));
}

#[test]
fn test_plist_parser_rejects_short_data() {
    let parser = PlistParser;

    // Too short to be a plist
    let data = b"short";
    assert!(!parser.is_plist(data));
}

#[test]
fn test_plist_parser_parses_xml_plist() {
    let parser = PlistParser;
    let case_id = Uuid::new_v4();

    let xml_plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>TestKey</key>
    <string>TestValue</string>
    <key>Number</key>
    <integer>42</integer>
</dict>
</plist>"#;

    let data_source: Arc<dyn DataSource> =
        Arc::new(MockDataSource::new(xml_plist.as_bytes().to_vec()));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "test.plist"}),
    );

    let result = parser.process(&artifact);
    assert!(result.is_ok());

    let artifacts = result.unwrap();
    assert_eq!(artifacts.len(), 1);

    let plist_artifact = &artifacts[0];
    assert_eq!(plist_artifact.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(plist_artifact.metadata["type"], "PlistFile");
    assert!(plist_artifact.metadata.get("content").is_some());
}

#[test]
fn test_plist_parser_handles_invalid_plist_data() {
    let parser = PlistParser;
    let case_id = Uuid::new_v4();

    // Invalid plist content (looks like plist header but content is garbage)
    let mut data = b"bplist00".to_vec();
    data.extend_from_slice(&[0xFF; 100]); // Garbage data

    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "invalid.plist"}),
    );

    // A file whose magic says "binary plist" and which will not parse is a
    // corrupt plist, not a file that was never one. Returning nothing made the
    // two indistinguishable (B5-020).
    let out = parser.process(&artifact).expect("processing succeeds");
    assert_eq!(out.len(), 1, "{out:?}");
    let md = &out[0].metadata;
    assert_eq!(md["type"], "PlistParseStatus");
    assert_eq!(md["status"], "ParseFailed");
    assert_eq!(md["content_incomplete"], serde_json::json!(true));
    assert_eq!(md["content_incomplete_reason"], "unresolved_structure");
    assert_eq!(md["file_name"], "invalid.plist");
    assert!(md["error"].is_string(), "the parser's reason travels: {md}");
}

#[test]
fn test_plist_parser_empty_data() {
    let parser = PlistParser;
    let case_id = Uuid::new_v4();

    let data = Vec::new();
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "empty.plist"}),
    );

    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_plist_value_to_json_boolean() {
    let value = plist::Value::Boolean(true);
    let json = plist_value_to_json(&value);
    assert_eq!(json, serde_json::json!(true));
}

#[test]
fn test_plist_value_to_json_integer() {
    let value = plist::Value::Integer(42.into());
    let json = plist_value_to_json(&value);
    assert_eq!(json, serde_json::json!(42));
}

#[test]
fn test_plist_value_to_json_date_is_rfc3339() {
    use std::time::{Duration, UNIX_EPOCH};
    // 2001-09-09T01:46:40Z is exactly 1_000_000_000 seconds after the Unix epoch.
    let st = UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    let value = plist::Value::Date(plist::Date::from(st));
    let json = plist_value_to_json(&value);
    // A plain RFC3339 string (the plist XML date form), not a Rust-Debug wrapper.
    assert_eq!(json, serde_json::json!("2001-09-09T01:46:40Z"));
    let s = json.as_str().expect("date serialized as a JSON string");
    assert!(s.ends_with('Z') && s.contains('T'), "not RFC3339: {s}");
}

#[test]
fn test_plist_value_to_json_large_unsigned_integer() {
    // A value larger than i64::MAX must not collapse to JSON null.
    let value = plist::Value::Integer(plist::Integer::from(u64::MAX));
    let json = plist_value_to_json(&value);
    assert!(
        !json.is_null(),
        "large unsigned integer must not become null"
    );
    assert_eq!(json.as_u64(), Some(u64::MAX));
}

#[test]
fn test_plist_parser_short_read_fails_closed() {
    // A data source that claims more bytes than it can actually deliver, with a
    // valid binary-plist header, must NOT be parsed as a zero-padded success.
    let parser = PlistParser;
    let ds: Arc<dyn DataSource> =
        Arc::new(TruncatedSource::new(b"bplist00truncated".to_vec(), 4096));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "truncated.plist" }),
    );
    let result = parser.process(&artifact).unwrap();
    // Fail closed: not one value may be published off a zero-padded tail.
    assert!(
        result
            .iter()
            .all(|a| a.metadata["type"] == "PlistParseStatus"),
        "no parsed plist record may come out of a short read: {result:?}"
    );
    // And the refusal is stated, not silent: a plist we would not parse must
    // not look like a file that simply held nothing (B5-020).
    assert_eq!(result.len(), 1, "{result:?}");
    let md = &result[0].metadata;
    assert_eq!(md["status"], json!("ShortRead"));
    assert!(md.get("content").is_none(), "no values were published");
    assert_eq!(md["content_incomplete"], json!(true));
    assert_eq!(md["content_incomplete_reason"], json!("short_read"));
    assert_eq!(md["declared_size"], json!(4096));
}

#[test]
fn test_plist_value_to_json_string() {
    let value = plist::Value::String("hello".to_string());
    let json = plist_value_to_json(&value);
    assert_eq!(json, serde_json::json!("hello"));
}

#[test]
fn test_plist_value_to_json_real() {
    let value = plist::Value::Real(2.5);
    let json = plist_value_to_json(&value);
    assert_eq!(json, serde_json::json!(2.5));
}

#[test]
fn test_plist_value_to_json_array() {
    let value = plist::Value::Array(vec![
        plist::Value::String("a".to_string()),
        plist::Value::Integer(1.into()),
    ]);
    let json = plist_value_to_json(&value);
    assert_eq!(json, serde_json::json!(["a", 1]));
}

#[test]
fn test_extract_plist_metadata_bundle_info() {
    let parser = PlistParser;
    let content = json!({
        "CFBundleIdentifier": "com.example.app",
        "CFBundleName": "Example App"
    });
    let metadata = parser.extract_plist_metadata(&content, "Info.plist");
    assert_eq!(metadata["plist_type"], "Bundle Info");
}

#[test]
fn test_extract_plist_metadata_generic() {
    let parser = PlistParser;
    let content = json!({
        "SomeKey": "SomeValue"
    });
    let metadata = parser.extract_plist_metadata(&content, "test.plist");
    assert_eq!(metadata["plist_type"], "Generic");
}

// Integration test with real plist file
#[test]
fn test_parse_real_plist_file() {
    use std::fs;
    use std::path::Path;

    let test_file = Path::new("../test_data/sample.plist");
    if !test_file.exists() {
        eprintln!("Skipping integration test: sample.plist not found");
        return;
    }

    let parser = PlistParser;
    let case_id = Uuid::new_v4();

    let data = fs::read(test_file).expect("Failed to read sample.plist");
    let data_source: Arc<dyn DataSource> = Arc::new(MockDataSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "sample.plist"}),
    );

    let result = parser.process(&artifact);
    assert!(
        result.is_ok(),
        "Failed to parse sample.plist: {:?}",
        result.err()
    );

    let artifacts = result.unwrap();
    assert!(
        !artifacts.is_empty(),
        "No artifacts produced from sample.plist"
    );
}

// --- Skipped plists must still be visible (B2-112) ---------------------------

fn oversize_artifact(declared: u64, name: &str) -> Artifact {
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(b"bplist00".to_vec(), declared));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": name }),
    )
}

/// A plist too large to load must leave a record saying so, not vanish.
#[test]
fn an_oversize_plist_leaves_a_record_saying_it_was_not_parsed() {
    let art = oversize_artifact(MAX_PLIST_BYTES + 1, "huge.plist");
    let out = PlistParser.process(&art).unwrap();
    assert_eq!(out.len(), 1);
    let md = &out[0].metadata;
    assert_eq!(md["type"], "PlistParseStatus");
    assert_eq!(md["status"], "OverSizeCap");
    assert_eq!(md["content_incomplete"], serde_json::json!(true));
    assert_eq!(md["content_incomplete_reason"], "cap_reached");
    assert_eq!(md["declared_size"], serde_json::json!(MAX_PLIST_BYTES + 1));
}

/// HUNT-112. A record whose content was too large to carry kept a "preview" of
/// the first ten keys — cloned whole. A compiled `.nib` resolves to two keys,
/// so its preview was the entire content: one record in an ordinary macOS
/// folder reached **295 MB** of metadata, and a walk of that folder took the
/// server to 28 GB resident and out of memory.
#[test]
fn the_preview_of_an_oversize_plist_is_a_preview() {
    // Two top-level keys, each far larger than any record should carry — the
    // shape of a resolved keyed archive.
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n",
    );
    for key in ["first", "second"] {
        xml.push_str(&format!("<key>{key}</key><array>\n"));
        for i in 0..20_000 {
            xml.push_str(&format!("<string>value {i} {}</string>\n", "x".repeat(40)));
        }
        xml.push_str("</array>\n");
    }
    xml.push_str("</dict>\n</plist>\n");

    let ds: Arc<dyn DataSource> = Arc::new(MockDataSource::new(xml.into_bytes()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "huge.plist"}),
    );
    let out = PlistParser.process(&artifact).expect("processing succeeds");
    let record = out
        .iter()
        .find(|a| a.metadata.get("content_note").is_some())
        .expect("the oversize-content path ran");
    let rendered = serde_json::to_string(&record.metadata).expect("serialisable");
    assert!(
        rendered.len() < 256 * 1024,
        "a record that could not carry its content must not carry it under \
         another name; this one was {} bytes",
        rendered.len()
    );
    // Still a preview: the keys are named, so an examiner knows what is in the
    // file even where the values were left out.
    let preview = record.metadata["content_preview"]
        .as_object()
        .expect("a preview object");
    assert!(preview.contains_key("first"));
    assert_eq!(record.metadata["content_incomplete"], json!(true));
}

/// Refusing to parse a truncated plist must be visible too: "we would not read
/// this" and "this file was empty" must never look the same.
#[test]
fn a_short_read_plist_leaves_a_record_saying_it_was_not_parsed() {
    let art = oversize_artifact(4096, "cut.plist");
    let out = PlistParser.process(&art).unwrap();
    assert_eq!(out.len(), 1);
    let md = &out[0].metadata;
    assert_eq!(md["status"], "ShortRead");
    assert_eq!(md["content_incomplete_reason"], "short_read");
}

/// A plist whose parsed content is too large to store must carry the standard
/// incompleteness pair, not only the prose note.
///
/// What an examiner learns: whether a keyword absent from this record is absent
/// from the file. `content_note` is prose; search, export and the court
/// completeness census read `content_incomplete`, so without the pair a record
/// holding ten of a thousand keys presents as a fully parsed plist (B5-036).
#[test]
fn a_plist_too_large_to_store_carries_the_standard_incompleteness_pair() {
    // An XML plist with enough distinct keys to blow past the 100 KB JSON cap.
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n",
    );
    for i in 0..4000 {
        xml.push_str(&format!(
            "<key>key_{i}</key><string>{}</string>\n",
            "v".repeat(40)
        ));
    }
    xml.push_str("</dict>\n</plist>\n");

    let ds: Arc<dyn DataSource> = Arc::new(MockDataSource::new(xml.into_bytes()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "big.plist"}),
    );

    let out = PlistParser.process(&artifact).expect("processing succeeds");
    let record = out
        .iter()
        .find(|a| a.metadata.get("content_note").is_some())
        .expect("the oversize-content path ran");
    // The size is reported as a floor, not a figure: the serialiser stops at
    // the cap rather than measuring a value it is going to discard.
    assert!(record.metadata["content_size_at_least"].is_number());
    assert_eq!(record.metadata["content_incomplete"], json!(true));
    assert_eq!(record.metadata["content_incomplete_reason"], "cap_reached");
}

/// **An NSKeyedArchiver plist is resolved end to end, from real bytes.**
///
/// The unit tests build a `Dictionary` directly. This serialises a genuine
/// binary plist and drives it through `parse_plist_data`, because a resolver
/// that is never reached is worth nothing — a lesson this codebase has already
/// paid for once.
#[test]
fn a_real_binary_keyed_archive_is_resolved_when_parsed() {
    use plist::{Dictionary, Uid, Value};

    let mut entry = Dictionary::new();
    entry.insert("account".into(), Value::Uid(Uid::new(2)));
    entry.insert("url".into(), Value::Uid(Uid::new(3)));

    let mut top = Dictionary::new();
    top.insert("root".into(), Value::Uid(Uid::new(1)));

    let mut archive = Dictionary::new();
    archive.insert("$archiver".into(), Value::String("NSKeyedArchiver".into()));
    archive.insert("$version".into(), Value::Integer(100_000.into()));
    archive.insert("$top".into(), Value::Dictionary(top));
    archive.insert(
        "$objects".into(),
        Value::Array(vec![
            Value::String("$null".into()),
            Value::Dictionary(entry),
            Value::String("alice@example.com".into()),
            Value::String("https://example.com/report.pdf".into()),
        ]),
    );

    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &Value::Dictionary(archive)).expect("serialises");
    assert_eq!(
        &bytes[..6],
        b"bplist",
        "the fixture must be a real binary plist"
    );

    let parsed = PlistParser
        .parse_plist_data(&bytes)
        .expect("a well-formed archive parses");

    let root = &parsed["keyed_archive"]["root"]["root"];
    assert_eq!(
        root["account"],
        serde_json::json!("alice@example.com"),
        "the archive was not resolved: {parsed}"
    );
    assert_eq!(
        root["url"],
        serde_json::json!("https://example.com/report.pdf")
    );

    // And the literal form is kept, because resolution is this module's reading
    // of the file rather than the file itself.
    assert!(
        parsed["raw"]["$objects"].is_array(),
        "the unresolved form must remain available for an examiner to check"
    );
}

/// An ordinary preferences plist must be left exactly as it was. Resolution
/// applies to archives; restructuring anything else would rearrange a file that
/// was already in the form its author intended.
#[test]
fn an_ordinary_plist_is_not_restructured() {
    use plist::{Dictionary, Value};

    let mut prefs = Dictionary::new();
    prefs.insert("LastUser".into(), Value::String("alice".into()));
    prefs.insert("AutoLogin".into(), Value::Boolean(false));

    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &Value::Dictionary(prefs)).expect("serialises");

    let parsed = PlistParser.parse_plist_data(&bytes).expect("parses");
    assert_eq!(parsed["LastUser"], serde_json::json!("alice"));
    assert!(
        parsed.get("keyed_archive").is_none(),
        "a plist that is not an archive must not be wrapped as one"
    );
}

/// **A plist inside a Data field is opened, not reduced to hex.**
///
/// macOS and iOS routinely store one plist inside another — an NSKeyedArchiver
/// archive as the value of a preference key is the ordinary case. Rendered as
/// the first thirty-two bytes of hex, everything it holds is lost: the account,
/// the recent document, the bookmark. The bytes were there and were discarded
/// at the point of display.
#[test]
fn a_plist_nested_inside_a_data_field_is_opened() {
    use plist::{Dictionary, Value};

    let mut inner = Dictionary::new();
    inner.insert(
        "RecentDocument".into(),
        Value::String("/Users/alice/case.docx".into()),
    );
    inner.insert("Count".into(), Value::Integer(7.into()));
    let mut inner_bytes = Vec::new();
    plist::to_writer_binary(&mut inner_bytes, &Value::Dictionary(inner)).expect("serialises");
    assert!(
        inner_bytes.len() > 32,
        "the fixture must be longer than the hex preview, or it proves nothing"
    );

    let mut outer = Dictionary::new();
    outer.insert("Preference".into(), Value::Data(inner_bytes));
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &Value::Dictionary(outer)).expect("serialises");

    let parsed = PlistParser.parse_plist_data(&bytes).expect("parses");
    let nested = &parsed["Preference"]["nested_plist"];
    assert_eq!(
        nested["RecentDocument"],
        serde_json::json!("/Users/alice/case.docx"),
        "the nested plist was not opened: {parsed}"
    );
    assert_eq!(nested["Count"], serde_json::json!(7));
}

/// A blob that is not a plist keeps its honest description: the length, which
/// is often the only thing that can truthfully be said about it.
#[test]
fn an_opaque_blob_is_described_rather_than_guessed_at() {
    use plist::{Dictionary, Value};

    let mut outer = Dictionary::new();
    outer.insert("Thumbnail".into(), Value::Data(vec![0xFFu8; 500]));
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &Value::Dictionary(outer)).expect("serialises");

    let parsed = PlistParser.parse_plist_data(&bytes).expect("parses");
    let described = parsed["Thumbnail"].as_str().expect("a description");
    assert!(
        described.contains("500 bytes"),
        "the length must be stated: {described}"
    );
}

/// Something claiming to be a plist that will not parse is a fact about the
/// file. Presenting it as an ordinary opaque blob would hide that.
#[test]
fn a_data_field_that_claims_to_be_a_plist_and_is_not_says_so() {
    use plist::{Dictionary, Value};

    let mut broken = b"bplist00".to_vec();
    broken.extend_from_slice(&[0xAB; 64]);

    let mut outer = Dictionary::new();
    outer.insert("Damaged".into(), Value::Data(broken));
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &Value::Dictionary(outer)).expect("serialises");

    let parsed = PlistParser.parse_plist_data(&bytes).expect("parses");
    let note = parsed["Damaged"]["note"].as_str().unwrap_or_default();
    assert!(
        note.contains("did not parse"),
        "a damaged nested plist must be reported as damaged, not as a blob: {parsed}"
    );
    assert_eq!(parsed["Damaged"]["byte_length"], serde_json::json!(72));
}

// ---------------------------------------------------------------------------
// Embedded data blobs
// ---------------------------------------------------------------------------

/// Build an XML plist holding one data value of `len` bytes under `key`.
fn plist_with_blob(key: &str, bytes: &[u8]) -> Vec<u8> {
    // A binary plist, which is what macOS writes and what the parser meets.
    let mut dict = plist::Dictionary::new();
    dict.insert("FullName".into(), plist::Value::String("Eli Flatt".into()));
    dict.insert(key.into(), plist::Value::Data(bytes.to_vec()));
    let mut buf = Vec::new();
    plist::to_writer_binary(&mut buf, &plist::Value::Dictionary(dict)).unwrap();
    return buf;
    #[allow(unreachable_code)]
    {
        let b64 = String::new();
        let _ = (b64, key);
        Vec::new()
    }
}

fn run(parser: &PlistParser, name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(MockDataSource::new(bytes));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": name }),
    );
    parser.process(&artifact).expect("processing succeeds")
}

/// HUNT-104. The Magnet 2021 macOS CTF asks for the SHA-1 of the user's profile
/// picture, which lives as a `PictureData` blob inside `CryptoUserInfo.plist`.
/// Séance described it — `<data 789838 bytes: 4d4d002a…>` — and there it
/// stopped: the bytes could not be hashed, previewed, identified or exported,
/// so a question answered by the file's own content could not be answered from
/// the evidence holding it.
#[test]
fn a_data_blob_becomes_an_artifact_with_its_bytes() {
    // TIFF magic, as the CTF's own picture has.
    let mut blob = b"MM\x00\x2a".to_vec();
    blob.extend(std::iter::repeat_n(0xAB, 4096));
    let out = run(
        &PlistParser,
        "CryptoUserInfo.plist",
        plist_with_blob("PictureData", &blob),
    );

    let extracted = out
        .iter()
        .find(|a| a.metadata["type"] == "PlistDataBlob")
        .expect("the blob is extracted as its own artifact");
    assert_eq!(extracted.metadata["key_path"], "PictureData");
    assert_eq!(extracted.metadata["size"], blob.len());
    assert_eq!(
        extracted.metadata["name"],
        "CryptoUserInfo.plist:PictureData"
    );
    // The bytes are attached, so the hasher, the signature reader and the
    // gallery all see it — which is the whole point.
    let data = extracted.data.as_ref().expect("bytes are attached");
    let mut buf = vec![0u8; blob.len()];
    data.read_at(0, &mut buf).unwrap();
    assert_eq!(buf, blob);

    // And the plist record says how many it carried out.
    let record = out
        .iter()
        .find(|a| a.metadata["type"] == "PlistFile")
        .expect("the plist record is still produced");
    assert_eq!(record.metadata["data_blobs_extracted"], 1);
}

/// A preference file is full of small blobs — a window position, a checksum, a
/// token. Making an artifact of each would bury the case in noise.
#[test]
fn a_small_blob_stays_in_the_record() {
    let out = run(
        &PlistParser,
        "com.apple.example.plist",
        plist_with_blob("WindowState", b"tiny"),
    );
    assert!(!out.iter().any(|a| a.metadata["type"] == "PlistDataBlob"));
    let record = out
        .iter()
        .find(|a| a.metadata["type"] == "PlistFile")
        .expect("the plist record is still produced");
    assert_eq!(record.metadata["data_blobs_extracted"], 0);
}

/// A nested plist is opened, not extracted: its contents are already in the
/// record, and a second copy as an opaque blob would be the same evidence twice.
#[test]
fn a_nested_plist_is_not_also_extracted_as_a_blob() {
    let inner = {
        let mut v = plist::Dictionary::new();
        v.insert("inner".into(), plist::Value::String("value".into()));
        let mut buf = Vec::new();
        plist::to_writer_binary(&mut buf, &plist::Value::Dictionary(v)).unwrap();
        buf
    };
    assert!(inner.len() > 8 && inner.starts_with(b"bplist"));
    let out = run(
        &PlistParser,
        "com.apple.nested.plist",
        plist_with_blob("Archive", &inner),
    );
    assert!(!out.iter().any(|a| a.metadata["type"] == "PlistDataBlob"));
}

// ---------------------------------------------------------------------------
// HUNT-177 / HUNT-146: keyed-archive metadata, bounds and the over-size blob
// ---------------------------------------------------------------------------

/// A binary `NSKeyedArchiver` plist in the layout Foundation writes:
/// `$version`, `$archiver`, `$top` naming `root`, and a flat `$objects` array
/// whose index 0 is `$null`.
fn keyed_archive_bytes(objects: Vec<plist::Value>) -> Vec<u8> {
    use plist::{Dictionary, Uid, Value};
    let mut top = Dictionary::new();
    top.insert("root".into(), Value::Uid(Uid::new(1)));
    let mut archive = Dictionary::new();
    archive.insert("$version".into(), Value::Integer(100_000.into()));
    archive.insert("$archiver".into(), Value::String("NSKeyedArchiver".into()));
    archive.insert("$top".into(), Value::Dictionary(top));
    archive.insert("$objects".into(), Value::Array(objects));
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &Value::Dictionary(archive)).expect("serialises");
    bytes
}

/// A `$class` object as the archiver writes it.
fn class_object(name: &str) -> plist::Value {
    let mut class = plist::Dictionary::new();
    class.insert("$classname".into(), plist::Value::String(name.into()));
    class.insert(
        "$classes".into(),
        plist::Value::Array(vec![
            plist::Value::String(name.into()),
            plist::Value::String("NSObject".into()),
        ]),
    );
    plist::Value::Dictionary(class)
}

/// An archive whose root object (index 1) holds `payload` (index 2) under the
/// key `payload`, with its class at index 3 — an `NSData` member when `payload`
/// is a `Data` value, which is how the archiver stores one.
fn archive_holding(payload: plist::Value, class_name: &str) -> Vec<u8> {
    use plist::{Dictionary, Uid, Value};
    let mut root = Dictionary::new();
    root.insert("payload".into(), Value::Uid(Uid::new(2)));
    root.insert("$class".into(), Value::Uid(Uid::new(3)));
    keyed_archive_bytes(vec![
        Value::String("$null".into()),
        Value::Dictionary(root),
        payload,
        class_object(class_name),
    ])
}

/// HUNT-177. Every keyed archive's record reported `key_count: 2`,
/// `sample_keys: [keyed_archive, raw]` and `plist_type: Generic` — the keys of
/// this module's own wrapper, not of the file. The shape is the real one: the
/// Magnet 2021 image's `FavoriteVolumes.sfl2` is `$top {root: UID(1)}` over an
/// `NSDictionary` of `NS.keys` / `NS.objects` with a `$class` reference.
#[test]
fn a_keyed_archive_record_is_classified_from_the_archive_not_the_wrapper() {
    use plist::{Dictionary, Uid, Value};
    let mut root = Dictionary::new();
    root.insert(
        "NS.keys".into(),
        Value::Array(vec![Value::Uid(Uid::new(2)), Value::Uid(Uid::new(3))]),
    );
    root.insert(
        "NS.objects".into(),
        Value::Array(vec![Value::Uid(Uid::new(4)), Value::Uid(Uid::new(5))]),
    );
    root.insert("$class".into(), Value::Uid(Uid::new(6)));
    let mut class = Dictionary::new();
    class.insert("$classname".into(), Value::String("NSDictionary".into()));
    class.insert(
        "$classes".into(),
        Value::Array(vec![
            Value::String("NSDictionary".into()),
            Value::String("NSObject".into()),
        ]),
    );
    let bytes = keyed_archive_bytes(vec![
        Value::String("$null".into()),
        Value::Dictionary(root),
        Value::String("items".into()),
        Value::String("properties".into()),
        Value::Array(vec![]),
        Value::Dictionary(Dictionary::new()),
        Value::Dictionary(class),
    ]);

    let out = run(
        &PlistParser,
        "com.apple.LSSharedFileList.FavoriteVolumes.sfl2",
        bytes,
    );
    let md = &out
        .iter()
        .find(|a| a.metadata["type"] == "PlistFile")
        .expect("the plist record")
        .metadata;
    assert_ne!(
        md["sample_keys"],
        json!(["keyed_archive", "raw"]),
        "the record described the parser's wrapper, not the file: {md}"
    );
    assert_eq!(md["sample_keys"], json!(["root"]), "{md}");
    assert_eq!(md["key_count"], json!(1));
    assert_eq!(md["plist_type"], json!("Keyed Archive"));
    assert_eq!(md["archive_root_class"], json!("NSDictionary"));
}

/// HUNT-177 on real evidence: the Magnet 2021 macOS image's
/// `FavoriteVolumes.sfl2` (gitignored corpus; skipped where absent).
#[test]
fn the_real_sfl2_archive_is_classified_from_its_root() {
    let path = home(
        "ctf-evidence/macos2021/tree/private/var/root/Library/\
         Application Support/com.apple.sharedfilelist/\
         com.apple.LSSharedFileList.FavoriteVolumes.sfl2",
    );
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!(
            "skipping: {} not present (gitignored corpus)",
            path.display()
        );
        return;
    };
    let out = run(&PlistParser, "FavoriteVolumes.sfl2", bytes);
    let md = &out
        .iter()
        .find(|a| a.metadata["type"] == "PlistFile")
        .expect("the plist record")
        .metadata;
    assert_eq!(md["sample_keys"], json!(["root"]), "{md}");
    assert_eq!(md["plist_type"], json!("Keyed Archive"));
    assert_eq!(md["archive_root_class"], json!("NSDictionary"));
}

/// HUNT-177. The keyed-archive walker rendered an `NSData` member through
/// `plist_value_to_json`, which restarted the nesting depth at 0, so archives
/// nested inside archives were opened with no bound across levels. Twelve
/// levels deep, the innermost value must not be reached, and where the walk
/// stopped must be stated.
#[test]
fn archives_nested_inside_archives_stop_at_the_nesting_bound_and_say_so() {
    let mut bytes = archive_holding(plist::Value::String("deepest-secret".into()), "Holder");
    for _ in 0..12 {
        bytes = archive_holding(plist::Value::Data(bytes), "Holder");
    }
    let content = PlistParser.parse_plist_data(&bytes).expect("parses");
    let rendered = serde_json::to_string(&content).expect("serialisable");
    assert!(
        !rendered.contains("deepest-secret"),
        "a value twelve archives deep was opened past MAX_NESTED_PLIST_DEPTH ({MAX_NESTED_PLIST_DEPTH})"
    );
    assert!(
        rendered.contains("nesting bound"),
        "the plist left unopened at the bound must say so"
    );
}

/// HUNT-146. A nested archive inside an `NSData` member was resolved by a
/// fresh walker with a budget of its own, and the member's literal rendering
/// was charged to nothing — so an outer archive referring to the same `NSData`
/// object many times multiplied the transient tree by the reference count.
/// One budget now covers the whole file.
#[test]
fn a_nested_archive_referenced_many_times_shares_one_budget() {
    use plist::{Dictionary, Uid, Value};
    let big = "N".repeat(512 * 1024);
    let inner = archive_holding(Value::String(big), "Inner");

    // Index 2 is the NSData; the root refers to it 64 times.
    let mut root = Dictionary::new();
    root.insert(
        "NS.objects".into(),
        Value::Array((0..64).map(|_| Value::Uid(Uid::new(2))).collect()),
    );
    root.insert("$class".into(), Value::Uid(Uid::new(3)));
    let bytes = keyed_archive_bytes(vec![
        Value::String("$null".into()),
        Value::Dictionary(root),
        Value::Data(inner),
        class_object("NSArray"),
    ]);

    let content = PlistParser.parse_plist_data(&bytes).expect("parses");
    let rendered = serde_json::to_string(&content).expect("serialisable");
    assert!(
        rendered.len() < 16 * 1024 * 1024,
        "one 512 KiB nested archive referenced 64 times built {} bytes of transient tree",
        rendered.len()
    );
    assert_eq!(
        content["keyed_archive"]["truncated"],
        json!(true),
        "the walk that ran out of budget must say so"
    );
    assert_eq!(
        content["keyed_archive"]["truncation_reason"],
        json!("transient bytes")
    );
}

/// HUNT-177. A `Data` value over `MAX_EXTRACTED_BLOB` failed the `<=` test and
/// was neither carried out nor counted, so a 64 MiB file inside a plist left
/// nothing on the record saying it had been left behind.
#[test]
fn a_blob_over_the_extraction_cap_is_counted_and_disclosed() {
    let blob = vec![0x5Au8; MAX_EXTRACTED_BLOB + 1];
    let out = run(
        &PlistParser,
        "com.example.huge.plist",
        plist_with_blob("Attachment", &blob),
    );
    assert!(!out.iter().any(|a| a.metadata["type"] == "PlistDataBlob"));
    let md = &out
        .iter()
        .find(|a| a.metadata["type"] == "PlistFile")
        .expect("the plist record")
        .metadata;
    assert_eq!(
        md["inventory_incomplete"],
        json!(true),
        "an embedded value too large to carry out vanished with nothing said: {}",
        md.get("inventory_incomplete_detail")
            .unwrap_or(&json!(null))
    );
    assert_eq!(md["inventory_incomplete_reason"], json!("cap_reached"));
    assert_eq!(
        md["data_blobs_oversize"],
        json!([{ "key_path": "Attachment", "size": MAX_EXTRACTED_BLOB + 1 }])
    );
    let detail = md["inventory_incomplete_detail"].as_str().unwrap_or("");
    assert!(detail.contains("Attachment"), "{detail}");
}

/// Exactly `MAX_EXTRACTED_BLOBS` blobs followed by ordinary values is not a
/// capped walk: the flag was raised by the next value of any kind, so a plist
/// that gave up every blob it held claimed some were left behind.
#[test]
fn exactly_the_blob_limit_is_not_reported_as_capped() {
    let mut dict = plist::Dictionary::new();
    for i in 0..MAX_EXTRACTED_BLOBS {
        dict.insert(
            format!("blob{i:02}"),
            plist::Value::Data(vec![i as u8; 2048]),
        );
    }
    dict.insert("zz_after".into(), plist::Value::String("not a blob".into()));
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &plist::Value::Dictionary(dict)).unwrap();
    let out = run(&PlistParser, "sixty-four.plist", bytes);
    let md = &out
        .iter()
        .find(|a| a.metadata["type"] == "PlistFile")
        .expect("the plist record")
        .metadata;
    assert_eq!(md["data_blobs_extracted"], json!(MAX_EXTRACTED_BLOBS));
    assert!(
        md.get("data_blobs_capped").is_none(),
        "every blob was carried out, yet the record says some were not: {md}"
    );
}

/// HUNT-223. A resolution the walker stopped short — here a linked chain of
/// 100 `NSDictionary` objects, each naming the next under `NS.next`, deeper
/// than the walker's nesting bound — renders to a few kilobytes, far under the
/// 100 KB content cap. The record carried only `keyed_archive.truncated`, and
/// the completeness census, search and export, which read the standard
/// `content_incomplete` pair, saw a complete record.
#[test]
fn a_truncated_resolution_under_the_content_cap_is_stamped_incomplete() {
    use plist::{Dictionary, Uid, Value};
    const LINKS: u64 = 100;
    // Index 1 is the root; 1..=LINKS are the links; LINKS + 1 is the class.
    let class_index = LINKS + 1;
    let mut objects = vec![Value::String("$null".into())];
    for i in 1..=LINKS {
        let mut link = Dictionary::new();
        link.insert("label".into(), Value::String(format!("link-{i}")));
        if i < LINKS {
            link.insert("NS.next".into(), Value::Uid(Uid::new(i + 1)));
        }
        link.insert("$class".into(), Value::Uid(Uid::new(class_index)));
        objects.push(Value::Dictionary(link));
    }
    objects.push(class_object("NSDictionary"));
    let out = run(
        &PlistParser,
        "com.example.chain.plist",
        keyed_archive_bytes(objects),
    );
    let md = &out
        .iter()
        .find(|a| a.metadata["type"] == "PlistFile")
        .expect("the plist record")
        .metadata;
    assert!(
        md.get("content").is_some(),
        "stored whole, under the cap: {md}"
    );
    assert_eq!(md["content"]["keyed_archive"]["truncated"], json!(true));
    assert_eq!(md["content_incomplete"], json!(true), "{md}");
    assert_eq!(
        md["content_incomplete_reason"],
        json!(IncompleteReason::CapReached.as_str())
    );
    assert!(
        md["content_incomplete_detail"]
            .as_str()
            .is_some_and(|s| s.contains("nesting depth")),
        "{md}"
    );
}

/// HUNT-231. An ordinary (not keyed-archive) plist whose `Data` values nest
/// further binary plists past the nesting bound: the one left unopened was
/// marked only inside `content`, which search, export and the completeness
/// census do not read, so the record presented as fully parsed. Hitting the
/// nesting bound stamps the standard pair, as a stopped resolution does
/// (HUNT-223).
#[test]
fn a_plist_left_unopened_at_the_nesting_bound_is_stamped_incomplete() {
    use plist::{Dictionary, Value};
    let mut innermost = Dictionary::new();
    innermost.insert("Secret".into(), Value::String("deepest-secret".into()));
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &Value::Dictionary(innermost)).expect("serialises");
    for level in 0..12 {
        let mut d = Dictionary::new();
        d.insert(format!("Level{level}"), Value::Data(bytes));
        bytes = Vec::new();
        plist::to_writer_binary(&mut bytes, &Value::Dictionary(d)).expect("serialises");
    }
    let out = run(&PlistParser, "com.example.nested.plist", bytes);
    let md = &out
        .iter()
        .find(|a| a.metadata["type"] == "PlistFile")
        .expect("the plist record")
        .metadata;
    let rendered = md["content"].to_string();
    assert!(!rendered.contains("deepest-secret"), "bound held: {md}");
    assert!(rendered.contains("nesting bound"), "{md}");
    assert_eq!(md["content_incomplete"], json!(true), "{md}");
    assert_eq!(
        md["content_incomplete_reason"],
        json!(IncompleteReason::CapReached.as_str())
    );
    assert!(
        md["content_incomplete_detail"]
            .as_str()
            .is_some_and(|s| s.contains("plist nesting")),
        "{md}"
    );
}

/// The bound is not stamped on a plist that nests within it.
#[test]
fn a_plist_nested_within_the_bound_is_not_stamped_incomplete() {
    use plist::{Dictionary, Value};
    let mut inner = Dictionary::new();
    inner.insert("Secret".into(), Value::String("shallow".into()));
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &Value::Dictionary(inner)).expect("serialises");
    let mut outer = Dictionary::new();
    outer.insert("Inner".into(), Value::Data(bytes));
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &Value::Dictionary(outer)).expect("serialises");
    let out = run(&PlistParser, "com.example.shallow.plist", bytes);
    let md = &out
        .iter()
        .find(|a| a.metadata["type"] == "PlistFile")
        .expect("the plist record")
        .metadata;
    assert!(md.get("content_incomplete").is_none(), "{md}");
}
