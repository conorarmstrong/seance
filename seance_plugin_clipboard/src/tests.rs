//! The module end to end: an artifact in, records out.
//!
//! The unit tests beside each submodule cover the pieces. These cover what a
//! caller sees, and above all the two things that would make this parser worse
//! than useless: claiming to have read encrypted content, and attaching a
//! clipboard finding to a file that is not one.

use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

const OUTER: &str = "{11111111-2222-3333-4444-555555555555}";
const ITEM: &str = "{6f1e2a3b-4c5d-6e7f-8091-a2b3c4d5e6f7}";

fn base() -> String {
    r"C:\Users\jo\AppData\Local\Microsoft\Windows\Clipboard".to_string()
}

fn file(path: &str, bytes: Vec<u8>) -> Artifact {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({
            "path": path,
            "name": path.rsplit(['/', '\\']).next().unwrap_or(path),
            "is_directory": false,
            "created": "2026-03-04T05:06:07Z",
        }),
    )
}

/// A CMS enveloped-data blob with a protection descriptor, as Windows writes.
fn protected_blob(sid: &str) -> Vec<u8> {
    const OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03];
    let mut inner = vec![0x06, OID.len() as u8];
    inner.extend_from_slice(OID);
    inner.extend_from_slice(format!("SID={sid}").as_bytes());
    let mut out = vec![0x30, 0x82];
    out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    out.extend_from_slice(&inner);
    // Ciphertext-shaped filler, so the blob is not all header.
    out.extend_from_slice(&[0xC3; 512]);
    out
}

fn records(artifact: &Artifact) -> Vec<Artifact> {
    ClipboardParser.process(artifact).expect("never errors")
}

fn of_type(arts: &[Artifact], t: &str) -> Vec<Value> {
    arts.iter()
        .filter(|a| a.metadata.get("record_type").and_then(|v| v.as_str()) == Some(t))
        .map(|a| a.metadata.clone())
        .collect()
}

/// **The claim this parser must never make.** A record for an encrypted payload
/// must say the content is encrypted, must carry no plaintext, and must name
/// what reading it would take.
#[test]
fn an_encrypted_payload_never_yields_plaintext_and_says_it_is_encrypted() {
    let sid = "S-1-5-21-1004336348-1177238915-682003330-1001";
    let path = format!(r"{}\Pinned\{OUTER}\{ITEM}\VGV4dA==", base());
    let out = records(&file(&path, protected_blob(sid)));

    let payloads = of_type(&out, "WindowsClipboardItem");
    assert_eq!(payloads.len(), 1);
    let p = &payloads[0];

    assert_eq!(p["content_encrypted"], json!(true));
    assert_eq!(p["payload_encoding"], json!("cms_enveloped_data"));
    assert!(p["content_statement"]
        .as_str()
        .unwrap()
        .contains("cannot be read"));
    assert!(
        p["decryption_requirement"]
            .as_str()
            .unwrap()
            .contains("does not attempt decryption"),
        "the record must state that no decryption was attempted"
    );

    // No field may carry decoded content.
    for (key, value) in p.as_object().unwrap() {
        if let Some(text) = value.as_str() {
            assert!(
                !text.contains("\u{c3}\u{c3}"),
                "{key} looks like it carries payload bytes"
            );
        }
    }
    assert!(
        !p.as_object().unwrap().contains_key("content"),
        "there must be no content field at all"
    );
}

/// The format is legible from the filename without touching the payload, and
/// that is itself evidence: text and an image are different findings.
#[test]
fn the_clipboard_format_is_reported_from_the_filename() {
    for (name, expect) in [
        ("VGV4dA==", "Text"),
        ("Qml0bWFw", "Bitmap"),
        ("TG9jYWxl", "Locale"),
    ] {
        let path = format!(r"{}\Pinned\{OUTER}\{ITEM}\{name}", base());
        let out = records(&file(&path, protected_blob("S-1-5-18")));
        let p = &of_type(&out, "WindowsClipboardItem")[0];
        assert_eq!(p["clipboard_format"], json!(expect));
        assert!(p["format_meaning"].is_string(), "{expect} needs a meaning");
        assert_eq!(
            p["payload_file_name"],
            json!(name),
            "the on-disk name must be recorded verbatim so the file can be found \
             again — and base64 is case-sensitive, so folding it would both lose \
             the format and mis-name the file"
        );
    }
}

/// The protection descriptor names whose clipboard this was — recoverable
/// without the key, and stated with how it was obtained.
#[test]
fn the_account_the_payload_was_protected_to_is_recovered_and_qualified() {
    let sid = "S-1-5-21-1004336348-1177238915-682003330-1001";
    let path = format!(r"{}\Pinned\{OUTER}\{ITEM}\VGV4dA==", base());
    let out = records(&file(&path, protected_blob(sid)));
    let p = &of_type(&out, "WindowsClipboardItem")[0];

    assert_eq!(p["protected_to_sid"], json!(sid));
    assert!(
        p["protected_to_recovery"]
            .as_str()
            .unwrap()
            .contains("scanning"),
        "a scanned value must not be presented as a parsed one"
    );
}

/// An unencrypted payload is a finding, not a parse failure.
#[test]
fn a_payload_that_is_not_encrypted_is_flagged_for_a_look() {
    let path = format!(r"{}\Pinned\{OUTER}\{ITEM}\VGV4dA==", base());
    let out = records(&file(&path, b"this is plainly not a DER blob".to_vec()));
    let p = &of_type(&out, "WindowsClipboardItem")[0];

    assert_eq!(p["content_encrypted"], json!(false));
    assert_eq!(p["payload_encoding"], json!("not_der"));
    assert!(p["content_statement"]
        .as_str()
        .unwrap()
        .contains("worth looking at directly"));
}

/// The inventory yields a record and a timeline event per item.
#[test]
fn the_inventory_produces_a_record_and_a_timeline_event_per_item() {
    let doc = json!([
        {"itemId": ITEM, "timestamp": "2026-03-04T05:06:07Z", "source": "Local"},
        {"itemId": OUTER, "timestamp": "2026-03-05T05:06:07Z", "source": "Remote"}
    ])
    .to_string();
    let path = format!(r"{}\Pinned\metadata.json", base());
    let out = records(&file(&path, doc.into_bytes()));

    let index = of_type(&out, "WindowsClipboardIndex");
    assert_eq!(index.len(), 2);
    assert_eq!(index[0]["item_id"], json!(ITEM));
    assert_eq!(index[0]["clipboard_source"], json!("Local"));
    assert_eq!(index[0]["timestamp"], json!("2026-03-04T05:06:07+00:00"));
    assert_eq!(index[0]["timestamp_interpretation"], json!("rfc3339"));

    let events: Vec<_> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .collect();
    assert_eq!(events.len(), 2, "one event per dated item");
    assert_eq!(
        events[0].metadata["timestamp_desc"],
        json!("Windows Clipboard")
    );
}

/// **The absence caveat must be on every record**, not only on a summary.
///
/// Records are filtered, exported and pasted into statements one at a time. An
/// examiner holding two pinned items must not conclude that two things were
/// copied — most of clipboard history never reaches disk at all.
#[test]
fn every_record_carries_the_note_that_absence_proves_nothing() {
    let doc = json!([{"itemId": ITEM, "timestamp": "2026-03-04T05:06:07Z"}]).to_string();
    let mut all = records(&file(
        &format!(r"{}\Pinned\metadata.json", base()),
        doc.into_bytes(),
    ));
    all.extend(records(&file(
        &format!(r"{}\Pinned\{OUTER}\{ITEM}\VGV4dA==", base()),
        protected_blob("S-1-5-18"),
    )));

    let parsed: Vec<_> = all
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .collect();
    assert!(!parsed.is_empty());
    for record in parsed {
        let note = record.metadata["scope_note"]
            .as_str()
            .unwrap_or_else(|| panic!("no scope_note on {:?}", record.metadata["name"]));
        assert!(
            note.contains("NOT evidence that it was never copied"),
            "the caveat must be explicit on every record"
        );
    }
}

/// An unreadable inventory must not read as "this user pinned nothing".
#[test]
fn an_inventory_that_will_not_parse_says_so_rather_than_going_quiet() {
    let path = format!(r"{}\Pinned\metadata.json", base());
    let out = records(&file(&path, b"{ this is not json".to_vec()));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["parse_failed"], json!(true));
    assert!(out[0].metadata["parse_failure"]
        .as_str()
        .unwrap()
        .contains("could not be enumerated"));
}

/// **The gate.** A file that is not part of a clipboard store must produce
/// nothing at all — attaching a clipboard finding to unrelated evidence would
/// be a claim about a user's clipboard that the evidence does not support.
#[test]
fn files_outside_the_clipboard_store_produce_nothing() {
    for path in [
        r"C:\Users\jo\Documents\metadata.json",
        r"C:\Users\jo\Documents\clipboard\Pinned\VGV4dA==",
        r"C:\Users\jo\AppData\Local\Microsoft\Windows\Explorer\thumbcache_32.db",
        r"C:\Windows\System32\config\SOFTWARE",
    ] {
        assert!(
            records(&file(path, b"whatever".to_vec())).is_empty(),
            "must produce nothing for {path}"
        );
    }
}

/// A directory entry is not a payload, and an artifact with no path is not
/// classifiable at all.
#[test]
fn directories_and_pathless_artifacts_are_ignored() {
    let path = format!(r"{}\Pinned\{OUTER}\{ITEM}\VGV4dA==", base());
    let mut dir = file(&path, Vec::new());
    dir.metadata
        .as_object_mut()
        .unwrap()
        .insert("is_directory".into(), json!(true));
    assert!(records(&dir).is_empty());

    let pathless = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({"name": "VGV4dA=="}),
    );
    assert!(records(&pathless).is_empty());
}

/// The filesystem's own times reach the record: the folder's creation time is
/// what dates a pinned item when the inventory cannot be read.
#[test]
fn filesystem_timestamps_travel_onto_the_payload_record() {
    let path = format!(r"{}\Pinned\{OUTER}\{ITEM}\VGV4dA==", base());
    let out = records(&file(&path, protected_blob("S-1-5-18")));
    let p = &of_type(&out, "WindowsClipboardItem")[0];
    assert_eq!(
        p["filesystem_times"]["created"],
        json!("2026-03-04T05:06:07Z")
    );
}

/// Nothing in this parser may panic on evidence, whatever it holds.
#[test]
fn hostile_payloads_are_handled_without_panicking() {
    let path = format!(r"{}\Pinned\{OUTER}\{ITEM}\VGV4dA==", base());
    let mut lcg: u64 = 0x9E37_79B9_7F4A_7C15;
    for len in [0usize, 1, 2, 3, 64, 5000, 40_000] {
        let bytes: Vec<u8> = (0..len)
            .map(|_| {
                lcg = lcg.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                (lcg >> 33) as u8
            })
            .collect();
        let _ = records(&file(&path, bytes));
    }
    // A metadata.json of hostile shapes.
    for doc in ["[".repeat(500), "null".into(), "0".into(), String::new()] {
        let _ = records(&file(
            &format!(r"{}\Pinned\metadata.json", base()),
            doc.into_bytes(),
        ));
    }
}

/// The history store is reported as itself, not folded into pinned.
#[test]
fn the_history_store_is_distinguished_from_pinned() {
    let path = format!(r"{}\HistoryData\{OUTER}\{ITEM}\VGV4dA==", base());
    let out = records(&file(&path, protected_blob("S-1-5-18")));
    let p = &of_type(&out, "WindowsClipboardItem")[0];
    assert_eq!(p["clipboard_store"], json!("history_data"));
    assert!(p["store_meaning"].as_str().unwrap().contains("sync"));
}

/// HUNT-198, red before the fix: the timeline event carried how the value was
/// read but not which of the candidate fields it was read from, so an event
/// exported on its own could not be checked against the inventory.
#[test]
fn the_timeline_event_names_the_field_its_time_was_taken_from() {
    let doc = json!([{"itemId": ITEM, "pinnedTime": "2026-03-04T05:06:07Z"}]).to_string();
    let path = format!(r"{}\Pinned\metadata.json", base());
    let out = records(&file(&path, doc.into_bytes()));
    assert_eq!(
        of_type(&out, "WindowsClipboardIndex")[0]["timestamp_field"],
        json!("pinnedTime")
    );
    let event = out
        .iter()
        .find(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .expect("a dated item has an event");
    // The event's details travel as a JSON string beside the timestamp.
    let details: Value =
        serde_json::from_str(event.metadata["full_details"].as_str().unwrap()).unwrap();
    assert_eq!(
        details["timestamp_field"],
        json!("pinnedTime"),
        "{}",
        event.metadata
    );
}

/// HUNT-198, red before the fix: the 2018..2100 range check applied only to
/// numbers, so an RFC 3339 string dated before clipboard history existed was
/// put on the timeline.
#[test]
fn an_rfc3339_string_outside_the_plausible_range_is_not_a_date() {
    let doc = json!([
        {"itemId": ITEM, "timestamp": "1999-12-31T23:59:59Z"},
        {"itemId": OUTER, "timestamp": "2150-01-01T00:00:00Z"}
    ])
    .to_string();
    let path = format!(r"{}\Pinned\metadata.json", base());
    let out = records(&file(&path, doc.into_bytes()));
    for item in of_type(&out, "WindowsClipboardIndex") {
        assert!(item.get("timestamp").is_none(), "{item}");
    }
    assert!(
        !out.iter()
            .any(|a| a.artifact_type == ArtifactType::TimelineEvent),
        "no event for an implausible date"
    );
}

/// HUNT-198, red before the fix: the header scan accepts the needle in any
/// case (`Sid=`), and the record then wrote `protected_to` but no
/// `protected_to_sid`, because the record's own prefix test knew only `SID=`
/// and `sid=`.
#[test]
fn a_mixed_case_descriptor_still_yields_the_sid() {
    const OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03];
    let sid = "S-1-5-21-1004336348-1177238915-682003330-1001";
    let mut inner = vec![0x06, OID.len() as u8];
    inner.extend_from_slice(OID);
    inner.extend_from_slice(format!("Sid={sid}").as_bytes());
    let mut blob = vec![0x30, 0x82];
    blob.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    blob.extend_from_slice(&inner);
    blob.extend_from_slice(&[0xC3; 512]);

    let path = format!(r"{}\Pinned\{OUTER}\{ITEM}\VGV4dA==", base());
    let out = records(&file(&path, blob));
    let p = &of_type(&out, "WindowsClipboardItem")[0];
    assert_eq!(p["protected_to"], json!(format!("Sid={sid}")));
    assert_eq!(p["protected_to_sid"], json!(sid), "{p}");
}
