//! The Apple Mail `.emlx` reader against files Apple Mail wrote.
//!
//! Two sources, see `tests/fixtures/emlx/PROVENANCE.md`:
//!
//! * `hoover-testdata` (MIT): `1498.partial.emlx` and its `1498.3.emlxpart`,
//!   committed under `tests/fixtures/emlx/`. Their absence is a failure.
//! * PRONOM_Research `2.emlx` and `9.emlx`: **no licence**, so not committed.
//!   Read through the corpus gate from `$SEANCE_EMLX_CORPUS` (locally
//!   `~/forensic_corpora/emlx_samples`, as an absolute path): unset skips and
//!   says so, set-but-missing fails, and `SEANCE_REQUIRE_CORPUS=1` turns the
//!   skip into a failure. A skip is "could not look", never "checked".

use base64::Engine;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_core::test_support::corpus;
use seance_plugin_email::EmailParser;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/emlx")
}

/// The unlicensed PRONOM samples, through the project's corpus gate.
fn pronom(name: &str) -> Option<PathBuf> {
    corpus::file(CORPUS_VAR, &format!("pronom_research/{name}"))
}

const CORPUS_VAR: &str = "SEANCE_EMLX_CORPUS";

fn run_file(path: &Path) -> Vec<Artifact> {
    assert!(path.is_file(), "{} is missing", path.display());
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.to_path_buf()).expect("open"));
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    EmailParser.process(&artifact).expect("process")
}

fn message(out: &[Artifact]) -> &Value {
    &out.iter()
        .find(|a| a.metadata["type"] == "EmailMessage")
        .expect("an EmailMessage record")
        .metadata
}

fn attachment<'a>(out: &'a [Artifact], name: &str) -> Option<&'a Artifact> {
    out.iter().find(|a| {
        a.artifact_type == ArtifactType::FileEntry
            && a.metadata["source"] == "email_attachment"
            && a.metadata["name"] == name
    })
}

fn read_all(a: &Artifact) -> Vec<u8> {
    let ds = a.data.as_ref().expect("attachment bytes");
    let mut buf = vec![0u8; ds.size() as usize];
    let n = seance_core::io::read_full(ds.as_ref(), 0, &mut buf);
    buf.truncate(n);
    buf
}

fn body_has_no_plist(m: &Value) {
    for k in ["body_text", "body_html"] {
        let s = m[k].as_str().unwrap_or_default();
        assert!(!s.contains("<plist"), "{k} carries the trailing plist");
        assert!(
            !s.contains("date-received"),
            "{k} carries the trailing plist"
        );
    }
}

#[test]
fn pronom_2_emlx_is_read_as_apple_mail_wrote_it() {
    let Some(path) = pronom("2.emlx") else {
        return;
    };
    let out = run_file(&path);
    let m = message(&out);
    assert_eq!(m["format"], "emlx");
    assert_eq!(m["emlx_byte_count"], 701);
    assert_eq!(m["from"], "t.thorsted@icloud.com");
    assert_eq!(m["subject"], "Email");
    // Thu, 26 Oct 2023 20:43:30 -0600
    assert_eq!(m["date"], "2023-10-27T02:43:30+00:00");
    assert_eq!(m["emlx_date_received"], 1_698_374_610_i64);
    assert_eq!(m["emlx_date_last_viewed"], 1_698_374_610_i64);
    assert_eq!(m["emlx_flags"], 8_623_685_697_i64);
    assert_eq!(m["emlx_flags_decoded"], false);
    assert_eq!(m["emlx_plist_parsed"], true);
    assert!(m.get("content_incomplete").is_none());
    body_has_no_plist(m);
    assert!(m["body_html"].as_str().unwrap().contains("Testing"));
}

#[test]
fn pronom_9_emlx_multipart_bounded_at_18173_bytes() {
    let Some(path) = pronom("9.emlx") else {
        return;
    };
    let out = run_file(&path);
    let m = message(&out);
    assert_eq!(m["emlx_byte_count"], 18_173);
    assert_eq!(m["subject"], "More tests");
    assert_eq!(m["emlx_conversation_id"], 7);
    // The plist parsing at all is the check that the count bounded the
    // message on the closing boundary: one byte off and it would not.
    assert_eq!(m["emlx_plist_parsed"], true);
    assert_eq!(m["attachment_count"], 1);
    assert_eq!(m["attachments"][0]["content_type"], "application/pdf");
    body_has_no_plist(m);
    let pdf = out
        .iter()
        .find(|a| a.metadata["source"] == "email_attachment")
        .expect("the related PDF part as a child file");
    assert!(read_all(pdf).starts_with(b"%PDF"));
}

#[test]
fn hoover_partial_emlx_reunites_part_3_from_its_emlxpart() {
    let out = run_file(&fixture_dir().join("1498.partial.emlx"));
    let m = message(&out);
    assert_eq!(m["format"], "emlx");
    assert_eq!(m["emlx_byte_count"], 44_126);
    assert_eq!(m["emlx_remote_id"], "18354");
    assert_eq!(m["emlx_date_received"], 1_449_399_891_i64);
    assert_eq!(m["emlx_partial"], true);
    let parts = m["emlx_parts"].as_array().expect("emlx_parts");
    assert_eq!(parts.len(), 1, "only part 3 is a stub: {parts:?}");
    assert_eq!(parts[0]["section"], "3");
    assert_eq!(parts[0]["file"], "1498.3.emlxpart");
    assert_eq!(parts[0]["status"], "reunited");
    assert_eq!(parts[0]["bytes"], 75_521);
    // X-Apple-Content-Length counts the part with CRLF line ends; the file
    // stores LF. 75,521 bytes + 981 line ends = 76,502.
    assert_eq!(parts[0]["declared_length"], 76_502);
    assert_eq!(parts[0]["declared_length_agrees"], true);
    assert!(m.get("attachment_absent_reason").is_none());
    assert!(m.get("content_incomplete").is_none(), "{m:#}");
    body_has_no_plist(m);

    let pdf = attachment(&out, "Legea-299-2015-informatiile-publice.pdf")
        .expect("the PDF reunited from 1498.3.emlxpart");
    let bytes = read_all(pdf);
    assert!(
        bytes.starts_with(b"%PDF-1.4"),
        "{:?}",
        &bytes[..16.min(bytes.len())]
    );
    // The decoded length is the base64 in the part file, decoded.
    let part = std::fs::read(fixture_dir().join("1498.3.emlxpart")).unwrap();
    let b64: Vec<u8> = part
        .into_iter()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let expected = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("the part file is base64");
    assert_eq!(bytes, expected);
}

#[test]
fn a_partial_emlx_without_its_part_says_the_part_is_missing() {
    let out = run_file(&fixture_dir().join("missing-part/1498.partial.emlx"));
    let m = message(&out);
    assert_eq!(m["emlx_partial"], true);
    assert_eq!(m["content_incomplete"], true);
    let reason = m["attachment_absent_reason"].as_str().expect("reason");
    assert!(reason.contains("1498.3.emlxpart"), "{reason}");
    assert!(reason.contains("not present"), "{reason}");
    assert_eq!(m["emlx_parts"][0]["status"], "absent");
    assert!(attachment(&out, "Legea-299-2015-informatiile-publice.pdf").is_none());
}

#[test]
fn a_partial_emlx_on_a_source_that_cannot_look_says_so_not_absent() {
    let bytes = std::fs::read(fixture_dir().join("1498.partial.emlx")).unwrap();
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "1498.partial.emlx" }),
    );
    let out = EmailParser.process(&artifact).expect("process");
    let m = message(&out);
    assert_eq!(m["content_incomplete"], true);
    assert_eq!(m["emlx_parts"][0]["status"], "source_cannot_look");
    let reason = m["attachment_absent_reason"].as_str().unwrap();
    assert!(reason.contains("could not look"), "{reason}");
}

/// The committed Apple-written file with its name lost (a carve, or a
/// rename): read as `.emlx`, bounded by its count, the plist kept off the
/// body. Its `Return-Path:` is on line 2, so this pins the full-content
/// re-detection on real bytes; the case with identity headers past line 10
/// is pinned only synthetically (`lib.rs`
/// `a_nameless_emlx_larger_than_the_probe_is_still_read_as_emlx`), as none of
/// the three real files has that shape.
#[test]
fn hoover_partial_emlx_without_its_name_is_still_read_as_emlx() {
    let bytes = std::fs::read(fixture_dir().join("1498.partial.emlx")).unwrap();
    assert!(bytes.len() > 1024);
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "carved_000417" }),
    );
    let out = EmailParser.process(&artifact).expect("process");
    let m = message(&out);
    assert_eq!(m["format"], "emlx");
    assert_eq!(m["emlx_byte_count"], 44_126);
    assert_eq!(m["emlx_remote_id"], "18354");
    body_has_no_plist(m);
}
