//! How long a recording is, and when the device says it was made.

use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

/// Build a box: size, type, payload.
fn bx(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut out = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
    out.extend_from_slice(kind);
    out.extend_from_slice(payload);
    out
}

/// A version-0 `mvhd` payload.
fn mvhd_v0(created: u32, modified: u32, timescale: u32, duration: u32) -> Vec<u8> {
    let mut p = vec![0u8, 0, 0, 0]; // version 0, flags
    p.extend_from_slice(&created.to_be_bytes());
    p.extend_from_slice(&modified.to_be_bytes());
    p.extend_from_slice(&timescale.to_be_bytes());
    p.extend_from_slice(&duration.to_be_bytes());
    p.extend_from_slice(&[0u8; 76]); // rate, volume, matrix, predefined, next track id
    p
}

/// A version-1 `mvhd` payload: 64-bit times and duration.
fn mvhd_v1(created: u64, modified: u64, timescale: u32, duration: u64) -> Vec<u8> {
    let mut p = vec![1u8, 0, 0, 0];
    p.extend_from_slice(&created.to_be_bytes());
    p.extend_from_slice(&modified.to_be_bytes());
    p.extend_from_slice(&timescale.to_be_bytes());
    p.extend_from_slice(&duration.to_be_bytes());
    p.extend_from_slice(&[0u8; 76]);
    p
}

fn mp4(brand: &[u8; 4], mvhd_payload: Vec<u8>) -> Vec<u8> {
    let mut ftyp = brand.to_vec();
    ftyp.extend_from_slice(&[0, 0, 0, 0]); // minor version
    ftyp.extend_from_slice(brand);
    let mut out = bx(b"ftyp", &ftyp);
    out.extend_from_slice(&bx(b"moov", &bx(b"mvhd", &mvhd_payload)));
    out
}

fn artifact(name: &str, bytes: Vec<u8>) -> Artifact {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        serde_json::json!({"name": name, "path": format!("/Podcasts/{name}")}),
    )
}

fn parse(name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    MediaPropertiesModule::new()
        .process(&artifact(name, bytes))
        .expect("parsed")
}

/// The Magnet 2022 CTF asks how long the user's longest podcast was. The file
/// is an `.m4a` whose `mvhd` says 12,923.17 seconds — 03:35:23 — and Séance
/// listed the file with no duration at all, so the question could not be
/// answered from the evidence that holds the answer.
#[test]
fn a_recording_says_how_long_it_is() {
    // timescale 44100, duration 12923.17s -> 569,911,797 samples.
    let out = parse(
        "podcast.m4a",
        mp4(b"M4A ", mvhd_v0(0, 0, 44100, 569_911_797)),
    );
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["type"], "MediaProperties");
    assert_eq!(m["duration_seconds"].as_f64().unwrap().round(), 12923.0);
    // The form a human reads and a CTF answer is written in.
    assert_eq!(m["duration_hms"], "03:35:23");
    assert_eq!(m["timescale"], 44100);
    assert_eq!(m["major_brand"], "M4A ");
}

/// ISO-BMFF counts seconds from 1904-01-01 UTC. Read as a Unix time it is off
/// by 66 years, which on a timeline is not a small error.
#[test]
fn the_1904_epoch_is_converted_not_copied() {
    // 2022-02-13T05:53:52Z = 1644731632 Unix = 3727576432 in the 1904 epoch.
    let out = parse(
        "clip.mp4",
        mp4(b"isom", mvhd_v0(3_727_576_432, 3_727_576_432, 600, 6000)),
    );
    let m = &out[0].metadata;
    assert_eq!(m["created"], "2022-02-13T05:53:52+00:00");
    assert_eq!(m["modified"], "2022-02-13T05:53:52+00:00");
    assert_eq!(m["duration_seconds"], 10.0);
}

/// A `mvhd` may be version 1, with 64-bit times and duration. A parser that
/// only reads version 0 reads the version-1 fields at the wrong offsets and
/// reports a confident wrong answer.
#[test]
fn a_version_1_header_is_read_at_its_own_offsets() {
    let out = parse(
        "long.mov",
        mp4(
            b"qt  ",
            mvhd_v1(3_727_576_432, 3_727_576_432, 1000, 7_200_000),
        ),
    );
    let m = &out[0].metadata;
    assert_eq!(m["duration_seconds"], 7200.0);
    assert_eq!(m["duration_hms"], "02:00:00");
    assert_eq!(m["created"], "2022-02-13T05:53:52+00:00");
}

/// Zero is what a writer stores when it has no time to store, and dating every
/// such recording to 1904 would put a wall of events on the timeline that
/// nothing in the evidence supports.
#[test]
fn an_unset_creation_time_is_absent_not_1904() {
    let out = parse("clip.mp4", mp4(b"isom", mvhd_v0(0, 0, 600, 600)));
    let m = &out[0].metadata;
    assert!(m.get("created").is_none());
    assert!(m.get("modified").is_none());
    // The duration is still read.
    assert_eq!(m["duration_seconds"], 1.0);
}

/// A file whose `moov` was never written — an interrupted recording — has no
/// duration to report, and saying "0 seconds" would be a claim about the
/// recording rather than about this file.
#[test]
fn a_file_with_no_movie_header_says_so_rather_than_reporting_zero() {
    let mut truncated = bx(b"ftyp", b"isom\0\0\0\0isom");
    truncated.extend_from_slice(&bx(b"mdat", &[0u8; 64]));
    let out = parse("interrupted.mp4", truncated);
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert!(m.get("duration_seconds").is_none());
    assert_eq!(m["content_incomplete"], serde_json::json!(true));
    assert_eq!(m["content_incomplete_reason"], "unresolved_structure");
    assert!(m["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("moov"));
}

/// A timescale of zero would divide by zero; a hostile file must not decide
/// what this process does next.
#[test]
fn a_zero_timescale_is_refused_not_divided_by() {
    let out = parse("hostile.mp4", mp4(b"isom", mvhd_v0(0, 0, 0, 1000)));
    assert!(out[0].metadata.get("duration_seconds").is_none());
    assert_eq!(
        out[0].metadata["content_incomplete"],
        serde_json::json!(true)
    );
}

#[test]
fn only_media_containers_are_claimed() {
    assert!(parse("notes.txt", b"hello there".to_vec()).is_empty());
    // The name is not enough either: the ftyp box is what says it is one.
    assert!(parse("fake.mp4", b"not a media file at all".to_vec()).is_empty());
}
