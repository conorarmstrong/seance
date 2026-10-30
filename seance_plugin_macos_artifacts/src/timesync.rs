//! Apple Unified Log timesync database — `/var/db/diagnostics/timesync/*.timesync`.
//!
//! A `.tracev3` stamps its entries in **continuous time**: mach ticks since the
//! boot that wrote them, not a wall clock. The timesync database is what turns
//! one into the other. It is a flat run of little-endian records:
//!
//! * a **boot record** (48 bytes) — `u16` signature `0xBBB0`, `u16` header size
//!   (48), `u32` unknown, the 16-byte boot UUID, the mach timebase as `u32`
//!   numerator and `u32` denominator, the boot's wall-clock time as `i64`
//!   nanoseconds since 1970, and `u32` timezone offset (minutes) and `u32`
//!   daylight-saving flag;
//! * followed by that boot's **sync records** (32 bytes each) — `u32` signature
//!   `0x00207354` (`"Ts "`), `u32` flags, `u64` continuous time, `i64` wall time
//!   in nanoseconds since 1970, `u32` timezone offset and `u32` daylight flag.
//!
//! Each sync record is one **anchor**: at this continuous time on this boot, the
//! wall clock read this. A decoder converts an entry's continuous time through
//! the nearest anchor at or before it and the boot's timebase.
//!
//! # Scope, stated honestly
//!
//! This reads the file and reports what it says: one record per boot with its
//! UUID, timebase and anchors. It converts nothing — no `.tracev3` entry is
//! dated here — and it does not judge whether the wall clock the machine kept
//! was right: an anchor is what the machine believed the time was, which is
//! the only thing the file can say.
//!
//! The layout was read from the corpus files themselves and agrees with the
//! community reading in Mandiant's `macos-UnifiedLogs` (Apache-2.0), which is
//! used as a comparison, not as the answer.

use anyhow::Result;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Map, Value};
use tracing::info;

use crate::{basename_lower, stamp_incomplete, Staged};

/// Boot record signature, as the `u16` at its start.
const BOOT_SIGNATURE: u16 = 0xBBB0;
/// Bytes in a boot record, which its own header-size field also states.
const BOOT_BYTES: usize = 48;
/// Sync record signature, `"Ts \0"` read as a little-endian `u32`.
const SYNC_SIGNATURE: u32 = 0x0020_7354;
/// Bytes in a sync record.
const SYNC_BYTES: usize = 32;
/// Largest timesync file staged. Real ones are a few KB.
const MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Anchors carried on one boot's record. The count is always exact; past this
/// the list itself is cut and the record says so.
const MAX_ANCHORS_PER_BOOT: usize = 10_000;

const NOTE: &str = "A timesync record says what the machine's own clock read at a given \
    continuous time on a given boot. It dates nothing by itself and does not say the clock was \
    right: it is the table a unified-log decoder converts an entry's continuous time through.";

fn le_u16(d: &[u8], at: usize) -> Option<u16> {
    d.get(at..at.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn le_u32(d: &[u8], at: usize) -> Option<u32> {
    d.get(at..at.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le_u64(d: &[u8], at: usize) -> Option<u64> {
    d.get(at..at.checked_add(8)?).map(|s| {
        let mut b = [0u8; 8];
        b.copy_from_slice(s);
        u64::from_le_bytes(b)
    })
}

/// One sync anchor: continuous time on a boot to the wall clock.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Anchor {
    pub(crate) continuous_time: u64,
    pub(crate) wall_time_ns: i64,
    pub(crate) timezone_offset_minutes: u32,
    pub(crate) daylight_saving: u32,
    pub(crate) flags: u32,
}

/// One boot and its anchors.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Boot {
    /// Upper-case hex, 32 digits, the form the uuidtext tree names files in.
    pub(crate) boot_uuid: String,
    pub(crate) timebase_numerator: u32,
    pub(crate) timebase_denominator: u32,
    pub(crate) boot_time_ns: i64,
    pub(crate) timezone_offset_minutes: u32,
    pub(crate) daylight_saving: u32,
    /// Byte offset of the boot record in the file.
    pub(crate) offset: usize,
    pub(crate) anchor_count: usize,
    pub(crate) anchors: Vec<Anchor>,
}

/// What the walk made of the file.
#[derive(Debug, Default)]
pub(crate) struct Timesync {
    pub(crate) boots: Vec<Boot>,
    /// Why the walk stopped before the end of the bytes, in words.
    pub(crate) flaw: Option<String>,
    /// A record ran past the end of the bytes.
    pub(crate) truncated: bool,
    /// A boot's anchor list was cut at `MAX_ANCHORS_PER_BOOT`.
    pub(crate) anchors_capped: bool,
}

/// Walk the records. `None` when the file does not open with a boot record,
/// because then nothing in it can be attributed to a boot.
pub(crate) fn parse(data: &[u8]) -> Option<Timesync> {
    if le_u16(data, 0)? != BOOT_SIGNATURE {
        return None;
    }
    let mut out = Timesync::default();
    let mut off = 0usize;
    while off < data.len() {
        if le_u16(data, off) == Some(BOOT_SIGNATURE) {
            let Some(rec) = data.get(off..off + BOOT_BYTES) else {
                out.truncated = true;
                break;
            };
            let header_size = le_u16(rec, 2).unwrap_or_default() as usize;
            if header_size != BOOT_BYTES {
                out.flaw = Some(format!(
                    "the boot record at byte {off} declares a header size of {header_size}, \
                     where the format has {BOOT_BYTES}, so the rest of the file was not read"
                ));
                break;
            }
            let boot_uuid = rec[8..24].iter().map(|b| format!("{b:02X}")).collect();
            out.boots.push(Boot {
                boot_uuid,
                timebase_numerator: le_u32(rec, 24).unwrap_or_default(),
                timebase_denominator: le_u32(rec, 28).unwrap_or_default(),
                boot_time_ns: le_u64(rec, 32).unwrap_or_default() as i64,
                timezone_offset_minutes: le_u32(rec, 40).unwrap_or_default(),
                daylight_saving: le_u32(rec, 44).unwrap_or_default(),
                offset: off,
                anchor_count: 0,
                anchors: Vec::new(),
            });
            off += BOOT_BYTES;
        } else if le_u32(data, off) == Some(SYNC_SIGNATURE) {
            let Some(rec) = data.get(off..off + SYNC_BYTES) else {
                out.truncated = true;
                break;
            };
            // The first record is a boot record, so there is always a boot to
            // attach an anchor to.
            let Some(boot) = out.boots.last_mut() else {
                break;
            };
            boot.anchor_count += 1;
            if boot.anchors.len() < MAX_ANCHORS_PER_BOOT {
                boot.anchors.push(Anchor {
                    flags: le_u32(rec, 4).unwrap_or_default(),
                    continuous_time: le_u64(rec, 8).unwrap_or_default(),
                    wall_time_ns: le_u64(rec, 16).unwrap_or_default() as i64,
                    timezone_offset_minutes: le_u32(rec, 24).unwrap_or_default(),
                    daylight_saving: le_u32(rec, 28).unwrap_or_default(),
                });
            } else {
                out.anchors_capped = true;
            }
            off += SYNC_BYTES;
        } else {
            out.flaw = Some(format!(
                "the bytes at offset {off} are neither a boot record nor a sync record, so the \
                 walk stopped there and the {} byte(s) after it were not read",
                data.len() - off
            ));
            break;
        }
    }
    Some(out)
}

/// Wall-clock nanoseconds since 1970 as RFC 3339, when it is in range.
fn ns_rfc3339(ns: i64) -> Option<String> {
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = ns.rem_euclid(1_000_000_000) as u32;
    crate::to_rfc3339_nanos(secs, nanos)
}

pub struct UnifiedLogTimesyncParser;

fn named_timesync(name: &str) -> bool {
    basename_lower(name).ends_with(".timesync")
}

fn boot_artifact(artifact: &Artifact, file_name: &str, boot: &Boot, capped: bool) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("UnifiedLogBoot"));
    meta.insert("subtype".into(), json!("timesync_boot"));
    meta.insert("source_file_name".into(), json!(file_name));
    meta.insert("source_format".into(), json!("unifiedlog_timesync"));
    meta.insert("boot_uuid".into(), json!(boot.boot_uuid));
    meta.insert("record_offset".into(), json!(boot.offset));
    meta.insert("timebase_numerator".into(), json!(boot.timebase_numerator));
    meta.insert(
        "timebase_denominator".into(),
        json!(boot.timebase_denominator),
    );
    meta.insert("boot_time_ns".into(), json!(boot.boot_time_ns));
    if let Some(text) = ns_rfc3339(boot.boot_time_ns) {
        meta.insert(
            "timestamp".into(),
            json!(boot.boot_time_ns.div_euclid(1_000_000_000)),
        );
        meta.insert("timestamp_rfc3339".into(), json!(text));
    }
    meta.insert(
        "timezone_offset_minutes".into(),
        json!(boot.timezone_offset_minutes),
    );
    meta.insert("daylight_saving".into(), json!(boot.daylight_saving));
    meta.insert("anchor_count".into(), json!(boot.anchor_count));
    let anchors: Vec<Value> = boot
        .anchors
        .iter()
        .map(|a| {
            let mut m = Map::new();
            m.insert("continuous_time".into(), json!(a.continuous_time));
            m.insert("wall_time_ns".into(), json!(a.wall_time_ns));
            if let Some(text) = ns_rfc3339(a.wall_time_ns) {
                m.insert("wall_time_rfc3339".into(), json!(text));
            }
            m.insert(
                "timezone_offset_minutes".into(),
                json!(a.timezone_offset_minutes),
            );
            m.insert("daylight_saving".into(), json!(a.daylight_saving));
            m.insert("flags".into(), json!(a.flags));
            Value::Object(m)
        })
        .collect();
    meta.insert("anchors".into(), Value::Array(anchors));
    if capped && boot.anchor_count > boot.anchors.len() {
        let _ = stamp_incomplete(
            &mut meta,
            "content",
            &[(
                IncompleteReason::CapReached,
                format!(
                    "{} anchor(s) were counted and the first {MAX_ANCHORS_PER_BOOT} are listed",
                    boot.anchor_count
                ),
            )],
        );
    }
    meta.insert("note".into(), json!(NOTE));
    let when = ns_rfc3339(boot.boot_time_ns).unwrap_or_else(|| "an out-of-range time".into());
    meta.insert(
        "name".into(),
        json!(format!(
            "Boot {} at {when} ({} timesync anchor(s))",
            boot.boot_uuid, boot.anchor_count
        )),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("timesync_boot")
}

fn file_artifact(artifact: &Artifact, file_name: &str, staged: &Staged, ts: &Timesync) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("UnifiedLogTimesync"));
    meta.insert("subtype".into(), json!("timesync"));
    meta.insert("file_name".into(), json!(file_name));
    meta.insert("bytes_staged".into(), json!(staged.got));
    meta.insert("declared_size".into(), json!(staged.declared));
    meta.insert("boots".into(), json!(ts.boots.len()));
    meta.insert(
        "anchors".into(),
        json!(ts.boots.iter().map(|b| b.anchor_count).sum::<usize>()),
    );
    let mut reasons: Vec<(IncompleteReason, String)> = Vec::new();
    if let Some(reason) = staged.incomplete_reason() {
        reasons.push((reason, staged.detail(file_name)));
    }
    if ts.truncated {
        reasons.push((
            IncompleteReason::ShortRead,
            "the last record runs past the end of the bytes held, so it was not read; the \
             boots and anchors before it are reported"
                .to_string(),
        ));
    }
    if let Some(flaw) = &ts.flaw {
        reasons.push((IncompleteReason::UnresolvedStructure, flaw.clone()));
    }
    if ts.anchors_capped {
        reasons.push((
            IncompleteReason::CapReached,
            format!("a boot held more than {MAX_ANCHORS_PER_BOOT} anchors; the list was cut and the count kept"),
        ));
    }
    let _ = stamp_incomplete(&mut meta, "content", &reasons);
    meta.insert("note".into(), json!(NOTE));
    meta.insert(
        "name".into(),
        json!(format!(
            "Unified log timesync {file_name}: {} boot(s)",
            ts.boots.len()
        )),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("timesync")
}

impl ForensicsModule for UnifiedLogTimesyncParser {
    fn id(&self) -> &str {
        "macos.unifiedlog_timesync"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        let named = named_timesync(name);
        if !named {
            // Unnamed, the claim rests on content: a boot record whose own
            // size field says 48, followed by a sync record. The two-byte
            // signature alone is too common a pair of bytes to claim a file on.
            let mut head = [0u8; BOOT_BYTES + 4];
            let n = seance_core::io::read_full(ds.as_ref(), 0, &mut head);
            let head = &head[..n];
            if le_u16(head, 0) != Some(BOOT_SIGNATURE)
                || le_u16(head, 2) != Some(BOOT_BYTES as u16)
                || le_u32(head, BOOT_BYTES) != Some(SYNC_SIGNATURE)
            {
                return Ok(Vec::new());
            }
        }
        let staged = Staged::read(ds.as_ref(), MAX_BYTES);
        let Some(ts) = parse(&staged.bytes) else {
            // Only a file the OS named `.timesync` reaches here. It is a
            // finding that it does not read, not a silence (HUNT-179).
            return Ok(vec![staged.unreadable_marker(
                artifact.case_id,
                artifact.id,
                "UnifiedLogTimesync",
                name,
                "NotATimesyncFile",
                "does not open with a timesync boot record",
                "so no boot or clock anchor could be read from it",
            )]);
        };
        let mut out = Vec::with_capacity(ts.boots.len() + 1);
        out.push(file_artifact(artifact, name, &staged, &ts));
        for boot in &ts.boots {
            out.push(boot_artifact(artifact, name, boot, ts.anchors_capped));
        }
        info!(
            "UnifiedLogTimesyncParser: {name} — {} boot(s)",
            ts.boots.len()
        );
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use std::sync::Arc;
    use uuid::Uuid;

    // Written from literal offsets, not the reader's constants, so a mistake
    // in those cannot make a test agree with itself.
    fn boot_record(uuid: [u8; 16], numer: u32, denom: u32, boot_ns: i64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xBBB0u16.to_le_bytes());
        out.extend_from_slice(&48u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&uuid);
        out.extend_from_slice(&numer.to_le_bytes());
        out.extend_from_slice(&denom.to_le_bytes());
        out.extend_from_slice(&boot_ns.to_le_bytes());
        out.extend_from_slice(&480u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(out.len(), 48);
        out
    }

    fn sync_record(continuous: u64, wall_ns: i64) -> Vec<u8> {
        let mut out = b"Ts \0".to_vec();
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&continuous.to_le_bytes());
        out.extend_from_slice(&wall_ns.to_le_bytes());
        out.extend_from_slice(&480u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(out.len(), 32);
        out
    }

    const UUID_A: [u8; 16] = [
        0x9A, 0x6A, 0x31, 0x24, 0x27, 0x4A, 0x44, 0xB2, 0x9A, 0xBF, 0x2B, 0xC9, 0xE4, 0x59, 0x9B,
        0x3B,
    ];

    fn run(bytes: Vec<u8>, name: &str) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(bytes))),
            json!({ "name": name }),
        );
        UnifiedLogTimesyncParser.process(&art).unwrap()
    }

    fn of_type<'a>(out: &'a [Artifact], wanted: &str) -> Vec<&'a Value> {
        out.iter()
            .map(|a| &a.metadata)
            .filter(|m| m.get("type").and_then(|v| v.as_str()) == Some(wanted))
            .collect()
    }

    #[test]
    fn a_synthetic_boot_record_carries_its_uuid_and_timebase() {
        let mut bytes = boot_record(UUID_A, 125, 3, 1_640_000_000_000_000_000);
        bytes.extend(sync_record(6_000_000_000, 1_640_000_000_250_000_000));
        let out = run(bytes, "0000000000000002.timesync");
        let boots = of_type(&out, "UnifiedLogBoot");
        assert_eq!(boots.len(), 1, "one boot record, one boot");
        let b = boots[0];
        assert_eq!(b["boot_uuid"], json!("9A6A3124274A44B29ABF2BC9E4599B3B"));
        assert_eq!(b["timebase_numerator"], json!(125));
        assert_eq!(b["timebase_denominator"], json!(3));
        assert_eq!(b["boot_time_ns"], json!(1_640_000_000_000_000_000i64));
        assert_eq!(b["timestamp_rfc3339"], json!("2021-12-20T11:33:20+00:00"));
        assert_eq!(b["anchor_count"], json!(1));
        assert_eq!(b["anchors"][0]["continuous_time"], json!(6_000_000_000u64));
        assert_eq!(
            b["anchors"][0]["wall_time_ns"],
            json!(1_640_000_000_250_000_000i64)
        );
        let file = of_type(&out, "UnifiedLogTimesync");
        assert_eq!(file[0]["boots"], json!(1));
        assert!(file[0].get("content_incomplete").is_none(), "a whole file");
    }

    #[test]
    fn a_truncated_timesync_keeps_the_boots_read_and_says_so() {
        let mut bytes = boot_record(UUID_A, 1, 1, 1_640_000_000_000_000_000);
        bytes.extend(sync_record(1, 1_640_000_000_000_000_001));
        let mut second = sync_record(2, 1_640_000_000_000_000_002);
        second.truncate(20);
        bytes.extend(second);
        let out = run(bytes.clone(), "0000000000000002.timesync");
        let boots = of_type(&out, "UnifiedLogBoot");
        assert_eq!(boots.len(), 1);
        assert_eq!(boots[0]["anchor_count"], json!(1));
        let file = of_type(&out, "UnifiedLogTimesync")[0];
        assert_eq!(file["content_incomplete"], json!(true));
        assert_eq!(file["content_incomplete_reason"], json!("short_read"));

        // A record that is neither kind stops the walk as unresolved structure.
        let mut bad = boot_record(UUID_A, 1, 1, 1_640_000_000_000_000_000);
        bad.extend([0u8; 32]);
        let out = run(bad, "0000000000000002.timesync");
        let file = of_type(&out, "UnifiedLogTimesync")[0];
        assert_eq!(
            file["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        assert_eq!(of_type(&out, "UnifiedLogBoot").len(), 1, "the boot is kept");
    }

    #[test]
    fn an_unnamed_file_needs_a_boot_record_and_a_sync_record_to_be_claimed() {
        let mut bytes = boot_record(UUID_A, 1, 1, 0);
        bytes.extend(sync_record(1, 1));
        assert!(!run(bytes, "blob.bin").is_empty());
        // Two bytes of signature alone is a coincidence.
        let mut lone = 0xBBB0u16.to_le_bytes().to_vec();
        lone.extend([0u8; 80]);
        assert!(run(lone, "blob.bin").is_empty());
    }

    #[test]
    fn a_named_timesync_that_is_not_one_is_reported_not_dropped() {
        let out = run(b"Not a timesync file".to_vec(), "BadFile.timesync");
        assert_eq!(out.len(), 1, "the OS's own name for it makes it a finding");
        assert_eq!(out[0].metadata["subtype"], json!("parse_incomplete"));
        assert_eq!(out[0].metadata["content_incomplete"], json!(true));
    }

    fn corpus() -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("forensic_corpora/mandiant_unifiedlogs/test_data")
    }

    #[test]
    fn every_bad_data_timesync_is_refused_or_marked_without_panicking() {
        let dir = corpus().join("Bad Data/Timesync");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        };
        let mut seen = 0;
        for e in entries.flatten() {
            let bytes = std::fs::read(e.path()).unwrap();
            let name = e.file_name().to_string_lossy().to_string();
            let out = run(bytes, &name);
            seen += 1;
            // Every one of these is named `.timesync` and is damaged, so every
            // one must be reported and every one must say it is incomplete.
            assert!(!out.is_empty(), "{name} vanished");
            assert_eq!(
                out[0].metadata["content_incomplete"],
                json!(true),
                "{name} reported as whole"
            );
        }
        assert_eq!(seen, 4);
    }

    /// The Big Sur archive's own timesync, read from the corpus. The figures
    /// are what this reader finds in the file; Mandiant's reading of the same
    /// file is a comparison, not the source of them.
    #[test]
    fn the_big_sur_archives_timesync_yields_its_boots() {
        let path =
            corpus().join("system_logs_big_sur.logarchive/timesync/0000000000000002.timesync");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        };
        let out = run(bytes, "0000000000000002.timesync");
        let file = of_type(&out, "UnifiedLogTimesync")[0];
        assert!(file.get("content_incomplete").is_none(), "read whole");
        let boots = of_type(&out, "UnifiedLogBoot");
        assert_eq!(file["boots"], json!(boots.len()));
        assert_eq!(boots.len(), BIG_SUR_BOOTS);
        assert_eq!(
            boots[0]["boot_uuid"],
            json!("9A6A3124274A44B29ABF2BC9E4599B3B")
        );
        assert_eq!(boots[0]["timebase_numerator"], json!(1));
        assert_eq!(boots[0]["timebase_denominator"], json!(1));
        assert_eq!(boots[0]["anchor_count"], json!(BIG_SUR_FIRST_BOOT_ANCHORS));
        assert_eq!(file["anchors"], json!(BIG_SUR_ANCHORS));
    }

    /// Every timesync file in the six archives reads to its last byte with no
    /// flaw — the layout holds from High Sierra to Tahoe.
    #[test]
    fn every_archives_timesync_reads_whole() {
        let Ok(archives) = std::fs::read_dir(corpus()) else {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        };
        let mut files = 0;
        for a in archives.flatten() {
            let Ok(ts) = std::fs::read_dir(a.path().join("timesync")) else {
                continue;
            };
            for f in ts.flatten() {
                let bytes = std::fs::read(f.path()).unwrap();
                let parsed = parse(&bytes).expect("opens with a boot record");
                assert!(parsed.flaw.is_none() && !parsed.truncated, "{:?}", f.path());
                assert!(!parsed.boots.is_empty());
                files += 1;
            }
        }
        assert_eq!(files, 10, "1 + 1 + 1 + 1 + 5 + 1 timesync files");
    }

    const BIG_SUR_BOOTS: usize = 5;
    const BIG_SUR_FIRST_BOOT_ANCHORS: usize = 5;
    const BIG_SUR_ANCHORS: usize = 23;
}
