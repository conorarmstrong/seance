//! A voicemail's audio and transcript: the `<ROWID>.amr` and
//! `<ROWID>.transcript` files beside `voicemail.db`.
//!
//! Validated on the Magnet 2020 CTF iPhone (iOS 12.4): five rows (ROWID
//! 1, 2, 3, 4, 6), an `.amr` for each whose magic is `#!AMR\n`, and an
//! `NSKeyedArchiver` transcript for each whose root is a
//! `VMVoicemailTranscript` with `transcriptionString`, `confidence`,
//! `confidenceRating` and `segments`. A sixth audio file, `5.amr`, has no
//! row: it is reported as an orphan, and that it was a voicemail since
//! deleted is the natural reading but is not inferred on the record.

use std::collections::BTreeSet;

use seance_core::data_source::DataSource;
use seance_core::io::read_full;
use serde_json::{json, Map, Value};

/// Largest transcript read (the largest held is 52 KB).
const MAX_TRANSCRIPT_BYTES: u64 = 16 * 1024 * 1024;

/// What a `.transcript` archive gave.
pub(crate) struct Transcript {
    pub(crate) text: String,
    pub(crate) confidence: Option<f64>,
    pub(crate) confidence_rating: Option<i64>,
    pub(crate) segments: Option<usize>,
}

/// Decode a `VMVoicemailTranscript` keyed archive.
pub(crate) fn decode_transcript(bytes: &[u8]) -> Result<Transcript, String> {
    use plist::Value as P;
    let v: P = plist::from_bytes(bytes).map_err(|e| format!("not a property list: {e}"))?;
    let d = v.as_dictionary().ok_or("the plist is not a dictionary")?;
    if d.get("$archiver").and_then(P::as_string) != Some("NSKeyedArchiver") {
        return Err("not an NSKeyedArchiver archive".into());
    }
    let objects = d
        .get("$objects")
        .and_then(P::as_array)
        .ok_or("the archive has no $objects")?;
    let root = d
        .get("$top")
        .and_then(P::as_dictionary)
        .and_then(|t| t.get("root"))
        .and_then(|v| resolve(objects, v))
        .and_then(P::as_dictionary)
        .ok_or("the archive has no root object")?;
    // The class must be the one this reader was validated on.
    let class = root
        .get("$class")
        .and_then(|v| resolve(objects, v))
        .and_then(P::as_dictionary)
        .and_then(|c| c.get("$classname"))
        .and_then(P::as_string);
    if class != Some("VMVoicemailTranscript") {
        return Err(format!(
            "the root object is {}, not a VMVoicemailTranscript",
            class.unwrap_or("of no class")
        ));
    }
    let text = root
        .get("transcriptionString")
        .and_then(|v| resolve(objects, v))
        .and_then(P::as_string)
        .ok_or("the transcript has no transcriptionString")?
        .to_string();
    let number = |k: &str| match root.get(k).and_then(|v| resolve(objects, v)) {
        Some(P::Real(r)) => Some(*r),
        Some(P::Integer(i)) => i.as_signed().map(|i| i as f64),
        _ => None,
    };
    let segments = root
        .get("segments")
        .and_then(|v| resolve(objects, v))
        .and_then(P::as_dictionary)
        .and_then(|s| s.get("NS.objects"))
        .and_then(P::as_array)
        .map(Vec::len);
    Ok(Transcript {
        text,
        confidence: number("confidence"),
        confidence_rating: number("confidenceRating").map(|r| r as i64),
        segments,
    })
}

/// An archive reference resolved against `$objects`; a non-reference is
/// itself.
fn resolve<'a>(objects: &'a [plist::Value], v: &'a plist::Value) -> Option<&'a plist::Value> {
    match v {
        plist::Value::Uid(u) => objects.get(u.get() as usize),
        other => Some(other),
    }
}

/// The audio container, by magic: the name is not trusted.
fn audio_format(head: &[u8]) -> &'static str {
    if head.starts_with(b"#!AMR") {
        "amr"
    } else if head.len() >= 8 && &head[4..8] == b"ftyp" {
        "mp4"
    } else {
        "unrecognised"
    }
}

/// Per-store tallies for the summary.
#[derive(Default)]
pub(crate) struct FileTally {
    pub(crate) audio_present: usize,
    pub(crate) audio_absent: usize,
    pub(crate) transcripts_read: usize,
    pub(crate) transcripts_unread: usize,
    pub(crate) unresolved: usize,
}

/// Attach the row's audio and transcript to its record `m`.
pub(crate) fn attach(
    m: &mut Map<String, Value>,
    rowid: i64,
    ds: &dyn DataSource,
    t: &mut FileTally,
) {
    if !ds.supports_siblings() {
        t.unresolved += 1;
        m.insert(
            "audio_unresolved".into(),
            json!("source_cannot_open_neighbours"),
        );
        m.insert(
            "transcript_unresolved".into(),
            json!("source_cannot_open_neighbours"),
        );
        return;
    }
    let audio_name = format!("{rowid}.amr");
    match ds.open_relative(&audio_name) {
        Some(audio) => {
            t.audio_present += 1;
            let mut head = [0u8; 12];
            let n = read_full(audio.as_ref(), 0, &mut head);
            m.insert("audio_present".into(), json!(true));
            m.insert("audio_file".into(), json!(audio_name));
            m.insert("audio_bytes".into(), json!(audio.size()));
            m.insert("audio_format".into(), json!(audio_format(&head[..n])));
        }
        None => {
            t.audio_absent += 1;
            m.insert("audio_present".into(), json!(false));
        }
    }
    let tname = format!("{rowid}.transcript");
    match ds.open_relative(&tname) {
        None => {
            m.insert("transcript_present".into(), json!(false));
        }
        Some(src) => {
            m.insert("transcript_present".into(), json!(true));
            m.insert("transcript_source".into(), json!(tname));
            let size = src.size();
            let decoded = if size > MAX_TRANSCRIPT_BYTES {
                Err(format!(
                    "{size} bytes is over the {MAX_TRANSCRIPT_BYTES}-byte cap"
                ))
            } else {
                let mut buf = vec![0u8; size as usize];
                let n = read_full(src.as_ref(), 0, &mut buf);
                if (n as u64) < size {
                    Err(format!("only {n} of {size} bytes could be read"))
                } else {
                    decode_transcript(&buf)
                }
            };
            match decoded {
                Ok(tr) => {
                    t.transcripts_read += 1;
                    m.insert("transcript".into(), json!(tr.text));
                    if let Some(c) = tr.confidence {
                        m.insert("transcript_confidence".into(), json!(c));
                    }
                    if let Some(r) = tr.confidence_rating {
                        m.insert("transcript_confidence_rating".into(), json!(r));
                    }
                    if let Some(s) = tr.segments {
                        m.insert("transcript_segments".into(), json!(s));
                    }
                    m.insert(
                        "transcript_note".into(),
                        json!("the device's own speech-to-text, not a human transcription"),
                    );
                }
                Err(why) => {
                    t.transcripts_unread += 1;
                    m.insert("transcript_unread_reason".into(), json!(why));
                }
            }
        }
    }
}

/// `<digits>.amr` files beside the store that no row names.
pub(crate) enum Orphans {
    /// The directory was listed; these names are named by no row.
    Listed(Vec<(String, i64, u64)>),
    /// The source cannot list its directory.
    CannotList,
}

pub(crate) fn orphans(ds: &dyn DataSource, rowids: &BTreeSet<i64>) -> Orphans {
    let Some(names) = ds.list_from_ancestor(0, "") else {
        return Orphans::CannotList;
    };
    let mut out = Vec::new();
    for name in names {
        let Some(stem) = name.strip_suffix(".amr") else {
            continue;
        };
        let Ok(id) = stem.parse::<i64>() else {
            continue;
        };
        if rowids.contains(&id) {
            continue;
        }
        let size = ds.open_relative(&name).map(|s| s.size()).unwrap_or(0);
        out.push((name, id, size));
    }
    Orphans::Listed(out)
}
