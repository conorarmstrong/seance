//! Known-answer tests for the §1.5 remainder over real iOS extractions held in
//! `~/forensic_corpora`, gated on `SEANCE_IOS_CORPORA` (the directory holding
//! them). Unset, each test prints `SKIPPED` and returns; set, a missing file
//! fails, because a corpus named and not there is a broken run, not a skip.
//!
//! The images are public CTF / reference material and are not redistributed
//! here; each directory's `SOURCE.md` / `PROVENANCE.md` gives the source URL
//! and hashes. What each answer is graded against is named on the test:
//! a published answer key where one exists, otherwise the artifact's own
//! contents read with `sqlite3` before the parser was written.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
};
use seance_plugin_ios_artifacts::{
    HealthKitParser, NotesParser, VoiceMemosParser, VoicemailParser,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

fn corpus(rel: &str) -> Option<PathBuf> {
    let Some(root) = std::env::var_os("SEANCE_IOS_CORPORA") else {
        eprintln!("SKIPPED: SEANCE_IOS_CORPORA is not set (the directory holding the iOS corpora)");
        return None;
    };
    let p = PathBuf::from(root).join(rel);
    assert!(
        p.is_file(),
        "SEANCE_IOS_CORPORA is set but {} is not there",
        p.display()
    );
    Some(p)
}

fn run(module: &dyn ForensicsModule, rel: &str) -> Option<Vec<Artifact>> {
    let path = corpus(rel)?;
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.clone()).expect("source"));
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name, "path": path.display().to_string() }),
    );
    Some(module.process(&art).expect("process"))
}

macro_rules! run_or_skip {
    ($module:expr, $rel:expr) => {
        match run($module, $rel) {
            Some(out) => out,
            None => return,
        }
    };
}

fn of_type<'a>(arts: &'a [Artifact], ty: &str) -> Vec<&'a Value> {
    arts.iter()
        .filter(|a| a.metadata.get("type").and_then(Value::as_str) == Some(ty))
        .map(|a| &a.metadata)
        .collect()
}

fn one<'a>(arts: &'a [Artifact], ty: &str) -> &'a Value {
    let v = of_type(arts, ty);
    assert_eq!(v.len(), 1, "expected exactly one {ty}, got {}", v.len());
    v[0]
}

fn f(v: &Value, k: &str) -> f64 {
    v[k].as_f64()
        .unwrap_or_else(|| panic!("{k} is not a number: {v}"))
}

// --- HealthKit workouts and sleep --------------------------------------------

const HICKMAN17_HEALTH: &str =
    "hickman_ios17/ffs_selected/fs/filesystem1/private/var/mobile/Library/Health/healthdb_secure.sqlite";
const HICKMAN14_HEALTH: &str =
    "hickman_ios_multi/ios_14_3/fs/private/var/mobile/Library/Health/healthdb_secure.sqlite";

/// UTC seconds of a local wall-clock minute `offset_h` hours behind UTC.
fn local(y: i32, mo: u32, d: u32, h: u32, mi: u32, offset_h: i64) -> i64 {
    let days = {
        // days from civil (Howard Hinnant)
        let y = if mo <= 2 { y - 1 } else { y } as i64;
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let m = mo as i64;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146097 + doe - 719468
    };
    days * 86400 + (h as i64) * 3600 + (mi as i64) * 60 + offset_h * 3600
}

/// The Hickman iOS 17 creation PDF, Fitness (p. 93): date, local start
/// (EDT, UTC-4), activity, total time (mm:ss), distance (mi), average heart
/// rate, active calories. `None` where the PDF and the file disagree and the
/// row is not graded on that column (named on each).
#[allow(clippy::type_complexity)]
const HICKMAN17_FITNESS: &[(
    (i32, u32, u32, u32, u32),
    &str,
    (u32, u32),
    f64,
    Option<f64>,
    Option<f64>,
)] = &[
    (
        (2023, 7, 8, 7, 47),
        "running",
        (25, 29),
        3.03,
        None,
        Some(348.0),
    ),
    (
        (2023, 7, 10, 7, 46),
        "running",
        (25, 17),
        3.06,
        None,
        Some(340.0),
    ),
    (
        (2023, 7, 13, 7, 47),
        "running",
        (25, 28),
        3.04,
        None,
        Some(346.0),
    ),
    (
        (2023, 7, 19, 7, 16),
        "running",
        (25, 51),
        3.03,
        None,
        Some(349.0),
    ),
    // The PDF's 385 kcal is not what the store holds (342.4); graded on the
    // rest of the row.
    ((2023, 7, 24, 7, 58), "running", (25, 24), 3.02, None, None),
    (
        (2023, 7, 24, 8, 24),
        "walking",
        (13, 57),
        0.74,
        None,
        Some(89.0),
    ),
    (
        (2024, 7, 23, 15, 55),
        "running",
        (26, 25),
        3.13,
        Some(169.0),
        Some(374.0),
    ),
    // The PDF lists this walk at 16:37, which is its end (16:21:56 + 15:53).
    (
        (2024, 7, 23, 16, 21),
        "walking",
        (15, 53),
        0.89,
        Some(140.0),
        Some(111.0),
    ),
    (
        (2024, 7, 25, 16, 33),
        "running",
        (25, 31),
        // A recorded workout distance in km, not pi.
        #[allow(clippy::approx_constant)]
        3.14,
        Some(169.0),
        Some(374.0),
    ),
    (
        (2024, 7, 25, 16, 59),
        "walking",
        (20, 36),
        1.19,
        Some(135.0),
        Some(159.0),
    ),
];

#[test]
fn hickman_ios17_workouts_are_the_ones_the_creation_notes_list() {
    let out = run_or_skip!(&HealthKitParser, HICKMAN17_HEALTH);
    let workouts = of_type(&out, "HealthWorkout");
    // The file's own count (`SELECT count(*) FROM workouts`).
    assert_eq!(workouts.len(), 29);
    assert!(workouts.iter().all(|w| w["schema"] == "workout_activities"));
    for ((y, mo, d, h, mi), activity, (mm, ss), miles, hr, kcal) in HICKMAN17_FITNESS {
        let want = local(*y, *mo, *d, *h, *mi, 4);
        let w = workouts
            .iter()
            .find(|w| w["start"].as_i64().is_some_and(|s| (s - want).abs() < 60))
            .unwrap_or_else(|| panic!("no workout starting {y}-{mo}-{d} {h}:{mi} EDT"));
        assert_eq!(w["activity_type_name"], *activity, "{w}");
        assert_eq!(w["location_type_name"], "outdoor", "{w}");
        let dur = f(w, "duration_seconds");
        assert_eq!(dur.floor() as u32, mm * 60 + ss, "{w}");
        let mi_read = f(w, "total_distance_km") / 1.609_344;
        assert!(
            (mi_read - miles).abs() < 0.01,
            "{mi_read} mi vs {miles}: {w}"
        );
        if let Some(hr) = hr {
            assert!((f(w, "heart_rate_avg_bpm") - hr).abs() < 1.0, "{w}");
        }
        if let Some(kcal) = kcal {
            assert!((f(w, "active_energy_kcal") - kcal).abs() < 1.0, "{w}");
        }
        assert_eq!(w["recording_timezone"], "America/New_York");
    }
    let s = one(&out, "HealthKitSummary");
    assert_eq!(s["workouts_decoded"], true);
    assert_eq!(s["workouts"], 29);
    assert_eq!(s["workout_rows"], 29);
}

#[test]
fn hickman_ios17_sleep_samples_are_staged_and_the_watch_nights_match_the_notes() {
    let out = run_or_skip!(&HealthKitParser, HICKMAN17_HEALTH);
    let sleep: Vec<&Value> = of_type(&out, "HealthSample")
        .into_iter()
        .filter(|s| s["data_type"] == 63)
        .collect();
    // The file's own count (`samples WHERE data_type = 63`) and stage split
    // (`category_samples.value`: 375/210/9/46/18/20).
    assert_eq!(sleep.len(), 678);
    let count = |stage: &str| sleep.iter().filter(|s| s["sleep_stage"] == stage).count();
    assert_eq!(count("in_bed"), 375);
    assert_eq!(count("asleep_unspecified"), 210);
    assert_eq!(count("awake"), 9);
    assert_eq!(count("asleep_core"), 46);
    assert_eq!(count("asleep_deep"), 18);
    assert_eq!(count("asleep_rem"), 20);
    // The PDF's nightly totals (Health, p. 94) for three Watch nights, against
    // the Watch's asleep samples ending that local day: 7 h 7 m, 7 h 34 m,
    // 7 h 21 m. Apple's own rollup rounds and merges, so within 3 minutes.
    for ((y, mo, d), minutes) in [
        ((2023, 7, 8), 427.0),
        ((2023, 7, 10), 454.0),
        ((2023, 7, 13), 441.0),
    ] {
        let day_start = local(y, mo, d, 0, 0, 4);
        let asleep: f64 = sleep
            .iter()
            .filter(|s| s["asleep"] == true && s["origin_product_type"] == "Watch4,3")
            .filter(|s| {
                let e = s["end"].as_i64().unwrap();
                e >= day_start && e < day_start + 86_400
            })
            .map(|s| f(s, "duration_seconds") / 60.0)
            .sum();
        assert!(
            (asleep - minutes).abs() <= 3.0,
            "{y}-{mo}-{d}: {asleep} min vs {minutes}"
        );
    }
    let s = one(&out, "HealthKitSummary");
    assert_eq!(s["sleep_samples"], 678);
}

#[test]
fn hickman_ios14_workouts_on_the_pre_ios16_schema_are_the_ones_the_notes_list() {
    let out = run_or_skip!(&HealthKitParser, HICKMAN14_HEALTH);
    let workouts = of_type(&out, "HealthWorkout");
    assert_eq!(workouts.len(), 12);
    assert!(workouts.iter().all(|w| w["schema"] == "workouts"));
    // iOS14-3-ImageCreation, Fitness: EST (UTC-5) start – end.
    for ((y, mo, d, h, mi), (eh, emi), activity) in [
        ((2021, 1, 24, 11, 30), (11, 53), "running"),
        ((2021, 1, 30, 13, 52), (14, 14), "running"),
        ((2021, 1, 30, 14, 15), (14, 28), "walking"),
        ((2021, 2, 6, 15, 24), (15, 40), "walking"),
        ((2021, 2, 17, 14, 27), (14, 39), "running"),
        ((2021, 2, 17, 14, 40), (14, 50), "walking"),
    ] {
        let want = local(y, mo, d, h, mi, 5);
        let w = workouts
            .iter()
            .find(|w| w["start"].as_i64().is_some_and(|s| (s - want).abs() < 60))
            .unwrap_or_else(|| panic!("no workout starting {y}-{mo}-{d} {h}:{mi} EST"));
        assert_eq!(w["activity_type_name"], activity, "{w}");
        let end = local(y, mo, d, eh, emi, 5);
        assert!((w["end"].as_i64().unwrap() - end).abs() < 60, "{w}");
    }
}

// --- Voice Memos -------------------------------------------------------------

const MSAB_VOICE_MEMOS: &str = "msab2026_ios/fs/iPhone12/Volumes/private/var/mobile/Containers/Shared/AppGroup/9CF7ED5D-EEAE-407D-A873-97B3645640DB/Recordings/CloudRecordings.db";
const ABE_VOICE_MEMOS: &str =
    "cellebrite_ctf2023/Abe/fs/outer/filesystem2/mobile/Library/Recordings/CloudRecordings.db";

/// MSAB 2026 iPhone 12 (iOS 18.7), the iOS 17/18 AppGroup location. Graded on
/// the store's own rows (read with `sqlite3`, WAL applied) and the three
/// `.m4a` files beside it; the answer key's "Don't record me" answer comes
/// from a transcription the image does not store, so it is not an oracle.
#[test]
fn msab_ios18_voice_memos_are_the_three_recordings_with_their_audio() {
    let out = run_or_skip!(&VoiceMemosParser, MSAB_VOICE_MEMOS);
    let memos = of_type(&out, "VoiceMemo");
    assert_eq!(memos.len(), 3);
    for (title, file, secs, bytes, dur) in [
        (
            "Flour Bakery + Café",
            "20251219 183652.m4a",
            1_766_187_412,
            169_967,
            19.7295625,
        ),
        (
            "Flour Bakery + Café 2",
            "20251219 183730.m4a",
            1_766_187_450,
            137_074,
            15.7,
        ),
        (
            "Flour Bakery + Café 3",
            "20251219 183800.m4a",
            1_766_187_480,
            136_670,
            15.72575,
        ),
    ] {
        let m = memos
            .iter()
            .find(|m| m["title"] == title)
            .unwrap_or_else(|| panic!("no memo titled {title}"));
        assert_eq!(m["file_name"], file);
        assert_eq!(m["date"], secs, "{m}");
        assert!((f(m, "duration_seconds") - dur).abs() < 1e-6, "{m}");
        assert_eq!(m["audio_present"], true, "{m}");
        assert_eq!(m["audio_bytes"], bytes, "{m}");
    }
    let s = one(&out, "VoiceMemosSummary");
    assert_eq!(s["recordings"], 3);
    assert_eq!(s["audio_present"], 3);
}

/// Cellebrite 2023 CTF "Abe" iPhone X (iOS 16.5), `Library/Recordings`.
/// Graded on the store's own rows. The 31 `.m4a` files are in the image's
/// listing but were not extracted into the corpus, so audio is not graded.
#[test]
fn abe_ios16_voice_memos_are_the_31_recordings_in_their_folders() {
    let out = run_or_skip!(&VoiceMemosParser, ABE_VOICE_MEMOS);
    let memos = of_type(&out, "VoiceMemo");
    assert_eq!(memos.len(), 31);
    let by_id = |id: i64| *memos.iter().find(|m| m["recording_id"] == id).unwrap();
    let first = by_id(1);
    assert_eq!(first["title"], "Seattle-Tacoma International Airport");
    assert_eq!(
        first["path"],
        "/var/mobile/Library/Recordings/20220425 044901-40BEDCA4.m4a"
    );
    assert_eq!(first["file_name"], "20220425 044901-40BEDCA4.m4a");
    assert_eq!(by_id(9)["folder"], "Hidden");
    assert_eq!(by_id(13)["folder"], "Hidden");
    assert_eq!(by_id(14)["folder"], "Huh");
    // One row carries an eviction date, 28 s after it was recorded.
    let evicted: Vec<&&Value> = memos
        .iter()
        .filter(|m| m.get("eviction_date").is_some())
        .collect();
    assert_eq!(evicted.len(), 1);
    assert_eq!(evicted[0]["recording_id"], 29);
    assert_eq!(evicted[0]["eviction_date"], 708_290_170 + 978_307_200);
    assert_eq!(by_id(30)["flags"], 12);
    let s = one(&out, "VoiceMemosSummary");
    assert_eq!(s["recordings"], 31);
    assert_eq!(s["folders"], 2);
    assert_eq!(s["with_eviction_date"], 1);
}

// --- Voicemail audio and transcripts ----------------------------------------

const MAGNET2020_VOICEMAIL: &str =
    "magnet_ctf2020_ios/fs/iOS_Filesystem/private/var/mobile/Library/Voicemail/voicemail.db";

/// Magnet 2020 CTF iPhone (iOS 12.4). No answer key covers voicemail, so this
/// is graded on the artifact's own contents: the five rows, the `.amr`
/// beside each, and each `.transcript` archive's `transcriptionString` read
/// with Python's `plistlib` before the reader existed.
#[test]
fn magnet2020_voicemails_carry_their_audio_and_transcripts_and_the_orphan_is_found() {
    let out = run_or_skip!(&VoicemailParser, MAGNET2020_VOICEMAIL);
    let vms = of_type(&out, "Voicemail");
    assert_eq!(vms.len(), 5);
    for (rowid, sender, bytes, starts, segments) in [
        (
            1,
            "+15188577515",
            8_486,
            "Hey it's Paul is Joe going to see",
            12,
        ),
        (
            2,
            "+15188577515",
            14_246,
            "It's the palms job if you can give me a call buddy",
            24,
        ),
        (
            3,
            "+15184246993",
            40_326,
            "Hey Stephan it's Chris Danielle",
            63,
        ),
        (
            4,
            "+15184246993",
            27_494,
            "Hey Stefan could you give me a call",
            32,
        ),
        (
            6,
            "+18003235000",
            246_982,
            "Hi this is central states pension fun",
            301,
        ),
    ] {
        let v = vms.iter().find(|v| v["rowid"] == rowid).unwrap();
        assert_eq!(v["sender"], sender);
        assert_eq!(v["audio_present"], true, "{v}");
        assert_eq!(v["audio_format"], "amr");
        assert_eq!(v["audio_bytes"], bytes);
        assert!(v["transcript"].as_str().unwrap().starts_with(starts), "{v}");
        assert_eq!(v["transcript_segments"], segments);
    }
    let orphan = one(&out, "VoicemailAudioOrphan");
    assert_eq!(orphan["audio_file"], "5.amr");
    assert_eq!(orphan["audio_bytes"], 234_789);
    let s = one(&out, "VoicemailSummary");
    assert_eq!(s["voicemails"], 5);
    assert_eq!(s["audio_present"], 5);
    assert_eq!(s["transcripts_read"], 5);
    assert_eq!(s["orphan_audio_files"], 1);
}

// --- Deleted notes and note attachments --------------------------------------

const MSAB_NOTES: &str = "msab2026_ios/fs/iPhone12/Volumes/private/var/mobile/Containers/Shared/AppGroup/62B055B5-47BD-47BA-A2CC-C9D74F922777/NoteStore.sqlite";
const MAGNET2021_NOTES: &str = "magnet_ctf2021_ios/fs/private/var/mobile/Containers/Shared/AppGroup/E325D0D4-1ADF-4D35-9CF8-6F7DEBFB2156/NoteStore.sqlite";
const HICKMAN17_NOTES: &str = "hickman_ios17/ffs_selected/fs/filesystem1/private/var/mobile/Containers/Shared/AppGroup/72DA7FCC-4DD6-458D-A328-D7CD7ED267D2/NoteStore.sqlite";

fn note(out: &[Artifact], id: i64) -> &Value {
    of_type(out, "Note")
        .into_iter()
        .find(|n| n["note_id"] == id)
        .unwrap_or_else(|| panic!("no note {id}"))
}

/// MSAB 2026 iPhone 12 (iOS 18.7). Graded on the store's own rows (WAL
/// applied) and the files under `Accounts/` beside it.
#[test]
fn msab_ios18_deleted_note_and_attachments_are_read_with_their_media() {
    let out = run_or_skip!(&NotesParser, MSAB_NOTES);
    // Note 73: untitled, marked for deletion, in Recently Deleted. Note 17 is
    // in Recently Deleted without the mark.
    let n73 = note(&out, 73);
    assert_eq!(n73["deleted"], true);
    assert_eq!(n73["marked_for_deletion"], true);
    assert_eq!(n73["in_recently_deleted"], true);
    assert_eq!(n73["attachments"], 2);
    let n17 = note(&out, 17);
    assert_eq!(n17["deleted"], true);
    assert_eq!(n17["marked_for_deletion"], false);
    assert_eq!(n17["in_recently_deleted"], true);

    let atts = of_type(&out, "NoteAttachment");
    assert_eq!(atts.len(), 11);
    let by = |id: i64| *atts.iter().find(|a| a["attachment_id"] == id).unwrap();
    let png = by(24);
    assert_eq!(png["type_uti"], "public.png");
    assert_eq!(
        png["media_file_name"],
        "Screenshot 2025-12-11 at 4.29.52 PM.png"
    );
    assert_eq!(png["media_present"], true);
    assert_eq!(png["media_bytes"], 83_062);
    assert_eq!(png["deleted"], false);
    // The deleted note's two attachments: marked, their files present and
    // empty.
    for (id, file) in [(74, "IMG_0032.heic"), (76, "Image.jpeg")] {
        let a = by(id);
        assert_eq!(a["deleted"], true, "{a}");
        assert_eq!(a["marked_for_deletion"], true, "{a}");
        assert_eq!(a["media_file_name"], file, "{a}");
        assert_eq!(a["media_bytes"], 0, "{a}");
        assert_eq!(a["media_empty"], true, "{a}");
    }
    // Locked attachments: ciphertext under the media identifier.
    let locked = by(61);
    assert_eq!(locked["password_protected"], true);
    assert_eq!(locked["media_encrypted"], true);
    assert_eq!(locked["media_bytes"], 116_830);
    // Three drawings.
    assert_eq!(
        atts.iter()
            .filter(|a| a["type_uti"] == "com.apple.paper")
            .count(),
        3
    );
    let s = one(&out, "NotesSummary");
    assert_eq!(s["attachments"], 11);
    assert_eq!(s["deleted_attachments"], 2);
    assert_eq!(s["attachment_media_present"], 8);
}

/// Magnet 2021 CTF iPhone 8 (iOS 14): note 10 marked for deletion, and the
/// HEIC attachment of note 17 under `Media/<id>/` with no generation level.
#[test]
fn magnet2021_ios14_deleted_note_and_heic_attachment() {
    let out = run_or_skip!(&NotesParser, MAGNET2021_NOTES);
    let n10 = note(&out, 10);
    assert_eq!(n10["deleted"], true);
    assert_eq!(n10["marked_for_deletion"], true);
    assert_eq!(n10["in_recently_deleted"], true);
    let a = one(&out, "NoteAttachment");
    assert_eq!(a["note_id"], 17);
    assert_eq!(a["type_uti"], "public.heic");
    assert_eq!(a["media_file_name"], "IMG_0003.heic");
    assert_eq!(a["media_present"], true);
    assert_eq!(a["media_bytes"], 866_557);
    let s = one(&out, "NotesSummary");
    assert_eq!(s["deleted_notes"], 1);
}

/// Hickman iOS 17: notes 42 and 43 marked for deletion in Recently Deleted.
#[test]
fn hickman_ios17_two_deleted_notes() {
    let out = run_or_skip!(&NotesParser, HICKMAN17_NOTES);
    for id in [42, 43] {
        let n = note(&out, id);
        assert_eq!(n["deleted"], true, "{n}");
        assert_eq!(n["marked_for_deletion"], true, "{n}");
        assert_eq!(n["in_recently_deleted"], true, "{n}");
    }
    let s = one(&out, "NotesSummary");
    assert_eq!(s["notes"], 14);
    assert_eq!(s["deleted_notes"], 2);
    assert_eq!(s["attachments"], 0);
}
