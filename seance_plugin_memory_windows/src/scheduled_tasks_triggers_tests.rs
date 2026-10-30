//! The TaskCache `Triggers` blob: the header, the job bucket, and one record
//! per trigger by magic, bounded by the blob's own lengths.
//!
//! The first test decodes the real `\SeanceTestBeacon` blob, copied byte for
//! byte from the in-memory SOFTWARE hive of the Windows 11 26200 capture (the
//! task `plant-artifacts.ps1` created with `/sc hourly`). The rest are
//! synthetic blobs built to the layout, and pin mechanism only.

use super::scheduled_tasks_triggers::*;

/// `\SeanceTestBeacon`'s `Triggers` value on the 26200 capture.
const BEACON: &str = "1700000000000000010708000000060000109747df25dd010007080000000600ffffffffffffffff3821414248484848246d2ea6484848480e0000004848484841007500740068006f0072000000484800000000484848480048484848484848004848484848484801000000484848481c0000004848484801050000000000051500000011a01308918a05611c5ccdc9e8030000484848482a0000004848484846004f00520045004e005300490043002d005700310031005c0061006e0061006c0079007300740000004848484848482c0000004848484858020000100e000080f40300ffffffff0700000000000000000000000000000000000000000000000000000048484848dddd000000000000010708000000060000109747df25dd010000000000000000000000000000000000000000000000000000000000000000100e000000000000ffffffff000000000000000000000000000100000100000000000000490200000000000048484848";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// A little writer for the blob's aligned fields.
#[derive(Default)]
struct Blob(Vec<u8>);

impl Blob {
    fn pad(&mut self, of: usize) -> &mut Self {
        let pad = (8 - of % 8) % 8;
        self.0.extend(std::iter::repeat_n(0x48, pad));
        self
    }
    fn aligned_u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self.0.extend([0x48; 7]);
        self
    }
    fn aligned_u32(&mut self, v: u32) -> &mut Self {
        self.0.extend(v.to_le_bytes());
        self.0.extend([0x48; 4]);
        self
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend(v.to_le_bytes());
        self
    }
    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    fn time(&mut self, localized: bool, filetime: u64) -> &mut Self {
        self.aligned_u8(u8::from(localized));
        self.0.extend(filetime.to_le_bytes());
        self
    }
    /// A length-prefixed UTF-16 string with its terminator, padded.
    fn aligned_bstr(&mut self, text: &str) -> &mut Self {
        let mut units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        if !text.is_empty() {
            units.extend([0, 0]);
        }
        self.aligned_u32(units.len() as u32);
        let n = units.len();
        self.bytes(&units).pad(n)
    }
    /// A character-counted string, terminated and padded.
    fn expand_str(&mut self, text: &str) -> &mut Self {
        let chars = text.encode_utf16().count() as u32;
        self.aligned_u32(chars);
        if chars == 0 {
            return self;
        }
        let mut units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        units.extend([0, 0]);
        let n = units.len();
        self.bytes(&units).pad(n)
    }
    /// The trigger's id: a four-byte length, the string, padded counting the length.
    fn id(&mut self, text: &str) -> &mut Self {
        let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        self.u32(units.len() as u32);
        let n = units.len() + 4;
        self.bytes(&units).pad(n)
    }
    /// A version 0x17 header and a job bucket with no user and no settings.
    fn header() -> Blob {
        let mut b = Blob::default();
        b.aligned_u8(0x17)
            .time(true, START)
            .time(false, u64::MAX)
            .aligned_u32(0x4000_0000)
            .aligned_u32(0x1234_5678)
            .aligned_bstr("Author")
            .aligned_bstr("")
            .aligned_u8(1) // skip the user
            .aligned_u32(0); // no optional settings
        b
    }
    /// The generic trigger body.
    fn generic(&mut self, interval: u32, enabled: bool, id: &str) -> &mut Self {
        self.time(true, START)
            .time(false, 0)
            .u32(30) // delay
            .u32(u32::MAX) // timeout
            .u32(interval)
            .u32(0)
            .u32(0)
            .bytes(&[0, 0, 0, 0])
            .aligned_u8(u8::from(enabled))
            .bytes(&[0; 8])
            .id(id)
    }
}

/// 2026-08-06 20:08:00 as a FILETIME.
const START: u64 = 0x01dd_25df_4797_1000;

/// **The planted hourly task is decoded**: one time trigger, starting at the
/// wall-clock time `schtasks` wrote, repeating every hour (PT1H), enabled.
#[test]
fn a_time_trigger_with_hourly_repetition_is_decoded() {
    let out = decode_triggers(&hex(BEACON)).expect("decodes");
    assert_eq!(out.version, 0x17);
    assert!(out.stopped.is_none(), "{:?}", out.stopped);
    assert_eq!(out.principal_id.as_deref(), Some("Author"));
    assert_eq!(out.user.as_deref(), Some("FORENSIC-W11\\analyst"));
    assert_eq!(
        out.user_sid.as_deref(),
        Some("S-1-5-21-135503889-1627753105-3385678876-1000")
    );
    assert_eq!(out.triggers.len(), 1);
    let t = &out.triggers[0];
    assert_eq!(t.kind.name(), "time");
    assert_eq!(
        t.kind,
        TriggerKind::Time {
            schedule: "once".into(),
            data: [0, 0, 0]
        }
    );
    let start = t.start.as_ref().expect("a start boundary");
    assert!(start.localized);
    assert_eq!(start.filetime, START);
    assert_eq!(start.text, "2026-08-06T20:08:00");
    assert!(t.end.is_none());
    assert_eq!(t.repetition_interval_seconds, 3600);
    assert_eq!(t.repetition_duration_seconds, 0);
    assert!(t.enabled);
    assert_eq!(t.id.as_deref(), Some(""));
    let json = out.to_json();
    assert_eq!(json["triggers"][0]["kind"], "time");
    assert_eq!(json["triggers"][0]["repetition_interval"], "PT1H");
    assert_eq!(json["triggers"][0]["start"]["localized"], true);
}

/// **A boot and a logon trigger are decoded, in the order the blob holds
/// them**, each with its own enabled flag and delay.
#[test]
fn a_boot_and_a_logon_trigger_are_decoded_in_order() {
    let mut b = Blob::header();
    b.aligned_u32(0xFFFF).generic(0, true, "Boot1");
    b.aligned_u32(0xAAAA)
        .generic(0, false, "")
        .aligned_u8(0) // a user
        .aligned_u8(1) // no SID
        .aligned_bstr("DOMAIN\\someone");
    let out = decode_triggers(&b.0).expect("decodes");
    assert!(out.stopped.is_none(), "{:?}", out.stopped);
    let kinds: Vec<&str> = out.triggers.iter().map(|t| t.kind.name()).collect();
    assert_eq!(kinds, ["boot", "logon"]);
    assert_eq!(out.triggers[0].id.as_deref(), Some("Boot1"));
    assert!(out.triggers[0].enabled);
    assert_eq!(out.triggers[0].delay_seconds, Some(30));
    assert!(!out.triggers[1].enabled);
    assert_eq!(
        out.triggers[1].kind,
        TriggerKind::Logon {
            user: Some("DOMAIN\\someone".into())
        }
    );
}

/// **A trigger kind this decoder does not know stops the decode**, with the
/// kind, where it was and how many bytes were left, and what came before it
/// kept. It is never guessed at.
#[test]
fn an_unknown_trigger_kind_stops_the_decode_and_is_reported() {
    let mut b = Blob::header();
    b.aligned_u32(0xEEEE).generic(0, true, "");
    let at = b.0.len();
    b.aligned_u32(0xBBBB).bytes(&[0; 40]);
    let out = decode_triggers(&b.0).expect("the header decodes");
    assert_eq!(out.triggers.len(), 1);
    assert_eq!(out.triggers[0].kind, TriggerKind::Idle);
    let stop = out.stopped.as_ref().expect("stopped");
    assert!(stop.contains("0xbbbb"), "{stop}");
    assert!(stop.contains(&format!("byte {at}")), "{stop}");
    assert!(
        stop.contains(&format!("{} byte(s)", b.0.len() - at)),
        "{stop}"
    );
    assert!(!out.is_whole());
}

/// **A record that runs past the blob is refused, not truncated** into a
/// plausible trigger.
#[test]
fn a_trigger_record_that_runs_past_the_blob_is_refused() {
    let mut b = Blob::header();
    b.aligned_u32(0xFFFF).generic(0, true, "");
    let whole = b.0.len();
    b.aligned_u32(0xFFFF).generic(0, true, "");
    let cut = &b.0[..b.0.len() - 12];
    let out = decode_triggers(cut).expect("the header decodes");
    assert_eq!(out.triggers.len(), 1, "only the whole record is kept");
    let stop = out.stopped.as_ref().expect("stopped");
    assert!(stop.contains("runs past"), "{stop}");
    assert!(stop.contains(&format!("byte {whole}")), "{stop}");

    // A header cut short is refused outright.
    assert!(decode_triggers(&b.0[..20]).is_err());
    // A version this decoder has not seen is refused, not guessed at.
    let mut other = Blob::header().0;
    other[0] = 0x19;
    assert!(decode_triggers(&other).unwrap_err().contains("0x19"));
}

/// **A zero boundary is absent, not 1601**, and so is the all-ones "no end".
#[test]
fn a_zero_boundary_is_absent_not_1601() {
    let mut b = Blob::header();
    b.aligned_u32(0x8888).generic(0, true, "");
    let out = decode_triggers(&b.0).expect("decodes");
    assert!(out.end_boundary.is_none(), "all ones is no end");
    let t = &out.triggers[0];
    assert_eq!(t.kind, TriggerKind::Registration);
    assert!(t.end.is_none(), "zero is no end");
    assert!(!out.to_json().to_string().contains("1601"));
}

/// **An event trigger carries its subscription text** and its value queries,
/// and a WNF trigger's data is not padded -- the next record follows it
/// directly, which the 26200 capture showed.
#[test]
fn an_event_trigger_carries_its_subscription_text() {
    let query = "<QueryList><Query Id=\"0\"><Select Path=\"System\">*[System[EventID=1]]</Select></Query></QueryList>";
    let mut b = Blob::header();
    b.aligned_u32(0x6666)
        .generic(0, true, "")
        .bytes(&[0x75, 0x10, 0xbc, 0xa3, 0x2f, 0x01, 0x89, 0x15])
        .aligned_u32(1)
        .bytes(&[1]);
    b.aligned_u32(0xCCCC)
        .generic(0, true, "")
        .expand_str(query)
        .u32(0)
        .u32(0)
        .expand_str("")
        .aligned_u32(1)
        .expand_str("Name")
        .expand_str("Event/EventData/Data[@Name='x']");
    let out = decode_triggers(&b.0).expect("decodes");
    assert!(out.stopped.is_none(), "{:?}", out.stopped);
    assert_eq!(out.triggers.len(), 2);
    assert_eq!(
        out.triggers[0].kind,
        TriggerKind::Wnf {
            state_name: "7510bca32f018915".into(),
            data_length: 1
        }
    );
    assert_eq!(
        out.triggers[1].kind,
        TriggerKind::Event {
            subscription: query.into(),
            value_queries: vec![("Name".into(), "Event/EventData/Data[@Name='x']".into())],
        }
    );
}
