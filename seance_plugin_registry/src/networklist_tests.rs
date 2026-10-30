//! Which networks this machine was on, and when — measured before it was
//! decoded.
//!
//! # Ground truth
//!
//! `reference/plaso/test_data/SOFTWARE`, a real Windows 7-era hive, walked to
//! `Microsoft\Windows NT\CurrentVersion\NetworkList`. It holds three profiles
//! and three signatures, and every byte in the fixtures below was read out of
//! it:
//!
//! ```text
//! Profiles\{1EDE3981-…}  ProfileName "shieldbase.local"  Managed 1  Category 2  NameType 6
//!     DateCreated       da070b0003000a000b0017002b009f02  = 2010-11-10T11:23:43.671
//!     DateLastConnected dc070400030004000700300027008801  = 2012-04-04T07:48:39.392
//!     key last written (FILETIME, UTC) 129780137193927500 = 2012-04-04T11:48:39.392Z
//! Profiles\{F20C3FC8-…}  ProfileName "Network  2"        Managed 0  Category 1  NameType 6
//!     DateLastConnected dc070300050002000a00290037004900  = 2012-03-02T10:41:55.073
//!     key last written 129751765150733750                 = 2012-03-02T15:41:55.073Z
//! Profiles\{F9642846-…}  ProfileName "Network"           Managed 0  Category 1  NameType 6
//!     DateLastConnected da070b0003000a000b0012003b007701  = 2010-11-10T11:18:59.375
//!     key last written 129338831393750000                 = 2010-11-10T17:18:59.375Z
//! Signatures\Managed\0101…330A    ProfileGuid {1EDE3981-…}  FirstNetwork "shieldbase.local"
//!     DnsSuffix "<none>"  Source 160  DefaultGatewayMac 00:18:f8:ea:2e:a2
//! Signatures\Unmanaged\0101…E0F1  ProfileGuid {F20C3FC8-…}  FirstNetwork "Network  2"
//!     DnsSuffix "<none>"  Source 8    DefaultGatewayMac 00:00:5e:00:01:1d
//! Signatures\Unmanaged\0101…BE73  ProfileGuid {F9642846-…}  FirstNetwork "Network"
//!     DnsSuffix "tx.rr.com"  Source 8 DefaultGatewayMac 00:18:f8:ea:2e:a2
//! ```
//!
//! # The finding that decided the design
//!
//! In all three profiles the `DateLastConnected` SYSTEMTIME and the profile
//! key's own last-written FILETIME agree **to the millisecond** — .392, .073,
//! .375 — and differ by exactly four, five and six hours. Three matching
//! sub-second values are not a coincidence: connecting to a network is what
//! writes the key, so the two record the same instant, and the difference is
//! the machine's offset from UTC. The +5 h in March 2012 and +4 h in April
//! 2012 straddle the United States daylight-saving transition of 11 March
//! 2012, which is what a real machine's offset does.
//!
//! So these values are **local time**, and the offset is measured rather than
//! assumed. A tool that reads them as UTC puts four to six hours on a report.
//!
//! One cross-check outside this key: the gateway MAC `00:18:f8:ea:2e:a2` on
//! two of the signatures is the same address the NLA cache under
//! `NetworkList\Nla\Cache\Intranet` records for interface
//! `{6AAFC9A9-0542-4DB2-8760-CCFFA953737C}` — which is the very interface
//! `netinterfaces_tests` measures its DHCP lease from, in the SYSTEM hive of
//! the same machine.

use super::networklist::*;
use crate::resident::{Anchor, ResidentCapture, ResidentKey, ResidentValue};

fn sz(name: &str, text: &str) -> ResidentValue {
    let mut data: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    data.extend_from_slice(&[0, 0]);
    ResidentValue {
        name: name.into(),
        data_type: None,
        data,
    }
}

fn dword(name: &str, value: u32) -> ResidentValue {
    ResidentValue {
        name: name.into(),
        data_type: None,
        data: value.to_le_bytes().to_vec(),
    }
}

fn binary(name: &str, hex: &str) -> ResidentValue {
    let data = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    ResidentValue {
        name: name.into(),
        data_type: None,
        data,
    }
}

/// The three real profiles, as the resident capture hands them over.
fn profile_keys() -> Vec<ResidentKey> {
    vec![
        ResidentKey {
            key_path: r"ROOT\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{1EDE3981-5784-4C61-B5A7-CF328A10043E}".into(),
            anchor: Anchor::NetworkListProfile {
                guid: "{1EDE3981-5784-4C61-B5A7-CF328A10043E}".into(),
            },
            last_written_filetime: 129_780_137_193_927_500,
            values: vec![
                sz("ProfileName", "shieldbase.local"),
                sz("Description", "shieldbase.local"),
                dword("Managed", 1),
                dword("Category", 2),
                dword("NameType", 6),
                binary("DateCreated", "da070b0003000a000b0017002b009f02"),
                binary("DateLastConnected", "dc070400030004000700300027008801"),
            ],
        },
        ResidentKey {
            key_path: r"ROOT\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{F20C3FC8-1692-44E5-B9B9-55C80CD16774}".into(),
            anchor: Anchor::NetworkListProfile {
                guid: "{F20C3FC8-1692-44E5-B9B9-55C80CD16774}".into(),
            },
            last_written_filetime: 129_751_765_150_733_750,
            values: vec![
                sz("ProfileName", "Network  2"),
                sz("Description", "Network"),
                dword("Managed", 0),
                dword("Category", 1),
                dword("NameType", 6),
                binary("DateCreated", "db070700020005000f001c0016002e02"),
                binary("DateLastConnected", "dc070300050002000a00290037004900"),
            ],
        },
        ResidentKey {
            key_path: r"ROOT\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{F9642846-4369-4D3A-86A4-DE66EC52DF4E}".into(),
            anchor: Anchor::NetworkListProfile {
                guid: "{F9642846-4369-4D3A-86A4-DE66EC52DF4E}".into(),
            },
            last_written_filetime: 129_338_831_393_750_000,
            values: vec![
                sz("ProfileName", "Network"),
                sz("Description", "Network"),
                dword("Managed", 0),
                dword("Category", 1),
                dword("NameType", 6),
                binary("DateCreated", "da070b0003000a000a00160032006d00"),
                binary("DateLastConnected", "da070b0003000a000b0012003b007701"),
            ],
        },
    ]
}

/// The three real signatures.
fn signature_keys() -> Vec<ResidentKey> {
    let managed = "010103000F0000F0A00000000F0000F04877183BBCC1495973365295DA721F30805382CDDD2C3D241D1422F95656330A";
    let unmanaged_two = "010103000F0000F0080000000F0000F029BDFD5F735233873E95F239F6B144561A3D78CDC1FA8F858A74813564A1E0F1";
    let unmanaged_one = "010103000F0000F0080000000F0000F0E9FCA9380AC3E7BA1C8AA7633826DFF8754F01750663898B537F8930291EBE73";
    vec![
        ResidentKey {
            key_path: format!(
                r"ROOT\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{managed}"
            ),
            anchor: Anchor::NetworkListSignature {
                managed: true,
                signature: managed.into(),
            },
            last_written_filetime: 129_338_834_236_718_750,
            values: vec![
                sz("ProfileGuid", "{1EDE3981-5784-4C61-B5A7-CF328A10043E}"),
                sz("Description", "shieldbase.local"),
                dword("Source", 160),
                sz("DnsSuffix", "<none>"),
                sz("FirstNetwork", "shieldbase.local"),
                binary("DefaultGatewayMac", "0018f8ea2ea2"),
            ],
        },
        ResidentKey {
            key_path: format!(
                r"ROOT\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\{unmanaged_two}"
            ),
            anchor: Anchor::NetworkListSignature {
                managed: false,
                signature: unmanaged_two.into(),
            },
            last_written_filetime: 129_543_713_025_742_187,
            values: vec![
                sz("ProfileGuid", "{F20C3FC8-1692-44E5-B9B9-55C80CD16774}"),
                sz("Description", "Network  2"),
                dword("Source", 8),
                sz("DnsSuffix", "<none>"),
                sz("FirstNetwork", "Network  2"),
                binary("DefaultGatewayMac", "00005e00011d"),
            ],
        },
        ResidentKey {
            key_path: format!(
                r"ROOT\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\{unmanaged_one}"
            ),
            anchor: Anchor::NetworkListSignature {
                managed: false,
                signature: unmanaged_one.into(),
            },
            last_written_filetime: 129_338_869_701_093_750,
            values: vec![
                sz("ProfileGuid", "{F9642846-4369-4D3A-86A4-DE66EC52DF4E}"),
                sz("Description", "Network"),
                dword("Source", 8),
                sz("DnsSuffix", "tx.rr.com"),
                sz("FirstNetwork", "Network"),
                binary("DefaultGatewayMac", "0018f8ea2ea2"),
            ],
        },
    ]
}

/// A capture built the way the walk builds one, so the fixtures go through
/// the same door the evidence does.
fn capture(keys: Vec<ResidentKey>) -> ResidentCapture {
    let mut out = ResidentCapture::default();
    for key in keys {
        let index = out
            .begin_key(&key.key_path, key.anchor, key.last_written_filetime)
            .expect("a capture with no cap set");
        for value in key.values {
            out.push_value(index, &value.name, value.data_type, &value.data);
        }
    }
    out
}

fn records() -> Vec<serde_json::Value> {
    let mut keys = profile_keys();
    keys.extend(signature_keys());
    emit(&capture(keys))
}

fn by_name<'a>(records: &'a [serde_json::Value], name: &str) -> &'a serde_json::Value {
    records
        .iter()
        .find(|r| r["profile_name"] == name)
        .unwrap_or_else(|| panic!("no profile named {name}"))
}

// ── What the profiles state ─────────────────────────────────────────────────

/// Every field of the three real profiles, and the kind of network each was.
#[test]
fn the_profiles_of_a_real_hive_are_read_with_their_kind_and_category() {
    let records = records();
    assert_eq!(records.len(), 3, "three profiles, each with its signature");

    let domain = by_name(&records, "shieldbase.local");
    assert_eq!(domain["type"], "NetworkProfile");
    assert_eq!(domain["managed_by_a_domain"], serde_json::json!(true));
    assert_eq!(domain["category"], "domain");
    assert_eq!(domain["category_raw"], 2);
    assert_eq!(domain["network_kind"], "wired");
    assert_eq!(domain["wireless"], serde_json::json!(false));
    assert_eq!(domain["network_name"], "shieldbase.local");
    assert_eq!(domain["dns_suffix"], "<none>");
    assert_eq!(domain["default_gateway_mac"], "00:18:f8:ea:2e:a2");

    let home = by_name(&records, "Network");
    assert_eq!(home["category"], "private");
    assert_eq!(home["managed_by_a_domain"], serde_json::json!(false));
    assert_eq!(
        home["dns_suffix"], "tx.rr.com",
        "the DNS suffix is what the machine was told the network was called"
    );
    assert!(home["statement"]
        .as_str()
        .is_some_and(|s| s.contains("LOCAL time")));
}

// ── The zone, measured rather than assumed ──────────────────────────────────

/// **The offset is measured against the key's own write.** All three profiles
/// agree to the millisecond, and the +5/+4 pair either side of 11 March 2012
/// is a real daylight-saving transition.
#[test]
fn the_local_times_offset_is_measured_against_the_keys_own_write() {
    let records = records();
    for (name, offset, last_connected_utc, created_utc) in [
        (
            "shieldbase.local",
            -240,
            "2012-04-04T11:48:39.392+00:00",
            "2010-11-10T15:23:43.671+00:00",
        ),
        (
            "Network  2",
            -300,
            "2012-03-02T15:41:55.073+00:00",
            "2011-07-05T20:28:22.558+00:00",
        ),
        (
            "Network",
            -360,
            "2010-11-10T17:18:59.375+00:00",
            "2010-11-10T16:22:50.109+00:00",
        ),
    ] {
        let r = by_name(&records, name);
        assert_eq!(
            r["time_zone_basis"], "measured_against_the_keys_own_write",
            "{name}"
        );
        assert_eq!(r["time_zone_offset_minutes"], offset, "{name}");
        assert_eq!(
            r["date_last_connected"], last_connected_utc,
            "{name}: taken from the key's own FILETIME, which is UTC"
        );
        assert_eq!(
            r["date_created"], created_utc,
            "{name}: derived with the measured offset, and labelled as derived"
        );
        assert!(
            r["time_zone_note"]
                .as_str()
                .is_some_and(|n| n.contains("DERIVED")),
            "{name}"
        );
        assert!(r["content_incomplete"].is_null(), "{name}");
    }

    // And the local times as written are on the record whatever the basis,
    // because they are what the evidence states.
    let r = by_name(&records, "shieldbase.local");
    assert_eq!(r["date_last_connected_local"], "2012-04-04T07:48:39.392");
    assert_eq!(r["date_created_local"], "2010-11-10T11:23:43.671");
}

/// **Where the two do not correspond, no instant is claimed.** A date whose
/// zone is unknown is not a date a timeline may carry.
#[test]
fn a_profile_whose_zone_cannot_be_measured_claims_no_instant() {
    let mut keys = profile_keys();
    // Move the key's own write by half a second: the sub-second parts no
    // longer agree, so the two are not the same instant and nothing about the
    // zone follows.
    keys[0].last_written_filetime += 5_000_000;
    let records = emit(&capture(keys));
    let r = by_name(&records, "shieldbase.local");
    assert_eq!(r["time_zone_basis"], "not_decidable");
    assert!(r["date_last_connected"].is_null());
    assert!(r["date_created"].is_null());
    assert_eq!(
        r["date_last_connected_local"], "2012-04-04T07:48:39.392",
        "what the evidence states is still on the record"
    );
    assert_eq!(r["content_incomplete"], serde_json::json!(true));
    assert_eq!(r["content_incomplete_reason"], "unvalidated");
    assert!(r["time_zone_note"]
        .as_str()
        .is_some_and(|n| n.contains("NO INSTANT IS CLAIMED")));

    // A difference no zone offset could be is refused the same way.
    assert_eq!(
        zone_basis(
            SystemTime::parse(&[
                0xda, 0x07, 0x0b, 0x00, 0x03, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x12, 0x00, 0x3b, 0x00,
                0x77, 0x01
            ]),
            129_338_831_393_750_000 + 20 * 3_600 * 10_000_000,
        ),
        ZoneBasis::NotDecidable,
        "twenty hours is not an offset any zone uses"
    );
    assert_eq!(
        zone_basis(None, 129_338_831_393_750_000),
        ZoneBasis::NoLastConnected
    );
}

// ── The join, and the halves that do not join ───────────────────────────────

/// A signature naming a profile this hive does not hold is still evidence of a
/// network the machine recognised: dropping it would lose the SSID and the
/// gateway MAC because the other key is gone.
#[test]
fn a_signature_with_no_profile_is_still_a_record_and_says_what_is_missing() {
    let records = emit(&capture(signature_keys()));
    assert_eq!(records.len(), 3, "three signatures, no profiles");
    for r in &records {
        assert_eq!(r["subtype"], "signature_without_a_profile");
        assert!(r["date_last_connected"].is_null());
        assert_eq!(r["content_incomplete"], serde_json::json!(true));
        assert_eq!(r["content_incomplete_reason"], "unmapped");
        assert!(r["detail"]
            .as_str()
            .is_some_and(|d| d.contains("does not hold")));
    }
    let named: Vec<&str> = records.iter().filter_map(|r| r["name"].as_str()).collect();
    assert!(named.contains(&"shieldbase.local"), "{named:?}");
    assert!(named.contains(&"Network  2"), "{named:?}");
}

/// A profile with no signature says what is therefore not known about it.
#[test]
fn a_profile_with_no_signature_says_what_is_not_known() {
    let records = emit(&capture(profile_keys()));
    let r = by_name(&records, "Network");
    assert!(r["default_gateway_mac"].is_null());
    assert!(r["dns_suffix"].is_null());
    assert!(r["signature_note"]
        .as_str()
        .is_some_and(|n| n.contains("no signature for this profile")));
    // It is still a network the machine was on, with its times.
    assert_eq!(r["date_last_connected"], "2010-11-10T17:18:59.375+00:00");
}

// ── What it refuses ─────────────────────────────────────────────────────────

/// Sixteen bytes are not a date. Every field is checked against what a
/// calendar allows, because a value read from the wrong offset would otherwise
/// be published as a day in the year 65535.
#[test]
fn sixteen_bytes_that_are_not_a_date_are_refused() {
    assert!(SystemTime::parse(&[0xff; 16]).is_none(), "year 65535");
    assert!(SystemTime::parse(&[]).is_none());
    assert!(SystemTime::parse(&[0; 15]).is_none(), "too short");
    // Month 13.
    let mut bytes = [0u8; 16];
    bytes[0..2].copy_from_slice(&2012u16.to_le_bytes());
    bytes[2..4].copy_from_slice(&13u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
    assert!(SystemTime::parse(&bytes).is_none());
    // And the real one reads.
    let good = SystemTime::parse(&[
        0xdc, 0x07, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x07, 0x00, 0x30, 0x00, 0x27, 0x00, 0x88,
        0x01,
    ])
    .expect("the real DateLastConnected");
    assert_eq!(good.as_written(), "2012-04-04T07:48:39.392");
    assert_eq!(good.day_of_week, 3, "a Wednesday, as the value states");
}

/// A `NameType` this build does not name is reported by its number rather than
/// guessed at: the wrong word would put a machine on a wireless network it was
/// never near.
#[test]
fn a_name_type_this_build_does_not_name_is_reported_by_number() {
    let mut keys = profile_keys();
    keys[0].values.retain(|v| v.name != "NameType");
    keys[0].values.push(dword("NameType", 0x99));
    let records = emit(&capture(keys));
    let r = by_name(&records, "shieldbase.local");
    assert_eq!(r["network_kind"], "unknown");
    assert_eq!(r["name_type_raw"], 0x99);
    assert_eq!(r["wireless"], serde_json::json!(false));

    // And the wireless value is named, since that is the one §4.3 is about.
    let mut keys = profile_keys();
    keys[0].values.retain(|v| v.name != "NameType");
    keys[0].values.push(dword("NameType", 0x47));
    let records = emit(&capture(keys));
    let r = by_name(&records, "shieldbase.local");
    assert_eq!(r["network_kind"], "wireless");
    assert_eq!(r["wireless"], serde_json::json!(true));
    assert!(r["wireless_profile_note"]
        .as_str()
        .is_some_and(|n| n.contains("Wlansvc")));
}

/// The key shapes are recognised by their segments, and a key merely named
/// like one is not.
#[test]
fn the_key_shapes_are_recognised_and_look_alikes_are_not() {
    assert_eq!(
        profile_key(
            r"ROOT\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{1EDE3981-5784-4C61-B5A7-CF328A10043E}"
        )
        .as_deref(),
        Some("{1EDE3981-5784-4C61-B5A7-CF328A10043E}")
    );
    assert!(profile_key(r"ROOT\NetworkList\Profiles").is_none());
    assert!(
        profile_key(r"ROOT\Something\Profiles\{1EDE3981-5784-4C61-B5A7-CF328A10043E}").is_none(),
        "a Profiles key under something else is not this"
    );
    assert!(
        profile_key(r"ROOT\NetworkList\Profiles\notaguid").is_none(),
        "a subkey that is not a GUID is not a profile"
    );

    assert_eq!(
        signature_key(r"ROOT\NetworkList\Signatures\Managed\0101ABCD"),
        Some((true, "0101ABCD".to_string()))
    );
    assert_eq!(
        signature_key(r"ROOT\NetworkList\Signatures\Unmanaged\0101ABCD"),
        Some((false, "0101ABCD".to_string()))
    );
    assert!(signature_key(r"ROOT\NetworkList\Signatures\Managed").is_none());
    assert!(
        signature_key(r"ROOT\NetworkList\Signatures\Other\0101ABCD").is_none(),
        "only the two branches Windows writes"
    );
    assert!(
        signature_key(r"ROOT\NetworkList\Signatures\Managed\not-hex").is_none(),
        "a signature is hex"
    );
}

/// A six-byte MAC renders the way every other tool prints one; any other
/// length is not a MAC and is not rendered as one.
#[test]
fn a_gateway_mac_of_the_wrong_length_is_not_rendered_as_one() {
    let mut keys = signature_keys();
    keys[0].values.retain(|v| v.name != "DefaultGatewayMac");
    keys[0].values.push(binary("DefaultGatewayMac", "0018f8"));
    let records = emit(&capture(keys));
    let r = records
        .iter()
        .find(|r| r["name"] == "shieldbase.local")
        .expect("the signature record");
    assert!(r["default_gateway_mac"].is_null());
}
