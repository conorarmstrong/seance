//! Which networks this machine has been on, and **when it was last on them**.
//!
//! `ROADMAP` §4.3's remainder. `seance_plugin_wlan` reads the wireless profiles
//! the WLAN service writes, and those carry no timestamps at all: they say the
//! machine was *configured* to join a network, not that it ever did. This is
//! where the joins are.
//!
//! # The two halves, and the join between them
//!
//! `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList` holds:
//!
//! * `Profiles\{GUID}` — the profile: its name, whether it was managed by a
//!   domain, its firewall category, what **kind** of network it was (wired,
//!   wireless or VPN), and two times: `DateCreated` and `DateLastConnected`.
//! * `Signatures\Managed\<sig>` and `Signatures\Unmanaged\<sig>` — what the
//!   machine recognised the network *by*: the SSID (`FirstNetwork`), the DNS
//!   suffix, and **the default gateway's MAC address**, which is the closest
//!   thing Windows keeps to a fingerprint of a physical place.
//!
//! The two are joined by the signature's `ProfileGuid`. A profile with no
//! signature, and a signature naming a profile this hive does not hold, are
//! both reported as themselves: on a real hive either can happen, and folding
//! them together would invent a network.
//!
//! # The times are LOCAL time, and this measures the offset rather than
//! assuming it
//!
//! `DateCreated` and `DateLastConnected` are 16-byte `SYSTEMTIME` structures
//! with no zone in them, and Windows writes them in **the machine's local
//! time**. A tool that reads them as UTC puts an hour or six on a report.
//!
//! The offset is not assumed here, it is *measured*, because the registry
//! carries the other half of the pair: connecting to a network is what writes
//! the profile key, so the key's own last-written `FILETIME` — which **is**
//! UTC — records the same instant as `DateLastConnected`. Measured on the real
//! Windows 7-era `SOFTWARE` hive in `reference/plaso/test_data`, all three
//! profiles agree to the millisecond and differ by whole hours:
//!
//! | profile | key's own write (UTC) | `DateLastConnected` | difference |
//! |---|---|---|---|
//! | `shieldbase.local` | 2012-04-04T11:48:39.392 | 2012-04-04T07:48:39.392 | +4 h |
//! | `Network  2` | 2012-03-02T15:41:55.073 | 2012-03-02T10:41:55.073 | +5 h |
//! | `Network` | 2010-11-10T17:18:59.375 | 2010-11-10T11:18:59.375 | +6 h |
//!
//! Three matching sub-second values are not a coincidence, and the +5/+4 pair
//! either side of 11 March 2012 is a United States daylight-saving transition,
//! which is what a real machine's offset does. So: where the two correspond,
//! the record states the local time as written, the UTC instant **from the
//! FILETIME itself**, and the offset it measured. Where they do not, it states
//! the local time as written and **claims no instant at all** — a date with an
//! unknown zone is not a date a timeline may carry.
//!
//! `DateCreated` has no FILETIME of its own to pair with. Its UTC is derived
//! with the offset measured at the last connection, and the record says so:
//! if the machine crossed a daylight-saving boundary between creating the
//! profile and last using it, that derivation is out by an hour, and the local
//! time as written is the primary.

use seance_core::io::IncompleteReason;
use serde_json::{json, Value};

/// A `SYSTEMTIME` as the registry holds it: no zone, whole fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemTime {
    pub year: u16,
    pub month: u16,
    pub day_of_week: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub milliseconds: u16,
}

impl SystemTime {
    /// Read the 16 bytes, or refuse them.
    ///
    /// Every field is checked against what a calendar allows, because a
    /// `REG_BINARY` of the right length is not a date: a value read out of the
    /// wrong offset would otherwise be published as a day in the year 65535.
    pub fn parse(bytes: &[u8]) -> Option<SystemTime> {
        let words: Vec<u16> = bytes
            .get(..16)?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let out = SystemTime {
            year: words[0],
            month: words[1],
            day_of_week: words[2],
            day: words[3],
            hour: words[4],
            minute: words[5],
            second: words[6],
            milliseconds: words[7],
        };
        let sane = (1601..=9999).contains(&out.year)
            && (1..=12).contains(&out.month)
            && (1..=31).contains(&out.day)
            && out.day_of_week <= 6
            && out.hour <= 23
            && out.minute <= 59
            && out.second <= 60
            && out.milliseconds <= 999;
        sane.then_some(out)
    }

    /// The written form, with no zone on it, because the value has none.
    pub fn as_written(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.milliseconds
        )
    }

    /// The instant this would be if it were UTC, in milliseconds since the
    /// Unix epoch. Used only to measure the difference against a FILETIME that
    /// **is** UTC; never published as a time.
    pub fn as_if_utc_millis(&self) -> Option<i64> {
        let date = chrono::NaiveDate::from_ymd_opt(
            i32::from(self.year),
            u32::from(self.month),
            u32::from(self.day),
        )?;
        let time = chrono::NaiveTime::from_hms_milli_opt(
            u32::from(self.hour),
            u32::from(self.minute),
            u32::from(self.second).min(59),
            u32::from(self.milliseconds),
        )?;
        Some(date.and_time(time).and_utc().timestamp_millis())
    }
}

/// A `FILETIME` as milliseconds since the Unix epoch. The registry's key
/// timestamps are UTC by definition.
pub fn filetime_millis(filetime: u64) -> Option<i64> {
    // 11644473600 seconds between 1601-01-01 and 1970-01-01.
    let millis = i64::try_from(filetime / 10_000).ok()?;
    millis.checked_sub(11_644_473_600_000)
}

/// Milliseconds since the Unix epoch as RFC 3339 in UTC.
fn millis_to_rfc3339(millis: i64) -> Option<String> {
    chrono::DateTime::from_timestamp_millis(millis).map(|d| d.to_rfc3339())
}

/// How the zone of a profile's `SYSTEMTIME` values was decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZoneBasis {
    /// `DateLastConnected` and the key's own last-written FILETIME record the
    /// same instant, and the difference between them is the machine's offset
    /// from UTC at that moment. The offset is in minutes, positive east.
    MeasuredAgainstTheKeysOwnWrite { offset_minutes: i32 },
    /// The two do not correspond — different sub-second values, or a
    /// difference no zone offset can be — so the local times are published as
    /// written and no instant is claimed.
    NotDecidable,
    /// The profile carries no `DateLastConnected`, so there is nothing to
    /// measure against.
    NoLastConnected,
}

impl ZoneBasis {
    pub fn as_str(&self) -> &'static str {
        match self {
            ZoneBasis::MeasuredAgainstTheKeysOwnWrite { .. } => {
                "measured_against_the_keys_own_write"
            }
            ZoneBasis::NotDecidable => "not_decidable",
            ZoneBasis::NoLastConnected => "no_last_connected_value",
        }
    }

    pub fn offset_minutes(&self) -> Option<i32> {
        match self {
            ZoneBasis::MeasuredAgainstTheKeysOwnWrite { offset_minutes } => Some(*offset_minutes),
            _ => None,
        }
    }
}

/// The largest offset from UTC any zone uses (UTC+14, Kiritimati), and the
/// smallest (UTC-12). A difference outside this is not a zone offset.
const MAX_OFFSET_MINUTES: i64 = 14 * 60;
const MIN_OFFSET_MINUTES: i64 = -12 * 60;

/// Decide the zone by comparing `DateLastConnected` against the key's own
/// last-written FILETIME.
pub fn zone_basis(last_connected: Option<SystemTime>, key_filetime: u64) -> ZoneBasis {
    let Some(last_connected) = last_connected else {
        return ZoneBasis::NoLastConnected;
    };
    let (Some(local_as_utc), Some(written_utc)) = (
        last_connected.as_if_utc_millis(),
        filetime_millis(key_filetime),
    ) else {
        return ZoneBasis::NotDecidable;
    };
    let difference = written_utc - local_as_utc;
    // A whole number of minutes, and one a zone could be. Zones are whole
    // minutes; every offset in use is a multiple of 15, but the check is the
    // looser one because the historical table is not this module's to assert.
    if difference % 60_000 != 0 {
        return ZoneBasis::NotDecidable;
    }
    let minutes = difference / 60_000;
    if !(MIN_OFFSET_MINUTES..=MAX_OFFSET_MINUTES).contains(&minutes) {
        return ZoneBasis::NotDecidable;
    }
    // The offset is how far the local clock is from UTC: local = UTC + offset,
    // and `difference` is UTC - local, so the offset is its negation.
    ZoneBasis::MeasuredAgainstTheKeysOwnWrite {
        offset_minutes: -(minutes as i32),
    }
}

/// What `Category` says the firewall made of the network.
fn category_name(category: u32) -> &'static str {
    match category {
        0 => "public",
        1 => "private",
        2 => "domain",
        _ => "not a category this build names",
    }
}

/// What `NameType` says the network was.
///
/// Three values are documented and named; anything else is reported by its
/// number rather than guessed at, because the wrong word here would put a
/// machine on a wireless network it was never near.
fn name_type_kind(name_type: u32) -> &'static str {
    match name_type {
        0x06 => "wired",
        0x17 => "vpn",
        0x47 => "wireless",
        _ => "unknown",
    }
}

/// One `Signatures\{Managed,Unmanaged}\<sig>` key.
#[derive(Clone, Debug, Default)]
pub struct Signature {
    pub signature: String,
    pub managed_branch: bool,
    pub profile_guid: Option<String>,
    pub description: Option<String>,
    /// The SSID for a wireless network, the network's name otherwise. This is
    /// the field that joins a NetworkList profile to a wireless profile read
    /// from `Wlansvc`.
    pub first_network: Option<String>,
    pub dns_suffix: Option<String>,
    /// The default gateway's MAC address — the closest thing Windows keeps to
    /// a fingerprint of a physical place.
    pub default_gateway_mac: Option<String>,
    pub source: Option<u32>,
    pub key_path: String,
}

/// One `Profiles\{GUID}` key, with the signature that names it where the hive
/// holds one.
#[derive(Clone, Debug, Default)]
pub struct Profile {
    pub profile_guid: String,
    pub profile_name: Option<String>,
    pub description: Option<String>,
    pub managed: Option<bool>,
    pub category: Option<u32>,
    pub name_type: Option<u32>,
    pub date_created: Option<SystemTime>,
    pub date_last_connected: Option<SystemTime>,
    pub key_path: String,
    pub key_last_written_filetime: u64,
    pub signatures: Vec<Signature>,
}

/// The sentence every one of these records carries.
const STATEMENT: &str = concat!(
    "A network this machine has been on, from the NetworkList keys the Network Location ",
    "Awareness service writes. DateLastConnected is the last time it connected to THIS ",
    "network, and DateCreated the first. Both are written in the machine's LOCAL time with no ",
    "zone recorded; where this record carries a UTC instant, the offset was measured against ",
    "the profile key's own last-written timestamp (which is UTC) rather than assumed -- and ",
    "where it carries none, the local time as written is all the evidence states. The gateway ",
    "MAC is what the machine recognised the network by; it identifies a piece of hardware at a ",
    "place, not the place."
);

impl Profile {
    /// The kind of network, by `NameType`.
    pub fn kind(&self) -> &'static str {
        self.name_type.map_or("unknown", name_type_kind)
    }

    /// The SSID or network name the signature carries.
    pub fn network_name(&self) -> Option<String> {
        self.signatures
            .iter()
            .find_map(|s| s.first_network.clone())
            .or_else(|| self.profile_name.clone())
    }

    pub fn to_json(&self) -> Value {
        let basis = zone_basis(self.date_last_connected, self.key_last_written_filetime);
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!("NetworkProfile"));
        m.insert(
            "name".into(),
            json!(self
                .profile_name
                .clone()
                .or_else(|| self.network_name())
                .unwrap_or_else(|| self.profile_guid.clone())),
        );
        m.insert("profile_guid".into(), json!(self.profile_guid));
        m.insert("profile_name".into(), json!(self.profile_name));
        m.insert("description".into(), json!(self.description));
        m.insert("network_name".into(), json!(self.network_name()));
        m.insert("network_kind".into(), json!(self.kind()));
        m.insert("name_type_raw".into(), json!(self.name_type));
        m.insert("managed_by_a_domain".into(), json!(self.managed));
        m.insert("category".into(), json!(self.category.map(category_name)));
        m.insert("category_raw".into(), json!(self.category));
        m.insert("wireless".into(), json!(self.name_type.map(|t| t == 0x47)));

        // The times, as written and — only where the zone was measured — as
        // instants.
        m.insert(
            "date_created_local".into(),
            json!(self.date_created.map(|t| t.as_written())),
        );
        m.insert(
            "date_last_connected_local".into(),
            json!(self.date_last_connected.map(|t| t.as_written())),
        );
        m.insert("time_zone_basis".into(), json!(basis.as_str()));
        m.insert(
            "time_zone_offset_minutes".into(),
            json!(basis.offset_minutes()),
        );
        match basis {
            ZoneBasis::MeasuredAgainstTheKeysOwnWrite { offset_minutes } => {
                // Last connected: the FILETIME itself is the instant, so it is
                // published rather than derived.
                if let Some(instant) =
                    filetime_millis(self.key_last_written_filetime).and_then(millis_to_rfc3339)
                {
                    m.insert("date_last_connected".into(), json!(instant));
                }
                // Created: derived with the offset measured at the last
                // connection, which is an inference and is labelled.
                if let Some(created) = self
                    .date_created
                    .and_then(|t| t.as_if_utc_millis())
                    .map(|local| local - i64::from(offset_minutes) * 60_000)
                    .and_then(millis_to_rfc3339)
                {
                    m.insert("date_created".into(), json!(created));
                }
                m.insert(
                    "time_zone_note".into(),
                    json!(format!(
                        "DateLastConnected ({}) and this key's own last-written timestamp \
                         record the same instant -- connecting is what writes the key -- and \
                         they differ by {} minutes, which is this machine's offset from UTC at \
                         that moment. date_last_connected is taken from the timestamp itself, \
                         so it is exact. date_created is DERIVED by applying the same offset, \
                         and if the machine crossed a daylight-saving boundary between first \
                         and last use it is out by an hour: date_created_local is what the \
                         evidence states.",
                        self.date_last_connected
                            .map(|t| t.as_written())
                            .unwrap_or_default(),
                        offset_minutes
                    )),
                );
            }
            ZoneBasis::NotDecidable | ZoneBasis::NoLastConnected => {
                m.insert(
                    "time_zone_note".into(),
                    json!(
                        "NO INSTANT IS CLAIMED for this profile. Its times are written in the \
                         machine's local time with no zone recorded, and this build could not \
                         measure the offset: either the profile carries no DateLastConnected, \
                         or that value and the key's own last-written timestamp do not record \
                         the same instant. The local times above are what the evidence states; \
                         placing them on a timeline needs the machine's zone from elsewhere \
                         (the TimeZoneInformation key)."
                    ),
                );
                if self.date_created.is_some() || self.date_last_connected.is_some() {
                    m.insert("content_incomplete".into(), json!(true));
                    m.insert(
                        "content_incomplete_reason".into(),
                        json!(IncompleteReason::Unvalidated.as_str()),
                    );
                }
            }
        }

        // What the machine recognised the network by.
        m.insert(
            "signatures".into(),
            json!(self
                .signatures
                .iter()
                .map(Signature::to_json)
                .collect::<Vec<_>>()),
        );
        m.insert(
            "default_gateway_mac".into(),
            json!(self
                .signatures
                .iter()
                .find_map(|s| s.default_gateway_mac.clone())),
        );
        m.insert(
            "dns_suffix".into(),
            json!(self.signatures.iter().find_map(|s| s.dns_suffix.clone())),
        );
        if self.signatures.is_empty() {
            m.insert(
                "signature_note".into(),
                json!(
                    "This hive holds no signature for this profile, so the SSID, the DNS \
                     suffix and the gateway MAC are not known for it. The profile is still a \
                     network this machine was on."
                ),
            );
        }
        m.insert("key_path".into(), json!(self.key_path));
        m.insert(
            "key_last_written".into(),
            json!(filetime_millis(self.key_last_written_filetime).and_then(millis_to_rfc3339)),
        );
        m.insert("statement".into(), json!(STATEMENT));
        m.insert(
            "wireless_profile_note".into(),
            json!(
                "Where network_kind is `wireless`, network_name is the SSID, and the wireless \
                 profile of the same SSID read from ProgramData\\Microsoft\\Wlansvc (a \
                 WifiNetwork record) carries the security and the key. The two are not folded \
                 into one record: one says the machine was configured for a network, this one \
                 says it was on it."
            ),
        );
        Value::Object(m)
    }
}

impl Signature {
    pub fn to_json(&self) -> Value {
        json!({
            "signature": self.signature,
            "branch": if self.managed_branch { "managed" } else { "unmanaged" },
            "profile_guid": self.profile_guid,
            "description": self.description,
            "first_network": self.first_network,
            "dns_suffix": self.dns_suffix,
            "default_gateway_mac": self.default_gateway_mac,
            "source_raw": self.source,
            "key_path": self.key_path,
        })
    }
}

/// Recognise `…\NetworkList\Profiles\{GUID}`, returning the GUID.
pub fn profile_key(key_path: &str) -> Option<String> {
    let parts: Vec<&str> = key_path.split('\\').collect();
    let guid = parts.last()?;
    let parent = parts.get(parts.len().checked_sub(2)?)?;
    let grandparent = parts.get(parts.len().checked_sub(3)?)?;
    (parent.eq_ignore_ascii_case("Profiles")
        && grandparent.eq_ignore_ascii_case("NetworkList")
        && guid.starts_with('{')
        && guid.ends_with('}'))
    .then(|| (*guid).to_string())
}

/// Recognise `…\NetworkList\Signatures\{Managed,Unmanaged}\<sig>`, returning
/// whether it is the managed branch and the signature.
pub fn signature_key(key_path: &str) -> Option<(bool, String)> {
    let parts: Vec<&str> = key_path.split('\\').collect();
    let signature = parts.last()?;
    let branch = parts.get(parts.len().checked_sub(2)?)?;
    let parent = parts.get(parts.len().checked_sub(3)?)?;
    if !parent.eq_ignore_ascii_case("Signatures") {
        return None;
    }
    let managed = if branch.eq_ignore_ascii_case("Managed") {
        true
    } else if branch.eq_ignore_ascii_case("Unmanaged") {
        false
    } else {
        return None;
    };
    // A signature is a long hex string; the branch key itself is not one.
    (!signature.is_empty() && signature.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| (managed, (*signature).to_string()))
}

/// Emit one record per profile, with its signatures joined on, plus one for
/// any signature naming a profile this hive does not hold.
pub fn emit(capture: &crate::resident::ResidentCapture) -> Vec<Value> {
    use crate::resident::Anchor;

    let mut signatures: Vec<Signature> = Vec::new();
    for key in capture.keys_matching(|a| matches!(a, Anchor::NetworkListSignature { .. })) {
        let Anchor::NetworkListSignature { managed, signature } = &key.anchor else {
            continue;
        };
        let sz = |name: &str| value_sz(key, name);
        signatures.push(Signature {
            signature: signature.clone(),
            managed_branch: *managed,
            profile_guid: sz("ProfileGuid"),
            description: sz("Description"),
            first_network: sz("FirstNetwork"),
            dns_suffix: sz("DnsSuffix"),
            default_gateway_mac: value_mac(key, "DefaultGatewayMac"),
            source: value_dword(key, "Source"),
            key_path: key.key_path.clone(),
        });
    }

    let mut out = Vec::new();
    let mut claimed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for key in capture.keys_matching(|a| matches!(a, Anchor::NetworkListProfile { .. })) {
        let Anchor::NetworkListProfile { guid } = &key.anchor else {
            continue;
        };
        if key.values.is_empty() {
            continue;
        }
        let mine: Vec<Signature> = signatures
            .iter()
            .filter(|s| {
                s.profile_guid
                    .as_deref()
                    .is_some_and(|g| g.eq_ignore_ascii_case(guid))
            })
            .cloned()
            .collect();
        for signature in &mine {
            claimed.insert(signature.signature.clone());
        }
        let profile = Profile {
            profile_guid: guid.clone(),
            profile_name: value_sz(key, "ProfileName"),
            description: value_sz(key, "Description"),
            managed: value_dword(key, "Managed").map(|v| v != 0),
            category: value_dword(key, "Category"),
            name_type: value_dword(key, "NameType"),
            date_created: value_systemtime(key, "DateCreated"),
            date_last_connected: value_systemtime(key, "DateLastConnected"),
            key_path: key.key_path.clone(),
            key_last_written_filetime: key.last_written_filetime,
            signatures: mine,
        };
        out.push(profile.to_json());
    }

    // A signature naming a profile this hive does not hold is evidence of a
    // network the machine recognised; dropping it would lose the SSID and the
    // gateway MAC because the other key is gone.
    for signature in signatures
        .iter()
        .filter(|s| !claimed.contains(&s.signature))
    {
        let mut m = json!({
            "type": "NetworkProfile",
            "subtype": "signature_without_a_profile",
            "name": signature
                .first_network
                .clone()
                .or_else(|| signature.description.clone())
                .unwrap_or_else(|| signature.signature.clone()),
            "network_name": signature.first_network,
            "profile_guid": signature.profile_guid,
            "signatures": [signature.to_json()],
            "default_gateway_mac": signature.default_gateway_mac,
            "dns_suffix": signature.dns_suffix,
            "key_path": signature.key_path,
            "statement": STATEMENT,
        });
        let detail = format!(
            "This is a network signature whose ProfileGuid ({}) names a profile key this hive \
             does not hold, so there is no DateCreated and no DateLastConnected for it: the \
             machine recognised this network and when it was on it is not in this evidence. \
             The profile may have been deleted, or be in a hive that was not captured.",
            signature.profile_guid.as_deref().unwrap_or("absent")
        );
        if let Some(map) = m.as_object_mut() {
            map.insert("detail".into(), json!(detail));
            map.insert("content_incomplete".into(), json!(true));
            map.insert(
                "content_incomplete_reason".into(),
                json!(IncompleteReason::Unmapped.as_str()),
            );
            map.insert("content_incomplete_detail".into(), json!(detail));
        }
        out.push(m);
    }
    out
}

fn value_sz(key: &crate::resident::ResidentKey, name: &str) -> Option<String> {
    key.values
        .iter()
        .find(|v| v.name.eq_ignore_ascii_case(name))
        .map(|v| utf16le(&v.data))
        .filter(|s| !s.is_empty())
}

fn value_dword(key: &crate::resident::ResidentKey, name: &str) -> Option<u32> {
    key.values
        .iter()
        .find(|v| v.name.eq_ignore_ascii_case(name))
        .and_then(|v| v.data.get(..4))
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
}

fn value_systemtime(key: &crate::resident::ResidentKey, name: &str) -> Option<SystemTime> {
    key.values
        .iter()
        .find(|v| v.name.eq_ignore_ascii_case(name))
        .and_then(|v| SystemTime::parse(&v.data))
}

/// A six-byte MAC in the form every other tool prints. Any other length is not
/// a MAC and is not rendered as one.
fn value_mac(key: &crate::resident::ResidentKey, name: &str) -> Option<String> {
    let bytes = key
        .values
        .iter()
        .find(|v| v.name.eq_ignore_ascii_case(name))
        .map(|v| v.data.clone())?;
    (bytes.len() == 6).then(|| {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    })
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}
