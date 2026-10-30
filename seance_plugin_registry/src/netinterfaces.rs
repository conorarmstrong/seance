//! Per-interface network configuration: address, DHCP server, and the lease.
//!
//! `ROADMAP` §2.6, question 9 of the NIST CFReDS Data Leakage key. The machine's
//! DNS domain was read; nothing read the per-interface configuration under
//! `Tcpip\Parameters\Interfaces\{GUID}`, so "what address did this machine
//! have, and from which server" had no answer.
//!
//! # The lease times, and why they are checked rather than converted
//!
//! `LeaseObtainedTime`, `T1`, `T2` and `LeaseTerminatesTime` are `REG_DWORD`s,
//! and **what they count is not fixed across machines.** On the real Windows 7
//! hive in `reference/` they are Unix seconds; on a Windows 10 image examined
//! while this was planned, the same field held `812456`, which is not a Unix
//! time at all.
//!
//! So a value is presented as a time only when the lease's own arithmetic
//! agrees that it is one:
//!
//! ```text
//! LeaseObtainedTime + Lease == LeaseTerminatesTime
//! ```
//!
//! On the Windows 7 hive that is `1289408803 + 540000 == 1289948803`, exactly,
//! with `T1` at half the lease and `T2` at seven-eighths — the standard DHCP
//! renewal points. Four independent values agreeing is a basis. A value that
//! fails the check is published as the **number it is**, with a sentence saying
//! it does not decode as a time here, because presenting a boot-relative
//! counter as a date in 1970 would put a wrong day on a report.
//!
//! # What is deliberately out of scope
//!
//! `Tcpip6`. Its value set is entirely disjoint — `Dhcpv6Iaid`,
//! `Dhcpv6InformationObtainedTime` and the rest — and the roadmap bullet this
//! implements names the DHCP address, server, domain and lease times only. The
//! record says the IPv6 side was not read, rather than leaving its absence to
//! read as an absence of IPv6 configuration.

use seance_core::io::IncompleteReason;
use serde_json::{json, Value};

/// How a lease time was decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseBasis {
    /// The lease arithmetic agrees these are Unix seconds.
    UnixSecondsConfirmedByLeaseArithmetic,
    /// The arithmetic does not agree, so the values are published as numbers.
    NotDecodable,
    /// There is no lease: the interface is statically configured, or DHCP never
    /// completed. All four fields are zero.
    NoLease,
}

impl LeaseBasis {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnixSecondsConfirmedByLeaseArithmetic => {
                "unix_seconds_confirmed_by_lease_arithmetic"
            }
            Self::NotDecodable => "not_decodable_as_a_time",
            Self::NoLease => "no_lease_recorded",
        }
    }
}

/// One interface's configuration.
#[derive(Clone, Debug, Default)]
pub struct NetworkInterface {
    pub interface_guid: String,
    pub control_set: Option<String>,
    pub dhcp_enabled: Option<bool>,
    pub ip_addresses: Vec<String>,
    pub subnet_masks: Vec<String>,
    pub default_gateways: Vec<String>,
    pub dhcp_server: Option<String>,
    pub name_servers: Option<String>,
    pub domain: Option<String>,
    /// The address, mask, gateway, name servers and domain the DHCP server
    /// **handed out**, from the `Dhcp`-prefixed values. A DHCP-configured
    /// interface leaves `IPAddress`, `SubnetMask`, `DefaultGateway`,
    /// `NameServer` and `Domain` empty and holds its lease here, so reading the
    /// static names alone reports a machine that had an address as one with
    /// none (`ROADMAP` §2.6, key question 9, found on the Data Leakage image).
    pub dhcp_ip_addresses: Vec<String>,
    pub dhcp_subnet_masks: Vec<String>,
    pub dhcp_default_gateways: Vec<String>,
    pub dhcp_name_servers: Option<String>,
    pub dhcp_domain: Option<String>,
    pub lease_seconds: Option<u32>,
    pub lease_obtained_raw: Option<u32>,
    pub lease_terminates_raw: Option<u32>,
    pub t1_raw: Option<u32>,
    pub t2_raw: Option<u32>,
    pub key_path: String,
    pub key_last_written: Option<String>,
}

/// Decide whether the lease fields are Unix seconds, by their own arithmetic.
pub fn lease_basis(
    obtained: Option<u32>,
    lease: Option<u32>,
    terminates: Option<u32>,
) -> LeaseBasis {
    match (obtained, lease, terminates) {
        // All zero: no lease. A static interface, or DHCP that never completed.
        (Some(0), Some(0), Some(0)) | (Some(0), None, Some(0)) => LeaseBasis::NoLease,
        (Some(o), Some(l), Some(t)) if o != 0 && o.checked_add(l) == Some(t) => {
            LeaseBasis::UnixSecondsConfirmedByLeaseArithmetic
        }
        _ => LeaseBasis::NotDecodable,
    }
}

/// Unix seconds to RFC 3339, refusing the zero and negative sentinels.
///
/// Declared here rather than borrowed from `seance_api::system_info`, which
/// has its own private copy: a plugin cannot depend on the API crate, and this
/// is four lines.
fn unix_to_rfc3339(secs: u32) -> Option<String> {
    if secs == 0 {
        return None;
    }
    chrono::DateTime::from_timestamp(secs as i64, 0).map(|d| d.to_rfc3339())
}

impl NetworkInterface {
    pub fn to_json(&self) -> Value {
        let basis = lease_basis(
            self.lease_obtained_raw,
            self.lease_seconds,
            self.lease_terminates_raw,
        );
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!("NetworkInterface"));
        m.insert(
            "name".into(),
            json!(self
                .ip_addresses
                .first()
                .or_else(|| self.dhcp_ip_addresses.first())
                .cloned()
                .unwrap_or_else(|| self.interface_guid.clone())),
        );
        m.insert("interface_guid".into(), json!(self.interface_guid));
        m.insert("control_set".into(), json!(self.control_set));
        m.insert("dhcp_enabled".into(), json!(self.dhcp_enabled));
        m.insert("ip_addresses".into(), json!(self.ip_addresses));
        m.insert("subnet_masks".into(), json!(self.subnet_masks));
        m.insert("default_gateways".into(), json!(self.default_gateways));
        m.insert("dhcp_server".into(), json!(self.dhcp_server));
        m.insert("name_servers".into(), json!(self.name_servers));
        m.insert("domain".into(), json!(self.domain));
        m.insert("dhcp_ip_addresses".into(), json!(self.dhcp_ip_addresses));
        m.insert("dhcp_subnet_masks".into(), json!(self.dhcp_subnet_masks));
        m.insert(
            "dhcp_default_gateways".into(),
            json!(self.dhcp_default_gateways),
        );
        m.insert("dhcp_name_servers".into(), json!(self.dhcp_name_servers));
        m.insert("dhcp_domain".into(), json!(self.dhcp_domain));
        m.insert("lease_seconds".into(), json!(self.lease_seconds));
        m.insert("lease_time_basis".into(), json!(basis.as_str()));
        // The raw numbers are always published, whatever the basis: they are
        // what the registry holds, and a reader checking this build's reading
        // needs them.
        m.insert("lease_obtained_raw".into(), json!(self.lease_obtained_raw));
        m.insert(
            "lease_terminates_raw".into(),
            json!(self.lease_terminates_raw),
        );
        m.insert("t1_raw".into(), json!(self.t1_raw));
        m.insert("t2_raw".into(), json!(self.t2_raw));

        match basis {
            LeaseBasis::UnixSecondsConfirmedByLeaseArithmetic => {
                for (field, raw) in [
                    ("lease_obtained", self.lease_obtained_raw),
                    ("lease_terminates", self.lease_terminates_raw),
                    ("lease_renew_t1", self.t1_raw),
                    ("lease_renew_t2", self.t2_raw),
                ] {
                    if let Some(t) = raw.filter(|r| *r != 0).and_then(unix_to_rfc3339) {
                        m.insert(field.into(), json!(t));
                    }
                }
                m.insert(
                    "lease_time_note".into(),
                    json!(format!(
                        "These four values are presented as Unix seconds because the lease's \
                         own arithmetic agrees: obtained + lease ({} + {}) equals terminates \
                         ({}). What these fields count is not fixed across Windows versions, \
                         so the check is made per interface rather than assumed.",
                        self.lease_obtained_raw.unwrap_or(0),
                        self.lease_seconds.unwrap_or(0),
                        self.lease_terminates_raw.unwrap_or(0)
                    )),
                );
            }
            LeaseBasis::NoLease => {
                m.insert(
                    "lease_time_note".into(),
                    json!(
                        "This interface records no lease: the obtained, terminates and \
                           duration fields are all zero. It is statically configured, or DHCP \
                           never completed on it. That is not a lease whose times are \
                           unknown."
                    ),
                );
            }
            LeaseBasis::NotDecodable => {
                // Published as numbers, never as dates. A boot-relative
                // counter rendered as a 1970 date puts a wrong day on a report.
                m.insert(
                    "lease_time_note".into(),
                    json!(format!(
                        "The lease fields are published as the numbers they are and NOT as \
                         times. Their arithmetic does not agree that they are Unix seconds -- \
                         obtained + lease ({} + {}) does not equal terminates ({}) -- and on \
                         some Windows versions these fields hold a boot-relative counter. \
                         Rendering one as a date would put a wrong day on a report.",
                        self.lease_obtained_raw
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "absent".into()),
                        self.lease_seconds
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "absent".into()),
                        self.lease_terminates_raw
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "absent".into())
                    )),
                );
                m.insert("content_incomplete".into(), json!(true));
                m.insert(
                    "content_incomplete_reason".into(),
                    json!(IncompleteReason::Unvalidated.as_str()),
                );
            }
        }
        m.insert("key_path".into(), json!(self.key_path));
        m.insert("key_last_written".into(), json!(self.key_last_written));
        // IPv6 is a separate tree with a disjoint value set and is not read.
        m.insert(
            "ipv6_not_read".into(),
            json!(
                "This record is the IPv4 configuration under Tcpip. The Tcpip6 tree holds a \
                   different set of values and is not read by this build, so nothing here is \
                   evidence about this interface's IPv6 configuration either way."
            ),
        );
        Value::Object(m)
    }
}

/// Recognise a `Tcpip\Parameters\Interfaces\{GUID}` key, returning its control
/// set and GUID.
///
/// **`Tcpip6` is deliberately not matched.** Its value set is disjoint and the
/// roadmap bullet this implements names the IPv4 DHCP fields only; matching it
/// here would produce records whose every field is absent.
pub fn interface_key(key_path: &str) -> Option<(String, String)> {
    let segments: Vec<&str> = key_path.split('\\').filter(|s| !s.is_empty()).collect();
    let lower: Vec<String> = segments.iter().map(|s| s.to_ascii_lowercase()).collect();
    let ifaces = lower.iter().position(|s| s == "interfaces")?;
    // `…\Services\Tcpip\Parameters\Interfaces\{GUID}` — and `tcpip`, exactly,
    // never `tcpip6`.
    if lower.get(ifaces.checked_sub(1)?)? != "parameters" {
        return None;
    }
    if lower.get(ifaces.checked_sub(2)?)? != "tcpip" {
        return None;
    }
    if lower.len() != ifaces + 2 {
        return None;
    }
    let guid = segments.get(ifaces + 1)?;
    if !(guid.starts_with('{') && guid.ends_with('}')) {
        return None;
    }
    let control_set = lower
        .iter()
        .enumerate()
        .find(|(_, s)| s.starts_with("controlset") || *s == "currentcontrolset")
        .map(|(i, _)| segments[i].to_string())
        .unwrap_or_else(|| "(unknown control set)".to_string());
    Some((control_set, guid.to_string()))
}

/// Turn the walk's capture into interface records.
pub fn emit(capture: &crate::resident::ResidentCapture) -> Vec<Value> {
    use crate::resident::Anchor;

    let mut out = Vec::new();
    for key in capture.keys_matching(|a| matches!(a, Anchor::NetworkInterface { .. })) {
        let Anchor::NetworkInterface { control_set, guid } = &key.anchor else {
            continue;
        };
        // An interface key with no values at all is one the machine has a GUID
        // for and no configuration under -- a real shape on the Windows 7 hive,
        // and not a record worth emitting.
        if key.values.is_empty() {
            continue;
        }
        let sz = |name: &str| {
            key.values
                .iter()
                .find(|v| v.name.eq_ignore_ascii_case(name))
                .map(|v| utf16le(&v.data))
                .filter(|s| !s.is_empty())
        };
        let dword = |name: &str| {
            key.values
                .iter()
                .find(|v| v.name.eq_ignore_ascii_case(name))
                .and_then(|v| v.data.get(..4))
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
        };
        let multi = |name: &str| {
            key.values
                .iter()
                .find(|v| v.name.eq_ignore_ascii_case(name))
                .map(|v| utf16le_multi(&v.data))
                .unwrap_or_default()
        };
        let iface = NetworkInterface {
            interface_guid: guid.clone(),
            control_set: Some(control_set.clone()),
            dhcp_enabled: dword("EnableDHCP").map(|v| v != 0),
            ip_addresses: multi("IPAddress"),
            subnet_masks: multi("SubnetMask"),
            default_gateways: multi("DefaultGateway"),
            dhcp_server: sz("DhcpServer"),
            name_servers: sz("NameServer"),
            domain: sz("Domain"),
            dhcp_ip_addresses: multi("DhcpIPAddress"),
            dhcp_subnet_masks: multi("DhcpSubnetMask"),
            dhcp_default_gateways: multi("DhcpDefaultGateway"),
            dhcp_name_servers: sz("DhcpNameServer"),
            dhcp_domain: sz("DhcpDomain"),
            lease_seconds: dword("Lease"),
            lease_obtained_raw: dword("LeaseObtainedTime"),
            lease_terminates_raw: dword("LeaseTerminatesTime"),
            t1_raw: dword("T1"),
            t2_raw: dword("T2"),
            key_path: key.key_path.clone(),
            key_last_written: seance_core::time::filetime_to_rfc3339(key.last_written_filetime),
        };
        out.push(iface.to_json());
    }
    out
}

/// A `REG_SZ` body: UTF-16LE, NUL-terminated.
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

/// A `REG_MULTI_SZ` body: UTF-16LE strings, each NUL-terminated.
///
/// Read from the RAW bytes rather than from the walk's rendering, which joins
/// them with ` | ` -- a separator that is also a legal character in a string,
/// so splitting on it would be a decoder depending on a display format.
fn utf16le_multi(bytes: &[u8]) -> Vec<String> {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    units
        .split(|&u| u == 0)
        .filter(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}
