//! Per-interface network configuration — stated before it was decoded.
//!
//! # Ground truth
//!
//! `reference/plaso/test_data/SYSTEM`, a real Windows 7 hive, which holds six
//! `Tcpip\Parameters\Interfaces\{GUID}` keys across two control sets. Its
//! DHCP-configured interface `{6AAFC9A9-…}` holds, measured off the bytes:
//!
//! ```text
//! Lease                540000
//! LeaseObtainedTime    1289408803
//! T1                   1289678803
//! T2                   1289881303
//! LeaseTerminatesTime  1289948803
//! ```
//!
//! And the arithmetic closes: `1289408803 + 540000 == 1289948803`, with `T1` at
//! half the lease (270,000) and `T2` at seven-eighths (472,500) — the standard
//! DHCP renewal points. **Four independent values agreeing** is what licenses
//! reading them as Unix seconds. 1289408803 is 2010-11-10T17:06:43Z.
//!
//! Its other interface `{698E50A9-…}` has `EnableDHCP = 0` and all four lease
//! fields zero: no lease, which is a different fact from a lease whose times
//! are unknown.
//!
//! # The claim this module refuses
//!
//! The plan asserted that on a Windows 10 image the same field held `812456`
//! and so was "NOT Unix seconds". That is true of one value on one image and is
//! not a property of the field. So the decode is decided per interface by the
//! arithmetic, and a value that fails the check is published as a **number**.

use super::netinterfaces::*;

/// The measured Windows 7 interface.
fn dhcp_interface() -> NetworkInterface {
    NetworkInterface {
        interface_guid: "{6AAFC9A9-0542-4DB2-8760-CCFFA953737C}".into(),
        control_set: Some("ControlSet001".into()),
        dhcp_enabled: Some(false),
        ip_addresses: vec!["192.168.1.46".into()],
        subnet_masks: vec!["255.255.255.0".into()],
        default_gateways: vec!["192.168.1.1".into()],
        dhcp_server: Some("192.168.1.1".into()),
        lease_seconds: Some(540_000),
        lease_obtained_raw: Some(1_289_408_803),
        lease_terminates_raw: Some(1_289_948_803),
        t1_raw: Some(1_289_678_803),
        t2_raw: Some(1_289_881_303),
        key_path: r"ROOT\ControlSet001\Services\Tcpip\Parameters\Interfaces\{6AAFC9A9-0542-4DB2-8760-CCFFA953737C}".into(),
        ..Default::default()
    }
}

// --- The lease arithmetic decides ------------------------------------------

/// The lease's own arithmetic is what licenses reading its fields as times.
#[test]
fn the_lease_arithmetic_is_what_decides_the_times_are_unix_seconds() {
    assert_eq!(
        lease_basis(Some(1_289_408_803), Some(540_000), Some(1_289_948_803)),
        LeaseBasis::UnixSecondsConfirmedByLeaseArithmetic,
        "obtained + lease == terminates, exactly, on the real hive"
    );
    // One byte off in any of the three and the licence is withdrawn.
    assert_eq!(
        lease_basis(Some(1_289_408_803), Some(540_000), Some(1_289_948_804)),
        LeaseBasis::NotDecodable
    );
    assert_eq!(
        lease_basis(Some(812_456), Some(0), Some(0)),
        LeaseBasis::NotDecodable,
        "the Windows 10 shape the plan described: a number that is not a Unix time"
    );
}

/// All four fields zero is **no lease**, not a lease at the epoch.
///
/// The real hive's static interface is exactly this. Rendering it as
/// 1970-01-01 would put a date on a report for a lease that never existed.
#[test]
fn an_interface_with_no_lease_says_so_rather_than_dating_it_to_the_epoch() {
    assert_eq!(lease_basis(Some(0), Some(0), Some(0)), LeaseBasis::NoLease);
    let mut i = dhcp_interface();
    i.lease_seconds = Some(0);
    i.lease_obtained_raw = Some(0);
    i.lease_terminates_raw = Some(0);
    i.t1_raw = Some(0);
    i.t2_raw = Some(0);
    let j = i.to_json();
    assert_eq!(j["lease_time_basis"], "no_lease_recorded");
    assert!(j["lease_obtained"].is_null(), "no date at all");
    assert!(
        j["lease_time_note"]
            .as_str()
            .unwrap_or("")
            .contains("not a lease whose times are unknown"),
        "got {:?}",
        j["lease_time_note"]
    );
    assert!(
        j["content_incomplete"].is_null(),
        "a static interface is a complete answer, not an incomplete one"
    );
}

/// The confirmed case decodes all four times, and says why it was allowed to.
#[test]
fn a_confirmed_lease_decodes_its_four_times_and_states_the_basis() {
    let j = dhcp_interface().to_json();
    assert_eq!(
        j["lease_time_basis"],
        "unix_seconds_confirmed_by_lease_arithmetic"
    );
    assert_eq!(j["lease_obtained"], "2010-11-10T17:06:43+00:00");
    assert_eq!(j["lease_terminates"], "2010-11-16T23:06:43+00:00");
    assert_eq!(j["lease_renew_t1"], "2010-11-13T20:06:43+00:00");
    assert_eq!(j["lease_renew_t2"], "2010-11-16T04:21:43+00:00");
    let note = j["lease_time_note"].as_str().unwrap_or("");
    assert!(
        note.contains("1289408803 + 540000") && note.contains("1289948803"),
        "the arithmetic that licensed the decode must be on the record: {note:?}"
    );
    assert!(
        note.contains("not fixed across Windows versions"),
        "and why the check is made per interface: {note:?}"
    );
}

/// **The raw numbers are always published**, whatever the basis.
///
/// They are what the registry holds, and a reader checking this build's
/// reading needs them.
#[test]
fn the_raw_lease_numbers_are_always_published() {
    for i in [dhcp_interface(), {
        let mut n = dhcp_interface();
        n.lease_terminates_raw = Some(999);
        n
    }] {
        let j = i.to_json();
        assert_eq!(j["lease_obtained_raw"], serde_json::json!(1_289_408_803));
        assert!(j["t1_raw"].is_u64() && j["t2_raw"].is_u64());
    }
}

/// A lease whose arithmetic fails publishes numbers, **never dates**, and is
/// marked unvalidated.
#[test]
fn a_lease_that_fails_the_check_publishes_numbers_and_not_dates() {
    let mut i = dhcp_interface();
    i.lease_obtained_raw = Some(812_456);
    i.lease_seconds = Some(0);
    i.lease_terminates_raw = Some(0);
    let j = i.to_json();
    assert_eq!(j["lease_time_basis"], "not_decodable_as_a_time");
    for field in [
        "lease_obtained",
        "lease_terminates",
        "lease_renew_t1",
        "lease_renew_t2",
    ] {
        assert!(
            j[field].is_null(),
            "{field} must not be rendered as a date: {:?}",
            j[field]
        );
    }
    assert_eq!(j["lease_obtained_raw"], serde_json::json!(812_456));
    assert_eq!(j["content_incomplete"], serde_json::json!(true));
    assert_eq!(
        j["content_incomplete_reason"],
        serde_json::json!("unvalidated")
    );
    assert!(
        j["lease_time_note"]
            .as_str()
            .unwrap_or("")
            .contains("wrong day on a report"),
        "got {:?}",
        j["lease_time_note"]
    );
}

/// The record says IPv6 was not read, so its absence is not read as an absence
/// of IPv6 configuration.
#[test]
fn the_record_states_that_the_ipv6_tree_was_not_read() {
    let j = dhcp_interface().to_json();
    assert!(
        j["ipv6_not_read"]
            .as_str()
            .unwrap_or("")
            .contains("nothing here is evidence about this interface's IPv6"),
        "got {:?}",
        j["ipv6_not_read"]
    );
}

/// The configuration an examiner asks for is on the record.
#[test]
fn the_record_carries_the_address_the_server_and_the_gateway() {
    let j = dhcp_interface().to_json();
    assert_eq!(j["ip_addresses"][0], "192.168.1.46");
    assert_eq!(j["subnet_masks"][0], "255.255.255.0");
    assert_eq!(j["default_gateways"][0], "192.168.1.1");
    assert_eq!(j["dhcp_server"], "192.168.1.1");
    assert_eq!(j["control_set"], "ControlSet001");
    assert_eq!(
        j["interface_guid"],
        "{6AAFC9A9-0542-4DB2-8760-CCFFA953737C}"
    );
    // The name is the address, so a list of these reads as a list of addresses.
    assert_eq!(j["name"], "192.168.1.46");
}

// --- Anchoring, and end to end on the real hive ----------------------------

/// `Tcpip6` is **not** matched, and the key must be the interface itself.
#[test]
fn the_ipv6_tree_is_not_matched_and_neither_is_a_container() {
    let ok = r"ROOT\ControlSet001\Services\Tcpip\Parameters\Interfaces\{6AAFC9A9-0542-4DB2-8760-CCFFA953737C}";
    let (cs, guid) = interface_key(ok).expect("the IPv4 interface");
    assert_eq!(cs, "ControlSet001");
    assert_eq!(guid, "{6AAFC9A9-0542-4DB2-8760-CCFFA953737C}");

    for path in [
        // Tcpip6 is out of scope: its value set is disjoint and records from it
        // would have every field absent.
        r"ROOT\ControlSet001\Services\Tcpip6\Parameters\Interfaces\{6AAFC9A9-0542-4DB2-8760-CCFFA953737C}",
        // The container, not an interface.
        r"ROOT\ControlSet001\Services\Tcpip\Parameters\Interfaces",
        // A subkey of an interface.
        r"ROOT\ControlSet001\Services\Tcpip\Parameters\Interfaces\{6AAFC9A9}\Deeper",
        // Not a GUID.
        r"ROOT\ControlSet001\Services\Tcpip\Parameters\Interfaces\NotAGuid",
        // The right leaf under the wrong tree.
        r"ROOT\ControlSet001\Services\NetBT\Parameters\Interfaces\{6AAFC9A9}",
    ] {
        assert!(interface_key(path).is_none(), "for {path}");
    }
}

/// The real Windows 7 hive's interfaces come through, and the DHCP one carries
/// its lease as **times** because the arithmetic said it could.
#[test]
fn the_real_windows_seven_interfaces_come_through_with_their_leases() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("SYSTEM") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("SYSTEM", bytes);
    let ifaces: Vec<_> = all
        .iter()
        .filter(|r| r["type"] == "NetworkInterface")
        .collect();
    assert!(
        !ifaces.is_empty(),
        "this hive holds six interface keys across two control sets; the empty ones are \
         skipped and the configured ones must come through"
    );

    let dhcp = ifaces
        .iter()
        .find(|i| i["lease_obtained_raw"] == serde_json::json!(1_289_408_803))
        .expect("the interface whose lease this hive records");

    assert_eq!(
        dhcp["lease_time_basis"], "unix_seconds_confirmed_by_lease_arithmetic",
        "the lease's own arithmetic licensed the decode"
    );
    assert_eq!(dhcp["lease_obtained"], "2010-11-10T17:06:43+00:00");
    assert_eq!(dhcp["lease_terminates"], "2010-11-16T23:06:43+00:00");
    assert_eq!(dhcp["lease_seconds"], serde_json::json!(540_000));
    assert!(
        dhcp["dhcp_server"].is_string(),
        "the server that issued it: {:?}",
        dhcp["dhcp_server"]
    );
    assert!(
        !dhcp["ip_addresses"]
            .as_array()
            .expect("addresses")
            .is_empty(),
        "and the address it held"
    );
    // Read from raw bytes, so no ` | ` separator survives into a field.
    for a in dhcp["ip_addresses"].as_array().unwrap() {
        let s = a.as_str().unwrap_or("");
        assert!(
            !s.contains('|') && !s.is_empty(),
            "a REG_MULTI_SZ element must not carry the walk's display separator: {s:?}"
        );
    }
    assert!(dhcp["control_set"].is_string());
}

/// The static interface on the same hive reports **no lease**, and no date.
#[test]
fn the_real_static_interface_reports_no_lease_rather_than_an_epoch_date() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("SYSTEM") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("SYSTEM", bytes);
    let statics: Vec<_> = all
        .iter()
        .filter(|r| r["type"] == "NetworkInterface" && r["lease_time_basis"] == "no_lease_recorded")
        .collect();
    assert!(
        !statics.is_empty(),
        "this hive has an interface with EnableDHCP 0 and all four lease fields zero"
    );
    for s in statics {
        assert!(
            s["lease_obtained"].is_null(),
            "no date for a lease that never was"
        );
        assert!(s["lease_terminates"].is_null());
        assert!(
            s["lease_time_note"]
                .as_str()
                .unwrap_or("")
                .contains("statically configured"),
            "got {:?}",
            s["lease_time_note"]
        );
    }
}

/// No interface record anywhere carries a 1970 date.
///
/// That is what a zero lease field rendered as a Unix time looks like, and it
/// is the failure the arithmetic check exists to prevent.
#[test]
fn no_interface_record_carries_an_epoch_date() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("SYSTEM") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("SYSTEM", bytes);
    for i in all.iter().filter(|r| r["type"] == "NetworkInterface") {
        for f in [
            "lease_obtained",
            "lease_terminates",
            "lease_renew_t1",
            "lease_renew_t2",
        ] {
            if let Some(t) = i[f].as_str() {
                assert!(
                    !t.starts_with("1970-"),
                    "{f} is 1970, which is a zero rendered as a time: {t}"
                );
            }
        }
    }
}

// --- The DHCP-handed-out configuration (Data Leakage key question 9) ------

/// A DHCP interface leaves the static names empty and holds what the server
/// gave it in the `Dhcp`-prefixed values; the record must carry them, and the
/// record's name must be the address it held rather than the GUID.
#[test]
fn a_dhcp_interface_carries_the_address_the_server_handed_out() {
    let iface = NetworkInterface {
        interface_guid: "{E2B9AEEC-B1F7-4778-A049-50D7F2DAB2DE}".into(),
        control_set: Some("ControlSet001".into()),
        dhcp_enabled: Some(true),
        dhcp_ip_addresses: vec!["10.11.11.129".into()],
        dhcp_subnet_masks: vec!["255.255.255.0".into()],
        dhcp_default_gateways: vec!["10.11.11.2".into()],
        dhcp_name_servers: Some("10.11.11.2".into()),
        dhcp_domain: Some("localdomain".into()),
        dhcp_server: Some("10.11.11.254".into()),
        ..Default::default()
    };
    let j = iface.to_json();
    assert_eq!(j["dhcp_ip_addresses"][0], "10.11.11.129");
    assert_eq!(j["dhcp_subnet_masks"][0], "255.255.255.0");
    assert_eq!(j["dhcp_default_gateways"][0], "10.11.11.2");
    assert_eq!(j["dhcp_name_servers"], "10.11.11.2");
    assert_eq!(j["dhcp_domain"], "localdomain");
    assert_eq!(j["dhcp_server"], "10.11.11.254");
    assert_eq!(j["name"], "10.11.11.129");
    // The static fields stay what the registry holds: empty.
    assert!(j["ip_addresses"].as_array().unwrap().is_empty());
}

/// The NIST CFReDS Data Leakage PC's SYSTEM hive (`SEANCE_LEAKAGE_SYSTEM_HIVE`),
/// graded against key question 9: 10.11.11.129 / 255.255.255.0, name server and
/// gateway 10.11.11.2, domain `localdomain`, DHCP server 10.11.11.254.
#[test]
fn the_data_leakage_dhcp_interface_reads_the_key_answer() {
    let Ok(path) = std::env::var("SEANCE_LEAKAGE_SYSTEM_HIVE") else {
        return;
    };
    let bytes = std::fs::read(path).expect("the hive named by SEANCE_LEAKAGE_SYSTEM_HIVE");
    let all = super::userassist_tests::records_for_tests("SYSTEM", bytes);
    let hit = all
        .iter()
        .find(|r| r["type"] == "NetworkInterface" && r["dhcp_ip_addresses"][0] == "10.11.11.129")
        .expect("the DHCP interface with the key's address");
    assert_eq!(hit["dhcp_subnet_masks"][0], "255.255.255.0");
    assert_eq!(hit["dhcp_default_gateways"][0], "10.11.11.2");
    assert_eq!(hit["dhcp_name_servers"], "10.11.11.2");
    assert_eq!(hit["dhcp_domain"], "localdomain");
    assert_eq!(hit["dhcp_server"], "10.11.11.254");
}
