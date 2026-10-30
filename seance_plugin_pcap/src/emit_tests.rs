use super::*;
use crate::container::{
    CaptureFormat, CaptureMeta, Interface, InterfaceStatistics, SectionInfo, StopReason, TsResol,
};
use crate::decode::{Decoded, DnsAnswer, DnsMessage, Refusal};
use crate::flows::{Endpoint, FlowTable};
use crate::STAGING_CAP_BYTES;
use seance_core::artifact::{Artifact, ArtifactType};
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TCP: u8 = 6;
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

fn v4(s: &str) -> IpAddr {
    IpAddr::V4(s.parse::<Ipv4Addr>().expect("literal"))
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().expect("literal"))
}

fn at(secs: u64) -> Option<u64> {
    Some(secs * 1_000_000)
}

fn tcp(src: IpAddr, sp: u16, dst: IpAddr, dp: u16, flags: u8) -> Decoded {
    Decoded {
        src,
        dst,
        protocol: TCP,
        src_port: Some(sp),
        dst_port: Some(dp),
        tcp_flags: Some(flags),
        tcp_seq: None,
        payload_offset: 0,
        payload_len: 0,
        ipv4_checksum_unset: false,
    }
}

/// A one-interface Ethernet pcapng that read cleanly to the end.
fn clean_meta() -> CaptureMeta {
    CaptureMeta {
        format: CaptureFormat::PcapNg,
        little_endian: true,
        major: 1,
        minor: 0,
        interfaces: vec![Interface {
            linktype: 1,
            snaplen: 262_144,
            ts_resol: TsResol::Pow10(6),
            name: Some("eth0".into()),
        }],
        cap_reached_interfaces: false,
        sections: vec![SectionInfo {
            hardware: None,
            os: Some("Linux 5.8.0-kali1-amd64".into()),
            application: Some("Mergecap (Wireshark) 3.2.6".into()),
        }],
        cap_reached_sections: false,
        unknown_block_types: BTreeMap::new(),
        cap_reached_unknown_block_types: false,
        unknown_blocks_past_type_cap: 0,
        packets_on_undeclared_interface: 0,
        packet_blocks_short: 0,
        packets_without_timestamp: 0,
        packets_with_unresolvable_timestamp: 0,
        over_claimed_packets: 0,
        mismatched_block_trailers: 0,
        truncated_options: 0,
        stopped: None,
        bytes_read: 4096,
        interface_statistics: BTreeMap::new(),
        reported_drops: 0,
        reported_os_drops: 0,
        unreadable_statistics: 0,
    }
}

/// The C2 conversation from Case 001, fully captured.
fn c2_table() -> FlowTable {
    let mut table = FlowTable::new();
    let host = v4("10.42.85.10");
    let c2 = v4("203.78.103.109");
    table.observe(&tcp(host, 62414, c2, 443, SYN), at(1_600_482_318), 74, 74);
    table.observe(
        &tcp(c2, 443, host, 62414, SYN | ACK),
        at(1_600_482_319),
        74,
        74,
    );
    table.observe(&tcp(host, 62414, c2, 443, ACK), at(1_600_482_330), 66, 66);
    table
}

/// No conversation refused by the stream table unless a test asks for one.
static NO_REFUSED_FLOWS: std::collections::BTreeSet<crate::flows::FlowKey> =
    std::collections::BTreeSet::new();

/// No ARP unless a test asks for it.
static EMPTY_ARP: std::sync::LazyLock<crate::arp::ArpTable> =
    std::sync::LazyLock::new(crate::arp::ArpTable::new);

fn input<'a>(
    meta: &'a CaptureMeta,
    flows: &'a FlowTable,
    dns: &'a [DnsObservation],
) -> CaptureInput<'a> {
    CaptureInput {
        case_id: uuid::Uuid::nil(),
        parent_id: uuid::Uuid::from_u128(7),
        source_name: "case001.pcap",
        meta,
        flows,
        // No reassembled streams unless a test asks for them: `input_with`
        // below is the one that does.
        streams: &[],
        // Nor any HTTP: the end-to-end tests in `lib.rs` are where a
        // reassembled conversation is read as HTTP.
        http: &[],
        tls: &[],
        arp: &EMPTY_ARP,
        arp_unreadable: 0,
        stream_cap_reached: false,
        segments_beyond_stream_cap: 0,
        refused_stream_flows: &NO_REFUSED_FLOWS,
        reassembly_bytes_held: 0,
        reassembly_budget_reached: false,
        segments_beyond_reassembly_budget: 0,
        packets: flows.packets_in_flows()
            + flows.packets_refused()
            + flows.packets_no_network_layer()
            + flows.packets_past_cap(),
        first_seen_micros: at(1_600_482_318),
        last_seen_micros: at(1_600_482_330),
        dns,
        dns_cap: 1000,
        dns_cap_reached: false,
        dns_undecodable: 0,
        dns_header_short: 0,
        bytes_declared: 4096,
        bytes_staged: 4096,
        staging_cap: STAGING_CAP_BYTES,
    }
}

fn of_type<'a>(artifacts: &'a [Artifact], ty: &str) -> Vec<&'a Artifact> {
    artifacts
        .iter()
        .filter(|a| a.metadata.get("type").and_then(Value::as_str) == Some(ty))
        .collect()
}

fn keys(a: &Artifact) -> Vec<&str> {
    a.metadata
        .as_object()
        .expect("object metadata")
        .keys()
        .map(String::as_str)
        .collect()
}

fn get<'a>(a: &'a Artifact, key: &str) -> &'a Value {
    a.metadata
        .get(key)
        .unwrap_or_else(|| panic!("no key {key} in {}", a.metadata))
}

#[test]
fn a_microsecond_instant_renders_as_rfc3339_utc_with_the_fraction_kept() {
    // The C2 first-seen from the plan, to the millisecond it names.
    assert_eq!(
        rfc3339_micros(1_600_482_318_566_000),
        "2020-09-19T02:25:18.566000Z"
    );
    assert_eq!(rfc3339_micros(0), "1970-01-01T00:00:00.000000Z");
    // A leap day, and the century rule either side of it.
    assert_eq!(
        rfc3339_micros(951_782_400_000_000),
        "2000-02-29T00:00:00.000000Z"
    );
    assert_eq!(
        rfc3339_micros(4_102_444_800_000_000),
        "2100-01-01T00:00:00.000000Z"
    );
    assert_eq!(
        rfc3339_micros(1_709_164_799_999_999),
        "2024-02-28T23:59:59.999999Z"
    );
}

#[test]
fn the_largest_possible_instant_renders_without_panicking() {
    let s = rfc3339_micros(u64::MAX);
    assert!(s.ends_with('Z'), "{s}");
}

#[test]
fn an_ipv6_endpoint_is_bracketed_so_its_port_is_not_read_as_a_hextet() {
    assert_eq!(
        endpoint_label(Endpoint {
            ip: v6("2001:db8::5"),
            port: Some(51000)
        }),
        "[2001:db8::5]:51000"
    );
    assert_eq!(
        endpoint_label(Endpoint {
            ip: v4("10.0.0.5"),
            port: Some(443)
        }),
        "10.0.0.5:443"
    );
    assert_eq!(
        endpoint_label(Endpoint {
            ip: v4("10.0.0.5"),
            port: None
        }),
        "10.0.0.5"
    );
}

#[test]
fn the_capture_record_carries_the_format_the_provenance_and_the_counts() {
    let meta = clean_meta();
    let flows = c2_table();
    let out = emit(&input(&meta, &flows, &[]));

    let captures = of_type(&out, "NetworkCapture");
    assert_eq!(captures.len(), 1);
    let c = captures[0];
    assert_eq!(c.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(c.parent_id, Some(uuid::Uuid::from_u128(7)));
    assert_eq!(get(c, "format"), "pcapng");
    assert_eq!(get(c, "version"), "1.0");
    assert_eq!(get(c, "little_endian"), true);
    assert_eq!(get(c, "interface_count"), 1);
    assert_eq!(get(c, "linktypes"), &serde_json::json!([1]));
    assert_eq!(get(c, "snaplens"), &serde_json::json!([262144]));
    assert_eq!(get(c, "packets"), 3);
    assert_eq!(get(c, "flow_count"), 1);
    assert_eq!(get(c, "first_seen"), "2020-09-19T02:25:18.000000Z");
    assert_eq!(get(c, "last_seen"), "2020-09-19T02:25:30.000000Z");
    assert_eq!(get(c, "packets_without_timestamp"), 0);
    // The provenance is a list, one entry per section: a merged capture has
    // one per merged file and an examiner quoting it should see all of them.
    let sections = get(c, "sections").as_array().expect("sections list");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0]["os"], "Linux 5.8.0-kali1-amd64");
    assert_eq!(sections[0]["application"], "Mergecap (Wireshark) 3.2.6");
    assert_eq!(sections[0]["hardware"], Value::Null);
    assert_eq!(get(c, "reported_drops"), 0);
    assert_eq!(get(c, "reported_os_drops"), 0);
    assert_eq!(get(c, "unknown_block_types"), &serde_json::json!({}));
    assert_eq!(get(c, "over_claimed_packets"), 0);
    assert_eq!(get(c, "mismatched_block_trailers"), 0);
    assert_eq!(get(c, "truncated_options"), 0);
    assert_eq!(get(c, "stopped"), &Value::Null);
    assert_eq!(get(c, "refusals"), &serde_json::json!({}));
    assert_eq!(get(c, "truncated_packets"), 0);
    // Clean capture: no stamp of any kind.
    assert!(c.metadata.get("content_incomplete").is_none());
    assert!(c.metadata.get("inventory_incomplete").is_none());
    assert!(get(c, "name").as_str().unwrap().contains("case001.pcap"));
    assert!(get(c, "short_desc").as_str().unwrap().contains("3 packets"));
}

#[test]
fn a_walk_that_stopped_early_stamps_the_capture_short_read_and_says_where() {
    let mut meta = clean_meta();
    meta.stopped = Some(StopReason::BlockPastEof {
        at: 3000,
        declared: 5000,
        remaining: 1096,
    });
    meta.bytes_read = 3000;
    let flows = c2_table();
    let out = emit(&input(&meta, &flows, &[]));

    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, "content_incomplete"), true);
    assert_eq!(get(c, "content_incomplete_reason"), "short_read");
    assert_eq!(get(c, "stopped")["reason"], "block_past_eof");
    assert_eq!(get(c, "stopped")["at"], 3000);
    assert_eq!(get(c, "bytes_read"), 3000);
    assert_eq!(get(c, "bytes_total"), 4096);
    let detail = get(c, "content_incomplete_detail").as_str().unwrap();
    assert!(detail.contains("3000"), "{detail}");
    assert!(detail.contains("block_past_eof"), "{detail}");
}

#[test]
fn drops_the_capture_engine_reported_stamp_the_capture_short_read() {
    // The only place in the evidence where the evidence itself says how
    // much of it is missing.
    let mut meta = clean_meta();
    meta.interface_statistics.insert(
        0,
        InterfaceStatistics {
            if_received: Some(1000),
            if_drops: Some(12),
            os_drops: None,
        },
    );
    meta.reported_drops = 12;
    let flows = c2_table();
    let out = emit(&input(&meta, &flows, &[]));

    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, "content_incomplete"), true);
    assert_eq!(get(c, "content_incomplete_reason"), "short_read");
    assert_eq!(get(c, "reported_drops"), 12);
    let stats = get(c, "interface_statistics").as_array().unwrap();
    assert_eq!(stats[0]["interface"], 0);
    assert_eq!(stats[0]["received"], 1000);
    assert_eq!(stats[0]["dropped"], 12);
    // Not stated is null, not zero.
    assert_eq!(stats[0]["os_dropped"], Value::Null);
    assert!(get(c, "content_incomplete_detail")
        .as_str()
        .unwrap()
        .contains("12 packets"));
}

#[test]
fn a_truncated_packet_anywhere_stamps_the_capture_short_read() {
    let meta = clean_meta();
    let mut flows = FlowTable::new();
    flows.observe(
        &tcp(v4("10.0.0.5"), 1, v4("10.0.0.9"), 80, SYN),
        at(1),
        1500,
        96,
    );
    let out = emit(&input(&meta, &flows, &[]));

    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, "content_incomplete"), true);
    assert_eq!(get(c, "content_incomplete_reason"), "short_read");
    assert_eq!(get(c, "truncated_packets"), 1);
}

#[test]
fn a_source_larger_than_the_staging_cap_stamps_the_capture_cap_reached() {
    let meta = clean_meta();
    let flows = c2_table();
    let mut inp = input(&meta, &flows, &[]);
    inp.bytes_declared = STAGING_CAP_BYTES + 1;
    inp.bytes_staged = STAGING_CAP_BYTES;
    let out = emit(&inp);

    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, "content_incomplete"), true);
    assert_eq!(get(c, "content_incomplete_reason"), "cap_reached");
    assert_eq!(get(c, "bytes_declared"), STAGING_CAP_BYTES + 1);
    assert_eq!(get(c, "bytes_staged"), STAGING_CAP_BYTES);
    assert_eq!(get(c, "staging_cap_bytes"), STAGING_CAP_BYTES);
    assert!(get(c, "content_incomplete_detail")
        .as_str()
        .unwrap()
        .contains("staging cap"));
}

/// A 300 MiB capture on media that failed at 100 MiB: the cap did not stop
/// the read, the medium did. Attributing it to the cap sends the examiner to
/// raise a limit when the evidence is what failed.
#[test]
fn a_read_that_stopped_short_of_both_the_declared_size_and_the_cap_is_a_short_read_not_the_cap() {
    let meta = clean_meta();
    let flows = c2_table();
    let mut inp = input(&meta, &flows, &[]);
    inp.bytes_declared = STAGING_CAP_BYTES + 1;
    inp.bytes_staged = STAGING_CAP_BYTES / 2;
    let out = emit(&inp);

    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, "content_incomplete"), true);
    assert_eq!(get(c, "content_incomplete_reason"), "short_read");
    let detail = get(c, "content_incomplete_detail").as_str().unwrap();
    assert!(detail.contains("could be read"), "{detail}");
    // Both facts are stated: the read fell short, and the cap would have
    // bounded it anyway.
    assert!(detail.contains("staging cap"), "{detail}");
}

#[test]
fn a_source_that_read_short_of_its_declared_size_stamps_the_capture_short_read() {
    let meta = clean_meta();
    let flows = c2_table();
    let mut inp = input(&meta, &flows, &[]);
    inp.bytes_declared = 8192;
    inp.bytes_staged = 4096;
    let out = emit(&inp);

    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, "content_incomplete"), true);
    assert_eq!(get(c, "content_incomplete_reason"), "short_read");
}

#[test]
fn the_flow_cap_stamps_the_capture_inventory_incomplete_naming_the_cap() {
    let meta = clean_meta();
    let mut flows = FlowTable::with_cap(1);
    flows.observe(
        &tcp(v4("10.0.0.5"), 1, v4("10.0.0.9"), 80, SYN),
        at(1),
        74,
        74,
    );
    flows.observe(
        &tcp(v4("10.0.0.5"), 2, v4("10.0.0.9"), 80, SYN),
        at(2),
        74,
        74,
    );
    let out = emit(&input(&meta, &flows, &[]));

    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, "inventory_incomplete"), true);
    assert_eq!(get(c, "inventory_incomplete_reason"), "cap_reached");
    assert_eq!(get(c, "flow_cap"), 1);
    assert_eq!(get(c, "flow_cap_reached"), true);
    assert_eq!(get(c, "packets_past_flow_cap"), 1);
    assert!(get(c, "inventory_incomplete_detail")
        .as_str()
        .unwrap()
        .contains("1 flows"));
    // Content is whole even though the inventory is not.
    assert!(c.metadata.get("content_incomplete").is_none());
    assert_eq!(of_type(&out, "NetworkFlow").len(), 1);
}

/// The flow page's banner is computed from the records on the page. A cap
/// stamped only on the capture record leaves the flow list saying "N
/// records" with no banner, identical to an uncapped capture — and the flows
/// past the cap are exactly where a late-starting beacon would be.
#[test]
fn the_flow_cap_is_stamped_on_every_flow_naming_the_cap_and_not_on_the_dns_list() {
    let meta = clean_meta();
    let mut flows = FlowTable::with_cap(1);
    flows.observe(
        &tcp(v4("10.0.0.5"), 1, v4("10.0.0.9"), 80, SYN),
        at(1),
        74,
        74,
    );
    flows.observe(
        &tcp(v4("10.0.0.5"), 2, v4("10.0.0.9"), 80, SYN),
        at(2),
        74,
        74,
    );
    let dns = [dns_response()];
    let out = emit(&input(&meta, &flows, &dns));

    let records = of_type(&out, "NetworkFlow");
    assert!(!records.is_empty());
    for r in records {
        assert_eq!(get(r, "inventory_incomplete"), true);
        assert_eq!(get(r, "inventory_incomplete_reason"), "cap_reached");
        let detail = get(r, "inventory_incomplete_detail").as_str().unwrap();
        assert!(detail.contains("flow cap of 1"), "{detail}");
        // A cap on the inventory is not a hole in this record's content.
        assert!(r.metadata.get("content_incomplete").is_none());
    }
    // DNS is observed from every packet, not from the flow table, so the DNS
    // list is whole when the flow list is capped; stamping it would say
    // otherwise.
    for r in of_type(&out, "DnsResolution") {
        assert!(r.metadata.get("inventory_incomplete").is_none());
    }
}

#[test]
fn the_dns_cap_is_stamped_on_every_dns_record_and_not_on_the_flows() {
    let meta = clean_meta();
    let flows = c2_table();
    let dns = [dns_response()];
    let mut inp = input(&meta, &flows, &dns);
    inp.dns_cap_reached = true;
    let out = emit(&inp);
    for r in of_type(&out, "DnsResolution") {
        assert_eq!(get(r, "inventory_incomplete"), true);
        assert_eq!(get(r, "inventory_incomplete_reason"), "cap_reached");
        assert!(get(r, "inventory_incomplete_detail")
            .as_str()
            .unwrap()
            .contains("DNS cap"));
    }
    // The DNS list being short says nothing about the flow list: every flow
    // was still counted. Stamping the flows would mark a whole inventory as
    // incomplete on the strength of a different inventory's cap.
    for r in of_type(&out, "NetworkFlow") {
        assert!(
            r.metadata.get("inventory_incomplete").is_none(),
            "a DNS cap must not stamp the flow list: {:?}",
            r.metadata.get("inventory_incomplete_detail")
        );
    }
    let capture = of_type(&out, "NetworkCapture");
    assert_eq!(get(capture[0], "inventory_incomplete"), true);
}

/// Every count on every record is of a prefix of the file. A flow that reads
/// as whole with no badge, drawn from the first 256 MiB of a 2 GB capture,
/// is the same defect as a capped list: the record does not say.
#[test]
fn a_staging_cap_prefix_read_is_stamped_on_every_flow_and_dns_record() {
    let meta = clean_meta();
    let flows = c2_table();
    let dns = [dns_response()];
    let mut inp = input(&meta, &flows, &dns);
    inp.bytes_declared = STAGING_CAP_BYTES + 1;
    inp.bytes_staged = STAGING_CAP_BYTES;
    let out = emit(&inp);
    for ty in ["NetworkFlow", "DnsResolution"] {
        for r in of_type(&out, ty) {
            assert_eq!(get(r, "content_incomplete"), true, "{ty}");
            assert_eq!(get(r, "content_incomplete_reason"), "cap_reached");
            let detail = get(r, "content_incomplete_detail").as_str().unwrap();
            assert!(detail.contains("staging cap"), "{ty}: {detail}");
            assert!(r.metadata.get("inventory_incomplete").is_none(), "{ty}");
        }
    }
}

#[test]
fn a_walk_that_stopped_early_is_stamped_on_every_flow_and_dns_record() {
    let mut meta = clean_meta();
    meta.stopped = Some(StopReason::BlockPastEof {
        at: 3000,
        declared: 5000,
        remaining: 1096,
    });
    meta.bytes_read = 3000;
    let flows = c2_table();
    let dns = [dns_response()];
    let out = emit(&input(&meta, &flows, &dns));
    for ty in ["NetworkFlow", "DnsResolution"] {
        for r in of_type(&out, ty) {
            assert_eq!(get(r, "content_incomplete"), true, "{ty}");
            assert_eq!(get(r, "content_incomplete_reason"), "short_read");
            assert!(get(r, "content_incomplete_detail")
                .as_str()
                .unwrap()
                .contains("block_past_eof"));
        }
    }
}

#[test]
fn drops_the_capture_engine_reported_are_stamped_on_every_flow_and_dns_record() {
    let mut meta = clean_meta();
    meta.reported_drops = 12;
    let flows = c2_table();
    let dns = [dns_response()];
    let out = emit(&input(&meta, &flows, &dns));
    for ty in ["NetworkFlow", "DnsResolution"] {
        for r in of_type(&out, ty) {
            assert_eq!(get(r, "content_incomplete"), true, "{ty}");
            assert_eq!(get(r, "content_incomplete_reason"), "short_read");
            assert!(get(r, "content_incomplete_detail")
                .as_str()
                .unwrap()
                .contains("12 packets"));
        }
    }
}

/// A flow that is short in its own right and comes from a short capture
/// keeps its own reason and gains the capture's sentence: neither fact may
/// overwrite the other.
#[test]
fn a_flow_with_its_own_shortfall_keeps_its_reason_and_adds_the_capture_level_detail() {
    let meta = clean_meta();
    let mut flows = FlowTable::new();
    flows.observe_refusal(
        &Refusal::Ipv4ChecksumFailed {
            src: v4("10.0.0.5"),
            dst: v4("10.0.0.9"),
        },
        at(1),
        100,
        100,
    );
    let mut inp = input(&meta, &flows, &[]);
    inp.bytes_declared = STAGING_CAP_BYTES + 1;
    inp.bytes_staged = STAGING_CAP_BYTES;
    let out = emit(&inp);
    let f = of_type(&out, "NetworkFlow")[0];
    assert_eq!(get(f, "content_incomplete_reason"), "unresolved_structure");
    let detail = get(f, "content_incomplete_detail").as_str().unwrap();
    assert!(detail.contains("ipv4_checksum_failed"), "{detail}");
    assert!(detail.contains("staging cap"), "{detail}");
}

/// Snaplen truncation is stamped on the flows it touched; a clean flow in a
/// capture where some other flow was cut is whole, and stamping it would
/// make the badge mean nothing.
#[test]
fn another_flows_snaplen_cut_does_not_stamp_a_flow_that_was_captured_whole() {
    let meta = clean_meta();
    let mut flows = c2_table();
    flows.observe(
        &tcp(v4("10.0.0.5"), 1, v4("10.0.0.9"), 80, SYN),
        at(1),
        1500,
        96,
    );
    let out = emit(&input(&meta, &flows, &[]));
    let records = of_type(&out, "NetworkFlow");
    assert_eq!(records.len(), 2);
    let whole = records
        .iter()
        .find(|f| get(f, "truncated_packets") == 0)
        .expect("the whole flow");
    assert!(whole.metadata.get("content_incomplete").is_none());
}

/// A port-53 payload that did not decode is a DNS message that was there
/// and is not listed. `dns_messages: 0` for it is the same output as a
/// capture with no DNS at all, so the count is written and the inventory is
/// stamped — on every DNS record too, since the DNS list is what is short.
#[test]
fn port_53_payloads_that_did_not_decode_are_counted_and_stamp_the_inventory() {
    let meta = clean_meta();
    let flows = c2_table();
    let dns = [dns_response()];
    let mut inp = input(&meta, &flows, &dns);
    inp.dns_undecodable = 2;
    let out = emit(&inp);
    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, "dns_undecodable"), 2);
    assert_eq!(get(c, "inventory_incomplete"), true);
    assert_eq!(
        get(c, "inventory_incomplete_reason"),
        "unresolved_structure"
    );
    let detail = get(c, "inventory_incomplete_detail").as_str().unwrap();
    assert!(detail.contains("2 port-53"), "{detail}");
    for r in of_type(&out, "DnsResolution") {
        assert_eq!(get(r, "inventory_incomplete"), true);
        assert!(get(r, "inventory_incomplete_detail")
            .as_str()
            .unwrap()
            .contains("did not decode"));
    }
}

/// A port-53 payload shorter than the twelve-byte DNS header is a cut, not a
/// lie: `tcpdump -s 50` leaves eight bytes of DNS. It is counted apart from
/// the malformed case and stamped as a short read, because the examiner's
/// next step is the snaplen, not the sender.
#[test]
fn port_53_payloads_cut_inside_the_dns_header_are_counted_as_short_not_malformed() {
    let meta = clean_meta();
    let flows = c2_table();
    let mut inp = input(&meta, &flows, &[]);
    inp.dns_header_short = 3;
    let out = emit(&inp);
    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, "dns_header_short"), 3);
    assert_eq!(get(c, "dns_undecodable"), 0);
    assert_eq!(get(c, "inventory_incomplete"), true);
    assert_eq!(get(c, "inventory_incomplete_reason"), "short_read");
    assert!(get(c, "inventory_incomplete_detail")
        .as_str()
        .unwrap()
        .contains("3 port-53"));
}

#[test]
fn the_dns_cap_stamps_the_capture_inventory_incomplete() {
    let meta = clean_meta();
    let flows = c2_table();
    let mut inp = input(&meta, &flows, &[]);
    inp.dns_cap_reached = true;
    let out = emit(&inp);
    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, "inventory_incomplete"), true);
    assert_eq!(get(c, "inventory_incomplete_reason"), "cap_reached");
    assert_eq!(get(c, "dns_cap_reached"), true);
    assert_eq!(get(c, "dns_cap"), 1000);
}

#[test]
fn a_refused_linktype_interface_gets_its_own_refusal_record_naming_the_linktype() {
    let mut meta = clean_meta();
    meta.interfaces.push(Interface {
        linktype: 228,
        snaplen: 65535,
        ts_resol: TsResol::Pow10(6),
        name: None,
    });
    let mut flows = c2_table();
    flows.observe_refusal(&Refusal::UnsupportedLinktype(228), at(5), 60, 60);
    flows.observe_refusal(&Refusal::UnsupportedLinktype(228), at(6), 60, 60);
    let out = emit(&input(&meta, &flows, &[]));

    let refusals = of_type(&out, "NetworkCaptureRefusal");
    assert_eq!(refusals.len(), 1);
    let r = refusals[0];
    assert_eq!(r.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(get(r, "subtype"), "unsupported_linktype");
    assert_eq!(get(r, "linktype"), 228);
    assert_eq!(get(r, "interface"), 1);
    assert_eq!(get(r, "packets_refused_with_linktype"), 2);
    assert_eq!(get(r, "content_incomplete"), true);
    assert_eq!(get(r, "content_incomplete_reason"), "unresolved_structure");
    assert!(get(r, "name").as_str().unwrap().contains("228"));
    // The capture record still reports the refusal by reason and by number.
    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, "refusals")["unsupported_linktype"], 2);
    assert_eq!(get(c, "unsupported_linktypes")["228"], 2);
    // And the Ethernet flows are still there: one refused interface does not
    // empty the flow list.
    assert_eq!(of_type(&out, "NetworkFlow").len(), 1);
}

#[test]
fn a_supported_interface_gets_no_refusal_record() {
    let mut meta = clean_meta();
    for linktype in [101, 113] {
        meta.interfaces.push(Interface {
            linktype,
            snaplen: 65535,
            ts_resol: TsResol::Pow10(6),
            name: None,
        });
    }
    let flows = c2_table();
    let out = emit(&input(&meta, &flows, &[]));
    assert!(of_type(&out, "NetworkCaptureRefusal").is_empty());
}

#[test]
fn a_capture_with_no_ip_packets_still_emits_its_capture_record() {
    // Silence is the failure HUNT-060 names: a capture of nothing but ARP
    // must still say "read, N packets, none carried IP".
    let meta = clean_meta();
    let mut flows = FlowTable::new();
    flows.observe_no_network_layer();
    flows.observe_no_network_layer();
    let mut inp = input(&meta, &flows, &[]);
    inp.first_seen_micros = None;
    inp.last_seen_micros = None;
    let out = emit(&inp);

    assert_eq!(out.len(), 1);
    let c = &out[0];
    assert_eq!(get(c, "type"), "NetworkCapture");
    assert_eq!(get(c, "packets"), 2);
    assert_eq!(get(c, "packets_no_network_layer"), 2);
    assert_eq!(get(c, "flow_count"), 0);
    assert_eq!(get(c, "first_seen"), &Value::Null);
    assert_eq!(get(c, "last_seen"), &Value::Null);
    assert!(c.metadata.get("content_incomplete").is_none());
}

#[test]
fn a_flow_record_carries_exactly_the_keys_the_viewer_reads_with_local_being_the_internal_end() {
    let meta = clean_meta();
    let flows = c2_table();
    let out = emit(&input(&meta, &flows, &[]));

    let f = of_type(&out, "NetworkFlow")[0];
    assert_eq!(f.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(f.parent_id, Some(uuid::Uuid::from_u128(7)));
    for key in [
        "protocol",
        "local_ip",
        "local_port",
        "remote_ip",
        "remote_port",
        "remote_is_external",
        "packets_out",
        "bytes_out",
        "packets_in",
        "bytes_in",
        "packets",
        "bytes",
        "first_seen",
        "last_seen",
        "duration_seconds",
        "tcp_state",
        "truncated_packets",
        "name",
        "short_desc",
    ] {
        assert!(keys(f).contains(&key), "flow record lacks {key}");
    }
    assert_eq!(get(f, "protocol"), "tcp");
    assert_eq!(get(f, "local_ip"), "10.42.85.10");
    assert_eq!(get(f, "local_port"), 62414);
    assert_eq!(get(f, "remote_ip"), "203.78.103.109");
    assert_eq!(get(f, "remote_port"), 443);
    assert_eq!(get(f, "remote_is_external"), true);
    assert_eq!(get(f, "packets_out"), 2);
    assert_eq!(get(f, "bytes_out"), 140);
    assert_eq!(get(f, "packets_in"), 1);
    assert_eq!(get(f, "bytes_in"), 74);
    assert_eq!(get(f, "packets"), 3);
    assert_eq!(get(f, "bytes"), 214);
    assert_eq!(get(f, "first_seen"), "2020-09-19T02:25:18.000000Z");
    assert_eq!(get(f, "last_seen"), "2020-09-19T02:25:30.000000Z");
    assert_eq!(get(f, "duration_seconds"), 12.0);
    assert_eq!(get(f, "tcp_state"), "handshake_seen");
    assert_eq!(get(f, "truncated_packets"), 0);
    assert!(f.metadata.get("content_incomplete").is_none());
    assert_eq!(
        get(f, "short_desc"),
        "tcp 10.42.85.10:62414 -> 203.78.103.109:443"
    );
    assert!(get(f, "name")
        .as_str()
        .unwrap()
        .contains("203.78.103.109:443"));
}

#[test]
fn a_flow_whose_server_spoke_first_still_puts_the_internal_host_on_the_local_side() {
    let meta = clean_meta();
    let mut flows = FlowTable::new();
    flows.observe(
        &tcp(v4("203.78.103.109"), 443, v4("10.42.85.10"), 62414, ACK),
        at(1),
        60,
        60,
    );
    flows.observe(
        &tcp(v4("10.42.85.10"), 62414, v4("203.78.103.109"), 443, ACK),
        at(2),
        60,
        60,
    );
    let out = emit(&input(&meta, &flows, &[]));
    let f = of_type(&out, "NetworkFlow")[0];
    assert_eq!(get(f, "local_ip"), "10.42.85.10");
    assert_eq!(get(f, "remote_ip"), "203.78.103.109");
    // "out" is what the local host sent, not what the initiator sent.
    assert_eq!(get(f, "packets_out"), 1);
    assert_eq!(get(f, "packets_in"), 1);
    assert_eq!(get(f, "tcp_state"), "established_no_handshake_seen");
}

#[test]
fn a_portless_flow_has_null_ports_and_a_null_tcp_state_never_zero() {
    let meta = clean_meta();
    let mut flows = FlowTable::new();
    flows.observe(
        &Decoded {
            src: v4("10.0.0.5"),
            dst: v4("10.0.0.1"),
            protocol: 1,
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            tcp_seq: None,
            payload_offset: 0,
            payload_len: 0,
            ipv4_checksum_unset: false,
        },
        None,
        64,
        64,
    );
    let out = emit(&input(&meta, &flows, &[]));
    let f = of_type(&out, "NetworkFlow")[0];
    assert_eq!(get(f, "protocol"), "icmp");
    assert_eq!(get(f, "local_port"), &Value::Null);
    assert_eq!(get(f, "remote_port"), &Value::Null);
    assert_eq!(get(f, "tcp_state"), &Value::Null);
    assert_eq!(get(f, "first_seen"), &Value::Null);
    assert_eq!(get(f, "last_seen"), &Value::Null);
    assert_eq!(get(f, "duration_seconds"), &Value::Null);
    assert_eq!(get(f, "remote_is_external"), false);
    assert_eq!(get(f, "short_desc"), "icmp 10.0.0.5 -> 10.0.0.1");
    // No timestamp means no timeline event, not one at the epoch.
    assert!(of_type(&out, "TimelineEvent").is_empty());
    assert!(out
        .iter()
        .all(|a| a.artifact_type != ArtifactType::TimelineEvent));
}

/// The timeline event must carry the fraction: dozens of connections open
/// within one second of a brute force, and the order they opened in is the
/// sequence an intrusion is reconstructed from.
#[test]
fn a_timeline_event_keeps_the_microseconds_of_the_flows_first_packet() {
    let meta = clean_meta();
    let mut flows = FlowTable::new();
    flows.observe(
        &tcp(v4("10.42.85.10"), 62414, v4("203.78.103.109"), 443, SYN),
        Some(1_600_482_318_566_123),
        74,
        74,
    );
    let out = emit(&input(&meta, &flows, &[]));
    let e = out
        .iter()
        .find(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .expect("one event");
    assert_eq!(get(e, "timestamp"), "2020-09-19T02:25:18.566123+00:00");
}

/// A duration is a difference between two observations. One packet has
/// none, and "0.0 s" for it is the same text as a two-packet exchange in the
/// same microsecond — the placeholder must be null, not zero.
#[test]
fn a_one_packet_flow_has_a_null_duration_not_zero() {
    let meta = clean_meta();
    let mut flows = FlowTable::new();
    flows.observe(
        &tcp(v4("10.0.0.5"), 40000, v4("10.0.0.9"), 22, SYN),
        at(1),
        74,
        74,
    );
    let out = emit(&input(&meta, &flows, &[]));
    let f = of_type(&out, "NetworkFlow")[0];
    assert_eq!(get(f, "packets"), 1);
    assert_eq!(get(f, "first_seen"), "1970-01-01T00:00:01.000000Z");
    assert_eq!(get(f, "duration_seconds"), &Value::Null);
}

/// A flow of 100 SPBs and one EPB: first_seen is the one EPB's instant and
/// the row must not read as a 101-packet conversation that began and ended
/// there. The record says how many packets carried a timestamp, nulls a
/// duration that fewer than two of them support, and is stamped.
#[test]
fn a_flow_with_untimed_packets_says_how_many_were_timed_and_nulls_a_one_instant_duration() {
    let meta = clean_meta();
    let mut flows = FlowTable::new();
    let a = tcp(v4("10.0.0.5"), 40000, v4("10.0.0.9"), 22, ACK);
    flows.observe(&a, None, 66, 66);
    flows.observe(&a, None, 66, 66);
    flows.observe(&a, at(50), 66, 66);
    let out = emit(&input(&meta, &flows, &[]));
    let f = of_type(&out, "NetworkFlow")[0];
    assert_eq!(get(f, "packets"), 3);
    assert_eq!(get(f, "packets_without_timestamp"), 2);
    assert_eq!(get(f, "timestamped_packets"), 1);
    assert_eq!(get(f, "first_seen"), "1970-01-01T00:00:50.000000Z");
    assert_eq!(get(f, "duration_seconds"), &Value::Null);
    assert_eq!(get(f, "content_incomplete"), true);
    assert_eq!(get(f, "content_incomplete_reason"), "unresolved_structure");
    let detail = get(f, "content_incomplete_detail").as_str().unwrap();
    assert!(detail.contains("2 of 3"), "{detail}");
    assert!(detail.contains("timestamp"), "{detail}");
}

/// Two timed packets among untimed ones do support a duration: it is the
/// span of the timed ones, and the record still says the rest were untimed.
#[test]
fn a_flow_with_two_timed_packets_among_untimed_ones_has_the_duration_of_the_timed_pair() {
    let meta = clean_meta();
    let mut flows = FlowTable::new();
    let a = tcp(v4("10.0.0.5"), 40000, v4("10.0.0.9"), 22, ACK);
    flows.observe(&a, at(10), 66, 66);
    flows.observe(&a, None, 66, 66);
    flows.observe(&a, at(13), 66, 66);
    let out = emit(&input(&meta, &flows, &[]));
    let f = of_type(&out, "NetworkFlow")[0];
    assert_eq!(get(f, "timestamped_packets"), 2);
    assert_eq!(get(f, "duration_seconds"), 3.0);
    assert_eq!(get(f, "content_incomplete"), true);
}

/// A fully timed flow has timestamped_packets equal to packets and no stamp
/// for it: the field is always present so a reader never has to infer it.
#[test]
fn a_fully_timed_flow_reports_every_packet_as_timestamped_and_is_not_stamped() {
    let meta = clean_meta();
    let flows = c2_table();
    let out = emit(&input(&meta, &flows, &[]));
    let f = of_type(&out, "NetworkFlow")[0];
    assert_eq!(get(f, "timestamped_packets"), 3);
    assert_eq!(get(f, "packets_without_timestamp"), 0);
    assert!(f.metadata.get("content_incomplete").is_none());
}

/// "Local" means "the RFC 1918 side" on one row and "whoever spoke first"
/// on the next, and the column header is the same for both. The record has
/// to say which rule chose the side.
#[test]
fn the_record_says_which_rule_chose_the_local_side() {
    let meta = clean_meta();
    let mut flows = FlowTable::new();
    flows.observe(
        &tcp(v4("203.78.103.109"), 443, v4("10.42.85.10"), 62414, ACK),
        at(1),
        60,
        60,
    );
    flows.observe(
        &tcp(v4("10.0.0.9"), 22, v4("10.0.0.5"), 40000, ACK),
        at(2),
        60,
        60,
    );
    flows.observe(
        &tcp(v4("198.51.100.7"), 53, v4("203.0.113.9"), 53, ACK),
        at(3),
        60,
        60,
    );
    let out = emit(&input(&meta, &flows, &[]));
    let records = of_type(&out, "NetworkFlow");
    assert_eq!(get(records[0], "local_ip"), "10.42.85.10");
    assert_eq!(get(records[0], "local_chosen_by"), "internal");
    assert_eq!(get(records[1], "local_ip"), "10.0.0.9");
    assert_eq!(get(records[1], "local_chosen_by"), "first_packet");
    assert_eq!(get(records[2], "local_ip"), "198.51.100.7");
    assert_eq!(get(records[2], "local_chosen_by"), "first_packet");
}

#[test]
fn protocol_labels_name_the_common_transports_and_number_the_rest() {
    assert_eq!(protocol_label(Some(6)), Value::from("tcp"));
    assert_eq!(protocol_label(Some(17)), Value::from("udp"));
    assert_eq!(protocol_label(Some(1)), Value::from("icmp"));
    assert_eq!(protocol_label(Some(58)), Value::from("icmpv6"));
    assert_eq!(protocol_label(Some(2)), Value::from("ip-2"));
    assert_eq!(protocol_label(Some(47)), Value::from("ip-47"));
    // Not read is not a number.
    assert_eq!(protocol_label(None), Value::Null);
}

#[test]
fn a_flow_with_truncated_packets_is_stamped_short_read() {
    let meta = clean_meta();
    let mut flows = FlowTable::new();
    flows.observe(
        &tcp(v4("10.0.0.5"), 1, v4("10.0.0.9"), 80, SYN),
        at(1),
        1500,
        96,
    );
    let out = emit(&input(&meta, &flows, &[]));
    let f = of_type(&out, "NetworkFlow")[0];
    assert_eq!(get(f, "truncated_packets"), 1);
    assert_eq!(get(f, "content_incomplete"), true);
    assert_eq!(get(f, "content_incomplete_reason"), "short_read");
    assert_eq!(get(f, "bytes"), 96);
    assert_eq!(get(f, "wire_bytes"), 1500);
}

#[test]
fn an_ip_pair_flow_holding_refused_packets_is_stamped_and_names_the_reasons() {
    let meta = clean_meta();
    let mut flows = FlowTable::new();
    flows.observe_refusal(
        &Refusal::Ipv4ChecksumFailed {
            src: v4("10.0.0.5"),
            dst: v4("10.0.0.9"),
        },
        at(1),
        100,
        100,
    );
    let out = emit(&input(&meta, &flows, &[]));
    let f = of_type(&out, "NetworkFlow")[0];
    assert_eq!(get(f, "protocol"), &Value::Null);
    assert_eq!(get(f, "local_port"), &Value::Null);
    assert_eq!(get(f, "content_incomplete"), true);
    // The bytes were all there; the header did not verify. That is not a
    // short read, and calling it one would send an examiner to the snaplen.
    assert_eq!(get(f, "content_incomplete_reason"), "unresolved_structure");
    assert_eq!(get(f, "unattributed_packets")["ipv4_checksum_failed"], 1);
    assert_eq!(get(f, "unattributed_packets_total"), 1);
    assert!(get(f, "content_incomplete_detail")
        .as_str()
        .unwrap()
        .contains("ipv4_checksum_failed"));
}

/// Transmit checksum offload on the capturing host: the record counts the
/// unset packets and stamps nothing, because the packets are whole and
/// attributed and "unset" is a fact about the NIC, not a gap in the evidence.
#[test]
fn a_flow_with_unset_checksum_packets_counts_them_and_is_not_stamped_incomplete() {
    let meta = clean_meta();
    let mut flows = FlowTable::new();
    let mut syn = tcp(v4("10.0.0.5"), 40000, v4("203.0.113.9"), 443, SYN);
    syn.ipv4_checksum_unset = true;
    flows.observe(&syn, at(1), 74, 74);
    flows.observe(
        &tcp(v4("203.0.113.9"), 443, v4("10.0.0.5"), 40000, SYN | ACK),
        at(2),
        74,
        74,
    );
    let out = emit(&input(&meta, &flows, &[]));
    let f = of_type(&out, "NetworkFlow")[0];
    assert_eq!(get(f, "checksum_unset_packets"), 1);
    assert_eq!(get(f, "packets_out"), 1);
    assert_eq!(get(f, "packets_in"), 1);
    assert_eq!(get(f, "local_is_initiator"), true);
    assert_eq!(get(f, "refused_packets_between_hosts"), 0);
    assert!(f.metadata.get("content_incomplete").is_none());
}

/// The SYN's checksum was wrong (a nonzero mismatch: possible corruption), so
/// it sits on the IP-pair flow; the ported flow holding the SYN-ACK must say
/// its other half was refused, or the row reads "the remote host opened this
/// and we sent nothing".
#[test]
fn a_ported_flow_whose_other_half_was_refused_between_the_same_hosts_says_so_and_is_stamped() {
    let meta = clean_meta();
    let mut flows = FlowTable::new();
    flows.observe_refusal(
        &Refusal::Ipv4ChecksumFailed {
            src: v4("10.0.0.5"),
            dst: v4("203.0.113.9"),
        },
        at(1),
        74,
        74,
    );
    flows.observe(
        &tcp(v4("203.0.113.9"), 443, v4("10.0.0.5"), 40000, SYN | ACK),
        at(2),
        74,
        74,
    );
    let out = emit(&input(&meta, &flows, &[]));
    let records = of_type(&out, "NetworkFlow");
    assert_eq!(records.len(), 2);
    let ported = records
        .iter()
        .find(|f| get(f, "local_port") != &Value::Null)
        .expect("the ported flow");
    assert_eq!(get(ported, "refused_packets_between_hosts"), 1);
    assert_eq!(get(ported, "content_incomplete"), true);
    assert_eq!(
        get(ported, "content_incomplete_reason"),
        "unresolved_structure"
    );
    let detail = get(ported, "content_incomplete_detail").as_str().unwrap();
    assert!(detail.contains("ipv4_checksum_failed"), "{detail}");
    assert!(detail.contains("10.0.0.5"), "{detail}");
    assert!(detail.contains("203.0.113.9"), "{detail}");
    // The IP-pair flow does not count its own refused packets as elsewhere.
    let pair = records
        .iter()
        .find(|f| get(f, "local_port") == &Value::Null)
        .expect("the IP-pair flow");
    assert_eq!(get(pair, "refused_packets_between_hosts"), 0);
}

#[test]
fn a_transport_cut_by_the_snaplen_is_a_short_read_on_its_ip_pair() {
    let meta = clean_meta();
    let mut flows = FlowTable::new();
    flows.observe_refusal(
        &Refusal::TransportTruncated {
            src: v4("10.0.0.5"),
            dst: v4("10.0.0.9"),
            protocol: TCP,
        },
        at(1),
        100,
        40,
    );
    let out = emit(&input(&meta, &flows, &[]));
    let f = of_type(&out, "NetworkFlow")[0];
    assert_eq!(get(f, "protocol"), "tcp");
    assert_eq!(get(f, "content_incomplete_reason"), "short_read");
}

#[test]
fn every_timed_flow_gets_a_timeline_event_at_its_first_packet() {
    let meta = clean_meta();
    let flows = c2_table();
    let out = emit(&input(&meta, &flows, &[]));

    let events: Vec<&Artifact> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .collect();
    assert_eq!(events.len(), 1);
    let e = events[0];
    assert_eq!(e.parent_id, Some(uuid::Uuid::from_u128(7)));
    // RFC 3339 with the microseconds and an explicit +00:00, because the
    // timeline store keeps sub-second order and offset provenance from an
    // RFC 3339 string and drops both from a bare integer. A capture clock is
    // UTC by definition, so the offset is known, not unknowable.
    assert_eq!(get(e, "timestamp"), "2020-09-19T02:25:18.000000+00:00");
    assert_eq!(get(e, "timestamp_micros"), 1_600_482_318_000_000u64);
    assert_eq!(get(e, "timestamp_desc"), "Network flow first seen");
    assert_eq!(get(e, "source_module"), MODULE_ID);
    assert_eq!(
        get(e, "short_desc"),
        "tcp 10.42.85.10:62414 -> 203.78.103.109:443"
    );
    assert_eq!(get(e, "remote_is_external"), true);
}

/// A DNS UPDATE is not a query and not a response: it carries no question
/// and no answer, and a record that called it "DNS query: (no question read)"
/// would say the parse lost something. The opcode names what it is, and on
/// the DFIR Madness capture what it is matters — the compromised desktop
/// registering itself with the domain controller.
#[test]
fn a_dns_update_is_recorded_by_its_opcode_and_not_as_a_query_with_no_question() {
    let meta = clean_meta();
    let flows = c2_table();
    let mut obs = dns_response();
    obs.message = DnsMessage {
        id: 0xa250,
        is_response: false,
        opcode: 5,
        tc: false,
        rcode: 0,
        questions: vec![],
        answers: vec![],
        truncated: false,
    };
    let dns = [obs];
    let out = emit(&input(&meta, &flows, &dns));
    let records = of_type(&out, "DnsResolution");
    assert_eq!(records.len(), 1);
    let r = records[0];
    assert_eq!(get(r, "opcode"), 5);
    assert_eq!(get(r, "opcode_name"), "update");
    assert_eq!(get(r, "resolved"), false);
    let short = get(r, "short_desc").as_str().unwrap().to_string();
    assert!(short.starts_with("DNS update"), "{short}");
    assert!(
        !short.contains("no question read"),
        "an update has no question to have lost: {short}"
    );
    assert!(
        r.metadata.get("content_incomplete").is_none(),
        "a well-formed update is not a cut message"
    );
}

fn dns_response() -> DnsObservation {
    DnsObservation {
        message: DnsMessage {
            id: 0x1234,
            is_response: true,
            opcode: 0,
            tc: false,
            rcode: 0,
            questions: vec!["update.example.net".into()],
            answers: vec![
                DnsAnswer {
                    name: "update.example.net".into(),
                    rtype: 5,
                    data: "cdn.example.net".into(),
                },
                DnsAnswer {
                    name: "cdn.example.net".into(),
                    rtype: 1,
                    data: "203.78.103.109".into(),
                },
            ],
            truncated: false,
        },
        src: Endpoint {
            ip: v4("10.42.85.1"),
            port: Some(53),
        },
        dst: Endpoint {
            ip: v4("10.42.85.10"),
            port: Some(51234),
        },
        ts_micros: at(1_600_482_300),
    }
}

#[test]
fn a_dns_response_becomes_a_resolution_record_with_the_answers_and_the_endpoints() {
    let meta = clean_meta();
    let flows = c2_table();
    let dns = [dns_response()];
    let out = emit(&input(&meta, &flows, &dns));

    let records = of_type(&out, "DnsResolution");
    assert_eq!(records.len(), 1);
    let r = records[0];
    assert_eq!(r.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(r.parent_id, Some(uuid::Uuid::from_u128(7)));
    assert_eq!(get(r, "name"), "update.example.net");
    assert_eq!(get(r, "is_response"), true);
    assert_eq!(get(r, "transaction_id"), 0x1234);
    assert_eq!(get(r, "truncated"), false);
    assert_eq!(get(r, "tc"), false);
    let answers = get(r, "answers").as_array().unwrap();
    assert_eq!(answers.len(), 2);
    assert_eq!(answers[0]["rtype"], 5);
    assert_eq!(answers[0]["rtype_name"], "CNAME");
    assert_eq!(answers[0]["data"], "cdn.example.net");
    assert_eq!(answers[1]["rtype_name"], "A");
    assert_eq!(answers[1]["data"], "203.78.103.109");
    assert_eq!(
        get(r, "answer_data"),
        &serde_json::json!(["cdn.example.net", "203.78.103.109"])
    );
    // The client is the side that asked, whichever direction this packet went.
    assert_eq!(get(r, "client_ip"), "10.42.85.10");
    assert_eq!(get(r, "client_port"), 51234);
    assert_eq!(get(r, "server_ip"), "10.42.85.1");
    assert_eq!(get(r, "server_port"), 53);
    assert_eq!(get(r, "timestamp"), "2020-09-19T02:25:00.000000Z");
    // Provenance: this name came off the wire, not from the examination host.
    assert_eq!(get(r, "resolved_by"), "capture");
    assert!(get(r, "short_desc")
        .as_str()
        .unwrap()
        .contains("update.example.net"));
    assert!(r.metadata.get("content_incomplete").is_none());
}

/// NXDOMAIN, SERVFAIL and a NOERROR response with nothing in the answer
/// section are three different findings. Each record carries the RCODE by
/// number and name, and `resolved` is true only when the server answered
/// with records — a response is not a resolution just because it arrived.
#[test]
fn a_dns_response_with_a_nonzero_rcode_is_not_a_resolution_and_names_the_rcode() {
    let meta = clean_meta();
    let flows = c2_table();
    let mut obs = dns_response();
    obs.message.questions = vec!["evil.example".into()];
    obs.message.answers.clear();
    obs.message.rcode = 3;
    let out = emit(&input(&meta, &flows, &[obs]));
    let r = of_type(&out, "DnsResolution")[0];
    assert_eq!(get(r, "rcode"), 3);
    assert_eq!(get(r, "rcode_name"), "NXDOMAIN");
    assert_eq!(get(r, "answer_count"), 0);
    assert_eq!(get(r, "resolved"), false);
    let short = get(r, "short_desc").as_str().unwrap();
    assert!(short.contains("NXDOMAIN"), "{short}");
    assert!(short.contains("evil.example"), "{short}");
}

#[test]
fn a_noerror_response_with_no_answers_is_not_a_resolution_and_says_so() {
    let meta = clean_meta();
    let flows = c2_table();
    let mut obs = dns_response();
    obs.message.answers.clear();
    let out = emit(&input(&meta, &flows, &[obs]));
    let r = of_type(&out, "DnsResolution")[0];
    assert_eq!(get(r, "rcode"), 0);
    assert_eq!(get(r, "rcode_name"), "NOERROR");
    assert_eq!(get(r, "resolved"), false);
    let short = get(r, "short_desc").as_str().unwrap();
    assert!(short.contains("no answer"), "{short}");
}

#[test]
fn a_response_with_answers_is_a_resolution_and_a_query_is_not() {
    let meta = clean_meta();
    let flows = c2_table();
    let response = dns_response();
    let mut query = dns_response();
    query.message.is_response = false;
    query.message.answers.clear();
    let out = emit(&input(&meta, &flows, &[response, query]));
    let records = of_type(&out, "DnsResolution");
    assert_eq!(get(records[0], "resolved"), true);
    assert_eq!(get(records[0], "rcode_name"), "NOERROR");
    assert_eq!(get(records[1], "resolved"), false);
}

#[test]
fn rcode_names_cover_the_assigned_values_and_number_the_rest() {
    assert_eq!(rcode_name(0), "NOERROR");
    assert_eq!(rcode_name(1), "FORMERR");
    assert_eq!(rcode_name(2), "SERVFAIL");
    assert_eq!(rcode_name(3), "NXDOMAIN");
    assert_eq!(rcode_name(4), "NOTIMP");
    assert_eq!(rcode_name(5), "REFUSED");
    assert_eq!(rcode_name(9), "RCODE9");
}

#[test]
fn a_dns_query_becomes_a_record_with_no_answers_and_the_client_as_its_source() {
    let meta = clean_meta();
    let flows = c2_table();
    let mut obs = dns_response();
    obs.message.is_response = false;
    obs.message.answers.clear();
    std::mem::swap(&mut obs.src, &mut obs.dst);
    let out = emit(&input(&meta, &flows, &[obs]));

    let r = of_type(&out, "DnsResolution")[0];
    assert_eq!(get(r, "is_response"), false);
    assert_eq!(get(r, "answers"), &serde_json::json!([]));
    assert_eq!(get(r, "client_ip"), "10.42.85.10");
    assert_eq!(get(r, "server_ip"), "10.42.85.1");
    assert!(get(r, "short_desc")
        .as_str()
        .unwrap()
        .starts_with("DNS query"));
}

#[test]
fn a_dns_message_the_capture_cut_is_stamped_short_read_and_its_partial_answers_kept() {
    let meta = clean_meta();
    let flows = c2_table();
    let mut obs = dns_response();
    obs.message.truncated = true;
    obs.message.answers.truncate(1);
    let out = emit(&input(&meta, &flows, &[obs]));

    let r = of_type(&out, "DnsResolution")[0];
    assert_eq!(get(r, "truncated"), true);
    assert_eq!(get(r, "content_incomplete"), true);
    assert_eq!(get(r, "content_incomplete_reason"), "short_read");
    assert_eq!(get(r, "answers").as_array().unwrap().len(), 1);
}

#[test]
fn a_dns_message_with_two_questions_becomes_two_records() {
    let meta = clean_meta();
    let flows = c2_table();
    let mut obs = dns_response();
    obs.message.questions.push("other.example.net".into());
    let out = emit(&input(&meta, &flows, &[obs]));
    let records = of_type(&out, "DnsResolution");
    assert_eq!(records.len(), 2);
    assert_eq!(get(records[1], "name"), "other.example.net");
}

#[test]
fn a_dns_message_with_no_question_still_becomes_one_record_rather_than_none() {
    // A qdcount-0 response, or a query the capture cut inside its question,
    // is still a DNS packet on the wire; a decoder that emitted nothing for
    // it would empty the DNS tier of every heavily-snapped capture.
    let meta = clean_meta();
    let flows = c2_table();
    let mut obs = dns_response();
    obs.message.questions.clear();
    obs.message.truncated = true;
    let out = emit(&input(&meta, &flows, &[obs]));
    let records = of_type(&out, "DnsResolution");
    assert_eq!(records.len(), 1);
    assert_eq!(get(records[0], "name"), &Value::Null);
    assert_eq!(get(records[0], "content_incomplete"), true);
}

#[test]
fn the_read_failure_record_names_the_error_and_stamps_both_incompleteness_kinds() {
    let r = refusal_record(
        uuid::Uuid::nil(),
        uuid::Uuid::from_u128(7),
        "case001.pcap",
        "not_a_capture",
        "the bytes do not open with a pcap or pcapng header",
    );
    assert_eq!(r.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(r.parent_id, Some(uuid::Uuid::from_u128(7)));
    assert_eq!(get(&r, "type"), "NetworkCaptureRefusal");
    assert_eq!(get(&r, "subtype"), "not_a_capture");
    assert_eq!(get(&r, "content_incomplete"), true);
    assert_eq!(get(&r, "content_incomplete_reason"), "unresolved_structure");
    assert_eq!(get(&r, "inventory_incomplete"), true);
    assert_eq!(
        get(&r, "inventory_incomplete_reason"),
        "unresolved_structure"
    );
    let detail = get(&r, "detail").as_str().unwrap();
    assert!(detail.contains("case001.pcap"));
    assert!(detail.contains("do not open"));
    assert!(get(&r, "name").as_str().unwrap().contains("not read"));
}

#[test]
fn a_capture_read_from_an_undeclared_interface_or_a_short_block_is_reported_not_swallowed() {
    let mut meta = clean_meta();
    meta.packets_on_undeclared_interface = 3;
    meta.packet_blocks_short = 1;
    meta.packets_with_unresolvable_timestamp = 2;
    meta.unknown_block_types.insert(4, 1);
    meta.unknown_block_types.insert(10, 2);
    let flows = c2_table();
    let out = emit(&input(&meta, &flows, &[]));
    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, "packets_on_undeclared_interface"), 3);
    assert_eq!(get(c, "packet_blocks_short"), 1);
    assert_eq!(get(c, "packets_with_unresolvable_timestamp"), 2);
    assert_eq!(
        get(c, "unknown_block_types"),
        &serde_json::json!({"4": 1, "10": 2})
    );
    // Packets the walk saw and could not hand up are content the capture
    // holds and the flow list does not.
    assert_eq!(get(c, "content_incomplete"), true);
    assert_eq!(get(c, "content_incomplete_reason"), "unresolved_structure");
}

/// Each of these is a count of something the file said and this reader could
/// not read whole. Pinned one at a time, because a test that sets several
/// together and asserts the stamp once cannot tell which of them earned it.
fn only_this_counter_stamps_the_capture(
    set: impl FnOnce(&mut CaptureMeta),
    key: &str,
    expected_reason: &str,
    detail_mentions: &str,
) {
    let mut meta = clean_meta();
    set(&mut meta);
    let flows = c2_table();
    let out = emit(&input(&meta, &flows, &[]));
    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, key), 1, "{key} is written as a count");
    assert_eq!(
        get(c, "content_incomplete"),
        true,
        "{key} alone must stamp the capture record"
    );
    assert_eq!(get(c, "content_incomplete_reason"), expected_reason);
    let detail = get(c, "content_incomplete_detail").as_str().unwrap();
    assert!(detail.contains(detail_mentions), "{key}: {detail}");
}

/// The engine attested a loss and the figure could not be read: that is not
/// "no drops", and a record without a stamp reads as a complete capture.
#[test]
fn an_unreadable_interface_statistics_counter_stamps_the_capture_on_its_own() {
    only_this_counter_stamps_the_capture(
        |m| m.unreadable_statistics = 1,
        "unreadable_statistics",
        "unresolved_structure",
        "could not be read",
    );
}

#[test]
fn an_over_claimed_packet_stamps_the_capture_on_its_own() {
    only_this_counter_stamps_the_capture(
        |m| m.over_claimed_packets = 1,
        "over_claimed_packets",
        "unresolved_structure",
        "declared more captured bytes",
    );
}

#[test]
fn a_mismatched_block_trailer_stamps_the_capture_on_its_own() {
    only_this_counter_stamps_the_capture(
        |m| m.mismatched_block_trailers = 1,
        "mismatched_block_trailers",
        "unresolved_structure",
        "trailing length",
    );
}

#[test]
fn a_truncated_option_list_stamps_the_capture_on_its_own() {
    only_this_counter_stamps_the_capture(
        |m| m.truncated_options = 1,
        "truncated_options",
        "unresolved_structure",
        "option",
    );
}

#[test]
fn a_packet_on_an_undeclared_interface_stamps_the_capture_on_its_own() {
    only_this_counter_stamps_the_capture(
        |m| m.packets_on_undeclared_interface = 1,
        "packets_on_undeclared_interface",
        "unresolved_structure",
        "no IDB declared",
    );
}

#[test]
fn a_short_packet_block_stamps_the_capture_on_its_own() {
    only_this_counter_stamps_the_capture(
        |m| m.packet_blocks_short = 1,
        "packet_blocks_short",
        "unresolved_structure",
        "shorter than their own fixed fields",
    );
}

/// A refusal with no addresses — a frame cut inside its IP header, a VLAN
/// stack deeper than the walk — reaches no flow and no per-flow count. The
/// capture record is the only place it can be stamped, and `tcpdump -s 20`
/// makes every packet one of these.
#[test]
fn a_refusal_with_no_addresses_stamps_the_capture_record_because_no_flow_can_carry_it() {
    let meta = clean_meta();
    let mut flows = c2_table();
    flows.observe_refusal(
        &Refusal::FrameTruncated { need: 34, have: 20 },
        at(5),
        60,
        20,
    );
    flows.observe_refusal(&Refusal::VlanDepthExceeded, at(6), 60, 60);
    let out = emit(&input(&meta, &flows, &[]));
    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, "refusals")["frame_truncated"], 1);
    assert_eq!(get(c, "refusals")["vlan_depth_exceeded"], 1);
    assert_eq!(get(c, "packets_refused_without_addresses"), 2);
    assert_eq!(get(c, "content_incomplete"), true);
    assert_eq!(get(c, "content_incomplete_reason"), "unresolved_structure");
    let detail = get(c, "content_incomplete_detail").as_str().unwrap();
    assert!(detail.contains("frame_truncated"), "{detail}");
    assert!(detail.contains("in no flow"), "{detail}");
}

/// A refusal that carried addresses is on an IP-pair flow, which is stamped
/// itself; the capture record must not call the file structurally short for
/// it, or every host capture with one bad checksum reads as damaged.
#[test]
fn a_refusal_with_addresses_does_not_by_itself_stamp_the_capture_record() {
    let meta = clean_meta();
    let mut flows = c2_table();
    flows.observe_refusal(
        &Refusal::Ipv4ChecksumFailed {
            src: v4("10.0.0.5"),
            dst: v4("10.0.0.9"),
        },
        at(5),
        60,
        60,
    );
    let out = emit(&input(&meta, &flows, &[]));
    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, "packets_refused_without_addresses"), 0);
    assert!(c.metadata.get("content_incomplete").is_none());
}

#[test]
fn a_classic_pcap_reports_its_format_and_an_empty_provenance_list() {
    let mut meta = clean_meta();
    meta.format = CaptureFormat::PcapNano;
    meta.major = 2;
    meta.minor = 4;
    meta.sections.clear();
    let flows = c2_table();
    let out = emit(&input(&meta, &flows, &[]));
    let c = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(c, "format"), "pcap-ns");
    assert_eq!(get(c, "version"), "2.4");
    assert_eq!(get(c, "sections"), &serde_json::json!([]));
}

// ── Reassembled streams on the flow record (§4.3 stage 2) ───────────────────

/// Build the two streams of one conversation, with a hole and a conflict in
/// the request direction, so the record's honesty can be read off it.
fn streams_for(flows: &FlowTable) -> Vec<crate::reassemble::Stream> {
    let host = v4("10.42.85.10");
    let c2 = v4("203.78.103.109");
    let key = crate::flows::FlowKey::new(
        Some(TCP),
        crate::flows::Endpoint {
            ip: host,
            port: Some(62414),
        },
        crate::flows::Endpoint {
            ip: c2,
            port: Some(443),
        },
    );
    let mut r = crate::reassemble::Reassembler::new(crate::reassemble::ReassemblyConfig::default());
    let mut seg = |src: IpAddr, sp: u16, dst: IpAddr, dp: u16, seq: u32, flags: u8, b: &[u8]| {
        let mut d = tcp(src, sp, dst, dp, flags);
        d.tcp_seq = Some(seq);
        let direction = if src == host {
            crate::flows::Direction::Out
        } else {
            crate::flows::Direction::In
        };
        r.offer(key, direction, &d, b);
    };
    // The host speaks first, so it is the initiator and the local endpoint.
    seg(host, 62414, c2, 443, 1000, SYN, &[]);
    seg(host, 62414, c2, 443, 1001, ACK, b"GET /a");
    // ... a segment is missing ...
    seg(host, 62414, c2, 443, 1011, ACK, b"HTTP/1.1\r\n");
    // ... and one offset pair is claimed twice with different bytes.
    seg(host, 62414, c2, 443, 1001, ACK, b"GET /X");
    seg(c2, 443, host, 62414, 5001, ACK, b"HTTP/1.1 200 OK\r\n");
    let _ = flows;
    r.finish()
}

/// **The flow record carries what each endpoint said**, with the gap named and
/// the disagreement named, and the record is marked short of the conversation
/// on both counts.
#[test]
fn a_flow_record_carries_its_reassembled_streams_and_says_what_is_missing() {
    let meta = clean_meta();
    let flows = c2_table();
    let streams = streams_for(&flows);
    let mut input = input(&meta, &flows, &[]);
    input.streams = &streams;

    let out = emit(&input);
    let flow = out
        .iter()
        .find(|a| a.metadata["type"] == "NetworkFlow")
        .expect("a flow record");
    let tcp_streams = &flow.metadata["tcp_streams"];
    assert!(!tcp_streams.is_null(), "{}", flow.metadata);

    // The host spoke first, so its bytes are the local-to-remote direction.
    let out_stream = &tcp_streams["local_to_remote"];
    assert_eq!(out_stream["base_from_syn"], serde_json::json!(true));
    assert_eq!(
        out_stream["runs"], 2,
        "the missing segment leaves two pieces"
    );
    assert_eq!(out_stream["holes"][0]["offset"], 6);
    assert_eq!(out_stream["holes"][0]["length"], 4);
    assert_eq!(out_stream["holes_total_bytes"], 4);
    assert_eq!(out_stream["conflicts"][0]["offset"], 0);
    assert_eq!(out_stream["contiguous"], serde_json::json!(false));

    let in_stream = &tcp_streams["remote_to_local"];
    assert_eq!(
        in_stream["base_from_syn"],
        serde_json::json!(false),
        "the capture holds no SYN from the server, so offset 0 is the first byte it saw"
    );
    assert_eq!(in_stream["bytes_held"], 17);
    assert_eq!(in_stream["contiguous"], serde_json::json!(true));

    // **And the record is marked short of the conversation, twice.** A record
    // whose stream has a hole and a disagreement in it must not read as a
    // record of the whole exchange.
    assert_eq!(
        flow.metadata["content_incomplete"],
        serde_json::json!(true),
        "{}",
        flow.metadata
    );
    let detail = flow.metadata["content_incomplete_detail"]
        .as_str()
        .expect("the record states what it is short of");
    assert!(
        detail.contains("missing 4 byte(s) in 1 place(s)"),
        "{detail}"
    );
    assert!(
        detail.contains("claimed twice with different bytes"),
        "{detail}"
    );
    assert!(
        detail.contains("6 byte(s) before the first gap"),
        "{detail}"
    );
    // The first reason is the stamp's, and a missing byte is a short read.
    assert_eq!(flow.metadata["content_incomplete_reason"], "short_read");
}

/// A UDP flow has no reassembled stream, and the field is absent rather than
/// present and empty — a stream that is not there is not a stream that held
/// nothing.
#[test]
fn a_flow_with_no_tcp_stream_carries_no_stream_field() {
    let meta = clean_meta();
    let flows = c2_table();
    let input = input(&meta, &flows, &[]);
    let out = emit(&input);
    let flow = out
        .iter()
        .find(|a| a.metadata["type"] == "NetworkFlow")
        .expect("a flow record");
    assert!(
        flow.metadata.get("tcp_streams").is_none(),
        "{}",
        flow.metadata
    );
}

// ── The HTTP transaction cap ────────────────────────────────────────────────

/// **A capture of a scan is bounded, and the bound is stated.** Ten thousand
/// one-request connections is an afternoon's work for a scanner; past the
/// ceiling the transactions are counted and no record is written for them,
/// which is the difference between a bounded run and an unusable case.
#[test]
fn transactions_past_the_ceiling_are_counted_and_not_written() {
    use crate::flows::{Direction, FlowKey};
    use crate::http::{Conversation, Pairing, StreamFacts, Transaction};

    let client = Endpoint {
        ip: v4("10.42.85.10"),
        port: Some(49152),
    };
    let server = Endpoint {
        ip: v4("203.78.103.109"),
        port: Some(80),
    };
    let request = crate::http::parse_stream(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n", true)
        .messages
        .remove(0);
    let over = crate::http::MAX_TRANSACTIONS_PER_CAPTURE + 1;
    let conversation = Conversation {
        flow: FlowKey::new(Some(6), client, server),
        client,
        server,
        requests_from: Direction::Out,
        transactions: (0..over)
            .map(|_| Transaction {
                request: Some(request.clone()),
                response: None,
                pairing: Pairing::RequestUnanswered,
            })
            .collect(),
        requests: StreamFacts::default(),
        responses: StreamFacts::default(),
    };

    let meta = clean_meta();
    let flows = c2_table();
    let dns: Vec<DnsObservation> = Vec::new();
    let conversations = [conversation];
    let mut input = input(&meta, &flows, &dns);
    input.http = &conversations;
    let out = emit(&input);

    assert_eq!(
        of_type(&out, "HttpTransaction").len(),
        crate::http::MAX_TRANSACTIONS_PER_CAPTURE
    );
    let capture = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(capture, "http_transactions"), &json!(over));
    assert_eq!(
        get(capture, "http_transaction_cap"),
        &json!(crate::http::MAX_TRANSACTIONS_PER_CAPTURE)
    );
    assert_eq!(
        get(capture, "http_transaction_cap_reached"),
        &json!(true),
        "a count that stops at the ceiling with no flag reads as the whole traffic"
    );
    assert_eq!(get(capture, "http_transactions_beyond_cap"), &json!(1));
    assert_eq!(get(capture, "http_requests_unanswered"), &json!(10_000));
}

// ── Whose bytes are whose, and what a cap costs ─────────────────────────────

/// Two streams of one conversation, in whichever direction the caller wants
/// the client to be, so the branch that decides client from server is
/// exercised both ways round.
///
/// `client_spoke_first` false is the mid-connection case: the capture's first
/// packet is the server's, so the flow table's "initiator" IS the server and
/// a reader that took the initiator for the client would label every row
/// backwards.
fn exchange_streams(client_spoke_first: bool) -> (FlowTable, Vec<crate::reassemble::Stream>) {
    let host = v4("10.42.85.10");
    let server = v4("93.184.216.34");
    let client = crate::flows::Endpoint {
        ip: host,
        port: Some(49152),
    };
    let remote = crate::flows::Endpoint {
        ip: server,
        port: Some(80),
    };
    let key = crate::flows::FlowKey::new(Some(TCP), client, remote);

    let mut table = FlowTable::new();
    let mut reassembler =
        crate::reassemble::Reassembler::new(crate::reassemble::ReassemblyConfig::default());
    let request = b"GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";

    // The flow table's initiator is whoever this capture saw speak first.
    let mut offer = |from_host: bool, seq: u32, payload: &[u8], flags: u8| {
        let (src, sp, dst, dp) = if from_host {
            (host, 49152u16, server, 80u16)
        } else {
            (server, 80, host, 49152)
        };
        let mut decoded = tcp(src, sp, dst, dp, flags);
        decoded.tcp_seq = Some(seq);
        let placed = table.observe(&decoded, at(1_600_482_318), 60, 60);
        if let Some((flow, direction)) = placed {
            reassembler.offer(flow, direction, &decoded, payload);
        }
    };
    if client_spoke_first {
        offer(true, 1000, &[], SYN);
        offer(false, 5000, &[], SYN | ACK);
        offer(true, 1001, request, ACK);
        offer(false, 5001, response, ACK);
    } else {
        // No handshake: the capture begins with the server's bytes.
        offer(false, 5001, response, ACK);
        offer(true, 1001, request, ACK);
    }
    let _ = key;
    (table, reassembler.finish())
}

/// **Which endpoint is the client is decided by the bytes, both ways round.**
/// A capture that begins mid-conversation makes the SERVER the flow's
/// initiator, and a reader that took the initiator for the client would name
/// the server as the client on every row.
#[test]
fn a_conversation_read_the_other_way_round_still_names_the_client_correctly() {
    for client_spoke_first in [true, false] {
        let (flows, streams) = exchange_streams(client_spoke_first);
        let conversations = crate::http::conversations(&flows, &streams);
        assert_eq!(conversations.len(), 1, "one conversation");
        let conversation = &conversations[0];
        assert_eq!(
            conversation.client.port,
            Some(49152),
            "the client is the side whose bytes were requests (client first: \
             {client_spoke_first})"
        );
        assert_eq!(conversation.server.port, Some(80));
        assert_eq!(conversation.transactions.len(), 1);
        let transaction = &conversation.transactions[0];
        assert_eq!(
            transaction
                .request
                .as_ref()
                .and_then(|r| r.target.clone())
                .as_deref(),
            Some("/login")
        );
        assert_eq!(
            transaction.response.as_ref().and_then(|r| r.status),
            Some(200)
        );
        // And the pairing says what it rests on: a capture with no handshake
        // cannot claim the request order is the connection's.
        if client_spoke_first {
            assert_eq!(transaction.pairing, crate::http::Pairing::InOrder);
            assert!(!conversation.mid_connection());
        } else {
            assert_eq!(
                transaction.pairing,
                crate::http::Pairing::InOrderFromAnIncompleteStart,
                "no handshake was captured, so the start of this connection is missing"
            );
            assert!(conversation.mid_connection());
            assert!(conversation.requests.present && !conversation.requests.base_from_syn);
        }
    }
}

/// The same, for TLS: the client is the side that sent the ClientHello, and a
/// capture that begins with the server's bytes must still say so.
#[test]
fn a_tls_session_read_the_other_way_round_still_names_the_client_correctly() {
    let host = v4("10.42.85.10");
    let server = v4("93.184.216.34");
    let client_hello = include_bytes!("../tests/fixtures/tls12_client_to_server.bin");
    let server_hello = include_bytes!("../tests/fixtures/tls12_server_to_client.bin");

    for client_spoke_first in [true, false] {
        let mut table = FlowTable::new();
        let mut reassembler =
            crate::reassemble::Reassembler::new(crate::reassemble::ReassemblyConfig::default());
        let mut offer = |from_host: bool, seq: u32, payload: &[u8], flags: u8| {
            let (src, sp, dst, dp) = if from_host {
                (host, 49152u16, server, 443u16)
            } else {
                (server, 443, host, 49152)
            };
            let mut decoded = tcp(src, sp, dst, dp, flags);
            decoded.tcp_seq = Some(seq);
            if let Some((flow, direction)) = table.observe(&decoded, at(1_600_482_318), 60, 60) {
                reassembler.offer(flow, direction, &decoded, payload);
            }
        };
        if client_spoke_first {
            offer(true, 1001, client_hello, ACK);
            offer(false, 5001, server_hello, ACK);
        } else {
            offer(false, 5001, server_hello, ACK);
            offer(true, 1001, client_hello, ACK);
        }
        let streams = reassembler.finish();
        let sessions = crate::tls::sessions(&table, &streams);
        assert_eq!(sessions.len(), 1);
        let session = &sessions[0];
        assert_eq!(
            session.client.port,
            Some(49152),
            "the client is the side that sent the ClientHello (client first: \
             {client_spoke_first})"
        );
        assert_eq!(session.server.port, Some(443));
        assert_eq!(session.server_name(), Some("lab.seance.invalid"));
        assert_eq!(session.certificates.len(), 1);
        // Neither direction has a handshake in this fixture, so neither
        // session is complete however completely the records parsed.
        assert!(!session.is_complete());
        assert!(!session.client_stream.base_from_syn);
    }
}

/// **A cap that drops records raises an inventory stamp on the records it
/// bounds, not just a number on the capture record.** The records page
/// computes its banner from the records in front of the reader, so a count
/// they may never open is not a statement to them.
#[test]
fn a_cap_that_drops_records_stamps_the_records_it_bounds() {
    use crate::flows::{Direction, FlowKey};
    use crate::http::{Conversation, Doubt, Pairing, StreamFacts, Transaction};

    let client = Endpoint {
        ip: v4("10.42.85.10"),
        port: Some(49152),
    };
    let server = Endpoint {
        ip: v4("203.78.103.109"),
        port: Some(80),
    };
    let request = crate::http::parse_stream(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n", true)
        .messages
        .remove(0);
    let over = crate::http::MAX_TRANSACTIONS_PER_CAPTURE + 5;
    let conversation = Conversation {
        flow: FlowKey::new(Some(6), client, server),
        client,
        server,
        requests_from: Direction::Out,
        transactions: (0..over)
            .map(|_| Transaction {
                request: Some(request.clone()),
                response: None,
                pairing: Pairing::RequestUnanswered,
            })
            .collect(),
        requests: StreamFacts::default(),
        responses: StreamFacts::default(),
    };
    let _ = Doubt::default();

    let meta = clean_meta();
    let flows = c2_table();
    let conversations = [conversation];
    let mut input = input(&meta, &flows, &[]);
    input.http = &conversations;
    let out = emit(&input);

    let capture = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(capture, "http_transactions_beyond_cap"), &json!(5));
    assert_eq!(get(capture, "inventory_incomplete"), &json!(true));
    let detail = get(capture, "inventory_incomplete_detail")
        .as_str()
        .expect("a detail");
    assert!(detail.contains("HTTP transaction cap"), "{detail}");

    // And every transaction record carries it, because that is the list the
    // number is about.
    let transaction = of_type(&out, "HttpTransaction")[0];
    assert_eq!(get(transaction, "inventory_incomplete"), &json!(true));
    assert!(get(transaction, "inventory_incomplete_detail")
        .as_str()
        .is_some_and(|d| d.contains("no record was written for them")));
}

/// **An ARP binding is drawn from the capture's packets, so it inherits what
/// the capture fell short by.** A binding built from the first third of a file
/// must not read as the segment's whole ARP.
#[test]
fn an_arp_binding_inherits_the_captures_own_shortfall() {
    let mut table = crate::arp::ArpTable::new();
    table.observe(
        &crate::arp::Observation {
            operation: 2,
            sender_mac: [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e],
            sender_ip: "10.42.85.1".parse().expect("an address"),
            target_mac: [0; 6],
            target_ip: "10.42.85.10".parse().expect("an address"),
            frame_source_mac: Some([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]),
        },
        at(1_600_482_318),
    );

    let meta = clean_meta();
    let flows = c2_table();
    let mut input = input(&meta, &flows, &[]);
    input.arp = &table;
    // The capture was staged to a cap: everything drawn from it is drawn from
    // a prefix.
    input.bytes_declared = 4096 * 1000;
    input.staging_cap = 4096;
    input.bytes_staged = 4096;
    input.arp_unreadable = 3;
    let out = emit(&input);

    let binding = of_type(&out, "ArpBinding")[0];
    assert_eq!(get(binding, "ip"), "10.42.85.1");
    assert_eq!(get(binding, "content_incomplete"), &json!(true));
    let detail = get(binding, "content_incomplete_detail")
        .as_str()
        .expect("a detail");
    assert!(
        detail.contains("only the first 4096 bytes were read"),
        "{detail}"
    );
    // And the ARP frames this build cannot read are an inventory shortfall on
    // the binding list, not a number on one record.
    assert_eq!(get(binding, "inventory_incomplete"), &json!(true));
    assert!(get(binding, "inventory_incomplete_detail")
        .as_str()
        .is_some_and(|d| d.contains("3 ARP frame(s)")));
}

/// **A body cut by the ceiling leaves the transaction record saying so.** The
/// wire held more than the record and its artifact do, and "complete" beside
/// a prefix is the one thing a record must never say.
#[test]
fn a_body_cut_by_the_ceiling_stamps_the_transaction_record() {
    use crate::flows::{Direction, FlowKey};
    use crate::http::{BodyEnd, Conversation, Kind, Message, Pairing, StreamFacts, Transaction};

    let client = Endpoint {
        ip: v4("10.42.85.10"),
        port: Some(49152),
    };
    let server = Endpoint {
        ip: v4("203.78.103.109"),
        port: Some(80),
    };
    let mut response = Message {
        kind: Kind::Response,
        offset: 0,
        method: None,
        target: None,
        version: Some("HTTP/1.1".into()),
        status: Some(200),
        reason: Some("OK".into()),
        headers: std::collections::BTreeMap::new(),
        headers_complete: true,
        headers_dropped: 0,
        folded_headers: 0,
        body: b"the prefix that was kept".to_vec(),
        body_capped: true,
        body_end: BodyEnd::LengthSatisfied {
            declared: 41_943_040,
        },
    };
    response
        .headers
        .insert("content-length".into(), "41943040".into());
    assert!(
        !response.is_whole(),
        "a capped body is not a whole message, whatever its framing says"
    );

    let conversation = Conversation {
        flow: FlowKey::new(Some(TCP), client, server),
        client,
        server,
        requests_from: Direction::Out,
        transactions: vec![Transaction {
            request: None,
            response: Some(response),
            pairing: Pairing::ResponseUnmatched,
        }],
        requests: StreamFacts::default(),
        responses: StreamFacts::default(),
    };

    let meta = clean_meta();
    let flows = c2_table();
    let conversations = [conversation];
    let mut input = input(&meta, &flows, &[]);
    input.http = &conversations;
    let out = emit(&input);

    let transaction = of_type(&out, "HttpTransaction")[0];
    assert_eq!(
        get(transaction, "response")["complete"],
        json!(false),
        "{}",
        transaction.metadata["response"]
    );
    assert_eq!(get(transaction, "content_incomplete"), &json!(true));
    let detail = get(transaction, "content_incomplete_detail")
        .as_str()
        .expect("a detail");
    assert!(
        detail.contains(&crate::http::MAX_BODY_BYTES.to_string()),
        "the ceiling is named: {detail}"
    );
    // And the capture's own count of short transactions agrees with the row.
    let capture = of_type(&out, "NetworkCapture")[0];
    assert_eq!(get(capture, "http_transactions_incomplete"), &json!(1));

    // The body artifact holds the prefix and says which ceiling cut it.
    let body = out
        .iter()
        .find(|a| a.metadata.get("http_body").is_some())
        .expect("a body artifact");
    assert_eq!(body.metadata["content_incomplete"], json!(true));
    assert_eq!(body.metadata["content_incomplete_reason"], "cap_reached");
}

/// **"No server name was sent" is a claim about the client, and it must not be
/// made when the client's half of the conversation is not in the capture.**
/// Three reasons reach an absent SNI and only one is about the client; this
/// string is the record's name, its short description and the line a report
/// quotes.
#[test]
fn a_session_without_the_clients_half_does_not_claim_the_client_sent_no_name() {
    use crate::flows::{Endpoint as E, FlowKey};

    let client = E {
        ip: v4("10.42.85.10"),
        port: Some(49152),
    };
    let server = E {
        ip: v4("93.184.216.34"),
        port: Some(443),
    };
    let server_hello = include_bytes!("../tests/fixtures/tls12_server_to_client.bin");
    let read = crate::tls::read_direction(server_hello).expect("the server's direction");
    let session = crate::tls::Session {
        flow: FlowKey::new(Some(TCP), client, server),
        client,
        server,
        // The client's half is not in this capture at all.
        client_side: None,
        server_side: Some(read),
        client_stream: crate::http::StreamFacts::default(),
        server_stream: crate::http::StreamFacts::default(),
        certificates: Vec::new(),
        unparsable_certificates: 0,
    };
    assert!(!session.client_hello_read());

    let meta = clean_meta();
    let flows = c2_table();
    let sessions = [session];
    let mut input = input(&meta, &flows, &[]);
    input.tls = &sessions;
    let out = emit(&input);
    let record = of_type(&out, "TlsSession")[0];

    let name = get(record, "name").as_str().expect("a name");
    assert!(
        name.contains("the client's half of this conversation was not captured"),
        "{name}"
    );
    assert!(!name.contains("no server name was sent"), "{name}");
    assert_eq!(get(record, "client_hello_read"), &json!(false));
    // And the three fields read out of the ClientHello are null rather than
    // false and zero, which would read as answers.
    assert_eq!(get(record, "encrypted_client_hello"), &json!(null));
    assert_eq!(get(record, "session_resumption_attempted"), &json!(null));
    assert_eq!(get(record, "known_weak_ciphers_offered"), &json!(null));
    assert_eq!(get(record, "ja3_md5"), &json!(null));
}

/// **Every ceiling is named on the capture record, including the two the
/// bodies have.** The README claims it; the body budget and the inflate
/// ceiling were the two it was not true of.
#[test]
fn the_body_budget_and_the_inflate_ceiling_are_on_the_capture_record() {
    let meta = clean_meta();
    let flows = c2_table();
    let input = input(&meta, &flows, &[]);
    let out = emit(&input);
    let capture = of_type(&out, "NetworkCapture")[0];
    assert_eq!(
        get(capture, "http_body_budget"),
        &json!(crate::http::MAX_BODY_BYTES_PER_CAPTURE)
    );
    assert_eq!(
        get(capture, "http_body_inflate_ceiling"),
        &json!(crate::http::MAX_DECODED_BODY_BYTES)
    );
    assert_eq!(
        get(capture, "http_body_wire_ceiling"),
        &json!(crate::http::MAX_BODY_BYTES)
    );
    assert_eq!(get(capture, "http_body_bytes_held"), &json!(0));
    assert_eq!(
        get(capture, "http_bodies_cut_by_the_body_budget"),
        &json!(0)
    );
}

/// **A conversation the stream table had no room for says so on its own
/// record.** On DFIR Madness Case 001 the table filled with an RDP brute force
/// and every command-and-control flow's record then read like a flow that
/// carried no bytes: no `tcp_streams`, no stamp, only a capture-level sentence
/// on a record the examiner had not opened.
#[test]
fn a_flow_the_stream_table_refused_says_its_bytes_were_not_read() {
    let meta = clean_meta();
    let flows = c2_table();
    let refused: std::collections::BTreeSet<crate::flows::FlowKey> = flows
        .flows()
        .map(|f| crate::flows::FlowKey::new(f.protocol, f.initiator, f.responder))
        .collect();
    let mut input = input(&meta, &flows, &[]);
    input.stream_cap_reached = true;
    input.segments_beyond_stream_cap = 3;
    input.refused_stream_flows = &refused;

    let out = emit(&input);
    let flow = out
        .iter()
        .find(|a| a.metadata["type"] == "NetworkFlow")
        .expect("a flow record");
    assert_eq!(
        flow.metadata["tcp_streams_not_read"],
        serde_json::json!(true)
    );
    assert_eq!(
        flow.metadata["tcp_directions_not_read"],
        serde_json::json!(["local_to_remote", "remote_to_local"]),
        "neither direction was held"
    );
    assert_eq!(flow.metadata["content_incomplete"], serde_json::json!(true));
    assert_eq!(flow.metadata["content_incomplete_reason"], "cap_reached");
    let detail = flow.metadata["content_incomplete_detail"]
        .as_str()
        .expect("the record states what it is short of");
    assert!(
        detail.contains("this conversation's bytes were not reassembled"),
        "{detail}"
    );
}

/// **A conversation the table filled between its two directions names the
/// direction it refused.** The stream the table held was read — its request
/// parsed, its ClientHello made a `TlsSession` — so a stamp saying nothing was
/// read from the conversation would contradict the records beside it. Only
/// the refused direction is said to be unread.
#[test]
fn a_flow_refused_in_one_direction_names_that_direction_and_not_the_other() {
    let meta = clean_meta();
    let flows = c2_table();
    let host = v4("10.42.85.10");
    let c2 = v4("203.78.103.109");
    let key = crate::flows::FlowKey::new(
        Some(TCP),
        crate::flows::Endpoint {
            ip: host,
            port: Some(62414),
        },
        crate::flows::Endpoint {
            ip: c2,
            port: Some(443),
        },
    );
    // A table with room for one stream: the host's is tabled, then the table
    // is full when the reply arrives.
    let mut r = crate::reassemble::Reassembler::new(crate::reassemble::ReassemblyConfig {
        max_streams: 1,
        ..crate::reassemble::ReassemblyConfig::default()
    });
    let mut out_seg = tcp(host, 62414, c2, 443, ACK);
    out_seg.tcp_seq = Some(1001);
    r.offer(
        key,
        crate::flows::Direction::Out,
        &out_seg,
        b"GET / HTTP/1.1\r\n",
    );
    let mut in_seg = tcp(c2, 443, host, 62414, ACK);
    in_seg.tcp_seq = Some(5001);
    r.offer(
        key,
        crate::flows::Direction::In,
        &in_seg,
        b"HTTP/1.1 200 OK\r\n",
    );
    let refused = r.take_refused_flows();
    assert_eq!(refused.len(), 1, "the conversation is named");
    let streams = r.finish();
    assert_eq!(streams.len(), 1, "one direction was tabled");

    let mut input = input(&meta, &flows, &[]);
    input.streams = &streams;
    input.stream_cap_reached = true;
    input.segments_beyond_stream_cap = 1;
    input.refused_stream_flows = &refused;

    let out = emit(&input);
    let flow = out
        .iter()
        .find(|a| a.metadata["type"] == "NetworkFlow")
        .expect("a flow record");
    assert!(
        !flow.metadata["tcp_streams"]["local_to_remote"].is_null(),
        "the tabled direction is carried: {}",
        flow.metadata
    );
    assert_eq!(
        flow.metadata["tcp_directions_not_read"],
        serde_json::json!(["remote_to_local"]),
        "only the refused direction is named"
    );
    let detail = flow.metadata["content_incomplete_detail"]
        .as_str()
        .expect("the record states what it is short of");
    assert!(
        detail.contains("remote to local"),
        "the refused direction is named: {detail}"
    );
    assert!(
        !detail.contains("this conversation's bytes were not reassembled"),
        "the stamp does not deny what the tabled direction yielded: {detail}"
    );
}
