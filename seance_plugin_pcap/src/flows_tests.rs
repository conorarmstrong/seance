use super::*;
use crate::decode::{Decoded, Refusal};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP: u8 = 1;

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const FIN: u8 = 0x01;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;

fn v4(s: &str) -> IpAddr {
    IpAddr::V4(s.parse::<Ipv4Addr>().expect("literal"))
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().expect("literal"))
}

/// A decoded packet between two ports. Payload fields are irrelevant to the
/// flow layer and are zero.
fn pkt(src: &str, sp: u16, dst: &str, dp: u16, protocol: u8, flags: Option<u8>) -> Decoded {
    Decoded {
        src: v4(src),
        dst: v4(dst),
        protocol,
        src_port: Some(sp),
        dst_port: Some(dp),
        tcp_flags: flags,
        tcp_seq: None,
        payload_offset: 0,
        payload_len: 0,
        ipv4_checksum_unset: false,
    }
}

/// The same packet as sent by a host whose NIC had not yet filled the IPv4
/// checksum in: every outbound packet on a host capture looks like this.
fn unset(mut d: Decoded) -> Decoded {
    d.ipv4_checksum_unset = true;
    d
}

fn tcp(src: &str, sp: u16, dst: &str, dp: u16, flags: u8) -> Decoded {
    pkt(src, sp, dst, dp, TCP, Some(flags))
}

fn icmp(src: &str, dst: &str) -> Decoded {
    Decoded {
        src: v4(src),
        dst: v4(dst),
        protocol: ICMP,
        src_port: None,
        dst_port: None,
        tcp_flags: None,
        tcp_seq: None,
        payload_offset: 0,
        payload_len: 0,
        ipv4_checksum_unset: false,
    }
}

/// Seconds since the epoch, in the microsecond unit the container hands up.
fn at(secs: u64) -> Option<u64> {
    Some(secs * 1_000_000)
}

fn only_flow(table: &FlowTable) -> &Flow {
    let flows: Vec<&Flow> = table.flows().collect();
    assert_eq!(flows.len(), 1, "expected exactly one flow, got {:?}", flows);
    flows[0]
}

#[test]
fn packets_in_both_directions_between_the_same_two_endpoints_are_one_flow() {
    let mut table = FlowTable::new();
    table.observe(
        &tcp("10.42.85.10", 62414, "203.78.103.109", 443, SYN),
        at(100),
        74,
        74,
    );
    table.observe(
        &tcp("203.78.103.109", 443, "10.42.85.10", 62414, SYN | ACK),
        at(101),
        74,
        74,
    );
    table.observe(
        &tcp("10.42.85.10", 62414, "203.78.103.109", 443, ACK),
        at(102),
        66,
        66,
    );
    table.observe(
        &tcp("10.42.85.10", 62414, "203.78.103.109", 443, PSH | ACK),
        at(103),
        500,
        500,
    );
    table.observe(
        &tcp("203.78.103.109", 443, "10.42.85.10", 62414, ACK),
        at(110),
        1500,
        1500,
    );

    let flow = only_flow(&table);
    // The initiator is whoever sent the first packet; "out" is its direction.
    assert_eq!(flow.initiator.ip, v4("10.42.85.10"));
    assert_eq!(flow.initiator.port, Some(62414));
    assert_eq!(flow.responder.ip, v4("203.78.103.109"));
    assert_eq!(flow.responder.port, Some(443));
    assert_eq!(flow.protocol, Some(TCP));
    assert_eq!((flow.packets_out, flow.bytes_out), (3, 640));
    assert_eq!((flow.packets_in, flow.bytes_in), (2, 1574));
    assert_eq!(flow.packets(), 5);
    assert_eq!(flow.bytes(), 2214);
    assert_eq!(flow.first_seen_micros, at(100));
    assert_eq!(flow.last_seen_micros, at(110));
    assert_eq!(flow.duration_micros(), Some(10_000_000));
    assert_eq!(flow.truncated_packets, 0);
    assert_eq!(table.packets_in_flows(), 5);
}

#[test]
fn a_reply_that_arrives_first_in_the_file_still_makes_the_replier_the_initiator() {
    // The flow layer cannot know who "really" started a conversation whose
    // opening the capture missed; it records who it saw first and says so
    // through tcp_state, never by guessing from port numbers.
    let mut table = FlowTable::new();
    table.observe(
        &tcp("203.78.103.109", 443, "10.42.85.10", 62414, ACK),
        at(1),
        60,
        60,
    );
    table.observe(
        &tcp("10.42.85.10", 62414, "203.78.103.109", 443, ACK),
        at(2),
        60,
        60,
    );

    let flow = only_flow(&table);
    assert_eq!(flow.initiator.ip, v4("203.78.103.109"));
    assert_eq!(flow.packets_out, 1);
    assert_eq!(flow.packets_in, 1);
    assert_eq!(flow.tcp_state(), Some(TcpState::EstablishedNoHandshakeSeen));
}

#[test]
fn the_same_ports_over_udp_and_tcp_are_two_flows() {
    let mut table = FlowTable::new();
    table.observe(
        &pkt("10.0.0.5", 53, "10.0.0.1", 53, UDP, None),
        at(1),
        80,
        80,
    );
    table.observe(&tcp("10.0.0.5", 53, "10.0.0.1", 53, SYN), at(2), 74, 74);
    assert_eq!(table.len(), 2);
}

#[test]
fn a_lone_syn_with_no_reply_is_a_syn_only_flow() {
    let mut table = FlowTable::new();
    table.observe(&tcp("10.0.0.5", 40000, "10.0.0.9", 22, SYN), at(1), 74, 74);
    table.observe(&tcp("10.0.0.5", 40000, "10.0.0.9", 22, SYN), at(2), 74, 74);

    let flow = only_flow(&table);
    assert_eq!(flow.tcp_state(), Some(TcpState::SynOnly));
    assert_eq!(flow.packets_in, 0);
}

#[test]
fn a_completed_handshake_with_no_teardown_is_handshake_seen() {
    let mut table = FlowTable::new();
    table.observe(&tcp("10.0.0.5", 40000, "10.0.0.9", 22, SYN), at(1), 74, 74);
    table.observe(
        &tcp("10.0.0.9", 22, "10.0.0.5", 40000, SYN | ACK),
        at(2),
        74,
        74,
    );
    table.observe(&tcp("10.0.0.5", 40000, "10.0.0.9", 22, ACK), at(3), 66, 66);

    assert_eq!(only_flow(&table).tcp_state(), Some(TcpState::HandshakeSeen));
}

#[test]
fn a_handshake_followed_by_a_reset_is_reset_not_established() {
    let mut table = FlowTable::new();
    table.observe(&tcp("10.0.0.5", 40000, "10.0.0.9", 22, SYN), at(1), 74, 74);
    table.observe(
        &tcp("10.0.0.9", 22, "10.0.0.5", 40000, SYN | ACK),
        at(2),
        74,
        74,
    );
    table.observe(
        &tcp("10.0.0.9", 22, "10.0.0.5", 40000, RST | ACK),
        at(3),
        60,
        60,
    );

    assert_eq!(only_flow(&table).tcp_state(), Some(TcpState::Reset));
}

#[test]
fn a_handshake_followed_by_a_fin_is_closed() {
    let mut table = FlowTable::new();
    table.observe(&tcp("10.0.0.5", 40000, "10.0.0.9", 22, SYN), at(1), 74, 74);
    table.observe(
        &tcp("10.0.0.9", 22, "10.0.0.5", 40000, SYN | ACK),
        at(2),
        74,
        74,
    );
    table.observe(
        &tcp("10.0.0.5", 40000, "10.0.0.9", 22, FIN | ACK),
        at(3),
        66,
        66,
    );

    assert_eq!(only_flow(&table).tcp_state(), Some(TcpState::Closed));
}

#[test]
fn a_syn_sent_straight_to_a_reset_is_reset_because_the_refusal_is_the_finding() {
    // A port scan against a closed port looks exactly like this. "syn_only"
    // would hide the RST that proves the host was there and answered.
    let mut table = FlowTable::new();
    table.observe(&tcp("10.0.0.5", 40000, "10.0.0.9", 22, SYN), at(1), 74, 74);
    table.observe(
        &tcp("10.0.0.9", 22, "10.0.0.5", 40000, RST | ACK),
        at(2),
        60,
        60,
    );

    assert_eq!(only_flow(&table).tcp_state(), Some(TcpState::Reset));
}

#[test]
fn a_flow_that_is_not_tcp_has_no_tcp_state() {
    let mut table = FlowTable::new();
    table.observe(
        &pkt("10.0.0.5", 5353, "224.0.0.251", 5353, UDP, None),
        at(1),
        80,
        80,
    );
    assert_eq!(only_flow(&table).tcp_state(), None);
}

#[test]
fn a_tcp_packet_the_capture_cut_inside_its_header_has_no_flags_and_no_handshake_claim() {
    // `tcp_flags: None` on a TCP packet means the byte was not present; the
    // state machine must treat that as "no flags were read", which is not a
    // statement about a handshake either way. "No handshake seen" would be a
    // claim about flags on a packet whose flags byte is not in the file.
    let mut table = FlowTable::new();
    table.observe(
        &pkt("10.0.0.5", 40000, "10.0.0.9", 22, TCP, None),
        at(1),
        74,
        40,
    );
    assert_eq!(
        only_flow(&table).tcp_state(),
        Some(TcpState::NoTransportSeen)
    );
}

/// The IP-pair flow for TCP packets whose transport header the snaplen cut:
/// the protocol byte said TCP, no flags byte was ever in the file. Reporting
/// "no handshake seen" here would be the same row text as a genuine
/// mid-stream ACK-only conversation, for packets that had no readable flags.
#[test]
fn an_ip_pair_flow_of_tcp_packets_refused_before_their_flags_reports_no_transport_seen() {
    let mut table = FlowTable::new();
    table.observe_refusal(
        &Refusal::TransportTruncated {
            src: v4("10.0.0.5"),
            dst: v4("10.0.0.9"),
            protocol: TCP,
        },
        at(1),
        100,
        40,
    );
    let flow = only_flow(&table);
    assert_eq!(flow.protocol, Some(TCP));
    assert_eq!(flow.tcp_state(), Some(TcpState::NoTransportSeen));
    assert_eq!(flow.tcp_state().unwrap().as_str(), "no_transport_seen");
}

/// A capture joined mid-connection: ACKs and a FIN, no SYN in the file. The
/// connection's opening — its time and its initiator — is not in the
/// evidence, and "closed" alone would read exactly like a fully captured
/// connection. The token has to say what was seen.
#[test]
fn a_fin_on_a_flow_whose_handshake_was_never_seen_is_closed_no_handshake_seen() {
    let mut table = FlowTable::new();
    table.observe(
        &tcp("10.0.0.5", 50000, "203.0.113.9", 443, ACK),
        at(1),
        66,
        66,
    );
    table.observe(
        &tcp("203.0.113.9", 443, "10.0.0.5", 50000, ACK),
        at(2),
        66,
        66,
    );
    table.observe(
        &tcp("10.0.0.5", 50000, "203.0.113.9", 443, FIN | ACK),
        at(3),
        66,
        66,
    );
    let state = only_flow(&table).tcp_state();
    assert_eq!(state, Some(TcpState::ClosedNoHandshakeSeen));
    assert_eq!(state.unwrap().as_str(), "closed_no_handshake_seen");
}

/// A bare RST on a session the capture never saw open is not the same
/// finding as a SYN answered by RST: the first says nothing about who opened
/// the connection, the second is what a port scan leaves.
#[test]
fn a_reset_on_a_flow_whose_handshake_was_never_seen_is_reset_no_handshake_seen() {
    let mut table = FlowTable::new();
    table.observe(
        &tcp("10.0.0.5", 50000, "203.0.113.9", 443, ACK),
        at(1),
        66,
        66,
    );
    table.observe(
        &tcp("203.0.113.9", 443, "10.0.0.5", 50000, RST),
        at(2),
        60,
        60,
    );
    let state = only_flow(&table).tcp_state();
    assert_eq!(state, Some(TcpState::ResetNoHandshakeSeen));
    assert_eq!(state.unwrap().as_str(), "reset_no_handshake_seen");
}

/// Every token names what was seen, and every variant has its own token: two
/// variants sharing one would be the conflation this enum exists to prevent.
/// A capture that holds the SYN but missed the SYN-ACK — or the reverse — has
/// half the opening in it. "No handshake seen" was the label for that, which
/// says the opening is not in the evidence when part of it is; and the part
/// that is there is what dates the connection and names its initiator.
#[test]
fn half_a_handshake_in_the_file_is_partially_seen_not_no_handshake_seen() {
    // SYN seen, SYN-ACK missed, then data flowed.
    let mut table = FlowTable::with_cap(8);
    table.observe(&tcp("10.0.0.5", 40000, "10.0.0.9", 80, SYN), at(1), 74, 74);
    table.observe(&tcp("10.0.0.5", 40000, "10.0.0.9", 80, ACK), at(2), 60, 60);
    table.observe(&tcp("10.0.0.9", 80, "10.0.0.5", 40000, ACK), at(3), 60, 60);
    let flow = table.flows().next().expect("flow");
    assert_eq!(flow.tcp_state(), Some(TcpState::HandshakePartiallySeen));

    // SYN missed, SYN-ACK seen: the responder's half only.
    let mut table = FlowTable::with_cap(8);
    table.observe(
        &tcp("10.0.0.9", 80, "10.0.0.5", 40001, SYN | ACK),
        at(1),
        74,
        74,
    );
    table.observe(&tcp("10.0.0.5", 40001, "10.0.0.9", 80, ACK), at(2), 60, 60);
    let flow = table.flows().next().expect("flow");
    assert_eq!(flow.tcp_state(), Some(TcpState::HandshakePartiallySeen));

    // Neither: genuinely joined mid-connection.
    let mut table = FlowTable::with_cap(8);
    table.observe(&tcp("10.0.0.5", 40002, "10.0.0.9", 80, ACK), at(1), 60, 60);
    table.observe(&tcp("10.0.0.9", 80, "10.0.0.5", 40002, ACK), at(2), 60, 60);
    let flow = table.flows().next().expect("flow");
    assert_eq!(flow.tcp_state(), Some(TcpState::EstablishedNoHandshakeSeen));
}

#[test]
fn every_tcp_state_token_is_distinct_and_says_what_was_seen() {
    let all = [
        (TcpState::SynOnly, "syn_only"),
        (TcpState::HandshakeSeen, "handshake_seen"),
        (TcpState::HandshakePartiallySeen, "handshake_partially_seen"),
        (
            TcpState::EstablishedNoHandshakeSeen,
            "established_no_handshake_seen",
        ),
        (TcpState::Closed, "closed"),
        (TcpState::ClosedNoHandshakeSeen, "closed_no_handshake_seen"),
        (TcpState::Reset, "reset"),
        (TcpState::ResetNoHandshakeSeen, "reset_no_handshake_seen"),
        (TcpState::NoTransportSeen, "no_transport_seen"),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for (state, token) in all {
        assert_eq!(state.as_str(), token);
        assert!(seen.insert(token), "{token} is used twice");
    }
    assert_eq!(seen.len(), all.len());
}

#[test]
fn the_flow_cap_stops_new_flows_but_keeps_counting_packets_on_existing_ones() {
    let mut table = FlowTable::with_cap(2);
    table.observe(&tcp("10.0.0.5", 1, "10.0.0.9", 80, SYN), at(1), 74, 74);
    table.observe(&tcp("10.0.0.5", 2, "10.0.0.9", 80, SYN), at(2), 74, 74);
    assert!(!table.cap_reached());

    table.observe(&tcp("10.0.0.5", 3, "10.0.0.9", 80, SYN), at(3), 74, 74);
    table.observe(
        &tcp("10.0.0.9", 80, "10.0.0.5", 1, SYN | ACK),
        at(4),
        74,
        74,
    );

    assert!(table.cap_reached());
    assert_eq!(table.cap(), 2);
    assert_eq!(table.len(), 2);
    // The third flow's packet was seen and not tabled: it is counted, so the
    // capture record can say how much traffic the flow list does not cover.
    assert_eq!(table.packets_past_cap(), 1);
    // The reply on flow 1 still lands on flow 1.
    let first = table.flows().next().expect("first flow");
    assert_eq!(first.initiator.port, Some(1));
    assert_eq!(first.packets_in, 1);
    // Three tabled plus one past the cap: the two figures together account
    // for every packet observed.
    assert_eq!(table.packets_in_flows(), 3);
}

#[test]
fn a_packet_captured_short_of_its_wire_length_is_counted_as_truncated_at_its_captured_bytes() {
    let mut table = FlowTable::new();
    table.observe(&icmp("10.0.0.5", "10.0.0.1"), at(1), 1500, 96);
    table.observe(&icmp("10.0.0.1", "10.0.0.5"), at(2), 64, 64);

    let flow = only_flow(&table);
    assert_eq!(flow.truncated_packets, 1);
    // `bytes` is what the evidence holds; `wire_bytes` is what the capture
    // engine said crossed the wire. The viewer shows the first and flags the
    // gap; both must be present for that to be an honest figure.
    assert_eq!(flow.bytes_out, 96);
    assert_eq!(flow.bytes(), 160);
    assert_eq!(flow.wire_bytes(), 1564);
}

#[test]
fn a_packet_with_no_timestamp_is_counted_and_does_not_move_first_or_last_seen() {
    let mut table = FlowTable::new();
    table.observe(&icmp("10.0.0.5", "10.0.0.1"), None, 64, 64);
    table.observe(&icmp("10.0.0.5", "10.0.0.1"), at(50), 64, 64);
    table.observe(&icmp("10.0.0.5", "10.0.0.1"), None, 64, 64);

    let flow = only_flow(&table);
    assert_eq!(flow.first_seen_micros, at(50));
    assert_eq!(flow.last_seen_micros, at(50));
    assert_eq!(flow.packets_without_timestamp, 2);
    assert_eq!(flow.packets(), 3);
}

#[test]
fn a_flow_whose_packets_all_lack_timestamps_has_no_first_seen_rather_than_the_epoch() {
    let mut table = FlowTable::new();
    table.observe(&icmp("10.0.0.5", "10.0.0.1"), None, 64, 64);
    let flow = only_flow(&table);
    assert_eq!(flow.first_seen_micros, None);
    assert_eq!(flow.duration_micros(), None);
}

#[test]
fn a_checksum_failed_packet_lands_on_the_ip_pair_with_its_reason_and_no_ports() {
    let mut table = FlowTable::new();
    let refusal = Refusal::Ipv4ChecksumFailed {
        src: v4("10.0.0.5"),
        dst: v4("10.0.0.9"),
    };
    table.observe_refusal(&refusal, at(1), 100, 100);

    let flow = only_flow(&table);
    assert_eq!(flow.initiator.ip, v4("10.0.0.5"));
    assert_eq!(flow.initiator.port, None);
    assert_eq!(flow.responder.port, None);
    // The transport was never read, so the protocol is not claimed.
    assert_eq!(flow.protocol, None);
    assert_eq!(flow.packets_out, 1);
    assert_eq!(flow.bytes_out, 100);
    assert_eq!(
        flow.unattributed_packets.get("ipv4_checksum_failed"),
        Some(&1)
    );
    assert_eq!(flow.unattributed_packets_total(), 1);
    // And the capture-level table counts it too, so the capture record's
    // per-reason figures cover every refused packet, attributed or not.
    assert_eq!(table.refusals().get("ipv4_checksum_failed"), Some(&1));
}

/// A host capture with transmit checksum offload: the SYN goes out with a
/// zero checksum field, the SYN-ACK comes back with a verified one. Both
/// belong to one conversation, and a table that sent the unset packet
/// anywhere else would show the remote host opening a connection the local
/// host never sent a byte on.
#[test]
fn an_unset_checksum_packet_lands_on_its_ported_flow_and_is_counted_there_as_unset_not_refused() {
    let mut table = FlowTable::new();
    table.observe(
        &unset(tcp("10.0.0.5", 40000, "203.0.113.9", 443, SYN)),
        at(1),
        74,
        74,
    );
    table.observe(
        &tcp("203.0.113.9", 443, "10.0.0.5", 40000, SYN | ACK),
        at(2),
        74,
        74,
    );
    table.observe(
        &unset(tcp("10.0.0.5", 40000, "203.0.113.9", 443, ACK)),
        at(3),
        66,
        66,
    );

    let flow = only_flow(&table);
    assert_eq!(flow.initiator.ip, v4("10.0.0.5"));
    assert_eq!(flow.initiator.port, Some(40000));
    assert_eq!(flow.packets_out, 2);
    assert_eq!(flow.packets_in, 1);
    assert_eq!(flow.checksum_unset_packets, 2);
    assert_eq!(flow.tcp_state(), Some(TcpState::HandshakeSeen));
    // A qualification, not a refusal: nothing is unattributed and the
    // capture-level refusal table does not count it.
    assert_eq!(flow.unattributed_packets_total(), 0);
    assert_eq!(table.packets_refused(), 0);
    assert!(table.refusals().is_empty());
}

/// A packet refused for a nonzero, wrong checksum still lands on the IP pair
/// — but a ported flow between the same two hosts must be able to learn that
/// its other half may be sitting there, or it reads as a conversation the
/// remote host opened and the local host never answered.
#[test]
fn a_ported_flow_can_see_the_packets_refused_between_its_two_hosts_by_reason() {
    let mut table = FlowTable::new();
    table.observe(
        &tcp("203.0.113.9", 443, "10.0.0.5", 40000, SYN | ACK),
        at(2),
        74,
        74,
    );
    table.observe_refusal(
        &Refusal::Ipv4ChecksumFailed {
            src: v4("10.0.0.5"),
            dst: v4("203.0.113.9"),
        },
        at(1),
        74,
        74,
    );
    table.observe_refusal(
        &Refusal::Ipv4ChecksumFailed {
            src: v4("203.0.113.9"),
            dst: v4("10.0.0.5"),
        },
        at(3),
        60,
        60,
    );
    // A different pair of hosts: not this flow's business.
    table.observe_refusal(
        &Refusal::Ipv4ChecksumFailed {
            src: v4("10.0.0.5"),
            dst: v4("10.0.0.7"),
        },
        at(4),
        60,
        60,
    );

    let flows: Vec<&Flow> = table.flows().collect();
    assert_eq!(flows.len(), 3);
    let ported = 0;
    assert_eq!(flows[ported].initiator.port, Some(443));
    let refused = table.refused_packets_between_hosts(ported);
    assert_eq!(refused.get("ipv4_checksum_failed"), Some(&2));
    assert_eq!(refused.values().sum::<u64>(), 2);
    // The IP-pair flow does not count its own packets as "refused elsewhere".
    let pair = 1;
    assert_eq!(flows[pair].initiator.port, None);
    assert!(table.refused_packets_between_hosts(pair).is_empty());
}

/// A refusal that read the protocol byte is only the other half of a flow in
/// that protocol: a UDP fragment between two hosts says nothing about a TCP
/// conversation between them, but a checksum-failed packet, whose protocol
/// byte was never trusted, might belong to either.
#[test]
fn refusals_that_named_a_protocol_only_count_against_flows_in_that_protocol() {
    let mut table = FlowTable::new();
    table.observe(&tcp("10.0.0.5", 40000, "10.0.0.9", 443, SYN), at(1), 74, 74);
    table.observe(
        &pkt("10.0.0.5", 4000, "10.0.0.9", 53, UDP, None),
        at(2),
        1500,
        1500,
    );
    table.observe_refusal(
        &Refusal::NonInitialFragment {
            src: v4("10.0.0.5"),
            dst: v4("10.0.0.9"),
            protocol: UDP,
            id: 7,
            bytes_present: 500,
        },
        at(3),
        520,
        520,
    );
    table.observe_refusal(
        &Refusal::Ipv4ChecksumFailed {
            src: v4("10.0.0.9"),
            dst: v4("10.0.0.5"),
        },
        at(4),
        60,
        60,
    );

    let tcp_refused = table.refused_packets_between_hosts(0);
    assert_eq!(tcp_refused.get("non_initial_fragment"), None);
    assert_eq!(tcp_refused.get("ipv4_checksum_failed"), Some(&1));
    let udp_refused = table.refused_packets_between_hosts(1);
    assert_eq!(udp_refused.get("non_initial_fragment"), Some(&1));
    assert_eq!(udp_refused.get("ipv4_checksum_failed"), Some(&1));
}

#[test]
fn a_non_initial_fragment_lands_on_the_ip_pair_and_never_creates_a_ports_flow() {
    let mut table = FlowTable::new();
    // The first fragment carried the UDP header and made a ports flow.
    table.observe(
        &pkt("10.0.0.5", 4000, "10.0.0.9", 53, UDP, None),
        at(1),
        1500,
        1500,
    );
    table.observe_refusal(
        &Refusal::NonInitialFragment {
            src: v4("10.0.0.5"),
            dst: v4("10.0.0.9"),
            protocol: UDP,
            id: 7,
            bytes_present: 500,
        },
        at(1),
        520,
        520,
    );

    let flows: Vec<&Flow> = table.flows().collect();
    assert_eq!(flows.len(), 2);
    let pair = flows
        .iter()
        .find(|f| f.initiator.port.is_none())
        .expect("an IP-pair flow for the fragment");
    assert_eq!(pair.protocol, Some(UDP));
    assert_eq!(pair.responder.port, None);
    assert_eq!(pair.bytes_out, 520);
    assert_eq!(
        pair.unattributed_packets.get("non_initial_fragment"),
        Some(&1)
    );
    let ports = flows
        .iter()
        .find(|f| f.initiator.port.is_some())
        .expect("the ports flow");
    assert_eq!(ports.packets(), 1);
}

#[test]
fn a_refusal_with_no_addresses_creates_no_flow_and_is_counted_by_reason() {
    let mut table = FlowTable::new();
    table.observe_refusal(&Refusal::UnsupportedLinktype(228), at(1), 60, 60);
    table.observe_refusal(&Refusal::UnsupportedLinktype(228), at(2), 60, 60);
    table.observe_refusal(&Refusal::FrameTruncated { need: 14, have: 6 }, at(3), 60, 6);

    assert_eq!(table.len(), 0);
    assert_eq!(table.refusals().get("unsupported_linktype"), Some(&2));
    assert_eq!(table.refusals().get("frame_truncated"), Some(&1));
    assert_eq!(table.unsupported_linktypes().get(&228), Some(&2));
    assert_eq!(table.packets_refused(), 3);
}

#[test]
fn a_frame_with_no_network_layer_is_counted_and_is_not_a_refusal() {
    let mut table = FlowTable::new();
    table.observe_no_network_layer();
    assert_eq!(table.packets_no_network_layer(), 1);
    assert_eq!(table.packets_refused(), 0);
    assert_eq!(table.len(), 0);
}

#[test]
fn the_ip_pair_flows_count_against_the_cap_like_any_other() {
    let mut table = FlowTable::with_cap(1);
    table.observe(&tcp("10.0.0.5", 1, "10.0.0.9", 80, SYN), at(1), 74, 74);
    table.observe_refusal(
        &Refusal::Ipv4ChecksumFailed {
            src: v4("10.0.0.5"),
            dst: v4("10.0.0.7"),
        },
        at(2),
        60,
        60,
    );
    assert!(table.cap_reached());
    assert_eq!(table.packets_past_cap(), 1);
    // Still counted by reason at the capture level, so it is not lost twice.
    assert_eq!(table.refusals().get("ipv4_checksum_failed"), Some(&1));
}

#[test]
fn private_loopback_and_link_local_ranges_are_internal() {
    for ip in [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "127.0.0.1",
        "127.255.255.255",
        "169.254.1.1",
    ] {
        assert!(is_internal(v4(ip)), "{ip} should be internal");
    }
    for ip in ["::1", "fe80::1", "febf::1", "fc00::1", "fd12:3456::1"] {
        assert!(is_internal(v6(ip)), "{ip} should be internal");
    }
}

#[test]
fn routable_addresses_and_the_edges_of_the_private_ranges_are_not_internal() {
    for ip in [
        "203.78.103.109",
        "194.61.24.102",
        "8.8.8.8",
        "172.15.255.255",
        "172.32.0.0",
        "192.169.0.1",
        "11.0.0.1",
        "169.253.1.1",
        "224.0.0.251",
    ] {
        assert!(!is_internal(v4(ip)), "{ip} should not be internal");
    }
    for ip in ["2001:db8::1", "fec0::1", "fe00::1", "ff02::fb"] {
        assert!(!is_internal(v6(ip)), "{ip} should not be internal");
    }
}

#[test]
fn an_external_peer_is_routable_which_multicast_and_broadcast_are_not() {
    // "external" is the badge that finds a C2 address. Multicast, broadcast
    // and the unspecified address are not internal, but calling them external
    // would fill the top of the list with mDNS and DHCP.
    assert!(is_external(v4("203.78.103.109")));
    assert!(is_external(v6("2001:db8::1")));
    for ip in [
        "224.0.0.251",
        "239.255.255.250",
        "255.255.255.255",
        "0.0.0.0",
        "10.0.0.1",
    ] {
        assert!(!is_external(v4(ip)), "{ip} should not be external");
    }
    for ip in ["ff02::fb", "::", "fe80::1"] {
        assert!(!is_external(v6(ip)), "{ip} should not be external");
    }
}

#[test]
fn local_is_the_internal_endpoint_when_exactly_one_is_and_the_initiator_otherwise() {
    let mut table = FlowTable::new();
    // Server replies first in the file: the external host is the initiator,
    // but the local endpoint is still the internal one.
    table.observe(
        &tcp("203.78.103.109", 443, "10.42.85.10", 62414, ACK),
        at(1),
        60,
        60,
    );
    // Two internal hosts: the initiator is local.
    table.observe(&tcp("10.0.0.9", 22, "10.0.0.5", 40000, ACK), at(2), 60, 60);
    // Two external hosts (a SPAN of a transit link): the initiator is local.
    table.observe(&tcp("8.8.8.8", 53, "1.1.1.1", 53, ACK), at(3), 60, 60);

    let flows: Vec<&Flow> = table.flows().collect();
    let (local, remote) = flows[0].local_and_remote();
    assert_eq!(
        (local.ip, remote.ip),
        (v4("10.42.85.10"), v4("203.78.103.109"))
    );
    let (local, remote) = flows[1].local_and_remote();
    assert_eq!((local.ip, remote.ip), (v4("10.0.0.9"), v4("10.0.0.5")));
    let (local, remote) = flows[2].local_and_remote();
    assert_eq!((local.ip, remote.ip), (v4("8.8.8.8"), v4("1.1.1.1")));
}

#[test]
fn packet_and_byte_counters_saturate_rather_than_overflow_on_a_hostile_capture() {
    // orig_len is a u32 the file chooses; 2^32 packets of u32::MAX bytes is
    // not a real capture, but a counter that panics is a capture that hangs
    // the ingest, and the release profile turns overflow into a panic.
    let mut flow = Flow::new(
        Endpoint {
            ip: v4("10.0.0.5"),
            port: None,
        },
        Endpoint {
            ip: v4("10.0.0.9"),
            port: None,
        },
        Some(ICMP),
    );
    flow.bytes_out = u64::MAX - 10;
    flow.bytes_in = u64::MAX - 10;
    flow.wire_bytes_out = u64::MAX - 10;
    flow.wire_bytes_in = u64::MAX - 10;
    flow.packets_out = u64::MAX;
    flow.packets_in = u64::MAX;
    flow.count(Direction::Out, at(1), u32::MAX, u32::MAX);
    flow.count(Direction::In, at(2), u32::MAX, u32::MAX);
    assert_eq!(flow.bytes(), u64::MAX);
    assert_eq!(flow.wire_bytes(), u64::MAX);
    assert_eq!(flow.packets(), u64::MAX);
}
