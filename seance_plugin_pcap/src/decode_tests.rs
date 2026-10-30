//! Frame fixtures are hand-built, byte by byte, for the same reason the registry
//! crate builds `regf` base blocks by hand: a fixture produced by the code under
//! test proves only that the code agrees with itself. Every offset below is the
//! offset the RFC gives.
//!
//! Every test that expects a refusal names the variant. `decode` once returned
//! one value for "no IP here" and for five different refusals, and the tests
//! asserted that value for both an ARP frame and a bad checksum — so the suite
//! proved the two were indistinguishable and called it correct. A test that
//! accepts "some refusal" would let that come back.

use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

const LINKTYPE_ETHERNET: u16 = 1;
const LINKTYPE_RAW: u16 = 101;
const LINKTYPE_IEEE802_11: u16 = 105;
const LINKTYPE_LINUX_SLL: u16 = 113;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_AH: u8 = 51;

const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
const TCP_PSH: u8 = 0x08;

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

/// A 14-byte Ethernet II header. The two MACs are arbitrary but distinct, so a
/// decoder that reads the source where the destination is would be visible.
fn ethernet(ethertype: u16) -> Vec<u8> {
    let mut h = Vec::with_capacity(14);
    h.extend_from_slice(&[0x00, 0x0c, 0x29, 0x1a, 0x2b, 0x3c]); // dst
    h.extend_from_slice(&[0x00, 0x50, 0x56, 0xc0, 0x00, 0x08]); // src
    h.extend_from_slice(&ethertype.to_be_bytes());
    h
}

/// The 16-byte Linux "cooked capture" header (LINKTYPE_LINUX_SLL): packet type,
/// ARPHRD type, link-layer address length, an 8-byte address field, then the
/// protocol — which for IP carries the same ethertype values Ethernet uses.
fn linux_sll(ethertype: u16) -> Vec<u8> {
    let mut h = Vec::with_capacity(16);
    h.extend_from_slice(&0u16.to_be_bytes()); // packet type: to us
    h.extend_from_slice(&1u16.to_be_bytes()); // ARPHRD_ETHER
    h.extend_from_slice(&6u16.to_be_bytes()); // address length
    h.extend_from_slice(&[0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, 0x00, 0x00]);
    h.extend_from_slice(&ethertype.to_be_bytes());
    h
}

/// RFC 1071: the ones-complement sum of the header's 16-bit words, complemented.
/// Written out rather than reused from the decoder so the fixture and the code
/// under test cannot share a mistake.
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
        i += 2;
    }
    if i < header.len() {
        sum += u32::from(header[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An IPv4 header with a correct checksum. `options` must be a multiple of four
/// bytes; its presence raises IHL above 5 and moves the transport header.
fn ipv4(src: [u8; 4], dst: [u8; 4], protocol: u8, payload_len: usize, options: &[u8]) -> Vec<u8> {
    assert!(
        options.len().is_multiple_of(4),
        "IPv4 options are 32-bit words"
    );
    let ihl = 5 + options.len() / 4;
    let header_len = ihl * 4;
    let mut h = Vec::with_capacity(header_len);
    h.push(0x40 | ihl as u8); // version 4
    h.push(0x00); // DSCP/ECN
    h.extend_from_slice(&((header_len + payload_len) as u16).to_be_bytes());
    h.extend_from_slice(&0xbeefu16.to_be_bytes()); // identification
    h.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    h.push(64); // TTL
    h.push(protocol);
    h.extend_from_slice(&[0, 0]); // checksum, filled in below
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h.extend_from_slice(options);
    let ck = ipv4_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h
}

/// Overwrite one 16-bit word of an IPv4 header and recompute its checksum, so a
/// test can vary a field without the checksum gate refusing the frame for a
/// reason the test is not about.
fn patch_ipv4_word(header: &mut [u8], at: usize, word: u16) {
    header[at..at + 2].copy_from_slice(&word.to_be_bytes());
    header[10..12].copy_from_slice(&[0, 0]);
    let ck = ipv4_checksum(header);
    header[10..12].copy_from_slice(&ck.to_be_bytes());
}

/// A 40-byte IPv6 header. `payload_len` counts everything after it, extension
/// headers included.
fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload_len: usize) -> Vec<u8> {
    let mut h = Vec::with_capacity(40);
    h.extend_from_slice(&0x6000_0000u32.to_be_bytes()); // version 6, no TC/flow
    h.extend_from_slice(&(payload_len as u16).to_be_bytes());
    h.push(next_header);
    h.push(64); // hop limit
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    h
}

/// A minimal 8-byte hop-by-hop options header: next header, then a length in
/// 8-byte units *not counting the first eight*, then PadN filling the rest.
fn hop_by_hop(next_header: u8) -> Vec<u8> {
    vec![next_header, 0, 0x01, 0x04, 0, 0, 0, 0]
}

/// A 20-byte TCP header with no options (data offset 5).
fn tcp(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
    let mut h = Vec::with_capacity(20);
    h.extend_from_slice(&src_port.to_be_bytes());
    h.extend_from_slice(&dst_port.to_be_bytes());
    h.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // sequence
    h.extend_from_slice(&0x0000_0000u32.to_be_bytes()); // acknowledgement
    h.push(5 << 4); // data offset 5, reserved 0
    h.push(flags);
    h.extend_from_slice(&8192u16.to_be_bytes()); // window
    h.extend_from_slice(&[0, 0]); // checksum: not verified for TCP
    h.extend_from_slice(&[0, 0]); // urgent pointer
    h
}

/// An 8-byte UDP header. `length` is the header plus payload, per RFC 768.
fn udp(src_port: u16, dst_port: u16, payload_len: usize) -> Vec<u8> {
    let mut h = Vec::with_capacity(8);
    h.extend_from_slice(&src_port.to_be_bytes());
    h.extend_from_slice(&dst_port.to_be_bytes());
    h.extend_from_slice(&((8 + payload_len) as u16).to_be_bytes());
    h.extend_from_slice(&[0, 0]); // checksum: optional over IPv4
    h
}

/// Ethernet + IPv4 + TCP + payload, the shape most of these tests want.
fn eth_ipv4_tcp(
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let transport = {
        let mut t = tcp(src_port, dst_port, flags);
        t.extend_from_slice(payload);
        t
    };
    let mut frame = ethernet(ETHERTYPE_IPV4);
    frame.extend_from_slice(&ipv4(src, dst, IPPROTO_TCP, transport.len(), &[]));
    frame.extend_from_slice(&transport);
    frame
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// The decoded headers, or a panic that names what came back instead. Tests
/// that expect a decode go through this so a refusal or "no network layer"
/// fails them with the variant in the message rather than an `unwrap` line.
fn headers(linktype: u16, frame: &[u8]) -> Decoded {
    match decode(linktype, frame) {
        Decode::Headers(d) => d,
        other => panic!("expected decoded headers, got {other:?}"),
    }
}

/// The refusal, or a panic naming what came back instead.
fn refused(linktype: u16, frame: &[u8]) -> Refusal {
    match decode(linktype, frame) {
        Decode::Refused(r) => r,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Ethernet / IPv4 / TCP
// ---------------------------------------------------------------------------

/// The base case. Every later test varies one thing away from this frame, so if
/// this one is wrong the rest say nothing.
#[test]
fn an_ethernet_ipv4_tcp_frame_yields_its_addresses_ports_and_flags() {
    let frame = eth_ipv4_tcp(
        [10, 42, 85, 10],
        [203, 78, 103, 109],
        50875,
        443,
        TCP_SYN | TCP_ACK,
        b"hello",
    );

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.src, v4(10, 42, 85, 10));
    assert_eq!(d.dst, v4(203, 78, 103, 109));
    assert_eq!(d.protocol, IPPROTO_TCP);
    assert_eq!(d.src_port, Some(50875));
    assert_eq!(d.dst_port, Some(443));
    assert_eq!(d.tcp_flags, Some(TCP_SYN | TCP_ACK));
    assert_eq!(d.payload_offset, 14 + 20 + 20);
    assert_eq!(d.payload_len, 5);
    assert_eq!(
        &frame[d.payload_offset..d.payload_offset + d.payload_len],
        b"hello"
    );
}

/// **The big-endian port trap.** Ports are network byte order, and the code
/// around them — pcapng blocks, pcap record headers — is little-endian, so the
/// wrong `from_le_bytes` here is an easy and near-invisible mistake: port 80 read
/// the wrong way is 20480 and port 443 is 47873, both legal-looking ephemeral
/// ports. An examiner reading "the host was serving on 20480" concludes there was
/// no web server, which is the opposite of what the packet says.
/// `seance_plugin_memory_windows/src/netscan.rs` documents the same defect class
/// against tcpip.sys; this is the network tier's copy of that test.
#[test]
fn tcp_ports_are_read_big_endian_so_port_80_is_80_and_not_20480() {
    let frame = eth_ipv4_tcp(
        [10, 42, 85, 10],
        [194, 61, 24, 102],
        80,
        443,
        TCP_PSH | TCP_ACK,
        b"",
    );

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.src_port, Some(80), "not 20480");
    assert_eq!(d.dst_port, Some(443), "not 47873");
}

/// The flags byte is a single octet, so it cannot be got wrong by byte order —
/// but it can be got wrong by offset, which lands on the 4-bit data offset above
/// it and reports every segment as flagless. A flow with no flags has no TCP
/// state, and the flow table would grade a completed session the same as a
/// refused one.
#[test]
fn a_bare_syn_is_distinguishable_from_a_syn_ack_by_its_flags_byte() {
    let syn = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, TCP_SYN, b"");
    let syn_ack = eth_ipv4_tcp(
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        80,
        1234,
        TCP_SYN | TCP_ACK,
        b"",
    );

    assert_eq!(headers(LINKTYPE_ETHERNET, &syn).tcp_flags, Some(0x02));
    assert_eq!(headers(LINKTYPE_ETHERNET, &syn_ack).tcp_flags, Some(0x12));
}

#[test]
fn an_ethernet_ipv4_udp_frame_yields_its_ports_and_payload_bounds() {
    let payload = b"\x00\x01\x02\x03\x04\x05\x06\x07";
    let transport = {
        let mut t = udp(53210, 53, payload.len());
        t.extend_from_slice(payload);
        t
    };
    let mut frame = ethernet(ETHERTYPE_IPV4);
    frame.extend_from_slice(&ipv4(
        [10, 42, 85, 10],
        [10, 42, 85, 2],
        IPPROTO_UDP,
        transport.len(),
        &[],
    ));
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.protocol, IPPROTO_UDP);
    assert_eq!(d.src_port, Some(53210));
    assert_eq!(d.dst_port, Some(53), "not 13568");
    assert_eq!(d.tcp_flags, None, "UDP has no flags to report");
    assert_eq!(d.payload_offset, 14 + 20 + 8);
    assert_eq!(d.payload_len, payload.len());
    assert_eq!(
        &frame[d.payload_offset..d.payload_offset + d.payload_len],
        payload
    );
}

/// ICMP has no ports. Reporting the first four payload bytes as a port pair —
/// which is what a decoder that keys off "is there payload" rather than off the
/// protocol number does — invents a service that was never contacted.
#[test]
fn an_icmp_packet_is_decoded_with_no_ports_rather_than_borrowed_ones() {
    let icmp = [8u8, 0, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01]; // echo request
    let mut frame = ethernet(ETHERTYPE_IPV4);
    frame.extend_from_slice(&ipv4(
        [10, 42, 85, 10],
        [8, 8, 8, 8],
        IPPROTO_ICMP,
        icmp.len(),
        &[],
    ));
    frame.extend_from_slice(&icmp);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.protocol, IPPROTO_ICMP);
    assert_eq!(d.src_port, None);
    assert_eq!(d.dst_port, None);
    assert_eq!(d.tcp_flags, None);
    assert_eq!(d.payload_offset, 14 + 20);
    assert_eq!(d.payload_len, icmp.len());
}

/// IHL is in 32-bit words and is routinely 5, so a decoder that hardcodes 20
/// bytes works on almost every frame and then silently misreads the ones with
/// options. Here the option bytes sit exactly where the ports would be read from,
/// so a hardcoded offset produces the plausible-looking port 1796.
#[test]
fn ipv4_options_move_the_transport_header_and_are_not_themselves_read_as_ports() {
    let options = [0x07u8, 0x04, 0xAA, 0xBB]; // record route, no addresses yet
    let transport = tcp(31337, 8080, TCP_ACK);
    let mut frame = ethernet(ETHERTYPE_IPV4);
    frame.extend_from_slice(&ipv4(
        [172, 16, 0, 5],
        [172, 16, 0, 9],
        IPPROTO_TCP,
        transport.len(),
        &options,
    ));
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(
        d.src_port,
        Some(31337),
        "the option bytes are not the ports"
    );
    assert_ne!(d.src_port, Some(0x0704));
    assert_eq!(d.dst_port, Some(8080));
    assert_eq!(d.payload_offset, 14 + 24 + 20);
    assert_eq!(d.payload_len, 0);
}

/// A header whose checksum fails names addresses the evidence does not stand
/// behind, so the packet is not decoded — but it is not *deleted* either. The
/// refusal names the addresses as the bytes state them, so the caller can count
/// the packet against that IP pair under a stamp that says the header did not
/// verify. Before this was a refusal it was the same value as "ARP", and every
/// such packet vanished from the capture with nothing recording that it had.
#[test]
fn an_ipv4_header_whose_checksum_does_not_verify_is_refused_by_name_with_its_addresses() {
    let mut frame = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, TCP_SYN, b"");
    // Flip one bit in the source address, leaving the stored checksum stale.
    frame[14 + 12] ^= 0x01;

    let refusal = refused(LINKTYPE_ETHERNET, &frame);

    assert_eq!(
        refusal,
        Refusal::Ipv4ChecksumFailed {
            src: v4(11, 0, 0, 1),
            dst: v4(10, 0, 0, 2),
        },
        "a header that fails its own integrity check is refused, and the refusal carries the addresses it names"
    );
    assert_eq!(refusal.reason(), "ipv4_checksum_failed");
    assert_ne!(
        decode(LINKTYPE_ETHERNET, &frame),
        Decode::NoNetworkLayer,
        "a refused IP packet must never read as a frame with no IP in it"
    );
}

/// **The offload case.** On any capture taken on an endpoint — rather than a
/// tap or SPAN port — every packet the capturing host *sent* carries an IPv4
/// checksum of 0x0000, because the NIC fills it in after the capture point.
/// That is half the packets of every conversation on a host capture. Treating
/// it as a failed checksum says "these bytes are corrupt", which is false; the
/// NIC had not computed the field yet. And refusing it is worse than wrong:
/// the header is structurally intact and the transport header behind it is
/// readable, so a refusal deletes one direction of every conversation the
/// capturing host took part in and inverts who opened it. The packet decodes,
/// and the record says the field was unset — an examiner told "corrupt" looks
/// for tampering, one told "unset" looks at `ethtool -k`.
#[test]
fn an_ipv4_checksum_field_of_zero_decodes_with_its_ports_and_is_marked_unset_not_corrupt() {
    let mut frame = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, TCP_SYN, b"");
    assert_ne!(
        &frame[14 + 10..14 + 12],
        &[0, 0],
        "the fixture's real checksum must be nonzero or zeroing it changes nothing"
    );
    frame[14 + 10] = 0;
    frame[14 + 11] = 0;

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert!(
        d.ipv4_checksum_unset,
        "a zero checksum field is reported as unset"
    );
    assert_eq!(d.src, v4(10, 0, 0, 1));
    assert_eq!(d.dst, v4(10, 0, 0, 2));
    assert_eq!(d.protocol, IPPROTO_TCP);
    assert_eq!(d.src_port, Some(1234));
    assert_eq!(d.dst_port, Some(80));
    assert_eq!(d.tcp_flags, Some(TCP_SYN));
}

/// The other half of the offload rule: a header whose checksum verifies is not
/// marked unset, and a nonzero checksum that does not verify is still refused.
/// Without both, "unset" could quietly become the label for every packet.
#[test]
fn a_verified_checksum_is_not_marked_unset_and_a_stale_nonzero_one_is_still_refused() {
    let frame = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, TCP_SYN, b"");
    assert!(!headers(LINKTYPE_ETHERNET, &frame).ipv4_checksum_unset);

    let mut stale = frame.clone();
    stale[14 + 12] ^= 0x01;
    assert!(matches!(
        decode(LINKTYPE_ETHERNET, &stale),
        Decode::Refused(Refusal::Ipv4ChecksumFailed { .. })
    ));
}

/// An IPv6 header has no checksum, so the flag is a statement about IPv4 only
/// and must be false there rather than absent or accidentally true.
#[test]
fn an_ipv6_packet_is_never_marked_checksum_unset_because_ipv6_has_no_header_checksum() {
    let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let transport = tcp(1234, 80, TCP_SYN);
    let mut frame = ethernet(ETHERTYPE_IPV6);
    frame.extend_from_slice(&ipv6(src, dst, IPPROTO_TCP, transport.len()));
    frame.extend_from_slice(&transport);
    assert!(!headers(LINKTYPE_ETHERNET, &frame).ipv4_checksum_unset);
}

/// The companion to the tests above: the fixture builder's checksum must be the
/// one the wire would carry, or "rejects a bad checksum" would be trivially true
/// because it rejects every frame.
#[test]
fn the_unmodified_fixture_checksum_verifies_so_the_rejection_test_means_something() {
    let header = ipv4([10, 0, 0, 1], [10, 0, 0, 2], IPPROTO_TCP, 0, &[]);
    // Summing a header that already carries its checksum yields 0xffff.
    let mut sum: u32 = 0;
    for pair in header.as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    assert_eq!(sum, 0xffff);
}

/// A fragment other than the first carries no transport header at all: the
/// bytes at that offset are the middle of someone's payload. Reading them as
/// ports invents a connection to a service that was never contacted, and it is
/// a connection an attacker can choose the ports of — fragment offset 185 with
/// a payload that starts `31337 → 4444, PSH` is two bytes of header away from
/// a report that says the host spoke to a listener on 4444. The IPv6 twin of
/// this test existed and the IPv4 path, the common one, was never given it:
/// the decoder did not read the fragment-offset field at all.
#[test]
fn a_non_first_ipv4_fragment_is_refused_rather_than_given_the_ports_of_whatever_follows_it() {
    let body = tcp(31337, 4444, TCP_PSH); // payload bytes that look like a header
    let mut ip = ipv4([10, 0, 0, 1], [10, 0, 0, 2], IPPROTO_TCP, body.len(), &[]);
    patch_ipv4_word(&mut ip, 6, 0x00B9); // no flags, fragment offset 185 (byte 1480)
    let mut frame = ethernet(ETHERTYPE_IPV4);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&body);

    let refusal = refused(LINKTYPE_ETHERNET, &frame);

    assert_eq!(
        refusal,
        Refusal::NonInitialFragment {
            src: v4(10, 0, 0, 1),
            dst: v4(10, 0, 0, 2),
            protocol: IPPROTO_TCP,
            id: 0xbeef,
            bytes_present: body.len(),
        },
        "the addresses, protocol and identification are evidence; the ports are not"
    );
    assert_eq!(refusal.reason(), "non_initial_fragment");
}

/// The first fragment (offset 0, more-fragments set) does carry the transport
/// header, and refusing it too would lose the ports of every fragmented
/// conversation entirely.
#[test]
fn a_first_ipv4_fragment_with_more_to_follow_still_decodes_its_transport_header() {
    let transport = tcp(50000, 2049, TCP_ACK);
    let mut ip = ipv4(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        IPPROTO_TCP,
        transport.len(),
        &[],
    );
    patch_ipv4_word(&mut ip, 6, 0x2000); // more fragments, offset 0
    let mut frame = ethernet(ETHERTYPE_IPV4);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.dst_port, Some(2049));
}

/// Segmentation offload leaves the IPv4 total length at zero on frames captured
/// on the sending host. Treating zero literally reports every such packet as
/// carrying nothing, so a host capture's outbound payloads all read as empty.
#[test]
fn an_ipv4_total_length_of_zero_from_segmentation_offload_falls_back_to_the_bytes_captured() {
    let transport = {
        let mut t = tcp(50875, 443, TCP_ACK);
        t.extend_from_slice(b"six by");
        t
    };
    let mut ip = ipv4(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        IPPROTO_TCP,
        transport.len(),
        &[],
    );
    patch_ipv4_word(&mut ip, 2, 0);
    let mut frame = ethernet(ETHERTYPE_IPV4);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.dst_port, Some(443));
    assert_eq!(d.payload_offset, 14 + 20 + 20);
    assert_eq!(
        d.payload_len, 6,
        "the bytes present are all there is to go on"
    );

    // The same frame cut inside its TCP header is a snaplen truncation, not a
    // datagram that declared itself short: the field said nothing.
    assert_eq!(
        refused(LINKTYPE_ETHERNET, &frame[..14 + 20 + 10]),
        Refusal::TransportTruncated {
            src: v4(10, 0, 0, 1),
            dst: v4(10, 0, 0, 2),
            protocol: IPPROTO_TCP,
        }
    );
}

/// Padding is not payload, and it is not a transport header either. An IPv4
/// datagram whose own length says nothing follows its header, inside a frame
/// the NIC padded to 60 bytes with stale buffer contents, must not have those
/// bytes read as ports and flags. Here they would read as 16705 → 16705 with
/// flags 0x41 — a service that was never contacted.
#[test]
fn ethernet_padding_past_the_end_of_a_short_ip_datagram_is_not_read_as_a_transport_header() {
    for protocol in [IPPROTO_TCP, IPPROTO_UDP] {
        let mut frame = ethernet(ETHERTYPE_IPV4);
        frame.extend_from_slice(&ipv4([10, 0, 0, 1], [10, 0, 0, 2], protocol, 0, &[]));
        frame.resize(60, 0x41);

        assert_eq!(
            refused(LINKTYPE_ETHERNET, &frame),
            Refusal::DatagramTooShortForTransport {
                src: v4(10, 0, 0, 1),
                dst: v4(10, 0, 0, 2),
                protocol,
                declared: 0,
            },
            "protocol {protocol}: the datagram, not the frame, is what ended"
        );
    }
}

/// The IPv4 header's own length field cannot be smaller than the header: a
/// value that is has no meaning and must not be turned into a payload bound.
#[test]
fn an_ipv4_total_length_shorter_than_its_own_header_is_refused_as_malformed() {
    let mut ip = ipv4([10, 0, 0, 1], [10, 0, 0, 2], IPPROTO_TCP, 20, &[]);
    patch_ipv4_word(&mut ip, 2, 10);
    let mut frame = ethernet(ETHERTYPE_IPV4);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp(1, 2, TCP_SYN));

    let refusal = refused(LINKTYPE_ETHERNET, &frame);

    assert!(
        matches!(refusal, Refusal::MalformedIpHeader { .. }),
        "got {refusal:?}"
    );
}

/// Ethertype 0x0800 says IPv4; a version nibble that says otherwise is not a
/// frame with no network layer, it is a frame whose network layer this module
/// could not read. The two must not share a value.
#[test]
fn an_ip_version_nibble_that_contradicts_the_ethertype_is_refused_not_reported_as_no_ip() {
    let mut frame = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, TCP_SYN, b"");
    frame[14] = 0x65; // version 6, IHL 5, under an IPv4 ethertype

    let refusal = refused(LINKTYPE_ETHERNET, &frame);

    assert!(
        matches!(refusal, Refusal::MalformedIpHeader { .. }),
        "got {refusal:?}"
    );
    assert_eq!(refusal.reason(), "malformed_ip_header");
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

#[test]
fn an_ipv6_tcp_frame_decodes_both_addresses_and_ports() {
    let src: Ipv6Addr = "2001:db8::10".parse().unwrap();
    let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let transport = {
        let mut t = tcp(49152, 443, TCP_SYN);
        t.extend_from_slice(b"xyz");
        t
    };
    let mut frame = ethernet(ETHERTYPE_IPV6);
    frame.extend_from_slice(&ipv6(src, dst, IPPROTO_TCP, transport.len()));
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.src, IpAddr::V6(src));
    assert_eq!(d.dst, IpAddr::V6(dst));
    assert_eq!(d.protocol, IPPROTO_TCP);
    assert_eq!(d.src_port, Some(49152));
    assert_eq!(d.dst_port, Some(443));
    assert_eq!(d.payload_offset, 14 + 40 + 20);
    assert_eq!(d.payload_len, 3);
}

/// IPv6 puts the transport header behind a chain rather than at a fixed offset.
/// A decoder that reads the next-header field and stops sees protocol 0 here and
/// would either report a hop-by-hop "protocol" or drop the packet — so every TCP
/// conversation carrying a router alert disappears from the flow table, and the
/// absence looks like the hosts never spoke.
#[test]
fn an_ipv6_hop_by_hop_header_is_walked_past_to_reach_the_tcp_header() {
    let src: Ipv6Addr = "fe80::1".parse().unwrap();
    let dst: Ipv6Addr = "fe80::2".parse().unwrap();
    let ext = hop_by_hop(IPPROTO_TCP);
    let transport = tcp(1025, 22, TCP_ACK);
    let mut frame = ethernet(ETHERTYPE_IPV6);
    frame.extend_from_slice(&ipv6(
        src,
        dst,
        IPPROTO_HOPOPTS,
        ext.len() + transport.len(),
    ));
    frame.extend_from_slice(&ext);
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(
        d.protocol, IPPROTO_TCP,
        "the reported protocol is the transport, not the extension header"
    );
    assert_eq!(d.src_port, Some(1025));
    assert_eq!(d.dst_port, Some(22));
    assert_eq!(d.payload_offset, 14 + 40 + 8 + 20);
    assert_eq!(d.payload_len, 0);
}

/// The IPv6 twin of the IPv4 offload case: a Payload Length of zero means a
/// jumbogram or a locally captured offload frame, and in both the bytes present
/// are the only measure. Reading zero literally zeroes every outbound IPv6
/// payload on a host capture — and because a zero payload never reaches the DNS
/// decoder, IPv6 DNS on such a capture produces no resolutions at all, which
/// reads as "no DNS was sent".
#[test]
fn an_ipv6_payload_length_of_zero_from_offload_falls_back_to_the_bytes_captured() {
    let src: Ipv6Addr = "2001:db8::10".parse().unwrap();
    let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let transport = {
        let mut t = tcp(49152, 443, TCP_ACK);
        t.extend_from_slice(b"ten bytes!");
        t
    };
    let mut frame = ethernet(ETHERTYPE_IPV6);
    frame.extend_from_slice(&ipv6(src, dst, IPPROTO_TCP, 0));
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.dst_port, Some(443));
    assert_eq!(d.payload_offset, 14 + 40 + 20);
    assert_eq!(d.payload_len, 10, "not zero");
}

/// The Authentication Header is an extension header, and its length field is
/// in 4-byte units minus two — not the 8-byte-units-minus-one rule the other
/// extension headers use. A walker that stops at 51 reports an AH-protected
/// TCP session as a portless protocol-51 flow that never joins the TCP table;
/// a walker that applies the 8-byte rule lands its transport header in the
/// wrong place and reads the ICV as ports.
#[test]
fn an_ipv6_authentication_header_is_walked_in_four_byte_units_to_reach_the_tcp_header() {
    let src: Ipv6Addr = "2001:db8::a".parse().unwrap();
    let dst: Ipv6Addr = "2001:db8::b".parse().unwrap();
    // RFC 4302: next header, payload length (= AH length in 32-bit words minus
    // two, so 1 means twelve bytes), reserved, SPI, sequence number.
    let ah = [
        IPPROTO_TCP,
        1,
        0,
        0,
        0x00,
        0x00,
        0x10,
        0x01,
        0x00,
        0x00,
        0x00,
        0x2a,
    ];
    let transport = tcp(1234, 80, TCP_ACK);
    let mut frame = ethernet(ETHERTYPE_IPV6);
    frame.extend_from_slice(&ipv6(src, dst, IPPROTO_AH, ah.len() + transport.len()));
    frame.extend_from_slice(&ah);
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.protocol, IPPROTO_TCP, "not 51");
    assert_eq!(d.src_port, Some(1234));
    assert_eq!(d.dst_port, Some(80));
    assert_eq!(d.payload_offset, 14 + 40 + 12 + 20);
}

// ---------------------------------------------------------------------------
// Frames that carry no IP, and tags in front of the ones that do
// ---------------------------------------------------------------------------

/// ARP is not a failure and not a refusal: the frame is intact and simply has no
/// IP layer. Reporting it as a refusal would make every capture look partly
/// undecodable, which devalues the refusals that mean something. It is its own
/// outcome — never a value a refusal can also produce.
#[test]
fn an_arp_frame_is_a_well_formed_frame_with_no_network_layer_rather_than_a_refusal() {
    let mut frame = ethernet(ETHERTYPE_ARP);
    frame.extend_from_slice(&[
        0x00, 0x01, // hardware type: Ethernet
        0x08, 0x00, // protocol type: IPv4
        0x06, 0x04, // address lengths
        0x00, 0x01, // opcode: request
        0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, 10, 42, 85, 1, // sender
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 10, 42, 85, 10, // target
    ]);

    // ARP is its own outcome: no IP layer, and the claims inside it read,
    // because they are the only record of which hardware answered for which
    // address. The caller counts it as a frame with no network layer all the
    // same.
    let claim = match decode(LINKTYPE_ETHERNET, &frame) {
        Decode::Arp(Some(claim)) => claim,
        other => panic!("{other:?}"),
    };
    assert_eq!(claim.operation, 1);
    assert_eq!(claim.sender_mac, [0x00, 0x50, 0x56, 0xc0, 0x00, 0x08]);
    assert_eq!(claim.sender_ip, std::net::Ipv4Addr::new(10, 42, 85, 1));
    assert_eq!(claim.target_ip, std::net::Ipv4Addr::new(10, 42, 85, 10));
    assert_eq!(
        claim.frame_source_mac,
        Some([0x00, 0x50, 0x56, 0xc0, 0x00, 0x08]),
        "the frame's own source, which a claim is compared against -- here the fixture's \
         sender claims its own address and the two agree"
    );
    assert_eq!(claim.frame_source_mac, Some(claim.sender_mac));

    // A hardware or protocol type this build does not read is an ARP frame it
    // could not read, which is not the same as a segment with no ARP on it.
    let mut foreign = ethernet(ETHERTYPE_ARP);
    foreign.extend_from_slice(&[0x00, 0x06, 0x80, 0x35, 0x06, 0x04, 0x00, 0x01]);
    foreign.extend_from_slice(&[0u8; 20]);
    assert_eq!(decode(LINKTYPE_ETHERNET, &foreign), Decode::Arp(None));

    // And a frame cut inside the packet is refused the same way.
    let mut cut = ethernet(ETHERTYPE_ARP);
    cut.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]);
    assert_eq!(decode(LINKTYPE_ETHERNET, &cut), Decode::Arp(None));
}

/// A 802.1Q tag inserts four bytes between the MACs and the real ethertype. A
/// decoder that does not unwrap it sees ethertype 0x8100, concludes "not IP", and
/// silently drops every packet on a tagged trunk — which on a switch SPAN capture
/// is most of the evidence.
#[test]
fn a_vlan_tagged_frame_decodes_the_ipv4_packet_behind_the_tag() {
    let transport = tcp(4444, 445, TCP_PSH | TCP_ACK);
    let mut frame = ethernet(ETHERTYPE_VLAN);
    frame.extend_from_slice(&0x0064u16.to_be_bytes()); // priority 0, VLAN id 100
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(&ipv4(
        [10, 42, 85, 10],
        [10, 42, 85, 3],
        IPPROTO_TCP,
        transport.len(),
        &[],
    ));
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.src, v4(10, 42, 85, 10));
    assert_eq!(d.dst_port, Some(445));
    assert_eq!(d.payload_offset, 14 + 4 + 20 + 20);
}

/// More tags than this build walks is a refusal, not a frame with no IP in it:
/// there may well be IP behind the fourth tag, and "no network layer" would be
/// a claim about bytes that were never looked at.
#[test]
fn a_vlan_stack_deeper_than_the_walk_is_refused_rather_than_reported_as_no_ip() {
    let mut frame = ethernet(ETHERTYPE_VLAN);
    for _ in 0..3 {
        frame.extend_from_slice(&0x0001u16.to_be_bytes());
        frame.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
    }
    frame.extend_from_slice(&0x0001u16.to_be_bytes());
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(&ipv4([10, 0, 0, 1], [10, 0, 0, 2], IPPROTO_TCP, 20, &[]));
    frame.extend_from_slice(&tcp(1, 2, TCP_SYN));

    let refusal = refused(LINKTYPE_ETHERNET, &frame);

    assert_eq!(refusal, Refusal::VlanDepthExceeded);
    assert_eq!(refusal.reason(), "vlan_depth_exceeded");
}

// ---------------------------------------------------------------------------
// Link types other than Ethernet
// ---------------------------------------------------------------------------

/// LINKTYPE_RAW has no link header at all; the frame begins at the IP version
/// nibble. Skipping a nonexistent 14-byte Ethernet header here reads the IP
/// header from the middle of itself, which yields addresses assembled from a TTL
/// and a checksum.
#[test]
fn linktype_raw_starts_at_the_ip_version_nibble_with_no_link_header() {
    let transport = tcp(1337, 80, TCP_SYN);
    let mut frame = ipv4(
        [192, 168, 1, 50],
        [93, 184, 216, 34],
        IPPROTO_TCP,
        transport.len(),
        &[],
    );
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_RAW, &frame);

    assert_eq!(d.src, v4(192, 168, 1, 50));
    assert_eq!(d.dst, v4(93, 184, 216, 34));
    assert_eq!(d.dst_port, Some(80), "not 20480");
    assert_eq!(d.payload_offset, 20 + 20);
}

/// The same, for IPv6: LINKTYPE_RAW carries either family and the version nibble
/// is the only thing that says which.
#[test]
fn linktype_raw_reads_the_version_nibble_to_tell_ipv4_from_ipv6() {
    let src: Ipv6Addr = "2001:db8::beef".parse().unwrap();
    let dst: Ipv6Addr = "2001:db8::cafe".parse().unwrap();
    let transport = udp(5353, 5353, 0);
    let mut frame = ipv6(src, dst, IPPROTO_UDP, transport.len());
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_RAW, &frame);

    assert_eq!(d.src, IpAddr::V6(src));
    assert_eq!(d.protocol, IPPROTO_UDP);
    assert_eq!(d.src_port, Some(5353));
}

/// A RAW frame is IP by definition, so a version nibble that is neither 4 nor 6
/// is a header this module cannot read — not a frame without one.
#[test]
fn linktype_raw_with_an_unknown_version_nibble_is_refused_not_reported_as_no_ip() {
    let mut frame = vec![0x50u8; 40];
    frame[0] = 0x50; // version 5

    let refusal = refused(LINKTYPE_RAW, &frame);

    assert!(
        matches!(refusal, Refusal::MalformedIpHeader { .. }),
        "got {refusal:?}"
    );
}

/// Linux SLL is what `tcpdump -i any` produces, so it turns up in captures taken
/// during incident response far more often than its obscurity suggests. Its
/// header is 16 bytes, not Ethernet's 14: getting that wrong shifts every field
/// by two and the IPv4 checksum then fails, so the whole capture decodes to
/// nothing at all.
#[test]
fn linktype_linux_sll_skips_its_sixteen_byte_cooked_header() {
    let transport = tcp(60000, 3389, TCP_SYN);
    let mut frame = linux_sll(ETHERTYPE_IPV4);
    frame.extend_from_slice(&ipv4(
        [10, 42, 85, 115],
        [10, 42, 85, 10],
        IPPROTO_TCP,
        transport.len(),
        &[],
    ));
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_LINUX_SLL, &frame);

    assert_eq!(d.src, v4(10, 42, 85, 115));
    assert_eq!(d.dst, v4(10, 42, 85, 10));
    assert_eq!(d.dst_port, Some(3389));
    assert_eq!(d.payload_offset, 16 + 20 + 20);
}

/// A LINKTYPE this build cannot decode must be refused **by number**. "No
/// network layer" would be recorded as "this frame carried no IP", which is a
/// false statement about the evidence: a capture of 802.11 management frames
/// would render as a network with no traffic on it, and nothing on the screen
/// would tell the examiner that a decoder was missing rather than that the wire
/// was quiet. It is the same discipline `netscan.rs` applies when it refuses an
/// unknown `_TCP_ENDPOINT` layout instead of guessing offsets.
#[test]
fn an_undecodable_linktype_is_refused_by_number_rather_than_reported_as_carrying_no_ip() {
    let frame = vec![0u8; 64];

    let refusal = refused(LINKTYPE_IEEE802_11, &frame);

    assert_eq!(refusal, Refusal::UnsupportedLinktype(LINKTYPE_IEEE802_11));
    assert_eq!(refusal.reason(), "unsupported_linktype");

    // The number must survive into whatever the caller prints, or the refusal
    // record cannot name the format the examiner needs a decoder for.
    assert!(
        format!("{refusal:?}").contains("105"),
        "the refusal must name the linktype: {refusal:?}"
    );
}

/// The refusal is a property of the linktype, not of the bytes: a perfectly good
/// IPv4 packet handed over under an unsupported linktype is still a refusal,
/// because this build cannot know where the link header ends.
#[test]
fn an_unsupported_linktype_is_refused_even_when_the_bytes_happen_to_parse_as_ip() {
    let frame = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, TCP_SYN, b"");

    assert_eq!(
        decode(LINKTYPE_IEEE802_11, &frame),
        Decode::Refused(Refusal::UnsupportedLinktype(LINKTYPE_IEEE802_11))
    );
}

/// Every refusal token is distinct and machine-safe, because the emission layer
/// counts and names refusals by it. Two variants sharing a token would be the
/// `Ok(None)` conflation back again, one layer up.
#[test]
fn every_refusal_reason_is_a_distinct_snake_case_token() {
    let a = v4(10, 0, 0, 1);
    let b = v4(10, 0, 0, 2);
    let all = [
        Refusal::UnsupportedLinktype(105),
        Refusal::FrameTruncated { need: 14, have: 3 },
        Refusal::Ipv4ChecksumFailed { src: a, dst: b },
        Refusal::MalformedIpHeader { detail: "x" },
        Refusal::VlanDepthExceeded,
        Refusal::ExtensionHeaderDepthExceeded,
        Refusal::NonInitialFragment {
            src: a,
            dst: b,
            protocol: 6,
            id: 1,
            bytes_present: 0,
        },
        Refusal::TransportTruncated {
            src: a,
            dst: b,
            protocol: 6,
        },
        Refusal::DatagramTooShortForTransport {
            src: a,
            dst: b,
            protocol: 6,
            declared: 4,
        },
    ];

    let mut seen = std::collections::BTreeSet::new();
    for refusal in &all {
        let token = refusal.reason();
        // The emission layer asks by token which refusals reached no flow;
        // the answer must be the variant's own, or a new variant with
        // addresses would be stamped as address-less one layer up.
        assert_eq!(
            Refusal::reason_carries_addresses(token),
            refusal.addresses().is_some(),
            "{token}: the token table and the variant disagree about addresses"
        );
        assert!(
            !token.is_empty()
                && token
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'),
            "{token:?} is not snake_case"
        );
        assert!(seen.insert(token), "{token} is used by two variants");
    }
    assert_eq!(seen.len(), all.len());
}

// ---------------------------------------------------------------------------
// Truncation
// ---------------------------------------------------------------------------

/// Every capture truncates: snaplen cuts frames mid-header, and the last record
/// in a capture stopped by a full disk or a killed process is cut wherever the
/// write stopped. Each prefix below is a frame an examiner will really be handed.
/// A panic here aborts the ingest of a 188 MB capture over one short frame, and
/// an out-of-bounds read is a `forbid(unsafe_code)` crate's version of the same
/// thing. Beyond not panicking, every prefix must say *what* was cut: no prefix
/// of an IPv4 frame is a frame with no network layer.
#[test]
fn every_truncation_of_an_ethernet_frame_names_what_was_cut_and_never_panics() {
    let full = eth_ipv4_tcp(
        [10, 42, 85, 10],
        [203, 78, 103, 109],
        50875,
        443,
        TCP_SYN,
        b"payload",
    );

    for n in 0..=full.len() {
        let frame = &full[..n];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            decode(LINKTYPE_ETHERNET, frame)
        }))
        .unwrap_or_else(|_| panic!("decode panicked on a {n}-byte frame"));

        match (n, &result) {
            (0..14, Decode::Refused(Refusal::FrameTruncated { need: 14, have })) if *have == n => {}
            (14..34, Decode::Refused(Refusal::FrameTruncated { need: 34, have })) if *have == n => {
            }
            (
                34..54,
                Decode::Refused(Refusal::TransportTruncated {
                    src,
                    dst,
                    protocol: IPPROTO_TCP,
                }),
            ) if *src == v4(10, 42, 85, 10) && *dst == v4(203, 78, 103, 109) => {}
            (54.., Decode::Headers(d)) => {
                let end = d
                    .payload_offset
                    .checked_add(d.payload_len)
                    .expect("payload bounds must not overflow");
                assert!(
                    end <= n,
                    "a {n}-byte frame reported payload out to {end}, which is not in evidence"
                );
                assert_eq!(d.dst_port, Some(443));
            }
            _ => panic!("a {n}-byte frame decoded to {result:?}"),
        }
    }
}

/// The same sweep for the two headerless/short-header linktypes, where an
/// off-by-one in the header skip is not caught by an ethertype check.
#[test]
fn every_truncation_of_a_raw_or_cooked_frame_names_what_was_cut_and_never_panics() {
    let transport = tcp(1337, 80, TCP_SYN);
    let mut ip = ipv4(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        IPPROTO_TCP,
        transport.len(),
        &[],
    );
    ip.extend_from_slice(&transport);

    let mut cooked = linux_sll(ETHERTYPE_IPV4);
    cooked.extend_from_slice(&ip);

    for (linktype, full, link_len) in [
        (LINKTYPE_RAW, &ip, 0usize),
        (LINKTYPE_LINUX_SLL, &cooked, 16usize),
    ] {
        for n in 0..=full.len() {
            let frame = &full[..n];
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decode(linktype, frame)))
                    .unwrap_or_else(|_| {
                        panic!("decode panicked on a {n}-byte LINKTYPE {linktype} frame")
                    });

            let ip_end = link_len + 20;
            let transport_end = ip_end + 20;
            match &result {
                Decode::Refused(Refusal::FrameTruncated { need, have }) if n < link_len => {
                    assert_eq!(
                        (*need, *have),
                        (link_len, n),
                        "LINKTYPE {linktype}, {n} bytes"
                    );
                }
                Decode::Refused(Refusal::FrameTruncated { need, have }) if n < ip_end => {
                    assert_eq!(
                        (*need, *have),
                        (ip_end, n),
                        "LINKTYPE {linktype}, {n} bytes"
                    );
                }
                Decode::Refused(Refusal::TransportTruncated { protocol, .. })
                    if n < transport_end =>
                {
                    assert_eq!(*protocol, IPPROTO_TCP);
                }
                Decode::Headers(d) if n >= transport_end => {
                    assert!(d.payload_offset.checked_add(d.payload_len).unwrap() <= n);
                }
                other => panic!("a {n}-byte LINKTYPE {linktype} frame decoded to {other:?}"),
            }
        }
    }
}

/// A frame shorter than its link header is a truncation, named as one with the
/// byte counts, so the caller can stamp the packet short rather than record a
/// well-formed frame that carried nothing.
#[test]
fn a_frame_too_short_for_its_link_header_is_refused_as_truncated_not_as_carrying_no_ip() {
    assert_eq!(
        refused(LINKTYPE_ETHERNET, &[0u8; 10]),
        Refusal::FrameTruncated { need: 14, have: 10 }
    );
    assert_eq!(
        refused(LINKTYPE_LINUX_SLL, &[0u8; 15]),
        Refusal::FrameTruncated { need: 16, have: 15 }
    );
    assert_eq!(
        refused(LINKTYPE_RAW, &[]),
        Refusal::FrameTruncated { need: 20, have: 0 }
    );
    assert_eq!(
        Refusal::FrameTruncated { need: 14, have: 10 }.reason(),
        "frame_truncated"
    );
}

/// An IPv6 header whose payload length field claims more than the frame holds is
/// the snaplen case with a hostile edge: the claimed length must never be used to
/// slice, only compared against what is present. The addresses and ports are
/// still evidence and are decoded — a decoder that bailed here would drop every
/// snaplen-truncated IPv6 packet, the largest class in a real capture.
#[test]
fn an_ip_length_field_larger_than_the_frame_does_not_produce_an_out_of_bounds_payload() {
    let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let transport = tcp(80, 12345, TCP_ACK);
    let mut frame = ethernet(ETHERTYPE_IPV6);
    // Claim 60000 bytes of payload behind a header followed by only 20.
    frame.extend_from_slice(&ipv6(src, dst, IPPROTO_TCP, 60_000));
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert!(
        d.payload_offset + d.payload_len <= frame.len(),
        "the payload reported must be bytes the capture actually holds"
    );
    assert_eq!(d.payload_len, 0, "no payload bytes were captured");
    assert_eq!(d.src_port, Some(80));
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

/// Encode a domain name as DNS labels, terminated by a zero-length label.
fn dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn dns_header(id: u16, flags: u16, qd: u16, an: u16) -> Vec<u8> {
    let mut h = Vec::with_capacity(12);
    h.extend_from_slice(&id.to_be_bytes());
    h.extend_from_slice(&flags.to_be_bytes());
    h.extend_from_slice(&qd.to_be_bytes());
    h.extend_from_slice(&an.to_be_bytes());
    h.extend_from_slice(&0u16.to_be_bytes()); // nscount
    h.extend_from_slice(&0u16.to_be_bytes()); // arcount
    h
}

/// A response to `www.example.com` with one A answer, 49 bytes: the question
/// section ends at byte 33 and the answer's rdata ends at 49.
fn dns_a_response() -> Vec<u8> {
    let mut full = dns_header(0x1234, 0x8180, 1, 1);
    full.extend_from_slice(&dns_name("www.example.com"));
    full.extend_from_slice(&1u16.to_be_bytes());
    full.extend_from_slice(&1u16.to_be_bytes());
    full.extend_from_slice(&[0xC0, 0x0C]);
    full.extend_from_slice(&1u16.to_be_bytes());
    full.extend_from_slice(&1u16.to_be_bytes());
    full.extend_from_slice(&300u32.to_be_bytes());
    full.extend_from_slice(&4u16.to_be_bytes());
    full.extend_from_slice(&[10, 0, 0, 7]);
    assert_eq!(full.len(), 49);
    full
}

#[test]
fn a_dns_query_yields_its_question_name_and_is_not_marked_a_response() {
    let mut msg = dns_header(0x1234, 0x0100, 1, 0); // RD set
    msg.extend_from_slice(&dns_name("example.com"));
    msg.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

    let m = decode_dns(&msg).expect("a well-formed query decodes");

    assert_eq!(m.id, 0x1234, "not 0x3412");
    assert!(!m.is_response);
    assert!(!m.tc);
    assert!(!m.truncated, "the whole message was read");
    assert_eq!(m.questions, vec!["example.com".to_string()]);
    assert!(m.answers.is_empty());
}

/// RCODE is the server's own statement of why there are no answers. NXDOMAIN
/// ("the name does not exist"), SERVFAIL, REFUSED and a NOERROR response with
/// nothing in the answer section are four different findings; a decoder that
/// does not read the low four bits of the flags word makes them one record
/// shape, and an examiner reads "asked, no answer" for a name the server
/// positively denied.
/// Ten of the 2,650 port-53 messages in the DFIR Madness capture are DNS
/// UPDATEs (opcode 5): the compromised hosts registering their names with the
/// domain controller. An UPDATE's sections are zone, prerequisite and update,
/// not question and answer, so reading them as answers hit a zero-length
/// prerequisite and refused — and the refusal said "a layout the decoder
/// refused to guess at", which is true of the parse and false of the message.
/// The message is well-formed. It is a different kind of message, and the
/// opcode says which.
#[test]
fn a_dns_update_is_reported_by_its_opcode_rather_than_refused_as_malformed() {
    // The exact bytes off that capture: id a250, flags 2800 (opcode 5), one
    // zone entry, one prerequisite, three updates, no additional.
    let mut m = Vec::new();
    m.extend_from_slice(&[0xa2, 0x50, 0x28, 0x00, 0, 1, 0, 1, 0, 3, 0, 0]);
    // Zone: C137.local SOA IN
    m.extend_from_slice(b"\x04C137\x05local\x00");
    m.extend_from_slice(&[0, 6, 0, 1]);
    // Prerequisite: a name, type CNAME, class ANY, ttl 0, rdlength 0 — the
    // "RRset does not exist" form, which is the one that tripped the parser.
    m.extend_from_slice(b"\x0cDESKTOP-SDN1\xc0\x0c");
    m.extend_from_slice(&[0, 5, 0, 0xff, 0, 0, 0, 0, 0, 0]);
    let msg = decode_dns(&m).expect("a well-formed update decodes to a message");
    assert_eq!(msg.opcode, 5);
    assert!(!msg.is_response);
    assert!(
        msg.questions.is_empty() && msg.answers.is_empty(),
        "an update's sections are not questions and answers and must not be presented as them"
    );
    assert!(
        !msg.truncated,
        "nothing was cut; the message is simply not a query"
    );

    // A plain query still reports opcode 0, so the field means something.
    let mut q = dns_header(0x1234, 0x0100, 1, 0);
    q.extend_from_slice(&dns_name("example.com"));
    q.extend_from_slice(&[0, 1, 0, 1]);
    assert_eq!(decode_dns(&q).unwrap().opcode, 0);
}

#[test]
fn a_dns_response_carries_its_rcode_so_nxdomain_reads_as_nxdomain() {
    let mut nxdomain = dns_header(0x1234, 0x8183, 1, 0); // QR + RD + RA, RCODE 3
    nxdomain.extend_from_slice(&dns_name("evil.example"));
    nxdomain.extend_from_slice(&1u16.to_be_bytes());
    nxdomain.extend_from_slice(&1u16.to_be_bytes());
    let m = decode_dns(&nxdomain).expect("a well-formed NXDOMAIN decodes");
    assert!(m.is_response);
    assert_eq!(m.rcode, 3);
    assert!(m.answers.is_empty());

    let servfail = dns_header(0x1235, 0x8182, 0, 0); // RCODE 2
    assert_eq!(decode_dns(&servfail).expect("decodes").rcode, 2);

    // A query has RCODE 0 and so does a successful response; the field is
    // read from the same bits either way.
    let mut query = dns_header(0x1236, 0x0100, 1, 0);
    query.extend_from_slice(&dns_name("example.com"));
    query.extend_from_slice(&[0, 1, 0, 1]);
    assert_eq!(decode_dns(&query).expect("decodes").rcode, 0);
    assert_eq!(decode_dns(&dns_a_response()).expect("decodes").rcode, 0);
}

/// Name compression is not an optional optimisation: essentially every real
/// response uses a 0xC0 pointer for the answer's name, so a decoder that does not
/// follow one reports the answer name as garbage or drops the answer — and the
/// answer is the whole point, because it is what proves the address belonged to
/// the name at that moment.
#[test]
fn a_dns_response_decompresses_a_pointer_back_to_the_question_name() {
    let mut msg = dns_header(0x1234, 0x8180, 1, 1); // QR + RD + RA
    msg.extend_from_slice(&dns_name("example.com"));
    msg.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

    // Answer: NAME is a pointer to offset 12, where the question's name sits.
    msg.extend_from_slice(&[0xC0, 0x0C]);
    msg.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    msg.extend_from_slice(&300u32.to_be_bytes()); // TTL
    msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    msg.extend_from_slice(&[93, 184, 216, 34]); // RDATA

    let m = decode_dns(&msg).expect("a well-formed response decodes");

    assert!(m.is_response);
    assert!(!m.truncated);
    assert_eq!(m.questions, vec!["example.com".to_string()]);
    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.answers[0].name, "example.com", "the pointer was followed");
    assert_eq!(m.answers[0].rtype, 1);
    assert_eq!(m.answers[0].data, "93.184.216.34");
}

/// A pointer that points at itself is two bytes an attacker can put in a capture,
/// and a naive decompressor follows it forever. Ingesting a hostile capture must
/// not hang the case: the honest answer is that this message could not be read.
/// A loop is a lie about the layout, not a cut, so it discredits the message
/// rather than marking it truncated.
#[test]
fn a_dns_name_pointer_loop_terminates_instead_of_hanging() {
    let mut msg = dns_header(0x0001, 0x0100, 1, 0);
    msg.extend_from_slice(&[0xC0, 0x0C]); // at offset 12, pointing to offset 12
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());

    assert_eq!(
        decode_dns(&msg),
        None,
        "a name that cannot be resolved is not a name to put in a report"
    );
}

/// Two pointers pointing at each other: the same defect one indirection further
/// out, which a "did the pointer target move backwards?" check catches but a
/// "does the pointer point at itself?" check does not.
#[test]
fn a_dns_name_pointer_cycle_between_two_offsets_also_terminates() {
    let mut msg = dns_header(0x0002, 0x0100, 1, 0);
    msg.extend_from_slice(&[0xC0, 0x0E]); // offset 12 -> offset 14
    msg.extend_from_slice(&[0xC0, 0x0C]); // offset 14 -> offset 12
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());

    assert_eq!(decode_dns(&msg), None);
}

/// Every prefix of a real response. UDP/53 traffic is truncated by snaplen like
/// anything else — `tcpdump -s 96` leaves 54 bytes of DNS, and this 49-byte
/// response is short only because its name is — so what the cut left must come
/// back, and it must come back *marked*: a message cut inside its answer section
/// that read as a complete question-with-no-answer would be a claim that the
/// name went unresolved, which the evidence does not support.
#[test]
fn every_truncation_of_a_dns_response_keeps_what_was_read_and_says_it_was_cut() {
    let full = dns_a_response();

    for n in 0..full.len() {
        let payload = &full[..n];
        let m = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decode_dns(payload)))
            .unwrap_or_else(|_| panic!("decode_dns panicked on a {n}-byte payload"));
        match (n, m) {
            (0..12, None) => {}
            (12..33, Some(m)) => {
                assert!(m.truncated, "{n} bytes: cut inside the question");
                assert!(
                    m.questions.is_empty(),
                    "{n} bytes: no complete question was read"
                );
                assert!(m.answers.is_empty());
            }
            (33.., Some(m)) => {
                assert!(m.truncated, "{n} bytes: cut inside the answer");
                assert_eq!(m.questions, vec!["www.example.com".to_string()]);
                assert!(
                    m.answers.is_empty(),
                    "{n} bytes: no complete answer was read"
                );
            }
            (_, other) => panic!("a {n}-byte payload decoded to {other:?}"),
        }
    }

    let complete = decode_dns(&full).expect("the untruncated message decodes");
    assert!(!complete.truncated);
    assert_eq!(complete.questions, vec!["www.example.com".to_string()]);
    assert_eq!(complete.answers[0].data, "10.0.0.7");
}

/// The single most common shape on a snaplen-limited capture: header and
/// question intact, the answer's rdata cut. The question is evidence — it is the
/// name the host asked for — and it comes back, with the cut recorded on the
/// message rather than in the absence of the answer.
#[test]
fn a_dns_response_cut_inside_its_answer_section_keeps_the_question_and_says_it_was_cut() {
    let full = dns_a_response();
    let cut = &full[..full.len() - 3];

    let m = decode_dns(cut).expect("the header and question are present and are evidence");

    assert_eq!(m.id, 0x1234);
    assert!(m.is_response);
    assert_eq!(m.questions, vec!["www.example.com".to_string()]);
    assert!(
        m.answers.is_empty(),
        "an answer whose rdata was cut is not an answer"
    );
    assert!(
        m.truncated,
        "the message must carry the cut, not hide it in an empty answer list"
    );
}

/// A second answer cut after a first complete one: the first is kept, because
/// the packet does contain it, and the message still says it was cut.
#[test]
fn a_dns_response_cut_inside_its_second_answer_keeps_the_first_and_says_it_was_cut() {
    let mut msg = dns_a_response();
    msg[7] = 2; // ancount 2
    msg.extend_from_slice(&[0xC0, 0x0C]);
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&300u32.to_be_bytes());
    msg.extend_from_slice(&4u16.to_be_bytes());
    msg.extend_from_slice(&[10, 0]); // two of the four address bytes

    let m = decode_dns(&msg).expect("the first answer is present");

    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.answers[0].data, "10.0.0.7");
    assert!(m.truncated);
}

/// TC is the *server* attesting that the answer set was cut to fit UDP. It is
/// not the same finding as the capture cutting the bytes — the message on the
/// wire is complete as sent — so it is reported on its own field, and a message
/// with TC set and every byte present is not marked as cut by the capture.
#[test]
fn a_dns_response_the_server_marked_truncated_reports_the_tc_bit_separately() {
    let mut msg = dns_a_response();
    msg[2..4].copy_from_slice(&0x8380u16.to_be_bytes()); // QR + TC + RD + RA

    let m = decode_dns(&msg).expect("a complete message with TC set decodes");

    assert!(m.tc, "the server said it truncated the answer set");
    assert!(!m.truncated, "the capture did not cut the bytes");
    assert_eq!(m.answers.len(), 1);
}

#[test]
fn a_payload_too_short_to_hold_a_dns_header_is_not_a_dns_message() {
    for n in 0..12 {
        assert_eq!(decode_dns(&vec![0u8; n]), None, "{n} bytes is not a header");
    }
}

// ---------------------------------------------------------------------------
// Added with the implementation: the gaps the red stage listed as unwritten,
// plus the places the implementation had to choose a behaviour the tests
// above do not pin.
// ---------------------------------------------------------------------------

/// The IPv4 counterpart of this — IHL above five — is tested above; the TCP data
/// offset is the same trap one layer down, and it is the common one, because
/// almost every SYN on a modern network carries MSS, window scale and SACK
/// options. A decoder that hardcodes 20 bytes reports twelve bytes of option
/// data as the start of the payload, and every "follow stream" built on it
/// begins with garbage.
#[test]
fn tcp_options_move_the_payload_and_the_data_offset_is_counted_in_four_byte_words() {
    let options = [
        0x02u8, 0x04, 0x05, 0xb4, // MSS 1460
        0x01, 0x03, 0x03, 0x07, // NOP, window scale 7
        0x01, 0x01, 0x04, 0x02, // NOP, NOP, SACK permitted
    ];
    let mut transport = tcp(50875, 443, TCP_SYN);
    transport[12] = 8 << 4; // data offset 8: 20 fixed bytes plus 12 of options
    transport.extend_from_slice(&options);
    transport.extend_from_slice(b"body");

    let mut frame = ethernet(ETHERTYPE_IPV4);
    frame.extend_from_slice(&ipv4(
        [10, 42, 85, 10],
        [203, 78, 103, 109],
        IPPROTO_TCP,
        transport.len(),
        &[],
    ));
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.src_port, Some(50875));
    assert_eq!(d.payload_offset, 14 + 20 + 32);
    assert_eq!(d.payload_len, 4);
    assert_eq!(
        &frame[d.payload_offset..d.payload_offset + d.payload_len],
        b"body"
    );
}

/// A data offset below five is malformed — the fixed header alone is five
/// words. Honouring it would put `payload_offset` inside the TCP header, so
/// every "follow stream" would begin with the header's own bytes.
#[test]
fn a_tcp_data_offset_below_five_is_clamped_to_the_fixed_header_rather_than_overlapping_it() {
    let mut transport = tcp(50875, 443, TCP_ACK);
    transport[12] = 0;
    transport.extend_from_slice(b"12345678");
    let mut frame = ethernet(ETHERTYPE_IPV4);
    frame.extend_from_slice(&ipv4(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        IPPROTO_TCP,
        transport.len(),
        &[],
    ));
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.payload_offset, 14 + 20 + 20);
    assert_eq!(d.payload_len, 8);
}

/// RFC 768's length is a second claim about the same bytes, and a forged one
/// must not outrun either the IP layer's claim or the bytes captured.
#[test]
fn a_udp_length_field_larger_than_the_frame_is_bounded_by_the_bytes_captured() {
    let payload = [0xAAu8; 8];
    let mut transport = udp(1024, 53, payload.len());
    transport[4..6].copy_from_slice(&60000u16.to_be_bytes());
    transport.extend_from_slice(&payload);
    let mut frame = ethernet(ETHERTYPE_IPV4);
    frame.extend_from_slice(&ipv4(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        IPPROTO_UDP,
        transport.len(),
        &[],
    ));
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.payload_offset, 14 + 20 + 8);
    assert_eq!(d.payload_len, 8);
}

/// A routing header is walked exactly as a hop-by-hop one is — same
/// next-header/length shape — and getting only one of the two right leaves a
/// hole that shows up on the traffic an attacker is most likely to be shaping.
#[test]
fn an_ipv6_routing_header_is_walked_past_like_a_hop_by_hop_one() {
    let src: Ipv6Addr = "2001:db8::a".parse().unwrap();
    let dst: Ipv6Addr = "2001:db8::b".parse().unwrap();
    let routing = [43u8, 0, 0x04, 0x00, 0, 0, 0, 0]; // next TCP is set below
    let mut ext = routing;
    ext[0] = IPPROTO_TCP;
    let transport = tcp(1234, 993, TCP_ACK);
    let mut frame = ethernet(ETHERTYPE_IPV6);
    frame.extend_from_slice(&ipv6(src, dst, 43, ext.len() + transport.len()));
    frame.extend_from_slice(&ext);
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.protocol, IPPROTO_TCP);
    assert_eq!(d.dst_port, Some(993));
    assert_eq!(d.payload_offset, 14 + 40 + 8 + 20);
}

/// A fragment other than the first carries no transport header at all: the
/// bytes at that offset are the middle of someone's payload. Reading them as
/// ports invents a connection to a service that was never contacted, and it is
/// a connection an attacker can choose the ports of. The refusal carries the
/// addresses, the fragmented protocol and the identification so the bytes can
/// be attributed to the IP pair and, one day, reassembled.
#[test]
fn a_non_first_ipv6_fragment_is_refused_rather_than_given_the_ports_of_whatever_follows_it() {
    let src: Ipv6Addr = "2001:db8::a".parse().unwrap();
    let dst: Ipv6Addr = "2001:db8::b".parse().unwrap();
    let mut fragment = vec![IPPROTO_TCP, 0];
    fragment.extend_from_slice(&(185u16 << 3).to_be_bytes()); // offset 185, no more-fragments
    fragment.extend_from_slice(&0xdeadbeefu32.to_be_bytes()); // identification
    let body = tcp(31337, 4444, TCP_PSH); // payload bytes that look like a header

    let mut frame = ethernet(ETHERTYPE_IPV6);
    frame.extend_from_slice(&ipv6(
        src,
        dst,
        IPPROTO_FRAGMENT,
        fragment.len() + body.len(),
    ));
    frame.extend_from_slice(&fragment);
    frame.extend_from_slice(&body);

    assert_eq!(
        refused(LINKTYPE_ETHERNET, &frame),
        Refusal::NonInitialFragment {
            src: IpAddr::V6(src),
            dst: IpAddr::V6(dst),
            protocol: IPPROTO_TCP,
            id: 0xdeadbeef,
            bytes_present: body.len(),
        }
    );
}

/// An extension chain is bounded only by the packet, so a crafted one is a
/// cheap way to make a walker spin or to push the transport header past
/// anything a decoder is willing to read. Refusing the packet is honest; naming
/// the last extension header as its "protocol" is not — and neither is calling
/// a packet whose addresses were read "a frame with no network layer".
#[test]
fn an_ipv6_extension_chain_longer_than_the_walk_is_refused_rather_than_guessed() {
    let src: Ipv6Addr = "2001:db8::a".parse().unwrap();
    let dst: Ipv6Addr = "2001:db8::b".parse().unwrap();
    let mut chain = Vec::new();
    for _ in 0..9 {
        chain.extend_from_slice(&hop_by_hop(IPPROTO_HOPOPTS));
    }
    let transport = tcp(1, 2, TCP_SYN);
    let mut frame = ethernet(ETHERTYPE_IPV6);
    frame.extend_from_slice(&ipv6(
        src,
        dst,
        IPPROTO_HOPOPTS,
        chain.len() + transport.len(),
    ));
    frame.extend_from_slice(&chain);
    frame.extend_from_slice(&transport);

    let refusal = refused(LINKTYPE_ETHERNET, &frame);

    assert_eq!(
        refusal,
        Refusal::ExtensionHeaderDepthExceeded,
        "a transport header we did not reach must not be named"
    );
    assert_eq!(refusal.reason(), "extension_header_depth_exceeded");
}

/// A frame cut inside an extension header ended before the network layer was
/// complete, so it is a frame truncation with the byte counts — not a transport
/// truncation, which would name a transport the chain never reached.
#[test]
fn a_frame_cut_inside_an_ipv6_extension_header_is_a_frame_truncation() {
    let src: Ipv6Addr = "2001:db8::a".parse().unwrap();
    let dst: Ipv6Addr = "2001:db8::b".parse().unwrap();
    let ext = hop_by_hop(IPPROTO_TCP);
    let mut frame = ethernet(ETHERTYPE_IPV6);
    frame.extend_from_slice(&ipv6(src, dst, IPPROTO_HOPOPTS, ext.len() + 20));
    frame.extend_from_slice(&ext[..5]);

    assert_eq!(
        refused(LINKTYPE_ETHERNET, &frame),
        Refusal::FrameTruncated {
            need: 14 + 40 + 8,
            have: 14 + 40 + 5,
        }
    );
}

/// Provider-bridged frames carry two tags. Unwrapping only the outer one leaves
/// the inner TPID looking like an ethertype, so the packet is dropped as "not
/// IP" — the same silent loss as not unwrapping a tag at all.
#[test]
fn two_stacked_vlan_tags_still_reach_the_ipv4_packet() {
    let transport = tcp(1025, 445, TCP_ACK);
    let mut frame = ethernet(0x88A8); // 802.1ad service tag
    frame.extend_from_slice(&0x0064u16.to_be_bytes());
    frame.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes()); // customer tag follows
    frame.extend_from_slice(&0x000au16.to_be_bytes());
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(&ipv4(
        [10, 42, 85, 10],
        [10, 42, 85, 4],
        IPPROTO_TCP,
        transport.len(),
        &[],
    ));
    frame.extend_from_slice(&transport);

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.dst, v4(10, 42, 85, 4));
    assert_eq!(d.dst_port, Some(445));
    assert_eq!(d.payload_offset, 14 + 8 + 20 + 20);
}

/// When snaplen cuts the frame inside the transport header the addresses are
/// still evidence and travel with the refusal, but no port is invented from the
/// bytes that did arrive — and the outcome is a named refusal, not a decode
/// with `None` ports, because that shape is exactly what ICMP produces and the
/// emission layer could not tell "this protocol has no ports" from "the
/// capture stopped before the ports".
#[test]
fn a_frame_cut_inside_its_tcp_header_is_refused_as_transport_truncated_with_its_addresses() {
    let full = eth_ipv4_tcp(
        [10, 42, 85, 10],
        [203, 78, 103, 109],
        50875,
        443,
        TCP_SYN,
        b"payload",
    );
    let cut = &full[..14 + 20 + 10];

    let refusal = refused(LINKTYPE_ETHERNET, cut);

    assert_eq!(
        refusal,
        Refusal::TransportTruncated {
            src: v4(10, 42, 85, 10),
            dst: v4(203, 78, 103, 109),
            protocol: IPPROTO_TCP,
        }
    );
    assert_eq!(refusal.reason(), "transport_truncated");
    assert_eq!(
        refusal.addresses(),
        Some((v4(10, 42, 85, 10), v4(203, 78, 103, 109)))
    );
}

/// Padding is not payload. An Ethernet frame shorter than 60 bytes is padded to
/// the minimum, and a decoder that reports "everything after the headers" hands
/// the stream reassembler bytes that belong to no packet.
#[test]
fn ethernet_padding_after_a_short_ip_packet_is_not_reported_as_payload() {
    let transport = udp(1024, 53, 0);
    let mut frame = ethernet(ETHERTYPE_IPV4);
    frame.extend_from_slice(&ipv4(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        IPPROTO_UDP,
        transport.len(),
        &[],
    ));
    frame.extend_from_slice(&transport);
    frame.resize(60, 0); // the NIC's padding to the minimum frame size

    let d = headers(LINKTYPE_ETHERNET, &frame);

    assert_eq!(d.payload_offset, 14 + 20 + 8);
    assert_eq!(d.payload_len, 0, "the padding is not UDP payload");
}

#[test]
fn a_dns_aaaa_answer_is_rendered_as_an_ipv6_address() {
    let mut msg = dns_header(0x2001, 0x8180, 1, 1);
    msg.extend_from_slice(&dns_name("ipv6.example.com"));
    msg.extend_from_slice(&28u16.to_be_bytes()); // QTYPE AAAA
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&[0xC0, 0x0C]);
    msg.extend_from_slice(&28u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&300u32.to_be_bytes());
    msg.extend_from_slice(&16u16.to_be_bytes());
    let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
    msg.extend_from_slice(&addr.octets());

    let m = decode_dns(&msg).expect("a well-formed AAAA response decodes");

    assert_eq!(m.answers[0].rtype, 28);
    assert_eq!(m.answers[0].data, "2001:db8::1");
}

/// A CNAME's rdata is itself a name, with its own compression pointers into the
/// message. Rendering it as hex would lose the redirection, which on a real case
/// is often the only place the CDN or the sinkhole is named.
#[test]
fn a_dns_cname_answer_resolves_the_name_in_its_rdata() {
    let mut msg = dns_header(0x3001, 0x8180, 1, 1);
    msg.extend_from_slice(&dns_name("www.example.com"));
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&[0xC0, 0x0C]);
    msg.extend_from_slice(&5u16.to_be_bytes()); // TYPE CNAME
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&300u32.to_be_bytes());
    let target = dns_name("edge.example.net");
    msg.extend_from_slice(&(target.len() as u16).to_be_bytes());
    msg.extend_from_slice(&target);

    let m = decode_dns(&msg).expect("a well-formed CNAME response decodes");

    assert_eq!(m.answers[0].name, "www.example.com");
    assert_eq!(m.answers[0].data, "edge.example.net");
}

/// A CNAME whose rdata ends inside the message may still point back at a name
/// before it — that is what compression is — and the pointer target lies
/// outside the rdata window legitimately.
#[test]
fn a_dns_cname_whose_rdata_is_a_compression_pointer_resolves_through_it() {
    let mut msg = dns_header(0x3002, 0x8180, 1, 1);
    msg.extend_from_slice(&dns_name("www.example.com"));
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&[0xC0, 0x0C]);
    msg.extend_from_slice(&5u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&300u32.to_be_bytes());
    msg.extend_from_slice(&2u16.to_be_bytes());
    msg.extend_from_slice(&[0xC0, 0x10]); // "example.com" — the question name past "www"

    let m = decode_dns(&msg).expect("a pointer-only rdata is a legal name");

    assert_eq!(m.answers[0].data, "example.com");
}

/// A record's rdata is RDLENGTH bytes and nothing else. A CNAME whose rdata is
/// one byte long but whose "name" continues past it would be assembled from the
/// bytes of the *next* record — here the word "secret" — and reported as a
/// resolution the record does not contain. RDLENGTH that contradicts its own
/// contents is a lie about the layout, and the message is refused as one.
#[test]
fn a_cname_whose_rdata_is_shorter_than_the_name_it_starts_is_not_completed_from_the_next_record() {
    let mut msg = dns_header(0x3003, 0x8180, 0, 1);
    msg.push(0); // answer name: root
    msg.extend_from_slice(&5u16.to_be_bytes()); // TYPE CNAME
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&0u32.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // RDLENGTH 1
    msg.push(6); // a label length of six, with the label outside the rdata
    msg.extend_from_slice(b"secret\0");

    assert_eq!(
        decode_dns(&msg),
        None,
        "a name read from outside its own record is not that record's rdata"
    );
}

/// An rtype this build does not render must still show its bytes: an answer
/// whose `data` is empty is indistinguishable from a field the decoder failed
/// to fill in, and an examiner cannot tell which they are looking at.
#[test]
fn an_answer_of_an_undecoded_type_shows_its_bytes_rather_than_an_empty_field() {
    let mut msg = dns_header(0x4001, 0x8180, 1, 1);
    msg.extend_from_slice(&dns_name("example.com"));
    msg.extend_from_slice(&99u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&[0xC0, 0x0C]);
    msg.extend_from_slice(&99u16.to_be_bytes()); // a type with no renderer here
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&60u32.to_be_bytes());
    msg.extend_from_slice(&3u16.to_be_bytes());
    msg.extend_from_slice(&[0xde, 0xad, 0xbe]);

    let m = decode_dns(&msg).expect("an unknown rtype is not a broken message");

    assert_eq!(m.answers[0].rtype, 99);
    assert_eq!(m.answers[0].data, "deadbe");
    assert!(!m.answers[0].data.is_empty());
}

/// An A record whose rdata is not four bytes is not an A record. Rendering it
/// would mean choosing four of its bytes to call an address, which is a
/// fabricated resolution — the exact thing a DNS answer is quoted to prove.
#[test]
fn an_a_record_with_the_wrong_rdata_length_is_refused_rather_than_squeezed_into_an_address() {
    let mut msg = dns_header(0x5001, 0x8180, 1, 1);
    msg.extend_from_slice(&dns_name("example.com"));
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&[0xC0, 0x0C]);
    msg.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&300u32.to_be_bytes());
    msg.extend_from_slice(&6u16.to_be_bytes()); // six bytes of "address"
    msg.extend_from_slice(&[93, 184, 216, 34, 0, 0]);

    assert_eq!(decode_dns(&msg), None);
}

/// A label is arbitrary bytes, and DNS tunnelling puts arbitrary bytes there on
/// purpose. A name shown with the odd bytes silently replaced is a name the
/// packet does not contain, and an embedded dot would split one label into two.
#[test]
fn a_label_containing_a_dot_or_an_unprintable_byte_is_escaped_not_silently_altered() {
    let mut msg = dns_header(0x6001, 0x0100, 1, 0);
    msg.push(3);
    msg.extend_from_slice(&[b'a', b'.', 0x00]);
    msg.extend_from_slice(&dns_name("example.com"));
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());

    let m = decode_dns(&msg).expect("odd bytes in a label do not break the message");

    assert_eq!(m.questions, vec!["a\\.\\x00.example.com".to_string()]);
}

/// The hand-built fixtures above all describe frames someone meant to send. A
/// capture recovered from unallocated space, or one an attacker authored, is
/// neither — and this crate is `forbid(unsafe_code)` with overflow checks on in
/// release, so the failure mode of a missed bounds check is a panic that aborts
/// the ingest of the whole case. The generator is a fixed LCG so a failure here
/// is reproducible rather than a flake. Every outcome's byte counts must also
/// be in evidence: a refusal that says "need 14, have 90" is as wrong as a
/// payload past the end of the frame.
#[test]
fn arbitrary_bytes_under_every_supported_linktype_decode_or_refuse_but_never_panic() {
    let mut state: u64 = 0x5ead_1234_dead_beef;
    let mut next = move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) as u32
    };

    for _ in 0..4000 {
        let len = (next() % 128) as usize;
        let mut frame = vec![0u8; len];
        for byte in frame.iter_mut() {
            *byte = next() as u8;
        }
        for linktype in [LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL] {
            let decoded =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decode(linktype, &frame)))
                    .unwrap_or_else(|_| {
                        panic!("decode panicked on {frame:02x?} as LINKTYPE {linktype}")
                    });

            match decoded {
                Decode::Headers(d) => assert!(
                    d.payload_offset.checked_add(d.payload_len).unwrap() <= frame.len(),
                    "reported payload is not inside the frame: {d:?} of {len} bytes"
                ),
                Decode::NoNetworkLayer => assert_ne!(
                    linktype, LINKTYPE_RAW,
                    "a RAW frame is IP by definition and cannot lack a network layer"
                ),
                Decode::Arp(observation) => {
                    assert_ne!(
                        linktype, LINKTYPE_RAW,
                        "a RAW frame is IP by definition and is never ARP"
                    );
                    // Whatever it read, it read it from this frame's own
                    // bytes: an ARP packet needs 28 of them after the link
                    // header.
                    if observation.is_some() {
                        assert!(frame.len() >= 28);
                    }
                }
                Decode::Refused(Refusal::FrameTruncated { need, have }) => {
                    assert_eq!(have, frame.len());
                    assert!(need > have, "a truncation must need more than it has");
                }
                Decode::Refused(Refusal::NonInitialFragment { bytes_present, .. }) => {
                    assert!(bytes_present <= frame.len());
                }
                Decode::Refused(Refusal::UnsupportedLinktype(_)) => {
                    panic!("a supported linktype is never refused by number")
                }
                Decode::Refused(_) => {}
            }
        }
        let dns = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decode_dns(&frame)))
            .unwrap_or_else(|_| panic!("decode_dns panicked on {frame:02x?}"));
        if let Some(m) = dns {
            assert!(m.answers.iter().all(|a| !a.data.is_empty()));
        }
    }
}

/// **ARP is read on a cooked capture too.** `tcpdump -i any` is the most
/// common way a Linux capture is made, and a decoder that read ARP on
/// Ethernet and not on LINKTYPE_LINUX_SLL would hand an examiner an empty
/// address inventory for half the captures in the world, with nothing saying
/// why.
#[test]
fn arp_is_decoded_on_a_cooked_capture_as_well_as_on_ethernet() {
    let arp_payload = [
        0x00, 0x01, // hardware type: Ethernet
        0x08, 0x00, // protocol type: IPv4
        0x06, 0x04, // address lengths
        0x00, 0x02, // opcode: reply
        0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 10, 42, 85, 1, // sender
        0x00, 0xde, 0xad, 0xbe, 0xef, 0x01, 10, 42, 85, 10, // target
    ];
    let mut frame = linux_sll(ETHERTYPE_ARP);
    frame.extend_from_slice(&arp_payload);
    let claim = match decode(LINKTYPE_LINUX_SLL, &frame) {
        Decode::Arp(Some(claim)) => claim,
        other => panic!("{other:?}"),
    };
    assert_eq!(claim.operation, 2);
    assert_eq!(claim.sender_ip, std::net::Ipv4Addr::new(10, 42, 85, 1));
    assert_eq!(claim.sender_mac, [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
    assert_eq!(
        claim.frame_source_mac,
        Some([0x00, 0x50, 0x56, 0xc0, 0x00, 0x08]),
        "the cooked header's own six-byte source, which the claim is compared against"
    );
    // A header declaring an address length that is not six is not compared
    // against an ARP claim: the two would be different kinds of thing.
    let mut other_link = linux_sll(ETHERTYPE_ARP);
    other_link[4..6].copy_from_slice(&8u16.to_be_bytes());
    other_link.extend_from_slice(&arp_payload);
    match decode(LINKTYPE_LINUX_SLL, &other_link) {
        Decode::Arp(Some(claim)) => assert_eq!(claim.frame_source_mac, None),
        other => panic!("{other:?}"),
    }
    // A cooked frame cut inside the ARP packet is an ARP frame this build
    // could not read, not a frame with no ARP in it.
    let mut cut = linux_sll(ETHERTYPE_ARP);
    cut.extend_from_slice(&arp_payload[..12]);
    assert_eq!(decode(LINKTYPE_LINUX_SLL, &cut), Decode::Arp(None));
}
