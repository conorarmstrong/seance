//! Reassembly: what the stream holds, what it does not, and the two things
//! that must never be done to a gap.

use std::net::{IpAddr, Ipv4Addr};

use super::reassemble::*;
use crate::decode::Decoded;
use crate::flows::{Direction, Endpoint, FlowKey};

const TCP: u8 = 6;
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

fn ip(s: &str) -> IpAddr {
    IpAddr::V4(s.parse::<Ipv4Addr>().expect("an IPv4 address"))
}

fn client() -> Endpoint {
    Endpoint {
        ip: ip("10.0.0.5"),
        port: Some(49152),
    }
}

fn server() -> Endpoint {
    Endpoint {
        ip: ip("93.184.216.34"),
        port: Some(80),
    }
}

fn flow() -> FlowKey {
    FlowKey::new(Some(TCP), client(), server())
}

/// One segment, as the decoder would hand it over.
fn seg(seq: u32, flags: u8) -> Decoded {
    Decoded {
        src: client().ip,
        dst: server().ip,
        protocol: TCP,
        src_port: client().port,
        dst_port: server().port,
        tcp_flags: Some(flags),
        tcp_seq: Some(seq),
        payload_offset: 0,
        payload_len: 0,
        ipv4_checksum_unset: false,
    }
}

/// A reassembler and the one stream key every test in this file uses.
fn one() -> (Reassembler, StreamKey) {
    (
        Reassembler::new(ReassemblyConfig::default()),
        StreamKey {
            flow: flow(),
            direction: Direction::Out,
        },
    )
}

fn offer(r: &mut Reassembler, seq: u32, flags: u8, bytes: &[u8]) {
    r.offer(flow(), Direction::Out, &seg(seq, flags), bytes);
}

/// **In order, the stream is one run and the whole thing is readable.**
#[test]
fn segments_in_order_assemble_into_one_run() {
    let (mut r, key) = one();
    offer(&mut r, 1000, SYN, &[]);
    offer(&mut r, 1001, ACK, b"GET / HTTP/1.1\r\n");
    offer(&mut r, 1017, ACK, b"Host: example.com\r\n\r\n");

    let s = r.stream(&key).expect("a stream");
    assert_eq!(s.runs.len(), 1, "{:?}", s.runs);
    assert_eq!(s.base_seq, 1001, "a SYN consumes one sequence number");
    assert!(s.base_from_syn);
    assert_eq!(
        s.contiguous_prefix(),
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    );
    assert!(s.holes().is_empty());
    assert!(s.is_contiguous());
    assert_eq!(s.segments, 2, "the SYN carries no data");
}

/// **Out of order, the stream still assembles.** The second segment arrives
/// first and the first one closes the gap behind it.
#[test]
fn segments_out_of_order_assemble_and_the_gap_closes() {
    let (mut r, key) = one();
    offer(&mut r, 1000, SYN, &[]);
    // `world` is the second five bytes of the stream, so it sits at offset 5.
    offer(&mut r, 1006, ACK, b"world");
    {
        let s = r.stream(&key).expect("a stream");
        assert_eq!(
            s.holes(),
            vec![Hole {
                offset: 0,
                length: 5
            }]
        );
        assert_eq!(
            s.contiguous_prefix(),
            b"",
            "nothing may be read across a hole, so the readable prefix is empty"
        );
    }
    offer(&mut r, 1001, ACK, b"hello");
    let s = r.stream(&key).expect("a stream");
    assert_eq!(s.runs.len(), 1);
    assert_eq!(s.contiguous_prefix(), b"helloworld");
    assert!(s.is_contiguous());
}

/// **A missing segment is a hole, and it is never closed.** The bytes either
/// side of it are held at their true offsets, and the prefix a parser may read
/// stops at it.
#[test]
fn a_missing_segment_leaves_a_hole_that_is_not_closed() {
    let (mut r, key) = one();
    offer(&mut r, 1000, SYN, &[]);
    offer(&mut r, 1001, ACK, b"AAAA");
    // 1005..1009 never arrives.
    offer(&mut r, 1009, ACK, b"CCCC");

    let s = r.stream(&key).expect("a stream");
    assert_eq!(s.runs.len(), 2, "two pieces, not one joined pair");
    assert_eq!(
        s.holes(),
        vec![Hole {
            offset: 4,
            length: 4
        }]
    );
    assert_eq!(s.bytes_held(), 8);
    assert_eq!(s.extent(), 12, "the stream reaches offset 12");
    assert_eq!(
        s.contiguous_prefix(),
        b"AAAA",
        "a parser is offered the bytes before the hole and no others"
    );
    assert!(!s.is_contiguous());
    // The second run is at its true offset, so nothing reads `AAAACCCC`.
    assert_eq!(s.runs[1].offset, 8);
    assert_eq!(s.runs[1].bytes, b"CCCC");
}

/// An identical retransmission is counted and changes nothing.
#[test]
fn an_identical_retransmission_is_counted_and_not_duplicated() {
    let (mut r, key) = one();
    offer(&mut r, 1000, SYN, &[]);
    offer(&mut r, 1001, ACK, b"hello");
    offer(&mut r, 1001, ACK, b"hello");

    let s = r.stream(&key).expect("a stream");
    assert_eq!(s.contiguous_prefix(), b"hello");
    assert_eq!(s.bytes_held(), 5);
    assert_eq!(s.retransmitted_bytes, 5);
    assert!(s.conflicts.is_empty());
    assert!(s.is_contiguous());
}

/// **A retransmission whose bytes differ is a finding.** The first bytes are
/// kept, the disagreement is recorded with its offset, and the stream stops
/// calling itself contiguous — because two readings of those offsets existed on
/// the wire and an examiner is being shown one of them.
#[test]
fn a_conflicting_retransmission_keeps_the_first_bytes_and_records_the_conflict() {
    let (mut r, key) = one();
    offer(&mut r, 1000, SYN, &[]);
    offer(&mut r, 1001, ACK, b"GET /index.html");
    offer(&mut r, 1001, ACK, b"GET /evil.html!");

    let s = r.stream(&key).expect("a stream");
    assert_eq!(
        s.contiguous_prefix(),
        b"GET /index.html",
        "the bytes that arrived first are the bytes held"
    );
    assert_eq!(s.conflicts.len(), 1);
    assert_eq!(s.conflicts[0].offset, 0);
    assert!(s.conflicts[0].length > 0);
    assert!(
        !s.is_contiguous(),
        "a stream with a disagreement in it is not a stream with one reading"
    );
    let json = s.to_json();
    assert_eq!(json["conflicts"][0]["offset"], 0);
    assert!(json["conflict_meaning"]
        .as_str()
        .is_some_and(|m| m.contains("DIFFERENT bytes")));
}

/// A segment that overlaps and extends contributes only its new bytes.
#[test]
fn an_overlapping_segment_contributes_only_what_is_new() {
    let (mut r, key) = one();
    offer(&mut r, 1000, SYN, &[]);
    offer(&mut r, 1001, ACK, b"abcdef");
    offer(&mut r, 1004, ACK, b"defghi");

    let s = r.stream(&key).expect("a stream");
    assert_eq!(s.contiguous_prefix(), b"abcdefghi");
    assert_eq!(s.retransmitted_bytes, 3, "`def` was already held");
    assert!(s.conflicts.is_empty());
}

/// An overlap that disagrees in its middle is one conflict, and the bytes
/// after it are still placed.
#[test]
fn an_overlap_that_disagrees_records_it_and_keeps_going() {
    let (mut r, key) = one();
    offer(&mut r, 1000, SYN, &[]);
    offer(&mut r, 1001, ACK, b"abcdef");
    offer(&mut r, 1004, ACK, b"XYZghi");

    let s = r.stream(&key).expect("a stream");
    assert_eq!(
        s.contiguous_prefix(),
        b"abcdefghi",
        "the held bytes win the overlap and the new tail is appended"
    );
    assert_eq!(s.conflicts.len(), 1);
    assert_eq!(s.conflicts[0].offset, 3);
    assert_eq!(s.conflicts[0].length, 3);
}

/// **A capture that begins mid-connection says so**, and offset 0 is the first
/// byte it saw rather than the connection's first byte.
#[test]
fn a_capture_with_no_handshake_says_its_base_is_not_the_connections_first_byte() {
    let (mut r, key) = one();
    offer(&mut r, 5000, ACK, b"...already in progress");

    let s = r.stream(&key).expect("a stream");
    assert!(!s.base_from_syn);
    assert_eq!(s.base_seq, 5000);
    assert_eq!(s.contiguous_prefix(), b"...already in progress");
    assert!(s.holes().is_empty(), "what came before is not a hole");
    let json = s.to_json();
    assert!(json["base_meaning"]
        .as_str()
        .is_some_and(|m| m.contains("FIRST BYTE THIS CAPTURE SAW")));
}

/// A retransmission of data sent before the capture began sits below the base:
/// it is counted and not placed, because a negative offset is not an offset.
#[test]
fn a_segment_below_the_base_is_counted_and_not_placed() {
    let (mut r, key) = one();
    offer(&mut r, 5000, ACK, b"current");
    offer(&mut r, 4000, ACK, b"older");

    let s = r.stream(&key).expect("a stream");
    assert_eq!(s.segments_before_base, 1);
    assert_eq!(s.bytes_held(), 7);
    assert_eq!(s.contiguous_prefix(), b"current");
}

/// A bare ACK opens no stream: its sequence number is the next byte the sender
/// intends, and taking that as a base would put the first data byte below zero.
#[test]
fn a_bare_ack_opens_no_stream() {
    let (mut r, key) = one();
    offer(&mut r, 9000, ACK, &[]);
    assert!(r.stream(&key).is_none());
    assert!(r.is_empty());
}

/// FIN and RST are recorded, and a stream with neither says it was still open
/// when the capture ended.
#[test]
fn how_a_stream_ended_is_recorded_and_an_unended_one_says_so() {
    let (mut r, key) = one();
    offer(&mut r, 1000, SYN, &[]);
    offer(&mut r, 1001, ACK, b"data");
    {
        let s = r.stream(&key).expect("a stream");
        assert!(!s.fin_seen && !s.rst_seen);
        assert_eq!(s.to_json()["fin_seen"], serde_json::json!(false));
    }
    offer(&mut r, 1005, FIN | ACK, &[]);
    assert!(r.stream(&key).expect("a stream").fin_seen);

    let (mut r2, key2) = one();
    offer(&mut r2, 1000, SYN, &[]);
    offer(&mut r2, 1001, RST, &[]);
    assert!(r2.stream(&key2).expect("a stream").rst_seen);
}

/// The two directions of one conversation are two streams, and the flow they
/// share keys both.
#[test]
fn the_two_directions_are_two_streams_on_one_flow() {
    let mut r = Reassembler::new(ReassemblyConfig::default());
    let out = StreamKey {
        flow: flow(),
        direction: Direction::Out,
    };
    let inbound = StreamKey {
        flow: flow(),
        direction: Direction::In,
    };
    r.offer(
        flow(),
        Direction::Out,
        &seg(1001, ACK),
        b"GET / HTTP/1.1\r\n",
    );
    r.offer(
        flow(),
        Direction::In,
        &seg(7001, ACK),
        b"HTTP/1.1 200 OK\r\n",
    );

    assert_eq!(r.len(), 2);
    assert_eq!(
        r.stream(&out).expect("out").contiguous_prefix(),
        b"GET / HTTP/1.1\r\n"
    );
    assert_eq!(
        r.stream(&inbound).expect("in").contiguous_prefix(),
        b"HTTP/1.1 200 OK\r\n"
    );
    assert_eq!(r.stream(&out).expect("out").key.flow, flow());
}

/// **Only the bytes the capture holds are placed.** A snaplen that cut a
/// segment in half leaves the rest a hole like any other: bytes that were not
/// captured are not bytes.
#[test]
fn a_snaplen_truncated_segment_contributes_only_its_captured_bytes() {
    let (mut r, key) = one();
    offer(&mut r, 1000, SYN, &[]);
    // The segment claimed 1001..1101 and the capture holds four bytes of it.
    offer(&mut r, 1001, ACK, b"ABCD");
    offer(&mut r, 1101, ACK, b"EFGH");

    let s = r.stream(&key).expect("a stream");
    assert_eq!(s.bytes_held(), 8);
    assert_eq!(
        s.holes(),
        vec![Hole {
            offset: 4,
            length: 96
        }]
    );
    assert_eq!(s.contiguous_prefix(), b"ABCD");
}

// ── Ceilings ────────────────────────────────────────────────────────────────

#[test]
fn the_byte_ceiling_stops_the_stream_at_the_offset_it_fired() {
    let (_, key) = one();
    let mut r = Reassembler::new(ReassemblyConfig {
        max_stream_bytes: 8,
        ..ReassemblyConfig::default()
    });
    offer(&mut r, 1000, SYN, &[]);
    offer(&mut r, 1001, ACK, b"AAAAAAAA");
    offer(&mut r, 1009, ACK, b"BBBBBBBB");

    let s = r.stream(&key).expect("a stream");
    assert_eq!(s.bytes_held(), 8);
    assert_eq!(s.stop, StreamStop::ByteCeiling { at: 8 });
    assert!(!s.is_contiguous(), "a stream that stopped is not complete");
    assert_eq!(s.to_json()["stop"]["reason"], "byte_ceiling");
    assert_eq!(s.to_json()["stop"]["at"], 8);
}

#[test]
fn the_run_ceiling_stops_new_pieces_and_says_where() {
    let (_, key) = one();
    let mut r = Reassembler::new(ReassemblyConfig {
        max_runs: 2,
        ..ReassemblyConfig::default()
    });
    offer(&mut r, 1000, SYN, &[]);
    // Three pieces with gaps between them: the third cannot be held.
    offer(&mut r, 1001, ACK, b"AA");
    offer(&mut r, 1011, ACK, b"BB");
    offer(&mut r, 1021, ACK, b"CC");

    let s = r.stream(&key).expect("a stream");
    assert_eq!(s.runs.len(), 2);
    assert!(
        matches!(s.stop, StreamStop::RunCeiling { at: 20 }),
        "{:?}",
        s.stop
    );
    // A piece that MERGES with a run it touches is still accepted at the
    // ceiling, because it does not add a piece.
    offer(&mut r, 1003, ACK, b"XX");
    let s = r.stream(&key).expect("a stream");
    assert_eq!(s.runs.len(), 2, "{:?}", s.runs);
    assert_eq!(s.runs[0].bytes, b"AAXX");
}

#[test]
fn the_stream_ceiling_counts_what_it_could_not_table() {
    let mut r = Reassembler::new(ReassemblyConfig {
        max_streams: 1,
        ..ReassemblyConfig::default()
    });
    r.offer(flow(), Direction::Out, &seg(1001, ACK), b"first");
    let other = FlowKey::new(
        Some(TCP),
        Endpoint {
            ip: ip("10.0.0.9"),
            port: Some(1234),
        },
        server(),
    );
    r.offer(other, Direction::Out, &seg(2001, ACK), b"second");

    assert_eq!(r.len(), 1);
    assert!(r.stream_cap_reached);
    assert_eq!(r.segments_beyond_cap, 1);
}

/// A segment with no sequence number is not a TCP segment, and nothing is
/// assembled from it.
#[test]
fn a_segment_with_no_sequence_number_is_not_assembled() {
    let (mut r, key) = one();
    let mut d = seg(1001, ACK);
    d.tcp_seq = None;
    r.offer(flow(), Direction::Out, &d, b"payload");
    assert!(r.stream(&key).is_none());
}

// ── The whole reassembly is bounded, not just each stream ───────────────────

/// **A per-stream ceiling is not a bound on memory.** Four thousand streams of
/// sixty-four megabytes is a quarter of a terabyte, and a capture of a busy
/// segment has four thousand streams. So the reassembly as a whole has a
/// budget, the streams that reach it say they were cut by it, and the capture
/// says how much was held.
#[test]
fn the_reassembly_as_a_whole_stops_at_its_budget_and_says_where() {
    let config = ReassemblyConfig {
        max_total_bytes: 100,
        ..ReassemblyConfig::default()
    };
    let mut reassembler = Reassembler::new(config);
    // Three streams of sixty bytes each: the first two fit within the budget's
    // hundred and the third finds nothing left.
    for (index, port) in [40_000u16, 40_001, 40_002].into_iter().enumerate() {
        let peer = Endpoint {
            ip: ip("10.0.0.5"),
            port: Some(port),
        };
        let key = FlowKey::new(Some(TCP), peer, server());
        let mut decoded = seg(1000, ACK);
        decoded.src_port = Some(port);
        reassembler.offer(key, Direction::Out, &decoded, &[b'a' + index as u8; 60]);
    }
    assert_eq!(
        reassembler.bytes_held, 100,
        "the budget is the bound, and it is not exceeded"
    );
    assert!(reassembler.total_budget_reached);
    assert_eq!(reassembler.segments_beyond_total_budget, 2);

    let streams = reassembler.finish();
    assert_eq!(streams.len(), 3, "every stream is still known");
    assert_eq!(streams[0].bytes_held(), 60);
    assert_eq!(
        streams[1].bytes_held(),
        40,
        "the second stream is cut where the budget ran out"
    );
    assert_eq!(streams[2].bytes_held(), 0);
    for stream in &streams[1..] {
        match stream.stop {
            StreamStop::TotalBudget { at } => assert!(
                at <= 40,
                "the offset the budget stopped this stream at: {at}"
            ),
            ref other => panic!("{other:?}"),
        }
    }
    assert!(streams[1].to_json()["stop"]["reason"]
        .as_str()
        .is_some_and(|r| r == "total_budget"));
}

/// **The stream table holds an ordinary brute force.** DFIR Madness Case 001's
/// capture holds 31,548 one-way TCP directions (`tcpdump`, folded by 5-tuple and
/// direction), most of them an RDP brute force from one host. At a ceiling of
/// 4,096 the table filled with the brute force at 02:19:27, about four and a
/// half minutes before the implant was downloaded at 02:24:06, and the download and every command-and-control session
/// were never read. The ceiling is on streams, and the bytes they hold are
/// bounded separately by [`MAX_TOTAL_BYTES`], so it must be far above what an
/// ordinary busy capture opens.
#[test]
fn the_default_table_holds_a_brute_force_of_twenty_thousand_conversations() {
    let mut r = Reassembler::new(ReassemblyConfig::default());
    for n in 0..20_000u32 {
        let attacker = Endpoint {
            ip: ip("194.61.24.102"),
            port: Some(1024 + (n % 60_000) as u16),
        };
        let victim = Endpoint {
            ip: IpAddr::V4(Ipv4Addr::from(0x0a2a_0000 + (n / 60_000) + 10)),
            port: Some(3389),
        };
        let key = FlowKey::new(Some(TCP), attacker, victim);
        r.offer(key, Direction::Out, &seg(n.wrapping_mul(7), SYN), &[]);
        r.offer(key, Direction::In, &seg(n.wrapping_mul(11), SYN | ACK), &[]);
    }
    assert!(!r.stream_cap_reached, "the table did not fill");
    assert_eq!(r.len(), 40_000);
    assert_eq!(r.segments_beyond_cap, 0);
}

/// A conversation the table had no room for is named, so its flow record can
/// say its bytes were not read — which is not the same as a flow that carried
/// none.
#[test]
fn a_conversation_the_table_refused_is_named() {
    let mut r = Reassembler::new(ReassemblyConfig {
        max_streams: 1,
        ..ReassemblyConfig::default()
    });
    r.offer(flow(), Direction::Out, &seg(1001, ACK), b"first");
    let other = FlowKey::new(
        Some(TCP),
        Endpoint {
            ip: ip("10.0.0.9"),
            port: Some(1234),
        },
        server(),
    );
    r.offer(other, Direction::Out, &seg(2001, ACK), b"second");
    r.offer(other, Direction::Out, &seg(2007, ACK), b"third");

    assert!(r.was_refused(&other), "the refused conversation is named");
    assert!(!r.was_refused(&flow()), "the tabled one is not");
    let refused = r.take_refused_flows();
    assert_eq!(refused.len(), 1, "named once, however many segments");
}
