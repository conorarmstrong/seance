#![forbid(unsafe_code)]
//! Network capture (pcap / pcapng) import and flow analysis.
//!
//! Raised by Case 001, whose 188 MB pcapng produced zero artifacts and whose
//! one decisive finding — the C2 address — is in nothing else. The module
//! reads classic pcap and pcapng by content (the case file is named `.pcap`
//! and is not one), decodes Ethernet, RAW and Linux SLL frames down to
//! TCP/UDP, and reports **flows**, not packets: 411,797 packets are a list
//! to scroll, 17 k conversations are something to investigate.
//!
//! Every way the result can fall short of the file is stamped in the
//! product's incompleteness vocabulary, and a capture that was detected and
//! then could not be read leaves a refusal record rather than nothing.

pub mod arp;
pub mod container;
pub mod decode;
pub mod emit;
pub mod flows;
pub mod http;

/// HTTP over a stream: what is read, what is refused, and the three ways a
/// message can be a prefix of one.
#[cfg(test)]
mod http_tests;

pub mod reassemble;
pub mod tls;
pub mod x509;

/// Reassembly: what the stream holds, what it does not, and the two things
/// that must never be done to a gap.
#[cfg(test)]
mod reassemble_tests;

use std::panic::{catch_unwind, AssertUnwindSafe};

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::file_detection::{detect_file_type, DetectedFileType};
use seance_core::module::{ForensicsModule, InputCapability, ModuleError};
use tracing::{info, warn};

use container::{read_capture, CaptureError, CaptureMeta};
use decode::{decode, decode_dns, Decode};
use emit::{emit, refusal_record, CaptureInput, DnsObservation};
use flows::{Endpoint, FlowTable};

/// The module id every record and timeline event names as its source.
pub const MODULE_ID: &str = "plugin.network.pcap_parser";

/// The most of a capture staged into memory. Streaming through
/// `SourceCursor` is the follow-up the plan names; until then a capture
/// larger than this is read as a prefix and the capture record says so.
pub const STAGING_CAP_BYTES: u64 = 256 * 1024 * 1024;

/// The most DNS messages kept per capture. Each becomes at least one
/// record; past the cap they still count in the flow they rode in, and the
/// capture record is stamped.
pub const DNS_CAP: usize = 100_000;

const UDP: u8 = 17;
/// IP protocol number for TCP, for the reassembly branch below.
const TCP: u8 = 6;
const DNS_PORT: u16 = 53;
/// The fixed DNS header; a payload shorter than this was cut, not malformed.
const DNS_HEADER_LEN: usize = 12;

pub struct PcapParser;

impl ForensicsModule for PcapParser {
    fn id(&self) -> &str {
        MODULE_ID
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        // A capture arrives as evidence in its own right, or as a file inside
        // a disk image; either way detection is by content, never by name.
        vec![ArtifactType::RawEvidence, ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let Some(data_source) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        let detected = detect_file_type(data_source.as_ref());
        if !matches!(
            detected,
            DetectedFileType::PcapFile | DetectedFileType::PcapNgFile
        ) {
            return Ok(Vec::new());
        }
        let name = source_name(artifact);
        info!(
            "Detected network capture ({:?}) by content: {} (ID: {})",
            detected, name, artifact.id
        );

        let declared = data_source.size();
        let buffer = seance_core::io::read_capped(data_source.as_ref(), STAGING_CAP_BYTES);
        let staged = buffer.len() as u64;

        // The reader is hand-rolled over checked arithmetic and should not
        // panic; if it does, the panic is a defect in this crate and the
        // record must say the capture was not read, not vanish with the
        // worker thread.
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            #[cfg(test)]
            if PANIC_FOR_TEST.with(|p| p.get()) {
                panic!("injected reader panic");
            }
            analyse(&buffer)
        }));
        let analysis = match outcome {
            Ok(Ok(analysis)) => analysis,
            Ok(Err(error)) => {
                warn!(
                    "Capture '{}' (ID: {}) detected but not readable: {:?}",
                    name, artifact.id, error
                );
                let (subtype, message) = describe_error(&error);
                return Ok(vec![refusal_record(
                    artifact.case_id,
                    artifact.id,
                    &name,
                    subtype,
                    &message,
                )]);
            }
            Err(panic) => {
                warn!(
                    "Capture reader panicked on '{}' (ID: {})",
                    name, artifact.id
                );
                return Ok(vec![panic_refusal_record(
                    artifact.case_id,
                    artifact.id,
                    &name,
                    panic.as_ref(),
                )]);
            }
        };

        let input = CaptureInput {
            case_id: artifact.case_id,
            parent_id: artifact.id,
            source_name: &name,
            meta: &analysis.meta,
            flows: &analysis.flows,
            streams: &analysis.streams,
            http: &analysis.http,
            tls: &analysis.tls,
            arp: &analysis.arp,
            arp_unreadable: analysis.arp_unreadable,
            stream_cap_reached: analysis.stream_cap_reached,
            segments_beyond_stream_cap: analysis.segments_beyond_stream_cap,
            refused_stream_flows: &analysis.refused_stream_flows,
            reassembly_bytes_held: analysis.reassembly_bytes_held,
            reassembly_budget_reached: analysis.reassembly_budget_reached,
            segments_beyond_reassembly_budget: analysis.segments_beyond_reassembly_budget,
            packets: analysis.packets,
            first_seen_micros: analysis.first_seen_micros,
            last_seen_micros: analysis.last_seen_micros,
            dns: &analysis.dns,
            dns_cap: DNS_CAP,
            dns_cap_reached: analysis.dns_cap_reached,
            dns_undecodable: analysis.dns_undecodable,
            dns_header_short: analysis.dns_header_short,
            bytes_declared: declared,
            bytes_staged: staged,
            staging_cap: STAGING_CAP_BYTES,
        };
        let out = emit(&input);
        info!(
            "Capture '{}': {} packets, {} flows, {} DNS messages, {} artifacts",
            name,
            analysis.packets,
            analysis.flows.len(),
            analysis.dns.len(),
            out.len()
        );
        Ok(out)
    }
}

/// What one capture decoded to, before emission.
struct Analysis {
    meta: CaptureMeta,
    flows: FlowTable,
    /// Every TCP conversation's bytes, put back together (`ROADMAP` §4.3
    /// stage 2). Keyed the way the flow table keys a conversation, so a stream
    /// and its flow can be put beside each other.
    streams: Vec<crate::reassemble::Stream>,
    /// What those streams said in HTTP, conversation by conversation
    /// (`ROADMAP` §4.3 stage 2).
    http: Vec<crate::http::Conversation>,
    /// And what they said in TLS, session by session.
    tls: Vec<crate::tls::Session>,
    /// The address-resolution claims the capture holds, and the ARP frames
    /// this build could not read.
    arp: crate::arp::ArpTable,
    arp_unreadable: u64,
    /// Whether the stream table's own cap fired, and how many segments it
    /// could not hold.
    stream_cap_reached: bool,
    segments_beyond_stream_cap: u64,
    /// The conversations the stream table refused a direction of.
    refused_stream_flows: std::collections::BTreeSet<crate::flows::FlowKey>,
    /// What the reassembly held between every stream, and whether its budget
    /// was the thing that stopped it.
    reassembly_bytes_held: u64,
    reassembly_budget_reached: bool,
    segments_beyond_reassembly_budget: u64,
    packets: u64,
    first_seen_micros: Option<u64>,
    last_seen_micros: Option<u64>,
    dns: Vec<DnsObservation>,
    dns_cap_reached: bool,
    dns_undecodable: u64,
    dns_header_short: u64,
}

/// Walk, decode and aggregate one staged capture.
///
/// Two walks, not one: a packet names its interface by index, the
/// interface's LINKTYPE decides how the frame is decoded, and the container
/// hands the interface table back only when the walk ends. The first walk
/// is framing only and cheap; the alternative — buffering every packet's
/// position until the table is known — costs a second copy of the file's
/// worth of records on a capture of small packets.
fn analyse(bytes: &[u8]) -> Result<Analysis, CaptureError> {
    let interfaces = read_capture(bytes, &mut |_| {})?.interfaces;

    let mut flows = FlowTable::new();
    let mut arp = crate::arp::ArpTable::new();
    let mut arp_unreadable: u64 = 0;
    let mut reassembler =
        crate::reassemble::Reassembler::new(crate::reassemble::ReassemblyConfig::default());
    let mut dns: Vec<DnsObservation> = Vec::new();
    let mut dns_cap_reached = false;
    let mut dns_undecodable: u64 = 0;
    let mut dns_header_short: u64 = 0;
    let mut packets: u64 = 0;
    let mut first_seen: Option<u64> = None;
    let mut last_seen: Option<u64> = None;

    let meta = read_capture(bytes, &mut |packet| {
        packets = packets.saturating_add(1);
        if let Some(ts) = packet.ts_micros {
            first_seen = Some(first_seen.map_or(ts, |f| f.min(ts)));
            last_seen = Some(last_seen.map_or(ts, |l| l.max(ts)));
        }
        // The container withholds packets on undeclared interfaces, so the
        // index resolves; a miss here would be a container defect, and the
        // packet is refused by number rather than decoded by a guess.
        let linktype = interfaces
            .get(packet.iface as usize)
            .map_or(u16::MAX, |i| i.linktype);
        let captured = u32::try_from(packet.data.len()).unwrap_or(u32::MAX);
        match decode(linktype, packet.data) {
            Decode::Headers(d) => {
                let placed = flows.observe(&d, packet.ts_micros, packet.orig_len, captured);
                // TCP: offer the segment to the reassembler, keyed by the flow
                // the table just put it on so the stream and the flow cannot
                // disagree about which conversation they describe. Only the
                // bytes the frame actually holds are offered; a snaplen that
                // cut the segment leaves the rest a hole, which is what it is.
                if d.protocol == TCP {
                    if let Some((flow, direction)) = placed {
                        let end = d.payload_offset.saturating_add(d.payload_len);
                        let payload = packet.data.get(d.payload_offset..end).unwrap_or(&[]);
                        reassembler.offer(flow, direction, &d, payload);
                    }
                }
                let on_dns_port = d.src_port == Some(DNS_PORT) || d.dst_port == Some(DNS_PORT);
                if d.protocol == UDP && on_dns_port {
                    let end = d.payload_offset.saturating_add(d.payload_len);
                    let payload = packet.data.get(d.payload_offset..end).unwrap_or(&[]);
                    // A payload that does not decode was still a port-53
                    // message on the wire, and the two ways it can fail are
                    // counted apart: cut inside the header is the snaplen's
                    // doing, anything longer that fails is the message's.
                    let message = decode_dns(payload);
                    if message.is_none() {
                        if payload.len() < DNS_HEADER_LEN {
                            dns_header_short = dns_header_short.saturating_add(1);
                        } else {
                            dns_undecodable = dns_undecodable.saturating_add(1);
                        }
                    }
                    if let Some(message) = message {
                        if dns.len() < DNS_CAP {
                            dns.push(DnsObservation {
                                message,
                                src: Endpoint {
                                    ip: d.src,
                                    port: d.src_port,
                                },
                                dst: Endpoint {
                                    ip: d.dst,
                                    port: d.dst_port,
                                },
                                ts_micros: packet.ts_micros,
                            });
                        } else {
                            dns_cap_reached = true;
                        }
                    }
                }
            }
            // An ARP frame has no network layer and is counted as one that
            // has none, exactly as before; its claims are read as well,
            // because they are the only record of which hardware answered
            // for which address.
            Decode::Arp(observation) => {
                flows.observe_no_network_layer();
                match observation {
                    Some(observation) => arp.observe(&observation, packet.ts_micros),
                    None => arp_unreadable = arp_unreadable.saturating_add(1),
                }
            }
            Decode::NoNetworkLayer => flows.observe_no_network_layer(),
            Decode::Refused(r) => {
                flows.observe_refusal(&r, packet.ts_micros, packet.orig_len, captured)
            }
        }
    })?;

    let stream_cap_reached = reassembler.stream_cap_reached;
    let segments_beyond_stream_cap = reassembler.segments_beyond_cap;
    let refused_stream_flows = reassembler.take_refused_flows();
    let reassembly_bytes_held = reassembler.bytes_held;
    let reassembly_budget_reached = reassembler.total_budget_reached;
    let segments_beyond_reassembly_budget = reassembler.segments_beyond_total_budget;
    // HTTP is read after the walk, not during it: a message spans segments
    // that can arrive in any order, so it can only be read once the stream is
    // whole. Both halves are needed — the streams hold the bytes and the flow
    // table holds which endpoint sent them.
    let streams = reassembler.finish();
    let http = crate::http::conversations(&flows, &streams);
    let tls = crate::tls::sessions(&flows, &streams);
    Ok(Analysis {
        meta,
        flows,
        streams,
        http,
        tls,
        arp,
        arp_unreadable,
        stream_cap_reached,
        segments_beyond_stream_cap,
        refused_stream_flows,
        reassembly_bytes_held,
        reassembly_budget_reached,
        segments_beyond_reassembly_budget,
        packets,
        first_seen_micros: first_seen,
        last_seen_micros: last_seen,
        dns,
        dns_cap_reached,
        dns_undecodable,
        dns_header_short,
    })
}

/// The refusal record for a reader that panicked. The payload is whatever
/// the panic carried — a `&str` from `panic!("...")`, a `String` from a
/// formatted one, or something else entirely — and the message is quoted
/// where it can be read, because the sentence "the reader panicked" alone
/// sends nobody to the right line.
pub fn panic_refusal_record(
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    source_name: &str,
    payload: &(dyn std::any::Any + Send),
) -> Artifact {
    let message = if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    };
    refusal_record(
        case_id,
        parent_id,
        source_name,
        "panic",
        &format!("the capture reader panicked: {message}"),
    )
}

#[cfg(test)]
thread_local! {
    /// Set by a test to make the reader panic, so the catch_unwind arm of
    /// `process` is driven through `process` itself. Thread-local because
    /// tests run in parallel and one test's injection must not reach another.
    static PANIC_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A stable subtype token and an examiner-facing sentence for each way the
/// reader can refuse a file detection accepted.
fn describe_error(error: &CaptureError) -> (&'static str, String) {
    match error {
        CaptureError::NotACapture => (
            "not_a_capture",
            "the bytes do not open with a pcap or pcapng header the reader recognises".to_string(),
        ),
        CaptureError::UnsupportedVersion { major, minor } => (
            "unsupported_version",
            format!(
                "the capture declares format version {major}.{minor}, which this build does not \
                 read"
            ),
        ),
        CaptureError::HeaderTruncated => (
            "header_truncated",
            "the file ends inside its own header".to_string(),
        ),
    }
}

/// The name records quote for the source, from whichever metadata key the
/// producing module used.
fn source_name(artifact: &Artifact) -> String {
    ["name", "file_name", "source_path", "path"]
        .iter()
        .find_map(|k| artifact.metadata.get(*k).and_then(|v| v.as_str()))
        .filter(|s| !s.is_empty())
        .unwrap_or("unnamed capture")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::DataSource;
    use serde_json::{json, Value};
    use std::io;
    use std::sync::Arc;

    #[derive(Debug)]
    struct MemorySource(Vec<u8>);

    impl DataSource for MemorySource {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            let offset = offset as usize;
            if offset >= self.0.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.0.len() - offset);
            buf[..n].copy_from_slice(&self.0[offset..offset + n]);
            Ok(n)
        }

        fn size(&self) -> u64 {
            self.0.len() as u64
        }
    }

    fn evidence(bytes: Vec<u8>, name: &str) -> Artifact {
        Artifact::new(
            uuid::Uuid::nil(),
            ArtifactType::RawEvidence,
            Some(Arc::new(MemorySource(bytes))),
            json!({ "name": name }),
        )
    }

    // pcapng builders, little-endian, in the shape the container reads.

    fn ng_block(block_type: u32, body: &[u8]) -> Vec<u8> {
        let padded = body.len().div_ceil(4) * 4;
        let total = (padded + 12) as u32;
        let mut b = Vec::new();
        b.extend_from_slice(&block_type.to_le_bytes());
        b.extend_from_slice(&total.to_le_bytes());
        b.extend_from_slice(body);
        b.resize(8 + padded, 0);
        b.extend_from_slice(&total.to_le_bytes());
        b
    }

    fn option(code: u16, value: &[u8]) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&code.to_le_bytes());
        o.extend_from_slice(&(value.len() as u16).to_le_bytes());
        o.extend_from_slice(value);
        o.resize(4 + value.len().div_ceil(4) * 4, 0);
        o
    }

    fn shb(major: u16, os: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        body.extend_from_slice(&major.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&u64::MAX.to_le_bytes());
        body.extend_from_slice(&option(3, os.as_bytes()));
        body.extend_from_slice(&option(0, &[]));
        ng_block(0x0A0D_0D0A, &body)
    }

    fn idb(linktype: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&linktype.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&262_144u32.to_le_bytes());
        ng_block(1, &body)
    }

    fn epb(ts_micros: u64, data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&((ts_micros >> 32) as u32).to_le_bytes());
        body.extend_from_slice(&(ts_micros as u32).to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(data);
        ng_block(6, &body)
    }

    fn ipv4_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for pair in header.chunks(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// An Ethernet II / IPv4 / TCP frame with a verified header checksum.
    fn tcp_frame(src: [u8; 4], sp: u16, dst: [u8; 4], dp: u16, flags: u8) -> Vec<u8> {
        let mut f = ethernet_ipv4(src, dst, 6, 20, 0x4000);
        f.extend_from_slice(&sp.to_be_bytes());
        f.extend_from_slice(&dp.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        f
    }

    /// The same, with a sequence number and a payload: what reassembly is
    /// given. The IP total-length field covers the TCP header and the payload,
    /// as a real one does, so the decoder's own bounds are exercised.
    fn tcp_segment(
        src: [u8; 4],
        sp: u16,
        dst: [u8; 4],
        dp: u16,
        seq: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let len = u16::try_from(20 + payload.len()).expect("a test-sized payload");
        let mut f = ethernet_ipv4(src, dst, 6, len, 0x4000);
        f.extend_from_slice(&sp.to_be_bytes());
        f.extend_from_slice(&dp.to_be_bytes());
        f.extend_from_slice(&seq.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0]);
        f.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        f.extend_from_slice(payload);
        f
    }

    /// Ethernet II plus an IPv4 header with a verified checksum, carrying
    /// `payload_len` bytes of `protocol` after it. `frag` is the flags and
    /// fragment-offset word.
    fn ethernet_ipv4(
        src: [u8; 4],
        dst: [u8; 4],
        protocol: u8,
        payload_len: u16,
        frag: u16,
    ) -> Vec<u8> {
        let mut f = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        ];
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&(20 + payload_len).to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x01]);
        ip.extend_from_slice(&frag.to_be_bytes());
        ip.extend_from_slice(&[0x40, protocol, 0x00, 0x00]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        let csum = ipv4_checksum(&ip);
        ip[10..12].copy_from_slice(&csum.to_be_bytes());
        f.extend_from_slice(&ip);
        f
    }

    /// The frame with its IPv4 checksum field zeroed: what every packet the
    /// capturing host sent looks like under transmit checksum offload.
    fn with_checksum_unset(mut frame: Vec<u8>) -> Vec<u8> {
        frame[14 + 10] = 0;
        frame[14 + 11] = 0;
        frame
    }

    /// The frame with one TTL bit flipped and the checksum left stale: a
    /// nonzero checksum that does not verify, on a packet whose addresses
    /// still name the same two hosts.
    fn with_checksum_stale(mut frame: Vec<u8>) -> Vec<u8> {
        frame[14 + 8] ^= 0x01;
        frame
    }

    /// A classic little-endian pcap of the given version, LINKTYPE 1.
    fn classic_pcap(major: u16, minor: u16, records: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
        b.extend_from_slice(&major.to_le_bytes());
        b.extend_from_slice(&minor.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&65_535u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        for (ts_sec, ts_usec, data) in records {
            b.extend_from_slice(&ts_sec.to_le_bytes());
            b.extend_from_slice(&ts_usec.to_le_bytes());
            b.extend_from_slice(&(data.len() as u32).to_le_bytes());
            b.extend_from_slice(&(data.len() as u32).to_le_bytes());
            b.extend_from_slice(data);
        }
        b
    }

    fn one_flow_capture(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut file = shb(1, "lab");
        file.extend(idb(1));
        for (i, frame) in frames.iter().enumerate() {
            file.extend(epb(1_600_482_318_566_000 + i as u64 * 1_000, frame));
        }
        file
    }

    fn flow_with_port<'a>(flows: &[&'a Artifact], port: u16) -> &'a Artifact {
        flows
            .iter()
            .find(|f| f.metadata["local_port"] == port || f.metadata["remote_port"] == port)
            .unwrap_or_else(|| panic!("no flow with port {port}"))
    }

    fn ip_pair_flow<'a>(flows: &[&'a Artifact]) -> &'a Artifact {
        flows
            .iter()
            .find(|f| f.metadata["local_port"].is_null())
            .expect("an IP-pair flow")
    }

    fn three_packet_capture() -> Vec<u8> {
        let host = [10, 42, 85, 10];
        let c2 = [203, 78, 103, 109];
        let base = 1_600_482_318_566_000u64;
        let mut file = shb(1, "Linux 5.8.0-kali1-amd64");
        file.extend(idb(1));
        file.extend(epb(base, &tcp_frame(host, 62414, c2, 443, 0x02)));
        file.extend(epb(base + 120_000, &tcp_frame(c2, 443, host, 62414, 0x12)));
        file.extend(epb(base + 121_000, &tcp_frame(host, 62414, c2, 443, 0x10)));
        file
    }

    /// A whole HTTP exchange over TCP, out of order, with one segment of the
    /// request missing — what a capture with packet loss looks like.
    fn http_exchange_capture() -> Vec<u8> {
        let host = [10, 42, 85, 10];
        let server = [93, 184, 216, 34];
        let base = 1_600_482_318_566_000u64;
        let mut file = shb(1, "Linux 5.8.0-kali1-amd64");
        file.extend(idb(1));
        // Handshake.
        file.extend(epb(
            base,
            &tcp_segment(host, 49152, server, 80, 1000, 0x02, b""),
        ));
        file.extend(epb(
            base + 1_000,
            &tcp_segment(server, 80, host, 49152, 5000, 0x12, b""),
        ));
        // The request, in two segments, the second arriving first.
        file.extend(epb(
            base + 3_000,
            &tcp_segment(
                host,
                49152,
                server,
                80,
                1017,
                0x10,
                b"Host: example.com\r\n\r\n",
            ),
        ));
        file.extend(epb(
            base + 2_000,
            &tcp_segment(host, 49152, server, 80, 1001, 0x10, b"GET / HTTP/1.1\r\n"),
        ));
        // The response, with the middle segment lost: 5001..5018 arrives,
        // 5018..5030 does not, 5030.. does.
        file.extend(epb(
            base + 4_000,
            &tcp_segment(server, 80, host, 49152, 5001, 0x10, b"HTTP/1.1 200 OK\r\n"),
        ));
        file.extend(epb(
            base + 5_000,
            &tcp_segment(server, 80, host, 49152, 5030, 0x10, b"<html>hello</html>"),
        ));
        file
    }

    /// A conversation that opens with a handshake, carries `request` one way
    /// and `response` the other in one segment each, and closes if `fin`.
    /// 10.42.85.10:49152 to 93.184.216.34:80.
    fn http_capture(request: &[u8], response: &[u8], fin: bool) -> Vec<u8> {
        let host = [10, 42, 85, 10];
        let server = [93, 184, 216, 34];
        let base = 1_600_482_318_566_000u64;
        let mut file = shb(1, "Linux 5.8.0-kali1-amd64");
        file.extend(idb(1));
        file.extend(epb(
            base,
            &tcp_segment(host, 49152, server, 80, 1000, 0x02, b""),
        ));
        file.extend(epb(
            base + 1_000,
            &tcp_segment(server, 80, host, 49152, 5000, 0x12, b""),
        ));
        file.extend(epb(
            base + 2_000,
            &tcp_segment(host, 49152, server, 80, 1001, 0x18, request),
        ));
        file.extend(epb(
            base + 3_000,
            &tcp_segment(server, 80, host, 49152, 5001, 0x18, response),
        ));
        if fin {
            file.extend(epb(
                base + 4_000,
                &tcp_segment(
                    server,
                    80,
                    host,
                    49152,
                    5001 + response.len() as u32,
                    0x11,
                    b"",
                ),
            ));
        }
        file
    }

    /// A whole HTTP exchange, contiguous both ways, whose response carries a
    /// gzip'd body — which is how nearly every body crosses the wire.
    fn http_body_capture() -> Vec<u8> {
        let request = b"GET /brand/logo.png HTTP/1.1\r\nHost: files.example.net\r\n\r\n";
        // Large enough that its gzip stream is smaller than it is: a
        // fourty-byte body compresses to more than fourty bytes, and a test
        // built on one would be testing the header overhead.
        let mut object = b"\x89PNG\r\n\x1a\n".to_vec();
        for _ in 0..64 {
            object.extend_from_slice(b"the object an examiner wants to read\n");
        }
        let wire = gzip(&object);
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: image/png\r\n\
             Content-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            wire.len()
        )
        .into_bytes();
        response.extend_from_slice(&wire);
        // The server closes, which is what makes a body with no framing whole.
        http_capture(request, &response, true)
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(bytes).expect("gzip");
        e.finish().expect("gzip")
    }

    /// One ARP frame on Ethernet.
    #[allow(clippy::too_many_arguments)]
    fn arp_frame(
        frame_source: [u8; 6],
        frame_destination: [u8; 6],
        operation: u16,
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
    ) -> Vec<u8> {
        let mut f = frame_destination.to_vec();
        f.extend_from_slice(&frame_source);
        f.extend_from_slice(&0x0806u16.to_be_bytes());
        f.extend_from_slice(&1u16.to_be_bytes()); // Ethernet
        f.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        f.extend_from_slice(&[6, 4]);
        f.extend_from_slice(&operation.to_be_bytes());
        f.extend_from_slice(&sender_mac);
        f.extend_from_slice(&sender_ip);
        f.extend_from_slice(&target_mac);
        f.extend_from_slice(&target_ip);
        f
    }

    /// A capture of a real TLS handshake: the fixture bytes of
    /// `tests/fixtures/` over TCP 443, in 1400-byte segments, which is what a
    /// handshake looks like on the wire.
    fn tls_capture_from_fixtures(client: &[u8], server: &[u8]) -> Vec<u8> {
        let host = [10, 42, 85, 10];
        let srv = [93, 184, 216, 34];
        let base = 1_600_482_318_566_000u64;
        let mut file = shb(1, "Linux 5.8.0-kali1-amd64");
        file.extend(idb(1));
        file.extend(epb(
            base,
            &tcp_segment(host, 49152, srv, 443, 1000, 0x02, b""),
        ));
        file.extend(epb(
            base + 1_000,
            &tcp_segment(srv, 443, host, 49152, 5000, 0x12, b""),
        ));
        let mut at = base + 2_000;
        for (index, chunk) in client.chunks(1400).enumerate() {
            file.extend(epb(
                at,
                &tcp_segment(
                    host,
                    49152,
                    srv,
                    443,
                    1001 + (index * 1400) as u32,
                    0x18,
                    chunk,
                ),
            ));
            at += 1_000;
        }
        for (index, chunk) in server.chunks(1400).enumerate() {
            file.extend(epb(
                at,
                &tcp_segment(
                    srv,
                    443,
                    host,
                    49152,
                    5001 + (index * 1400) as u32,
                    0x18,
                    chunk,
                ),
            ));
            at += 1_000;
        }
        file
    }

    /// A TCP payload that is not HTTP, which must yield no HTTP record at all
    /// rather than a guess. Its bytes are the first of a TLS record, so the
    /// same fixture shows TLS being recognised where HTTP is not.
    fn tls_capture() -> Vec<u8> {
        let host = [10, 42, 85, 10];
        let server = [203, 78, 103, 109];
        let base = 1_600_482_318_566_000u64;
        let mut hello = vec![
            0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0x00, 0x00, 0x1c, 0x03, 0x03,
        ];
        hello.extend_from_slice(&[0x11; 23]);
        let mut file = shb(1, "Linux 5.8.0-kali1-amd64");
        file.extend(idb(1));
        file.extend(epb(
            base,
            &tcp_segment(host, 62414, server, 443, 1000, 0x02, b""),
        ));
        file.extend(epb(
            base + 1_000,
            &tcp_segment(server, 443, host, 62414, 5000, 0x12, b""),
        ));
        file.extend(epb(
            base + 2_000,
            &tcp_segment(host, 62414, server, 443, 1001, 0x18, &hello),
        ));
        file
    }

    fn of_type<'a>(out: &'a [Artifact], ty: &str) -> Vec<&'a Artifact> {
        out.iter()
            .filter(|a| a.metadata.get("type").and_then(Value::as_str) == Some(ty))
            .collect()
    }

    /// **End to end: the flow record carries what each side said.** The
    /// request arrived out of order and reassembles whole; the response lost a
    /// segment, so its record holds the two pieces at their true offsets, the
    /// gap between them, and only the bytes before the gap as readable.
    #[test]
    fn a_tcp_exchange_is_reassembled_onto_its_flow_record() {
        let artifact = evidence(http_exchange_capture(), "exchange.pcapng");
        let out = PcapParser.process(&artifact).expect("process");

        let flows = of_type(&out, "NetworkFlow");
        assert_eq!(flows.len(), 1, "one conversation");
        let streams = &flows[0].metadata["tcp_streams"];
        assert!(!streams.is_null(), "{}", flows[0].metadata);

        // The client spoke first, so it is the initiator; it is also the
        // local endpoint here, since 10.42.85.10 is private and the server is
        // not.
        let request = &streams["local_to_remote"];
        assert_eq!(request["base_from_syn"], serde_json::json!(true));
        assert_eq!(request["runs"], 1, "out of order, and still one piece");
        assert_eq!(request["bytes_held"], 37);
        assert_eq!(request["holes_total_bytes"], 0);
        assert_eq!(request["contiguous"], serde_json::json!(true));

        let response = &streams["remote_to_local"];
        assert_eq!(response["runs"], 2, "the lost segment leaves two pieces");
        assert_eq!(response["holes"][0]["offset"], 17);
        assert_eq!(response["holes"][0]["length"], 12);
        assert_eq!(response["bytes_held"], 35);
        assert_eq!(response["contiguous"], serde_json::json!(false));

        // And the record says it is short of the conversation, naming the gap.
        assert_eq!(
            flows[0].metadata["content_incomplete"],
            serde_json::json!(true)
        );
        let detail = flows[0].metadata["content_incomplete_detail"]
            .as_str()
            .expect("a detail");
        assert!(detail.contains("missing 12 byte(s)"), "{detail}");
        assert!(
            detail.contains("17 byte(s) before the first gap"),
            "{detail}"
        );

        // And the capture record counts the streams and what is wrong with
        // them, so an examiner reading the capture first knows before opening
        // a flow.
        let capture = of_type(&out, "NetworkCapture")[0];
        assert_eq!(capture.metadata["tcp_streams"], 2);
        assert_eq!(capture.metadata["tcp_streams_with_gaps"], 1);
        assert_eq!(capture.metadata["tcp_streams_with_conflicts"], 0);
        assert_eq!(
            capture.metadata["tcp_streams_without_handshake"], 0,
            "both directions have their SYN here: the client's SYN and the server's SYN-ACK, \
             each opening its own stream"
        );
        assert_eq!(
            capture.metadata["tcp_stream_cap_reached"],
            serde_json::json!(false)
        );
        assert!(capture.metadata["tcp_streams_meaning"]
            .as_str()
            .is_some_and(|m| m.contains("WITHOUT A HANDSHAKE")));
    }

    /// **End to end: the exchange becomes a transaction record that says what
    /// its pairing rests on.** The request reassembled whole; the response
    /// lost a segment, so only its start line was readable — and because one
    /// direction has a hole, the pairing is marked as one that may be wrong.
    #[test]
    fn an_http_exchange_becomes_a_transaction_record_that_says_how_it_was_paired() {
        let artifact = evidence(http_exchange_capture(), "exchange.pcapng");
        let out = PcapParser.process(&artifact).expect("process");

        let transactions = of_type(&out, "HttpTransaction");
        assert_eq!(transactions.len(), 1, "one request, one response");
        let m = &transactions[0].metadata;
        assert_eq!(transactions[0].parent_id, Some(artifact.id));

        // Who asked and who answered, decided by which side's bytes were
        // requests rather than by who this capture saw speak first.
        assert_eq!(m["client_ip"], "10.42.85.10");
        assert_eq!(m["client_port"], 49152);
        assert_eq!(m["server_ip"], "93.184.216.34");
        assert_eq!(m["server_port"], 80);

        assert_eq!(m["request"]["method"], "GET");
        assert_eq!(m["request"]["target"], "/");
        assert_eq!(m["request"]["host"], "example.com");
        assert_eq!(m["request"]["complete"], serde_json::json!(true));

        assert_eq!(m["response"]["status"], 200);
        assert_eq!(
            m["response"]["headers_complete"],
            serde_json::json!(false),
            "the gap begins inside the header block"
        );
        assert_eq!(m["response"]["complete"], serde_json::json!(false));

        assert_eq!(m["pairing"], "in_order_over_a_gap");
        assert!(
            m["pairing_basis"]
                .as_str()
                .is_some_and(|b| b.contains("MAY BE WRONG")),
            "{}",
            m["pairing_basis"]
        );

        // The streams the messages were read from, so an examiner knows what
        // was and was not offered to the parser.
        assert_eq!(m["request_stream"]["gaps"], 0);
        assert_eq!(m["request_stream"]["parsed_bytes"], 37);
        assert_eq!(m["response_stream"]["gaps"], 1);
        assert_eq!(m["response_stream"]["gap_bytes"], 12);
        assert_eq!(m["response_stream"]["parsed_bytes"], 17);
        assert_eq!(
            m["response_stream"]["bytes_after_first_gap"], 18,
            "the capture holds them and no message was read across the hole"
        );

        assert_eq!(m["content_incomplete"], serde_json::json!(true));
        let detail = m["content_incomplete_detail"].as_str().expect("a detail");
        assert!(detail.contains("headers"), "{detail}");

        // Nothing was handed on as a body: neither message had one.
        assert!(of_type(&out, "HttpTransaction")
            .iter()
            .all(|t| t.metadata["response"]["body_bytes"] == 0));
        assert_eq!(
            out.iter()
                .filter(|a| a.metadata.get("http_body").is_some())
                .count(),
            0
        );

        let capture = of_type(&out, "NetworkCapture")[0];
        assert_eq!(capture.metadata["http_transactions"], 1);
        assert_eq!(capture.metadata["http_conversations"], 1);
        assert_eq!(capture.metadata["http_transactions_incomplete"], 1);
        assert_eq!(capture.metadata["http_bodies"], 0);
        assert!(capture.metadata["http_meaning"]
            .as_str()
            .is_some_and(|m| m.contains("port")));
    }

    /// **The body is handed on as its own artifact, decoded.** The object an
    /// examiner wants is the PNG, not the gzip stream, so the artifact holds
    /// the inflated bytes, is named from the URL, and states what crossed the
    /// wire. It is parented to the transaction, so the chain of custody reads
    /// capture -> transaction -> object.
    #[test]
    fn a_response_body_is_handed_on_as_a_decoded_artifact_named_from_its_url() {
        let artifact = evidence(http_body_capture(), "download.pcapng");
        let out = PcapParser.process(&artifact).expect("process");

        let transactions = of_type(&out, "HttpTransaction");
        assert_eq!(transactions.len(), 1);
        let m = &transactions[0].metadata;
        assert_eq!(m["pairing"], "in_order", "both directions are contiguous");
        assert_eq!(m["request"]["target"], "/brand/logo.png");
        assert_eq!(m["response"]["content_type"], "image/png");
        assert_eq!(m["response"]["complete"], serde_json::json!(true));
        assert!(
            m["content_incomplete"].is_null(),
            "nothing here is short: {m}"
        );

        let bodies: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.metadata.get("http_body").is_some())
            .collect();
        assert_eq!(bodies.len(), 1, "one body in this exchange");
        let body = bodies[0];
        assert_eq!(body.artifact_type, ArtifactType::FileEntry);
        assert_eq!(body.parent_id, Some(transactions[0].id));
        assert_eq!(body.metadata["name"], "logo.png");
        assert_eq!(body.metadata["http_message"], "response");
        assert_eq!(body.metadata["http_target"], "/brand/logo.png");
        assert_eq!(body.metadata["http_host"], "files.example.net");
        assert_eq!(body.metadata["http_content_type"], "image/png");
        assert_eq!(body.metadata["http_content_encoding"], "gzip");
        assert_eq!(body.metadata["http_body_coding"], "decoded");
        assert!(body.metadata["http_body_statement"]
            .as_str()
            .is_some_and(|s| s.contains("decoded body")));
        assert!(body.metadata["content_incomplete"].is_null());

        // And the bytes are there for YARA, the hasher and the search index.
        let data = body.data.as_ref().expect("the body's bytes");
        let mut buf = vec![0u8; data.size() as usize];
        data.read_at(0, &mut buf).expect("read");
        assert!(buf.starts_with(b"\x89PNG"), "the object, inflated");
        assert_eq!(body.metadata["size"], buf.len());
        assert!(
            body.metadata["http_wire_bytes"].as_u64().expect("wire") < buf.len() as u64,
            "the wire carried fewer bytes than the object: that is what gzip is for"
        );
        // The record points at the artifact, so the two can be read together.
        assert_eq!(
            m["response"]["body_artifact_id"],
            serde_json::json!(body.id.to_string())
        );

        let capture = of_type(&out, "NetworkCapture")[0];
        assert_eq!(capture.metadata["http_bodies"], 1);
        assert_eq!(capture.metadata["http_transactions_incomplete"], 0);
    }

    /// **A body shorter than the message declared is still handed on, and
    /// never as the object.** A download cut off by the end of the capture is
    /// evidence of what was fetched; calling it the file would be the lie.
    #[test]
    fn a_body_shorter_than_it_declared_is_emitted_and_says_by_how_much() {
        let request = b"GET /tools/mimikatz.exe HTTP/1.1\r\nHost: 203.78.103.109\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                         Content-Length: 4096\r\n\r\nMZ\x90\x00 only the first bytes";
        let artifact = evidence(http_capture(request, response, false), "cut.pcapng");
        let out = PcapParser.process(&artifact).expect("process");

        let transactions = of_type(&out, "HttpTransaction");
        assert_eq!(transactions.len(), 1);
        let m = &transactions[0].metadata;
        assert_eq!(m["url"], "http://203.78.103.109/tools/mimikatz.exe");
        assert_eq!(m["response"]["body_end"], "length_short");
        assert_eq!(m["content_incomplete"], serde_json::json!(true));
        let detail = m["content_incomplete_detail"].as_str().expect("a detail");
        assert!(
            detail.contains("declared a body of 4096 bytes and 25 are in the capture"),
            "{detail}"
        );

        let body = out
            .iter()
            .find(|a| a.metadata.get("http_body").is_some())
            .expect("the body");
        assert_eq!(body.metadata["name"], "mimikatz.exe");
        assert_eq!(body.metadata["size"], 25);
        assert_eq!(body.metadata["content_incomplete"], serde_json::json!(true));
        assert_eq!(body.metadata["content_incomplete_reason"], "short_read");
        assert!(body.metadata["content_incomplete_detail"]
            .as_str()
            .is_some_and(|d| d.contains("4096")));
        // The claimed type is on the record as a claim, and the detectors
        // that run over these bytes are what answer what it is.
        assert_eq!(
            body.metadata["http_content_type"],
            "application/octet-stream"
        );
        assert_eq!(
            body.metadata["http_content_type_is_a_claim"],
            serde_json::json!(true)
        );
    }

    /// **The fields of a posted form reach the record**, because "what did
    /// they send" is the question a webmail post or a login answers, and the
    /// body artifact alone is not searchable as fields.
    #[test]
    fn a_posted_forms_fields_reach_the_transaction_record() {
        let body = b"to=lilytuckrige%40yahoo.com&message=Stop+teaching+that+class%21";
        let request = format!(
            "POST /secure/submit?sid=99 HTTP/1.1\r\nHost: www.willselfdestruct.com\r\n\
             Referer: http://www.willselfdestruct.com/\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        );
        let mut request = request.into_bytes();
        request.extend_from_slice(body);
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let artifact = evidence(http_capture(&request, response, true), "webmail.pcapng");
        let out = PcapParser.process(&artifact).expect("process");

        let transactions = of_type(&out, "HttpTransaction");
        assert_eq!(transactions.len(), 1);
        let request = &transactions[0].metadata["request"];
        assert_eq!(
            request["form_fields"]["fields"]["to"],
            "lilytuckrige@yahoo.com"
        );
        assert_eq!(
            request["form_fields"]["fields"]["message"],
            "Stop teaching that class!"
        );
        assert_eq!(request["query_fields"]["fields"]["sid"], "99");
        assert_eq!(
            request["referer"], "http://www.willselfdestruct.com/",
            "where the form was posted from"
        );
        // A response carries no form, and the field says so rather than being
        // absent — an absent field reads as "not looked for".
        assert!(transactions[0].metadata["response"]["form_fields"].is_null());
    }

    /// **What was uploaded is evidence too.** A POST body is handed on the
    /// same way, under a name that says which side of the exchange it came
    /// from rather than borrowing the target's.
    #[test]
    fn a_request_body_is_handed_on_under_a_name_that_says_it_was_uploaded() {
        let request = b"POST /upload.php HTTP/1.1\r\nHost: drop.example.org\r\n\
                        Content-Type: application/x-www-form-urlencoded\r\n\
                        Content-Length: 34\r\n\r\nuser=admin&pass=hunter2&file=notes";
        let response = b"HTTP/1.1 204 No Content\r\nServer: nginx\r\n\r\n";
        let artifact = evidence(http_capture(request, response, true), "upload.pcapng");
        let out = PcapParser.process(&artifact).expect("process");

        let transactions = of_type(&out, "HttpTransaction");
        assert_eq!(transactions.len(), 1);
        let m = &transactions[0].metadata;
        assert_eq!(m["request"]["method"], "POST");
        assert_eq!(m["response"]["status"], 204);
        assert_eq!(m["pairing"], "in_order");
        assert!(m["content_incomplete"].is_null(), "{m}");

        let bodies: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.metadata.get("http_body").is_some())
            .collect();
        assert_eq!(bodies.len(), 1, "the response carries none");
        assert_eq!(bodies[0].metadata["name"], "http-0-request-body");
        assert_eq!(bodies[0].metadata["http_message"], "request");
        assert_eq!(
            bodies[0].metadata["http_url"],
            "http://drop.example.org/upload.php"
        );
        let data = bodies[0].data.as_ref().expect("bytes");
        let mut buf = vec![0u8; data.size() as usize];
        data.read_at(0, &mut buf).expect("read");
        assert_eq!(&buf, b"user=admin&pass=hunter2&file=notes");
    }

    /// A TCP payload that is not HTTP yields no HTTP record: the module reads
    /// a start line or says nothing.
    #[test]
    fn a_tls_stream_yields_no_http_record() {
        let artifact = evidence(tls_capture(), "tls.pcapng");
        let out = PcapParser.process(&artifact).expect("process");
        assert!(of_type(&out, "HttpTransaction").is_empty());
        let capture = of_type(&out, "NetworkCapture")[0];
        assert_eq!(capture.metadata["http_transactions"], 0);
        assert_eq!(
            capture.metadata["tcp_streams"], 2,
            "the streams were reassembled; they are simply not HTTP"
        );
    }

    /// **End to end: an encrypted conversation is not an opaque one.** The
    /// name the client asked for, the version and cipher agreed, the client's
    /// fingerprint, and the certificate the server presented — all read from a
    /// real handshake reassembled out of the capture.
    #[test]
    fn a_tls_conversation_becomes_a_session_record_with_its_name_and_certificate() {
        let client = include_bytes!("../tests/fixtures/tls12_client_to_server.bin");
        let server = include_bytes!("../tests/fixtures/tls12_server_to_client.bin");
        let artifact = evidence(tls_capture_from_fixtures(client, server), "tls12.pcapng");
        let out = PcapParser.process(&artifact).expect("process");

        let sessions = of_type(&out, "TlsSession");
        assert_eq!(sessions.len(), 1, "one conversation");
        let m = &sessions[0].metadata;
        assert_eq!(sessions[0].parent_id, Some(artifact.id));
        assert_eq!(m["client_ip"], "10.42.85.10");
        assert_eq!(m["server_ip"], "93.184.216.34");
        assert_eq!(m["server_port"], 443);
        assert_eq!(m["server_name"], "lab.seance.invalid");
        assert_eq!(m["negotiated_version"], "TLS 1.2");
        assert_eq!(
            m["negotiated_cipher"],
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        );
        assert_eq!(m["cipher_is_known_weak"], serde_json::json!(false));
        assert_eq!(m["ja3_md5"], "1c9a15ffefdbe3d51d703fde3c4086eb");
        assert_eq!(m["certificates"], 1);
        assert_eq!(
            m["certificate_names"],
            serde_json::json!(["lab.seance.invalid", "alt.seance.invalid", "127.0.0.1"])
        );
        assert!(m["certificates_unavailable"].is_null());
        assert!(m["statement"]
            .as_str()
            .is_some_and(|s| s.contains("NO signature verified")));

        // The certificate is its own record, under the session that carried
        // it, with the fields openssl reads from the same bytes.
        let certificates = of_type(&out, "TlsCertificate");
        assert_eq!(certificates.len(), 1);
        let c = &certificates[0].metadata;
        assert_eq!(certificates[0].parent_id, Some(sessions[0].id));
        assert_eq!(c["position_in_chain"], 0);
        assert_eq!(
            c["subject"],
            "C=IE, ST=Dublin, O=Seance Lab, OU=Forensics, CN=lab.seance.invalid"
        );
        assert_eq!(c["subject_common_name"], "lab.seance.invalid");
        assert_eq!(c["not_before"], "2026-09-15T21:21:47Z");
        assert_eq!(c["not_after"], "2036-09-12T21:21:47Z");
        assert_eq!(c["self_signed"], serde_json::json!(true));
        assert_eq!(c["signature_verified"], serde_json::json!(false));
        assert_eq!(
            c["sha256"],
            "e0e0bc2fee38697c255da4b4115def0a5702b7b9dd05066d801c09e862ca875a"
        );

        // A timeline event at each end of the certificate's validity window:
        // a certificate issued the day before an intrusion is the finding.
        let events: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
            .filter(|a| a.metadata["event_type"] == "certificate_validity")
            .collect();
        assert_eq!(events.len(), 2, "not before and not after");
        assert_eq!(events[0].metadata["timestamp"], "2026-09-15T21:21:47Z");

        let capture = of_type(&out, "NetworkCapture")[0];
        assert_eq!(capture.metadata["tls_sessions"], 1);
        assert_eq!(capture.metadata["tls_server_names"], 1);
        assert_eq!(capture.metadata["tls_certificates"], 1);
        assert_eq!(capture.metadata["tls_self_signed_certificates"], 1);
        assert_eq!(capture.metadata["tls_sessions_without_a_certificate"], 0);
        assert!(capture.metadata["tls_meaning"]
            .as_str()
            .is_some_and(|s| s.contains("TLS 1.3")));
    }

    /// **TLS 1.3 hides the certificate, and the record says which of the two
    /// findings applies.** The server name is still there, and so is the
    /// sentence that stops an absent certificate being read as a server that
    /// presented none.
    #[test]
    fn a_tls13_session_says_why_it_has_no_certificate() {
        let client = include_bytes!("../tests/fixtures/tls13_client_to_server.bin");
        let server = include_bytes!("../tests/fixtures/tls13_server_to_client.bin");
        let artifact = evidence(tls_capture_from_fixtures(client, server), "tls13.pcapng");
        let out = PcapParser.process(&artifact).expect("process");

        let sessions = of_type(&out, "TlsSession");
        assert_eq!(sessions.len(), 1);
        let m = &sessions[0].metadata;
        assert_eq!(m["server_name"], "lab.seance.invalid");
        assert_eq!(m["negotiated_version"], "TLS 1.3");
        assert_eq!(m["negotiated_cipher"], "TLS_AES_256_GCM_SHA384");
        assert_eq!(m["alpn_offered"], serde_json::json!(["h2", "http/1.1"]));
        assert_eq!(m["ja3_md5"], "036bfa3a293e8fb976317efd97d7d778");
        assert_eq!(m["certificates"], 0);
        assert_eq!(m["certificates_unavailable"], "encrypted_by_tls13");
        assert!(m["certificates_unavailable_statement"]
            .as_str()
            .is_some_and(|s| s.contains("NO CAPTURE OF TLS 1.3 CAN HOLD")));
        assert!(of_type(&out, "TlsCertificate").is_empty());

        let capture = of_type(&out, "NetworkCapture")[0];
        assert_eq!(capture.metadata["tls_sessions"], 1);
        assert_eq!(capture.metadata["tls_certificates"], 0);
        assert_eq!(
            capture.metadata["tls_sessions_without_a_certificate"], 1,
            "counted, with the reason on the session"
        );
    }

    /// **End to end: who claimed which address, and where two hosts claimed
    /// one.** The gateway is answered for by the router and then by another
    /// machine, which is how a segment is poisoned — and also what a failover
    /// pair looks like, so the record states the claims and no verdict.
    #[test]
    fn arp_claims_become_binding_records_and_a_contested_address_is_named() {
        let laptop = [0x00, 0xde, 0xad, 0xbe, 0xef, 0x01];
        let router = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
        let attacker = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let broadcast = [0xff; 6];
        let base = 1_600_482_318_566_000u64;

        let mut file = shb(1, "Linux 5.8.0-kali1-amd64");
        file.extend(idb(1));
        // Who has the gateway?
        file.extend(epb(
            base,
            &arp_frame(
                laptop,
                broadcast,
                1,
                laptop,
                [10, 42, 85, 10],
                [0; 6],
                [10, 42, 85, 1],
            ),
        ));
        // The router answers.
        file.extend(epb(
            base + 1_000,
            &arp_frame(
                router,
                laptop,
                2,
                router,
                [10, 42, 85, 1],
                laptop,
                [10, 42, 85, 10],
            ),
        ));
        // And then another machine announces the gateway's address without
        // being asked.
        file.extend(epb(
            base + 60_000_000,
            &arp_frame(
                attacker,
                broadcast,
                2,
                attacker,
                [10, 42, 85, 1],
                attacker,
                [10, 42, 85, 1],
            ),
        ));
        let artifact = evidence(file, "arp-poison.pcapng");
        let out = PcapParser.process(&artifact).expect("process");

        let bindings = of_type(&out, "ArpBinding");
        assert_eq!(bindings.len(), 2, "the laptop and the gateway address");
        let gateway = bindings
            .iter()
            .find(|b| b.metadata["ip"] == "10.42.85.1")
            .expect("the gateway's record");
        assert_eq!(gateway.parent_id, Some(artifact.id));
        assert_eq!(gateway.metadata["contested"], serde_json::json!(true));
        assert_eq!(
            gateway.metadata["macs"],
            serde_json::json!(["00:1a:2b:3c:4d:5e", "00:11:22:33:44:55"]),
            "in the order they were first seen, so the record reads as a history"
        );
        assert_eq!(gateway.metadata["claims"][1]["gratuitous_announcements"], 1);
        let statement = gateway.metadata["statement"].as_str().expect("a statement");
        assert!(statement.contains("does not authenticate"), "{statement}");
        assert!(statement.contains("failover"), "{statement}");
        assert_eq!(
            gateway.metadata["content_incomplete"],
            serde_json::json!(true),
            "a contested address is not a complete account of anything"
        );

        let laptop_binding = bindings
            .iter()
            .find(|b| b.metadata["ip"] == "10.42.85.10")
            .expect("the laptop's record");
        assert_eq!(
            laptop_binding.metadata["contested"],
            serde_json::json!(false)
        );
        assert_eq!(laptop_binding.metadata["claims"][0]["in_requests"], 1);

        // The instant the contest began is on the timeline, because that is
        // when the segment's cache started to be wrong.
        let events: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
            .filter(|a| a.metadata["event_type"] == "arp_address_contested")
            .collect();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].metadata["ip"], "10.42.85.1");
        assert_eq!(
            events[0].metadata["timestamp"], "2020-09-19T02:26:18.566000+00:00",
            "the instant the second claim was seen, not the first"
        );
        assert_eq!(
            events[0].metadata["timestamp_micros"],
            1_600_482_378_566_000u64
        );

        let capture = of_type(&out, "NetworkCapture")[0];
        assert_eq!(capture.metadata["arp_frames"], 3);
        assert_eq!(capture.metadata["arp_addresses"], 2);
        assert_eq!(capture.metadata["arp_addresses_contested"], 1);
        assert_eq!(capture.metadata["arp_hardware_addresses"], 3);
        assert_eq!(capture.metadata["arp_requests"], 1);
        assert_eq!(capture.metadata["arp_replies"], 2);
        assert_eq!(capture.metadata["arp_gratuitous_replies"], 1);
        assert_eq!(capture.metadata["arp_probes"], 0);
        assert_eq!(capture.metadata["arp_unreadable_frames"], 0);
        assert_eq!(
            capture.metadata["packets_no_network_layer"], 3,
            "ARP still has no network layer; reading it does not change that"
        );
        assert!(capture.metadata["arp_meaning"]
            .as_str()
            .is_some_and(|m| m.contains("DOES NOT AUTHENTICATE")));
    }

    /// An ARP frame this build cannot read is counted as one, and not as an
    /// absence of ARP.
    #[test]
    fn an_arp_frame_this_build_cannot_read_is_counted_as_one() {
        let mut arp = vec![0xff; 6];
        arp.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        arp.extend_from_slice(&0x0806u16.to_be_bytes());
        // Hardware type 6 (IEEE 802) and a protocol this build does not read.
        arp.extend_from_slice(&[0x00, 0x06, 0x80, 0x35, 0x06, 0x04, 0x00, 0x01]);
        arp.extend_from_slice(&[0u8; 20]);
        let mut file = shb(1, "lab");
        file.extend(idb(1));
        file.extend(epb(1_000_000, &arp));
        let artifact = evidence(file, "odd-arp.pcapng");
        let out = PcapParser.process(&artifact).expect("process");

        assert!(of_type(&out, "ArpBinding").is_empty());
        let capture = of_type(&out, "NetworkCapture")[0];
        assert_eq!(capture.metadata["arp_frames"], 0);
        assert_eq!(capture.metadata["arp_unreadable_frames"], 1);
        assert_eq!(capture.metadata["packets_no_network_layer"], 1);
    }

    #[test]
    fn the_module_identifies_itself_and_subscribes_to_evidence_and_files() {
        let m = PcapParser;
        assert_eq!(m.id(), "plugin.network.pcap_parser");
        assert_eq!(
            m.subscribes_to(),
            vec![ArtifactType::RawEvidence, ArtifactType::FileEntry]
        );
        assert_eq!(m.input_capability(), InputCapability::RandomAccess);
    }

    #[test]
    fn a_single_section_pcapng_with_three_packets_becomes_a_capture_record_one_flow_and_its_event()
    {
        let artifact = evidence(three_packet_capture(), "case001.pcap");
        let out = PcapParser.process(&artifact).expect("process");

        let captures = of_type(&out, "NetworkCapture");
        assert_eq!(captures.len(), 1);
        let c = captures[0];
        assert_eq!(c.parent_id, Some(artifact.id));
        assert_eq!(c.metadata["format"], "pcapng");
        assert_eq!(c.metadata["packets"], 3);
        assert_eq!(c.metadata["flow_count"], 1);
        assert_eq!(c.metadata["sections"][0]["os"], "Linux 5.8.0-kali1-amd64");
        assert_eq!(c.metadata["first_seen"], "2020-09-19T02:25:18.566000Z");
        assert_eq!(c.metadata["last_seen"], "2020-09-19T02:25:18.687000Z");
        assert_eq!(c.metadata["bytes_declared"], c.metadata["bytes_staged"]);
        assert!(c.metadata.get("content_incomplete").is_none());
        assert!(c.metadata.get("inventory_incomplete").is_none());

        let flows = of_type(&out, "NetworkFlow");
        assert_eq!(flows.len(), 1);
        let f = flows[0];
        assert_eq!(f.metadata["protocol"], "tcp");
        assert_eq!(f.metadata["local_ip"], "10.42.85.10");
        assert_eq!(f.metadata["local_port"], 62414);
        assert_eq!(f.metadata["remote_ip"], "203.78.103.109");
        assert_eq!(f.metadata["remote_port"], 443);
        assert_eq!(f.metadata["remote_is_external"], true);
        assert_eq!(f.metadata["tcp_state"], "handshake_seen");
        assert_eq!(f.metadata["packets_out"], 2);
        assert_eq!(f.metadata["packets_in"], 1);
        assert_eq!(f.metadata["bytes"], 54 * 3);
        assert_eq!(f.metadata["truncated_packets"], 0);

        let events: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
            .collect();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].metadata["timestamp"],
            "2020-09-19T02:25:18.566000+00:00"
        );
        assert_eq!(events[0].metadata["source_module"], MODULE_ID);

        assert!(of_type(&out, "NetworkCaptureRefusal").is_empty());
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn a_file_that_is_not_a_capture_is_skipped_silently_because_it_is_not_ours() {
        let artifact = evidence(b"MZ\x90\x00 this is not a capture at all".to_vec(), "x.exe");
        let out = PcapParser.process(&artifact).expect("process");
        assert!(out.is_empty());
    }

    #[test]
    fn an_artifact_with_no_data_source_is_skipped() {
        let artifact = Artifact::new(
            uuid::Uuid::nil(),
            ArtifactType::FileEntry,
            None,
            json!({ "name": "capture.pcapng" }),
        );
        assert!(PcapParser.process(&artifact).expect("process").is_empty());
    }

    #[test]
    fn a_capture_detection_accepted_but_the_reader_refused_leaves_a_refusal_record() {
        // Detection reads the SHB and its byte-order magic; the version is
        // the reader's to refuse, and a version 2 section is one it does.
        let mut file = shb(2, "future");
        file.extend(idb(1));
        let artifact = evidence(file, "future.pcapng");
        let out = PcapParser.process(&artifact).expect("process");

        assert_eq!(out.len(), 1);
        let r = &out[0];
        assert_eq!(r.metadata["type"], "NetworkCaptureRefusal");
        assert_eq!(r.metadata["subtype"], "unsupported_version");
        assert_eq!(r.parent_id, Some(artifact.id));
        assert_eq!(r.metadata["content_incomplete"], true);
        assert_eq!(r.metadata["inventory_incomplete"], true);
        let error = r.metadata["error"].as_str().unwrap();
        assert!(error.contains("2.0"), "{error}");
        assert!(r.metadata["detail"]
            .as_str()
            .unwrap()
            .contains("future.pcapng"));
    }

    #[test]
    fn a_capture_of_nothing_but_arp_still_leaves_a_capture_record() {
        let mut arp = vec![0xff; 6];
        arp.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        arp.extend_from_slice(&0x0806u16.to_be_bytes());
        arp.extend_from_slice(&[0; 28]);
        let mut file = shb(1, "lab");
        file.extend(idb(1));
        file.extend(epb(1_000_000, &arp));
        let artifact = evidence(file, "arp.pcapng");
        let out = PcapParser.process(&artifact).expect("process");

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["type"], "NetworkCapture");
        assert_eq!(out[0].metadata["packets"], 1);
        assert_eq!(out[0].metadata["packets_no_network_layer"], 1);
        assert_eq!(out[0].metadata["flow_count"], 0);
    }

    #[test]
    fn a_capture_on_a_linktype_this_build_does_not_decode_leaves_a_refusal_naming_it() {
        let mut file = shb(1, "lab");
        file.extend(idb(228));
        file.extend(epb(1_000_000, &[0u8; 40]));
        let artifact = evidence(file, "ipv4-raw.pcapng");
        let out = PcapParser.process(&artifact).expect("process");

        let refusals = of_type(&out, "NetworkCaptureRefusal");
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].metadata["linktype"], 228);
        assert_eq!(refusals[0].metadata["packets_refused_with_linktype"], 1);
        let c = of_type(&out, "NetworkCapture")[0];
        assert_eq!(c.metadata["refusals"]["unsupported_linktype"], 1);
    }

    #[test]
    fn a_dns_response_on_port_53_becomes_a_resolution_record_naming_the_answer() {
        // Ethernet / IPv4 / UDP from 10.42.85.1:53 to 10.42.85.10:51234 with a
        // one-question, one-A-record response for update.example.net.
        let mut dns = Vec::new();
        dns.extend_from_slice(&[0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        for label in ["update", "example", "net"] {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label.as_bytes());
        }
        dns.extend_from_slice(&[0, 0, 1, 0, 1]);
        dns.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 78, 103, 109]);

        let udp_len = (8 + dns.len()) as u16;
        let mut f = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        ];
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&(20 + udp_len).to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00]);
        ip.extend_from_slice(&[10, 42, 85, 1]);
        ip.extend_from_slice(&[10, 42, 85, 10]);
        let csum = ipv4_checksum(&ip);
        ip[10..12].copy_from_slice(&csum.to_be_bytes());
        f.extend_from_slice(&ip);
        f.extend_from_slice(&53u16.to_be_bytes());
        f.extend_from_slice(&51234u16.to_be_bytes());
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&dns);

        let mut file = shb(1, "lab");
        file.extend(idb(1));
        file.extend(epb(1_600_482_300_000_000, &f));
        let out = PcapParser
            .process(&evidence(file, "dns.pcapng"))
            .expect("process");

        let records = of_type(&out, "DnsResolution");
        assert_eq!(records.len(), 1);
        let r = records[0];
        assert_eq!(r.metadata["name"], "update.example.net");
        assert_eq!(r.metadata["is_response"], true);
        assert_eq!(r.metadata["answer_data"], json!(["203.78.103.109"]));
        assert_eq!(r.metadata["client_ip"], "10.42.85.10");
        assert_eq!(r.metadata["server_ip"], "10.42.85.1");
        assert_eq!(r.metadata["timestamp"], "2020-09-19T02:25:00.000000Z");
        let c = of_type(&out, "NetworkCapture")[0];
        assert_eq!(c.metadata["dns_messages"], 1);
        assert_eq!(of_type(&out, "NetworkFlow").len(), 1);
    }

    /// Detection accepts any classic-pcap magic regardless of version so the
    /// reader can refuse a version by name. The refusal has to reach the
    /// record, or a 2.5 file is HUNT-060's silence again with a document
    /// promising otherwise.
    #[test]
    fn a_classic_pcap_of_an_unsupported_version_leaves_a_refusal_naming_the_version() {
        let file = classic_pcap(2, 5, &[]);
        let artifact = evidence(file, "future.pcap");
        let out = PcapParser.process(&artifact).expect("process");

        assert_eq!(out.len(), 1, "{out:?}");
        let r = &out[0];
        assert_eq!(r.metadata["type"], "NetworkCaptureRefusal");
        assert_eq!(r.metadata["subtype"], "unsupported_version");
        assert_eq!(r.parent_id, Some(artifact.id));
        let error = r.metadata["error"].as_str().unwrap();
        assert!(error.contains("2.5"), "{error}");
        assert_eq!(r.metadata["content_incomplete"], true);
        assert_eq!(r.metadata["inventory_incomplete"], true);
    }

    /// The bulk carver's `carved_packets.pcap` writes every record with both
    /// timestamp fields zero. End to end, that must be "no timestamp": no
    /// first_seen, no timeline event at the epoch, and a count that says so.
    #[test]
    fn a_classic_pcap_whose_records_are_dated_zero_yields_undated_flows_and_no_epoch_event() {
        let host = [10, 42, 85, 10];
        let c2 = [203, 78, 103, 109];
        let syn = tcp_frame(host, 62414, c2, 443, 0x02);
        let file = classic_pcap(2, 4, &[(0, 0, &syn), (0, 0, &syn)]);
        let out = PcapParser
            .process(&evidence(file, "carved_packets.pcap"))
            .expect("process");

        let c = of_type(&out, "NetworkCapture")[0];
        assert_eq!(c.metadata["packets"], 2);
        assert_eq!(c.metadata["packets_without_timestamp"], 2);
        assert_eq!(c.metadata["first_seen"], Value::Null);
        let f = of_type(&out, "NetworkFlow")[0];
        assert_eq!(f.metadata["packets"], 2);
        assert_eq!(f.metadata["timestamped_packets"], 0);
        assert_eq!(f.metadata["first_seen"], Value::Null);
        assert_eq!(f.metadata["duration_seconds"], Value::Null);
        assert!(out
            .iter()
            .all(|a| a.artifact_type != ArtifactType::TimelineEvent));
    }

    /// A stale checksum on the SYN: the packet is refused with its addresses
    /// and lands on the IP pair, and the ported flow holding the SYN-ACK
    /// says its other half was refused. A regression that dropped addressed
    /// refusals at the wiring would delete one direction of every such
    /// conversation with no counter naming it; this pins the join.
    #[test]
    fn a_bad_checksum_packet_lands_on_the_ip_pair_and_the_ported_flow_says_so_end_to_end() {
        let host = [10, 42, 85, 10];
        let c2 = [203, 78, 103, 109];
        let file = one_flow_capture(&[
            with_checksum_stale(tcp_frame(host, 62414, c2, 443, 0x02)),
            tcp_frame(c2, 443, host, 62414, 0x12),
        ]);
        let out = PcapParser
            .process(&evidence(file, "stale.pcapng"))
            .expect("process");

        let c = of_type(&out, "NetworkCapture")[0];
        assert_eq!(c.metadata["refusals"]["ipv4_checksum_failed"], 1);
        assert_eq!(c.metadata["packets_in_flows"], 2);
        let flows = of_type(&out, "NetworkFlow");
        assert_eq!(flows.len(), 2, "{flows:?}");

        let pair = ip_pair_flow(&flows);
        assert_eq!(pair.metadata["protocol"], Value::Null);
        assert_eq!(
            pair.metadata["unattributed_packets"]["ipv4_checksum_failed"],
            1
        );
        assert_eq!(pair.metadata["content_incomplete"], true);

        let ported = flow_with_port(&flows, 443);
        assert_eq!(ported.metadata["refused_packets_between_hosts"], 1);
        assert_eq!(
            ported.metadata["refused_packets_between_hosts_by_reason"]["ipv4_checksum_failed"],
            1
        );
        assert_eq!(ported.metadata["content_incomplete"], true);
        assert_eq!(
            ported.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
        assert!(ported.metadata["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("ipv4_checksum_failed"));
    }

    /// Transmit checksum offload on the capturing host: the SYN's checksum
    /// field is zero. The packet is whole and decodes onto the ported flow,
    /// counted as unset — not refused, not split off, not stamped.
    #[test]
    fn an_unset_checksum_packet_lands_on_the_ported_flow_counted_as_unset_end_to_end() {
        let host = [10, 42, 85, 10];
        let c2 = [203, 78, 103, 109];
        let file = one_flow_capture(&[
            with_checksum_unset(tcp_frame(host, 62414, c2, 443, 0x02)),
            tcp_frame(c2, 443, host, 62414, 0x12),
            with_checksum_unset(tcp_frame(host, 62414, c2, 443, 0x10)),
        ]);
        let out = PcapParser
            .process(&evidence(file, "offload.pcapng"))
            .expect("process");

        let c = of_type(&out, "NetworkCapture")[0];
        assert_eq!(c.metadata["refusals"], json!({}));
        assert_eq!(c.metadata["packets_refused"], 0);
        let flows = of_type(&out, "NetworkFlow");
        assert_eq!(flows.len(), 1, "{flows:?}");
        let f = flows[0];
        assert_eq!(f.metadata["local_ip"], "10.42.85.10");
        assert_eq!(f.metadata["local_is_initiator"], true);
        assert_eq!(f.metadata["packets_out"], 2);
        assert_eq!(f.metadata["packets_in"], 1);
        assert_eq!(f.metadata["checksum_unset_packets"], 2);
        assert_eq!(f.metadata["tcp_state"], "handshake_seen");
        assert_eq!(f.metadata["refused_packets_between_hosts"], 0);
        assert!(f.metadata.get("content_incomplete").is_none());
    }

    /// A non-initial fragment whose payload begins with bytes that read as
    /// `31337 -> 4444`: no ported flow may be made from it. It lands on the
    /// IP pair, and the UDP flow the first fragment made says a fragment of
    /// its protocol was refused between the hosts.
    #[test]
    fn a_non_initial_fragment_gives_no_ported_flow_its_bytes_end_to_end() {
        let host = [10, 42, 85, 10];
        let dns = [10, 42, 85, 1];
        // First fragment: MF set, offset 0, a UDP header 4000 -> 53.
        let mut first = ethernet_ipv4(host, dns, 17, 8 + 8, 0x2000);
        first.extend_from_slice(&4000u16.to_be_bytes());
        first.extend_from_slice(&53u16.to_be_bytes());
        first.extend_from_slice(&1500u16.to_be_bytes());
        first.extend_from_slice(&[0, 0]);
        first.extend_from_slice(&[0xaa; 8]);
        // Second fragment: offset 185 (byte 1480), payload that looks like
        // a UDP header for 31337 -> 4444.
        let mut second = ethernet_ipv4(host, dns, 17, 8, 0x00B9);
        second.extend_from_slice(&31337u16.to_be_bytes());
        second.extend_from_slice(&4444u16.to_be_bytes());
        second.extend_from_slice(&[0, 8, 0, 0]);
        let file = one_flow_capture(&[first, second]);
        let out = PcapParser
            .process(&evidence(file, "fragments.pcapng"))
            .expect("process");

        let c = of_type(&out, "NetworkCapture")[0];
        assert_eq!(c.metadata["refusals"]["non_initial_fragment"], 1);
        let flows = of_type(&out, "NetworkFlow");
        assert_eq!(flows.len(), 2, "{flows:?}");
        for f in &flows {
            for key in ["local_port", "remote_port"] {
                assert_ne!(f.metadata[key], 4444, "{}", f.metadata);
                assert_ne!(f.metadata[key], 31337, "{}", f.metadata);
            }
        }
        let pair = ip_pair_flow(&flows);
        assert_eq!(pair.metadata["protocol"], "udp");
        assert_eq!(
            pair.metadata["unattributed_packets"]["non_initial_fragment"],
            1
        );
        let ported = flow_with_port(&flows, 53);
        assert_eq!(ported.metadata["refused_packets_between_hosts"], 1);
        assert_eq!(ported.metadata["content_incomplete"], true);
    }

    /// `tcpdump -s 40` on Ethernet: 14 + 20 + 6 bytes, the TCP header cut
    /// after its ports. Nothing after the IP layer may be read, so the packet
    /// lands on the IP pair as TCP with no ports, stamped short_read, and its
    /// state says no flags were read — not "no handshake seen".
    #[test]
    fn a_transport_truncated_packet_lands_on_the_ip_pair_as_a_short_read_end_to_end() {
        let host = [10, 42, 85, 10];
        let c2 = [203, 78, 103, 109];
        let mut cut = tcp_frame(host, 62414, c2, 443, 0x02);
        cut.truncate(14 + 20 + 6);
        let mut file = shb(1, "lab");
        file.extend(idb(1));
        // The EPB's original length is the wire length; the captured bytes
        // are what the snaplen left.
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&1_600_482_318u32.to_le_bytes());
        body.extend_from_slice(&(cut.len() as u32).to_le_bytes());
        body.extend_from_slice(&54u32.to_le_bytes());
        body.extend_from_slice(&cut);
        file.extend(ng_block(6, &body));
        let out = PcapParser
            .process(&evidence(file, "snap40.pcapng"))
            .expect("process");

        let c = of_type(&out, "NetworkCapture")[0];
        assert_eq!(c.metadata["refusals"]["transport_truncated"], 1);
        assert_eq!(c.metadata["truncated_packets"], 1);
        let flows = of_type(&out, "NetworkFlow");
        assert_eq!(flows.len(), 1, "{flows:?}");
        let f = flows[0];
        assert_eq!(f.metadata["protocol"], "tcp");
        assert_eq!(f.metadata["local_port"], Value::Null);
        assert_eq!(f.metadata["remote_port"], Value::Null);
        assert_eq!(f.metadata["tcp_state"], "no_transport_seen");
        assert_eq!(f.metadata["content_incomplete"], true);
        assert_eq!(f.metadata["content_incomplete_reason"], "short_read");
        assert_eq!(f.metadata["unattributed_packets"]["transport_truncated"], 1);
    }

    /// A UDP/53 payload with a self-pointing compression pointer does not
    /// decode. It was a port-53 message on the wire, and `dns_messages: 0`
    /// with nothing else is the same output as a capture that held no DNS.
    #[test]
    fn a_port_53_payload_that_does_not_decode_is_counted_as_undecodable_not_dropped() {
        let host = [10, 42, 85, 10];
        let dns = [10, 42, 85, 1];
        let mut payload = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        payload.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        let mut looped = ethernet_ipv4(host, dns, 17, (8 + payload.len()) as u16, 0x4000);
        looped.extend_from_slice(&4000u16.to_be_bytes());
        looped.extend_from_slice(&53u16.to_be_bytes());
        looped.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        looped.extend_from_slice(&[0, 0]);
        looped.extend_from_slice(&payload);
        // And one cut inside the DNS header: eight bytes of it survive.
        let mut short = ethernet_ipv4(host, dns, 17, 8 + 8, 0x4000);
        short.extend_from_slice(&4001u16.to_be_bytes());
        short.extend_from_slice(&53u16.to_be_bytes());
        short.extend_from_slice(&16u16.to_be_bytes());
        short.extend_from_slice(&[0, 0]);
        short.extend_from_slice(&[0x12, 0x35, 0x01, 0x00, 0, 1, 0, 0]);
        let file = one_flow_capture(&[looped, short]);
        let out = PcapParser
            .process(&evidence(file, "hostile-dns.pcapng"))
            .expect("process");

        let c = of_type(&out, "NetworkCapture")[0];
        assert_eq!(c.metadata["dns_messages"], 0);
        assert_eq!(c.metadata["dns_undecodable"], 1);
        assert_eq!(c.metadata["dns_header_short"], 1);
        assert_eq!(c.metadata["inventory_incomplete"], true);
        assert!(of_type(&out, "DnsResolution").is_empty());
        assert_eq!(of_type(&out, "NetworkFlow").len(), 2);
    }

    /// The reader is written not to panic; if it ever does, the artifact
    /// list must hold a refusal record and not be empty. The record itself
    /// is built by one function, tested here for each payload shape a panic
    /// can carry.
    #[test]
    fn the_panic_refusal_record_names_the_capture_and_carries_the_panic_message() {
        let case = uuid::Uuid::nil();
        let parent = uuid::Uuid::from_u128(9);
        let payloads: Vec<(Box<dyn std::any::Any + Send>, &str)> = vec![
            (Box::new("index out of range"), "index out of range"),
            (
                Box::new(String::from("attempt to add with overflow")),
                "attempt to add with overflow",
            ),
            (Box::new(42u32), "unknown panic"),
        ];
        for (payload, expected) in payloads {
            let r = panic_refusal_record(case, parent, "case001.pcap", payload.as_ref());
            assert_eq!(r.metadata["type"], "NetworkCaptureRefusal");
            assert_eq!(r.metadata["subtype"], "panic");
            assert_eq!(r.parent_id, Some(parent));
            let error = r.metadata["error"].as_str().unwrap();
            assert!(error.contains(expected), "{error}");
            assert!(error.contains("panicked"), "{error}");
            assert_eq!(r.metadata["content_incomplete"], true);
            assert_eq!(r.metadata["inventory_incomplete"], true);
            assert!(r.metadata["detail"]
                .as_str()
                .unwrap()
                .contains("case001.pcap"));
        }
    }

    /// The catch_unwind arm, driven through `process`: a reader that panics
    /// yields the refusal record, never an empty artifact list.
    #[test]
    fn a_reader_panic_yields_a_refusal_record_through_process_rather_than_an_empty_list() {
        let artifact = evidence(three_packet_capture(), "case001.pcap");
        PANIC_FOR_TEST.with(|p| p.set(true));
        let out = PcapParser.process(&artifact).expect("process");
        PANIC_FOR_TEST.with(|p| p.set(false));

        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].metadata["type"], "NetworkCaptureRefusal");
        assert_eq!(out[0].metadata["subtype"], "panic");
        assert!(out[0].metadata["error"]
            .as_str()
            .unwrap()
            .contains("injected"));
        assert_eq!(out[0].parent_id, Some(artifact.id));
    }

    #[test]
    fn the_source_name_comes_from_whichever_key_the_producer_used() {
        let named = |m: Value| {
            source_name(&Artifact::new(
                uuid::Uuid::nil(),
                ArtifactType::FileEntry,
                None,
                m,
            ))
        };
        assert_eq!(named(json!({ "name": "a.pcap" })), "a.pcap");
        assert_eq!(named(json!({ "file_name": "b.pcap" })), "b.pcap");
        assert_eq!(named(json!({ "source_path": "/e/c.pcap" })), "/e/c.pcap");
        assert_eq!(named(json!({ "name": "" })), "unnamed capture");
        assert_eq!(named(json!({})), "unnamed capture");
    }
}
