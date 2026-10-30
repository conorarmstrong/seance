//! Record emission: the flow table and capture metadata become artifacts.
//!
//! Four `ParsedRecord` types, each named by `metadata.type`, plus one
//! `TimelineEvent` per timed flow:
//!
//! * `NetworkCapture` — one per capture file. Always emitted, even for a
//!   capture with no IP traffic at all: a capture that produced nothing is
//!   what `HUNT-060` records, and "read, 4,000 packets, none carried IP" is
//!   a finding where silence is not.
//! * `NetworkFlow` — one per bidirectional conversation, with the key set
//!   the `NetworkFlow` viewer reads. Those keys are pinned by a frontend
//!   test; do not rename them here without renaming them there.
//! * `DnsResolution` — one per question in a DNS message on the wire. The
//!   only names this module ever attaches to an address are the ones the
//!   capture proves; nothing here consults the examination host's resolver.
//! * `NetworkCaptureRefusal` — a capture that was detected and then could
//!   not be read, or an interface whose LINKTYPE this build does not decode.
//!   Never an empty flow list in either case.
//!
//! # The honesty stamps
//!
//! Every stamp is the vocabulary the rest of the product already reads:
//! `content_incomplete` / `content_incomplete_reason` for "there was more
//! here than this record holds", `inventory_incomplete` for "there were more
//! records than were made". One record can carry both. The reason token is
//! chosen by what actually happened — the staging cap is `cap_reached`, a
//! snaplen cut is `short_read`, a header that did not verify is
//! `unresolved_structure` — because an examiner reads the token as where to
//! look next, and sending them to the snaplen for a checksum failure wastes
//! the afternoon.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::io::IncompleteReason;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::container::{CaptureFormat, CaptureMeta};
use crate::decode::{decode, Decode, DnsMessage, Refusal};
use crate::flows::{is_external, Endpoint, Flow, FlowTable};
use crate::MODULE_ID;

/// One DNS message seen on the wire, with the packet it came in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsObservation {
    pub message: DnsMessage,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub ts_micros: Option<u64>,
}

/// Everything the emission stage needs, gathered by the module's `process`.
#[derive(Debug)]
pub struct CaptureInput<'a> {
    pub case_id: Uuid,
    /// The capture artifact every record is parented to.
    pub parent_id: Uuid,
    pub source_name: &'a str,
    pub meta: &'a CaptureMeta,
    pub flows: &'a FlowTable,
    /// Every TCP conversation's reassembled bytes, keyed the way the flow
    /// table keys a conversation (`ROADMAP` §4.3 stage 2).
    pub streams: &'a [crate::reassemble::Stream],
    /// Whether the stream table's own cap fired, with the segments it could
    /// not hold. A capture with more conversations than the table holds is a
    /// tap, and the honest answer is the cap named on the record.
    pub stream_cap_reached: bool,
    pub segments_beyond_stream_cap: u64,
    /// The conversations a direction of which the stream table had no room
    /// for. Their flow records say their bytes were not read: without it, a
    /// refused conversation's record reads exactly like one that carried no
    /// bytes at all.
    pub refused_stream_flows: &'a std::collections::BTreeSet<crate::flows::FlowKey>,
    /// What the reassembly held between every stream, and whether its own
    /// budget stopped it.
    pub reassembly_bytes_held: u64,
    pub reassembly_budget_reached: bool,
    pub segments_beyond_reassembly_budget: u64,
    /// The HTTP read out of those streams (`ROADMAP` §4.3 stage 2), one entry
    /// per conversation that spoke it.
    pub http: &'a [crate::http::Conversation],
    /// The TLS read out of those streams, one entry per conversation that
    /// spoke it.
    pub tls: &'a [crate::tls::Session],
    /// Who claimed which address, and how many ARP frames this build could
    /// not read.
    pub arp: &'a crate::arp::ArpTable,
    pub arp_unreadable: u64,
    /// Packets the container handed up, before any decode.
    pub packets: u64,
    pub first_seen_micros: Option<u64>,
    pub last_seen_micros: Option<u64>,
    pub dns: &'a [DnsObservation],
    pub dns_cap: usize,
    pub dns_cap_reached: bool,
    /// UDP/53 payloads of at least a DNS header that did not decode: a
    /// pointer that does not go backwards, an A record that is not four
    /// bytes. Messages that were on the wire and are in no record.
    pub dns_undecodable: u64,
    /// UDP/53 payloads shorter than the twelve-byte DNS header: cut by the
    /// snaplen, or not DNS at all. Counted apart from the malformed case
    /// because the examiner's next step differs.
    pub dns_header_short: u64,
    /// What the source declared, what was staged, and the cap that bounds
    /// staging. Staged < declared is a prefix read, and the walk's
    /// `bytes_total` is the prefix's length, not the file's.
    pub bytes_declared: u64,
    pub bytes_staged: u64,
    pub staging_cap: u64,
}

/// Build every artifact for one capture: the capture record first, then a
/// refusal per undecodable interface, then flows (each with its timeline
/// event), then DNS. Every shortfall of the capture as a whole is stamped on
/// every flow and DNS record as well as on the capture record, because the
/// records page computes its banner from the records in front of it: a flow
/// list drawn from a prefix, or cut off at a cap, must say so on the flow
/// list, not on a record type the examiner has not opened.
pub fn emit(input: &CaptureInput<'_>) -> Vec<Artifact> {
    let mut out = Vec::with_capacity(
        input
            .flows
            .len()
            .saturating_mul(2)
            .saturating_add(input.dns.len())
            .saturating_add(1),
    );
    let shortfalls = capture_shortfalls(input);
    out.push(capture_record(input, &shortfalls));
    for (index, iface) in input.meta.interfaces.iter().enumerate() {
        if !linktype_supported(iface.linktype) {
            out.push(linktype_refusal_record(input, index, iface.linktype));
        }
    }
    // One index for every per-flow stream lookup below, for the reason
    // `http::conversations` builds one.
    let stream_index = crate::reassemble::index_streams(input.streams);
    let for_flows = shortfalls.stamps_for(Scope::reaches_flows);
    let for_dns = shortfalls.stamps_for(Scope::reaches_dns);
    for (slot, flow) in input.flows.flows().enumerate() {
        let refused_between_hosts = input.flows.refused_packets_between_hosts(slot);
        let mut record = flow_record(
            input.case_id,
            input.parent_id,
            flow,
            &refused_between_hosts,
            &stream_index,
            input.refused_stream_flows,
        );
        for_flows.apply(&mut record.metadata);
        out.push(record);
        if let Some(event) = flow_timeline_event(input.case_id, input.parent_id, flow) {
            out.push(event);
        }
    }
    for observation in input.dns {
        for mut record in dns_records(input.case_id, input.parent_id, observation) {
            for_dns.apply(&mut record.metadata);
            out.push(record);
        }
    }
    // HTTP, transaction by transaction, bounded by the same cap the capture
    // record reports. A body artifact inherits nothing from the capture: its
    // own stamps say what the body is short by, and a capture-wide sentence
    // on a file's record would read as a claim about the file.
    let for_streams = shortfalls.stamps_for(Scope::reaches_stream_derived);
    let totals = http_totals(input);
    let mut index = 0usize;
    // Every body this capture hands on, across every transaction, comes out
    // of one budget.
    let mut body_budget = crate::http::MAX_BODY_BYTES_PER_CAPTURE;
    for conversation in input.http {
        for transaction in &conversation.transactions {
            if index >= totals.emitted {
                break;
            }
            let mut records =
                http_records(input, conversation, transaction, index, &mut body_budget);
            if let Some(record) = records.first_mut() {
                for_streams.apply(&mut record.metadata);
            }
            out.extend(records);
            index += 1;
        }
    }
    // TLS, session by session. A certificate record and its timeline events
    // are children of their session, so the chain of custody reads capture,
    // then the conversation, then what the server presented on it.
    // ARP, address by address. A binding is inherited by nothing and inherits
    // nothing: it is a claim about the segment, not a record drawn from a
    // flow.
    let for_arp = shortfalls.stamps_for(Scope::reaches_arp);
    for binding in input.arp.bindings() {
        let mut records = arp_records(input, &binding);
        if let Some(record) = records.first_mut() {
            for_arp.apply(&mut record.metadata);
        }
        out.extend(records);
    }
    let tls = tls_totals(input);
    for (index, session) in input.tls.iter().take(tls.emitted).enumerate() {
        let mut records = tls_records(input, session, index);
        if let Some(record) = records.first_mut() {
            for_streams.apply(&mut record.metadata);
        }
        out.extend(records);
    }
    out
}

/// One reason a capture fell short of its file, and whether it is a fact
/// about the capture as a whole — one every record drawn from it inherits —
/// or one the records it touched already carry themselves.
struct Shortfall {
    reason: IncompleteReason,
    detail: String,
    scope: Scope,
}

/// Which records a capture-level shortfall is stamped onto, besides the
/// capture record itself. A DNS cap says the DNS list is short and nothing
/// about the flow list, so stamping every flow for it would mark a whole
/// inventory incomplete on the strength of a different inventory's cap — a
/// false statement about records that were counted in full.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Everything drawn from the capture: a prefix read, a stopped walk,
    /// packets the engine dropped.
    All,
    /// The flow list only.
    Flows,
    /// The DNS list only.
    Dns,
    /// The records read out of the reassembled streams only: the HTTP
    /// transactions and the TLS sessions.
    Streams,
    /// The ARP bindings only.
    Arp,
    /// The capture record alone: a framing fault that lost no packet.
    CaptureOnly,
}

impl Scope {
    fn reaches_flows(self) -> bool {
        matches!(self, Scope::All | Scope::Flows)
    }
    fn reaches_dns(self) -> bool {
        matches!(self, Scope::All | Scope::Dns)
    }
    /// What was read out of the reassembled streams: the HTTP and TLS
    /// records. The flow cap reaches them as well as the flow list, because a
    /// conversation the flow table could not hold was offered to no
    /// reassembler and so spoke nothing this run could read.
    fn reaches_stream_derived(self) -> bool {
        matches!(self, Scope::All | Scope::Flows | Scope::Streams)
    }

    /// The address claims. They are not drawn from a flow — ARP has no
    /// transport layer — but they ARE drawn from the same packet walk, so
    /// every capture-wide content shortfall reaches them: a binding built
    /// from the first third of a file must not read as the segment's whole
    /// ARP.
    fn reaches_arp(self) -> bool {
        matches!(self, Scope::All | Scope::Arp)
    }
}

/// Every reason the capture's content or inventory is short, in the order
/// an examiner should read them.
struct CaptureShortfalls {
    content: Vec<Shortfall>,
    inventory: Vec<Shortfall>,
}

/// The stamps a flow or DNS record inherits from its capture: one per kind,
/// each with the capture-level reason and a detail naming the cause.
struct CaptureWideStamps {
    content: Option<(IncompleteReason, String)>,
    inventory: Option<(IncompleteReason, String)>,
}

impl CaptureShortfalls {
    /// The stamps for one kind of record, from the shortfalls whose scope
    /// reaches it.
    fn stamps_for(&self, reaches: fn(Scope) -> bool) -> CaptureWideStamps {
        let summarise = |list: &[Shortfall]| -> Option<(IncompleteReason, String)> {
            let wide: Vec<&Shortfall> = list.iter().filter(|s| reaches(s.scope)).collect();
            let first = wide.first()?;
            let details: Vec<&str> = wide.iter().map(|s| s.detail.as_str()).collect();
            Some((
                first.reason,
                format!(
                    "the capture this record was drawn from is incomplete: {}",
                    details.join("; ")
                ),
            ))
        };
        CaptureWideStamps {
            content: summarise(&self.content),
            inventory: summarise(&self.inventory),
        }
    }
}

impl CaptureWideStamps {
    /// Stamp one record. A record that is already short in its own right
    /// keeps its own reason — the more specific place to look — and the
    /// capture's sentence is appended to its detail, so neither fact
    /// overwrites the other.
    fn apply(&self, m: &mut Value) {
        for (kind, stamp_for) in [
            ("content_incomplete", &self.content),
            ("inventory_incomplete", &self.inventory),
        ] {
            let Some((reason, detail)) = stamp_for else {
                continue;
            };
            stamp_or_extend(m, kind, *reason, detail);
        }
    }
}

/// Every reason the content or the inventory falls short of the file, and
/// which of them every record inherits. Content first: the staging cap
/// bounds everything after it, then the walk, then what the capture engine
/// admitted, then the snaplen, then packets the walk saw and could not hand
/// up, then the file's own framing checks that failed. The snaplen is the one
/// reason the flows already carry themselves; everything else describes the
/// capture as a whole.
fn capture_shortfalls(input: &CaptureInput<'_>) -> CaptureShortfalls {
    let meta = input.meta;
    let flows = input.flows;
    let mut content: Vec<Shortfall> = Vec::new();
    let mut note = |reason: IncompleteReason, detail: String, scope: Scope| {
        content.push(Shortfall {
            reason,
            detail,
            scope,
        });
    };

    // What the read should have returned is the smaller of the file and the
    // cap. Fewer than that is the medium failing, which is a different place
    // to look from the cap — even when the cap would have bounded the read
    // anyway, and then both are said.
    let expected_staged = input.bytes_declared.min(input.staging_cap);
    if input.bytes_staged < expected_staged {
        let cap_note = if input.bytes_declared > input.staging_cap {
            format!(
                "; the staging cap of {} bytes would have bounded the read in any case",
                input.staging_cap
            )
        } else {
            String::new()
        };
        note(
            IncompleteReason::ShortRead,
            format!(
                "the source declared {} bytes and {} could be read; every count below is of \
                 that prefix{cap_note}",
                input.bytes_declared, input.bytes_staged
            ),
            Scope::All,
        );
    } else if input.bytes_staged < input.bytes_declared {
        note(
            IncompleteReason::CapReached,
            format!(
                "the source is {} bytes and the staging cap is {} bytes, so only the first {} \
                 bytes were read; every count below is of that prefix",
                input.bytes_declared, input.staging_cap, input.bytes_staged
            ),
            Scope::All,
        );
    }
    if let Some(stop) = meta.stopped {
        note(
            IncompleteReason::ShortRead,
            format!(
                "the walk stopped at byte {} of {} ({}); the {} bytes after it were not read",
                stop.at(),
                input.bytes_staged,
                stop.reason(),
                input.bytes_staged.saturating_sub(stop.at())
            ),
            Scope::All,
        );
    }
    if meta.reported_drops > 0 || meta.reported_os_drops > 0 {
        note(
            IncompleteReason::ShortRead,
            format!(
                "the capture engine itself reported dropping {} packets at the interface and {} \
                 in the operating system before they were written; they are not in this file",
                meta.reported_drops, meta.reported_os_drops
            ),
            Scope::All,
        );
    }
    let truncated_packets = flows
        .flows()
        .fold(0u64, |acc, f| acc.saturating_add(f.truncated_packets));
    if truncated_packets > 0 {
        note(
            IncompleteReason::ShortRead,
            format!(
                "{truncated_packets} packets were captured short of their wire length (snaplen); \
                 flow byte counts are of the bytes held, not the bytes sent"
            ),
            Scope::CaptureOnly,
        );
    }
    if meta.packets_on_undeclared_interface > 0 {
        note(
            IncompleteReason::UnresolvedStructure,
            format!(
                "{} packet blocks named an interface no IDB declared; those packets are in the \
                 file and in no flow",
                meta.packets_on_undeclared_interface
            ),
            Scope::All,
        );
    }
    if meta.packet_blocks_short > 0 {
        note(
            IncompleteReason::UnresolvedStructure,
            format!(
                "{} packet blocks were shorter than their own fixed fields; those packets are \
                 in the file and in no flow",
                meta.packet_blocks_short
            ),
            Scope::All,
        );
    }
    let without_addresses = flows.packets_refused_without_addresses();
    if without_addresses > 0 {
        // These reached no flow, so no per-flow count holds them; the
        // reasons are listed here because this record is the only one that
        // can say what they were.
        let reasons: Vec<String> = flows
            .refusals()
            .iter()
            .filter(|(reason, _)| !Refusal::reason_carries_addresses(reason))
            .map(|(reason, n)| format!("{n} {reason}"))
            .collect();
        note(
            IncompleteReason::UnresolvedStructure,
            format!(
                "{without_addresses} packets were refused before their addresses could be read \
                 ({}) and are in no flow",
                reasons.join(", ")
            ),
            Scope::All,
        );
    }
    if meta.unreadable_statistics > 0 {
        note(
            IncompleteReason::UnresolvedStructure,
            format!(
                "{} interface statistics counters were stated and could not be read; the \
                 capture engine may have attested a loss this record does not show",
                meta.unreadable_statistics
            ),
            Scope::All,
        );
    }
    if meta.over_claimed_packets > 0 {
        note(
            IncompleteReason::UnresolvedStructure,
            format!(
                "{} packet blocks declared more captured bytes than the block held; the bytes \
                 held were read and the difference is damage or forgery, not snaplen",
                meta.over_claimed_packets
            ),
            Scope::All,
        );
    }
    if meta.mismatched_block_trailers > 0 {
        note(
            IncompleteReason::UnresolvedStructure,
            format!(
                "{} blocks carried a trailing length that disagreed with the leading one; a \
                 reader walking backwards would see a different packet stream",
                meta.mismatched_block_trailers
            ),
            Scope::CaptureOnly,
        );
    }
    if meta.truncated_options > 0 {
        note(
            IncompleteReason::UnresolvedStructure,
            format!(
                "{} option lists ended inside an option; the cut option was not read, and \
                 where it was if_tsresol the default resolution stands in for it",
                meta.truncated_options
            ),
            Scope::All,
        );
    }

    let mut inventory: Vec<Shortfall> = Vec::new();
    if flows.cap_reached() {
        inventory.push(Shortfall {
            reason: IncompleteReason::CapReached,
            detail: format!(
                "the flow cap of {} flows was reached; {} packets belonged to flows that are \
                 not listed",
                flows.cap(),
                flows.packets_past_cap()
            ),
            scope: Scope::Flows,
        });
    }
    if input.reassembly_budget_reached {
        inventory.push(Shortfall {
            reason: IncompleteReason::CapReached,
            detail: format!(
                "this build's budget for assembling every TCP stream in a capture between them \
                 ({} bytes) was exhausted, and {} segment(s) arrived with none of it left; the \
                 streams cut by it say where, and what an application-layer parser was offered \
                 stops there",
                crate::reassemble::MAX_TOTAL_BYTES,
                input.segments_beyond_reassembly_budget
            ),
            scope: Scope::Flows,
        });
    }
    if input.dns_cap_reached {
        inventory.push(Shortfall {
            reason: IncompleteReason::CapReached,
            detail: format!(
                "the DNS cap of {} messages was reached; later DNS messages are not listed",
                input.dns_cap
            ),
            scope: Scope::Dns,
        });
    }
    if input.dns_undecodable > 0 {
        inventory.push(Shortfall {
            reason: IncompleteReason::UnresolvedStructure,
            detail: format!(
                "{} port-53 payloads were present and did not decode as DNS (a layout the \
                 decoder refused to guess at); they are counted on their flows and in no DNS \
                 record",
                input.dns_undecodable
            ),
            scope: Scope::Dns,
        });
    }
    if input.dns_header_short > 0 {
        inventory.push(Shortfall {
            reason: IncompleteReason::ShortRead,
            detail: format!(
                "{} port-53 payloads were cut inside the DNS header (snaplen) and are in no DNS \
                 record",
                input.dns_header_short
            ),
            scope: Scope::Dns,
        });
    }
    let http = http_totals(input);
    if http.transactions_beyond_cap > 0 {
        inventory.push(Shortfall {
            reason: IncompleteReason::CapReached,
            detail: format!(
                "the HTTP transaction cap of {} was reached; {} further transaction(s) were \
                 read out of the streams and no record was written for them",
                crate::http::MAX_TRANSACTIONS_PER_CAPTURE,
                http.transactions_beyond_cap
            ),
            scope: Scope::Streams,
        });
    }
    let tls = tls_totals(input);
    if tls.sessions_beyond_cap > 0 {
        inventory.push(Shortfall {
            reason: IncompleteReason::CapReached,
            detail: format!(
                "the TLS session cap of {} was reached; {} further session(s) were read out of \
                 the streams and no record was written for them",
                crate::tls::MAX_SESSIONS_PER_CAPTURE,
                tls.sessions_beyond_cap
            ),
            scope: Scope::Streams,
        });
    }
    if input.stream_cap_reached {
        inventory.push(Shortfall {
            reason: IncompleteReason::CapReached,
            detail: format!(
                "the TCP stream cap of {} was reached and {} segment(s) belonged to streams the \
                 table could not hold; those conversations' contents were not read at all",
                crate::reassemble::MAX_STREAMS,
                input.segments_beyond_stream_cap
            ),
            scope: Scope::Streams,
        });
    }
    if input.arp.addresses_beyond_cap > 0 {
        inventory.push(Shortfall {
            reason: IncompleteReason::CapReached,
            detail: format!(
                "the ARP address cap of {} was reached; {} claim(s) on further addresses were \
                 seen and are in no binding record",
                crate::arp::MAX_ADDRESSES,
                input.arp.addresses_beyond_cap
            ),
            scope: Scope::Arp,
        });
    }
    if input.arp.addresses_asked_about_beyond_cap > 0 {
        inventory.push(Shortfall {
            reason: IncompleteReason::CapReached,
            detail: format!(
                "{} address(es) that were asked about are past this build's ceiling of {} and \
                 are not listed",
                input.arp.addresses_asked_about_beyond_cap,
                crate::arp::MAX_ADDRESSES_ASKED_ABOUT
            ),
            scope: Scope::Arp,
        });
    }
    if http.bodies_cut_by_the_capture_budget > 0 {
        inventory.push(Shortfall {
            reason: IncompleteReason::CapReached,
            detail: format!(
                "this build's budget for the message bodies of one capture ({} bytes across \
                 every body) was exhausted, and {} body artifact(s) hold a prefix because of \
                 it; each says so on its own record",
                crate::http::MAX_BODY_BYTES_PER_CAPTURE,
                http.bodies_cut_by_the_capture_budget
            ),
            scope: Scope::Streams,
        });
    }
    if http.http2_conversations > 0 {
        inventory.push(Shortfall {
            reason: IncompleteReason::Unmapped,
            detail: format!(
                "{} conversation(s) in this capture speak HTTP/2, which this build does not \
                 read: they begin with HTTP/2's connection preface and no HttpTransaction \
                 record was written for any of them. HTTP/2 is most of the web, so an HTTP \
                 list that is short of a capture's real traffic is short by these",
                http.http2_conversations
            ),
            scope: Scope::Streams,
        });
    }
    if input.arp_unreadable > 0 {
        inventory.push(Shortfall {
            reason: IncompleteReason::Unmapped,
            detail: format!(
                "{} ARP frame(s) were present and are not read by this build (a hardware or \
                 protocol type that is not Ethernet and IPv4, or a frame cut inside the \
                 packet); whatever they claimed is in the capture and in no binding",
                input.arp_unreadable
            ),
            scope: Scope::Arp,
        });
    }
    if meta.cap_reached_interfaces || meta.cap_reached_sections {
        inventory.push(Shortfall {
            reason: IncompleteReason::CapReached,
            detail: "the interface or section table cap was reached; later interfaces or \
                     sections are not listed"
                .to_string(),
            scope: Scope::All,
        });
    }
    CaptureShortfalls { content, inventory }
}

/// Whether the decoder handles this LINKTYPE, asked of the decoder itself so
/// the answer cannot drift from what `decode` does.
fn linktype_supported(linktype: u16) -> bool {
    !matches!(
        decode(linktype, &[]),
        Decode::Refused(Refusal::UnsupportedLinktype(_))
    )
}

fn format_label(format: CaptureFormat) -> &'static str {
    match format {
        CaptureFormat::PcapMicro => "pcap",
        CaptureFormat::PcapNano => "pcap-ns",
        CaptureFormat::PcapNg => "pcapng",
    }
}

/// The `NetworkCapture` record and its stamps.
fn capture_record(input: &CaptureInput<'_>, shortfalls: &CaptureShortfalls) -> Artifact {
    let meta = input.meta;
    let flows = input.flows;
    let http = http_totals(input);
    let tls = tls_totals(input);

    let truncated_packets = flows
        .flows()
        .fold(0u64, |acc, f| acc.saturating_add(f.truncated_packets));

    let interfaces: Vec<Value> = meta
        .interfaces
        .iter()
        .enumerate()
        .map(|(i, iface)| {
            json!({
                "index": i,
                "linktype": iface.linktype,
                "linktype_supported": linktype_supported(iface.linktype),
                "snaplen": iface.snaplen,
                "name": iface.name,
                "ts_resol": format!("{:?}", iface.ts_resol),
            })
        })
        .collect();
    let sections: Vec<Value> = meta
        .sections
        .iter()
        .map(|s| {
            json!({
                "os": s.os,
                "hardware": s.hardware,
                "application": s.application,
            })
        })
        .collect();
    let interface_statistics: Vec<Value> = meta
        .interface_statistics
        .iter()
        .map(|(index, stats)| {
            json!({
                "interface": index,
                "received": stats.if_received,
                "dropped": stats.if_drops,
                "os_dropped": stats.os_drops,
            })
        })
        .collect();
    let unknown_block_types: Map<String, Value> = meta
        .unknown_block_types
        .iter()
        .map(|(k, v)| (k.to_string(), json!(v)))
        .collect();
    let refusals: Map<String, Value> = flows
        .refusals()
        .iter()
        .map(|(k, v)| ((*k).to_string(), json!(v)))
        .collect();
    let unsupported_linktypes: Map<String, Value> = flows
        .unsupported_linktypes()
        .iter()
        .map(|(k, v)| (k.to_string(), json!(v)))
        .collect();

    let format = format_label(meta.format);
    let short_desc = format!(
        "{format} capture, {} packets, {} flows, {} interfaces",
        input.packets,
        flows.len(),
        meta.interfaces.len()
    );

    // Three groups, merged: the `json!` macro is recursive per key and the
    // capture record has more keys than it expands in one literal.
    let identity = json!({
        "type": "NetworkCapture",
        "name": format!("{}: {short_desc}", input.source_name),
        "short_desc": short_desc,
        "source_name": input.source_name,
        "format": format,
        "version": format!("{}.{}", meta.major, meta.minor),
        "little_endian": meta.little_endian,
        "interface_count": meta.interfaces.len(),
        "interfaces": interfaces,
        "linktypes": meta.interfaces.iter().map(|i| i.linktype).collect::<Vec<_>>(),
        "snaplens": meta.interfaces.iter().map(|i| i.snaplen).collect::<Vec<_>>(),
        "cap_reached_interfaces": meta.cap_reached_interfaces,
        "sections": sections,
        "cap_reached_sections": meta.cap_reached_sections,
        "first_seen": input.first_seen_micros.map(rfc3339_micros),
        "last_seen": input.last_seen_micros.map(rfc3339_micros),
    });
    let counts = json!({
        "packets": input.packets,
        "packets_in_flows": flows.packets_in_flows(),
        "packets_refused": flows.packets_refused(),
        "packets_refused_without_addresses": flows.packets_refused_without_addresses(),
        "packets_no_network_layer": flows.packets_no_network_layer(),
        "packets_past_flow_cap": flows.packets_past_cap(),
        "packets_on_undeclared_interface": meta.packets_on_undeclared_interface,
        "packet_blocks_short": meta.packet_blocks_short,
        "packets_without_timestamp": meta.packets_without_timestamp,
        "packets_with_unresolvable_timestamp": meta.packets_with_unresolvable_timestamp,
        "truncated_packets": truncated_packets,
        "flow_count": flows.len(),
        "flow_cap": flows.cap(),
        "flow_cap_reached": flows.cap_reached(),
        "tcp_streams": input.streams.len(),
        "tcp_streams_with_gaps": input
            .streams
            .iter()
            .filter(|s| !s.holes().is_empty())
            .count(),
        "tcp_streams_with_conflicts": input
            .streams
            .iter()
            .filter(|s| !s.conflicts.is_empty())
            .count(),
        "tcp_streams_without_handshake": input
            .streams
            .iter()
            .filter(|s| !s.base_from_syn)
            .count(),
        "tcp_stream_cap": crate::reassemble::MAX_STREAMS,
        "tcp_reassembly_bytes_held": input.reassembly_bytes_held,
        "tcp_reassembly_budget": crate::reassemble::MAX_TOTAL_BYTES,
        "tcp_reassembly_budget_reached": input.reassembly_budget_reached,
        "segments_beyond_tcp_reassembly_budget": input.segments_beyond_reassembly_budget,
        "tcp_stream_cap_reached": input.stream_cap_reached,
        "segments_beyond_tcp_stream_cap": input.segments_beyond_stream_cap,
        "tcp_streams_meaning":
            "One stream per direction of each TCP conversation, reassembled from the segments \
             this capture holds. A stream WITHOUT A HANDSHAKE begins at the first byte the \
             capture saw rather than at the connection's first byte, so what came before it is \
             missing and its size is not knowable. A stream WITH A GAP is missing bytes whose \
             size IS knowable, and only the bytes before the first gap may be read as a \
             continuous message. A stream WITH A CONFLICT had two segments claim the same \
             offsets with different bytes: the first are held, and that is how a sensor is \
             evaded.",
        "dns_messages": input.dns.len(),
        "dns_cap": input.dns_cap,
        "dns_cap_reached": input.dns_cap_reached,
        "dns_undecodable": input.dns_undecodable,
        "dns_header_short": input.dns_header_short,
        "refusals": refusals,
        "unsupported_linktypes": unsupported_linktypes,
    });
    // The application protocols read out of the reassembled streams, in
    // their own object: one `json!` holding every count on this record
    // exceeds the macro's recursion limit, and these two belong together.
    let arp = input.arp;
    let arp_bindings = arp.bindings();
    let protocols = json!({
        "arp_frames": arp.frames,
        "arp_unreadable_frames": input.arp_unreadable,
        "arp_addresses": arp_bindings.len(),
        "arp_addresses_contested": arp_bindings.iter()
            .filter(|b| b.contested()).count(),
        "arp_hardware_addresses": arp.hardware_addresses(),
        "arp_requests": arp.requests,
        "arp_replies": arp.replies,
        "arp_other_operations": arp.other_operations,
        "arp_gratuitous_replies": arp.gratuitous,
        "arp_probes": arp.probes,
        "arp_frame_source_disagreements": arp.frame_source_disagreements,
        "arp_addresses_asked_about": arp.addresses_asked_about.iter().map(ToString::to_string)
            .collect::<Vec<_>>(),
        "arp_address_cap": crate::arp::MAX_ADDRESSES,
        "arp_addresses_beyond_cap": arp.addresses_beyond_cap,
        "arp_addresses_asked_about_beyond_cap": arp.addresses_asked_about_beyond_cap,
        "arp_meaning": ARP_MEANING,
        "http_conversations": http.conversations,
        "http_transactions": http.transactions,
        "http_transaction_cap": crate::http::MAX_TRANSACTIONS_PER_CAPTURE,
        "http_transaction_cap_reached": http.transactions_beyond_cap > 0,
        "http_transactions_beyond_cap": http.transactions_beyond_cap,
        "http_transactions_incomplete": http.incomplete,
        "http_transactions_paired_over_a_gap": http.paired_over_a_gap,
        "http_transactions_paired_from_an_incomplete_start": http.paired_from_an_incomplete_start,
        "http_requests_unanswered": http.unanswered,
        "http_responses_unmatched": http.unmatched,
        "http_bodies": http.bodies,
        "http_body_bytes_held": http.body_bytes,
        "http_body_budget": crate::http::MAX_BODY_BYTES_PER_CAPTURE,
        "http_body_inflate_ceiling": crate::http::MAX_DECODED_BODY_BYTES,
        "http_body_wire_ceiling": crate::http::MAX_BODY_BYTES,
        "http_bodies_cut_by_the_body_budget": http.bodies_cut_by_the_capture_budget,
        "http2_conversations_not_read": http.http2_conversations,
        "http_meaning": HTTP_MEANING,
    });
    let protocols_tls = json!({
        "tls_sessions": tls.sessions,
        "tls_session_cap": crate::tls::MAX_SESSIONS_PER_CAPTURE,
        "tls_session_cap_reached": tls.sessions_beyond_cap > 0,
        "tls_sessions_beyond_cap": tls.sessions_beyond_cap,
        "tls_server_names": tls.server_names,
        "tls_certificates": tls.certificates,
        "tls_self_signed_certificates": tls.self_signed,
        "tls_unparsable_certificates": tls.unparsable_certificates,
        "tls_sessions_without_a_certificate": tls.without_a_certificate,
        "tls_certificates_encrypted_by_tls13": tls.encrypted_by_tls13,
        "tls_sessions_with_a_known_weak_cipher": tls.weak_ciphers,
        "tls_sessions_incomplete": tls.incomplete,
        "tls_meaning": TLS_MEANING,
    });
    let walk = json!({
        "interface_statistics": interface_statistics,
        "reported_drops": meta.reported_drops,
        "reported_os_drops": meta.reported_os_drops,
        "unreadable_statistics": meta.unreadable_statistics,
        "unknown_block_types": unknown_block_types,
        "cap_reached_unknown_block_types": meta.cap_reached_unknown_block_types,
        "unknown_blocks_past_type_cap": meta.unknown_blocks_past_type_cap,
        "over_claimed_packets": meta.over_claimed_packets,
        "mismatched_block_trailers": meta.mismatched_block_trailers,
        "truncated_options": meta.truncated_options,
        "stopped": meta.stopped.map(|s| json!({ "reason": s.reason(), "at": s.at() })),
        "bytes_read": meta.bytes_read,
        "bytes_total": input.bytes_staged,
        "bytes_declared": input.bytes_declared,
        "bytes_staged": input.bytes_staged,
        "staging_cap_bytes": input.staging_cap,
    });
    let mut m = merge([identity, counts, protocols, protocols_tls, walk]);
    for (kind, list) in [
        ("content_incomplete", &shortfalls.content),
        ("inventory_incomplete", &shortfalls.inventory),
    ] {
        if let Some(first) = list.first() {
            let details: Vec<&str> = list.iter().map(|s| s.detail.as_str()).collect();
            stamp(&mut m, kind, first.reason, &details.join("; "));
        }
    }
    Artifact::new(input.case_id, ArtifactType::ParsedRecord, None, m).with_parent(input.parent_id)
}

/// Concatenate object literals into one object, in order.
fn merge<const N: usize>(parts: [Value; N]) -> Value {
    let mut out = Map::new();
    for part in parts {
        if let Value::Object(obj) = part {
            out.extend(obj);
        }
    }
    Value::Object(out)
}

/// Write one stamp family: `<kind>`, `<kind>_reason`, `<kind>_detail`.
fn stamp(m: &mut Value, kind: &str, reason: IncompleteReason, detail: &str) {
    if let Some(obj) = m.as_object_mut() {
        obj.insert(kind.to_string(), json!(true));
        obj.insert(format!("{kind}_reason"), json!(reason.as_str()));
        obj.insert(format!("{kind}_detail"), json!(detail));
    }
}

/// Add a stamp to a record that may already carry one of the same kind. The
/// existing reason stands — it is the record's own, more specific one — and
/// the new detail is appended so both facts are on the record.
fn stamp_or_extend(m: &mut Value, kind: &str, reason: IncompleteReason, detail: &str) {
    let existing = m
        .get(format!("{kind}_detail"))
        .and_then(Value::as_str)
        .map(str::to_string);
    match existing {
        Some(prior) if m.get(kind) == Some(&Value::Bool(true)) => {
            if let Some(obj) = m.as_object_mut() {
                obj.insert(
                    format!("{kind}_detail"),
                    json!(format!("{prior}; {detail}")),
                );
            }
        }
        _ => stamp(m, kind, reason, detail),
    }
}

/// A `NetworkCaptureRefusal` for an interface whose LINKTYPE is not decoded.
/// The packet count is by linktype, not by interface, because the flow
/// table counts refusals by the number the decoder saw; two interfaces with
/// the same unsupported linktype share the figure, and the key says so.
fn linktype_refusal_record(input: &CaptureInput<'_>, index: usize, linktype: u16) -> Artifact {
    let packets = input
        .flows
        .unsupported_linktypes()
        .get(&linktype)
        .copied()
        .unwrap_or(0);
    let detail = format!(
        "interface {index} of '{}' has LINKTYPE {linktype}, which this build does not decode; \
         {packets} packets with that linktype were counted and are in no flow. This is a \
         missing decoder, not an absence of traffic.",
        input.source_name
    );
    let m = json!({
        "type": "NetworkCaptureRefusal",
        "subtype": "unsupported_linktype",
        "name": format!("{}: interface {index} LINKTYPE {linktype} not decoded", input.source_name),
        "short_desc": format!("LINKTYPE {linktype} not decoded ({packets} packets)"),
        "source_name": input.source_name,
        "interface": index,
        "linktype": linktype,
        "packets_refused_with_linktype": packets,
        "detail": detail,
        "content_incomplete": true,
        "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
        "content_incomplete_detail": detail,
    });
    Artifact::new(input.case_id, ArtifactType::ParsedRecord, None, m)
        .with_parent(input.parent_id)
        .with_subtype("unsupported_linktype")
}

/// A `NetworkCaptureRefusal` for a capture that was detected and then could
/// not be read at all. HUNT-054's rule: a file detection routed here and
/// the reader refused must leave a record, or "unreadable" and "held no
/// traffic" render identically.
pub fn refusal_record(
    case_id: Uuid,
    parent_id: Uuid,
    source_name: &str,
    subtype: &str,
    error: &str,
) -> Artifact {
    let detail = format!(
        "'{source_name}' was detected as a network capture but could not be read: {error}. No \
         flow, address or name from it is in the case, so its silence is not evidence of absence."
    );
    let m = json!({
        "type": "NetworkCaptureRefusal",
        "subtype": subtype,
        "name": format!("{source_name}: capture not read — {error}"),
        "short_desc": format!("capture not read: {error}"),
        "source_name": source_name,
        "error": error,
        "detail": detail,
        "content_incomplete": true,
        "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
        "content_incomplete_detail": detail,
        "inventory_incomplete": true,
        "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
        "inventory_incomplete_detail": detail,
    });
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, m)
        .with_parent(parent_id)
        .with_subtype(subtype)
}

/// The viewer's protocol token: the common transports by name, everything
/// else by number, and `null` when the transport was never read.
pub fn protocol_label(protocol: Option<u8>) -> Value {
    match protocol {
        None => Value::Null,
        Some(6) => Value::from("tcp"),
        Some(17) => Value::from("udp"),
        Some(1) => Value::from("icmp"),
        Some(58) => Value::from("icmpv6"),
        Some(n) => Value::from(format!("ip-{n}")),
    }
}

/// `host:port`, with an IPv6 host bracketed so the port is not one more
/// hextet; a bare host when there is no port.
pub fn endpoint_label(e: Endpoint) -> String {
    match (e.ip, e.port) {
        (IpAddr::V6(ip), Some(port)) => format!("[{ip}]:{port}"),
        (ip, Some(port)) => format!("{ip}:{port}"),
        (ip, None) => ip.to_string(),
    }
}

/// The one-line description shared by the flow record and its timeline
/// event: protocol, local, remote.
fn flow_short_desc(flow: &Flow, local: Endpoint, remote: Endpoint) -> String {
    let protocol = match protocol_label(flow.protocol) {
        Value::String(s) => s,
        _ => "ip".to_string(),
    };
    format!(
        "{protocol} {} -> {}",
        endpoint_label(local),
        endpoint_label(remote)
    )
}

/// The `NetworkFlow` record. `out` and `in` are relative to the local
/// endpoint, which is not always the initiator. `refused_between_hosts` is
/// what sits on IP-pair flows between the same two hosts: packets that may be
/// this conversation's other half, refused before a port could be read.
fn flow_record(
    case_id: Uuid,
    parent_id: Uuid,
    flow: &Flow,
    refused_between_hosts: &BTreeMap<&'static str, u64>,
    streams: &BTreeMap<crate::reassemble::StreamKey, &crate::reassemble::Stream>,
    refused_stream_flows: &std::collections::BTreeSet<crate::flows::FlowKey>,
) -> Artifact {
    let (local, remote, local_chosen_by) = flow.local_and_remote_by();
    let local_is_initiator = local == flow.initiator;
    let (packets_out, bytes_out, packets_in, bytes_in) = if local_is_initiator {
        (
            flow.packets_out,
            flow.bytes_out,
            flow.packets_in,
            flow.bytes_in,
        )
    } else {
        (
            flow.packets_in,
            flow.bytes_in,
            flow.packets_out,
            flow.bytes_out,
        )
    };
    let short_desc = flow_short_desc(flow, local, remote);
    let unattributed: Map<String, Value> = flow
        .unattributed_packets
        .iter()
        .map(|(k, v)| ((*k).to_string(), json!(v)))
        .collect();
    let refused_between_hosts_total = refused_between_hosts
        .values()
        .fold(0u64, |acc, n| acc.saturating_add(*n));
    let refused_between_hosts_by_reason: Map<String, Value> = refused_between_hosts
        .iter()
        .map(|(k, v)| ((*k).to_string(), json!(v)))
        .collect();

    // The reassembled bytes for this conversation, if it is TCP and the table
    // held it. Named by which endpoint sent them rather than by the flow's
    // initiator: `local` and `remote` are what the rest of this record uses,
    // and a stream labelled the other way round would invert every row an
    // examiner reads.
    let key = crate::flows::FlowKey::new(flow.protocol, flow.initiator, flow.responder);
    let stream_for =
        |direction: crate::flows::Direction| crate::reassemble::stream_of(streams, key, direction);
    let (local_stream, remote_stream) = if local_is_initiator {
        (
            stream_for(crate::flows::Direction::Out),
            stream_for(crate::flows::Direction::In),
        )
    } else {
        (
            stream_for(crate::flows::Direction::In),
            stream_for(crate::flows::Direction::Out),
        )
    };
    let tcp_streams = (local_stream.is_some() || remote_stream.is_some()).then(|| {
        json!({
            "local_to_remote": local_stream.map(|s| s.to_json()),
            "remote_to_local": remote_stream.map(|s| s.to_json()),
            "statement":
                "The bytes each endpoint sent, reassembled from the segments this capture \
                 holds. A gap is reported and never closed: `holes` names what is missing, and \
                 only the bytes before the first hole may be read as a continuous message. \
                 Where two segments claimed the same offsets with different bytes, the first \
                 are held and the disagreement is in `conflicts` -- that is how a sensor is \
                 evaded, so it is reported rather than resolved.",
        })
    });

    let mut m = json!({
        "type": "NetworkFlow",
        "name": format!("{short_desc} ({} packets)", flow.packets()),
        "short_desc": short_desc,
        "protocol": protocol_label(flow.protocol),
        "protocol_number": flow.protocol,
        "local_ip": local.ip.to_string(),
        "local_port": local.port,
        "remote_ip": remote.ip.to_string(),
        "remote_port": remote.port,
        "remote_is_external": is_external(remote.ip),
        "local_chosen_by": local_chosen_by.as_str(),
        "local_is_initiator": local_is_initiator,
        "packets_out": packets_out,
        "bytes_out": bytes_out,
        "packets_in": packets_in,
        "bytes_in": bytes_in,
        "packets": flow.packets(),
        "bytes": flow.bytes(),
        "wire_bytes": flow.wire_bytes(),
        "first_seen": flow.first_seen_micros.map(rfc3339_micros),
        "last_seen": flow.last_seen_micros.map(rfc3339_micros),
        "duration_seconds": flow.duration_micros().map(|d| d as f64 / 1_000_000.0),
        "packets_without_timestamp": flow.packets_without_timestamp,
        "timestamped_packets": flow.timestamped_packets(),
        "tcp_state": flow.tcp_state().map(|s| s.as_str()),
        "truncated_packets": flow.truncated_packets,
        "checksum_unset_packets": flow.checksum_unset_packets,
        "unattributed_packets": unattributed,
        "unattributed_packets_total": flow.unattributed_packets_total(),
        "refused_packets_between_hosts": refused_between_hosts_total,
        "refused_packets_between_hosts_by_reason": refused_between_hosts_by_reason,
    });
    if let Some(streams) = tcp_streams {
        if let Some(object) = m.as_object_mut() {
            object.insert("tcp_streams".into(), streams);
        }
    }
    // A conversation the stream table had no room for. Without this its
    // record reads like one that carried no bytes: no streams, and no reason.
    //
    // The table refuses a direction, not a conversation: it can fill between a
    // conversation's two directions, and then one stream is held and read —
    // its request parsed, its ClientHello a `TlsSession` — while the other is
    // not. The table never gives a stream back, so a direction that was held
    // was never refused, and in a refused conversation a direction without a
    // stream is the one refused (or one that sent nothing that opens a stream,
    // which the table cannot tell apart once it has refused the conversation).
    let refused_by_stream_table = refused_stream_flows.contains(&key);
    let directions_not_read: Vec<(&str, &str)> = if refused_by_stream_table {
        [
            ("local_to_remote", "local to remote", local_stream.is_none()),
            (
                "remote_to_local",
                "remote to local",
                remote_stream.is_none(),
            ),
        ]
        .into_iter()
        .filter(|(_, _, absent)| *absent)
        .map(|(field, label, _)| (field, label))
        .collect()
    } else {
        Vec::new()
    };
    if refused_by_stream_table {
        if let Some(object) = m.as_object_mut() {
            object.insert("tcp_streams_not_read".into(), json!(true));
            object.insert(
                "tcp_directions_not_read".into(),
                json!(directions_not_read
                    .iter()
                    .map(|(field, _)| *field)
                    .collect::<Vec<_>>()),
            );
        }
    }

    // Every reason this record is short of the conversation, in the order an
    // examiner should read them. A snaplen cut, or a transport header the
    // frame ended before, is a short read. Anything else the decoder refused
    // after the addresses — a checksum that did not verify, a fragment whose
    // header is elsewhere, a datagram too short for what it claims — was
    // fully captured and not resolved, which is a different place to look.
    // The first reason is the stamp's; every detail is kept.
    let mut shortfalls: Vec<(IncompleteReason, String)> = Vec::new();
    if refused_by_stream_table {
        let ceiling = crate::reassemble::MAX_STREAMS;
        let detail = match directions_not_read.as_slice() {
            [(_, refused)] => {
                let held = if *refused == "local to remote" {
                    "remote to local"
                } else {
                    "local to remote"
                };
                format!(
                    "the {refused} direction's bytes were not reassembled: the stream table \
                     already held this build's ceiling of {ceiling} streams when its segments \
                     arrived, so no HTTP, TLS or other content was read from that direction and \
                     its absence from those records says nothing about what it carried; the \
                     {held} direction was held and read, and what was read from it stands"
                )
            }
            _ => format!(
                "this conversation's bytes were not reassembled: the stream table already held \
                 this build's ceiling of {ceiling} streams when its segments arrived, so no \
                 HTTP, TLS or other content was read from it and its absence from those records \
                 says nothing about what it carried"
            ),
        };
        shortfalls.push((IncompleteReason::CapReached, detail));
    }
    for (label, stream) in [
        ("local to remote", local_stream),
        ("remote to local", remote_stream),
    ] {
        let Some(stream) = stream else { continue };
        let holes = stream.holes();
        if !holes.is_empty() {
            let bytes = holes.iter().fold(0u64, |a, h| a.saturating_add(h.length));
            shortfalls.push((
                IncompleteReason::ShortRead,
                format!(
                    "the {label} stream is missing {bytes} byte(s) in {} place(s); only the {} \
                     byte(s) before the first gap may be read as a continuous message",
                    holes.len(),
                    stream.contiguous_prefix().len()
                ),
            ));
        }
        if !stream.conflicts.is_empty() {
            shortfalls.push((
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} place(s) in the {label} stream were claimed twice with different \
                     bytes; the bytes held are the ones that arrived first and the others are \
                     in no record",
                    stream.conflicts.len()
                ),
            ));
        }
        match &stream.stop {
            crate::reassemble::StreamStop::EndOfCapture => {}
            crate::reassemble::StreamStop::ByteCeiling { at } => shortfalls.push((
                IncompleteReason::CapReached,
                format!(
                    "the {label} stream reached this build's byte ceiling at offset {at}; \
                     nothing above it was assembled"
                ),
            )),
            crate::reassemble::StreamStop::RunCeiling { at } => shortfalls.push((
                IncompleteReason::CapReached,
                format!(
                    "the {label} stream already held this build's ceiling of separate pieces \
                     when a new one arrived at offset {at}; it was not assembled"
                ),
            )),
            crate::reassemble::StreamStop::TotalBudget { at } => shortfalls.push((
                IncompleteReason::CapReached,
                format!(
                    "the {label} stream was cut at offset {at} because this build's budget for \
                     assembling every stream in the capture between them was exhausted; the \
                     bytes above it are in the capture and were not assembled"
                ),
            )),
        }
    }
    if flow.truncated_packets > 0 {
        shortfalls.push((
            IncompleteReason::ShortRead,
            format!(
                "{} packets captured short of their wire length; bytes counts what was held",
                flow.truncated_packets
            ),
        ));
    }
    if flow.unattributed_packets_total() > 0 {
        let reason = if flow
            .unattributed_packets
            .contains_key("transport_truncated")
        {
            IncompleteReason::ShortRead
        } else {
            IncompleteReason::UnresolvedStructure
        };
        let reasons: Vec<String> = flow
            .unattributed_packets
            .iter()
            .map(|(k, v)| format!("{v} {k}"))
            .collect();
        shortfalls.push((
            reason,
            format!(
                "{} packets counted on this IP pair could not be attributed to a transport \
                 flow: {}",
                flow.unattributed_packets_total(),
                reasons.join(", ")
            ),
        ));
    }
    if flow.packets_without_timestamp > 0 {
        // first_seen, last_seen and the duration are over the timed subset;
        // a row that showed them beside the full packet count would present
        // the whole conversation as having happened in that window.
        shortfalls.push((
            IncompleteReason::UnresolvedStructure,
            format!(
                "{} of {} packets carried no timestamp; first_seen, last_seen and \
                 duration_seconds are over the {} that did",
                flow.packets_without_timestamp,
                flow.packets(),
                flow.timestamped_packets()
            ),
        ));
    }
    if refused_between_hosts_total > 0 {
        // Without this a row can read "the remote host opened this and we
        // sent nothing" while its other half sits on the IP-pair row.
        let reasons: Vec<String> = refused_between_hosts
            .iter()
            .map(|(k, v)| format!("{v} {k}"))
            .collect();
        shortfalls.push((
            IncompleteReason::UnresolvedStructure,
            format!(
                "{refused_between_hosts_total} packets between {} and {} were refused before \
                 a port could be read ({}) and are counted on the IP-pair flow, not here; \
                 they may be this conversation's other half, so its direction counts and \
                 initiator are not to be read as complete",
                local.ip,
                remote.ip,
                reasons.join(", ")
            ),
        ));
    }
    if let Some((reason, _)) = shortfalls.first() {
        let details: Vec<&str> = shortfalls.iter().map(|(_, d)| d.as_str()).collect();
        stamp(&mut m, "content_incomplete", *reason, &details.join("; "));
    }
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, m).with_parent(parent_id)
}

/// A timeline event at the flow's first packet, so network activity sits on
/// the axis that holds logons and file events. `None` when no packet on the
/// flow carried a timestamp: an event at the epoch would be a lie.
fn flow_timeline_event(case_id: Uuid, parent_id: Uuid, flow: &Flow) -> Option<Artifact> {
    let first = flow.first_seen_micros?;
    let (local, remote) = flow.local_and_remote();
    // RFC 3339 with the fraction and an explicit offset: the timeline store
    // keeps sub-second order and offset provenance from an RFC 3339 string
    // and drops both from a bare integer, and a capture clock is UTC by
    // definition, so the offset is known rather than unknowable.
    let m = json!({
        "timestamp": rfc3339_micros_utc_offset(first),
        "timestamp_micros": first,
        "timestamp_desc": "Network flow first seen",
        "source_module": MODULE_ID,
        "short_desc": flow_short_desc(flow, local, remote),
        "protocol": protocol_label(flow.protocol),
        "local_ip": local.ip.to_string(),
        "local_port": local.port,
        "remote_ip": remote.ip.to_string(),
        "remote_port": remote.port,
        "remote_is_external": is_external(remote.ip),
        "packets": flow.packets(),
        "bytes": flow.bytes(),
    });
    Some(Artifact::new(case_id, ArtifactType::TimelineEvent, None, m).with_parent(parent_id))
}

/// The RR type names an examiner reads without a table; the rest by number.
fn rtype_name(rtype: u16) -> String {
    match rtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        n => format!("TYPE{n}"),
    }
}

/// The assigned DNS opcodes (IANA), numbered where unassigned. Only 0 carries
/// questions and answers.
fn opcode_name(opcode: u8) -> String {
    match opcode {
        0 => "query".to_string(),
        1 => "iquery".to_string(),
        2 => "status".to_string(),
        4 => "notify".to_string(),
        5 => "update".to_string(),
        6 => "dso".to_string(),
        other => format!("opcode_{other}"),
    }
}

/// RFC 1035 §4.1.1 response codes by name; the rest by number.
pub fn rcode_name(rcode: u8) -> String {
    match rcode {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        n => format!("RCODE{n}"),
    }
}

/// One `DnsResolution` per question in the message; a message with no
/// question (qdcount 0, or cut inside the question) still gets one record
/// with a null name, because the packet was there.
fn dns_records(case_id: Uuid, parent_id: Uuid, obs: &DnsObservation) -> Vec<Artifact> {
    let msg = &obs.message;
    // The client is whoever asked: the sender of a query, the receiver of a
    // response.
    let (client, server) = if msg.is_response {
        (obs.dst, obs.src)
    } else {
        (obs.src, obs.dst)
    };
    let answers: Vec<Value> = msg
        .answers
        .iter()
        .map(|a| {
            json!({
                "name": a.name,
                "rtype": a.rtype,
                "rtype_name": rtype_name(a.rtype),
                "data": a.data,
            })
        })
        .collect();
    let answer_data: Vec<&str> = msg.answers.iter().map(|a| a.data.as_str()).collect();
    let timestamp = obs.ts_micros.map(rfc3339_micros);
    // A response is a resolution only when the server answered with records.
    // NXDOMAIN, SERVFAIL, REFUSED and a NOERROR response whose only record is
    // in a section this decoder does not read are all "asked, not resolved",
    // and each is named by its RCODE rather than shown as an empty answer.
    let rcode_label = rcode_name(msg.rcode);
    let resolved = msg.is_response && msg.rcode == 0 && !msg.answers.is_empty();

    let questions: Vec<Option<&str>> = if msg.questions.is_empty() {
        vec![None]
    } else {
        msg.questions.iter().map(|q| Some(q.as_str())).collect()
    };
    questions
        .into_iter()
        .map(|question| {
            // A message of another opcode is neither a query nor a response
            // and carries no question to have read; it is named for what it
            // is, and "(no question read)" would claim the parse lost one.
            let kind = if msg.opcode != 0 {
                format!("DNS {}", opcode_name(msg.opcode))
            } else if msg.is_response {
                "DNS response".to_string()
            } else {
                "DNS query".to_string()
            };
            let subject = question.map_or_else(
                || {
                    if msg.opcode != 0 {
                        format!("opcode {}", msg.opcode)
                    } else {
                        "(no question read)".to_string()
                    }
                },
                str::to_string,
            );
            let short_desc = if msg.opcode != 0 {
                format!("{kind} ({subject}) from {}", client.ip)
            } else if !msg.is_response {
                format!("{kind}: {subject}")
            } else if msg.rcode != 0 {
                format!("{kind}: {subject} -> {rcode_label}")
            } else if answer_data.is_empty() {
                format!("{kind}: {subject} -> {rcode_label}, no answer records read")
            } else {
                format!("{kind}: {subject} -> {}", answer_data.join(", "))
            };
            let mut m = json!({
                "type": "DnsResolution",
                "name": question,
                "short_desc": short_desc,
                "transaction_id": msg.id,
                "is_response": msg.is_response,
                "opcode": msg.opcode,
                "opcode_name": opcode_name(msg.opcode),
                "rcode": msg.rcode,
                "rcode_name": rcode_label,
                "resolved": resolved,
                "tc": msg.tc,
                "truncated": msg.truncated,
                "answers": answers,
                "answer_count": answers.len(),
                "answer_data": answer_data,
                "client_ip": client.ip.to_string(),
                "client_port": client.port,
                "server_ip": server.ip.to_string(),
                "server_port": server.port,
                "timestamp": timestamp,
                "resolved_by": "capture",
            });
            if msg.truncated {
                stamp(
                    &mut m,
                    "content_incomplete",
                    IncompleteReason::ShortRead,
                    "the capture ended before the counted records did; the questions and \
                     answers listed are those fully read before the cut",
                );
            }
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, m).with_parent(parent_id)
        })
        .collect()
}

/// Microseconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
/// Always six fractional digits, so a column of these aligns and a
/// millisecond timestamp is not mistaken for a second one.
pub fn rfc3339_micros(micros: u64) -> String {
    let secs = micros / 1_000_000;
    let frac = micros % 1_000_000;
    let days = secs / 86_400;
    let second_of_day = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{frac:06}Z",
        second_of_day / 3600,
        (second_of_day % 3600) / 60,
        second_of_day % 60
    )
}

/// The same instant with an explicit `+00:00` in place of `Z`, for the
/// timeline store, which reads the offset from the string.
pub fn rfc3339_micros_utc_offset(micros: u64) -> String {
    let mut s = rfc3339_micros(micros);
    s.pop();
    s.push_str("+00:00");
    s
}

/// Days since 1970-01-01 to a proleptic Gregorian (year, month, day).
/// Howard Hinnant's algorithm, for non-negative day counts; u64::MAX
/// microseconds is about 2.1e8 days, so nothing here approaches i64.
fn civil_from_days(days: u64) -> (i64, u32, u32) {
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
#[path = "emit_tests.rs"]
mod emit_tests;

// ── HTTP ────────────────────────────────────────────────────────────────────

/// What a capture's HTTP amounts to, counted once and read by both the
/// capture record and the emission loop so the two cannot disagree.
struct HttpTotals {
    conversations: usize,
    transactions: usize,
    /// Transactions this run writes a record for: the cap bounds it.
    emitted: usize,
    transactions_beyond_cap: usize,
    /// Message bodies handed on as their own artifacts, and the bytes they
    /// hold between them against the budget that bounds them.
    bodies: usize,
    body_bytes: u64,
    bodies_cut_by_the_capture_budget: usize,
    /// Transactions carrying a message that is a prefix of one.
    incomplete: usize,
    /// Conversations whose bytes begin with HTTP/2's connection preface. This
    /// build does not read HTTP/2, and HTTP/2 is most of the web: counting
    /// them is the difference between "no HTTP was found" and "HTTP/2 was
    /// found and is not read".
    http2_conversations: usize,
    /// Transactions paired over a stream with a hole in it, whose pairing may
    /// therefore be wrong.
    paired_over_a_gap: usize,
    /// And ones paired over a conversation whose start the capture does not
    /// hold, which is a different fault: no gap to measure, and the response
    /// beside a request may answer one sent before the capture began.
    paired_from_an_incomplete_start: usize,
    /// Transactions with no response, and responses with no request.
    unanswered: usize,
    unmatched: usize,
}

fn http_totals(input: &CaptureInput<'_>) -> HttpTotals {
    let transactions: usize = input.http.iter().map(|c| c.transactions.len()).sum();
    let emitted = transactions.min(crate::http::MAX_TRANSACTIONS_PER_CAPTURE);
    let mut totals = HttpTotals {
        conversations: input.http.len(),
        transactions,
        emitted,
        transactions_beyond_cap: transactions.saturating_sub(emitted),
        bodies: 0,
        body_bytes: 0,
        bodies_cut_by_the_capture_budget: 0,
        incomplete: 0,
        http2_conversations: input
            .http
            .iter()
            .filter(|c| c.requests.http2_preface || c.responses.http2_preface)
            .count(),
        paired_over_a_gap: 0,
        paired_from_an_incomplete_start: 0,
        unanswered: 0,
        unmatched: 0,
    };
    // Counted over the transactions that are emitted: the ones past the cap
    // were not read into records and nothing is claimed about them beyond
    // their number.
    for transaction in input
        .http
        .iter()
        .flat_map(|c| c.transactions.iter())
        .take(emitted)
    {
        for message in [&transaction.request, &transaction.response] {
            let Some(message) = message else { continue };
            if !message.body.is_empty() {
                totals.bodies += 1;
                // What the bodies hold once decoded, measured the same way
                // the emission measures it, so the capture record's figure
                // and the artifacts agree. The per-body ceiling and the
                // per-capture budget are both named beside it.
                let body = crate::http::body_bytes_within(
                    message,
                    crate::http::MAX_BODY_BYTES_PER_CAPTURE.saturating_sub(totals.body_bytes),
                );
                if matches!(
                    body.coding,
                    crate::http::Coding::CaptureBudgetExhausted { .. }
                ) {
                    totals.bodies_cut_by_the_capture_budget += 1;
                }
                totals.body_bytes = totals.body_bytes.saturating_add(body.bytes.len() as u64);
            }
        }
        if [&transaction.request, &transaction.response]
            .iter()
            .filter_map(|m| m.as_ref())
            .any(|m| !m.is_whole())
        {
            totals.incomplete += 1;
        }
        match transaction.pairing {
            crate::http::Pairing::InOrderOverAGap => totals.paired_over_a_gap += 1,
            crate::http::Pairing::InOrderFromAnIncompleteStart => {
                totals.paired_from_an_incomplete_start += 1
            }
            crate::http::Pairing::RequestUnanswered => totals.unanswered += 1,
            crate::http::Pairing::ResponseUnmatched => totals.unmatched += 1,
            crate::http::Pairing::InOrder => {}
        }
    }
    totals
}

/// What the HTTP figures on a capture record mean. On the record because a
/// reader who takes `http_transactions` for "the web traffic in this capture"
/// will be wrong in three ways at once.
const HTTP_MEANING: &str = concat!(
    "HTTP read from the reassembled TCP streams by start line, on any port -- so a server ",
    "on 8443 is read and a binary protocol on 80 is not. These figures are of CLEARTEXT ",
    "HTTP/1.x only: anything inside TLS is not here (its server names and certificates are ",
    "read separately), and HTTP/2 and HTTP/3 are not read at all. Each message is parsed ",
    "from the bytes before its stream's first gap and no further, so a conversation with ",
    "packet loss can hold fewer transactions than took place. A response is matched to a ",
    "request by order, which is how HTTP/1.1 answers on one connection; every transaction ",
    "carries the basis it was paired on, and one over a stream with a hole says its pairing ",
    "may be wrong."
);

/// One transaction's record, and an artifact for each message body.
///
/// The bodies are children of the transaction rather than of the capture: the
/// chain of custody an examiner reads is capture, then the exchange that
/// carried the object, then the object.
fn http_records(
    input: &CaptureInput<'_>,
    conversation: &crate::http::Conversation,
    transaction: &crate::http::Transaction,
    index: usize,
    body_budget: &mut u64,
) -> Vec<Artifact> {
    let client = conversation.client;
    let server = conversation.server;
    let request = transaction.request.as_ref();
    let response = transaction.response.as_ref();
    let host = request.and_then(|r| r.header("host")).map(str::to_string);
    let url = request.and_then(|r| http_url(r, host.as_deref(), server.port));
    let short_desc = http_short_desc(request, response, host.as_deref());

    let mut m = json!({
        "type": "HttpTransaction",
        "name": short_desc.clone(),
        "short_desc": short_desc,
        "protocol": protocol_label(conversation.flow.protocol),
        "client_ip": client.ip.to_string(),
        "client_port": client.port,
        "server_ip": server.ip.to_string(),
        "server_port": server.port,
        "server_is_external": is_external(server.ip),
        "client_chosen_by": "the direction of the conversation whose bytes parsed as HTTP \
                             requests, which is not necessarily the endpoint this capture saw \
                             speak first",
        "transaction_index": index,
        "url": url.clone(),
        "host": host,
        "pairing": transaction.pairing.as_str(),
        "pairing_basis": transaction.pairing.basis(),
        "request_stream": conversation.requests.to_json(),
        "response_stream": conversation.responses.to_json(),
    });

    // The record first, so the bodies can be parented to it and named in it.
    let mut record = Artifact::new(input.case_id, ArtifactType::ParsedRecord, None, m.take())
        .with_parent(input.parent_id);
    let mut bodies: Vec<Artifact> = Vec::new();
    let mut messages = Map::new();
    for (role, message) in [("request", request), ("response", response)] {
        let Some(message) = message else {
            messages.insert(role.to_string(), Value::Null);
            continue;
        };
        let mut json = message.to_json();
        // What was actually sent: a posted form's fields and the query
        // string's, decoded. Both are bounded on the record and whole in the
        // body artifact and the target.
        if let Some(object) = json.as_object_mut() {
            let form = crate::http::form_fields(message).filter(|f| !f.is_empty());
            object.insert(
                "form_fields".into(),
                form.map_or(Value::Null, |f| f.to_json()),
            );
            let query = message
                .target
                .as_deref()
                .and_then(crate::http::query_fields)
                .filter(|f| !f.is_empty());
            object.insert(
                "query_fields".into(),
                query.map_or(Value::Null, |f| f.to_json()),
            );
        }
        if !message.body.is_empty() {
            let body = http_body_record(
                input,
                conversation,
                transaction,
                index,
                role,
                message,
                url.as_deref(),
                host.as_deref(),
                record.id,
                body_budget,
            );
            if let Some(object) = json.as_object_mut() {
                object.insert("body_artifact_id".into(), json!(body.id.to_string()));
            }
            bodies.push(body);
        }
        messages.insert(role.to_string(), json);
    }
    if let Some(object) = record.metadata.as_object_mut() {
        for (key, value) in messages {
            object.insert(key, value);
        }
    }

    // Every reason this transaction is short of the exchange. A message that
    // is a prefix is a short read; a pairing made over a gap is a structure
    // this build could not resolve, and the two are different places to look.
    let mut shortfalls: Vec<(IncompleteReason, String)> = Vec::new();
    for (role, message) in [("request", request), ("response", response)] {
        let Some(message) = message else { continue };
        if !message.headers_complete {
            shortfalls.push((
                IncompleteReason::ShortRead,
                format!(
                    "the {role}'s headers are a prefix of the message's: the readable bytes of \
                     its stream ended inside the header block, so headers after the {} read \
                     here were not seen",
                    message.headers.len()
                ),
            ));
        }
        if message.headers_dropped > 0 {
            shortfalls.push((
                IncompleteReason::CapReached,
                format!(
                    "{} header line(s) of the {role} were beyond this build's ceiling and were \
                     not parsed",
                    message.headers_dropped
                ),
            ));
        }
        if let Some((reason, detail)) = body_shortfall(role, message) {
            shortfalls.push((reason, detail));
        }
        if message.body_capped {
            shortfalls.push((
                IncompleteReason::CapReached,
                format!(
                    "the {role}'s body reached this build's ceiling of {} bytes and the record \
                     and its artifact hold that prefix; the stream held more",
                    crate::http::MAX_BODY_BYTES
                ),
            ));
        }
        if message.folded_headers > 0 {
            shortfalls.push((
                IncompleteReason::Unvalidated,
                format!(
                    "{} header line(s) of the {role} were continued on the line after them \
                     (the obs-fold form RFC 9112 deprecates) and were joined with one space, as \
                     the specification requires. A message using it is worth a second look: \
                     implementations differ on what they do with one",
                    message.folded_headers
                ),
            ));
        }
    }
    if matches!(
        transaction.pairing,
        crate::http::Pairing::InOrderOverAGap
            | crate::http::Pairing::InOrderFromAnIncompleteStart
            | crate::http::Pairing::RequestUnanswered
            | crate::http::Pairing::ResponseUnmatched
    ) {
        shortfalls.push((
            IncompleteReason::UnresolvedStructure,
            transaction.pairing.basis().to_string(),
        ));
    }
    for (label, facts) in [
        ("request", &conversation.requests),
        ("response", &conversation.responses),
    ] {
        if facts.trailing_unparsed > 0 {
            shortfalls.push((
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} byte(s) of the {label} stream's readable prefix were not parsed as a \
                     message; they are in the stream on the flow record",
                    facts.trailing_unparsed
                ),
            ));
        }
        if facts.message_cap_reached {
            shortfalls.push((
                IncompleteReason::CapReached,
                format!(
                    "the {label} stream held this build's ceiling of {} messages; later ones \
                     were not parsed",
                    crate::http::MAX_MESSAGES_PER_STREAM
                ),
            ));
        }
        if facts.conflicts > 0 {
            shortfalls.push((
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} place(s) in the {label} stream were claimed twice with DIFFERENT bytes, \
                     totalling {} byte(s) in disagreement. The bytes read here are the ones \
                     that arrived first and the others are in no record -- that is how an \
                     intrusion sensor is evaded, so the message above is one of two readings \
                     and the flow record holds the disagreement",
                    facts.conflicts, facts.conflict_bytes
                ),
            ));
        }
        if facts.present && !facts.base_from_syn {
            shortfalls.push((
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the {label} stream has no handshake in this capture, so its offset zero is \
                     the first byte the capture saw and not the connection's first byte; what \
                     came before is missing and its size is not knowable"
                ),
            ));
        }
        if facts.stop != "end_of_capture" && facts.present {
            shortfalls.push((
                IncompleteReason::CapReached,
                format!(
                    "the {label} stream stopped being assembled at this build's {} ceiling{}; \
                     the bytes above it are in the capture and were not offered to any parser",
                    facts.stop.replace('_', " "),
                    facts
                        .stop_at
                        .map(|at| format!(" at offset {at}"))
                        .unwrap_or_default()
                ),
            ));
        }
        if facts.start_line_too_long {
            shortfalls.push((
                IncompleteReason::CapReached,
                format!(
                    "reading the {label} stream stopped at a start line longer than this \
                     build's ceiling of {} bytes; it was not read as a message and neither was \
                     anything after it",
                    crate::http::MAX_HEADER_LINE
                ),
            ));
        }
        if facts.messages_of_the_other_kind > 0 {
            shortfalls.push((
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} message(s) on the {label} stream were the other kind -- a response \
                     where requests were expected, or the reverse -- and were counted rather \
                     than paired",
                    facts.messages_of_the_other_kind
                ),
            ));
        }
    }
    if let Some((reason, _)) = shortfalls.first() {
        let details: Vec<&str> = shortfalls.iter().map(|(_, d)| d.as_str()).collect();
        stamp(
            &mut record.metadata,
            "content_incomplete",
            *reason,
            &details.join("; "),
        );
    }

    let mut out = vec![record];
    out.extend(bodies);
    out
}

/// How a message's body falls short of what it declared, if it does.
fn body_shortfall(
    role: &str,
    message: &crate::http::Message,
) -> Option<(IncompleteReason, String)> {
    use crate::http::BodyEnd;
    match &message.body_end {
        BodyEnd::None | BodyEnd::LengthSatisfied { .. } | BodyEnd::ChunkedComplete => None,
        BodyEnd::LengthShort { declared, present } => Some((
            IncompleteReason::ShortRead,
            format!(
                "the {role} declared a body of {declared} bytes and {present} are in the \
                 capture; the artifact holds those {present}"
            ),
        )),
        BodyEnd::ChunkedTruncated { present } => Some((
            IncompleteReason::ShortRead,
            format!(
                "the {role}'s chunked body has no terminating chunk in the capture; the \
                 {present} bytes assembled before it ran out are the artifact"
            ),
        )),
        BodyEnd::LengthDisagreement { declared } => Some((
            IncompleteReason::UnresolvedStructure,
            format!(
                "the {role} declared MORE THAN ONE body length and they do not agree \
                 (`Content-Length: {declared}`). RFC 9110 calls that unrecoverable, and it is \
                 the signature of a request-smuggling attempt: two devices in the path frame \
                 the stream differently on purpose. No framing was chosen, no body is claimed, \
                 and nothing after this message on the connection was read"
            ),
        )),
        BodyEnd::ChunkedMalformed { at } => Some((
            IncompleteReason::UnresolvedStructure,
            format!(
                "the {role}'s chunked body has a chunk-size line at offset {at} that this \
                 build could not read; the {} bytes assembled before it are the artifact and \
                 the rest was not decoded rather than guessed at",
                message.body.len()
            ),
        )),
        BodyEnd::ToEndOfStream { present, fin_seen } if !fin_seen => Some((
            IncompleteReason::ShortRead,
            format!(
                "the {role} declared no body length, so its body runs to the end of the \
                 connection -- and this capture does not hold that connection's close, so the \
                 {present} bytes held may be a prefix of it"
            ),
        )),
        BodyEnd::ToEndOfStream { .. } => None,
    }
}

/// One message body, handed on as its own artifact so the ordinary parsers,
/// YARA, the hasher and the search index see it.
///
/// **Not the carver**: `seance_plugin_carver` subscribes to `FileSystem` and
/// `UnallocatedSpace` only, so a body artifact is never carved. What does
/// reach it is every module that takes a `FileEntry` — the file-type
/// detector, YARA, the hasher, the media and document parsers — which is what
/// makes a downloaded executable in a capture the same evidence as one on the
/// disk.
#[allow(clippy::too_many_arguments)]
fn http_body_record(
    input: &CaptureInput<'_>,
    conversation: &crate::http::Conversation,
    transaction: &crate::http::Transaction,
    index: usize,
    role: &str,
    message: &crate::http::Message,
    url: Option<&str>,
    host: Option<&str>,
    transaction_id: Uuid,
    body_budget: &mut u64,
) -> Artifact {
    let target = transaction
        .request
        .as_ref()
        .and_then(|r| r.target.as_deref());
    // Bounded by what the capture has left to hold: a per-body ceiling is no
    // bound on ten thousand bodies.
    let body = crate::http::body_bytes_within(message, *body_budget);
    *body_budget = body_budget.saturating_sub(body.bytes.len() as u64);
    let name = http_body_name(role, index, target);
    let mut m = json!({
        "name": name,
        "size": body.bytes.len(),
        "http_body": true,
        "http_message": role,
        "http_transaction_index": index,
        "http_transaction_id": transaction_id.to_string(),
        "http_target": target,
        "http_host": host,
        "http_url": url,
        "http_method": transaction.request.as_ref().and_then(|r| r.method.clone()),
        "http_status": transaction.response.as_ref().and_then(|r| r.status),
        "http_content_type": message.content_type(),
        "http_content_encoding": body.coding.encoding(),
        "http_body_coding": body.coding.as_str(),
        "http_body_statement": body.coding.statement(),
        "http_wire_bytes": body.wire_bytes,
        "http_client_ip": conversation.client.ip.to_string(),
        "http_server_ip": conversation.server.ip.to_string(),
        "source_name": input.source_name,
        // The type is what the message claimed, and a claim is not a
        // finding: the ordinary detectors run over these bytes like any
        // other file's and their answer is the one to read.
        "http_content_type_is_a_claim": true,
    });
    if let Some((reason, detail)) = body_shortfall(role, message) {
        stamp_or_extend(&mut m, "content_incomplete", reason, &detail);
    }
    if message.body_capped {
        stamp_or_extend(
            &mut m,
            "content_incomplete",
            IncompleteReason::CapReached,
            &format!(
                "the body reached this build's ceiling of {} bytes on the wire and was cut \
                 there",
                crate::http::MAX_BODY_BYTES
            ),
        );
    }
    if let Some(reason) = body.coding.reason() {
        stamp_or_extend(
            &mut m,
            "content_incomplete",
            reason,
            &body.coding.statement(),
        );
    }
    let data: Arc<dyn seance_core::data_source::DataSource> = Arc::new(
        seance_core::data_source::ByteSliceDataSource::new(body.bytes),
    );
    Artifact::new(input.case_id, ArtifactType::FileEntry, Some(data), m).with_parent(transaction_id)
}

/// The name a body artifact is filed under. From the request target's last
/// path segment where it has one, because an examiner hunting `invoice.pdf`
/// searches for that name — and never from anything the message said about
/// itself, which a hostile server controls.
fn http_body_name(role: &str, index: usize, target: Option<&str>) -> String {
    let fallback = format!("http-{index}-{role}-body");
    if role != "response" {
        return fallback;
    }
    let Some(target) = target else {
        return fallback;
    };
    let path = target
        .split(['?', '#'])
        .next()
        .unwrap_or(target)
        .trim_end_matches('/');
    let last = path.rsplit('/').next().unwrap_or("");
    // A segment that is empty, or that a filesystem would read as a
    // traversal, is not used: the name is a convenience and the provenance is
    // in the metadata.
    if last.is_empty()
        || last == "."
        || last == ".."
        || last.contains('\\')
        || last.contains('\0')
        || last.len() > 128
    {
        return fallback;
    }
    last.to_string()
}

/// The URL as far as the capture states it: the target when it is absolute,
/// the `Host` header and the target when it is not, and nothing invented when
/// there is no host to join it to.
fn http_url(
    request: &crate::http::Message,
    host: Option<&str>,
    server_port: Option<u16>,
) -> Option<String> {
    let target = request.target.as_deref()?;
    let lowered = target.to_ascii_lowercase();
    if lowered.starts_with("http://") || lowered.starts_with("https://") {
        return Some(target.to_string());
    }
    let host = host?;
    // The scheme is stated, not assumed: these bytes were read as cleartext
    // HTTP off the wire, so http it is, whatever a redirect elsewhere says.
    let authority = match server_port {
        Some(port) if port != 80 && !host.contains(':') => format!("{host}:{port}"),
        _ => host.to_string(),
    };
    Some(format!("http://{authority}{target}"))
}

/// The one-line description, in the order an examiner reads it: what was
/// asked for, and what came back.
fn http_short_desc(
    request: Option<&crate::http::Message>,
    response: Option<&crate::http::Message>,
    host: Option<&str>,
) -> String {
    let asked = match request {
        Some(r) => format!(
            "{} {}{}",
            r.method.as_deref().unwrap_or("?"),
            host.unwrap_or(""),
            r.target.as_deref().unwrap_or("")
        ),
        None => "(the request is not in this capture)".to_string(),
    };
    let answered = match response {
        Some(r) => match (r.status, r.reason.as_deref()) {
            (Some(status), Some(reason)) => format!("{status} {reason}"),
            (Some(status), None) => status.to_string(),
            _ => "(no status line)".to_string(),
        },
        None => "(no response in this capture)".to_string(),
    };
    format!("{asked} -> {answered}")
}

// ── TLS ─────────────────────────────────────────────────────────────────────

/// What a capture's TLS amounts to, counted once for the capture record and
/// the emission loop both.
struct TlsTotals {
    sessions: usize,
    emitted: usize,
    sessions_beyond_cap: usize,
    server_names: usize,
    certificates: usize,
    self_signed: usize,
    unparsable_certificates: usize,
    without_a_certificate: usize,
    encrypted_by_tls13: usize,
    weak_ciphers: usize,
    incomplete: usize,
}

fn tls_totals(input: &CaptureInput<'_>) -> TlsTotals {
    let sessions = input.tls.len();
    let emitted = sessions.min(crate::tls::MAX_SESSIONS_PER_CAPTURE);
    let mut totals = TlsTotals {
        sessions,
        emitted,
        sessions_beyond_cap: sessions.saturating_sub(emitted),
        server_names: 0,
        certificates: 0,
        self_signed: 0,
        unparsable_certificates: 0,
        without_a_certificate: 0,
        encrypted_by_tls13: 0,
        weak_ciphers: 0,
        incomplete: 0,
    };
    for session in input.tls.iter().take(emitted) {
        if session.server_name().is_some() {
            totals.server_names += 1;
        }
        totals.certificates += session.certificates.len();
        totals.self_signed += session
            .certificates
            .iter()
            .filter(|c| c.self_signed)
            .count();
        totals.unparsable_certificates += session.unparsable_certificates;
        match session.certificates_unavailable() {
            Some(crate::tls::CertificatesUnavailable::EncryptedByTls13) => {
                totals.without_a_certificate += 1;
                totals.encrypted_by_tls13 += 1;
            }
            Some(crate::tls::CertificatesUnavailable::NotInTheCleartext)
            | Some(crate::tls::CertificatesUnavailable::NoServerHello) => {
                totals.without_a_certificate += 1
            }
            None => {}
        }
        if session
            .server_side
            .as_ref()
            .and_then(|h| h.server_hello.as_ref())
            .is_some_and(|h| crate::tls::cipher_is_known_weak(h.cipher_suite))
        {
            totals.weak_ciphers += 1;
        }
        if !session.is_complete() {
            totals.incomplete += 1;
        }
    }
    totals
}

/// What the TLS figures on a capture record mean.
const TLS_MEANING: &str = concat!(
    "TLS read from the reassembled streams by record header, on any port. Only the handshake ",
    "is readable: what the client asked for (the server_name extension), what was agreed, the ",
    "client's own fingerprint, and -- before TLS 1.3 -- the certificate the server presented. ",
    "Everything after the cipher changes is counted and never parsed. FROM TLS 1.3 THE ",
    "CERTIFICATE IS ENCRYPTED, so a session with no certificate here may be one whose server ",
    "presented a perfectly ordinary chain; `tls_sessions_without_a_certificate` counts them and ",
    "each session record says which of the two reasons applies. No signature is verified, no ",
    "chain is built and no trust store is consulted: a certificate is what a host CLAIMED to be."
);

/// One session's record, its certificates, and a timeline event at each end of
/// each certificate's validity window.
fn tls_records(
    input: &CaptureInput<'_>,
    session: &crate::tls::Session,
    index: usize,
) -> Vec<Artifact> {
    let client = session.client;
    let server = session.server;
    let hello = session
        .client_side
        .as_ref()
        .and_then(|h| h.client_hello.as_ref());
    let server_hello = session
        .server_side
        .as_ref()
        .and_then(|h| h.server_hello.as_ref());
    let version = session.negotiated_version();
    let cipher = server_hello.map(|h| h.cipher_suite);
    let leaf = session.certificates.first();
    let short_desc = tls_short_desc(session, version);

    let mut m = json!({
        "type": "TlsSession",
        "name": short_desc.clone(),
        "short_desc": short_desc,
        "session_index": index,
        "client_ip": client.ip.to_string(),
        "client_port": client.port,
        "server_ip": server.ip.to_string(),
        "server_port": server.port,
        "server_is_external": is_external(server.ip),
        "client_chosen_by": "the direction of the conversation whose bytes were a ClientHello",
        "server_name": session.server_name(),
        "server_name_source": "the client's server_name (SNI) extension, which is what the \
                               client ASKED FOR -- not a name this build resolved or verified",
        "alpn_offered": hello.map(|h| h.alpn.clone()).unwrap_or_default(),
        "alpn_selected": server_hello.and_then(|h| h.alpn.clone()),
        "highest_version_offered": hello
            .and_then(crate::tls::ClientHello::highest_version_offered)
            .map(crate::tls::version_name),
        "negotiated_version": version.map(crate::tls::version_name),
        "negotiated_version_number": version,
        "negotiated_cipher": cipher.map(|c| crate::tls::cipher_name(c).map(str::to_string)
            .unwrap_or_else(|| format!("0x{c:04X}"))),
        "negotiated_cipher_number": cipher,
        "cipher_is_known_weak": cipher.is_some_and(crate::tls::cipher_is_known_weak),
        // Three fields below were `0` and `false` whether the client said no
        // or the capture never held the ClientHello to ask. `null` is the
        // honest answer to the second, and `client_hello_read` says which.
        "client_hello_read": session.client_hello_read(),
        "known_weak_ciphers_offered": hello.map(|h| {
            h.cipher_suites
                .iter()
                .filter(|c| crate::tls::cipher_is_known_weak(**c))
                .count()
        }),
        "ja3": hello.map(|h| h.ja3.clone()),
        "ja3_md5": hello.map(|h| h.ja3_md5.clone()),
        "encrypted_client_hello": hello.map(|h| h.encrypted_client_hello),
        "session_resumption_attempted": hello.map(|h| h.session_id_bytes > 0),
        "client_hello": hello.map(crate::tls::ClientHello::to_json),
        "server_hello": server_hello.map(crate::tls::ServerHello::to_json),
        "client_direction": session.client_side.as_ref().map(crate::tls::Handshake::to_json),
        "server_direction": session.server_side.as_ref().map(crate::tls::Handshake::to_json),
    });
    let certificates_part = json!({
        "certificates": session.certificates.len(),
        "unparsable_certificates": session.unparsable_certificates,
        "certificate_names": crate::x509::names_in(&session.certificates),
        "certificate_subject": leaf.map(|c| c.subject.clone()),
        "certificate_issuer": leaf.map(|c| c.issuer.clone()),
        "certificate_self_signed": leaf.map(|c| c.self_signed),
        "certificate_sha256": leaf.map(|c| c.sha256.clone()),
        "certificate_not_before": leaf.and_then(|c| c.not_before.clone()),
        "certificate_not_after": leaf.and_then(|c| c.not_after.clone()),
        "certificates_unavailable": session.certificates_unavailable().map(|u| u.as_str()),
        "certificates_unavailable_statement": session.certificates_unavailable()
            .map(|u| u.statement()),
        "statement": TLS_SESSION_STATEMENT,
    });

    // Every reason this session is short of the conversation.
    let mut shortfalls: Vec<(IncompleteReason, String)> = Vec::new();
    for (label, handshake) in [
        ("client", session.client_side.as_ref()),
        ("server", session.server_side.as_ref()),
    ] {
        let Some(handshake) = handshake else {
            shortfalls.push((
                IncompleteReason::ShortRead,
                format!(
                    "the {label} direction of this conversation holds no readable TLS: it was \
                     not captured, or its first bytes are missing"
                ),
            ));
            continue;
        };
        if !handshake.stop.is_complete() {
            shortfalls.push((
                match handshake.stop {
                    crate::tls::Stop::RecordCeiling { .. }
                    | crate::tls::Stop::HandshakeCeiling { .. } => IncompleteReason::CapReached,
                    crate::tls::Stop::PartialRecord { .. } => IncompleteReason::ShortRead,
                    _ => IncompleteReason::UnresolvedStructure,
                },
                handshake.stop.statement(),
            ));
        }
        if handshake.handshake_message_truncated {
            shortfalls.push((
                IncompleteReason::ShortRead,
                format!(
                    "the {label} direction's cleartext handshake ends inside a message; that \
                     message was not read"
                ),
            ));
        }
        if handshake.certificates_beyond_cap > 0 {
            shortfalls.push((
                IncompleteReason::CapReached,
                format!(
                    "{} certificate(s) past this build's ceiling of {} in one chain were not \
                     read",
                    handshake.certificates_beyond_cap,
                    crate::tls::MAX_CERTIFICATES
                ),
            ));
        }
        if !handshake.certificates.is_empty() && !handshake.certificate_chain_complete {
            shortfalls.push((
                IncompleteReason::UnresolvedStructure,
                "the certificate message's own lengths did not add up; the certificates read \
                 before the disagreement are here and the rest were not read"
                    .to_string(),
            ));
        }
    }
    // What the streams themselves withheld from the reader. The handshake
    // walk only ever sees the contiguous prefix, so without these a session
    // read from a stream with a hole in it reads as one read in full.
    for (label, facts) in [
        ("client", &session.client_stream),
        ("server", &session.server_stream),
    ] {
        if !facts.present {
            continue;
        }
        if facts.gaps > 0 {
            shortfalls.push((
                IncompleteReason::ShortRead,
                format!(
                    "the {label} stream is missing {} byte(s) in {} place(s); only the {} \
                     byte(s) before the first gap were read as TLS records, and the {} byte(s) \
                     the capture holds beyond it were not",
                    facts.gap_bytes, facts.gaps, facts.parsed_bytes, facts.bytes_after_first_gap
                ),
            ));
        }
        if facts.conflicts > 0 {
            shortfalls.push((
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} place(s) in the {label} stream were claimed twice with DIFFERENT bytes; \
                     the records read here are one of two readings and the other is in no \
                     record",
                    facts.conflicts
                ),
            ));
        }
        if !facts.base_from_syn {
            shortfalls.push((
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the {label} stream has no handshake in this capture: what came before the \
                     first byte held is missing and its size is not knowable, so a ClientHello \
                     or a certificate sent earlier on this connection is not here"
                ),
            ));
        }
        if facts.stop != "end_of_capture" {
            shortfalls.push((
                IncompleteReason::CapReached,
                format!(
                    "the {label} stream stopped being assembled at this build's {} ceiling{}",
                    facts.stop.replace('_', " "),
                    facts
                        .stop_at
                        .map(|at| format!(" at offset {at}"))
                        .unwrap_or_default()
                ),
            ));
        }
    }
    if session.unparsable_certificates > 0 {
        shortfalls.push((
            IncompleteReason::UnresolvedStructure,
            format!(
                "{} certificate(s) the server presented could not be parsed by this build; they \
                 were sent and are not among the records below",
                session.unparsable_certificates
            ),
        ));
    }
    if let Some(reason) = session.certificates_unavailable() {
        shortfalls.push((
            match reason {
                // A certificate TLS 1.3 encrypted is not a shortfall of the
                // capture's reading; it is not there to be read. It is still
                // stamped, because a record with no certificate must not be
                // read as a complete account of the server.
                crate::tls::CertificatesUnavailable::EncryptedByTls13 => {
                    IncompleteReason::Encrypted
                }
                crate::tls::CertificatesUnavailable::NotInTheCleartext
                | crate::tls::CertificatesUnavailable::NoServerHello => {
                    IncompleteReason::UnresolvedStructure
                }
            },
            reason.statement().to_string(),
        ));
    }
    if let Some((reason, _)) = shortfalls.first() {
        let details: Vec<&str> = shortfalls.iter().map(|(_, d)| d.as_str()).collect();
        stamp(&mut m, "content_incomplete", *reason, &details.join("; "));
    }

    // In a second object: one `json!` holding every field of this record
    // exceeds the macro's recursion limit.
    let m = merge([
        m,
        certificates_part,
        json!({
            "client_stream": session.client_stream.to_json(),
            "server_stream": session.server_stream.to_json(),
        }),
    ]);
    let record = Artifact::new(input.case_id, ArtifactType::ParsedRecord, None, m)
        .with_parent(input.parent_id);
    let mut out = vec![];
    let mut children = Vec::new();
    for (position, certificate) in session.certificates.iter().enumerate() {
        children.extend(tls_certificate_records(
            input,
            session,
            certificate,
            position,
            record.id,
        ));
    }
    out.push(record);
    out.extend(children);
    out
}

/// The sentence a TLS session record carries.
const TLS_SESSION_STATEMENT: &str = concat!(
    "Read from the handshake, which is the only part of a TLS conversation in the clear. The ",
    "server name is what the CLIENT ASKED FOR and is not resolved or verified here; the ",
    "certificate's fields are as presented, with NO signature verified, NO chain built and NO ",
    "trust store consulted. Nothing of the conversation's content is readable, and none is ",
    "claimed."
);

/// One certificate from a chain, and a timeline event at each end of its
/// validity window.
fn tls_certificate_records(
    input: &CaptureInput<'_>,
    session: &crate::tls::Session,
    certificate: &crate::x509::Certificate,
    position: usize,
    session_id: Uuid,
) -> Vec<Artifact> {
    let name = certificate
        .subject_common_name
        .clone()
        .or_else(|| certificate.dns_names.first().cloned())
        .unwrap_or_else(|| certificate.subject.clone());
    let short_desc = format!(
        "{name} issued by {}",
        certificate
            .issuer_common_name
            .as_deref()
            .unwrap_or(&certificate.issuer)
    );
    let mut m = merge([
        json!({
            "type": "TlsCertificate",
            "name": short_desc.clone(),
            "short_desc": short_desc.clone(),
            "position_in_chain": position,
            "chain_length": session.certificates.len(),
            "server_ip": session.server.ip.to_string(),
            "server_port": session.server.port,
            "server_name_requested": session.server_name(),
            "source_name": input.source_name,
        }),
        certificate.to_json(),
    ]);
    // A certificate whose own name does not cover the name that was asked for
    // is worth reading twice, and saying so is arithmetic over two lists
    // rather than a verdict.
    if let Some(asked) = session.server_name() {
        let covers = certificate
            .names()
            .iter()
            .any(|name| name_covers(name, asked));
        if let Some(object) = m.as_object_mut() {
            // A name list cut by the ceiling cannot answer "no": the name
            // asked for may be one of the names past the cut. Only "yes" is
            // safe from a prefix, and neither answer is given without one.
            let assessable = covers || certificate.names_beyond_cap == 0;
            object.insert(
                "covers_the_name_requested".into(),
                if assessable {
                    json!(covers)
                } else {
                    Value::Null
                },
            );
            object.insert(
                "covers_the_name_requested_meaning".into(),
                json!(if assessable {
                    "Whether one of this certificate's own names matches the name the client asked for, wildcards included. It is a comparison of two strings: it is NOT a verification, which would need the signature and a trust store."
                        .to_string()
                } else {
                    format!(
                        "NOT ASSESSED. This certificate carries more alternative names than this build lists ({} past the ceiling), so the name the client asked for may be one of the names that were not read. A comparison against a list that is a prefix could only produce a false negative.",
                        certificate.names_beyond_cap
                    )
                }),
            );
        }
    }
    for (reason, detail) in certificate.shortfalls() {
        stamp_or_extend(&mut m, "content_incomplete", reason, &detail);
    }
    let mut out = vec![
        Artifact::new(input.case_id, ArtifactType::ParsedRecord, None, m).with_parent(session_id),
    ];
    let record_id = out[0].id;
    for (stamp_name, description, when) in [
        (
            "not_before",
            "TLS certificate valid from",
            certificate.not_before.as_deref(),
        ),
        (
            "not_after",
            "TLS certificate valid until",
            certificate.not_after.as_deref(),
        ),
    ] {
        let Some(when) = when else { continue };
        let event = json!({
            "timestamp": when,
            "timestamp_desc": description,
            "event_type": "certificate_validity",
            "validity_edge": stamp_name,
            "source_module": MODULE_ID,
            "short_desc": format!("{description}: {short_desc}"),
            "server_ip": session.server.ip.to_string(),
            "server_name_requested": session.server_name(),
            "certificate_subject": certificate.subject.clone(),
            "certificate_sha256": certificate.sha256.clone(),
            "self_signed": certificate.self_signed,
        });
        out.push(
            Artifact::new(input.case_id, ArtifactType::TimelineEvent, None, event)
                .with_parent(record_id),
        );
    }
    out
}

/// Whether a certificate's name covers the name that was asked for, wildcards
/// included. A comparison of two strings, and nothing more: see the meaning
/// sentence beside it on the record.
fn name_covers(certificate_name: &str, asked: &str) -> bool {
    let certificate_name = certificate_name.to_ascii_lowercase();
    let asked = asked.to_ascii_lowercase();
    if certificate_name == asked {
        return true;
    }
    // `*.example.com` covers one label, and not the bare domain.
    if let Some(suffix) = certificate_name.strip_prefix("*.") {
        if let Some((_, rest)) = asked.split_once('.') {
            return rest == suffix;
        }
    }
    false
}

fn tls_short_desc(session: &crate::tls::Session, version: Option<u16>) -> String {
    let version = version.map(crate::tls::version_name).unwrap_or("TLS");
    match session.server_name() {
        Some(name) => format!("{version} to {name} ({})", endpoint_label(session.server)),
        // Three reasons reach `None` and only one is a statement about the
        // client. Saying "no server name was sent" when the client's half of
        // the conversation is not in the capture is a claim about evidence
        // nobody has — and this string is the record's name, its short
        // description, and the line a report quotes.
        None => format!(
            "{version} to {} ({})",
            endpoint_label(session.server),
            if session.client_hello_read() {
                "no server name was sent"
            } else {
                "the client's half of this conversation was not captured"
            }
        ),
    }
}

// ── ARP ─────────────────────────────────────────────────────────────────────

/// What a capture's ARP amounts to.
const ARP_MEANING: &str = concat!(
    "Who claimed which address on the segment, read from the ARP frames the capture holds. ARP ",
    "DOES NOT AUTHENTICATE: a reply is believed because it arrived, so every binding here is an ",
    "announcement rather than a proven fact. An address claimed by more than one hardware ",
    "address is counted in arp_addresses_contested and is the signature of ARP cache poisoning ",
    "-- and equally of a failover pair, a DHCP lease handed on, a replaced network card or a ",
    "host moved between hypervisors; each binding record carries its claims and their times and ",
    "reaches no verdict. Addresses only ever ASKED ABOUT are listed apart from those claimed: ",
    "nobody announced them, and one nothing answered for is an address that was not in use."
);

/// One address's binding record, and a timeline event where the address is
/// contested.
fn arp_records(input: &CaptureInput<'_>, binding: &crate::arp::Binding) -> Vec<Artifact> {
    let short_desc = if binding.contested() {
        format!(
            "{} claimed by {} hardware addresses",
            binding.ip,
            binding.claims.len() + binding.macs_beyond_cap
        )
    } else {
        format!(
            "{} claimed by {}",
            binding.ip,
            binding
                .claims
                .first()
                .map(|c| crate::arp::mac_label(c.mac))
                .unwrap_or_else(|| "nobody".to_string())
        )
    };
    let mut m = merge([
        json!({
            "type": "ArpBinding",
            "name": short_desc.clone(),
            "short_desc": short_desc.clone(),
            "source_name": input.source_name,
        }),
        binding.to_json(),
    ]);
    // A contested address is not a complete account of who was at it, and a
    // reader taking the first row for the answer would be wrong.
    if binding.contested() {
        stamp(
            &mut m,
            "content_incomplete",
            IncompleteReason::UnresolvedStructure,
            binding.statement(),
        );
    }
    if binding.macs_beyond_cap > 0 {
        stamp_or_extend(
            &mut m,
            "content_incomplete",
            IncompleteReason::CapReached,
            &format!(
                "{} further hardware address(es) claimed this address, past this build's \
                 ceiling of {}; they are counted and not listed",
                binding.macs_beyond_cap,
                crate::arp::MAX_MACS_PER_ADDRESS
            ),
        );
    }
    let record = Artifact::new(input.case_id, ArtifactType::ParsedRecord, None, m)
        .with_parent(input.parent_id);
    let mut out = vec![];
    // The instant the contest began, which is when the segment's caches
    // started to be wrong. Not one event per binding: a capture of a /24
    // would put two hundred and fifty of them on the timeline and bury this.
    if let Some(at) = binding.contested_from() {
        let event = json!({
            "timestamp": rfc3339_micros_utc_offset(at),
            "timestamp_micros": at,
            "timestamp_desc": "ARP: a second hardware address claimed this address",
            "event_type": "arp_address_contested",
            "source_module": MODULE_ID,
            "short_desc": short_desc,
            "ip": binding.ip.to_string(),
            "macs": binding.claims.iter().map(|c| crate::arp::mac_label(c.mac))
                .collect::<Vec<_>>(),
            "statement": binding.statement(),
        });
        out.push(
            Artifact::new(input.case_id, ArtifactType::TimelineEvent, None, event)
                .with_parent(record.id),
        );
    }
    out.insert(0, record);
    out
}
