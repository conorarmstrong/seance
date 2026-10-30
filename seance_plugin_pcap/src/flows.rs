//! Flow aggregation: packets into bidirectional conversations.
//!
//! Flows are the unit the module reports in, not packets: Case 001's 411,797
//! packets collapse to about 17 k conversations, which is the order of things
//! the rest of the product handles comfortably, and a packet list is the
//! wrong primary view for an examiner anyway. Packets stay reachable through
//! the flow, never enumerated beside it.
//!
//! # What lands where
//!
//! A decoded packet lands on the flow keyed by its protocol and both
//! endpoints, whichever direction it travelled. A packet the decoder refused
//! *after* reading its addresses — a failed checksum, a non-initial fragment,
//! a transport header the snaplen cut — lands on the flow for its IP pair
//! with no ports, counted in that flow's bytes and separately under the
//! reason it was not attributed further. A refusal with no addresses is
//! counted by reason only. Nothing is dropped without a counter naming why,
//! because a flow list that silently omits one direction of a conversation
//! reads as a conversation that never had one.
//!
//! # Direction and locality are different questions
//!
//! `initiator` is whoever sent the first packet the capture holds, and
//! `packets_out` are that endpoint's. Which endpoint is *local* is decided
//! at emission from address ranges, because a capture that starts mid-stream
//! sees the server speak first, and a flow table that called the server
//! "local" on that basis would invert every row of a C2 hunt.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use crate::decode::{Decoded, Refusal};

/// The most flows one capture may table. Past it, packets on new flows are
/// counted and not tabled, and the capture record says so. A capture with
/// more conversations than this is a backbone tap, and the honest answer for
/// it is a cap the record names rather than a worker that runs out of memory.
pub const DEFAULT_FLOW_CAP: usize = 500_000;

const TCP: u8 = 6;
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// One end of a conversation. `port` is `None` for protocols without ports
/// and for the IP-pair flows that hold packets whose transport header was
/// never read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: Option<u16>,
}

/// Which way a packet travelled relative to the flow's initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    Out,
    In,
}

/// What the TCP flags seen on a flow add up to. Derived from flags alone, so
/// it is a statement about the packets in the capture, not about the
/// connection: a capture that starts after the handshake says
/// `EstablishedNoHandshakeSeen`, not `HandshakeSeen`, and one whose packets
/// never had a readable flags byte says `NoTransportSeen` rather than
/// anything about a handshake at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// SYNs and nothing else: a scan, a firewalled port, or a host that was
    /// not there.
    SynOnly,
    /// SYN and SYN-ACK both seen, no FIN or RST: the opening is in the file.
    HandshakeSeen,
    /// One half of the opening is in the file — the SYN without its SYN-ACK,
    /// or the SYN-ACK without its SYN — and packets flowed after it. Half an
    /// opening still dates the connection and names its initiator, which
    /// "no handshake seen" would deny.
    HandshakePartiallySeen,
    /// Packets flowed without any of the handshake in the file: the capture
    /// joined the connection late, or the engine dropped its opening. Its
    /// time and initiator are not in the evidence.
    EstablishedNoHandshakeSeen,
    /// A FIN was seen and no RST, and the opening (a SYN or SYN-ACK) was too.
    Closed,
    /// A FIN was seen and no RST, but no SYN or SYN-ACK: the close is in the
    /// file and the opening is not.
    ClosedNoHandshakeSeen,
    /// An RST was seen, and the opening was too. RST takes precedence over
    /// FIN because a reset ends a connection whatever else happened, and a
    /// SYN answered by RST is the finding a port scan leaves.
    Reset,
    /// An RST was seen on a connection whose opening is not in the file: a
    /// different finding from a refused SYN, and not to be read as one.
    ResetNoHandshakeSeen,
    /// No flags byte was ever read: every packet was refused before its
    /// transport header, or the capture cut each one inside it. This is not
    /// a statement about the handshake either way.
    NoTransportSeen,
}

impl TcpState {
    /// The token the viewer keys its labels on. Each says what was *seen*;
    /// none is a claim about packets that are not in the file.
    pub fn as_str(self) -> &'static str {
        match self {
            TcpState::SynOnly => "syn_only",
            TcpState::HandshakeSeen => "handshake_seen",
            TcpState::HandshakePartiallySeen => "handshake_partially_seen",
            TcpState::EstablishedNoHandshakeSeen => "established_no_handshake_seen",
            TcpState::Closed => "closed",
            TcpState::ClosedNoHandshakeSeen => "closed_no_handshake_seen",
            TcpState::Reset => "reset",
            TcpState::ResetNoHandshakeSeen => "reset_no_handshake_seen",
            TcpState::NoTransportSeen => "no_transport_seen",
        }
    }
}

/// The TCP flags a flow has seen, by kind. Each is set once and never read
/// back per packet, so the state is a function of the set and not of order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TcpFlagsSeen {
    /// Whether any flags byte was read at all. Without it, "no flags set"
    /// and "no flags present" collapse into the same absence.
    flags_read: bool,
    syn: bool,
    syn_ack: bool,
    ack: bool,
    fin: bool,
    rst: bool,
}

/// One bidirectional conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    /// IP protocol number. `None` on an IP-pair flow whose packets were
    /// refused before the protocol byte was trusted (a failed checksum).
    pub protocol: Option<u8>,
    /// The endpoint that sent the first packet in the capture.
    pub initiator: Endpoint,
    pub responder: Endpoint,
    pub packets_out: u64,
    /// Captured bytes, not wire bytes: what the evidence holds. See
    /// [`Flow::wire_bytes`] for what the capture engine said crossed the wire.
    pub bytes_out: u64,
    pub packets_in: u64,
    pub bytes_in: u64,
    pub wire_bytes_out: u64,
    pub wire_bytes_in: u64,
    pub first_seen_micros: Option<u64>,
    pub last_seen_micros: Option<u64>,
    /// Packets whose block carried no usable timestamp. They count in the
    /// packet and byte totals but not in first/last seen.
    pub packets_without_timestamp: u64,
    /// Packets captured short of their wire length.
    pub truncated_packets: u64,
    /// Packets whose IPv4 checksum field was zero: transmit offload on the
    /// capturing host left it unfilled. A qualification of the packets, which
    /// are whole and attributed; never a gap.
    pub checksum_unset_packets: u64,
    /// Packets counted on this flow that the decoder refused past the IP
    /// layer, by [`Refusal::reason`]. Only ever non-empty on an IP-pair flow.
    pub unattributed_packets: BTreeMap<&'static str, u64>,
    tcp: TcpFlagsSeen,
}

impl Flow {
    pub fn new(initiator: Endpoint, responder: Endpoint, protocol: Option<u8>) -> Self {
        Flow {
            protocol,
            initiator,
            responder,
            packets_out: 0,
            bytes_out: 0,
            packets_in: 0,
            bytes_in: 0,
            wire_bytes_out: 0,
            wire_bytes_in: 0,
            first_seen_micros: None,
            last_seen_micros: None,
            packets_without_timestamp: 0,
            truncated_packets: 0,
            checksum_unset_packets: 0,
            unattributed_packets: BTreeMap::new(),
            tcp: TcpFlagsSeen::default(),
        }
    }

    /// Count one packet. Every counter saturates: the lengths are the file's
    /// to choose and the release profile panics on overflow.
    pub fn count(
        &mut self,
        direction: Direction,
        ts_micros: Option<u64>,
        wire_len: u32,
        captured_len: u32,
    ) {
        let (packets, bytes, wire) = match direction {
            Direction::Out => (
                &mut self.packets_out,
                &mut self.bytes_out,
                &mut self.wire_bytes_out,
            ),
            Direction::In => (
                &mut self.packets_in,
                &mut self.bytes_in,
                &mut self.wire_bytes_in,
            ),
        };
        *packets = packets.saturating_add(1);
        *bytes = bytes.saturating_add(u64::from(captured_len));
        *wire = wire.saturating_add(u64::from(wire_len));
        if captured_len < wire_len {
            self.truncated_packets = self.truncated_packets.saturating_add(1);
        }
        match ts_micros {
            Some(ts) => {
                self.first_seen_micros = Some(self.first_seen_micros.map_or(ts, |f| f.min(ts)));
                self.last_seen_micros = Some(self.last_seen_micros.map_or(ts, |l| l.max(ts)));
            }
            None => {
                self.packets_without_timestamp = self.packets_without_timestamp.saturating_add(1);
            }
        }
    }

    fn note_tcp_flags(&mut self, flags: u8) {
        self.tcp.flags_read = true;
        let syn = flags & TCP_SYN != 0;
        let ack = flags & TCP_ACK != 0;
        if syn && ack {
            self.tcp.syn_ack = true;
        } else if syn {
            self.tcp.syn = true;
        }
        if ack {
            self.tcp.ack = true;
        }
        if flags & TCP_FIN != 0 {
            self.tcp.fin = true;
        }
        if flags & TCP_RST != 0 {
            self.tcp.rst = true;
        }
    }

    pub fn packets(&self) -> u64 {
        self.packets_out.saturating_add(self.packets_in)
    }

    pub fn bytes(&self) -> u64 {
        self.bytes_out.saturating_add(self.bytes_in)
    }

    pub fn wire_bytes(&self) -> u64 {
        self.wire_bytes_out.saturating_add(self.wire_bytes_in)
    }

    pub fn unattributed_packets_total(&self) -> u64 {
        self.unattributed_packets
            .values()
            .fold(0u64, |acc, n| acc.saturating_add(*n))
    }

    /// Packets that carried a timestamp: the ones first/last seen and the
    /// duration are computed over.
    pub fn timestamped_packets(&self) -> u64 {
        self.packets()
            .saturating_sub(self.packets_without_timestamp)
    }

    /// The span between the first and last timestamped packets. `None` when
    /// fewer than two packets carried a timestamp: a duration is a
    /// difference between two observations, and one instant has none — a
    /// `Some(0)` for it would be the same figure as a two-packet exchange in
    /// one microsecond.
    pub fn duration_micros(&self) -> Option<u64> {
        if self.timestamped_packets() < 2 {
            return None;
        }
        let first = self.first_seen_micros?;
        let last = self.last_seen_micros?;
        Some(last.saturating_sub(first))
    }

    /// The state the flags add up to; `None` for anything that is not TCP.
    ///
    /// Every branch says what was seen. "Opening seen" means a SYN or a
    /// SYN-ACK is in the file: a close or reset on a connection whose
    /// opening is not is a different finding from one on a connection that
    /// was captured whole, and the token keeps them apart.
    pub fn tcp_state(&self) -> Option<TcpState> {
        if self.protocol != Some(TCP) {
            return None;
        }
        let t = self.tcp;
        if !t.flags_read {
            return Some(TcpState::NoTransportSeen);
        }
        let opening_seen = t.syn || t.syn_ack;
        Some(if t.rst {
            if opening_seen {
                TcpState::Reset
            } else {
                TcpState::ResetNoHandshakeSeen
            }
        } else if t.fin {
            if opening_seen {
                TcpState::Closed
            } else {
                TcpState::ClosedNoHandshakeSeen
            }
        } else if t.syn && t.syn_ack {
            TcpState::HandshakeSeen
        } else if t.syn && !t.ack {
            TcpState::SynOnly
        } else if opening_seen {
            TcpState::HandshakePartiallySeen
        } else {
            TcpState::EstablishedNoHandshakeSeen
        })
    }

    /// Which endpoint to present as local: the internal one when exactly
    /// one is, else the initiator. Two internal hosts talking, or a capture
    /// of a transit link, have no better answer than "who spoke first".
    pub fn local_and_remote(&self) -> (Endpoint, Endpoint) {
        let (local, remote, _) = self.local_and_remote_by();
        (local, remote)
    }

    /// The rule that chose the local side, alongside the sides. The record
    /// carries it because "Local" reads the same on a row where it means
    /// "the RFC 1918 side" and on one where it means "whoever spoke first".
    pub fn local_and_remote_by(&self) -> (Endpoint, Endpoint, LocalChoice) {
        let initiator_internal = is_internal(self.initiator.ip);
        let responder_internal = is_internal(self.responder.ip);
        match (initiator_internal, responder_internal) {
            (false, true) => (self.responder, self.initiator, LocalChoice::Internal),
            (true, false) => (self.initiator, self.responder, LocalChoice::Internal),
            _ => (self.initiator, self.responder, LocalChoice::FirstPacket),
        }
    }
}

/// Which rule picked a flow's local endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalChoice {
    /// Exactly one endpoint is in an internal range; it is local.
    Internal,
    /// Both or neither are internal, so the first packet's sender stands
    /// in. Not a finding about the host: the token says so.
    FirstPacket,
}

impl LocalChoice {
    pub fn as_str(self) -> &'static str {
        match self {
            LocalChoice::Internal => "internal",
            LocalChoice::FirstPacket => "first_packet",
        }
    }
}

/// The flow a packet belongs to, whichever way it travelled: the two
/// endpoints in a fixed order.
///
/// Public so a stream can be keyed the same way (`crate::reassemble`) and a
/// reassembled stream can be put beside the flow it belongs to. Ordered so a
/// stream table can be a `BTreeMap` with a stable order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub protocol: Option<u8>,
    pub low: Endpoint,
    pub high: Endpoint,
}

impl FlowKey {
    pub fn new(protocol: Option<u8>, a: Endpoint, b: Endpoint) -> Self {
        if a <= b {
            FlowKey {
                protocol,
                low: a,
                high: b,
            }
        } else {
            FlowKey {
                protocol,
                low: b,
                high: a,
            }
        }
    }
}

/// Every flow in a capture, plus the counts of what did not become one.
#[derive(Debug)]
pub struct FlowTable {
    /// In first-seen order, which is what the index below points into and
    /// what the emission order follows, so a record's position is stable.
    flows: Vec<Flow>,
    index: HashMap<FlowKey, usize>,
    /// The IP-pair flows created by refusals, keyed by their two addresses
    /// in fixed order, so a ported flow between the same hosts can find the
    /// packets that may be its other half without a scan of the table.
    refused_pairs: HashMap<(IpAddr, IpAddr), Vec<usize>>,
    cap: usize,
    cap_reached: bool,
    packets_past_cap: u64,
    packets_in_flows: u64,
    packets_refused: u64,
    packets_refused_without_addresses: u64,
    packets_no_network_layer: u64,
    refusals: BTreeMap<&'static str, u64>,
    unsupported_linktypes: BTreeMap<u16, u64>,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowTable {
    pub fn new() -> Self {
        Self::with_cap(DEFAULT_FLOW_CAP)
    }

    pub fn with_cap(cap: usize) -> Self {
        FlowTable {
            flows: Vec::new(),
            index: HashMap::new(),
            refused_pairs: HashMap::new(),
            cap,
            cap_reached: false,
            packets_past_cap: 0,
            packets_in_flows: 0,
            packets_refused: 0,
            packets_refused_without_addresses: 0,
            packets_no_network_layer: 0,
            refusals: BTreeMap::new(),
            unsupported_linktypes: BTreeMap::new(),
        }
    }

    /// Count a decoded packet on its flow.
    /// Returns the flow this packet landed on and which way it travelled, so a
    /// caller that reassembles the stream keys it the same way the table keys
    /// the conversation — two tables keyed two ways would put a stream beside
    /// the wrong flow. `None` when the packet was not tabled at all (the flow
    /// cap fired).
    pub fn observe(
        &mut self,
        d: &Decoded,
        ts_micros: Option<u64>,
        wire_len: u32,
        captured_len: u32,
    ) -> Option<(FlowKey, Direction)> {
        let src = Endpoint {
            ip: d.src,
            port: d.src_port,
        };
        let dst = Endpoint {
            ip: d.dst,
            port: d.dst_port,
        };
        let key = FlowKey::new(Some(d.protocol), src, dst);
        let slot = self.slot(Some(d.protocol), src, dst)?;
        let flow = &mut self.flows[slot];
        let direction = if flow.initiator == src {
            Direction::Out
        } else {
            Direction::In
        };
        flow.count(direction, ts_micros, wire_len, captured_len);
        if d.ipv4_checksum_unset {
            flow.checksum_unset_packets = flow.checksum_unset_packets.saturating_add(1);
        }
        if d.protocol == TCP {
            // `None` here is a TCP packet whose flags byte the capture cut;
            // "no flags" and "flags not present" must not both read as an
            // ACK-less packet.
            if let Some(flags) = d.tcp_flags {
                flow.note_tcp_flags(flags);
            }
        }
        self.packets_in_flows = self.packets_in_flows.saturating_add(1);
        Some((key, direction))
    }

    /// Count a refused packet. One that carries addresses lands on its IP
    /// pair, stamped with the reason; one that does not is counted by
    /// reason alone. Both are counted in the capture-level refusal table.
    pub fn observe_refusal(
        &mut self,
        r: &Refusal,
        ts_micros: Option<u64>,
        wire_len: u32,
        captured_len: u32,
    ) {
        let reason = r.reason();
        let by_reason = self.refusals.entry(reason).or_insert(0);
        *by_reason = by_reason.saturating_add(1);
        self.packets_refused = self.packets_refused.saturating_add(1);
        if let Refusal::UnsupportedLinktype(n) = r {
            let by_linktype = self.unsupported_linktypes.entry(*n).or_insert(0);
            *by_linktype = by_linktype.saturating_add(1);
        }
        let Some((src_ip, dst_ip)) = r.addresses() else {
            self.packets_refused_without_addresses =
                self.packets_refused_without_addresses.saturating_add(1);
            return;
        };
        // The protocol byte was read before a fragment or transport refusal;
        // a checksum refusal means the header it sits in did not verify, so
        // it is not claimed.
        let protocol = match *r {
            Refusal::NonInitialFragment { protocol, .. }
            | Refusal::TransportTruncated { protocol, .. }
            | Refusal::DatagramTooShortForTransport { protocol, .. } => Some(protocol),
            _ => None,
        };
        let src = Endpoint {
            ip: src_ip,
            port: None,
        };
        let dst = Endpoint {
            ip: dst_ip,
            port: None,
        };
        let Some(slot) = self.slot(protocol, src, dst) else {
            return;
        };
        let flow = &mut self.flows[slot];
        let direction = if flow.initiator == src {
            Direction::Out
        } else {
            Direction::In
        };
        flow.count(direction, ts_micros, wire_len, captured_len);
        let count = flow.unattributed_packets.entry(reason).or_insert(0);
        *count = count.saturating_add(1);
        let pair = self
            .refused_pairs
            .entry(host_pair(src_ip, dst_ip))
            .or_default();
        if !pair.contains(&slot) {
            pair.push(slot);
        }
        self.packets_in_flows = self.packets_in_flows.saturating_add(1);
    }

    /// Packets refused after their addresses were read that sit on an IP-pair
    /// flow between the same two hosts as the flow at `slot`, by reason —
    /// the packets that may be that flow's other half. A refusal that read
    /// the protocol byte counts only against flows in that protocol; one
    /// that did not (a failed checksum) could belong to any of them. The
    /// flow's own packets are never its own "elsewhere".
    pub fn refused_packets_between_hosts(&self, slot: usize) -> BTreeMap<&'static str, u64> {
        let mut out = BTreeMap::new();
        let Some(flow) = self.flows.get(slot) else {
            return out;
        };
        let key = host_pair(flow.initiator.ip, flow.responder.ip);
        let Some(pairs) = self.refused_pairs.get(&key) else {
            return out;
        };
        for &other in pairs {
            if other == slot {
                continue;
            }
            let Some(pair) = self.flows.get(other) else {
                continue;
            };
            if pair.protocol.is_some() && pair.protocol != flow.protocol {
                continue;
            }
            for (reason, n) in &pair.unattributed_packets {
                let total = out.entry(*reason).or_insert(0u64);
                *total = total.saturating_add(*n);
            }
        }
        out
    }

    /// Count a frame that carried no network layer (ARP, STP). Not a refusal
    /// and not a flow; reported so the packet total still adds up.
    pub fn observe_no_network_layer(&mut self) {
        self.packets_no_network_layer = self.packets_no_network_layer.saturating_add(1);
    }

    /// The flow for these endpoints, creating it unless the cap forbids.
    /// `None` means the packet was counted past the cap and not tabled.
    fn slot(&mut self, protocol: Option<u8>, src: Endpoint, dst: Endpoint) -> Option<usize> {
        let key = FlowKey::new(protocol, src, dst);
        if let Some(&slot) = self.index.get(&key) {
            return Some(slot);
        }
        if self.flows.len() >= self.cap {
            self.cap_reached = true;
            self.packets_past_cap = self.packets_past_cap.saturating_add(1);
            return None;
        }
        let slot = self.flows.len();
        self.flows.push(Flow::new(src, dst, protocol));
        self.index.insert(key, slot);
        Some(slot)
    }

    /// Flows in first-seen order.
    pub fn flows(&self) -> impl Iterator<Item = &Flow> {
        self.flows.iter()
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    pub fn cap_reached(&self) -> bool {
        self.cap_reached
    }

    /// Packets that belonged to a flow the cap kept out of the table.
    pub fn packets_past_cap(&self) -> u64 {
        self.packets_past_cap
    }

    /// Packets counted on some flow, including refused ones on IP pairs.
    pub fn packets_in_flows(&self) -> u64 {
        self.packets_in_flows
    }

    /// Every refused packet, whether or not it also landed on an IP pair.
    pub fn packets_refused(&self) -> u64 {
        self.packets_refused
    }

    /// Refused packets that carried no addresses and so reached no flow at
    /// all: a frame cut inside its IP header, a VLAN stack deeper than the
    /// walk. The capture record is the only place these can be stamped.
    pub fn packets_refused_without_addresses(&self) -> u64 {
        self.packets_refused_without_addresses
    }

    pub fn packets_no_network_layer(&self) -> u64 {
        self.packets_no_network_layer
    }

    /// Refused packets by [`Refusal::reason`].
    pub fn refusals(&self) -> &BTreeMap<&'static str, u64> {
        &self.refusals
    }

    /// Refused packets by the LINKTYPE this build does not decode.
    pub fn unsupported_linktypes(&self) -> &BTreeMap<u16, u64> {
        &self.unsupported_linktypes
    }
}

/// Two addresses in a fixed order, so both directions key the same pair.
fn host_pair(a: IpAddr, b: IpAddr) -> (IpAddr, IpAddr) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// Whether an address is one that never leaves a site: RFC 1918, loopback,
/// link-local, and the IPv6 equivalents. This is the whole of the locality
/// rule; nothing here consults the examination host's own addresses or
/// routes, because the capture was not taken on it.
pub fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || o[0] == 127
                || (o[0] == 169 && o[1] == 254)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                // fe80::/10
                || (s[0] & 0xffc0) == 0xfe80
                // fc00::/7
                || (s[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Whether an address is a routable peer — not internal, and not multicast,
/// broadcast or unspecified. The badge that finds a C2 address must not
/// also light up on mDNS and DHCP.
pub fn is_external(ip: IpAddr) -> bool {
    if is_internal(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !(v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified()),
        IpAddr::V6(v6) => !(v6.is_multicast() || v6.is_unspecified()),
    }
}

#[cfg(test)]
#[path = "flows_tests.rs"]
mod flows_tests;
