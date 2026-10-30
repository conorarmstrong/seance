//! Link, network and transport decoding for one captured frame.
//!
//! The container walk hands this module a slice of bytes and the interface's
//! LINKTYPE; everything below is attacker-controlled, so every field read is
//! bounds-checked and every length is combined with checked arithmetic. The
//! release profile turns any overflow into a panic, and a capture is exactly
//! the kind of evidence an adversary gets to author.
//!
//! # Ports are big-endian inside otherwise-little-endian parsing
//!
//! Ports, ethertypes and IP lengths are network byte order, and the surrounding
//! code — pcapng blocks, record headers — is usually little-endian. Reading a
//! port the surrounding way turns 80 into 20480, which is a legal-looking
//! ephemeral port, so the error survives review and reaches a report.
//! `seance_plugin_memory_windows/src/netscan.rs` documents the same trap for
//! tcpip.sys structures; this is the second place in the codebase where it bites.
//!
//! # Refusal is not absence
//!
//! [`decode`] has three outcomes, and the type makes them impossible to
//! conflate: headers, a frame that genuinely carries no network layer (ARP,
//! STP), and a refusal that names its reason. The refusal is never an empty
//! result, because an empty result reads as "this frame carried no IP", which
//! is a statement about the evidence we are in no position to make. The
//! defect this guards against is concrete: an earlier version returned the ARP
//! value for a failed IPv4 checksum, and on a capture taken on the sending
//! host — where every outbound packet carries an unfilled checksum — that
//! silently deleted one direction of every conversation.
//!
//! Where a refusal happens after the addresses were read, it carries them, so
//! the caller can count the packet against its IP pair under a stamp rather
//! than lose it. What a refusal never carries is a port or a flag read from
//! bytes that are not a transport header.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One packet's link, network and transport headers, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// IP protocol number: 1 ICMP, 6 TCP, 17 UDP, 58 ICMPv6.
    pub protocol: u8,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<u8>,
    /// Offset into the frame handed to [`decode`] at which the transport
    /// payload begins.
    pub payload_offset: usize,
    /// Bytes of transport payload present in the frame. Snaplen truncation
    /// makes this smaller than the IP header claims; the caller reports that,
    /// this module does not invent the missing bytes.
    pub payload_len: usize,
    /// The TCP sequence number, as the header states it, for a TCP segment and
    /// `None` for everything else.
    ///
    /// **Verbatim, and never adjusted.** It is the byte offset of this
    /// segment's payload in a 32-bit space that wraps, relative to an initial
    /// sequence number this packet does not carry, so nothing here can turn it
    /// into a stream offset: that is [`crate::reassemble`]'s job and it needs
    /// the SYN, or an explicit statement that the capture began mid-stream.
    /// Reporting it as an offset would be a number an examiner could act on
    /// that means nothing.
    pub tcp_seq: Option<u32>,
    /// The IPv4 header checksum field was zero and the header did not verify:
    /// the NIC had not computed it when the frame was captured (transmit
    /// offload on the capturing host). The header is structurally intact and
    /// the transport header behind it was read, so this is a qualification of
    /// the packet, not a refusal of it — every outbound packet on a host
    /// capture looks like this, and refusing them deletes one direction of
    /// every conversation. Always `false` for IPv6, which has no checksum.
    pub ipv4_checksum_unset: bool,
}

/// The outcome of decoding one frame. Three outcomes, not two: a frame that
/// carries no network layer and a frame this module could not decode are
/// different statements about the evidence, and a caller must not be able to
/// treat them as the same value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decode {
    /// Link, network and (where present) transport headers decoded.
    Headers(Decoded),
    /// A well-formed frame that carries no network layer at all (STP, LLDP,
    /// an ARP this build cannot read ...). An observation about the wire, not
    /// a failure.
    NoNetworkLayer,
    /// An ARP frame, which carries no network layer either — it is counted as
    /// one of those as well — and whose claims are read, because they are the
    /// only record of which hardware answered for which address. `None` where
    /// the frame is ARP and this build cannot read it: a hardware or protocol
    /// type that is not Ethernet and IPv4, or a frame cut inside the packet.
    Arp(Option<crate::arp::Observation>),
    /// Something the caller MUST record. Never silently equivalent to
    /// [`Decode::NoNetworkLayer`].
    Refused(Refusal),
}

/// Why a frame was not decoded. Each variant carries whatever was read before
/// the refusal so the caller can attribute the packet as far as the evidence
/// allows; [`Refusal::reason`] gives a stable token for the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A LINKTYPE this build does not decode, by number, so the refusal can say
    /// which decoder the examiner is missing.
    UnsupportedLinktype(u16),
    /// The frame ended before the link or network layer was complete — inside
    /// the link header, the IP header, or an IPv6 extension header: `need`
    /// bytes were required, `have` were captured. A cut *after* the network
    /// layer is [`Refusal::TransportTruncated`], which has addresses to carry.
    FrameTruncated { need: usize, have: usize },
    /// The header checksum did not verify and the field was not zero — the
    /// bytes are corrupt or forged. The addresses are still reported, as the
    /// bytes state them, so the caller can count the packet against an IP
    /// pair with a stamp rather than lose it. A *zero* field is not this: it
    /// is offload leaving the field unfilled, the packet decodes, and
    /// [`Decoded::ipv4_checksum_unset`] says so.
    Ipv4ChecksumFailed { src: IpAddr, dst: IpAddr },
    /// The link layer named an IP family the version nibble contradicts, or a
    /// length field no IP header can have. `detail` says which.
    MalformedIpHeader { detail: &'static str },
    /// More stacked 802.1Q tags than this build walks. There may be IP behind
    /// them; it was not looked at.
    VlanDepthExceeded,
    /// More chained IPv6 extension headers than this build walks. The
    /// transport header was never reached, so it is not named.
    ExtensionHeaderDepthExceeded,
    /// A non-initial IP fragment: the transport header is in another packet,
    /// so no ports or flags exist here and NONE may be inferred from payload
    /// bytes. Addresses and protocol are reported so the bytes can be
    /// attributed to the IP pair; `id` is the datagram's identification, in
    /// case a reassembler ever wants it.
    NonInitialFragment {
        src: IpAddr,
        dst: IpAddr,
        protocol: u8,
        id: u32,
        bytes_present: usize,
    },
    /// The IP layer said a transport header should be here and the frame
    /// ended first (snaplen). The capture, not the packet, is what is short.
    TransportTruncated {
        src: IpAddr,
        dst: IpAddr,
        protocol: u8,
    },
    /// The IP layer said a transport header should be here and its own
    /// declared length ends first: `declared` bytes follow the IP header, fewer
    /// than the transport header needs. The frame is intact; the datagram is
    /// not. Kept apart from [`Refusal::TransportTruncated`] because a packet
    /// that declares itself too short to hold what it claims to carry is a
    /// finding about the sender, not about the capture.
    DatagramTooShortForTransport {
        src: IpAddr,
        dst: IpAddr,
        protocol: u8,
        declared: usize,
    },
}

impl Refusal {
    /// A stable snake_case token naming the refusal, for records and counters.
    /// One token per variant: two variants sharing one would be the "same
    /// value for different findings" defect one layer up.
    pub fn reason(&self) -> &'static str {
        match self {
            Refusal::UnsupportedLinktype(_) => "unsupported_linktype",
            Refusal::FrameTruncated { .. } => "frame_truncated",
            Refusal::Ipv4ChecksumFailed { .. } => "ipv4_checksum_failed",
            Refusal::MalformedIpHeader { .. } => "malformed_ip_header",
            Refusal::VlanDepthExceeded => "vlan_depth_exceeded",
            Refusal::ExtensionHeaderDepthExceeded => "extension_header_depth_exceeded",
            Refusal::NonInitialFragment { .. } => "non_initial_fragment",
            Refusal::TransportTruncated { .. } => "transport_truncated",
            Refusal::DatagramTooShortForTransport { .. } => "datagram_too_short_for_transport",
        }
    }

    /// Whether the variant behind a [`Refusal::reason`] token carries
    /// addresses, for callers that hold only the token. Pinned against every
    /// variant's own [`Refusal::addresses`] by test, so a new variant cannot
    /// be guessed at by the emission layer.
    pub fn reason_carries_addresses(reason: &str) -> bool {
        matches!(
            reason,
            "ipv4_checksum_failed"
                | "non_initial_fragment"
                | "transport_truncated"
                | "datagram_too_short_for_transport"
        )
    }

    /// The IP pair the refused packet belongs to, where the refusal happened
    /// late enough to have read one.
    pub fn addresses(&self) -> Option<(IpAddr, IpAddr)> {
        match *self {
            Refusal::Ipv4ChecksumFailed { src, dst }
            | Refusal::NonInitialFragment { src, dst, .. }
            | Refusal::TransportTruncated { src, dst, .. }
            | Refusal::DatagramTooShortForTransport { src, dst, .. } => Some((src, dst)),
            Refusal::UnsupportedLinktype(_)
            | Refusal::FrameTruncated { .. }
            | Refusal::MalformedIpHeader { .. }
            | Refusal::VlanDepthExceeded
            | Refusal::ExtensionHeaderDepthExceeded => None,
        }
    }
}

const LINKTYPE_ETHERNET: u16 = 1;
const LINKTYPE_RAW: u16 = 101;
const LINKTYPE_LINUX_SLL: u16 = 113;

const ETHERNET_HEADER_LEN: usize = 14;
const LINUX_SLL_HEADER_LEN: usize = 16;
const VLAN_TAG_LEN: usize = 4;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;
const ETHERTYPE_VLAN_LEGACY: u16 = 0x9100;

const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_AH: u8 = 51;
const IPPROTO_DSTOPTS: u8 = 60;

/// Stacked VLAN tags are legal (QinQ) but a frame carrying more than a handful
/// is either not a frame or is one this build should refuse to guess at.
const MAX_VLAN_TAGS: usize = 3;

/// An IPv6 extension chain has no length field of its own, so a crafted packet
/// can chain headers until a walker gives up or spins. Real traffic uses one or
/// two; past this the honest answer is that the transport header was not found.
const MAX_IPV6_EXT_HEADERS: usize = 8;

/// Decode one packet's link+network+transport headers. See [`Decode`] for the
/// three outcomes; a LINKTYPE this build does not decode is a refusal by
/// number, which the caller must report rather than swallow.
pub fn decode(linktype: u16, frame: &[u8]) -> Decode {
    match linktype {
        LINKTYPE_ETHERNET => decode_ethernet(frame),
        // LINKTYPE_RAW has no link header: the frame starts at the IP version
        // nibble, and that nibble is the only thing that says which family.
        LINKTYPE_RAW => decode_ip_by_version(frame, 0),
        LINKTYPE_LINUX_SLL => decode_linux_sll(frame),
        other => Decode::Refused(Refusal::UnsupportedLinktype(other)),
    }
}

fn truncated(need: usize, frame: &[u8]) -> Decode {
    Decode::Refused(Refusal::FrameTruncated {
        need,
        have: frame.len(),
    })
}

fn malformed(detail: &'static str) -> Decode {
    Decode::Refused(Refusal::MalformedIpHeader { detail })
}

fn decode_ethernet(frame: &[u8]) -> Decode {
    let Some(mut ethertype) = be16(frame, 12) else {
        return truncated(ETHERNET_HEADER_LEN, frame);
    };
    let mut offset = ETHERNET_HEADER_LEN;

    // An 802.1Q tag is four bytes: two of tag control information and two that
    // hold the ethertype the untagged frame would have carried. Stopping at the
    // tag would drop every packet on a tagged trunk, which on a switch SPAN
    // capture is most of the evidence. `offset` is bounded by the constants,
    // not by the file, so the saturating adds cannot in practice saturate.
    for _ in 0..MAX_VLAN_TAGS {
        if !is_vlan_tag(ethertype) {
            break;
        }
        let tag_end = offset.saturating_add(VLAN_TAG_LEN);
        let Some(inner) = be16(frame, offset.saturating_add(2)) else {
            return truncated(tag_end, frame);
        };
        ethertype = inner;
        offset = tag_end;
    }
    if is_vlan_tag(ethertype) {
        return Decode::Refused(Refusal::VlanDepthExceeded);
    }

    match ethertype {
        ETHERTYPE_IPV4 => decode_ipv4(frame, offset),
        ETHERTYPE_IPV6 => decode_ipv6(frame, offset),
        // ARP carries no IP layer and is read anyway: its claims are the only
        // record of which hardware answered for which address. The Ethernet
        // header's own source address goes with it, because a forger who sets
        // only the address inside the packet leaves the two at odds.
        ETHERTYPE_ARP => Decode::Arp(decode_arp(frame, offset, ethernet_source(frame))),
        // STP, LLDP and the rest are intact frames that simply have no IP
        // layer. Calling that a refusal would make every capture look partly
        // undecodable and devalue the refusals that mean something.
        _ => Decode::NoNetworkLayer,
    }
}

/// An Ethernet frame's own source address, which an ARP claim is compared
/// against. `None` for a link layer that has none.
fn ethernet_source(frame: &[u8]) -> Option<[u8; 6]> {
    let bytes = frame.get(6..12)?;
    let mut out = [0u8; 6];
    out.copy_from_slice(bytes);
    Some(out)
}

/// An ARP packet's claims, for the one hardware and protocol pair ARP is used
/// with in practice.
///
/// `None` for anything else — a hardware type that is not Ethernet, a protocol
/// that is not IPv4, address lengths that disagree with those, or a frame cut
/// inside the packet. The caller counts it as an ARP frame this build could not
/// read, which is a different statement from a segment with no ARP on it.
fn decode_arp(
    frame: &[u8],
    offset: usize,
    frame_source_mac: Option<[u8; 6]>,
) -> Option<crate::arp::Observation> {
    let packet = frame.get(offset..offset.checked_add(28)?)?;
    let hardware_type = u16::from_be_bytes([packet[0], packet[1]]);
    let protocol_type = u16::from_be_bytes([packet[2], packet[3]]);
    // Ethernet hardware, IPv4 protocol, and the address lengths those imply.
    // A packet whose lengths disagree with its types is one whose fields are
    // not where this reader would look for them.
    if hardware_type != 1 || protocol_type != ETHERTYPE_IPV4 || packet[4] != 6 || packet[5] != 4 {
        return None;
    }
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&packet[8..14]);
    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&packet[18..24]);
    Some(crate::arp::Observation {
        operation: u16::from_be_bytes([packet[6], packet[7]]),
        sender_mac,
        sender_ip: std::net::Ipv4Addr::new(packet[14], packet[15], packet[16], packet[17]),
        target_mac,
        target_ip: std::net::Ipv4Addr::new(packet[24], packet[25], packet[26], packet[27]),
        frame_source_mac,
    })
}

fn is_vlan_tag(ethertype: u16) -> bool {
    matches!(
        ethertype,
        ETHERTYPE_VLAN | ETHERTYPE_QINQ | ETHERTYPE_VLAN_LEGACY
    )
}

/// The Linux "cooked capture" header `tcpdump -i any` produces: 16 bytes, two
/// more than Ethernet's, ending in the same ethertype values.
fn decode_linux_sll(frame: &[u8]) -> Decode {
    match be16(frame, 14) {
        Some(ETHERTYPE_IPV4) => decode_ipv4(frame, LINUX_SLL_HEADER_LEN),
        Some(ETHERTYPE_IPV6) => decode_ipv6(frame, LINUX_SLL_HEADER_LEN),
        // ARP is read here as well as on Ethernet. `tcpdump -i any` is the
        // most common way a Linux capture is made, and a decoder that read
        // ARP on one link type and not the other would hand an examiner an
        // empty address inventory for half the captures in the world — with
        // nothing saying why.
        Some(ETHERTYPE_ARP) => Decode::Arp(decode_arp(
            frame,
            LINUX_SLL_HEADER_LEN,
            linux_sll_source(frame),
        )),
        Some(_) => Decode::NoNetworkLayer,
        None => truncated(LINUX_SLL_HEADER_LEN, frame),
    }
}

/// The link-layer source address a cooked-capture header carries, where it
/// carries a six-byte one.
///
/// The header holds the address length at bytes 4..6 and the address itself,
/// padded to eight bytes, at 6..14. Anything but a six-byte Ethernet address
/// is not compared against an ARP claim, because the comparison would be
/// between two different kinds of thing.
fn linux_sll_source(frame: &[u8]) -> Option<[u8; 6]> {
    if be16(frame, 4)? != 6 {
        return None;
    }
    let bytes = frame.get(6..12)?;
    let mut out = [0u8; 6];
    out.copy_from_slice(bytes);
    Some(out)
}

/// A RAW frame is IP by definition, so a version nibble that is neither family
/// is a header we cannot read — never a frame without one.
fn decode_ip_by_version(frame: &[u8], offset: usize) -> Decode {
    let Some(first) = frame.get(offset) else {
        return truncated(offset.saturating_add(IPV4_MIN_HEADER_LEN), frame);
    };
    match first >> 4 {
        4 => decode_ipv4(frame, offset),
        6 => decode_ipv6(frame, offset),
        _ => malformed("IP version nibble is neither 4 nor 6"),
    }
}

fn decode_ipv4(frame: &[u8], offset: usize) -> Decode {
    let Some(&first) = frame.get(offset) else {
        return truncated(offset.saturating_add(IPV4_MIN_HEADER_LEN), frame);
    };
    if first >> 4 != 4 {
        return malformed("IP version nibble is not 4 under an IPv4 link header");
    }
    let ihl = usize::from(first & 0x0f);
    if ihl < 5 {
        return malformed("IPv4 IHL below the five words a header occupies");
    }
    // ihl is four bits, so header_len is at most 60; offset is at most the
    // link header plus three VLAN tags. Neither comes from a length field.
    let header_len = ihl * 4;
    let header_end = offset.saturating_add(header_len);
    let Some(header) = frame.get(offset..header_end) else {
        return truncated(header_end, frame);
    };

    let src = IpAddr::V4(Ipv4Addr::new(
        header[12], header[13], header[14], header[15],
    ));
    let dst = IpAddr::V4(Ipv4Addr::new(
        header[16], header[17], header[18], header[19],
    ));

    // `seance_bulk::net` accepts a carved IPv4 header only when its checksum
    // verifies, because there the checksum is the only evidence the bytes are
    // a packet at all. Inside a capture the container framing has already
    // established that, so a failure is a finding to record, not a reason to
    // delete the packet: it is refused with its addresses. A zero field is
    // not a failure at all — the NIC had not filled it in yet, which is every
    // outbound packet on a host capture — and the header it sits in is intact,
    // so the packet decodes and carries the fact. "Not computed" and
    // "corrupt" are different findings, and only the second is a refusal.
    let mut ipv4_checksum_unset = false;
    if ones_complement_sum(header) != 0xffff {
        if header[10] == 0 && header[11] == 0 {
            ipv4_checksum_unset = true;
        } else {
            return Decode::Refused(Refusal::Ipv4ChecksumFailed { src, dst });
        }
    }

    let total_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let protocol = header[9];

    // The claimed length is what bounds the payload, not what is present: an
    // Ethernet frame padded up to its 60-byte minimum carries bytes after the
    // IP packet that belong to no one. A total length of zero is the exception
    // — segmentation offload leaves the field unset on locally captured frames
    // — and there the bytes present are all we have to go on, which `None`
    // says. A nonzero length shorter than the header itself is not a claim
    // about anything.
    let claimed = match total_len {
        0 => None,
        n if n < header_len => {
            return malformed("IPv4 total length shorter than its own header");
        }
        n => Some(n - header_len),
    };

    // Bytes 6..8 are three flag bits and a 13-bit fragment offset in 8-byte
    // units. Any nonzero offset means the transport header is in another
    // packet and the bytes that follow are the middle of a payload.
    let fragment_offset = u16::from_be_bytes([header[6], header[7]]) & 0x1fff;
    if fragment_offset != 0 {
        let present = frame.len().saturating_sub(header_end);
        return Decode::Refused(Refusal::NonInitialFragment {
            src,
            dst,
            protocol,
            id: u32::from(u16::from_be_bytes([header[4], header[5]])),
            bytes_present: present.min(claimed.unwrap_or(present)),
        });
    }

    decode_transport(
        frame,
        header_end,
        protocol,
        src,
        dst,
        claimed,
        ipv4_checksum_unset,
    )
}

fn decode_ipv6(frame: &[u8], offset: usize) -> Decode {
    let header_end = offset.saturating_add(IPV6_HEADER_LEN);
    let Some(header) = frame.get(offset..header_end) else {
        return truncated(header_end, frame);
    };
    if header[0] >> 4 != 6 {
        return malformed("IP version nibble is not 6 under an IPv6 link header");
    }
    // Payload Length zero means a jumbogram or, far more often, a locally
    // captured offload frame — the same carve-out IPv4 has for total length
    // zero, and without it every outbound IPv6 payload on a host capture
    // reads as empty and no IPv6 DNS reaches the decoder at all.
    let mut claimed = match u16::from_be_bytes([header[4], header[5]]) {
        0 => None,
        n => Some(usize::from(n)),
    };
    let mut next = header[6];
    let Ok(src_octets) = <[u8; 16]>::try_from(&header[8..24]) else {
        return malformed("IPv6 source address slice is not sixteen bytes");
    };
    let Ok(dst_octets) = <[u8; 16]>::try_from(&header[24..40]) else {
        return malformed("IPv6 destination address slice is not sixteen bytes");
    };
    let src = IpAddr::V6(Ipv6Addr::from(src_octets));
    let dst = IpAddr::V6(Ipv6Addr::from(dst_octets));

    // IPv6 puts the transport header behind a chain rather than at a fixed
    // offset. A decoder that reads next_header once and stops reports a
    // hop-by-hop options header as the "protocol" and loses every conversation
    // that carries a router alert — an absence that reads as silence on the wire.
    let mut cursor = header_end;
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        if !is_ipv6_extension(next) {
            break;
        }
        // Every extension header starts with its own next-header byte, then a
        // length whose unit depends on which header it is.
        let Some(&after) = frame.get(cursor) else {
            return truncated(cursor.saturating_add(2), frame);
        };
        let ext_len = match next {
            IPPROTO_FRAGMENT => {
                let frag_end = cursor.saturating_add(8);
                let Some(fragment) = frame.get(cursor..frag_end) else {
                    return truncated(frag_end, frame);
                };
                let raw = u16::from_be_bytes([fragment[2], fragment[3]]);
                if raw & 0xfff8 != 0 {
                    // A non-first fragment has no transport header in it at
                    // all. Reporting the ports from wherever the payload
                    // happens to start would invent a connection.
                    let present = frame.len().saturating_sub(frag_end);
                    let rest = claimed.map(|c| c.saturating_sub(8)).unwrap_or(present);
                    return Decode::Refused(Refusal::NonInitialFragment {
                        src,
                        dst,
                        protocol: after,
                        id: u32::from_be_bytes([
                            fragment[4],
                            fragment[5],
                            fragment[6],
                            fragment[7],
                        ]),
                        bytes_present: present.min(rest),
                    });
                }
                8
            }
            IPPROTO_AH => {
                // RFC 4302: length in 4-byte units, not counting the first two
                // — a different rule from every other extension header, so a
                // walker that lumps it in with them lands the transport header
                // in the wrong place and reads the ICV as ports.
                let Some(&units) = frame.get(cursor.saturating_add(1)) else {
                    return truncated(cursor.saturating_add(2), frame);
                };
                (usize::from(units) + 2) * 4
            }
            _ => {
                // Hop-by-hop, routing, destination options: length in 8-byte
                // units, not counting the first eight.
                let Some(&units) = frame.get(cursor.saturating_add(1)) else {
                    return truncated(cursor.saturating_add(2), frame);
                };
                (usize::from(units) + 1) * 8
            }
        };
        // `units` is one byte, so ext_len is at most 2048 and the sum cannot
        // overflow a usize that already indexes the frame.
        let ext_end = cursor.saturating_add(ext_len);
        if ext_end > frame.len() {
            // The chain ran off the end of what was captured before the
            // network layer was complete: a frame truncation, with the counts.
            return truncated(ext_end, frame);
        }
        next = after;
        cursor = ext_end;
        claimed = claimed.map(|c| c.saturating_sub(ext_len));
    }
    if is_ipv6_extension(next) {
        // Longer than we are willing to walk: refuse to name a transport we did
        // not reach rather than report the last extension header as one.
        return Decode::Refused(Refusal::ExtensionHeaderDepthExceeded);
    }

    decode_transport(frame, cursor, next, src, dst, claimed, false)
}

fn is_ipv6_extension(protocol: u8) -> bool {
    matches!(
        protocol,
        IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_FRAGMENT | IPPROTO_AH | IPPROTO_DSTOPTS
    )
}

/// Decode the transport header at `start`. `claimed` is how many bytes the IP
/// layer says follow, or `None` when it declared nothing (offload). Bytes
/// present always bound bytes reported: the claimed length is compared against
/// the frame, never used to slice it. `ipv4_checksum_unset` is carried
/// through untouched: it is the IP layer's finding about its own header.
fn decode_transport(
    frame: &[u8],
    start: usize,
    protocol: u8,
    src: IpAddr,
    dst: IpAddr,
    claimed: Option<usize>,
    ipv4_checksum_unset: bool,
) -> Decode {
    let present = frame.len().saturating_sub(start);
    let available = present.min(claimed.unwrap_or(present));

    // The header must lie within both the frame and the IP datagram. Reading
    // it out of the frame alone lets Ethernet padding past a short datagram
    // be reported as ports and flags — a service that was never contacted.
    // Which bound ended first is the difference between a short capture and a
    // short packet, and the refusal says which.
    let short = |header_len: usize| -> Option<Decode> {
        if available >= header_len {
            return None;
        }
        Some(Decode::Refused(match claimed {
            Some(declared) if declared < header_len && declared <= present => {
                Refusal::DatagramTooShortForTransport {
                    src,
                    dst,
                    protocol,
                    declared,
                }
            }
            _ => Refusal::TransportTruncated { src, dst, protocol },
        }))
    };

    match protocol {
        IPPROTO_TCP => {
            if let Some(refusal) = short(TCP_MIN_HEADER_LEN) {
                return refusal;
            }
            let Some(header) = frame.get(start..start.saturating_add(TCP_MIN_HEADER_LEN)) else {
                return Decode::Refused(Refusal::TransportTruncated { src, dst, protocol });
            };
            // The data offset is the high nibble of byte 12, in 4-byte units. A
            // value below five is malformed; clamping to the fixed header keeps
            // the payload bounds sane without inventing option bytes.
            let header_len = (usize::from(header[12] >> 4) * 4).max(TCP_MIN_HEADER_LEN);
            let (payload_offset, payload_len) = payload_bounds(frame, start, header_len, available);
            Decode::Headers(Decoded {
                src,
                dst,
                protocol,
                src_port: Some(u16::from_be_bytes([header[0], header[1]])),
                dst_port: Some(u16::from_be_bytes([header[2], header[3]])),
                tcp_flags: Some(header[13]),
                tcp_seq: Some(u32::from_be_bytes([
                    header[4], header[5], header[6], header[7],
                ])),
                payload_offset,
                payload_len,
                ipv4_checksum_unset,
            })
        }
        IPPROTO_UDP => {
            if let Some(refusal) = short(UDP_HEADER_LEN) {
                return refusal;
            }
            let Some(header) = frame.get(start..start.saturating_add(UDP_HEADER_LEN)) else {
                return Decode::Refused(Refusal::TransportTruncated { src, dst, protocol });
            };
            // RFC 768's length covers the header too, and it is a second claim
            // about the same bytes: take whichever of it and the IP layer's
            // claim is smaller, then bound both by what was captured. A value
            // below eight is impossible and is ignored rather than honoured.
            let udp_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
            let bounded = if udp_len >= UDP_HEADER_LEN {
                available.min(udp_len)
            } else {
                available
            };
            let (payload_offset, payload_len) =
                payload_bounds(frame, start, UDP_HEADER_LEN, bounded);
            Decode::Headers(Decoded {
                src,
                dst,
                protocol,
                src_port: Some(u16::from_be_bytes([header[0], header[1]])),
                dst_port: Some(u16::from_be_bytes([header[2], header[3]])),
                // UDP has no flags. Reporting a byte from the payload as flags
                // would give the flow table a TCP state it never observed.
                tcp_flags: None,
                tcp_seq: None,
                payload_offset,
                payload_len,
                ipv4_checksum_unset,
            })
        }
        // ICMP and everything else: no ports exist to report. A decoder that
        // keys off "is there payload" rather than off the protocol number
        // reports the first four bytes of an echo request as a port pair and
        // invents a service that was never contacted.
        _ => Decode::Headers(Decoded {
            src,
            dst,
            protocol,
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            tcp_seq: None,
            payload_offset: start.min(frame.len()),
            payload_len: available,
            ipv4_checksum_unset,
        }),
    }
}

/// Where the payload starts and how much of it the file actually holds. When the
/// transport header's options run past the captured bytes the payload is empty
/// and begins at the end of the frame, so `offset + len` is always in evidence.
fn payload_bounds(
    frame: &[u8],
    transport_start: usize,
    header_len: usize,
    available: usize,
) -> (usize, usize) {
    match transport_start.checked_add(header_len) {
        Some(start) if start <= frame.len() => {
            let present = frame.len() - start;
            (start, present.min(available.saturating_sub(header_len)))
        }
        _ => (frame.len(), 0),
    }
}

/// RFC 1071: fold the header's 16-bit big-endian words and complement. A header
/// carrying its own correct checksum sums to 0xffff, which is what callers test.
/// The accumulator cannot overflow — an IPv4 header is at most 60 bytes, so at
/// most thirty additions of 0xffff — and the assertion keeps that true for any
/// caller that comes later.
fn ones_complement_sum(header: &[u8]) -> u16 {
    debug_assert!(header.len() <= 60, "only IPv4 headers are summed here");
    let mut sum: u32 = 0;
    let (pairs, tail) = header.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let [odd] = tail {
        sum += u32::from(*odd) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    let pair = bytes.get(at..end)?;
    Some(u16::from_be_bytes([pair[0], pair[1]]))
}

/// A decoded DNS message. Only the parts that turn an address into a name the
/// evidence itself proves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    /// The TC bit: the server itself attesting that it cut the answer set to
    /// fit the transport. Distinct from `truncated`, which is the capture's
    /// cut, not the server's — a TC response whose every byte was captured is
    /// complete as evidence of what the server sent.
    pub tc: bool,
    /// The opcode, bits 11..15 of the flags word: 0 is a standard query or
    /// its response, 5 is a dynamic UPDATE (RFC 2136), 4 a NOTIFY. Only
    /// opcode 0 carries questions and answers; an UPDATE's sections are zone,
    /// prerequisite and update, and reading them as answers refuses a message
    /// that is well-formed. Ten of the 2,650 port-53 messages in the DFIR
    /// Madness capture are UPDATEs — hosts registering their names with the
    /// domain controller — and were reported as "a layout the decoder refused
    /// to guess at" until this field existed.
    pub opcode: u8,
    /// The response code, the low four bits of the flags word: the server's
    /// own statement of why a response has no answers. 3 is NXDOMAIN, "the
    /// name does not exist", which is a finding and not an absence; 0 on a
    /// query, where it means nothing.
    pub rcode: u8,
    pub questions: Vec<String>,
    pub answers: Vec<DnsAnswer>,
    /// The bytes ended before the counted records did. What is in `questions`
    /// and `answers` was fully read; what the header counted beyond it was not,
    /// and a message with this set must not be reported as "asked and got no
    /// answer".
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: u16,
    pub data: String,
}

/// A compression pointer must point strictly backwards, so this cap is belt and
/// braces — but a decoder is one refactor away from losing that rule, and the
/// cost of losing it is a capture that hangs the ingest.
const MAX_DNS_POINTER_JUMPS: usize = 16;

/// The longest name RFC 1035 allows, in wire bytes. Escaping can make the text
/// longer, so this bounds the labels consumed rather than the string produced.
const MAX_DNS_NAME_BYTES: usize = 255;

/// Rdata we do not decode is shown as hex, up to this many bytes, so an examiner
/// sees the bytes without a report carrying 64 KB of one record.
const MAX_RDATA_HEX_BYTES: usize = 64;

const DNS_HEADER_LEN: usize = 12;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_NS: u16 = 2;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_PTR: u16 = 12;
const DNS_TYPE_AAAA: u16 = 28;

/// Why a name could not be read. The two are kept apart because they mean
/// opposite things for the rest of the message: a cut leaves what came before
/// it standing, a lie about the layout discredits all of it.
enum NameError {
    /// The walk ran past the end of the bytes it was allowed to read.
    PastEnd,
    /// A pointer that does not go backwards, a reserved label type, a name
    /// longer than the protocol allows, or a walk past a bound that lies
    /// inside the message.
    Malformed,
}

/// Decode a DNS message from a UDP payload. `None` when the bytes are not a DNS
/// message at all, or when the message contradicts itself — a pointer loop, an
/// A record that is not four bytes — because a message that lies about its
/// layout cannot be trusted for the parts that seemed to parse. A message the
/// *capture* cut short is different: the header, and every question and answer
/// read before the cut, are evidence and are returned, with `truncated` set.
/// Snaplen makes that the common case — `tcpdump -s 96` leaves 54 bytes for
/// DNS — and a decoder that dropped the whole message would empty the DNS tier
/// of every such capture and say nothing about why.
pub fn decode_dns(payload: &[u8]) -> Option<DnsMessage> {
    let id = be16(payload, 0)?;
    let flags = be16(payload, 2)?;
    let qdcount = be16(payload, 4)?;
    let ancount = be16(payload, 6)?;
    // nscount and arcount occupy bytes 8..12; the header is not a header
    // without them even though this decode ignores those sections.
    be16(payload, 8)?;
    be16(payload, 10)?;

    let mut msg = DnsMessage {
        id,
        is_response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0x000f) as u8,
        tc: flags & 0x0200 != 0,
        rcode: (flags & 0x000f) as u8,
        questions: Vec::new(),
        answers: Vec::new(),
        truncated: false,
    };

    // Only a standard query has question and answer sections. Anything else
    // is handed back as what it is — a message of that opcode — with no
    // attempt to read sections that mean something different.
    if msg.opcode != 0 {
        return Some(msg);
    }

    let mut pos = DNS_HEADER_LEN;
    for _ in 0..qdcount {
        let (name, after) = match read_name(payload, pos, payload.len()) {
            Ok(read) => read,
            Err(NameError::PastEnd) => return Some(cut(msg)),
            Err(NameError::Malformed) => return None,
        };
        // QTYPE and QCLASS. Their absence means the question is cut, and a
        // question without them is not yet a name anyone asked for.
        let next = after.checked_add(4)?;
        if next > payload.len() {
            return Some(cut(msg));
        }
        msg.questions.push(name);
        pos = next;
    }

    for _ in 0..ancount {
        let (name, after) = match read_name(payload, pos, payload.len()) {
            Ok(read) => read,
            Err(NameError::PastEnd) => return Some(cut(msg)),
            Err(NameError::Malformed) => return None,
        };
        let Some(rtype) = be16(payload, after) else {
            return Some(cut(msg));
        };
        // CLASS at after+2 and TTL at after+4 are read past rather than kept.
        let Some(rdlength) = be16(payload, after.checked_add(8)?) else {
            return Some(cut(msg));
        };
        let rdata_start = after.checked_add(10)?;
        let rdata_end = rdata_start.checked_add(usize::from(rdlength))?;
        let Some(rdata) = payload.get(rdata_start..rdata_end) else {
            return Some(cut(msg));
        };
        let data = format_rdata(rtype, payload, rdata_start, rdata_end, rdata)?;
        msg.answers.push(DnsAnswer { name, rtype, data });
        pos = rdata_end;
    }

    Some(msg)
}

fn cut(mut msg: DnsMessage) -> DnsMessage {
    msg.truncated = true;
    msg
}

/// Read a name at `start`, following compression pointers. Returns the text and
/// the offset just past the name *in the walk that started at `start`* — which
/// for a compressed name is two bytes on, not wherever the pointer led.
///
/// `limit` bounds the inline part of the walk, the labels read before any
/// pointer: for a question or answer name that is the whole message, for a
/// name inside rdata it is the end of that rdata. Running past `limit` is
/// [`NameError::PastEnd`], which the caller reads as a cut when `limit` is the
/// end of the bytes and as a lie when it is not. After a pointer the walk is
/// somewhere earlier in the message, and running off the message from there
/// is always malformed: those bytes were present.
fn read_name(msg: &[u8], start: usize, limit: usize) -> Result<(String, usize), NameError> {
    let limit = limit.min(msg.len());
    let mut out = String::new();
    let mut pos = start;
    let mut consumed = 0usize;
    let mut jumps = 0usize;
    // Set by the first pointer: everything after it is read out of line, so the
    // enclosing record continues from just past that pointer.
    let mut end: Option<usize> = None;

    loop {
        let (bound, overrun) = match end {
            None => (limit, NameError::PastEnd),
            Some(_) => (msg.len(), NameError::Malformed),
        };
        if pos >= bound {
            return Err(overrun);
        }
        let len = *msg.get(pos).ok_or(NameError::Malformed)?;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    let after = match end {
                        Some(e) => e,
                        None => pos.checked_add(1).ok_or(NameError::Malformed)?,
                    };
                    return Ok((out, after));
                }
                let label_start = pos.checked_add(1).ok_or(NameError::Malformed)?;
                let label_end = label_start
                    .checked_add(usize::from(len))
                    .ok_or(NameError::Malformed)?;
                if label_end > bound {
                    return Err(overrun);
                }
                let label = msg
                    .get(label_start..label_end)
                    .ok_or(NameError::Malformed)?;
                consumed = consumed
                    .checked_add(usize::from(len))
                    .and_then(|c| c.checked_add(1))
                    .ok_or(NameError::Malformed)?;
                if consumed > MAX_DNS_NAME_BYTES {
                    return Err(NameError::Malformed);
                }
                if !out.is_empty() {
                    out.push('.');
                }
                push_label(&mut out, label);
                pos = label_end;
            }
            0xC0 => {
                let low_at = pos.checked_add(1).ok_or(NameError::Malformed)?;
                if low_at >= bound {
                    return Err(overrun);
                }
                let low = *msg.get(low_at).ok_or(NameError::Malformed)?;
                let target = (usize::from(len & 0x3f) << 8) | usize::from(low);
                if end.is_none() {
                    end = Some(low_at.checked_add(1).ok_or(NameError::Malformed)?);
                }
                // RFC 1035 pointers name a prior occurrence, so a target at or
                // after the pointer itself is not a name — it is a loop, and a
                // hostile capture is two bytes away from hanging the ingest of
                // the whole case. Both the self-pointer and the two-offset cycle
                // die here.
                if target >= pos {
                    return Err(NameError::Malformed);
                }
                jumps = jumps.checked_add(1).ok_or(NameError::Malformed)?;
                if jumps > MAX_DNS_POINTER_JUMPS {
                    return Err(NameError::Malformed);
                }
                pos = target;
            }
            // 0x40 and 0x80 are reserved label types. Guessing at one would be
            // guessing at a layout, which this crate does not do.
            _ => return Err(NameError::Malformed),
        }
    }
}

/// Append one label, escaping anything that is not printable ASCII and the dot
/// that would otherwise read as a label separator. DNS labels are arbitrary
/// bytes — tunnelling and exfiltration make full use of that — and a name shown
/// with the odd bytes silently replaced is a name the packet does not contain.
fn push_label(out: &mut String, label: &[u8]) {
    for &b in label {
        match b {
            b'.' => out.push_str("\\."),
            b'\\' => out.push_str("\\\\"),
            0x21..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
}

/// Render one answer's rdata. `None` rejects the whole message: an A record
/// whose rdata is not four bytes is not an A record, and reporting it as an
/// address would mean choosing four bytes to call one.
fn format_rdata(
    rtype: u16,
    msg: &[u8],
    rdata_start: usize,
    rdata_end: usize,
    rdata: &[u8],
) -> Option<String> {
    match rtype {
        DNS_TYPE_A => {
            let octets = <[u8; 4]>::try_from(rdata).ok()?;
            Some(Ipv4Addr::from(octets).to_string())
        }
        DNS_TYPE_AAAA => {
            let octets = <[u8; 16]>::try_from(rdata).ok()?;
            Some(Ipv6Addr::from(octets).to_string())
        }
        DNS_TYPE_NS | DNS_TYPE_CNAME | DNS_TYPE_PTR => {
            // These rdata are names whose compression pointers are offsets into
            // the whole message, so the name is read from `msg` — but its
            // inline labels must lie inside this record's rdata. A name that
            // runs past RDLENGTH would be assembled from the next record's
            // bytes and reported as a resolution this record does not contain;
            // that is RDLENGTH lying, and the message is refused as a whole.
            let (name, _) = read_name(msg, rdata_start, rdata_end).ok()?;
            // The root name encodes as a single zero byte and reads as empty.
            Some(if name.is_empty() {
                ".".to_string()
            } else {
                name
            })
        }
        _ => Some(hex_rdata(rdata)),
    }
}

fn hex_rdata(rdata: &[u8]) -> String {
    if rdata.is_empty() {
        // Never empty: an empty `data` is indistinguishable from a field we
        // failed to fill in, and the caller's test for that is the same test.
        return "(no rdata)".to_string();
    }
    let shown = rdata.len().min(MAX_RDATA_HEX_BYTES);
    let mut out = String::with_capacity(shown * 2 + 16);
    for &b in &rdata[..shown] {
        out.push_str(&format!("{b:02x}"));
    }
    if shown < rdata.len() {
        out.push_str(&format!("... ({} bytes)", rdata.len()));
    }
    out
}

#[cfg(test)]
#[path = "decode_tests.rs"]
mod decode_tests;
