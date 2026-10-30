//! The address-resolution claims a capture holds (`ROADMAP` §4.3 stage 2).
//!
//! # Why ARP is worth reading
//!
//! ARP is the only record of which hardware answered for which address on a
//! segment, and it names hosts that sent no IP traffic at all — a machine that
//! only ever asked "who has the gateway" is in the capture and in no flow.
//! Two things follow from it that nothing else in a capture gives:
//!
//! * the **inventory**: address to hardware address, with the times each claim
//!   was seen, which is what turns "10.42.85.10 did this" into "this machine
//!   did this";
//! * a **contested address**: one address claimed by two hardware addresses.
//!   That is the signature of ARP cache poisoning — an attacker on the segment
//!   answering for the gateway.
//!
//! # ARP does not authenticate, so every row here is a claim
//!
//! Nothing in the protocol proves a sender owns the address it announces: the
//! reply is believed because it arrived. So this module records what was
//! claimed, by whom and when, and reaches no verdict — a contested address is
//! also what a failover pair, a DHCP lease handed to another machine, a
//! replaced network card and a dual-homed host look like, and the record says
//! so beside every conflict it reports.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// Addresses this build will list. A scanned /16 reaches far more; past this
/// they are counted, and the count is on the record.
pub const MAX_ADDRESSES: usize = 4096;

/// Hardware addresses listed against one address. More than a couple is
/// already remarkable.
pub const MAX_MACS_PER_ADDRESS: usize = 16;

/// Addresses recorded as having been asked about.
pub const MAX_ADDRESSES_ASKED_ABOUT: usize = 4096;

/// Frame sources kept per claim, for the disagreement they evidence.
const MAX_FRAME_SOURCES: usize = 8;

/// One ARP packet, as read by [`crate::decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// 1 request, 2 reply, 3 and 4 the reverse-ARP pair.
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
    /// The Ethernet header's own source address, where the link layer has
    /// one. A forger who sets only the address inside the ARP packet leaves
    /// the two at odds.
    pub frame_source_mac: Option<[u8; 6]>,
}

/// One hardware address's claim on one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub mac: [u8; 6],
    pub first_seen: Option<u64>,
    pub last_seen: Option<u64>,
    pub packets: u64,
    pub in_requests: u64,
    pub in_replies: u64,
    /// Announcements nobody asked for: the sender and target address are the
    /// same.
    pub gratuitous: u64,
    /// Packets whose frame source disagreed with this claim.
    pub frame_source_disagreed: u64,
    /// The frame sources that disagreed, which are the other half of that
    /// fact.
    pub frame_sources: Vec<[u8; 6]>,
}

impl Claim {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "mac": mac_label(self.mac),
            "first_seen": self.first_seen.map(crate::emit::rfc3339_micros),
            "last_seen": self.last_seen.map(crate::emit::rfc3339_micros),
            "packets": self.packets,
            "in_requests": self.in_requests,
            "in_replies": self.in_replies,
            "gratuitous_announcements": self.gratuitous,
            "frame_source_disagreed": self.frame_source_disagreed,
            "disagreeing_frame_sources": self.frame_sources.iter().map(|m| mac_label(*m))
                .collect::<Vec<_>>(),
        })
    }
}

/// Every claim on one address, in the order the claims were first seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub ip: Ipv4Addr,
    pub claims: Vec<Claim>,
    /// Hardware addresses that claimed this address beyond
    /// [`MAX_MACS_PER_ADDRESS`], which are counted and not listed.
    pub macs_beyond_cap: usize,
}

impl Binding {
    /// Whether more than one hardware address claimed this address.
    pub fn contested(&self) -> bool {
        self.claims.len() > 1 || self.macs_beyond_cap > 0
    }

    /// When the contest began: the first time a *second* hardware address was
    /// seen claiming this address. `None` where it is not contested, or where
    /// no packet carried a timestamp.
    pub fn contested_from(&self) -> Option<u64> {
        if !self.contested() {
            return None;
        }
        let mut firsts: Vec<u64> = self.claims.iter().filter_map(|c| c.first_seen).collect();
        firsts.sort_unstable();
        firsts.get(1).copied()
    }

    /// The total across every claim.
    pub fn packets(&self) -> u64 {
        self.claims
            .iter()
            .fold(0u64, |a, c| a.saturating_add(c.packets))
    }

    /// The sentence this binding carries. It is on every one, contested or
    /// not, because "192.168.1.1 is 00:1a:2b:3c:4d:5e" reads as a fact and is
    /// a claim.
    pub fn statement(&self) -> &'static str {
        if self.contested() {
            "MORE THAN ONE HARDWARE ADDRESS CLAIMED THIS ADDRESS. ARP does not authenticate: a \
             reply is believed because it arrived, so this is the signature of ARP cache \
             poisoning -- and it is equally what a failover pair, a DHCP lease handed to another \
             machine, a replaced network card, a virtual machine moved between hosts and a \
             dual-homed host look like. The claims and their times are above; no verdict is \
             reached here."
        } else {
            "What this host CLAIMED. ARP does not authenticate, so a binding is an \
             announcement that was believed because it arrived, not a proven fact about the \
             hardware at this address."
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ip": self.ip.to_string(),
            "macs": self.claims.iter().map(|c| mac_label(c.mac)).collect::<Vec<_>>(),
            "claims": self.claims.iter().map(Claim::to_json).collect::<Vec<_>>(),
            "contested": self.contested(),
            "contested_from": self.contested_from().map(crate::emit::rfc3339_micros),
            "macs_beyond_cap": self.macs_beyond_cap,
            "packets": self.packets(),
            "statement": self.statement(),
        })
    }
}

/// Every claim a capture's ARP holds.
#[derive(Debug, Clone, Default)]
pub struct ArpTable {
    bindings: BTreeMap<Ipv4Addr, Binding>,
    by_mac: BTreeMap<[u8; 6], Vec<Ipv4Addr>>,
    /// Addresses a request asked about. A question, not a binding: nobody
    /// claimed these, and one that never appears as a sender is an address
    /// nothing answered for.
    pub addresses_asked_about: Vec<Ipv4Addr>,
    pub requests: u64,
    pub replies: u64,
    /// Operations that are neither: the reverse-ARP pair, and anything else.
    pub other_operations: u64,
    /// Requests from the unspecified address: a host checking whether an
    /// address is free, which claims nothing.
    pub probes: u64,
    pub gratuitous: u64,
    pub frame_source_disagreements: u64,
    pub frames: u64,
    pub addresses_beyond_cap: u64,
    pub addresses_asked_about_beyond_cap: u64,
}

impl ArpTable {
    pub fn new() -> Self {
        ArpTable::default()
    }

    /// Record one packet.
    pub fn observe(&mut self, observation: &Observation, ts_micros: Option<u64>) {
        self.frames = self.frames.saturating_add(1);
        match observation.operation {
            1 => self.requests = self.requests.saturating_add(1),
            2 => self.replies = self.replies.saturating_add(1),
            _ => self.other_operations = self.other_operations.saturating_add(1),
        }
        // An announcement nobody asked for. RFC 5227 §3 specifies it as a
        // REQUEST whose sender and target protocol address are the same —
        // which is the form Windows, `arping -U` and most ARP-spoofing tools
        // send — and the gratuitous-reply form is the other one. Counting
        // only replies misses the commoner half of the thing this counter
        // exists to name.
        let gratuitous = matches!(observation.operation, 1 | 2)
            && observation.sender_ip == observation.target_ip
            && !observation.sender_ip.is_unspecified();
        if gratuitous {
            self.gratuitous = self.gratuitous.saturating_add(1);
        }
        // What the packet asked about, where it asked about anything. A reply's
        // target is the host that asked, not a question, so only a request's
        // is recorded.
        // What the packet asked about, where it asked about anything. An
        // announcement is not a question: its target address is its own, and
        // filing it as one would list every announced address as an address
        // somebody was looking for.
        if observation.operation == 1
            && !observation.target_ip.is_unspecified()
            && observation.target_ip != observation.sender_ip
            && !self
                .addresses_asked_about
                .iter()
                .any(|a| a == &observation.target_ip)
        {
            if self.addresses_asked_about.len() < MAX_ADDRESSES_ASKED_ABOUT {
                self.addresses_asked_about.push(observation.target_ip);
            } else {
                self.addresses_asked_about_beyond_cap =
                    self.addresses_asked_about_beyond_cap.saturating_add(1);
            }
        }
        // The unspecified address claims nothing: it is a host asking whether
        // an address is free before taking it.
        if observation.sender_ip.is_unspecified() {
            self.probes = self.probes.saturating_add(1);
            return;
        }

        let disagreed = observation
            .frame_source_mac
            .is_some_and(|source| source != observation.sender_mac);
        if disagreed {
            self.frame_source_disagreements = self.frame_source_disagreements.saturating_add(1);
        }

        let binding = match self.bindings.get_mut(&observation.sender_ip) {
            Some(binding) => binding,
            None => {
                if self.bindings.len() >= MAX_ADDRESSES {
                    self.addresses_beyond_cap = self.addresses_beyond_cap.saturating_add(1);
                    return;
                }
                self.bindings
                    .entry(observation.sender_ip)
                    .or_insert_with(|| Binding {
                        ip: observation.sender_ip,
                        claims: Vec::new(),
                        macs_beyond_cap: 0,
                    })
            }
        };
        let claim = match binding
            .claims
            .iter_mut()
            .position(|c| c.mac == observation.sender_mac)
        {
            Some(index) => &mut binding.claims[index],
            None => {
                if binding.claims.len() >= MAX_MACS_PER_ADDRESS {
                    binding.macs_beyond_cap += 1;
                    return;
                }
                binding.claims.push(Claim {
                    mac: observation.sender_mac,
                    first_seen: None,
                    last_seen: None,
                    packets: 0,
                    in_requests: 0,
                    in_replies: 0,
                    gratuitous: 0,
                    frame_source_disagreed: 0,
                    frame_sources: Vec::new(),
                });
                binding.claims.last_mut().expect("just pushed")
            }
        };
        claim.packets = claim.packets.saturating_add(1);
        match observation.operation {
            1 => claim.in_requests = claim.in_requests.saturating_add(1),
            2 => claim.in_replies = claim.in_replies.saturating_add(1),
            _ => {}
        }
        if gratuitous {
            claim.gratuitous = claim.gratuitous.saturating_add(1);
        }
        if disagreed {
            claim.frame_source_disagreed = claim.frame_source_disagreed.saturating_add(1);
            if let Some(source) = observation.frame_source_mac {
                if claim.frame_sources.len() < MAX_FRAME_SOURCES
                    && !claim.frame_sources.contains(&source)
                {
                    claim.frame_sources.push(source);
                }
            }
        }
        if let Some(ts) = ts_micros {
            claim.first_seen = Some(claim.first_seen.map_or(ts, |f| f.min(ts)));
            claim.last_seen = Some(claim.last_seen.map_or(ts, |l| l.max(ts)));
        }
        let addresses = self.by_mac.entry(observation.sender_mac).or_default();
        if !addresses.contains(&observation.sender_ip) {
            addresses.push(observation.sender_ip);
        }
    }

    /// Every binding, by address, each with its claims ordered by when they
    /// were first seen — so the record reads as a history rather than as a
    /// set.
    pub fn bindings(&self) -> Vec<Binding> {
        self.bindings
            .values()
            .map(|binding| {
                let mut binding = binding.clone();
                // A claim with no timestamp sorts last: it is not known to
                // have come before one that has a time.
                binding
                    .claims
                    .sort_by_key(|c| (c.first_seen.is_none(), c.first_seen));
                binding
            })
            .collect()
    }

    /// The addresses more than one hardware address claimed.
    pub fn contested(&self) -> Vec<Binding> {
        self.bindings()
            .into_iter()
            .filter(Binding::contested)
            .collect()
    }

    /// The addresses one hardware address claimed. Several is ordinary for a
    /// router or a virtual-machine host and remarkable for a workstation.
    pub fn addresses_for(&self, mac: [u8; 6]) -> Vec<Ipv4Addr> {
        self.by_mac.get(&mac).cloned().unwrap_or_default()
    }

    /// Hardware addresses seen claiming anything.
    pub fn hardware_addresses(&self) -> usize {
        self.by_mac.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames == 0
    }
}

/// A hardware address in the form every other tool prints, so a value from a
/// record can be pasted into a search.
pub fn mac_label(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
#[path = "arp_tests.rs"]
mod arp_tests;
