//! What the ARP table records, and what it refuses to conclude.

use super::*;
use std::net::Ipv4Addr;

fn ip(s: &str) -> Ipv4Addr {
    s.parse().expect("an address")
}

const ROUTER: [u8; 6] = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
const LAPTOP: [u8; 6] = [0x00, 0xde, 0xad, 0xbe, 0xef, 0x01];
const ATTACKER: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

fn claim(mac: [u8; 6], sender: &str, target: &str, operation: u16) -> Observation {
    Observation {
        operation,
        sender_mac: mac,
        sender_ip: ip(sender),
        target_mac: [0; 6],
        target_ip: ip(target),
        frame_source_mac: Some(mac),
    }
}

// ── What a binding is ───────────────────────────────────────────────────────

/// **A binding is what a host said**, and the table is an inventory of
/// claims. Both directions are indexed, because the question is asked both
/// ways: which address does this hardware use, and which hardware answers for
/// this address.
#[test]
fn a_sender_claiming_an_address_becomes_a_binding_in_both_directions() {
    let mut table = ArpTable::new();
    table.observe(
        &claim(ROUTER, "192.168.1.1", "192.168.1.50", 2),
        Some(1_000),
    );
    table.observe(
        &claim(ROUTER, "192.168.1.1", "192.168.1.51", 2),
        Some(3_000),
    );

    let bindings = table.bindings();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].ip, ip("192.168.1.1"));
    assert_eq!(bindings[0].claims.len(), 1);
    let claim = &bindings[0].claims[0];
    assert_eq!(claim.mac, ROUTER);
    assert_eq!(claim.packets, 2);
    assert_eq!(claim.first_seen, Some(1_000));
    assert_eq!(claim.last_seen, Some(3_000));
    assert!(!bindings[0].contested());
    assert_eq!(table.addresses_for(ROUTER), vec![ip("192.168.1.1")]);
    assert_eq!(table.replies, 2);
    assert_eq!(table.requests, 0);
}

/// A request carries the sender's own binding as surely as a reply does: a
/// host asking "who has .50" is announcing that it is .40 at this hardware
/// address.
#[test]
fn a_request_carries_its_senders_own_binding() {
    let mut table = ArpTable::new();
    table.observe(&claim(LAPTOP, "192.168.1.40", "192.168.1.50", 1), Some(10));
    assert_eq!(table.bindings().len(), 1);
    assert_eq!(table.bindings()[0].ip, ip("192.168.1.40"));
    assert_eq!(table.requests, 1);
    // And what it asked about is recorded as a question, not as a binding.
    assert_eq!(table.addresses_asked_about, vec![ip("192.168.1.50")]);
}

/// **An address with no sender is a probe, not a binding.** A host checking
/// whether an address is free sends `0.0.0.0`, and recording that as a
/// binding would put every DHCP client on the network at one address.
#[test]
fn a_probe_from_the_unspecified_address_is_not_a_binding() {
    let mut table = ArpTable::new();
    table.observe(&claim(LAPTOP, "0.0.0.0", "192.168.1.77", 1), Some(10));
    assert!(table.bindings().is_empty());
    assert_eq!(table.probes, 1);
    assert_eq!(table.addresses_asked_about, vec![ip("192.168.1.77")]);
}

/// A reply whose sender and target address are the same is a gratuitous
/// announcement: a host telling the segment to update its cache without being
/// asked. That is how an address is taken over, and also how every failover
/// pair and every DHCP renewal announces itself.
#[test]
fn a_gratuitous_reply_is_counted_as_one() {
    let mut table = ArpTable::new();
    table.observe(
        &claim(ATTACKER, "192.168.1.1", "192.168.1.1", 2),
        Some(5_000),
    );
    assert_eq!(table.gratuitous, 1);
    assert_eq!(table.bindings()[0].claims[0].gratuitous, 1);
}

// ── Two hosts, one address ──────────────────────────────────────────────────

/// **An address claimed by two hardware addresses is contested, and that is
/// all it is called.** It is the signature of ARP cache poisoning; it is also
/// what a failover pair, a DHCP lease handed on, a replaced network card and
/// a dual-homed host all look like. The record states the claims and their
/// times, and no verdict.
#[test]
fn an_address_claimed_by_two_hosts_is_contested_and_no_verdict_is_reached() {
    let mut table = ArpTable::new();
    table.observe(
        &claim(ROUTER, "192.168.1.1", "192.168.1.50", 2),
        Some(1_000),
    );
    table.observe(
        &claim(ATTACKER, "192.168.1.1", "192.168.1.50", 2),
        Some(9_000),
    );

    let contested = table.contested();
    assert_eq!(contested.len(), 1);
    let binding = &contested[0];
    assert!(binding.contested());
    assert_eq!(binding.claims.len(), 2);
    // In the order they were first seen, so the record reads as a history.
    assert_eq!(binding.claims[0].mac, ROUTER);
    assert_eq!(binding.claims[1].mac, ATTACKER);
    assert_eq!(binding.contested_from(), Some(9_000));
    assert!(binding.statement().contains("does not authenticate"));
    assert!(
        binding.statement().contains("failover"),
        "the innocent explanations are on the record: {}",
        binding.statement()
    );
}

/// **The hardware address inside an ARP packet need not be the one that sent
/// the frame, and a disagreement is recorded.** A forger who sets only the
/// inner field leaves the two at odds, which is a fact about the bytes.
#[test]
fn a_frame_whose_source_disagrees_with_the_claim_inside_it_is_counted() {
    let mut table = ArpTable::new();
    let mut observation = claim(ATTACKER, "192.168.1.1", "192.168.1.50", 2);
    observation.frame_source_mac = Some(LAPTOP);
    table.observe(&observation, Some(10));
    assert_eq!(table.frame_source_disagreements, 1);
    assert_eq!(table.bindings()[0].claims[0].frame_source_disagreed, 1);
    assert_eq!(
        table.bindings()[0].claims[0].frame_sources,
        vec![LAPTOP],
        "and the frame's own source is kept, because it is the other half of the disagreement"
    );
}

// ── Bounds ──────────────────────────────────────────────────────────────────

/// A capture of a scanned segment holds thousands of addresses. Past the
/// ceiling they are counted and not listed, and the count says so.
#[test]
fn addresses_past_the_ceiling_are_counted_and_not_listed() {
    let mut table = ArpTable::new();
    for n in 0..=MAX_ADDRESSES {
        let ip = Ipv4Addr::from(0x0a00_0000 + n as u32);
        table.observe(
            &Observation {
                operation: 1,
                sender_mac: LAPTOP,
                sender_ip: ip,
                target_mac: [0; 6],
                target_ip: Ipv4Addr::new(10, 0, 0, 1),
                frame_source_mac: Some(LAPTOP),
            },
            Some(1),
        );
    }
    assert_eq!(table.bindings().len(), MAX_ADDRESSES);
    assert_eq!(table.addresses_beyond_cap, 1);
}

/// One address claimed by more hardware addresses than the ceiling holds is
/// the loudest possible conflict; the ones past it are counted so the record
/// cannot read as a complete list of claimants.
#[test]
fn claims_past_the_ceiling_on_one_address_are_counted() {
    let mut table = ArpTable::new();
    for n in 0..=MAX_MACS_PER_ADDRESS {
        let mut mac = [0u8; 6];
        mac[5] = n as u8;
        mac[4] = (n >> 8) as u8;
        table.observe(&claim(mac, "192.168.1.1", "192.168.1.50", 2), Some(1));
    }
    let binding = &table.bindings()[0];
    assert_eq!(binding.claims.len(), MAX_MACS_PER_ADDRESS);
    assert_eq!(binding.macs_beyond_cap, 1);
    assert!(binding.statement().contains("does not authenticate"));
}

/// A hardware address is rendered the way every other tool renders one, so a
/// value from this record can be pasted into a search.
#[test]
fn a_hardware_address_renders_in_the_ordinary_form() {
    assert_eq!(mac_label(ROUTER), "00:1a:2b:3c:4d:5e");
    assert_eq!(mac_label([0xff; 6]), "ff:ff:ff:ff:ff:ff");
}

/// **The announcement form is a request, not a reply** (RFC 5227 §3), and it
/// is the form Windows, `arping -U` and most spoofing tools send. Counting
/// only gratuitous replies misses the commoner half of the thing the counter
/// exists to name — and an announcement is not a question, so its own address
/// must not be filed as one somebody was looking for.
#[test]
fn an_announcement_sent_as_a_request_is_gratuitous_and_is_not_a_question() {
    let mut table = ArpTable::new();
    table.observe(
        &claim(ATTACKER, "192.168.1.1", "192.168.1.1", 1),
        Some(5_000),
    );
    assert_eq!(table.gratuitous, 1, "the request form counts");
    assert_eq!(table.requests, 1);
    assert_eq!(table.bindings()[0].claims[0].gratuitous, 1);
    assert!(
        table.addresses_asked_about.is_empty(),
        "an announcement is not a question: {:?}",
        table.addresses_asked_about
    );
    // A probe still claims nothing and is still a question about its target.
    let mut table = ArpTable::new();
    table.observe(&claim(LAPTOP, "0.0.0.0", "192.168.1.77", 1), Some(10));
    assert_eq!(table.gratuitous, 0);
    assert_eq!(table.probes, 1);
    assert_eq!(table.addresses_asked_about, vec![ip("192.168.1.77")]);
}
