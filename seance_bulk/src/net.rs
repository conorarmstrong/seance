//! Carve network packets from a raw byte stream and reassemble a pcap.
//!
//! bulk_extractor's `scan_net` recognises IP packets *anywhere* — most valuably
//! in a RAM capture, hibernation file or swap, where historical traffic persists
//! after the connections that carried it have closed. The memory tier's live
//! `netscan` sees only current connections; this sees the ones already gone.
//!
//! Recognition is conservative on purpose: an IPv4 header is accepted only when
//! its version, header length, total length and protocol are self-consistent
//! *and its header checksum verifies*. A valid 16-bit ones-complement checksum
//! over 20+ bytes is not something random data produces by accident, so a hit is
//! a real packet, not a coincidence — the same "verify, don't guess" discipline
//! as the AES scanner.

/// A carved IP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarvedPacket {
    /// Byte offset of the packet in the scanned buffer.
    pub offset: usize,
    /// IP protocol number (1 ICMP, 6 TCP, 17 UDP).
    pub protocol: u8,
    /// Source IPv4 address.
    pub src: [u8; 4],
    /// Destination IPv4 address.
    pub dst: [u8; 4],
    /// Total packet length from the IP header.
    pub total_len: usize,
}

impl CarvedPacket {
    /// Dotted-quad source, for reporting.
    pub fn src_str(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.src[0], self.src[1], self.src[2], self.src[3]
        )
    }
    /// Dotted-quad destination, for reporting.
    pub fn dst_str(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.dst[0], self.dst[1], self.dst[2], self.dst[3]
        )
    }
}

/// Verify the IPv4 header checksum: the ones-complement sum of the header's
/// 16-bit words (checksum field included) must be 0xffff.
fn ipv4_checksum_ok(header: &[u8]) -> bool {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
}

/// Try to read a valid IPv4 packet header at `buf[offset..]`.
fn packet_at(buf: &[u8], offset: usize) -> Option<CarvedPacket> {
    let rest = buf.get(offset..)?;
    if rest.len() < 20 {
        return None;
    }
    let b0 = rest[0];
    if b0 >> 4 != 4 {
        return None; // not IPv4
    }
    let ihl = (b0 & 0x0f) as usize;
    if !(5..=15).contains(&ihl) {
        return None;
    }
    let header_len = ihl * 4;
    let total_len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
    if total_len < header_len || total_len < 20 || total_len > rest.len() {
        return None;
    }
    let protocol = rest[9];
    if !matches!(protocol, 1 | 6 | 17) {
        return None; // ICMP / TCP / UDP only, to keep false positives near zero
    }
    if !ipv4_checksum_ok(&rest[..header_len]) {
        return None;
    }
    Some(CarvedPacket {
        offset,
        protocol,
        src: [rest[12], rest[13], rest[14], rest[15]],
        dst: [rest[16], rest[17], rest[18], rest[19]],
        total_len,
    })
}

/// Carve every valid IPv4 packet from the buffer. After a hit the scan advances
/// past the whole packet, so a packet's payload cannot spuriously re-match.
pub fn carve_packets(buf: &[u8]) -> Vec<CarvedPacket> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset + 20 <= buf.len() {
        match packet_at(buf, offset) {
            Some(p) => {
                let advance = p.total_len;
                out.push(p);
                offset += advance;
            }
            None => offset += 1,
        }
    }
    out
}

/// pcap `LINKTYPE_RAW`: the record data is a raw IP packet, no link header.
const LINKTYPE_RAW: u32 = 101;

/// Reassemble carved packets into a pcap byte stream (LINKTYPE_RAW).
///
/// Timestamps are zero: a packet carved from memory has no capture time, and
/// inventing one would be dishonest. `orig_buf` is the buffer the packets were
/// carved from, so the exact packet bytes are copied out.
pub fn write_pcap(packets: &[CarvedPacket], orig_buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // Global header, little-endian.
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
    out.extend_from_slice(&2u16.to_le_bytes()); // version major
    out.extend_from_slice(&4u16.to_le_bytes()); // version minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&LINKTYPE_RAW.to_le_bytes()); // network
    for p in packets {
        let end = (p.offset + p.total_len).min(orig_buf.len());
        let data = &orig_buf[p.offset..end];
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_sec (unknown)
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // incl_len
        out.extend_from_slice(&(p.total_len as u32).to_le_bytes()); // orig_len
        out.extend_from_slice(data);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid IPv4/UDP packet with a correct header checksum.
    fn make_udp_packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45; // v4, IHL 5
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64; // TTL
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        // Compute and insert the header checksum.
        let mut sum: u32 = 0;
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([p[i], p[i + 1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        p[10..12].copy_from_slice(&cksum.to_be_bytes());
        // UDP header + payload.
        p[20..22].copy_from_slice(&1234u16.to_be_bytes()); // src port
        p[22..24].copy_from_slice(&53u16.to_be_bytes()); // dst port
        p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p[28..].copy_from_slice(payload);
        p
    }

    #[test]
    fn carves_a_planted_packet_from_memory_noise() {
        let pkt = make_udp_packet([10, 0, 0, 5], [8, 8, 8, 8], b"hello dns");
        let mut mem = vec![0u8; 5000];
        for (i, b) in mem.iter_mut().enumerate() {
            *b = (i * 37 % 253) as u8;
        }
        let at = 1000;
        mem[at..at + pkt.len()].copy_from_slice(&pkt);

        let found = carve_packets(&mem);
        let p = found.iter().find(|p| p.offset == at).expect("carve packet");
        assert_eq!(p.protocol, 17);
        assert_eq!(p.src_str(), "10.0.0.5");
        assert_eq!(p.dst_str(), "8.8.8.8");
        assert_eq!(p.total_len, pkt.len());
    }

    #[test]
    fn produces_a_valid_pcap_header_and_record() {
        let pkt = make_udp_packet([1, 1, 1, 1], [2, 2, 2, 2], b"x");
        let carved = carve_packets(&pkt);
        assert_eq!(carved.len(), 1);
        let pcap = write_pcap(&carved, &pkt);
        // Global header magic + LINKTYPE_RAW.
        assert_eq!(&pcap[0..4], &0xa1b2c3d4u32.to_le_bytes());
        assert_eq!(&pcap[20..24], &LINKTYPE_RAW.to_le_bytes());
        // One record: 24 (global) + 16 (record hdr) + packet.
        assert_eq!(pcap.len(), 24 + 16 + pkt.len());
        let incl = u32::from_le_bytes([pcap[24 + 8], pcap[24 + 9], pcap[24 + 10], pcap[24 + 11]]);
        assert_eq!(incl as usize, pkt.len());
    }

    #[test]
    fn rejects_data_with_a_bad_checksum() {
        let mut pkt = make_udp_packet([1, 2, 3, 4], [5, 6, 7, 8], b"data");
        pkt[10] ^= 0xff; // corrupt the checksum
        assert!(
            carve_packets(&pkt).is_empty(),
            "bad checksum must not carve"
        );
    }

    #[test]
    fn does_not_false_positive_on_random_data() {
        let mut mem = vec![0u8; 200_000];
        let mut state = 0xdeadbeefu32;
        for b in mem.iter_mut() {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (state >> 24) as u8;
        }
        // A stray valid checksum over a random 20-byte window is possible but
        // must also pass version/IHL/length/protocol — vanishingly rare. Allow a
        // tiny nonzero count rather than asserting exactly zero would be wrong;
        // in practice this is empty. Assert it is at most a trickle.
        let n = carve_packets(&mem).len();
        assert!(n <= 2, "random data should carve ~0 packets, got {n}");
    }

    #[test]
    fn carves_multiple_back_to_back_packets() {
        let a = make_udp_packet([1, 1, 1, 1], [2, 2, 2, 2], b"one");
        let b = make_udp_packet([3, 3, 3, 3], [4, 4, 4, 4], b"twotwo");
        let mut mem = Vec::new();
        mem.extend_from_slice(&a);
        mem.extend_from_slice(&b);
        let found = carve_packets(&mem);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].src_str(), "1.1.1.1");
        assert_eq!(found[1].src_str(), "3.3.3.3");
    }
}
