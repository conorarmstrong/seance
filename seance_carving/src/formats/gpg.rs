use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// OpenPGP / GPG carving signature. Headers (offset 0): OpenPGP old-format packet tag bytes 0x85
/// (pubkey-enc session key),
/// 0x8c (symkey-enc session key), 0x95 (secret key), 0x99 (public key), and the 5-byte
/// PGP marker {0xa8,0x03,'P','G','P'} (extension "pgp"). PhotoRec validates by parsing the
/// full RFC4880 packet chain and re-walks packets in file_check to size the file; that
/// packet-chain parser and sizing are degraded here to a validated header-magic + max-size
/// carve.
struct GpgSignature;

const PGP_HEADER: &[u8] = &[0xa8, 0x03, b'P', b'G', b'P'];

/// Validate that a byte matching one of the single-byte OpenPGP old-format
/// packet tags (0x85/0x8c/0x95/0x99) actually begins a plausible OpenPGP packet,
/// not just a random byte. A 1-byte magic false-matches ~1.5% of random data, so
/// during carving such a byte on a block boundary would spuriously start a "GPG
/// file" and truncate the real file being recovered. We require the old-format
/// bits, a definite length, and a version byte valid for the packet's tag.
fn valid_openpgp_old_packet(buf: &[u8]) -> bool {
    let Some(&tag_byte) = buf.first() else {
        return false;
    };
    // Old-format packet: bit 7 set (packet), bit 6 clear (old format).
    if tag_byte & 0xC0 != 0x80 {
        return false;
    }
    let tag = (tag_byte >> 2) & 0x0F;
    // Length-type -> size of the length field. Reject the indeterminate form (3):
    // too loose to accept as a carving header.
    let len_size = match tag_byte & 0x03 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => return false,
    };
    // The packet body (whose first byte is the version) follows the length field.
    let version = match buf.get(1 + len_size) {
        Some(&v) => v,
        None => return false,
    };
    let body = 1 + len_size;
    // The algorithm byte each packet names, where its layout puts it
    // (RFC 4880 5.1, 5.3, 5.5.2; RFC 9580 for versions 5 and 6).
    let at = |off: usize| buf.get(body + off).copied();
    match tag {
        // Public-Key Encrypted Session Key. v3: version, 8-byte key ID, then
        // the algorithm. v6: version, a count of the key fields that follow
        // (0 for an anonymous recipient, else a key version and its
        // fingerprint: 1 + 20 for a v4 key, 1 + 32 for a v6 key), then the
        // algorithm. Either way it must be one a session key is encrypted to.
        1 => match version {
            3 => at(9).is_some_and(encryption_algorithm),
            6 => {
                let fields = at(1);
                let key_version = at(2);
                let fits = match fields {
                    Some(0) => true,
                    Some(21) => key_version == Some(4),
                    Some(33) => key_version == Some(6),
                    _ => false,
                };
                fits && at(2 + fields.unwrap_or(0) as usize).is_some_and(encryption_algorithm)
            }
            _ => false,
        },
        // Symmetric-Key Encrypted Session Key: v4/v5 name the cipher right
        // after the version; v6 has a field count first, then the cipher and
        // an AEAD mode (1–3).
        3 => match version {
            4 | 5 => at(1).is_some_and(symmetric_algorithm),
            6 => {
                at(2).is_some_and(symmetric_algorithm)
                    && at(3).is_some_and(|a| (1..=3).contains(&a))
            }
            _ => false,
        },
        // Secret-Key / Public-Key: v2/v3 carry a 2-byte validity period after
        // the 4-byte creation time and are RSA keys (a v3 Key ID is the low 64
        // bits of the RSA modulus, RFC 4880 12.2); later versions have no
        // validity field.
        5 | 6 => match version {
            2 | 3 => at(7).is_some_and(|a| matches!(a, 1..=3)),
            4..=6 => at(5).is_some_and(public_key_algorithm),
            _ => false,
        },
        _ => false,
    }
}

/// Algorithms a session key can be encrypted to: RSA (1, 2), Elgamal (16),
/// ECDH (18), X25519 (25), X448 (26), and the private range 100–110.
fn encryption_algorithm(id: u8) -> bool {
    matches!(id, 1 | 2 | 16 | 18 | 25 | 26 | 100..=110)
}

/// Symmetric cipher IDs RFC 4880/9580 assign (1–13), and the private range.
fn symmetric_algorithm(id: u8) -> bool {
    matches!(id, 1..=13 | 100..=110)
}

/// Public-key algorithm IDs RFC 4880 and RFC 9580 assign (1–3, 16–28), plus
/// the private/experimental range 100–110.
fn public_key_algorithm(id: u8) -> bool {
    matches!(id, 1..=3 | 16..=28 | 100..=110)
}

impl FileSignature for GpgSignature {
    fn name(&self) -> &str {
        "GPG"
    }

    fn extensions(&self) -> &[&str] {
        &["gpg", "pgp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.is_empty() {
            return None;
        }
        let extension = if buf.len() >= PGP_HEADER.len() && &buf[0..PGP_HEADER.len()] == PGP_HEADER
        {
            "pgp"
        } else if matches!(buf[0], 0x85 | 0x8c | 0x95 | 0x99) && valid_openpgp_old_packet(buf) {
            "gpg"
        } else {
            return None;
        };
        Some(RecoveryInit {
            min_filesize: 23,
            extension: extension.to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x95], Arc::new(GpgSignature));
    registry.register(0, &[0x8c], Arc::new(GpgSignature));
    registry.register(0, &[0x85], Arc::new(GpgSignature));
    registry.register(0, PGP_HEADER, Arc::new(GpgSignature));
    registry.register(0, &[0x99], Arc::new(GpgSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpg_header_match() {
        let sig = GpgSignature;
        // 0x95 = old-format Secret-Key packet (tag 5, 2-byte length); the packet
        // body begins with a valid version byte (4), a creation time and a
        // public-key algorithm (1, RSA).
        assert_eq!(
            sig.header_check(&[0x95, 0x00, 0x0d, 0x04, 0x5b, 0xd6, 0x0e, 0xe1, 0x01], 0)
                .map(|i| i.extension),
            Some("gpg".to_string())
        );
        assert_eq!(
            sig.header_check(&[0xa8, 0x03, b'P', b'G', b'P'], 0)
                .map(|i| i.extension),
            Some("pgp".to_string())
        );
    }

    #[test]
    fn test_gpg_rejects_false_single_byte_match() {
        let sig = GpgSignature;
        // A 0x95 tag byte followed by an invalid version (0x00, not 2..=6) is
        // random data, not an OpenPGP packet -- reject so a stray 0x95 on a block
        // boundary can't truncate the real file being carved.
        assert!(sig
            .header_check(&[0x95, 0xff, 0xff, 0x00, 0x11], 0)
            .is_none());
        // Too short to validate the version byte -> reject.
        assert!(sig.header_check(&[0x95, 0x00, 0x01], 0).is_none());
    }

    /// A 0x95 byte from compressed PDF content in DFTT #12 (sector 6786 of
    /// `12-carve-ext2.dd`) passes the tag, length and version checks — it
    /// reads as a version 3 secret key — and cut `n_lin_ss.pdf` short. Its
    /// public-key algorithm byte (0xB1) is none RFC 4880/9580 assigns.
    #[test]
    fn a_key_packet_naming_no_public_key_algorithm_is_refused() {
        let real = [
            0x95, 0xd2, 0xe6, 0x03, 0x5b, 0xd6, 0x0e, 0xe1, 0x16, 0x29, 0xb1, 0x94,
        ];
        assert!(GpgSignature.header_check(&real, 0).is_none());
        // The same packet naming RSA (1) is a plausible v3 key.
        let mut rsa = real;
        rsa[10] = 1;
        assert!(GpgSignature.header_check(&rsa, 0).is_some());
        // Version 4: creation time, then the algorithm.
        assert!(GpgSignature
            .header_check(&[0x99, 0x01, 0x0d, 0x04, 1, 2, 3, 4, 0xEE], 0)
            .is_none());
        assert!(GpgSignature
            .header_check(&[0x99, 0x01, 0x0d, 0x04, 1, 2, 3, 4, 22], 0)
            .is_some());
    }

    /// Three more false matches on DFTT #11 (`11-carve-fat.dd`), each inside
    /// a real file, each refused by a rule of the packet's own layout:
    /// - byte 9,433,600 (inside `lin_1.2.pdf`): a v6 session-key packet whose
    ///   key-field count (0x47) is none a v6 PKESK can have (0, 21 or 33);
    /// - byte 1,046,016: a v3 key naming X25519 (25), where a v3 key is RSA
    ///   (its Key ID is the low 64 bits of the RSA modulus, RFC 4880 12.2);
    /// - byte 6,120,448: a v3 session-key packet naming Ed25519 (27), a
    ///   signing-only algorithm no session key is encrypted to.
    #[test]
    fn packets_whose_layout_rules_them_out_are_refused() {
        let v6_pkesk = [0x85, 0x41, 0x8a, 0x06, 0x47, 0x06, 0x02, 0x0c, 0x54, 0xc2];
        assert!(GpgSignature.header_check(&v6_pkesk, 0).is_none());
        let v3_x25519 = [
            0x95, 0xed, 0xc5, 0x03, 0x6d, 0xf1, 0x7a, 0x3d, 0x42, 0xce, 0x19, 0x28,
        ];
        assert!(GpgSignature.header_check(&v3_x25519, 0).is_none());
        let pkesk_ed25519 = [
            0x85, 0x58, 0xa9, 0x03, 0x94, 0x1b, 0xd7, 0xa0, 0x9a, 0x6f, 0x5e, 0x58, 0x1b, 0xf1,
        ];
        assert!(GpgSignature.header_check(&pkesk_ed25519, 0).is_none());

        // The accepted shapes of each.
        let mut v6_ok = [0u8; 40];
        v6_ok[..6].copy_from_slice(&[0x85, 0x00, 0x30, 0x06, 33, 0x06]);
        v6_ok[6 + 32] = 25; // X25519
        assert!(GpgSignature.header_check(&v6_ok, 0).is_some());
        let mut v3_rsa = v3_x25519;
        v3_rsa[10] = 1;
        assert!(GpgSignature.header_check(&v3_rsa, 0).is_some());
        let mut pkesk_elgamal = pkesk_ed25519;
        pkesk_elgamal[12] = 16;
        assert!(GpgSignature.header_check(&pkesk_elgamal, 0).is_some());
    }

    #[test]
    fn test_gpg_no_match() {
        let sig = GpgSignature;
        assert!(sig.header_check(&[0x00, 0x11, 0x22], 0).is_none());
        assert!(sig.header_check(&[], 0).is_none());
    }
}
