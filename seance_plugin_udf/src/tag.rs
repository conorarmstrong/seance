//! ECMA-167 3/7.2 descriptor tags: the 16-byte header every UDF descriptor
//! starts with, and the two checks that make a descriptor believable — the tag
//! checksum over the header and the CRC-ITU over the descriptor body.

/// Length of a descriptor tag.
pub const TAG_LEN: usize = 16;

/// Tag identifiers (ECMA-167 3/7.2.1 and 4/7.2.1).
pub mod ident {
    pub const PVD: u16 = 1;
    pub const AVDP: u16 = 2;
    pub const VDP: u16 = 3;
    pub const PD: u16 = 5;
    pub const LVD: u16 = 6;
    pub const TD: u16 = 8;
    pub const FSD: u16 = 256;
    pub const FID: u16 = 257;
    pub const AED: u16 = 258;
    pub const FE: u16 = 261;
    pub const EFE: u16 = 266;
}

/// A tag that passed its checks.
#[derive(Debug, Clone, Copy)]
pub struct Tag {
    pub ident: u16,
    pub crc_len: u16,
    pub location: u32,
}

/// Why a descriptor was not believed. Each maps to a stable reason string
/// published on the record that names the refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagError {
    TooShort,
    Checksum,
    CrcLengthExceedsDescriptor,
    Crc,
    UnexpectedIdentifier { expected: u16, found: u16 },
    Location { expected: u32, found: u32 },
}

impl TagError {
    pub fn as_str(self) -> &'static str {
        match self {
            TagError::TooShort => "descriptor_too_short",
            TagError::Checksum => "tag_checksum_mismatch",
            TagError::CrcLengthExceedsDescriptor => "tag_crc_length_exceeds_descriptor",
            TagError::Crc => "descriptor_crc_mismatch",
            TagError::UnexpectedIdentifier { .. } => "unexpected_tag_identifier",
            TagError::Location { .. } => "tag_location_mismatch",
        }
    }
}

/// CRC-ITU-T as ECMA-167 1/7.2.6 specifies it: polynomial x^16+x^12+x^5+1
/// (0x1021), initial value 0, no reflection, no final XOR.
pub fn crc_itu(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Parse and verify the tag at the start of `buf`: its checksum, its CRC over
/// the `crc_len` bytes that follow it, and, when given, its identifier and its
/// recorded location.
pub fn verify(
    buf: &[u8],
    expected_ident: Option<u16>,
    expected_location: Option<u32>,
) -> Result<Tag, TagError> {
    let h = buf.get(..TAG_LEN).ok_or(TagError::TooShort)?;
    let sum = (0..TAG_LEN)
        .filter(|&i| i != 4)
        .fold(0u8, |a, i| a.wrapping_add(h[i]));
    if sum != h[4] {
        return Err(TagError::Checksum);
    }
    let tag = Tag {
        ident: u16::from_le_bytes([h[0], h[1]]),
        crc_len: u16::from_le_bytes([h[10], h[11]]),
        location: u32::from_le_bytes([h[12], h[13], h[14], h[15]]),
    };
    let crc = u16::from_le_bytes([h[8], h[9]]);
    if let Some(expected) = expected_ident {
        if tag.ident != expected {
            return Err(TagError::UnexpectedIdentifier {
                expected,
                found: tag.ident,
            });
        }
    }
    let body = buf
        .get(TAG_LEN..TAG_LEN + tag.crc_len as usize)
        .ok_or(TagError::CrcLengthExceedsDescriptor)?;
    if crc_itu(body) != crc {
        return Err(TagError::Crc);
    }
    if let Some(expected) = expected_location {
        if tag.location != expected {
            return Err(TagError::Location {
                expected,
                found: tag.location,
            });
        }
    }
    Ok(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_itu_known_answer() {
        // The CRC-16/XMODEM check value (poly 0x1021, init 0), which is the
        // ECMA-167 CRC: the standard's own example is "123456789" -> 0x31C3.
        assert_eq!(crc_itu(b"123456789"), 0x31C3);
    }

    #[test]
    fn tag_checksum_and_crc_are_verified() {
        let mut d = vec![0u8; 64];
        d[0..2].copy_from_slice(&ident::FSD.to_le_bytes());
        d[2] = 2;
        d[12..16].copy_from_slice(&7u32.to_le_bytes());
        d[20] = 0xAB;
        let crc = crc_itu(&d[16..64]);
        d[8..10].copy_from_slice(&crc.to_le_bytes());
        d[10..12].copy_from_slice(&48u16.to_le_bytes());
        d[4] = (0..16)
            .filter(|&i| i != 4)
            .fold(0u8, |a, i| a.wrapping_add(d[i]));
        let t = verify(&d, Some(ident::FSD), Some(7)).expect("valid tag");
        assert_eq!(t.location, 7);
        assert_eq!(
            verify(&d, Some(ident::FE), None).unwrap_err().as_str(),
            "unexpected_tag_identifier"
        );
        assert_eq!(
            verify(&d, None, Some(8)).unwrap_err(),
            TagError::Location {
                expected: 8,
                found: 7
            }
        );
        let mut bad = d.clone();
        bad[30] ^= 1;
        assert_eq!(verify(&bad, None, None).unwrap_err(), TagError::Crc);
        let mut bad = d.clone();
        bad[6] ^= 1;
        assert_eq!(verify(&bad, None, None).unwrap_err(), TagError::Checksum);
    }
}
