//! OSTA CS0 (OSTA UDF 2.1.1): the character set every UDF name is stored in.
//! The first byte is a compression identifier: 8 means one byte per
//! character (code points 0-255), 16 means UTF-16 big-endian.

/// Why a CS0 name could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cs0Error {
    /// A compression identifier other than 8 or 16 (UDF 2.60 adds 254 and
    /// 255, which this reader does not decode).
    UnsupportedCompression(u8),
}

/// Decode a CS0 byte string (compression identifier first). An empty input
/// is the empty name.
pub fn decode(bytes: &[u8]) -> Result<String, Cs0Error> {
    let Some((&id, body)) = bytes.split_first() else {
        return Ok(String::new());
    };
    match id {
        8 => Ok(body.iter().map(|&b| b as char).collect()),
        16 => {
            // A trailing odd byte is not half a character to invent.
            let units: Vec<u16> = body
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes(*c))
                .collect();
            Ok(String::from_utf16_lossy(&units))
        }
        other => Err(Cs0Error::UnsupportedCompression(other)),
    }
}

/// Decode a fixed-length `dstring` field (ECMA-167 1/7.2.12): the last byte is
/// the number of bytes in use, compression identifier included.
pub fn decode_dstring(field: &[u8]) -> Result<String, Cs0Error> {
    let Some((&len, body)) = field.split_last() else {
        return Ok(String::new());
    };
    let len = (len as usize).min(body.len());
    decode(&body[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cs0_8bit_is_latin1() {
        assert_eq!(decode(&[8, b'R', b'E', 0xE9]).unwrap(), "RE\u{e9}");
    }

    #[test]
    fn cs0_16bit_name_decodes_utf16be() {
        // "Ω.txt" in UTF-16BE
        let mut b = vec![16u8, 0x03, 0xA9];
        for c in ".txt".bytes() {
            b.extend_from_slice(&[0, c]);
        }
        assert_eq!(decode(&b).unwrap(), "\u{3a9}.txt");
    }

    #[test]
    fn cs0_unknown_compression_is_refused() {
        assert_eq!(
            decode(&[254, b'a']).unwrap_err(),
            Cs0Error::UnsupportedCompression(254)
        );
    }

    #[test]
    fn dstring_uses_trailing_length() {
        let mut f = [0u8; 32];
        f[..4].copy_from_slice(&[8, b'A', b'B', b'C']);
        f[31] = 4;
        assert_eq!(decode_dstring(&f).unwrap(), "ABC");
        assert_eq!(decode_dstring(&[0u8; 32]).unwrap(), "");
    }
}
