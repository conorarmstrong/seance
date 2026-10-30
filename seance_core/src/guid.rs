//! Microsoft GUID formatting.
//!
//! A GUID stored on disk by Windows (VSS catalog entries, `ActivitiesCache.db`
//! `Id` blobs, registry values, LNK/shellbag structures) uses the *mixed-endian*
//! convention: `Data1` (4 bytes), `Data2` (2 bytes) and `Data3` (2 bytes) are
//! little-endian, while `Data4` (the final 8 bytes) is stored in display order.
//! Byte-order-blind hex dumping produces a different string for the same GUID,
//! so this was worth having in exactly one place.

/// Format 16 raw GUID bytes as the canonical lower-case Microsoft GUID string
/// (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`), honouring the mixed-endian layout.
///
/// This matches both `.NET`'s `new Guid(bytes).ToString()` and the libyal /
/// `vshadow` rendering of a VSS store identifier.
///
/// ```
/// use seance_core::guid::format_guid;
/// let bytes: [u8; 16] = [
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
///     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
/// ];
/// assert_eq!(format_guid(&bytes), "03020100-0504-0706-0809-0a0b0c0d0e0f");
/// ```
pub fn format_guid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[3], bytes[2], bytes[1], bytes[0],
        bytes[5], bytes[4],
        bytes[7], bytes[6],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_endian_per_ms_convention() {
        let bytes: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        assert_eq!(format_guid(&bytes), "03020100-0504-0706-0809-0a0b0c0d0e0f");
    }

    #[test]
    fn all_zero_and_all_ff() {
        assert_eq!(
            format_guid(&[0u8; 16]),
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(
            format_guid(&[0xFFu8; 16]),
            "ffffffff-ffff-ffff-ffff-ffffffffffff"
        );
    }
}
