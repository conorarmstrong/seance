//! The CRC-32 the PST/OST node database stores (MS-PST §5.3): the reflected
//! 0xEDB88320 polynomial, initial value 0 and no final inversion — so it is not
//! the zlib CRC-32, which inverts on both sides.

const fn make_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static TABLE: [u32; 256] = make_table();

/// The NDB CRC of `data`.
pub fn ndb_crc(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |crc, &b| {
        TABLE[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8)
    })
}

/// The NDB signature of a page or block: its offset folded with its BID
/// (MS-PST ComputeSig).
pub fn ndb_sig(ib: u64, bid: u64) -> u16 {
    let x = ib ^ bid;
    ((x >> 16) ^ x) as u16
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_ndb_crc_is_the_uninverted_crc32() {
        // zlib's CRC-32 of "123456789" is 0xCBF43926; the zero-seeded,
        // uninverted form MS-PST stores is a different number.
        assert_eq!(super::ndb_crc(b""), 0);
        assert_eq!(super::ndb_crc(b"123456789"), 0x2DFD_2D88);
    }

    #[test]
    fn the_signature_folds_the_offset_with_the_bid() {
        // The Data Leakage OST's NBT root page: bid 0x36EB at 0x90000 carries
        // wSig 0x36E2 in its trailer.
        assert_eq!(super::ndb_sig(0x90000, 0x36EB), 0x36E2);
    }
}
