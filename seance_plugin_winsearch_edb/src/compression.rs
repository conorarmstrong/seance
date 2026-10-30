//! Windows Search's encoded binary text values (Windows 7 `SystemIndex_0A`).
//!
//! Some text properties — `System_Search_AutoSummary` above all — are stored
//! not as ESE text but as a binary value that is first **obfuscated** and then,
//! by its first byte, in one of several forms. libesedb hands these over as
//! raw bytes.
//!
//! - **Obfuscation.** Every byte is XORed with one byte of the 32-bit value
//!   `0x05000113 ^ length` (low byte first, cycling every four bytes) and with
//!   the low byte of its own index. The constant is the one libyal's published
//!   Windows Search format notes give; it was checked here on real bytes: on
//!   every one of the 113 such values in the Data Leakage index it yields a
//!   first byte of 0, 1, 2 or 3 and, for 0 and 1, legible text.
//! - **Type 1** — eight-bit text: each byte is one character, U+0000–U+00FF.
//! - **Type 0** — runs, read off the bytes: a run is a count byte, a byte that
//!   is the high half of every character in the run, and `count` low halves.
//!   So `91 00 <145 bytes>` is 145 Latin characters and `01 20 19` is U+2019.
//! - **Types 2 and 3** carry a 256-byte table after a length — the shape of
//!   LZ77+Huffman — and are **not decoded** here. They are reported by type,
//!   never rendered as text.

/// What decoding one value gave.
#[derive(Debug, Clone, PartialEq)]
pub enum Decoded {
    Text(String),
    /// A form this build does not decode; the type byte is carried.
    NotDecoded {
        type_byte: u8,
        reason: &'static str,
    },
}

/// Undo the XOR obfuscation.
pub fn deobfuscate(data: &[u8]) -> Vec<u8> {
    let key = 0x0500_0113u32 ^ data.len() as u32;
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ (key >> ((i % 4) * 8)) as u8 ^ (i as u8))
        .collect()
}

fn finish(units: impl Iterator<Item = u32>) -> String {
    let s: String = units.filter_map(char::from_u32).collect();
    s.trim_end_matches('\0').to_string()
}

/// Deobfuscate and decode a text value.
pub fn decode_text(data: &[u8]) -> Decoded {
    let plain = deobfuscate(data);
    let Some((&ty, body)) = plain.split_first() else {
        return Decoded::NotDecoded {
            type_byte: 0,
            reason: "empty value",
        };
    };
    match ty {
        1 => Decoded::Text(finish(body.iter().map(|&b| b as u32))),
        0 => {
            let mut units = Vec::with_capacity(body.len());
            let mut p = 0usize;
            while p < body.len() {
                if p + 2 > body.len() {
                    return Decoded::NotDecoded {
                        type_byte: 0,
                        reason: "a run header is cut off",
                    };
                }
                let (count, high) = (body[p] as usize, body[p + 1] as u32);
                let run = body.get(p + 2..p + 2 + count);
                let Some(run) = run else {
                    return Decoded::NotDecoded {
                        type_byte: 0,
                        reason: "a run is longer than the value",
                    };
                };
                units.extend(run.iter().map(|&lo| (high << 8) | lo as u32));
                p += 2 + count;
            }
            Decoded::Text(finish(units.into_iter()))
        }
        2 | 3 => Decoded::NotDecoded {
            type_byte: ty,
            reason: "compressed (a Huffman-table form this build does not decode)",
        },
        other => Decoded::NotDecoded {
            type_byte: other,
            reason: "an unknown encoding type",
        },
    }
}
