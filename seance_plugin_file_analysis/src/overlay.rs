//! Trailing-data ("overlay") detection.
//!
//! Several container formats have a definite end-of-image terminator. Any bytes
//! that follow it are an *overlay*: data appended after the file's logical end.
//! This is a classic hiding technique — a ZIP/Office document, an executable, or
//! a second file concatenated onto a valid image, which keeps a valid header and
//! a matching extension and so slips past header-only signature checks.
//!
//! [`image_logical_end`] returns where the image data ends for the formats that
//! have a walkable structure (JPEG, PNG). The caller compares that to the file
//! size; a positive difference is an overlay whose bytes can then be
//! magic-sniffed to guess what was hidden.

/// Whether overlay detection can walk this content type's structure. Type names
/// are `magic::detect_content_type`'s labels ("JPEG", "PNG").
pub fn supports(content_type: &str) -> bool {
    matches!(content_type, "JPEG" | "PNG")
}

/// Byte offset at which a well-formed image ends, for formats with a definite
/// terminator. `None` when the type is unsupported or the structure is
/// malformed (in which case no overlay claim can be made).
pub fn image_logical_end(content_type: &str, data: &[u8]) -> Option<usize> {
    match content_type {
        "JPEG" => jpeg_end(data),
        "PNG" => png_end(data),
        _ => None,
    }
}

/// Walk JPEG markers to the EOI (`FF D9`) that terminates the image, returning
/// the offset just past it. Correctly steps over segment payloads and the
/// entropy-coded scan data after `SOS` (honoring `FF00` byte-stuffing and `RSTn`
/// restart markers), so an `FF D9` that appears inside compressed data is not
/// mistaken for the end.
fn jpeg_end(d: &[u8]) -> Option<usize> {
    if d.len() < 2 || d[0] != 0xFF || d[1] != 0xD8 {
        return None;
    }
    let mut i = 2;
    while i + 1 < d.len() {
        if d[i] != 0xFF {
            return None; // desync: not at a marker where one is required
        }
        // A marker may be preceded by any number of 0xFF fill bytes.
        let mut j = i;
        while j < d.len() && d[j] == 0xFF {
            j += 1;
        }
        if j >= d.len() {
            return None;
        }
        let marker = d[j];
        i = j + 1;
        match marker {
            0xD9 => return Some(i), // EOI
            // Standalone markers carry no payload.
            0xD8 | 0x01 => {}
            0xD0..=0xD7 => {}
            0xDA => {
                // Start of Scan: a length-prefixed header, then entropy data.
                if i + 1 >= d.len() {
                    return None;
                }
                let len = ((d[i] as usize) << 8) | d[i + 1] as usize;
                if len < 2 {
                    return None;
                }
                i += len;
                // Scan entropy-coded data up to the next real marker.
                while i + 1 < d.len() {
                    if d[i] == 0xFF {
                        let n = d[i + 1];
                        if n == 0x00 || (0xD0..=0xD7).contains(&n) {
                            i += 2; // stuffed byte or restart marker: still scan data
                        } else {
                            break; // real marker: hand back to the outer walk
                        }
                    } else {
                        i += 1;
                    }
                }
            }
            _ => {
                // Any other marker introduces a 2-byte length-prefixed segment.
                if i + 1 >= d.len() {
                    return None;
                }
                let len = ((d[i] as usize) << 8) | d[i + 1] as usize;
                if len < 2 {
                    return None;
                }
                i += len;
            }
        }
    }
    None
}

/// Walk PNG chunks to `IEND`, returning the offset just past its CRC.
fn png_end(d: &[u8]) -> Option<usize> {
    const SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if d.len() < 8 || d[..8] != SIG {
        return None;
    }
    let mut i = 8;
    // Each chunk: 4-byte length, 4-byte type, `length` data bytes, 4-byte CRC.
    while i + 8 <= d.len() {
        let len = u32::from_be_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]) as usize;
        let ctype = &d[i + 4..i + 8];
        let next = i.checked_add(12)?.checked_add(len)?; // len+type(8)+data+crc(4)
        if ctype == b"IEND" {
            return Some(next.min(d.len()));
        }
        if next <= i {
            return None;
        }
        i = next;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jpeg_without_overlay_ends_at_eoi() {
        // SOI, a tiny APP0, SOS with 2 bytes of scan data, EOI.
        let d = [
            0xFF, 0xD8, // SOI
            0xFF, 0xE0, 0x00, 0x04, 0xAA, 0xBB, // APP0 len=4 (2 payload)
            0xFF, 0xDA, 0x00, 0x02, // SOS len=2 (no extra header bytes)
            0x12, 0x34, // entropy data
            0xFF, 0xD9, // EOI
        ];
        assert_eq!(jpeg_end(&d), Some(d.len()));
    }

    #[test]
    fn jpeg_end_ignores_ff_d9_inside_scan_via_stuffing() {
        // Scan data contains FF 00 (stuffed) which must not end the image.
        let d = [
            0xFF, 0xD8, // SOI
            0xFF, 0xDA, 0x00, 0x02, // SOS
            0xFF, 0x00, 0x12, // stuffed FF, then a byte
            0xFF, 0xD9, // real EOI
        ];
        assert_eq!(jpeg_end(&d), Some(d.len()));
    }

    #[test]
    fn detects_overlay_after_jpeg() {
        let mut d = vec![0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02, 0x12, 0x34, 0xFF, 0xD9];
        let logical = d.len();
        d.extend_from_slice(b"PK\x03\x04 hidden zip");
        let end = image_logical_end("JPEG", &d).unwrap();
        assert_eq!(end, logical);
        assert!(d.len() > end, "overlay present");
    }

    #[test]
    fn png_end_after_iend() {
        let mut d = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        // IHDR chunk (length 13)
        d.extend_from_slice(&13u32.to_be_bytes());
        d.extend_from_slice(b"IHDR");
        d.extend_from_slice(&[0u8; 13]);
        d.extend_from_slice(&[0, 0, 0, 0]); // crc
                                            // IEND chunk (length 0)
        let iend_start = d.len();
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(b"IEND");
        d.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]); // crc
        let end = png_end(&d).unwrap();
        assert_eq!(end, iend_start + 12);
    }

    #[test]
    fn non_image_type_is_none() {
        assert_eq!(image_logical_end("pdf", &[0xFF, 0xD8, 0xFF, 0xD9]), None);
    }
}
