//! Decode-and-rescan: lift encoded spans out of a buffer into child buffers.
//!
//! bulk_extractor probes every byte for a decodable sequence and re-examines the
//! decoded bytes, which is how it finds a base64-encoded JPEG or a gzipped JSON
//! object that a file-oriented carver walks straight past. In Séance the
//! *recursion already exists*: the orchestrator re-queues produced artifacts, so
//! a decoded child buffer is re-analysed by the whole parser/carver set for free.
//! What was missing is the decoders that turn an encoded *span inside a buffer*
//! into that child. This module is those decoders.
//!
//! Each decoder here is single-shot and returns the decoded bytes. **Recursion
//! must be bounded by the caller**, not by these functions: the orchestrator
//! re-queues produced artifacts but does NOT track a generation/depth, so a
//! consumer that re-feeds decoded children (see `seance_plugin_bulk`'s
//! `DecodeRescan`) carries its own generation counter and stops at a fixed depth
//! — otherwise nested/compounding encodings would never terminate.

use base64::Engine;
use std::io::Read;

/// A decoded region: what was decoded, from where, and the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// Decoder that produced this (`"base64"`, `"gzip"`, `"xor255"`).
    pub method: &'static str,
    /// Offset in the parent buffer where the encoded span began.
    pub offset: usize,
    /// The decoded bytes — a child buffer for the pipeline to re-scan.
    pub data: Vec<u8>,
    /// True when `data` was cut short by an output cap (a decompression-bomb /
    /// budget guard). The bytes present are correct, but the decoded stream was
    /// longer; consumers must treat the content as incomplete, never as whole.
    pub truncated: bool,
}

/// Minimum decoded length worth emitting: below this the "decode" is noise.
const MIN_DECODED: usize = 16;

/// Largest total decoded output one base64 scan will allocate, across all spans.
/// The input is evidence content, so without this a buffer of base64 text makes
/// the decoder allocate three quarters of its own size before any caller can
/// apply a ceiling. Matches the largest decoded budget any caller scans
/// (`seance_plugin_yara`'s per-region byte ceiling).
pub const MAX_BASE64_TOTAL_OUT: usize = 64 * 1024 * 1024;
/// Cap on base64 spans one scan will decode — the same count as
/// `MAX_GZIP_ATTEMPTS`. Qualifying spans past it are counted, not decoded.
pub const MAX_BASE64_SPANS: usize = 4096;

/// The result of a base64 span scan: the decoded spans, and what the scan's
/// ceilings kept it from decoding. A consumer must carry `cap_reached` and
/// `spans_not_decoded` onto its coverage record — without them a capped scan
/// reads as a buffer that held no more encoded content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Base64Scan {
    /// The decoded spans, in buffer order. The last one may be `truncated`
    /// when the output ceiling fell inside it.
    pub decoded: Vec<Decoded>,
    /// Qualifying spans found after a ceiling was reached and never decoded.
    pub spans_not_decoded: usize,
    /// True when either ceiling ([`MAX_BASE64_SPANS`], [`MAX_BASE64_TOTAL_OUT`])
    /// stopped the scan decoding — a span was cut short or left undecoded.
    pub cap_reached: bool,
}

/// Find and decode base64 spans in a buffer.
///
/// A span is a run of ≥`min_b64_len` base64 characters. Each qualifying run is
/// decoded; runs that do not decode to a plausibly-binary payload are dropped.
/// Bounded by [`MAX_BASE64_SPANS`] and [`MAX_BASE64_TOTAL_OUT`]; what the
/// bounds left undecoded is on the returned [`Base64Scan`].
pub fn decode_base64_spans(buf: &[u8], min_b64_len: usize) -> Base64Scan {
    decode_base64_spans_bounded(buf, min_b64_len, MAX_BASE64_SPANS, MAX_BASE64_TOTAL_OUT)
}

fn decode_base64_spans_bounded(
    buf: &[u8],
    min_b64_len: usize,
    max_spans: usize,
    max_total_out: usize,
) -> Base64Scan {
    let engine = base64::engine::general_purpose::STANDARD;
    let mut scan = Base64Scan::default();
    let mut total_out = 0usize;
    let is_b64 = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=';
    let mut i = 0;
    while i < buf.len() {
        if !is_b64(buf[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < buf.len() && is_b64(buf[i]) {
            i += 1;
        }
        let span = &buf[start..i];
        if span.len() < min_b64_len {
            continue;
        }
        // base64 length must be a multiple of 4 to decode cleanly; trim any
        // trailing partial group rather than rejecting the whole span.
        let usable = span.len() - (span.len() % 4);
        if usable < min_b64_len {
            continue;
        }
        // Past a ceiling the span is counted, never decoded: the count is what
        // lets a consumer say how much encoded content went unexamined.
        if scan.decoded.len() >= max_spans || total_out >= max_total_out {
            scan.cap_reached = true;
            scan.spans_not_decoded += 1;
            continue;
        }
        // Decode at most the remaining output budget: whole 4-character groups
        // whose 3-byte outputs fit. A span cut here is marked truncated.
        let remaining = max_total_out - total_out;
        let budget_chars = (remaining / 3) * 4;
        let (take, truncated) = if usable > budget_chars {
            (budget_chars, true)
        } else {
            (usable, false)
        };
        if let Ok(data) = engine.decode(&span[..take]) {
            if data.len() >= MIN_DECODED {
                total_out += data.len();
                scan.cap_reached |= truncated;
                scan.decoded.push(Decoded {
                    method: "base64",
                    offset: start,
                    data,
                    truncated,
                });
            } else if truncated {
                // The budget left too little of this span to be worth emitting;
                // it is still a span the ceiling kept from being decoded.
                scan.cap_reached = true;
                scan.spans_not_decoded += 1;
            }
        }
    }
    scan
}

/// Largest total inflated output this scan will produce, across all members —
/// a guard against a decompression bomb and against adversarial input crafted to
/// make every offset inflate a lot.
const MAX_GZIP_TOTAL_OUT: usize = 512 * 1024 * 1024;
/// Cap on gzip-magic offsets a single scan will attempt to inflate. Each attempt
/// on a fake header fails cheaply, but a buffer crafted with many *valid* headers
/// whose bodies read far into the buffer would otherwise cost O(matches × size);
/// this bounds that to O(size). Well-formed images hold far fewer members.
const MAX_GZIP_ATTEMPTS: usize = 4096;

/// Find and inflate gzip members in a buffer (magic `1f 8b 08`).
pub fn decode_gzip_members(buf: &[u8]) -> Vec<Decoded> {
    let mut out = Vec::new();
    let mut base = 0;
    let mut attempts = 0usize;
    let mut total_out = 0usize;
    while base < buf.len() {
        let Some(rel) = memchr::memchr(0x1f, &buf[base..]) else {
            break;
        };
        let abs = base + rel;
        // gzip: 1f 8b 08 (deflate method).
        if abs + 3 <= buf.len() && buf[abs + 1] == 0x8b && buf[abs + 2] == 0x08 {
            if attempts >= MAX_GZIP_ATTEMPTS || total_out >= MAX_GZIP_TOTAL_OUT {
                break;
            }
            attempts += 1;
            let mut decoder = flate2::read::GzDecoder::new(&buf[abs..]);
            let mut data = Vec::new();
            // Bound each member's output too, so one crafted member cannot
            // inflate unboundedly (zip-bomb): read at most the remaining budget,
            // plus one byte so we can tell whether the stream was actually cut.
            let remaining = MAX_GZIP_TOTAL_OUT - total_out;
            let _ = std::io::Read::take(&mut decoder, remaining as u64 + 1).read_to_end(&mut data);
            // If we read more than the budget, the member was longer than we kept:
            // mark it truncated so a consumer never treats a partial file as whole.
            let truncated = data.len() > remaining;
            data.truncate(remaining);
            if data.len() >= MIN_DECODED {
                total_out += data.len();
                out.push(Decoded {
                    method: "gzip",
                    offset: abs,
                    data,
                    truncated,
                });
            }
        }
        base = abs + 1;
    }
    out
}

/// XOR the whole buffer with a single-byte key (the classic 0xFF/0x?? obfuscation
/// malware and packers use). Only emitted when the caller asks for a key, because
/// XOR of arbitrary data is always "successful" — the value is in re-scanning the
/// result, which the pipeline does. Returns one child buffer.
pub fn decode_xor(buf: &[u8], key: u8) -> Option<Decoded> {
    if buf.len() < MIN_DECODED || key == 0 {
        return None; // key 0 is a no-op
    }
    Some(Decoded {
        method: "xor",
        offset: 0,
        data: buf.iter().map(|b| b ^ key).collect(),
        truncated: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::io::Write;

    #[test]
    fn decodes_a_base64_embedded_payload() {
        // A "JPEG-ish" payload embedded as base64 in surrounding text — the
        // canonical bulk_extractor case.
        let payload: Vec<u8> = (0..64).map(|i| (i * 3 + 1) as u8).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
        let mut buf = b"prefix text ".to_vec();
        let span_start = buf.len();
        buf.extend_from_slice(b64.as_bytes());
        buf.extend_from_slice(b" suffix");

        let decoded = decode_base64_spans(&buf, 20).decoded;
        let hit = decoded
            .iter()
            .find(|d| d.data == payload)
            .expect("payload must round-trip out of base64");
        assert_eq!(hit.method, "base64");
        assert_eq!(hit.offset, span_start);
    }

    #[test]
    fn ignores_short_base64_noise() {
        // Short base64-looking runs (words like "data", "true") must not decode.
        let buf = b"the data is true and good";
        assert!(decode_base64_spans(buf, 20).decoded.is_empty());
    }

    #[test]
    fn inflates_a_gzip_member() {
        let original = b"the quick brown fox jumps over the lazy dog, repeatedly and at length";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let gz = encoder.finish().unwrap();

        let mut buf = vec![0u8, 1, 2, 3];
        let at = buf.len();
        buf.extend_from_slice(&gz);
        buf.extend_from_slice(&[9, 9, 9]);

        let members = decode_gzip_members(&buf);
        let hit = members
            .iter()
            .find(|d| d.offset == at)
            .expect("gzip member");
        assert_eq!(hit.method, "gzip");
        assert_eq!(hit.data, original);
        assert!(!hit.truncated, "a fully-inflated member is not truncated");
    }

    #[test]
    fn xor_deobfuscates_and_reverses() {
        let secret = b"a secret configuration string that is long enough";
        let obf: Vec<u8> = secret.iter().map(|b| b ^ 0x5a).collect();
        let decoded = decode_xor(&obf, 0x5a).expect("xor decode");
        assert_eq!(decoded.data, secret);
        assert_eq!(decoded.method, "xor");
    }

    #[test]
    fn xor_rejects_noop_key_and_tiny_buffers() {
        assert!(decode_xor(b"long enough buffer here", 0).is_none());
        assert!(decode_xor(b"short", 0x11).is_none());
    }

    #[test]
    fn gzip_scan_ignores_non_members() {
        // 0x1f bytes that are not gzip headers must not crash or yield output.
        let buf = vec![0x1f, 0x00, 0x1f, 0x42, 0x1f, 0x8b, 0x00];
        let members = decode_gzip_members(&buf);
        assert!(members.is_empty());
    }

    #[test]
    fn base64_scan_stops_decoding_at_the_span_ceiling() {
        // 5,000 distinct 32-character base64 lines — the shape of a log or a
        // mail spool full of encoded attachments' first lines.
        let mut buf = Vec::new();
        for i in 0..5000u32 {
            let payload: Vec<u8> = (0..24).map(|j| (i as u8).wrapping_add(j)).collect();
            buf.extend_from_slice(
                base64::engine::general_purpose::STANDARD
                    .encode(&payload)
                    .as_bytes(),
            );
            buf.push(b'\n');
        }
        let scan = decode_base64_spans(&buf, 20);
        assert!(
            scan.decoded.len() <= MAX_BASE64_SPANS,
            "decoded {} spans, no ceiling",
            scan.decoded.len()
        );
        assert_eq!(scan.decoded.len(), MAX_BASE64_SPANS);
        assert!(scan.cap_reached, "the ceiling must be reported, not silent");
        assert_eq!(scan.spans_not_decoded, 5000 - MAX_BASE64_SPANS);
    }

    #[test]
    fn base64_scan_stops_allocating_at_the_output_ceiling() {
        // Three 4,000-character spans (3,000 bytes decoded each) against a
        // 5,000-byte budget: the first decodes whole, the second is cut at the
        // budget and marked truncated, the third is counted and not decoded.
        let payload: Vec<u8> = (0..3000u32).map(|i| (i * 7 + 3) as u8).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
        let mut buf = Vec::new();
        for _ in 0..3 {
            buf.extend_from_slice(b64.as_bytes());
            buf.extend_from_slice(b"\r\n--boundary--\r\n");
        }
        let scan = decode_base64_spans_bounded(&buf, 20, MAX_BASE64_SPANS, 5000);
        assert_eq!(scan.decoded.len(), 2);
        assert_eq!(scan.decoded[0].data, payload);
        assert!(!scan.decoded[0].truncated);
        assert_eq!(scan.decoded[1].data, payload[..1998].to_vec());
        assert!(
            scan.decoded[1].truncated,
            "a span cut by the budget says so"
        );
        let total: usize = scan.decoded.iter().map(|d| d.data.len()).sum();
        assert!(
            total <= 5000,
            "allocated {total} bytes past a 5000-byte budget"
        );
        assert!(scan.cap_reached);
        assert_eq!(scan.spans_not_decoded, 1);
    }

    #[test]
    fn an_uncapped_base64_scan_reports_no_cap() {
        let payload: Vec<u8> = (0..64).map(|i| (i * 3 + 1) as u8).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
        let scan = decode_base64_spans(b64.as_bytes(), 20);
        assert_eq!(scan.decoded.len(), 1);
        assert!(!scan.cap_reached);
        assert_eq!(scan.spans_not_decoded, 0);
    }

    #[test]
    fn round_trips_through_the_pipeline_shape() {
        // Prove the decoded child is itself scannable: base64 → bytes containing
        // an email, which the feature scanner then finds. This is the whole point
        // of decode-and-rescan.
        let inner = b"buried agent@covert.gov inside base64 padding padding padding";
        let b64 = base64::engine::general_purpose::STANDARD.encode(inner);
        let decoded = decode_base64_spans(b64.as_bytes(), 20).decoded;
        assert_eq!(decoded.len(), 1);
        let hits = crate::features::FeatureScanner::new().scan(&decoded[0].data);
        assert!(hits
            .iter()
            .any(|h| h.kind == "email" && h.value == "agent@covert.gov"));
    }
}
