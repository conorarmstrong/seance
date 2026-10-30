//! decmpfs: Apple's transparent file compression, as used on APFS (and HFS+).
//!
//! A compressed file has **no data-stream extents at all**. Its logical bytes
//! live either inside the `com.apple.decmpfs` extended attribute or in the data
//! stream of the `com.apple.ResourceFork` extended attribute, in fixed 64 KiB
//! chunks. Serving the extents that back that resource fork as the file's
//! content hands an examiner a compressed stream and hashes it as though it
//! were the file (BUG-156).
//!
//! Fail-closed contract: every function here either returns the file's complete
//! decoded bytes or an error naming why it could not. There is no partial
//! result and no fallback to the compressed bytes. An algorithm this module
//! cannot decode (LZFSE, compression types Apple has not documented) is an
//! error, never a pass-through — the caller turns that into an explicit
//! "content not decoded" flag on the artifact.

use crate::lzvn;
use flate2::read::ZlibDecoder;
use std::io::Read;

/// `decmpfs_disk_header.compression_magic`: the ASCII bytes `fpmc`, stored
/// little-endian.
pub(crate) const DECMPFS_MAGIC: u32 = 0x636d_7066;

/// Size of `decmpfs_disk_header` (magic, type, uncompressed size).
pub(crate) const DECMPFS_HEADER_LEN: usize = 16;

/// decmpfs stores compressed data in fixed chunks of this many decoded bytes;
/// only the final chunk is shorter.
pub(crate) const DECMPFS_CHUNK_LEN: usize = 65536;

/// How the decoded bytes were produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Algorithm {
    /// Not compressed at all — the bytes are stored verbatim.
    Stored,
    Zlib,
    Lzvn,
}

/// Where the compressed bytes live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Storage {
    /// Inside the `com.apple.decmpfs` attribute, after its 16-byte header.
    InlineXattr,
    /// In the data stream of the `com.apple.ResourceFork` attribute.
    ResourceFork,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Scheme {
    pub algorithm: Algorithm,
    pub storage: Storage,
}

impl Scheme {
    pub(crate) fn algorithm_label(&self) -> &'static str {
        match self.algorithm {
            Algorithm::Stored => "none",
            Algorithm::Zlib => "zlib",
            Algorithm::Lzvn => "lzvn",
        }
    }

    pub(crate) fn storage_label(&self) -> &'static str {
        match self.storage {
            Storage::InlineXattr => "inline_xattr",
            Storage::ResourceFork => "resource_fork",
        }
    }

    /// Stable identifier for the exact on-disk form, for artifact metadata.
    pub(crate) fn format_label(&self) -> &'static str {
        match (self.algorithm, self.storage) {
            (Algorithm::Stored, Storage::InlineXattr) => "decmpfs_stored_inline",
            (Algorithm::Stored, Storage::ResourceFork) => "decmpfs_stored_rsrc",
            (Algorithm::Zlib, Storage::InlineXattr) => "decmpfs_zlib_inline",
            (Algorithm::Zlib, Storage::ResourceFork) => "decmpfs_zlib_rsrc",
            (Algorithm::Lzvn, Storage::InlineXattr) => "decmpfs_lzvn_inline",
            (Algorithm::Lzvn, Storage::ResourceFork) => "decmpfs_lzvn_rsrc",
        }
    }
}

/// Map `decmpfs_disk_header.compression_type` to a scheme this module can
/// decode, or `None` when it cannot.
///
/// `None` is a first-class answer, not an omission: types 11 and 12 are LZFSE
/// and are decidedly real on modern macOS. The caller must flag those files as
/// undecoded rather than serve their compressed bytes.
pub(crate) fn scheme(compression_type: u32) -> Option<Scheme> {
    let (algorithm, storage) = match compression_type {
        1 | 9 => (Algorithm::Stored, Storage::InlineXattr),
        3 => (Algorithm::Zlib, Storage::InlineXattr),
        4 => (Algorithm::Zlib, Storage::ResourceFork),
        7 => (Algorithm::Lzvn, Storage::InlineXattr),
        8 => (Algorithm::Lzvn, Storage::ResourceFork),
        _ => return None,
    };
    Some(Scheme { algorithm, storage })
}

/// A parsed `decmpfs_disk_header`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub compression_type: u32,
    /// The file's logical size, as recorded by decmpfs itself.
    pub uncompressed_size: u64,
}

/// Parse the `com.apple.decmpfs` attribute header.
///
/// Returns `None` when the attribute is too short or does not carry the decmpfs
/// magic — an attribute of that name that is not a decmpfs header tells us
/// nothing about the file, and guessing would be worse than saying so.
pub(crate) fn parse_header(xattr: &[u8]) -> Option<Header> {
    if xattr.len() < DECMPFS_HEADER_LEN {
        return None;
    }
    let magic = u32::from_le_bytes([xattr[0], xattr[1], xattr[2], xattr[3]]);
    if magic != DECMPFS_MAGIC {
        return None;
    }
    Some(Header {
        compression_type: u32::from_le_bytes([xattr[4], xattr[5], xattr[6], xattr[7]]),
        uncompressed_size: u64::from_le_bytes([
            xattr[8], xattr[9], xattr[10], xattr[11], xattr[12], xattr[13], xattr[14], xattr[15],
        ]),
    })
}

/// Decode a compressed file's complete contents.
///
/// `payload` is the inline attribute bytes *after* the 16-byte header for
/// [`Storage::InlineXattr`], or the whole resource-fork stream for
/// [`Storage::ResourceFork`]. The result is always exactly
/// `uncompressed_size` bytes or an error.
pub(crate) fn decode(
    scheme: Scheme,
    payload: &[u8],
    uncompressed_size: usize,
) -> Result<Vec<u8>, String> {
    match (scheme.algorithm, scheme.storage) {
        (algorithm, Storage::InlineXattr) => decode_inline(algorithm, payload, uncompressed_size),
        (Algorithm::Zlib, Storage::ResourceFork) => {
            decode_zlib_resource_fork(payload, uncompressed_size)
        }
        (Algorithm::Lzvn, Storage::ResourceFork) => {
            decode_lzvn_resource_fork(payload, uncompressed_size)
        }
        (Algorithm::Stored, Storage::ResourceFork) => Err(
            "decmpfs declares uncompressed storage in the resource fork, whose layout this parser \
             does not know"
                .to_string(),
        ),
    }
}

fn decode_inline(
    algorithm: Algorithm,
    payload: &[u8],
    uncompressed_size: usize,
) -> Result<Vec<u8>, String> {
    match algorithm {
        // Stored inline comes in two forms: the bytes on their own, or the
        // bytes behind a single marker byte. The length settles which, so this
        // is a determination and not a guess; anything else is an error.
        Algorithm::Stored => {
            if payload.len() == uncompressed_size {
                Ok(payload.to_vec())
            } else if payload.len() == uncompressed_size + 1 {
                Ok(payload[1..].to_vec())
            } else {
                Err(format!(
                    "decmpfs stored attribute holds {} byte(s) for a {uncompressed_size}-byte file",
                    payload.len()
                ))
            }
        }
        // A leading byte whose low nibble is 0xF marks an uncompressed block;
        // a real zlib stream cannot start that way (the low nibble of a zlib
        // CMF byte is the compression method, which is always 8).
        Algorithm::Zlib => {
            if payload.first().is_some_and(|b| (b & 0x0F) == 0x0F) {
                exactly(
                    &payload[1..],
                    uncompressed_size,
                    "decmpfs stored zlib block",
                )
            } else {
                inflate(payload, uncompressed_size)
            }
        }
        // Likewise for LZVN: a block cannot begin with end-of-stream.
        Algorithm::Lzvn => {
            if payload.first() == Some(&lzvn::EOS_OPCODE) {
                exactly(
                    &payload[1..],
                    uncompressed_size,
                    "decmpfs stored LZVN block",
                )
            } else {
                lzvn::decode(payload, uncompressed_size)
            }
        }
    }
}

/// Copy `bytes` when it is exactly `expected` long, and fail otherwise.
fn exactly(bytes: &[u8], expected: usize, what: &str) -> Result<Vec<u8>, String> {
    if bytes.len() != expected {
        return Err(format!(
            "{what} holds {} byte(s) where {expected} were expected",
            bytes.len()
        ));
    }
    Ok(bytes.to_vec())
}

fn inflate(src: &[u8], expected: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(expected);
    ZlibDecoder::new(src)
        .read_to_end(&mut out)
        .map_err(|e| format!("decmpfs zlib block failed to inflate: {e}"))?;
    if out.len() != expected {
        return Err(format!(
            "decmpfs zlib block inflated to {} byte(s) where {expected} were expected",
            out.len()
        ));
    }
    Ok(out)
}

/// How many 64 KiB chunks a file of `size` decoded bytes occupies.
fn chunk_count(size: usize) -> usize {
    size.div_ceil(DECMPFS_CHUNK_LEN)
}

/// LZVN resource fork: the stream opens with a little-endian `u32` table of
/// chunk offsets. The first entry doubles as the table's own length, so the
/// chunk count is `table[0] / 4 - 1`, and chunk `i` spans
/// `table[i] .. table[i + 1]`.
fn decode_lzvn_resource_fork(payload: &[u8], uncompressed_size: usize) -> Result<Vec<u8>, String> {
    if payload.len() < 8 {
        return Err(format!(
            "decmpfs LZVN resource fork is {} byte(s), too short to hold a chunk table",
            payload.len()
        ));
    }
    let table_len = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    if table_len < 8 || !table_len.is_multiple_of(4) || table_len > payload.len() {
        return Err(format!(
            "decmpfs LZVN resource fork declares an implausible {table_len}-byte chunk table in \
             {} byte(s)",
            payload.len()
        ));
    }
    let count = table_len / 4 - 1;
    let expected = chunk_count(uncompressed_size);
    if count != expected {
        return Err(format!(
            "decmpfs LZVN resource fork lists {count} chunk(s) for a {uncompressed_size}-byte \
             file that needs {expected}"
        ));
    }

    let mut offsets: Vec<usize> = Vec::with_capacity(count + 1);
    for i in 0..=count {
        let at = i * 4;
        let raw = payload
            .get(at..at + 4)
            .ok_or_else(|| format!("decmpfs LZVN chunk table entry {i} is past the stream"))?;
        let off = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        if off > payload.len() {
            return Err(format!(
                "decmpfs LZVN chunk table entry {i} points to offset {off}, past the {}-byte \
                 stream",
                payload.len()
            ));
        }
        if offsets.last().is_some_and(|&prev| off < prev) {
            return Err(format!(
                "decmpfs LZVN chunk table entry {i} runs backwards to offset {off}"
            ));
        }
        offsets.push(off);
    }

    let mut out: Vec<u8> = Vec::with_capacity(uncompressed_size);
    for (i, window) in offsets.windows(2).enumerate() {
        if out.len() >= uncompressed_size {
            return Err(format!(
                "decmpfs LZVN resource fork has more chunks than its {uncompressed_size}-byte \
                 logical size accounts for"
            ));
        }
        let chunk = &payload[window[0]..window[1]];
        if chunk.is_empty() {
            return Err(format!("decmpfs LZVN chunk {i} is empty"));
        }
        let want = std::cmp::min(DECMPFS_CHUNK_LEN, uncompressed_size - out.len());
        let decoded = if chunk[0] == lzvn::EOS_OPCODE {
            exactly(&chunk[1..], want, "decmpfs stored LZVN chunk")?
        } else {
            lzvn::decode(chunk, want)?
        };
        out.extend_from_slice(&decoded);
    }

    if out.len() != uncompressed_size {
        return Err(format!(
            "decmpfs LZVN resource fork decoded to {} byte(s) where {uncompressed_size} were \
             expected",
            out.len()
        ));
    }
    Ok(out)
}

/// zlib resource fork: a classic resource-fork header points at a block whose
/// first little-endian `u32` is the chunk count, followed by that many
/// `(offset, length)` pairs relative to the start of the block.
fn decode_zlib_resource_fork(payload: &[u8], uncompressed_size: usize) -> Result<Vec<u8>, String> {
    if payload.len() < 16 {
        return Err(format!(
            "decmpfs zlib resource fork is {} byte(s), too short to hold a resource header",
            payload.len()
        ));
    }
    // Resource-fork header fields are big-endian.
    let data_offset = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    // Checked throughout: every one of these values comes off the image.
    let body_start = data_offset
        .checked_add(4)
        .ok_or_else(|| format!("decmpfs zlib resource fork data offset {data_offset} overflows"))?;
    let declared = payload
        .get(data_offset..body_start)
        .ok_or_else(|| {
            format!(
                "decmpfs zlib resource fork data offset {data_offset} is past the {}-byte stream",
                payload.len()
            )
        })
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)?;
    let body_end = body_start
        .checked_add(declared)
        .ok_or_else(|| format!("decmpfs zlib resource fork data length {declared} overflows"))?;
    let body = payload.get(body_start..body_end).ok_or_else(|| {
        format!(
            "decmpfs zlib resource fork declares {declared} byte(s) of data at offset \
                 {body_start}, past the {}-byte stream",
            payload.len()
        )
    })?;
    if body.len() < 4 {
        return Err("decmpfs zlib resource fork holds no chunk table".to_string());
    }

    let count = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    let expected = chunk_count(uncompressed_size);
    if count != expected {
        return Err(format!(
            "decmpfs zlib resource fork lists {count} chunk(s) for a {uncompressed_size}-byte \
             file that needs {expected}"
        ));
    }
    let table_end = count
        .checked_mul(8)
        .and_then(|n| n.checked_add(4))
        .ok_or_else(|| "decmpfs zlib chunk table length overflows".to_string())?;
    if table_end > body.len() {
        return Err(format!(
            "decmpfs zlib chunk table needs {table_end} byte(s) of a {}-byte block",
            body.len()
        ));
    }

    let mut out: Vec<u8> = Vec::with_capacity(uncompressed_size);
    for i in 0..count {
        let at = 4 + i * 8;
        let off = u32::from_le_bytes([body[at], body[at + 1], body[at + 2], body[at + 3]]) as usize;
        let len =
            u32::from_le_bytes([body[at + 4], body[at + 5], body[at + 6], body[at + 7]]) as usize;
        let end = off
            .checked_add(len)
            .ok_or_else(|| format!("decmpfs zlib chunk {i} has an overflowing extent"))?;
        let chunk = body.get(off..end).ok_or_else(|| {
            format!(
                "decmpfs zlib chunk {i} spans {off}..{end}, past the {}-byte block",
                body.len()
            )
        })?;
        if chunk.is_empty() {
            return Err(format!("decmpfs zlib chunk {i} is empty"));
        }
        if out.len() >= uncompressed_size {
            return Err(format!(
                "decmpfs zlib resource fork has more chunks than its {uncompressed_size}-byte \
                 logical size accounts for"
            ));
        }
        let want = std::cmp::min(DECMPFS_CHUNK_LEN, uncompressed_size - out.len());
        let decoded = if (chunk[0] & 0x0F) == 0x0F {
            exactly(&chunk[1..], want, "decmpfs stored zlib chunk")?
        } else {
            inflate(chunk, want)?
        };
        out.extend_from_slice(&decoded);
    }

    if out.len() != uncompressed_size {
        return Err(format!(
            "decmpfs zlib resource fork decoded to {} byte(s) where {uncompressed_size} were \
             expected",
            out.len()
        ));
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::lzvn::tests::{real_tail_chunk, real_tail_expected, REAL_TAIL_LEN};

    /// Build a `com.apple.decmpfs` attribute value.
    pub(crate) fn decmpfs_xattr(
        compression_type: u32,
        uncompressed_size: u64,
        body: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(DECMPFS_HEADER_LEN + body.len());
        out.extend_from_slice(&DECMPFS_MAGIC.to_le_bytes());
        out.extend_from_slice(&compression_type.to_le_bytes());
        out.extend_from_slice(&uncompressed_size.to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    /// Wrap already-encoded LZVN chunks in the resource-fork chunk table decmpfs
    /// type 8 uses.
    pub(crate) fn lzvn_resource_fork(chunks: &[Vec<u8>]) -> Vec<u8> {
        let table_len = (chunks.len() + 1) * 4;
        let mut offsets = Vec::with_capacity(chunks.len() + 1);
        let mut at = table_len;
        offsets.push(at);
        for c in chunks {
            at += c.len();
            offsets.push(at);
        }
        let mut out = Vec::with_capacity(at);
        for off in &offsets {
            out.extend_from_slice(&(*off as u32).to_le_bytes());
        }
        for c in chunks {
            out.extend_from_slice(c);
        }
        out
    }

    /// Wrap already-compressed zlib chunks in the resource-fork layout decmpfs
    /// type 4 uses.
    fn zlib_resource_fork(chunks: &[Vec<u8>]) -> Vec<u8> {
        let table_len = 4 + chunks.len() * 8;
        let mut block = Vec::new();
        block.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
        let mut at = table_len;
        for c in chunks {
            block.extend_from_slice(&(at as u32).to_le_bytes());
            block.extend_from_slice(&(c.len() as u32).to_le_bytes());
            at += c.len();
        }
        for c in chunks {
            block.extend_from_slice(c);
        }

        const DATA_OFFSET: usize = 256;
        let mut out = vec![0u8; DATA_OFFSET];
        out[0..4].copy_from_slice(&(DATA_OFFSET as u32).to_be_bytes());
        out[4..8].copy_from_slice(&((DATA_OFFSET + 4 + block.len()) as u32).to_be_bytes());
        out[8..12].copy_from_slice(&((block.len() + 4) as u32).to_be_bytes());
        out[12..16].copy_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(block.len() as u32).to_be_bytes());
        out.extend_from_slice(&block);
        out
    }

    fn deflate(bytes: &[u8]) -> Vec<u8> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn parses_a_real_decmpfs_header() {
        // Byte-for-byte the `com.apple.decmpfs` value of the 4,200,000-byte
        // fixture file: type 8 (LZVN in the resource fork).
        let raw = [
            0x66, 0x70, 0x6d, 0x63, 0x08, 0x00, 0x00, 0x00, 0x40, 0x16, 0x40, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let hdr = parse_header(&raw).expect("a real decmpfs header must parse");
        assert_eq!(hdr.compression_type, 8);
        assert_eq!(hdr.uncompressed_size, 4_200_000);
        let s = scheme(hdr.compression_type).expect("type 8 must be decodable");
        assert_eq!(s.algorithm, Algorithm::Lzvn);
        assert_eq!(s.storage, Storage::ResourceFork);
        assert_eq!(s.format_label(), "decmpfs_lzvn_rsrc");
    }

    #[test]
    fn rejects_an_attribute_without_the_decmpfs_magic() {
        assert!(parse_header(&[0u8; 16]).is_none());
        assert!(parse_header(&[0x66, 0x70, 0x6d]).is_none());
    }

    #[test]
    fn decodes_a_real_lzvn_resource_fork() {
        let rfork = lzvn_resource_fork(&[real_tail_chunk()]);
        let s = scheme(8).unwrap();
        let out = decode(s, &rfork, REAL_TAIL_LEN).expect("a real LZVN resource fork must decode");
        assert_eq!(out, real_tail_expected());
    }

    #[test]
    fn zlib_resource_fork_round_trips() {
        let plain: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let chunks: Vec<Vec<u8>> = plain.chunks(DECMPFS_CHUNK_LEN).map(deflate).collect();
        assert_eq!(chunks.len(), 2);
        let rfork = zlib_resource_fork(&chunks);
        let s = scheme(4).unwrap();
        assert_eq!(decode(s, &rfork, plain.len()).unwrap(), plain);
    }

    #[test]
    fn zlib_inline_round_trips() {
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(40);
        let body = deflate(&plain);
        let s = scheme(3).unwrap();
        assert_eq!(decode(s, &body, plain.len()).unwrap(), plain);
    }

    #[test]
    fn stored_inline_accepts_the_marker_byte_form() {
        // Real type-9 attributes carry one marker byte before the data.
        let plain = b"APPL????".to_vec();
        let mut body = vec![0xCCu8];
        body.extend_from_slice(&plain);
        let s = scheme(9).unwrap();
        assert_eq!(decode(s, &body, plain.len()).unwrap(), plain);
        // ... and the bare form.
        assert_eq!(decode(s, &plain, plain.len()).unwrap(), plain);
        // ... but not a length that matches neither.
        assert!(decode(s, &body, plain.len() + 4).is_err());
    }

    #[test]
    fn lzfse_and_unknown_types_are_reported_undecodable_not_passed_through() {
        // 11/12 are LZFSE and are real on modern macOS. The contract is that
        // they resolve to "no scheme" so the caller flags the file, rather than
        // this module quietly handing back the compressed bytes.
        assert!(scheme(11).is_none());
        assert!(scheme(12).is_none());
        assert!(scheme(0).is_none());
        assert!(scheme(99).is_none());
    }

    #[test]
    fn a_truncated_resource_fork_fails_closed() {
        let rfork = lzvn_resource_fork(&[real_tail_chunk()]);
        let s = scheme(8).unwrap();
        for cut in [4usize, 8, 20, rfork.len() - 1] {
            assert!(
                decode(s, &rfork[..cut], REAL_TAIL_LEN).is_err(),
                "a resource fork cut to {cut} bytes must not decode"
            );
        }
    }

    #[test]
    fn a_chunk_count_that_disagrees_with_the_logical_size_fails_closed() {
        // One chunk cannot hold a file larger than 64 KiB; claiming it does is
        // exactly the mis-framing that would produce short content.
        let rfork = lzvn_resource_fork(&[real_tail_chunk()]);
        let s = scheme(8).unwrap();
        let err = decode(s, &rfork, 200_000).expect_err("chunk count mismatch must fail");
        assert!(err.contains("chunk"), "{err}");
    }

    #[test]
    fn corrupt_compressed_bytes_never_yield_partial_content() {
        let mut rfork = lzvn_resource_fork(&[real_tail_chunk()]);
        let last = rfork.len() - 12;
        rfork[last] ^= 0xFF;
        let s = scheme(8).unwrap();
        assert!(decode(s, &rfork, REAL_TAIL_LEN).is_err());
    }
}
