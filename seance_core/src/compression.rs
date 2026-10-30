//! Filesystem content decompression, shared by the parsers (which decompress
//! in-memory at ingest so search indexing sees real content) and the API
//! content resolver (which decompresses on demand when re-serving from the DB,
//! with no size cap and no inlined bytes).
//!
//! - NTFS `$DATA`: LZNT1 over compression units (a hand-rolled decoder).
//! - btrfs extents: zlib or zstd per extent.

use std::sync::Arc;

use crate::data_source::{DataSource, RunListDataSource};

// --- NTFS LZNT1 -----------------------------------------------------------

/// Decompress an LZNT1 chunk stream (NTFS-compressed `$DATA`), producing up to
/// `max_out` bytes. Each chunk begins with a 2-byte header: bits 0-11 = chunk
/// data length minus 1, bit 15 = compressed. A zero header ends the stream.
/// Compressed chunks use flag-byte groups of 8 tokens: a 0 bit is a literal
/// byte, a 1 bit a 2-byte back-reference whose length/displacement bit split
/// widens as the chunk fills.
///
/// A malformed token (a truncated back-reference, a back-reference with nothing
/// to copy from, or one that reaches before the chunk start) means the stream
/// has lost synchronisation: everything after it would be garbage that merely
/// looks like content. The whole call fails with `InvalidData` rather than
/// returning what was decoded so far.
pub fn lznt1_decompress(input: &[u8], max_out: usize) -> std::io::Result<Vec<u8>> {
    let corrupt = |what: &str| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("malformed LZNT1 stream: {what}"),
        )
    };
    let mut out: Vec<u8> = Vec::with_capacity(max_out.min(1 << 20));
    let mut ip = 0usize;
    while ip + 2 <= input.len() && out.len() < max_out {
        let header = u16::from_le_bytes([input[ip], input[ip + 1]]);
        ip += 2;
        if header == 0 {
            break; // end of chunks (or sparse padding)
        }
        let chunk_len = ((header & 0x0FFF) as usize) + 1;
        let compressed = (header & 0x8000) != 0;
        let chunk_end = (ip + chunk_len).min(input.len());
        if !compressed {
            out.extend_from_slice(&input[ip..chunk_end]);
            ip = chunk_end;
            continue;
        }
        let chunk_out_start = out.len();
        while ip < chunk_end && out.len() < max_out {
            let flags = input[ip];
            ip += 1;
            for bit in 0..8 {
                if ip >= chunk_end || out.len() >= max_out {
                    break;
                }
                if (flags >> bit) & 1 == 0 {
                    out.push(input[ip]);
                    ip += 1;
                } else {
                    if ip + 2 > chunk_end {
                        return Err(corrupt("truncated back-reference token"));
                    }
                    let token = u16::from_le_bytes([input[ip], input[ip + 1]]) as usize;
                    ip += 2;
                    let pos = out.len() - chunk_out_start;
                    if pos == 0 {
                        return Err(corrupt("back-reference with nothing to copy from"));
                    }
                    let mut i = pos - 1;
                    let mut lmask = 0x0FFFusize;
                    let mut dshift = 12usize;
                    while i >= 0x10 {
                        lmask >>= 1;
                        dshift -= 1;
                        i >>= 1;
                    }
                    let length = (token & lmask) + 3;
                    let delta = (token >> dshift) + 1;
                    if delta > pos {
                        return Err(corrupt("back-reference before the start of the chunk"));
                    }
                    let start = out.len() - delta;
                    for src in start..start + length {
                        if out.len() >= max_out {
                            break;
                        }
                        let b = out[src];
                        out.push(b);
                    }
                }
            }
        }
        ip = chunk_end;
    }
    Ok(out)
}

/// Total non-sparse (allocated) bytes of `runs` overlapping [start, start+len).
fn allocated_len_in_range(runs: &[(Option<u64>, u64)], start: u64, len: u64) -> u64 {
    // Saturate rather than wrap: a corrupt run length must not turn a large
    // logical range into a small one and undercount allocated bytes.
    let end = start.saturating_add(len);
    let mut pos = 0u64;
    let mut allocated = 0u64;
    for (phys, run_len) in runs {
        let run_start = pos;
        let run_end = pos.saturating_add(*run_len);
        pos = run_end;
        if run_end <= start || run_start >= end || phys.is_none() {
            continue;
        }
        allocated += run_end.min(end) - run_start.max(start);
    }
    allocated
}

/// Read `buf.len()` bytes from `src` at `offset`. Returns `true` only if the
/// whole buffer was filled; a short read (EOF/error) returns `false` so callers
/// fail closed instead of treating the unread tail as real zero bytes.
#[must_use]
fn read_all_at(src: &dyn DataSource, offset: u64, buf: &mut [u8]) -> bool {
    let mut o = 0usize;
    while o < buf.len() {
        match src.read_at(offset + o as u64, &mut buf[o..]) {
            Ok(0) => break,
            Ok(n) => o += n,
            Err(_) => break,
        }
    }
    o == buf.len()
}

/// Reconstruct the logical content of an LZNT1-compressed `$DATA` attribute by
/// walking the run list one compression unit at a time. Each unit is stored
/// either fully allocated (uncompressed), partially allocated (compressed, with
/// sparse padding), or fully sparse (zeros). `byte_runs` are the on-disk
/// (compressed) runs relative to `fs_source`; `unit_size` is the compression
/// unit in bytes.
pub fn decompress_ntfs_data(
    fs_source: &Arc<dyn DataSource>,
    byte_runs: &[(Option<u64>, u64)],
    unit_size: u64,
    logical_size: u64,
) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind};
    if unit_size == 0 {
        return Ok(Vec::new());
    }
    // Defence in depth: `logical_size` originates from evidence metadata. Bound
    // the produced output so a hostile value can't exhaust memory even if a
    // caller reaches this without its own cap (the API resolver caps first).
    let logical_size = logical_size.min(MAX_DECOMPRESSED_BYTES);
    // `from_allocation`, not `with_logical_size`: `byte_runs` are the runs of
    // the *compressed* stream and `logical_size` is the length of the
    // *decompressed* output. Fitting the reader to `logical_size` would cut the
    // compressed input to the size of its own result, and the decompressor
    // would run out of input partway through every file whose data compressed
    // at all. The allocation genuinely is the content here.
    let reader = RunListDataSource::from_allocation(fs_source.clone(), byte_runs.to_vec());
    // Grow as we go rather than reserving the full (attacker-controlled) length.
    let mut out: Vec<u8> = Vec::with_capacity((logical_size as usize).min(1 << 20));
    let mut v = 0u64;
    while v < logical_size {
        let out_len = unit_size.min(logical_size - v) as usize;
        let alloc = allocated_len_in_range(byte_runs, v, unit_size);
        if alloc == 0 {
            out.resize(out.len() + out_len, 0); // fully sparse -- legitimately zeros
        } else if alloc >= unit_size {
            let mut buf = vec![0u8; out_len]; // stored uncompressed
                                              // A short read of on-disk bytes must not be served as zeros: a
                                              // truncated/corrupt compressed $DATA has to fail, not fabricate
                                              // plausible content that then hashes as if complete (BUG-046).
            if !read_all_at(&reader, v, &mut buf) {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "short read of uncompressed NTFS unit; refusing to zero-pad",
                ));
            }
            out.extend_from_slice(&buf);
        } else {
            let mut comp = vec![0u8; alloc as usize]; // compressed blob at unit start
            if !read_all_at(&reader, v, &mut comp) {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "short read of compressed NTFS unit; refusing to decode partial data",
                ));
            }
            let dec = lznt1_decompress(&comp, out_len)?;
            // LZNT1 units decompress to the full unit length (out_len for the
            // final partial unit). Fewer bytes means truncation/corruption --
            // do not pad the shortfall with zeros.
            if dec.len() < out_len {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "LZNT1 unit decompressed short; refusing to zero-pad",
                ));
            }
            out.extend_from_slice(&dec[..out_len]);
        }
        v += unit_size;
    }
    out.truncate(logical_size as usize);
    Ok(out)
}

// --- btrfs (zlib / zstd) --------------------------------------------------

/// Absolute ceiling on any single decompressed output, in bytes. Sizes driving
/// decompression allocations come from parsed evidence (claimed logical / ram
/// lengths), so they are attacker-controlled; producing more than this is
/// treated as a decode failure rather than an out-of-memory abort. 4 GiB covers
/// legitimate single-file content with wide margin.
pub const MAX_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// btrfs compression types (from the file_extent_item compression field).
pub const BTRFS_COMPRESS_NONE: u8 = 0;
pub const BTRFS_COMPRESS_ZLIB: u8 = 1;
pub const BTRFS_COMPRESS_ZSTD: u8 = 3;

/// Read up to `out.len()` decompressed bytes, tolerating a stream that ends
/// early (the last extent's ram_bytes can exceed the real decompressed length).
/// Returns the number of bytes produced, or `None` on any decoder error: an
/// error partway through a stream is corruption, and returning the shorter
/// output as if the stream had ended would present truncated content as whole.
fn read_up_to<R: std::io::Read>(r: &mut R, out: &mut [u8]) -> Option<usize> {
    let mut filled = 0;
    while filled < out.len() {
        match r.read(&mut out[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return None,
        }
    }
    Some(filled)
}

/// Decode a zlib extent into `out`. Returns the bytes produced when the stream
/// ends cleanly or `out` fills; `None` for a corrupt stream or one that ends
/// before its end marker. (A `Read` decoder answers `Ok(0)` for truncated
/// input, which cannot be told from a clean end of stream.)
fn zlib_up_to(data: &[u8], out: &mut [u8]) -> Option<usize> {
    use flate2::{Decompress, FlushDecompress, Status};
    if out.is_empty() {
        return Some(0);
    }
    let mut d = Decompress::new(true);
    loop {
        let (before_in, before_out) = (d.total_in(), d.total_out());
        let status = d
            .decompress(
                &data[before_in as usize..],
                &mut out[before_out as usize..],
                FlushDecompress::None,
            )
            .ok()?;
        let produced = d.total_out() as usize;
        if status == Status::StreamEnd || produced == out.len() {
            return Some(produced);
        }
        if d.total_in() == before_in && d.total_out() == before_out {
            return None; // input exhausted before the end marker
        }
    }
}

/// Decode a zstd extent: one or more frames, optionally followed by zero sector
/// padding (the last extent's ram_bytes can exceed the real length, and the
/// padding is not a frame). Anything after a frame that is neither zero padding
/// nor another valid frame is a decode failure, not an end of stream.
fn zstd_up_to(data: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut rest = data;
    let mut filled = 0;
    loop {
        let mut dec = zstd::stream::read::Decoder::with_buffer(rest)
            .ok()?
            .single_frame();
        filled += read_up_to(&mut dec, &mut out[filled..])?;
        rest = dec.finish();
        if filled == out.len() || rest.iter().all(|&b| b == 0) {
            return Some(filled);
        }
    }
}

/// Decompress a single btrfs extent blob (one compression stream per extent).
/// Returns None for LZO (no pure-Rust decoder wired up) or on decode failure.
/// The result may be shorter than `expected` only when the stream genuinely
/// ends early; callers that know the exact length should compare.
pub fn btrfs_decompress_blob(compression: u8, data: &[u8], expected: usize) -> Option<Vec<u8>> {
    // `expected` is the extent's claimed decompressed length from evidence;
    // refuse rather than allocate an unbounded buffer.
    if expected as u64 > MAX_DECOMPRESSED_BYTES {
        return None;
    }
    let mut out = vec![0u8; expected];
    let filled = match compression {
        BTRFS_COMPRESS_ZLIB => zlib_up_to(data, &mut out)?,
        BTRFS_COMPRESS_ZSTD => zstd_up_to(data, &mut out)?,
        _ => return None, // LZO (2) unsupported
    };
    out.truncate(filled);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lznt1_uncompressed_chunk_is_copied() {
        let input = [0x04, 0x30, 1, 2, 3, 4, 5];
        assert_eq!(lznt1_decompress(&input, 4096).unwrap(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn lznt1_backreference_run() {
        // literal 'A' then a back-ref (delta 1, length 10) -> 11 'A's.
        let input = [0x03, 0xB0, 0x02, b'A', 0x07, 0x00];
        assert_eq!(lznt1_decompress(&input, 4096).unwrap(), vec![b'A'; 11]);
    }

    #[test]
    fn btrfs_zlib_roundtrip() {
        use std::io::Write;
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(20);
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&plain).unwrap();
        let comp = enc.finish().unwrap();
        assert_eq!(
            btrfs_decompress_blob(BTRFS_COMPRESS_ZLIB, &comp, plain.len()).unwrap(),
            plain
        );
    }

    // --- LZNT1 malformed tokens ---------------------------------------------

    fn assert_invalid_data(r: std::io::Result<Vec<u8>>) {
        let e = r.expect_err("must fail");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "{e}");
    }

    #[test]
    fn lznt1_back_reference_with_nothing_to_copy_is_an_error() {
        // First token of the chunk is a back-reference: pos == 0.
        assert_invalid_data(lznt1_decompress(&[0x02, 0x80, 0x01, 0x00, 0x00], 4096));
    }

    #[test]
    fn lznt1_back_reference_before_chunk_start_is_an_error() {
        // 'A' then a back-reference with delta 2 when only 1 byte is behind it.
        assert_invalid_data(lznt1_decompress(
            &[0x03, 0x80, 0x02, b'A', 0x00, 0x10],
            4096,
        ));
    }

    #[test]
    fn lznt1_truncated_back_reference_token_is_an_error() {
        assert_invalid_data(lznt1_decompress(&[0x01, 0x80, 0x01, 0x00], 4096));
    }

    // --- decompress_ntfs_data ------------------------------------------------

    const UNIT: u64 = 16;

    /// A compressed unit that decodes to sixteen 'A's, padded to 8 allocated bytes.
    fn compressed_unit() -> Vec<u8> {
        let mut v = vec![0x03, 0x80, 0x02, b'A', 0x0c, 0x00];
        v.resize(8, 0);
        v
    }

    fn fs(bytes: Vec<u8>) -> Arc<dyn DataSource> {
        Arc::new(crate::data_source::ByteSliceDataSource::new(bytes))
    }

    #[test]
    fn ntfs_sparse_unit_is_zeros_and_logical_size_clamps_the_tail() {
        let out = decompress_ntfs_data(&fs(vec![]), &[(None, 32)], UNIT, 20).unwrap();
        assert_eq!(out, vec![0u8; 20]);
    }

    #[test]
    fn ntfs_uncompressed_unit_is_copied() {
        let data: Vec<u8> = (0..16).collect();
        let out = decompress_ntfs_data(&fs(data.clone()), &[(Some(0), 16)], UNIT, 16).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn ntfs_compressed_unit_is_decoded() {
        let out =
            decompress_ntfs_data(&fs(compressed_unit()), &[(Some(0), 8), (None, 8)], UNIT, 16)
                .unwrap();
        assert_eq!(out, vec![b'A'; 16]);
    }

    #[test]
    fn ntfs_short_read_of_an_uncompressed_unit_is_refused() {
        let e = decompress_ntfs_data(&fs(vec![1; 8]), &[(Some(0), 16)], UNIT, 16).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn ntfs_short_read_of_a_compressed_unit_is_refused() {
        let e = decompress_ntfs_data(&fs(vec![0x03, 0x80]), &[(Some(0), 8), (None, 8)], UNIT, 16)
            .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn ntfs_unit_that_decodes_short_is_refused_not_zero_padded() {
        // One literal byte only: decodes to 1 byte of the 16 required.
        let mut data = vec![0x01, 0x80, 0x00, b'A'];
        data.resize(8, 0);
        let r = decompress_ntfs_data(&fs(data), &[(Some(0), 8), (None, 8)], UNIT, 16);
        assert_invalid_data(r);
    }

    #[test]
    fn ntfs_unit_with_a_malformed_token_is_refused() {
        let mut data = vec![0x02, 0x80, 0x01, 0x00, 0x00];
        data.resize(8, 0);
        let r = decompress_ntfs_data(&fs(data), &[(Some(0), 8), (None, 8)], UNIT, 16);
        assert_invalid_data(r);
    }

    // --- btrfs ----------------------------------------------------------------

    fn zlib(plain: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(plain).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn btrfs_zlib_truncated_stream_is_a_failure_not_short_content() {
        let plain: Vec<u8> = (0..4000u32).map(|i| (i * 7 % 251) as u8).collect();
        let comp = zlib(&plain);
        let cut = &comp[..comp.len() / 2];
        assert_eq!(
            btrfs_decompress_blob(BTRFS_COMPRESS_ZLIB, cut, plain.len()),
            None
        );
    }

    #[test]
    fn btrfs_zlib_stream_ending_before_expected_is_returned_short() {
        let plain = b"short extent".to_vec();
        let got = btrfs_decompress_blob(BTRFS_COMPRESS_ZLIB, &zlib(&plain), 4096).unwrap();
        assert_eq!(got, plain);
    }

    #[test]
    fn btrfs_zstd_roundtrip_with_and_without_sector_padding() {
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(20);
        let mut comp = zstd::stream::encode_all(&plain[..], 3).unwrap();
        assert_eq!(
            btrfs_decompress_blob(BTRFS_COMPRESS_ZSTD, &comp, plain.len()).unwrap(),
            plain
        );
        // Zero sector padding after the frame, ram_bytes larger than the content.
        comp.resize(comp.len() + 100, 0);
        assert_eq!(
            btrfs_decompress_blob(BTRFS_COMPRESS_ZSTD, &comp, plain.len() + 500).unwrap(),
            plain
        );
    }

    #[test]
    fn btrfs_zstd_garbage_after_the_frame_is_a_failure() {
        let plain = b"abcdefghij".repeat(50);
        let mut comp = zstd::stream::encode_all(&plain[..], 3).unwrap();
        comp.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 1, 2, 3]);
        assert_eq!(
            btrfs_decompress_blob(BTRFS_COMPRESS_ZSTD, &comp, plain.len() + 500),
            None
        );
    }

    #[test]
    fn btrfs_zstd_truncated_frame_is_a_failure() {
        let plain: Vec<u8> = (0..8000u32).map(|i| (i * 31 % 253) as u8).collect();
        let comp = zstd::stream::encode_all(&plain[..], 3).unwrap();
        let cut = &comp[..comp.len() / 2];
        assert_eq!(
            btrfs_decompress_blob(BTRFS_COMPRESS_ZSTD, cut, plain.len()),
            None
        );
    }

    #[test]
    fn btrfs_lzo_is_refused() {
        assert_eq!(btrfs_decompress_blob(2, b"anything", 16), None);
    }
}
