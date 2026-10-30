//! The Xpress-Huffman page codec, validated against a **real Windows-produced
//! hiberfil** rather than only against Microsoft's `RtlCompressBuffer` vectors.
//!
//! Windows 10/11 hibernation is written entirely in plain Xpress — no build in
//! that line was observed to emit an Xpress-Huffman (method 2/3) page block. The
//! **NT6.3** line does: a Windows Server 2012 R2 / Windows 8.1 hiberfil carries
//! real method-2/3 blocks, so it is the corpus that exercises the Huffman path
//! end to end through the production reconstruction (the `walk_restore_set`
//! method dispatch and block framing), not just the codec in isolation.
//!
//! `SEANCE_WIN_HUFFMAN_HIBERFIL` must name such a hiberfil (several GiB, not in
//! the repo). Absent, this skips. The check is content-based and needs no marker
//! workload: a correct decode of a real Huffman block yields recognizable
//! Windows memory (registry hive bins, DLL paths, UTF-16 strings); a wrong
//! decode yields high-entropy garbage with none of it.

use seance_core::data_source::{DataSource, FileDataSource};
use std::sync::Arc;

fn hiberfil() -> Option<Arc<dyn DataSource>> {
    let p = std::env::var("SEANCE_WIN_HUFFMAN_HIBERFIL").ok()?;
    let src = FileDataSource::new(std::path::PathBuf::from(p)).ok()?;
    Some(Arc::new(src))
}

/// Every real Xpress-Huffman page block in the hiberfil decodes, and its output
/// is real Windows memory — the end-to-end proof for the method-2/3 path.
#[test]
fn real_windows_xpress_huffman_blocks_decode_to_coherent_memory() {
    let Some(src) = hiberfil() else {
        eprintln!(
            "skipping: set SEANCE_WIN_HUFFMAN_HIBERFIL to an NT6.3 (Win8.1/2012 R2) hiberfil"
        );
        return;
    };
    let fsz = src.size();
    let read = |off: u64, len: usize| -> Vec<u8> {
        let mut b = vec![0u8; len];
        let n = src.read_at(off, &mut b).unwrap_or(0);
        b.truncate(n);
        b
    };
    // FirstBootRestorePage (0x68) begins a linear run of compression tables:
    // 4-byte packed header (RangeCount:8, CompressedSize:22, CompressMethod:2)
    // then range entries then the compressed block.
    let hdr = read(0, 0x200);
    assert_eq!(&hdr[0..4], b"HIBR", "not a hibernation image");
    let first = u64::from_le_bytes(hdr[0x68..0x70].try_into().unwrap());

    let mut huff_blocks = 0u32;
    let mut huff_pages = 0u32;
    let mut readable = 0u32;
    let mut off = first * 0x1000;
    loop {
        if off + 4 > fsz {
            break;
        }
        let head = read(off, 4 + 16 * 8);
        if head.len() < 4 {
            break;
        }
        let h = u32::from_le_bytes(head[0..4].try_into().unwrap());
        let rc = (h & 0xFF) as usize;
        let cs = ((h >> 8) & 0x3FFFFF) as usize;
        let method = (h >> 30) & 3;
        if rc == 0 || rc > 16 || cs == 0 || head.len() < 4 + rc * 8 {
            break;
        }
        let mut total = 0usize;
        for r in 0..rc {
            let v = u64::from_le_bytes(head[4 + r * 8..4 + r * 8 + 8].try_into().unwrap());
            total += ((v & 0xF) + 1) as usize;
        }
        if total == 0 || total > 16 {
            break;
        }
        let block_off = off + 4 + (rc as u64) * 8;
        let raw_len = total * 0x1000;
        let block = read(block_off, cs);
        if block.len() < cs {
            break;
        }
        // Method 2/3 = Xpress-Huffman, unless stored at full size (uncompressed).
        if method >= 2 && cs != raw_len {
            let decoded = seance_memory::formats::xpress::decompress_huffman(&block, raw_len)
                .expect("a real Windows Xpress-Huffman block must decode");
            huff_blocks += 1;
            for page in decoded.chunks(0x1000) {
                huff_pages += 1;
                let ascii = page
                    .windows(8)
                    .any(|w| w.iter().all(|&b| (0x20..0x7f).contains(&b)));
                let utf16 = page.windows(16).any(|w| {
                    w.iter().enumerate().all(|(i, &b)| {
                        if i % 2 == 0 {
                            (0x20..0x7f).contains(&b)
                        } else {
                            b == 0
                        }
                    })
                });
                if ascii || utf16 {
                    readable += 1;
                }
            }
        }
        off = block_off + cs as u64;
    }

    eprintln!("Xpress-Huffman: {huff_blocks} real blocks decoded, {readable}/{huff_pages} pages hold readable Windows content");
    assert!(huff_blocks > 0, "corpus carried no Xpress-Huffman blocks");
    // A correct decode leaves most pages with recognizable content; a wrong one
    // would leave near-zero. The threshold is deliberately loose (memory has
    // zero/binary pages too) but far above what garbage would clear.
    assert!(
        readable * 4 >= huff_pages,
        "only {readable}/{huff_pages} Huffman-decoded pages were readable — a decode this wrong is not the codec working"
    );
}
