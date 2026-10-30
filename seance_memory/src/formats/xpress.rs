//! Plain Xpress (LZ77) decompression — the codec Windows hibernation uses.
//!
//! Windows compresses the pages in a hibernation file with the Xpress family of
//! codecs. The "plain" variant is an LZ77 scheme: a stream of 32-bit *indicator*
//! words whose bits, read most-significant first, say whether each following
//! token is a literal byte or a back-reference (a length and a distance into the
//! bytes already produced). This is `COMPRESSION_FORMAT_XPRESS` and covers the
//! `XpressFast` and `XpressMax` hibernation methods (the two that differ only in
//! how hard the *compressor* worked; the decoder is identical).
//!
//! # Provenance
//!
//! The algorithm is Microsoft's, published in [MS-XCA] "Plain LZ77", and this
//! transcription follows the widely-used reference in Comae's `Hibr2Bin`
//! (BSD-licensed) so that it decodes exactly what Windows wrote. It is validated
//! end to end against a real `hiberfil.sys` — see the hibernation
//! reconstruction and its integration test.
//!
//! # Xpress-Huffman
//!
//! The second half of this module decodes **Xpress-Huffman**
//! (`COMPRESSION_FORMAT_XPRESS_HUFFMAN`, the LZ77+Huffman variant), which is
//! what Windows 10/11 hibernation writes for nearly every kernel-set table — on
//! a Windows 11 build 26200 capture, 30,479 of 31,969 — and which the NT6.3
//! line uses for a minority of tables. Which header bit selects it differs by
//! layout; the hibernation reader owns that dispatch. Both codecs are validated
//! against Microsoft's compressor output and against real captures.

/// The magic the reference uses to initialise its nibble tracker; kept as a
/// named constant so the transcription reads against the source.
const NIBBLE_UNSET: usize = usize::MAX;

/// Decompress a plain-Xpress stream into at most `out_size` bytes.
///
/// Returns what was produced. A stream that ends early (truncated evidence)
/// yields the bytes decoded so far rather than an error: a hibernation image is
/// reconstructed page-run by page-run, and a short read costs the run it lands
/// in, not the whole image.
pub fn decompress(input: &[u8], out_size: usize) -> Vec<u8> {
    decode(input, out_size).0
}

/// Decompress a plain-Xpress stream that must yield exactly `out_size` bytes.
///
/// `None` if a back-reference reaches before the start of the output or the
/// stream ends short. This is the decoder a hibernation page block goes
/// through: a block that is not plain Xpress — an Xpress-Huffman block whose
/// flag was misread, say — produces a first back-reference into nothing, and
/// the lenient [`decompress`] would return a short garbage stream whose first
/// pages then look like memory. A page block yields every byte of its pages or
/// it yields nothing.
pub fn decompress_exact(input: &[u8], out_size: usize) -> Option<Vec<u8>> {
    let (out, well_formed) = decode(input, out_size);
    (well_formed && out.len() == out_size).then_some(out)
}

/// The decoder proper. The flag is false if any back-reference reached before
/// the start of the output; the bytes are what was produced regardless.
fn decode(input: &[u8], out_size: usize) -> (Vec<u8>, bool) {
    let mut well_formed = true;
    let mut out: Vec<u8> = Vec::with_capacity(out_size);
    let mut i = 0usize;
    let mut indicator: u32 = 0;
    let mut indicator_bit = 0u32;
    // The extended-length encoding stores one length nibble in a byte whose
    // *other* nibble serves a later match; `nibble` remembers that byte's
    // position so the high nibble is picked up next time.
    let mut nibble: usize = NIBBLE_UNSET;

    while out.len() < out_size && i < input.len() {
        if indicator_bit == 0 {
            if i + 4 > input.len() {
                break;
            }
            indicator = u32::from_le_bytes([input[i], input[i + 1], input[i + 2], input[i + 3]]);
            i += 4;
            indicator_bit = 32;
        }
        indicator_bit -= 1;

        // Bit clear → a literal byte. Bit set → a length/distance back-reference.
        if (indicator >> indicator_bit) & 1 == 0 {
            if i >= input.len() {
                break;
            }
            out.push(input[i]);
            i += 1;
            continue;
        }

        if i + 2 > input.len() {
            break;
        }
        let token = u16::from_le_bytes([input[i], input[i + 1]]) as usize;
        i += 2;
        // The token packs distance in its high 13 bits and a 3-bit length; a
        // length of 7 escapes to the extended encoding below.
        let offset = token / 8;
        let mut length = token % 8;

        if length == 7 {
            if nibble == NIBBLE_UNSET {
                nibble = i;
                if i >= input.len() {
                    break;
                }
                length = (input[i] % 16) as usize;
                i += 1;
            } else {
                if nibble >= input.len() {
                    break;
                }
                length = (input[nibble] / 16) as usize;
                nibble = NIBBLE_UNSET;
            }

            if length == 15 {
                if i >= input.len() {
                    break;
                }
                length = input[i] as usize;
                i += 1;

                if length == 255 {
                    if i + 2 > input.len() {
                        break;
                    }
                    length = u16::from_le_bytes([input[i], input[i + 1]]) as usize;
                    i += 2;
                    // The two-byte form stores the whole length, from which the
                    // constants folded in by the shorter forms are removed.
                    length = length.wrapping_sub(15 + 7);
                }
                length += 15;
            }
            length += 7;
        }
        length += 3;

        // Copy `length` bytes from `offset + 1` behind the write head, one byte
        // at a time so an overlapping run (the usual RLE case) is produced
        // correctly.
        if offset + 1 > out.len() {
            well_formed = false;
        }
        while length != 0 {
            if out.len() >= out_size || offset + 1 > out.len() {
                break;
            }
            let from = out.len() - offset - 1;
            out.push(out[from]);
            length -= 1;
        }
    }

    (out, well_formed)
}

// ---------------------------------------------------------------------------
// Xpress-Huffman (LZ77 + Huffman), the `XpressHuffFast`/`XpressHuffMax` variant.
// ---------------------------------------------------------------------------

/// Symbols in the one Huffman code: 256 literals + 256 match headers.
const HUFF_SYMBOLS: usize = 512;
/// The Huffman table that prefixes every chunk: 512 four-bit lengths.
const HUFF_TABLE_BYTES: usize = HUFF_SYMBOLS / 2;
/// Longest codeword the format allows.
const HUFF_MAX_LEN: usize = 15;
/// Bytes one chunk decodes to at most.
const HUFF_CHUNK: usize = 65536;
/// Minimum match length (a match symbol's stored length is this less).
const HUFF_MIN_MATCH: usize = 3;

/// A bit reader over 16-bit little-endian coding units, bits consumed
/// most-significant first — the [MS-XCA] convention, transcribed from wimlib's
/// `input_bitstream`. `next` is a byte cursor: the bit path advances it two
/// bytes at a time, while the interleaved byte reads for extended match lengths
/// take bytes from it directly, which is the format's one genuinely tricky part.
struct BitReader<'a> {
    data: &'a [u8],
    next: usize,
    bitbuf: u32,
    bitcount: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            next: 0,
            bitbuf: 0,
            bitcount: 0,
        }
    }

    /// Make at least `n` (≤ 16) bits available in `bitbuf`, loading one 16-bit
    /// coding unit if needed. Past the end, bits read as zero.
    fn ensure(&mut self, n: u32) {
        if self.bitcount >= n {
            return;
        }
        if self.next + 2 <= self.data.len() {
            let w = u16::from_le_bytes([self.data[self.next], self.data[self.next + 1]]) as u32;
            self.bitbuf |= w << (16 - self.bitcount);
            self.next += 2;
        }
        self.bitcount += 16;
    }

    fn peek(&self, n: u32) -> u32 {
        if n == 0 {
            0
        } else {
            self.bitbuf >> (32 - n)
        }
    }

    fn remove(&mut self, n: u32) {
        self.bitbuf <<= n;
        self.bitcount = self.bitcount.saturating_sub(n);
    }

    fn pop(&mut self, n: u32) -> u32 {
        self.ensure(n);
        let v = self.peek(n);
        self.remove(n);
        v
    }

    /// A byte read straight from the cursor — the interleaved literal for an
    /// extended match length, which sits past the words already buffered.
    fn read_byte(&mut self) -> u32 {
        if self.next >= self.data.len() {
            return 0;
        }
        let b = self.data[self.next];
        self.next += 1;
        b as u32
    }

    fn read_u16(&mut self) -> u32 {
        if self.next + 2 > self.data.len() {
            return 0;
        }
        let v = u16::from_le_bytes([self.data[self.next], self.data[self.next + 1]]);
        self.next += 2;
        v as u32
    }
}

/// A canonical Huffman decoder built from the 512 codeword lengths.
struct Huffman {
    counts: [u32; HUFF_MAX_LEN + 1],
    first_code: [u32; HUFF_MAX_LEN + 1],
    first_symbol: [u32; HUFF_MAX_LEN + 1],
    /// Symbols ordered by (length, symbol value) — the canonical order.
    symbols: Vec<u16>,
}

impl Huffman {
    fn build(lens: &[u8; HUFF_SYMBOLS]) -> Option<Self> {
        let mut counts = [0u32; HUFF_MAX_LEN + 1];
        for &l in lens.iter() {
            if l != 0 {
                if l as usize > HUFF_MAX_LEN {
                    return None;
                }
                counts[l as usize] += 1;
            }
        }
        let mut symbols = Vec::new();
        for len in 1..=HUFF_MAX_LEN {
            for (sym, &l) in lens.iter().enumerate() {
                if l as usize == len {
                    symbols.push(sym as u16);
                }
            }
        }
        let mut first_code = [0u32; HUFF_MAX_LEN + 1];
        let mut first_symbol = [0u32; HUFF_MAX_LEN + 1];
        let mut code = 0u32;
        let mut sidx = 0u32;
        for len in 1..=HUFF_MAX_LEN {
            first_code[len] = code;
            first_symbol[len] = sidx;
            code = (code + counts[len]) << 1;
            sidx += counts[len];
        }
        Some(Self {
            counts,
            first_code,
            first_symbol,
            symbols,
        })
    }

    /// Decode one symbol, reading its codeword most-significant bit first.
    fn decode(&self, br: &mut BitReader) -> Option<u16> {
        br.ensure(HUFF_MAX_LEN as u32);
        let mut code = 0u32;
        for len in 1..=HUFF_MAX_LEN {
            // The next bit, MSB-first, without yet consuming it.
            let bit = (br.bitbuf >> (32 - len as u32)) & 1;
            code = (code << 1) | bit;
            let cnt = self.counts[len];
            if cnt > 0 && code.wrapping_sub(self.first_code[len]) < cnt {
                br.remove(len as u32);
                let idx = self.first_symbol[len] + (code - self.first_code[len]);
                return self.symbols.get(idx as usize).copied();
            }
        }
        None
    }
}

/// Decompress an Xpress-Huffman stream into `out_size` bytes.
///
/// Transcribed from [MS-XCA] "LZ77+Huffman" and the wimlib reference: the stream
/// is a sequence of chunks, each a 256-byte Huffman table followed by
/// Huffman-coded literals and matches, decoding to at most 65536 bytes. Returns
/// `None` on a malformed table or an unresolvable back-reference — a hibernation
/// page block that will not decode is left a gap, never guessed.
pub fn decompress_huffman(input: &[u8], out_size: usize) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(out_size);
    let mut pos = 0usize;

    while out.len() < out_size {
        if pos + HUFF_TABLE_BYTES > input.len() {
            return None;
        }
        let table = &input[pos..pos + HUFF_TABLE_BYTES];
        let mut lens = [0u8; HUFF_SYMBOLS];
        for (i, &b) in table.iter().enumerate() {
            lens[2 * i] = b & 0x0f;
            lens[2 * i + 1] = b >> 4;
        }
        let huff = Huffman::build(&lens)?;
        let mut br = BitReader::new(&input[pos + HUFF_TABLE_BYTES..]);

        let chunk_end = (out.len() + HUFF_CHUNK).min(out_size);
        while out.len() < chunk_end {
            let sym = huff.decode(&mut br)? as usize;
            if sym < 256 {
                out.push(sym as u8);
                continue;
            }
            let mut length = sym & 0x0f;
            let log2_offset = (sym >> 4) & 0x0f;
            br.ensure(16);
            let offset = (1usize << log2_offset) | (br.pop(log2_offset as u32) as usize);
            if length == 0x0f {
                length += br.read_byte() as usize;
                if length == 0x0f + 0xff {
                    length = br.read_u16() as usize;
                }
            }
            length += HUFF_MIN_MATCH;

            if offset == 0 || offset > out.len() {
                return None;
            }
            for _ in 0..length {
                if out.len() >= out_size {
                    break;
                }
                let b = out[out.len() - offset];
                out.push(b);
            }
        }
        // The next chunk's table follows the bytes this chunk consumed.
        pos += HUFF_TABLE_BYTES + br.next;
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// A hand-traced vector: three literals `A`,`B`,`C` then a back-reference of
    /// length 6 at distance 3, reproducing `ABC` twice → `ABCABCABC`.
    ///
    /// Indicator: bits read MSB-first, so the four tokens consume bits 31,30,29
    /// (all 0 → literals) and 28 (1 → match); the indicator word is `1<<28`. The
    /// match token is `distance_minus_1 * 8 + (length - 3)` = `2*8 + 3` = 19.
    #[test]
    fn a_hand_traced_stream_decompresses() {
        let mut input = Vec::new();
        input.extend_from_slice(&(1u32 << 28).to_le_bytes()); // indicator
        input.extend_from_slice(b"ABC"); // three literals
        input.extend_from_slice(&19u16.to_le_bytes()); // match: dist 3, len 6
        assert_eq!(decompress(&input, 9), b"ABCABCABC");
    }

    /// A run of literals with no back-reference is copied verbatim.
    #[test]
    fn all_literals_pass_through() {
        let mut input = Vec::new();
        input.extend_from_slice(&0u32.to_le_bytes()); // every bit clear → literals
        input.extend_from_slice(b"hello");
        assert_eq!(decompress(&input, 5), b"hello");
    }

    /// A truncated stream yields what was decoded, not a panic.
    #[test]
    fn a_truncated_stream_stops_cleanly() {
        let input = [0u8, 0, 0, 0, b'x']; // indicator says "literal" then one byte
        assert_eq!(decompress(&input, 100), b"x");
    }

    /// Asking for fewer bytes than the stream encodes stops at the limit.
    #[test]
    fn output_is_bounded_by_out_size() {
        let mut input = Vec::new();
        input.extend_from_slice(&0u32.to_le_bytes());
        input.extend_from_slice(b"abcdef");
        assert_eq!(decompress(&input, 3), b"abc");
    }

    /// The exact decoder is the one a hibernation page block goes through: a
    /// block either yields every byte of its pages or it yields nothing.
    #[test]
    fn a_stream_that_decodes_to_exactly_the_size_asked_passes_the_exact_decoder() {
        let mut input = Vec::new();
        input.extend_from_slice(&(1u32 << 28).to_le_bytes());
        input.extend_from_slice(b"ABC");
        input.extend_from_slice(&19u16.to_le_bytes());
        assert_eq!(
            decompress_exact(&input, 9).as_deref(),
            Some(&b"ABCABCABC"[..])
        );
    }

    /// A back-reference that reaches before the start of the output is what an
    /// Xpress-Huffman block looks like to the plain decoder (its first token
    /// is table data). That is not a page; it is refused.
    #[test]
    fn a_back_reference_before_the_output_is_refused_by_the_exact_decoder() {
        let mut input = Vec::new();
        input.extend_from_slice(&(1u32 << 31).to_le_bytes()); // first token: a match
        input.extend_from_slice(&(4883u16 * 8).to_le_bytes()); // distance 4884, nothing behind
        input.extend_from_slice(b"xyz");
        assert_eq!(decompress_exact(&input, 4096), None);
        // The lenient decoder still returns what it could, for the callers that
        // bound their own reads.
        assert_eq!(decompress(&input, 4096), b"xyz");
    }

    /// A stream that runs out before the size asked for is refused too: a page
    /// is 4096 bytes or it is not a page.
    #[test]
    fn a_stream_that_falls_short_of_the_size_is_refused_by_the_exact_decoder() {
        let mut input = Vec::new();
        input.extend_from_slice(&0u32.to_le_bytes());
        input.extend_from_slice(b"hello");
        assert_eq!(decompress_exact(&input, 4096), None);
        assert_eq!(decompress_exact(&input, 5).as_deref(), Some(&b"hello"[..]));
    }

    /// Xpress-Huffman decompression is validated against **Microsoft's own
    /// compressor**: each pair below is `(input, RtlCompressBuffer(input,
    /// COMPRESSION_FORMAT_XPRESS_HUFFMAN))` captured from a Windows 11 guest, so
    /// reproducing the input from the compressed bytes proves the decoder decodes
    /// exactly what Windows wrote. The cases span a highly compressible run, real
    /// text, and incompressible random data (which exercises the literal path and
    /// a full Huffman table).
    #[test]
    fn xpress_huffman_matches_the_windows_compressor() {
        // "A" x 300 — one short match, tiny code.
        let repeat_in = unhex(&"41".repeat(300));
        let repeat_comp = unhex(
            "0000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000980000ff2801",
        );
        assert_eq!(
            decompress_huffman(&repeat_comp, repeat_in.len()).as_deref(),
            Some(&repeat_in[..]),
            "the highly compressible run must round-trip"
        );

        // "The quick brown fox ..." x 12 — text with repeated matches.
        let text_in = b"The quick brown fox jumps over the lazy dog. ".repeat(12);
        let text_comp = unhex(
            "00000000000000000000000000000000030000000000000600000000000000000000000000000000000006000000000060665666555555455555555555050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e6e49a0f503c05ee8f56c18a63330aa28086bd96627dd2e381ffe4b60000ffec01",
        );
        assert_eq!(
            decompress_huffman(&text_comp, text_in.len()).as_deref(),
            Some(&text_in[..]),
            "text must round-trip"
        );

        // 512 bytes of incompressible random data — all literals, a full table.
        let rand_in = unhex("3e17ba96ae04cd3b99869e56f0adbf3a6fb74d2555175dcc6e8b0914579ab036cfd6280bb3c707dbaef270dc9505096e676be7f10d46d827baed2722fbb9e4fed667871a85b386a8af727663a7813769819aadebb3bf2989fd0051c69fe4e0f50e71052d7eefe9b3e53e429bcf758038b5bea0600bf84a173efd1d8462c009ca918154357b0aea92b1fa06747c8eb987801810e04480ea1527eeee80d26451253577094e204bbdabd40dae11f2d59ab044950349af288611963f0d8c1b69c04ca8e03f05846b67345a650c36d1d82251543e3c3c6007750cf1f8b7e03d31906a4d61681296942bd82dcfef4a1c503fbe1dbc37dc2c83eba16a32148bb486f728d5a1e8706f0fbac013640f91182bf0a0b9f8c281fab33ec975c7a764809f23a7d7c6757a67ce4e0e0177c9c8745a883f4173d2bbc3762e21631ffaa868563f734067ba52b67539eaaab47f82ea75551b3e68220dcd67e36197531748d4a5a5aa3755870c9f3688cb39e8110ff6ab36edcadf6a003432a6d98458ba625ef116040fd44b95ee487b07df56d3e456d46aeb1c297df43ba57605aeae88467b256d47d20cff2260a1fe82636220dd5ec182afeece46347321c96a5d45e640bf348bb9e98b124ad4488b7a2afb90d98499a7ec2cd858acdf38d4b04395c41bbbbec22fd667f4d2af37dba643cb097790efe5c49df914e6dcdfd9b0b761073e836fbf6c");
        let rand_comp = unhex("98907879708977788998987908898890889780808889889990088777888998769889989898888908899988970808800888889860888799889889787700789999778797779770090987097997809790797800707807888977977098797087997797980888798889789097879777809770079087988877897778089899978780980800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000520009d4f3e1b0a77a0d6b48afe2dce5a7abab935d15b8f31a3aac3348854dd662656515d185b14fe07440f800d7fedb08606da3b728505ad25e7bc7418dc4372af099346c479a9de3528badc5a1a97ab77c6e87a71a13295fb79eb849d0f39e55fd405abc7389ec9c162ef6b0c18388284ab90d3603034c5f66aa972b9b79bff5e4dfc2775e6b3c960de08da23af32c2885f1f97666329565735403d348f17b081a154fa0b14d85fd1145efa944a4a8c403a37898ad93741e3acd1023b87a2bc6e11bfda90b02aa7e7e29c0f020ab20cc751ee54f236b6383162ecb65dafa93fe58f5981ed2cee12f26a39e35237718d71857f61e41d5a595c838ac8236e36ff56556f0c841092f0c506549b4a58b2c978c94edf44afa1c9d8846e12b3fd3caf9836cb7fef1f9245612587cad490f48a0bb6f05da53754a1ee67c37c2c371555ac0118b0f9cc7e2d5cd481522d1314c66d5a2c3731a77362852f34f6e1063b6309226c39bb0ac99655b035f0e87a525f73185d4b942f521417617a1f2b1dddde499c2844e278c729faca0673fcc5dfc3d8216c352767a3f81ff0f85e8b35dc631c95d23d3cf5ea0ea3053cd74b129adde0ef6f1378f8033f597da30d4b371e69aa2f913d831b2eb2d39d941a0668e760e1562689f8764e93ffa9ad11c6e52b7c4ae17282bd71bfb00a00000");
        assert_eq!(
            decompress_huffman(&rand_comp, rand_in.len()).as_deref(),
            Some(&rand_in[..]),
            "incompressible data must round-trip through the literal path"
        );
    }

    /// A malformed Huffman table (too short) is refused, not decoded to garbage.
    #[test]
    fn a_short_huffman_stream_is_refused() {
        assert_eq!(decompress_huffman(&[0u8; 10], 4096), None);
    }
}
