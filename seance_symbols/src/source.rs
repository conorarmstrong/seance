//! Getting ISF bytes off disk: transparent decompression, bomb guards, and the
//! provenance record that survives into the report.
//!
//! # Why the hashes are not optional
//!
//! A finding that says "`_EPROCESS.UniqueProcessId` is at offset 0x440" is only
//! as good as the file that said so. Every table carries the SHA-256 of the
//! bytes as supplied *and* of the JSON after decompression, so a report can
//! state exactly which symbol file produced a finding, and a defence expert can
//! obtain that file and reproduce the layout. Recording only the decompressed
//! hash would leave "which file on the disk?" unanswerable; recording only the
//! compressed hash would leave two differently-compressed copies of one ISF
//! looking like different evidence.
//!
//! # Why the limits are not optional either
//!
//! An ISF is a layout-defining input: a hostile one is a total analysis
//! integrity compromise, not merely a parsing one. A 200 KiB `.json.xz` that
//! expands to 40 GiB would take the examiner's workstation out mid-case, so
//! decompression runs under an absolute output ceiling and an expansion-ratio
//! check, and both fail with a named reason rather than being killed by the
//! kernel.

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{Result, SymbolError};

/// Absolute ceiling on decompressed JSON, unless the caller raises it.
///
/// Real kernel ISFs run to tens of megabytes; a gigabyte is well past anything
/// legitimate and well short of exhausting a workstation.
pub const DEFAULT_MAX_JSON_BYTES: u64 = 1024 * 1024 * 1024;

/// Default permitted expansion ratio for a compressed ISF.
pub const DEFAULT_MAX_RATIO: u64 = 400;

/// Expansion allowance floor, so a tiny but legitimately compressible fragment
/// is not refused for having a large ratio over a few hundred bytes.
pub const RATIO_FLOOR_BYTES: u64 = 16 * 1024 * 1024;

/// How an ISF file was stored.
///
/// `.json.bz2` and `.zip` pack members are named in the plan but are not
/// implemented here: this crate has no bzip2 or zip dependency, and inventing
/// one silently would be worse than saying so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// Plain JSON.
    None,
    /// gzip (`.json.gz`).
    Gzip,
    /// xz (`.json.xz`).
    Xz,
}

impl Compression {
    /// Bytes of prefix needed to identify a container.
    pub const MAGIC_LEN: usize = 6;

    /// Identify the container from the first bytes of the file.
    ///
    /// Content, never file extension: an ISF renamed by an examiner is still
    /// the same evidence, and an extension that lies must not change how the
    /// bytes are read.
    pub fn detect(prefix: &[u8]) -> Compression {
        if prefix.starts_with(&[0x1f, 0x8b]) {
            Compression::Gzip
        } else if prefix.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
            Compression::Xz
        } else {
            Compression::None
        }
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            Compression::None => "none",
            Compression::Gzip => "gzip",
            Compression::Xz => "xz",
        }
    }
}

/// Bounds applied to decompression.
#[derive(Debug, Clone, Copy)]
pub struct DecompressLimits {
    /// Absolute ceiling on decompressed bytes.
    pub max_json_bytes: u64,
    /// Permitted expansion ratio, applied above [`RATIO_FLOOR_BYTES`].
    pub max_ratio: u64,
}

impl Default for DecompressLimits {
    fn default() -> Self {
        Self {
            max_json_bytes: DEFAULT_MAX_JSON_BYTES,
            max_ratio: DEFAULT_MAX_RATIO,
        }
    }
}

impl DecompressLimits {
    /// The number of output bytes permitted for an input of `input_len`.
    ///
    /// The ratio allowance never exceeds the absolute ceiling, and never falls
    /// below [`RATIO_FLOOR_BYTES`], so a 2 KiB hand-written fragment
    /// compressing 30:1 is not mistaken for a bomb.
    pub fn allowance(&self, input_len: u64) -> u64 {
        let ratio_allowance = input_len
            .saturating_mul(self.max_ratio)
            .max(RATIO_FLOOR_BYTES);
        ratio_allowance.min(self.max_json_bytes)
    }
}

/// Where a symbol table's bytes came from, and what they hashed to.
///
/// Attached to every compiled table so a report can name the file that produced
/// a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsfProvenance {
    /// SHA-256 of the bytes as supplied, compressed or not. This is the hash of
    /// the file the examiner holds.
    pub source_sha256: String,
    /// Length of those bytes.
    pub source_len: u64,
    /// SHA-256 of the JSON after decompression. Equal to `source_sha256` for an
    /// uncompressed file.
    pub json_sha256: String,
    /// Length of the JSON.
    pub json_len: u64,
    /// How the file was stored.
    pub compression: Compression,
}

impl IsfProvenance {
    /// Serializable form for artifact metadata and report provenance blocks.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "source_sha256": self.source_sha256,
            "source_len": self.source_len,
            "json_sha256": self.json_sha256,
            "json_len": self.json_len,
            "compression": self.compression.as_str(),
        })
    }
}

/// Decompressed ISF bytes plus the provenance of the file they came from.
#[derive(Debug, Clone)]
pub struct IsfSource {
    /// The JSON document, decompressed.
    pub json: Vec<u8>,
    /// Hashes and lengths of both forms.
    pub provenance: IsfProvenance,
}

/// SHA-256 of a byte slice as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

/// Lowercase hex of a byte slice.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// A reader that refuses to yield more than `limit` bytes.
///
/// Errors rather than reporting end-of-file at the ceiling: a silently
/// truncated ISF would parse as a *smaller but valid-looking* document, which
/// is the failure this crate exists to prevent.
pub(crate) struct LimitedReader<R> {
    inner: R,
    limit: u64,
    count: u64,
    what: &'static str,
}

impl<R: Read> LimitedReader<R> {
    pub(crate) fn new(inner: R, limit: u64, what: &'static str) -> Self {
        Self {
            inner,
            limit,
            count: 0,
            what,
        }
    }

    /// Bytes delivered so far.
    pub(crate) fn count(&self) -> u64 {
        self.count
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.count = self.count.saturating_add(read as u64);
        if self.count > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{} exceeded its limit of {} bytes", self.what, self.limit),
            ));
        }
        Ok(read)
    }
}

/// A reader that SHA-256s everything that passes through it.
pub(crate) struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    count: u64,
}

impl<R: Read> HashingReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            count: 0,
        }
    }

    /// Consume the reader, yielding the hex digest and the byte count.
    pub(crate) fn finish(self) -> (String, u64) {
        (hex(&self.hasher.finalize()), self.count)
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.hasher.update(&buf[..read]);
        self.count = self.count.saturating_add(read as u64);
        Ok(read)
    }
}

/// Wrap a reader in whichever decoder its magic calls for.
///
/// gzip is read with a **multi-member** decoder. A single-member decoder stops
/// at the first member's trailer and reports end-of-file even when the file
/// holds more, so a `.json.gz` carrying two concatenated members would yield
/// only the first: a shorter, well-formed, silently different ISF whose
/// `json_sha256` would faithfully record the truncated document as if it were
/// the whole file. The multi-member decoder decodes every member and refuses
/// anything after the last one that is not another valid member.
pub(crate) fn decoder<'r, R: Read + 'r>(compression: Compression, reader: R) -> Box<dyn Read + 'r> {
    match compression {
        Compression::None => Box::new(reader),
        Compression::Gzip => Box::new(flate2::read::MultiGzDecoder::new(reader)),
        Compression::Xz => Box::new(xz2::read::XzDecoder::new(reader)),
    }
}

/// Decompress owned ISF bytes and record their provenance.
///
/// Takes ownership so an uncompressed file is not copied a second time.
///
/// # Errors
///
/// - [`SymbolError::SizeLimit`] if the output passes the absolute ceiling.
/// - [`SymbolError::CompressionRatio`] if it expands beyond the permitted ratio.
/// - [`SymbolError::Io`] if the compressed stream is truncated or corrupt.
///   Truncation is an error, never a short document: half an ISF still parses
///   as an ISF, and would silently describe a kernel with fewer members than it
///   has.
pub fn load(source: Vec<u8>, limits: &DecompressLimits) -> Result<IsfSource> {
    let source_len = source.len() as u64;
    let source_sha256 = sha256_hex(&source);
    let compression = Compression::detect(&source);

    let json = match compression {
        Compression::None => source,
        _ => {
            let allowance = limits.allowance(source_len);
            let mut reader = LimitedReader::new(
                decoder(compression, source.as_slice()),
                allowance,
                "the decompressed symbol file",
            );
            let mut out = Vec::new();
            match reader.read_to_end(&mut out) {
                Ok(_) => {}
                Err(err) if reader.count() > allowance => {
                    // Distinguish the ceiling from an ordinary I/O failure, and
                    // say which ceiling it was.
                    let _ = err;
                    if allowance >= limits.max_json_bytes {
                        return Err(SymbolError::SizeLimit {
                            what: "the decompressed symbol file",
                            limit: limits.max_json_bytes,
                        });
                    }
                    return Err(SymbolError::CompressionRatio {
                        input: source_len,
                        output: reader.count(),
                        ratio: reader.count() / source_len.max(1),
                        limit: limits.max_ratio,
                    });
                }
                Err(err) => return Err(SymbolError::Io(err)),
            }
            out
        }
    };

    let json_len = json.len() as u64;
    let json_sha256 = if compression == Compression::None {
        source_sha256.clone()
    } else {
        sha256_hex(&json)
    };

    Ok(IsfSource {
        json,
        provenance: IsfProvenance {
            source_sha256,
            source_len,
            json_sha256,
            json_len,
            compression,
        },
    })
}

/// Decompress a borrowed slice. Convenience for callers that already hold the
/// bytes; copies once for the uncompressed case.
pub fn load_slice(source: &[u8], limits: &DecompressLimits) -> Result<IsfSource> {
    load(source.to_vec(), limits)
}

/// Read and decompress an ISF file from disk.
pub fn load_path(path: &Path, limits: &DecompressLimits) -> Result<IsfSource> {
    let bytes = std::fs::read(path).map_err(SymbolError::Io)?;
    load(bytes, limits)
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::io::Write;

    /// gzip a byte slice, for round-trip tests.
    pub(crate) fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }

    /// xz a byte slice, for round-trip tests.
    pub(crate) fn xz(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
        encoder.write_all(bytes).expect("xz write");
        encoder.finish().expect("xz finish")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{gzip, xz};
    use super::*;

    #[test]
    fn compression_is_identified_from_content_not_from_a_file_name() {
        assert_eq!(Compression::detect(b"{\"metadata\""), Compression::None);
        assert_eq!(
            Compression::detect(&[0x1f, 0x8b, 0x08, 0x00]),
            Compression::Gzip
        );
        assert_eq!(
            Compression::detect(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]),
            Compression::Xz
        );
        // A short file must not be mistaken for anything.
        assert_eq!(Compression::detect(&[0x1f]), Compression::None);
        assert_eq!(Compression::detect(&[]), Compression::None);
    }

    #[test]
    fn a_gzipped_document_round_trips_and_records_both_hashes() {
        let plain = br#"{"metadata":{"format":"6.2.0"}}"#.to_vec();
        let compressed = gzip(&plain);
        let loaded = load(compressed.clone(), &DecompressLimits::default()).expect("loads");

        assert_eq!(loaded.json, plain);
        assert_eq!(loaded.provenance.compression, Compression::Gzip);
        assert_eq!(loaded.provenance.source_sha256, sha256_hex(&compressed));
        assert_eq!(loaded.provenance.json_sha256, sha256_hex(&plain));
        assert_ne!(
            loaded.provenance.source_sha256, loaded.provenance.json_sha256,
            "the file on disk and the JSON inside it are different evidence"
        );
        assert_eq!(loaded.provenance.source_len, compressed.len() as u64);
        assert_eq!(loaded.provenance.json_len, plain.len() as u64);
    }

    #[test]
    fn an_xz_document_round_trips() {
        let plain = br#"{"metadata":{"format":"4.0.0"}}"#.to_vec();
        let loaded = load(xz(&plain), &DecompressLimits::default()).expect("loads");
        assert_eq!(loaded.json, plain);
        assert_eq!(loaded.provenance.compression, Compression::Xz);
    }

    #[test]
    fn an_uncompressed_document_hashes_identically_on_both_sides() {
        let plain = br#"{"metadata":{"format":"6.2.0"}}"#.to_vec();
        let loaded = load(plain.clone(), &DecompressLimits::default()).expect("loads");
        assert_eq!(loaded.provenance.compression, Compression::None);
        assert_eq!(
            loaded.provenance.source_sha256,
            loaded.provenance.json_sha256
        );
        assert_eq!(loaded.json, plain);
    }

    #[test]
    fn a_decompression_bomb_is_refused_with_a_named_limit() {
        // 8 MiB of zeros compresses to a few kilobytes.
        let bomb = gzip(&vec![0u8; 8 * 1024 * 1024]);
        let limits = DecompressLimits {
            max_json_bytes: 64 * 1024,
            max_ratio: DEFAULT_MAX_RATIO,
        };
        let err = load(bomb, &limits).expect_err("a bomb must not be decompressed");
        match err {
            SymbolError::SizeLimit { limit, .. } => assert_eq!(limit, 64 * 1024),
            other => panic!("expected a size limit, got {other}"),
        }
    }

    #[test]
    fn a_truncated_compressed_file_errors_rather_than_yielding_half_a_table() {
        let plain = vec![b'x'; 64 * 1024];
        let mut compressed = gzip(&plain);
        compressed.truncate(compressed.len() / 2);
        let err = load(compressed, &DecompressLimits::default())
            .expect_err("half a gzip stream must not decompress");
        assert!(matches!(err, SymbolError::Io(_)), "{err}");
    }

    #[test]
    fn a_multi_member_gzip_yields_every_member_rather_than_only_the_first() {
        // Two concatenated members. A single-member decoder returns the first
        // and reports end-of-file, so the second half of the document would
        // vanish without any error and the recorded json_sha256 would attest to
        // the truncated version as though it were the file.
        let mut concatenated = gzip(br#"{"metadata":"#);
        concatenated.extend_from_slice(&gzip(br#"{"format":"6.2.0"}}"#));
        let loaded = load(concatenated, &DecompressLimits::default()).expect("loads");
        assert_eq!(loaded.json, br#"{"metadata":{"format":"6.2.0"}}"#);
    }

    #[test]
    fn bytes_appended_after_a_gzip_member_are_an_error_not_ignored() {
        let mut appended = gzip(br#"{"metadata":{"format":"6.2.0"}}"#);
        appended.extend_from_slice(b"trailing evidence");
        let err = load(appended, &DecompressLimits::default())
            .expect_err("content after the last member must not be silently dropped");
        assert!(matches!(err, SymbolError::Io(_)), "{err}");
    }

    #[test]
    fn garbage_that_claims_to_be_gzip_errors() {
        let mut garbage = vec![0x1f, 0x8b];
        garbage.extend_from_slice(&[0xff; 128]);
        let err = load(garbage, &DecompressLimits::default())
            .expect_err("a corrupt gzip header must not decompress");
        assert!(matches!(err, SymbolError::Io(_)), "{err}");
    }

    #[test]
    fn the_expansion_allowance_has_a_floor_so_small_fragments_are_not_bombs() {
        let limits = DecompressLimits::default();
        assert_eq!(limits.allowance(1), RATIO_FLOOR_BYTES);
        assert_eq!(
            limits.allowance(1024 * 1024),
            1024 * 1024 * DEFAULT_MAX_RATIO
        );
        // And never above the absolute ceiling.
        assert_eq!(limits.allowance(u64::MAX), DEFAULT_MAX_JSON_BYTES);
    }

    #[test]
    fn hex_is_lowercase_and_zero_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
