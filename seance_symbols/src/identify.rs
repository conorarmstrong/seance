//! Stage A: say what an ISF file is, without parsing it.
//!
//! # The question this answers
//!
//! A lab's symbol store holds hundreds of ISFs, each tens of megabytes. Before
//! an examination can start, something has to answer "which of these describes
//! *this* image?" for every candidate. Fully parsing each one to find out would
//! cost minutes and gigabytes for an answer that lives in a few hundred bytes
//! of `metadata`.
//!
//! So identification makes exactly one structural pass over the bytes. No DOM
//! is built, no type is deserialised, and memory stays flat regardless of file
//! size: the walker tracks nesting depth and string state, counts the members
//! of the four big blocks, and materialises only the `metadata` object and, at
//! most, a couple of named symbol entries. The pass reads every byte because
//! the file's SHA-256 has to cover every byte, but it *parses* only what
//! identity needs.
//!
//! # What identity means, per platform
//!
//! - **Windows**: the CodeView triple `{database}|{GUID}|{age}`, compared
//!   byte-for-byte against the one read out of the kernel's own RSDS record.
//! - **Linux and macOS**: the kernel banner, carried as base64 `constant_data`
//!   on `linux_banner` or `version`. Both sides of every comparison go through
//!   [`normalize_banner`], because dwarf2json leaves a trailing `"\x00\n"` on
//!   the banner and upstream strips it on only one side, so two byte-identical
//!   kernels can compare unequal.
//!
//! Identification never rejects a file for declaring an unsupported format
//! version. Reporting "this pack is format 7.0.0, which this build cannot read"
//! is more useful to a lab than an unexplained load failure; the refusal
//! happens at the admission gate, where it is recorded.

use std::io::Read;
use std::path::Path;

use crate::error::{Result, SymbolError};
use crate::isf::{
    IsfDocument, IsfMetadata, IsfOs, Producer, SymbolDef, Version, LINUX_BANNER_SYMBOL,
    MAC_BANNER_SYMBOL,
};
use crate::source::{
    decoder, Compression, DecompressLimits, HashingReader, IsfProvenance, LimitedReader,
};

/// Ceiling on the raw `metadata` object. Real ones are a few hundred bytes.
pub const DEFAULT_MAX_METADATA_BYTES: usize = 1024 * 1024;

/// Ceiling on one captured symbol entry. A banner is a few hundred bytes.
pub const DEFAULT_MAX_SYMBOL_BYTES: usize = 64 * 1024;

/// Ceiling on one JSON key. C++ mangled symbol names get long; 16 KiB is well
/// past any of them and well short of an allocation an attacker chooses.
const MAX_KEY_BYTES: usize = 16 * 1024;

/// Ceiling on JSON nesting. Matches serde_json's own recursion limit; a
/// legitimate ISF nests about six deep.
const MAX_DEPTH: u32 = 128;

/// Ceiling on a bare scalar token. The longest legitimate one is a 20-digit
/// address.
const MAX_SCALAR_BYTES: usize = 64;

/// How many members each top-level block declared.
///
/// Reported so a lab can see at a glance that a pack is a kernel table
/// (hundreds of thousands of symbols) rather than a hand-written format
/// fragment (a handful of types and no symbols at all).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IsfCounts {
    /// Entries in `base_types`.
    pub base_types: u64,
    /// Entries in `user_types`.
    pub user_types: u64,
    /// Entries in `enums`.
    pub enums: u64,
    /// Entries in `symbols`.
    pub symbols: u64,
}

impl IsfCounts {
    /// Serializable form for artifact metadata.
    pub fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "base_types": self.base_types,
            "user_types": self.user_types,
            "enums": self.enums,
            "symbols": self.symbols,
        })
    }
}

/// Where an identity string came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierSource {
    /// The Windows CodeView triple from `metadata.windows.pdb`.
    PdbTriple,
    /// A kernel banner from a symbol's `constant_data`.
    Banner,
    /// The file declares no identity of its own. Normal and legitimate for the
    /// version-independent fragments that describe file formats and pool
    /// headers rather than one kernel build.
    None,
}

impl IdentifierSource {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            IdentifierSource::PdbTriple => "pdb_triple",
            IdentifierSource::Banner => "banner",
            IdentifierSource::None => "none",
        }
    }
}

/// What an ISF file is, established without compiling it.
#[derive(Debug, Clone)]
pub struct IsfIdentity {
    /// Which OS the metadata declares.
    pub os: IsfOs,
    /// Declared format version, parsed.
    pub format: Version,
    /// Declared format version, exactly as written in the file.
    pub format_raw: String,
    /// The identity string, if the file declares one.
    pub identifier: Option<String>,
    /// Where that string came from.
    pub identifier_source: IdentifierSource,
    /// The identity's raw bytes before normalisation, kept because a banner's
    /// trailing NUL and newline are evidence about the producer, and because a
    /// comparison that fails should be explainable byte by byte.
    pub identifier_raw: Option<Vec<u8>>,
    /// Who produced the file.
    pub producer: Option<Producer>,
    /// Declared member counts of the four big blocks.
    pub counts: IsfCounts,
    /// Hashes and lengths of the file.
    pub provenance: IsfProvenance,
}

impl IsfIdentity {
    /// Whether this reader implements the declared format version.
    pub fn is_supported_format(&self) -> bool {
        self.format.is_supported()
    }

    /// Serializable form for artifact metadata and report provenance.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "os": self.os.as_str(),
            "format": self.format.to_string(),
            "format_raw": self.format_raw,
            "supported_format": self.is_supported_format(),
            "identifier": self.identifier,
            "identifier_source": self.identifier_source.as_str(),
            "producer": self.producer.as_ref().map(|p| serde_json::json!({
                "name": p.name,
                "version": p.version,
                "datetime": p.datetime,
            })),
            "counts": self.counts.to_json(),
            "provenance": self.provenance.to_json(),
        })
    }

    /// Assemble an identity from the pieces both pipelines produce.
    fn assemble(
        metadata: &IsfMetadata,
        counts: IsfCounts,
        banner_symbol: Option<&SymbolDef>,
        provenance: IsfProvenance,
    ) -> Result<IsfIdentity> {
        if metadata.os_key_count() > 1 {
            return Err(SymbolError::malformed(
                "metadata declares more than one operating system; \
                 the ISF metadata block is a oneOf and cannot be for two platforms",
            ));
        }
        let format = metadata.version()?;
        let os = metadata.os();

        let (identifier, identifier_source, identifier_raw) = match os {
            IsfOs::Windows => match metadata.windows_identifier() {
                Some(triple) => (Some(triple), IdentifierSource::PdbTriple, None),
                None => (None, IdentifierSource::None, None),
            },
            IsfOs::Linux | IsfOs::Mac => match banner_symbol {
                Some(symbol) => match symbol.constant_bytes()? {
                    Some(raw) => {
                        let normalised = normalize_banner(&raw)?;
                        (Some(normalised), IdentifierSource::Banner, Some(raw))
                    }
                    None => (None, IdentifierSource::None, None),
                },
                None => (None, IdentifierSource::None, None),
            },
            IsfOs::None => (None, IdentifierSource::None, None),
        };

        Ok(IsfIdentity {
            os,
            format,
            format_raw: metadata.format.clone(),
            identifier,
            identifier_source,
            identifier_raw,
            producer: metadata.producer.clone(),
            counts,
            provenance,
        })
    }

    /// Identity of an already-parsed document.
    ///
    /// Produces exactly what [`identify`] would have produced for the same
    /// bytes, so a table's recorded identity never depends on which path
    /// loaded it.
    pub fn from_document(doc: &IsfDocument, provenance: IsfProvenance) -> Result<IsfIdentity> {
        let counts = IsfCounts {
            base_types: doc.base_types.len() as u64,
            user_types: doc.user_types.len() as u64,
            enums: doc.enums.len() as u64,
            symbols: doc.symbols.len() as u64,
        };
        let banner = doc
            .metadata
            .os()
            .banner_symbol()
            .and_then(|name| doc.symbols.get(name));
        IsfIdentity::assemble(&doc.metadata, counts, banner, provenance)
    }
}

/// Normalise a kernel banner for comparison.
///
/// dwarf2json-produced Linux banners end `"\x00\n"`, and upstream strips the
/// trailing byte only for identifiers coming from its remote list, not for
/// identifiers extracted from a local ISF. That asymmetry makes two
/// byte-identical kernels compare unequal. Séance defines this one function and
/// applies it to **both** sides of every comparison, keeping the raw bytes
/// alongside.
///
/// Truncates at the first NUL and trims surrounding whitespace. Nothing else:
/// no case folding, no whitespace collapsing inside the string, because the
/// compiler version and build timestamp inside a banner are what distinguish
/// two kernels that are otherwise identically named.
///
/// # Errors
///
/// [`SymbolError::Malformed`] if the bytes before the NUL are not UTF-8. A
/// lossy conversion would replace the corrupt bytes with a valid string and
/// then compare it, which is a comparison of something that was never in
/// evidence.
pub fn normalize_banner(raw: &[u8]) -> Result<String> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let text = std::str::from_utf8(&raw[..end]).map_err(|e| {
        SymbolError::malformed(format!(
            "the kernel banner is not valid UTF-8 at byte {}",
            e.valid_up_to()
        ))
    })?;
    Ok(text.trim().to_string())
}

/// Options for Stage A.
#[derive(Debug, Clone)]
pub struct IdentifyOptions {
    /// Symbols whose entry should be captured during the pass, so their
    /// `constant_data` is available for banner identity.
    pub banner_symbols: Vec<String>,
    /// Ceiling on the raw `metadata` object.
    pub max_metadata_bytes: usize,
    /// Ceiling on one captured symbol entry.
    pub max_symbol_bytes: usize,
    /// Decompression bounds.
    pub limits: DecompressLimits,
}

/// How far a scan read, and every `(symbol, bytes)` pair it recovered.
///
/// Named because the tuple appears in a signature clippy calls too complex to
/// read at a glance, and it is easier to reason about a scan's answer when the
/// two halves have names: how much of the source was covered, and what was
/// found in it.
type ScanFindings = (u64, Vec<(String, Vec<u8>)>);

impl Default for IdentifyOptions {
    fn default() -> Self {
        Self {
            banner_symbols: vec![
                LINUX_BANNER_SYMBOL.to_string(),
                MAC_BANNER_SYMBOL.to_string(),
            ],
            max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES,
            max_symbol_bytes: DEFAULT_MAX_SYMBOL_BYTES,
            limits: DecompressLimits::default(),
        }
    }
}

/// Identify an ISF from bytes already in memory.
pub fn identify(source: &[u8], options: &IdentifyOptions) -> Result<IsfIdentity> {
    identify_reader(std::io::Cursor::new(source), options)
}

/// Identify an ISF file on disk, decompressing on the fly.
pub fn identify_path(path: &Path, options: &IdentifyOptions) -> Result<IsfIdentity> {
    let file = std::fs::File::open(path).map_err(SymbolError::Io)?;
    identify_reader(file, options)
}

/// Identify an ISF from any reader, streaming.
///
/// Bounded memory: the reader is consumed in 64 KiB blocks and nothing is
/// retained except the `metadata` object and any captured symbol entries.
///
/// # Errors
///
/// Any structural break in the document, a truncated stream, a nesting depth
/// beyond [`MAX_DEPTH`], content after the closing brace, a missing `metadata`
/// block, or a decompressed size beyond the configured limits. A file that
/// cannot be identified is never guessed at.
pub fn identify_reader<R: Read>(reader: R, options: &IdentifyOptions) -> Result<IsfIdentity> {
    let mut source = HashingReader::new(reader);

    let mut magic = [0u8; Compression::MAGIC_LEN];
    let magic_len = read_prefix(&mut source, &mut magic).map_err(SymbolError::Io)?;
    let compression = Compression::detect(&magic[..magic_len]);

    let wanted: Vec<&str> = options.banner_symbols.iter().map(String::as_str).collect();

    let (skimmed, json_sha256, json_len) = {
        let head = std::io::Cursor::new(magic[..magic_len].to_vec()).chain(&mut source);
        let decoded = decoder(compression, head);
        let bounded = LimitedReader::new(
            decoded,
            options.limits.max_json_bytes,
            "the decompressed symbol file",
        );
        let mut hashing = HashingReader::new(bounded);
        let skimmed = Skimmer::new(&mut hashing).skim(&wanted, options)?;
        let (sha, len) = hashing.finish();
        (skimmed, sha, len)
    };

    // The file's own hash must cover the whole file, including any bytes the
    // decoder did not need. Draining is not optional: a hash over "the part we
    // happened to read" is not a hash of the evidence.
    std::io::copy(&mut source, &mut std::io::sink()).map_err(SymbolError::Io)?;
    let (source_sha256, source_len) = source.finish();

    if compression != Compression::None {
        let allowance = options.limits.allowance(source_len);
        if json_len > allowance {
            return Err(SymbolError::CompressionRatio {
                input: source_len,
                output: json_len,
                ratio: json_len / source_len.max(1),
                limit: options.limits.max_ratio,
            });
        }
    }

    let provenance = IsfProvenance {
        source_sha256,
        source_len,
        json_sha256,
        json_len,
        compression,
    };

    let banner_name = skimmed.metadata.os().banner_symbol();
    let banner = banner_name.and_then(|name| {
        skimmed
            .captured
            .iter()
            .find(|(captured, _)| captured == name)
            .map(|(_, def)| def)
    });

    IsfIdentity::assemble(&skimmed.metadata, skimmed.counts, banner, provenance)
}

/// Fill `buf` as far as the reader allows, returning how many bytes arrived.
fn read_prefix<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

/// What one structural pass recovered.
#[derive(Debug)]
struct Skimmed {
    metadata: IsfMetadata,
    counts: IsfCounts,
    captured: Vec<(String, SymbolDef)>,
}

/// A JSON structure walker that materialises nothing it is not asked for.
///
/// Deliberately not a parser: it validates nesting, strings and separators
/// well enough to walk the document exactly once and to fail on anything it
/// cannot account for, and hands the few byte ranges that matter to
/// `serde_json`. Every loop is bounded and the nesting counter is explicit, so
/// a hostile document cannot exhaust the stack or the heap.
struct Skimmer<R: Read> {
    inner: R,
    buffer: Box<[u8]>,
    position: usize,
    filled: usize,
    exhausted: bool,
    consumed: u64,
    sink: Option<Vec<u8>>,
    sink_cap: usize,
}

impl<R: Read> Skimmer<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: vec![0u8; 64 * 1024].into_boxed_slice(),
            position: 0,
            filled: 0,
            exhausted: false,
            consumed: 0,
            sink: None,
            sink_cap: 0,
        }
    }

    fn refill(&mut self) -> Result<()> {
        self.position = 0;
        loop {
            match self.inner.read(&mut self.buffer) {
                Ok(0) => {
                    self.filled = 0;
                    self.exhausted = true;
                    return Ok(());
                }
                Ok(read) => {
                    self.filled = read;
                    return Ok(());
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(SymbolError::Io(err)),
            }
        }
    }

    #[inline]
    fn peek(&mut self) -> Result<Option<u8>> {
        if self.position == self.filled {
            if self.exhausted {
                return Ok(None);
            }
            self.refill()?;
            if self.filled == 0 {
                return Ok(None);
            }
        }
        Ok(Some(self.buffer[self.position]))
    }

    #[inline]
    fn take(&mut self) -> Result<u8> {
        match self.peek()? {
            None => Err(SymbolError::malformed(format!(
                "the symbol file ends after {} bytes, in the middle of a JSON value",
                self.consumed
            ))),
            Some(byte) => {
                self.position += 1;
                self.consumed += 1;
                if let Some(sink) = self.sink.as_mut() {
                    if sink.len() >= self.sink_cap {
                        return Err(SymbolError::SizeLimit {
                            what: "a captured block of the symbol file",
                            limit: self.sink_cap as u64,
                        });
                    }
                    sink.push(byte);
                }
                Ok(byte)
            }
        }
    }

    /// Advance past whitespace and return the next significant byte, unconsumed.
    fn skip_whitespace(&mut self) -> Result<Option<u8>> {
        loop {
            match self.peek()? {
                Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r') => {
                    self.take()?;
                }
                other => return Ok(other),
            }
        }
    }

    fn expect(&mut self, wanted: u8) -> Result<()> {
        match self.skip_whitespace()? {
            Some(byte) if byte == wanted => {
                self.take()?;
                Ok(())
            }
            Some(byte) => Err(SymbolError::malformed(format!(
                "expected '{}' at byte {} of the symbol file, found '{}'",
                wanted as char,
                self.consumed,
                byte.escape_ascii()
            ))),
            None => Err(SymbolError::malformed(format!(
                "the symbol file ends where '{}' was expected",
                wanted as char
            ))),
        }
    }

    /// Copy the next string token, quotes included, into `out`.
    fn read_string_token(&mut self, out: &mut Vec<u8>) -> Result<()> {
        out.clear();
        match self.skip_whitespace()? {
            Some(b'"') => {}
            Some(byte) => {
                return Err(SymbolError::malformed(format!(
                    "expected a JSON key at byte {} of the symbol file, found '{}'",
                    self.consumed,
                    byte.escape_ascii()
                )))
            }
            None => {
                return Err(SymbolError::malformed(
                    "the symbol file ends where a JSON key was expected",
                ))
            }
        }
        out.push(self.take()?);
        loop {
            if out.len() >= MAX_KEY_BYTES {
                return Err(SymbolError::SizeLimit {
                    what: "a JSON key in the symbol file",
                    limit: MAX_KEY_BYTES as u64,
                });
            }
            let byte = self.take()?;
            out.push(byte);
            if byte == b'\\' {
                out.push(self.take()?);
                continue;
            }
            if byte == b'"' {
                return Ok(());
            }
        }
    }

    /// Walk a string token without keeping it.
    fn skip_string(&mut self) -> Result<()> {
        match self.skip_whitespace()? {
            Some(b'"') => {}
            Some(byte) => {
                return Err(SymbolError::malformed(format!(
                    "expected a JSON string at byte {} of the symbol file, found '{}'",
                    self.consumed,
                    byte.escape_ascii()
                )))
            }
            None => {
                return Err(SymbolError::malformed(
                    "the symbol file ends where a JSON string was expected",
                ))
            }
        }
        self.take()?;
        loop {
            let byte = self.take()?;
            if byte == b'\\' {
                self.take()?;
                continue;
            }
            if byte == b'"' {
                return Ok(());
            }
        }
    }

    /// Walk one value of any shape.
    fn skip_value(&mut self, depth: u32) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(SymbolError::malformed(format!(
                "the symbol file nests more than {MAX_DEPTH} levels deep"
            )));
        }
        match self.skip_whitespace()? {
            None => Err(SymbolError::malformed(
                "the symbol file ends where a JSON value was expected",
            )),
            Some(b'{') => {
                self.take()?;
                self.skip_object_body(depth)
            }
            Some(b'[') => {
                self.take()?;
                self.skip_array_body(depth)
            }
            Some(b'"') => self.skip_string(),
            Some(_) => self.skip_scalar(),
        }
    }

    fn skip_object_body(&mut self, depth: u32) -> Result<()> {
        if let Some(b'}') = self.skip_whitespace()? {
            self.take()?;
            return Ok(());
        }
        loop {
            self.skip_string()?;
            self.expect(b':')?;
            self.skip_value(depth + 1)?;
            match self.skip_whitespace()? {
                Some(b',') => {
                    self.take()?;
                }
                Some(b'}') => {
                    self.take()?;
                    return Ok(());
                }
                Some(byte) => {
                    return Err(SymbolError::malformed(format!(
                        "expected ',' or '}}' at byte {} of the symbol file, found '{}'",
                        self.consumed,
                        byte.escape_ascii()
                    )))
                }
                None => {
                    return Err(SymbolError::malformed(
                        "the symbol file ends inside a JSON object",
                    ))
                }
            }
        }
    }

    fn skip_array_body(&mut self, depth: u32) -> Result<()> {
        if let Some(b']') = self.skip_whitespace()? {
            self.take()?;
            return Ok(());
        }
        loop {
            self.skip_value(depth + 1)?;
            match self.skip_whitespace()? {
                Some(b',') => {
                    self.take()?;
                }
                Some(b']') => {
                    self.take()?;
                    return Ok(());
                }
                Some(byte) => {
                    return Err(SymbolError::malformed(format!(
                        "expected ',' or ']' at byte {} of the symbol file, found '{}'",
                        self.consumed,
                        byte.escape_ascii()
                    )))
                }
                None => {
                    return Err(SymbolError::malformed(
                        "the symbol file ends inside a JSON array",
                    ))
                }
            }
        }
    }

    fn skip_scalar(&mut self) -> Result<()> {
        let mut length = 0usize;
        loop {
            match self.peek()? {
                Some(byte)
                    if byte.is_ascii_alphanumeric()
                        || byte == b'+'
                        || byte == b'-'
                        || byte == b'.' =>
                {
                    self.take()?;
                    length += 1;
                    if length > MAX_SCALAR_BYTES {
                        return Err(SymbolError::malformed(format!(
                            "a JSON number or literal at byte {} of the symbol file is \
                             longer than {MAX_SCALAR_BYTES} bytes",
                            self.consumed
                        )));
                    }
                }
                _ => break,
            }
        }
        if length == 0 {
            return Err(SymbolError::malformed(format!(
                "unexpected byte at offset {} of the symbol file where a JSON value was expected",
                self.consumed
            )));
        }
        Ok(())
    }

    /// Walk one value, keeping its bytes.
    fn capture_value(&mut self, cap: usize, depth: u32) -> Result<Vec<u8>> {
        self.skip_whitespace()?;
        self.sink = Some(Vec::with_capacity(256));
        self.sink_cap = cap;
        let outcome = self.skip_value(depth);
        let captured = self.sink.take();
        outcome?;
        match captured {
            Some(bytes) => Ok(bytes),
            None => Err(SymbolError::malformed(
                "internal inconsistency: the capture buffer was lost mid-value",
            )),
        }
    }

    /// Count the members of an object, keeping nothing.
    fn count_members(&mut self, depth: u32) -> Result<u64> {
        self.expect(b'{')?;
        if let Some(b'}') = self.skip_whitespace()? {
            self.take()?;
            return Ok(0);
        }
        let mut count = 0u64;
        loop {
            self.skip_string()?;
            self.expect(b':')?;
            self.skip_value(depth + 1)?;
            count = count.saturating_add(1);
            match self.skip_whitespace()? {
                Some(b',') => {
                    self.take()?;
                }
                Some(b'}') => {
                    self.take()?;
                    return Ok(count);
                }
                Some(byte) => {
                    return Err(SymbolError::malformed(format!(
                        "expected ',' or '}}' at byte {} of the symbol file, found '{}'",
                        self.consumed,
                        byte.escape_ascii()
                    )))
                }
                None => {
                    return Err(SymbolError::malformed(
                        "the symbol file ends inside a JSON object",
                    ))
                }
            }
        }
    }

    /// Count the members of `symbols`, keeping the entries whose names match.
    ///
    /// Names are matched against the raw key token, so a symbol whose name is
    /// written with JSON escapes is not captured here. That is a miss, never a
    /// false match: an identity that cannot be established during Stage A ends
    /// as "unidentified", which fails closed.
    fn count_symbols(
        &mut self,
        wanted: &[&str],
        options: &IdentifyOptions,
        depth: u32,
    ) -> Result<ScanFindings> {
        let quoted: Vec<Vec<u8>> = wanted
            .iter()
            .map(|name| format!("\"{name}\"").into_bytes())
            .collect();

        self.expect(b'{')?;
        if let Some(b'}') = self.skip_whitespace()? {
            self.take()?;
            return Ok((0, Vec::new()));
        }
        let mut count = 0u64;
        let mut captured: Vec<(String, Vec<u8>)> = Vec::new();
        let mut key = Vec::with_capacity(64);
        loop {
            self.read_string_token(&mut key)?;
            self.expect(b':')?;
            match quoted.iter().position(|candidate| *candidate == key) {
                Some(index) if !captured.iter().any(|(name, _)| name == wanted[index]) => {
                    let raw = self.capture_value(options.max_symbol_bytes, depth + 1)?;
                    captured.push((wanted[index].to_string(), raw));
                }
                _ => self.skip_value(depth + 1)?,
            }
            count = count.saturating_add(1);
            match self.skip_whitespace()? {
                Some(b',') => {
                    self.take()?;
                }
                Some(b'}') => {
                    self.take()?;
                    return Ok((count, captured));
                }
                Some(byte) => {
                    return Err(SymbolError::malformed(format!(
                        "expected ',' or '}}' at byte {} of the symbol file, found '{}'",
                        self.consumed,
                        byte.escape_ascii()
                    )))
                }
                None => {
                    return Err(SymbolError::malformed(
                        "the symbol file ends inside the symbols block",
                    ))
                }
            }
        }
    }

    /// The one structural pass.
    fn skim(mut self, wanted: &[&str], options: &IdentifyOptions) -> Result<Skimmed> {
        self.expect(b'{')?;

        let mut metadata_raw: Option<Vec<u8>> = None;
        let mut counts = IsfCounts::default();
        let mut captured_raw: Vec<(String, Vec<u8>)> = Vec::new();
        let mut seen_base = false;
        let mut seen_user = false;
        let mut seen_enums = false;
        let mut seen_symbols = false;
        let mut key = Vec::with_capacity(32);

        if let Some(b'}') = self.skip_whitespace()? {
            return Err(SymbolError::malformed(
                "the symbol file is an empty JSON object, with no metadata block",
            ));
        }

        loop {
            self.read_string_token(&mut key)?;
            self.expect(b':')?;
            match key.as_slice() {
                b"\"metadata\"" => {
                    if metadata_raw.is_some() {
                        return Err(SymbolError::malformed(
                            "the symbol file declares 'metadata' twice",
                        ));
                    }
                    metadata_raw = Some(self.capture_value(options.max_metadata_bytes, 1)?);
                }
                b"\"base_types\"" => {
                    if seen_base {
                        return Err(SymbolError::malformed(
                            "the symbol file declares 'base_types' twice",
                        ));
                    }
                    seen_base = true;
                    counts.base_types = self.count_members(1)?;
                }
                b"\"user_types\"" => {
                    if seen_user {
                        return Err(SymbolError::malformed(
                            "the symbol file declares 'user_types' twice",
                        ));
                    }
                    seen_user = true;
                    counts.user_types = self.count_members(1)?;
                }
                b"\"enums\"" => {
                    if seen_enums {
                        return Err(SymbolError::malformed(
                            "the symbol file declares 'enums' twice",
                        ));
                    }
                    seen_enums = true;
                    counts.enums = self.count_members(1)?;
                }
                b"\"symbols\"" => {
                    if seen_symbols {
                        return Err(SymbolError::malformed(
                            "the symbol file declares 'symbols' twice",
                        ));
                    }
                    seen_symbols = true;
                    let (count, captured) = self.count_symbols(wanted, options, 1)?;
                    counts.symbols = count;
                    captured_raw = captured;
                }
                _ => self.skip_value(1)?,
            }
            match self.skip_whitespace()? {
                Some(b',') => {
                    self.take()?;
                }
                Some(b'}') => {
                    self.take()?;
                    break;
                }
                Some(byte) => {
                    return Err(SymbolError::malformed(format!(
                        "expected ',' or '}}' at byte {} of the symbol file, found '{}'",
                        self.consumed,
                        byte.escape_ascii()
                    )))
                }
                None => {
                    return Err(SymbolError::malformed(
                        "the symbol file ends inside the top-level object",
                    ))
                }
            }
        }

        if let Some(byte) = self.skip_whitespace()? {
            return Err(SymbolError::malformed(format!(
                "the symbol file has content after the closing brace, starting with '{}'",
                byte.escape_ascii()
            )));
        }

        let metadata_raw = metadata_raw.ok_or_else(|| {
            SymbolError::malformed(
                "the symbol file has no metadata block, so it identifies nothing",
            )
        })?;
        let metadata: IsfMetadata = serde_json::from_slice(&metadata_raw)
            .map_err(|e| SymbolError::json("the metadata block", e))?;

        let mut captured = Vec::with_capacity(captured_raw.len());
        for (name, raw) in captured_raw {
            let def: SymbolDef = serde_json::from_slice(&raw)
                .map_err(|e| SymbolError::json(format!("symbol '{name}'"), e))?;
            captured.push((name, def));
        }

        Ok(Skimmed {
            metadata,
            counts,
            captured,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::test_support::{gzip, xz};

    /// A Linux ISF whose symbols block is far larger than its metadata, so a
    /// test that identifies it proves identification did not need the symbols.
    fn linux_isf(extra_symbols: usize) -> String {
        let mut symbols = String::from(
            r#""linux_banner": {"address": 18446744071595622400,
                 "constant_data": "TGludXggdmVyc2lvbiA2LjEuMAoA"}"#,
        );
        for index in 0..extra_symbols {
            symbols.push_str(&format!(
                r#", "filler_symbol_{index}": {{"address": {}, "type": {{"kind":"base","name":"int"}}}}"#,
                4096 + index
            ));
        }
        format!(
            r#"{{
              "metadata": {{
                "format": "6.2.0",
                "producer": {{"name": "dwarf2json", "version": "0.9.0", "datetime": "2026-07-01"}},
                "linux": {{"symbols": [{{"kind": "dwarf", "name": "vmlinux"}}], "types": []}}
              }},
              "base_types": {{
                "pointer": {{"size": 8, "signed": false, "kind": "int", "endian": "little"}},
                "int": {{"size": 4, "signed": true, "kind": "int", "endian": "little"}}
              }},
              "user_types": {{
                "task_struct": {{"size": 32, "kind": "struct", "fields": {{
                  "pid": {{"offset": 8, "type": {{"kind": "base", "name": "int"}}}}
                }}}}
              }},
              "enums": {{}},
              "symbols": {{{symbols}}}
            }}"#
        )
    }

    fn windows_isf() -> &'static str {
        r#"{
          "metadata": {
            "format": "6.1.0",
            "producer": {"name": "seance_symbols_pdb", "version": "0.9.0"},
            "windows": {"pdb": {
               "GUID": "1c9f3fb0e2a54c1e9f0f8d1b2c3d4e5f", "age": 1,
               "database": "ntkrnlmp.pdb", "machine_type": 34404}}
          },
          "base_types": {"pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"}},
          "user_types": {},
          "enums": {},
          "symbols": {"PsActiveProcessHead": {"address": 18446744071578845184}}
        }"#
    }

    #[test]
    fn a_linux_isf_is_identified_by_its_banner_without_reading_its_types() {
        let json = linux_isf(500);
        let identity = identify(json.as_bytes(), &IdentifyOptions::default()).expect("identifies");

        assert_eq!(identity.os, IsfOs::Linux);
        assert_eq!(identity.format, Version::new(6, 2, 0));
        assert_eq!(identity.identifier.as_deref(), Some("Linux version 6.1.0"));
        assert_eq!(identity.identifier_source, IdentifierSource::Banner);
        assert_eq!(
            identity.identifier_raw.as_deref(),
            Some(&b"Linux version 6.1.0\n\0"[..]),
            "the raw bytes are kept so a failed comparison can be explained"
        );
        assert_eq!(identity.counts.symbols, 501);
        assert_eq!(identity.counts.base_types, 2);
        assert_eq!(identity.counts.user_types, 1);
        assert_eq!(identity.counts.enums, 0);
        assert_eq!(
            identity.producer.as_ref().and_then(|p| p.name.as_deref()),
            Some("dwarf2json")
        );
        assert!(identity.is_supported_format());
    }

    #[test]
    fn a_windows_isf_is_identified_by_its_codeview_triple() {
        let identity =
            identify(windows_isf().as_bytes(), &IdentifyOptions::default()).expect("identifies");
        assert_eq!(identity.os, IsfOs::Windows);
        assert_eq!(
            identity.identifier.as_deref(),
            Some("ntkrnlmp.pdb|1C9F3FB0E2A54C1E9F0F8D1B2C3D4E5F|1")
        );
        assert_eq!(identity.identifier_source, IdentifierSource::PdbTriple);
        assert_eq!(identity.counts.symbols, 1);
    }

    #[test]
    fn identification_is_identical_whether_the_file_is_compressed_or_not() {
        let json = linux_isf(20);
        let plain = identify(json.as_bytes(), &IdentifyOptions::default()).expect("plain");
        let gz_bytes = gzip(json.as_bytes());
        let gzipped = identify(&gz_bytes, &IdentifyOptions::default()).expect("gzip");
        let xz_bytes = xz(json.as_bytes());
        let xzipped = identify(&xz_bytes, &IdentifyOptions::default()).expect("xz");

        assert_eq!(plain.identifier, gzipped.identifier);
        assert_eq!(plain.identifier, xzipped.identifier);
        assert_eq!(plain.counts, gzipped.counts);
        assert_eq!(plain.counts, xzipped.counts);

        // The JSON hash is the same file; the source hashes are three different
        // files, and the record must not pretend otherwise.
        assert_eq!(plain.provenance.json_sha256, gzipped.provenance.json_sha256);
        assert_eq!(plain.provenance.json_sha256, xzipped.provenance.json_sha256);
        assert_ne!(
            gzipped.provenance.source_sha256,
            xzipped.provenance.source_sha256
        );
        assert_eq!(gzipped.provenance.compression, Compression::Gzip);
        assert_eq!(xzipped.provenance.compression, Compression::Xz);
        assert_eq!(gzipped.provenance.source_len, gz_bytes.len() as u64);
    }

    #[test]
    fn a_fragment_with_no_operating_system_key_identifies_as_having_no_identity() {
        let json = r#"{
            "metadata": {"format": "4.0.0", "producer": {"name": "hand-written"}},
            "base_types": {"pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"}},
            "user_types": {"_POOL_HEADER": {"size": 16, "kind": "struct", "fields": {}}},
            "enums": {},
            "symbols": {}
        }"#;
        let identity = identify(json.as_bytes(), &IdentifyOptions::default()).expect("identifies");
        assert_eq!(identity.os, IsfOs::None);
        assert_eq!(identity.identifier, None);
        assert_eq!(identity.identifier_source, IdentifierSource::None);
        assert_eq!(identity.format, Version::new(4, 0, 0));
        assert!(
            identity.is_supported_format(),
            "4.0.0 is the floor precisely so the pool-header fragments load"
        );
    }

    #[test]
    fn an_unsupported_format_still_identifies_and_says_it_is_unsupported() {
        let json = r#"{"metadata": {"format": "7.0.0"}, "symbols": {}}"#;
        let identity = identify(json.as_bytes(), &IdentifyOptions::default()).expect("identifies");
        assert_eq!(identity.format, Version::new(7, 0, 0));
        assert!(!identity.is_supported_format());
    }

    #[test]
    fn a_garbage_file_errors_rather_than_panicking() {
        for garbage in [
            &b"this is not JSON at all"[..],
            &b""[..],
            &b"[]"[..],
            &b"{"[..],
            &b"{\"metadata\":"[..],
            &b"{\"metadata\": {\"format\": \"6.2.0\""[..],
            &[0xff, 0xfe, 0x00, 0x01][..],
        ] {
            let err = identify(garbage, &IdentifyOptions::default())
                .expect_err("garbage must not identify");
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn a_truncated_document_errors_rather_than_identifying_half_a_file() {
        let json = linux_isf(50);
        let truncated = &json.as_bytes()[..json.len() / 2];
        let err = identify(truncated, &IdentifyOptions::default())
            .expect_err("half a file is not a file");
        assert!(err.to_string().contains("ends"), "{err}");
    }

    #[test]
    fn content_after_the_closing_brace_is_refused() {
        let json = format!("{} trailing garbage", linux_isf(1));
        let err = identify(json.as_bytes(), &IdentifyOptions::default())
            .expect_err("appended content must be refused");
        assert!(err.to_string().contains("after the closing brace"), "{err}");
    }

    #[test]
    fn a_document_with_no_metadata_block_identifies_nothing() {
        let json = r#"{"base_types": {}, "user_types": {}, "enums": {}, "symbols": {}}"#;
        let err = identify(json.as_bytes(), &IdentifyOptions::default())
            .expect_err("no metadata means no identity");
        assert!(err.to_string().contains("no metadata block"), "{err}");
    }

    #[test]
    fn a_repeated_top_level_key_is_refused() {
        let json = r#"{"metadata": {"format": "6.2.0"}, "metadata": {"format": "4.0.0"}}"#;
        let err = identify(json.as_bytes(), &IdentifyOptions::default())
            .expect_err("two metadata blocks must be refused");
        assert!(err.to_string().contains("twice"), "{err}");
    }

    #[test]
    fn deeply_nested_json_is_refused_rather_than_exhausting_anything() {
        let mut json = String::from(r#"{"metadata": {"format": "6.2.0"}, "junk": "#);
        json.push_str(&"[".repeat(600));
        json.push_str(&"]".repeat(600));
        json.push('}');
        let err = identify(json.as_bytes(), &IdentifyOptions::default())
            .expect_err("600 levels of nesting must be refused");
        assert!(err.to_string().contains("nests more than"), "{err}");
    }

    #[test]
    fn a_metadata_block_declaring_two_operating_systems_is_refused() {
        let json = r#"{"metadata": {"format": "6.2.0", "windows": {}, "linux": {}}}"#;
        let err = identify(json.as_bytes(), &IdentifyOptions::default())
            .expect_err("a two-OS metadata block is not a oneOf");
        assert!(
            err.to_string().contains("more than one operating system"),
            "{err}"
        );
    }

    #[test]
    fn an_oversized_metadata_block_is_refused_rather_than_buffered() {
        let filler = "x".repeat(4096);
        let json = format!(
            r#"{{"metadata": {{"format": "6.2.0", "note": "{filler}"}}, "symbols": {{}}}}"#
        );
        let options = IdentifyOptions {
            max_metadata_bytes: 512,
            ..IdentifyOptions::default()
        };
        let err = identify(json.as_bytes(), &options).expect_err("must not buffer without bound");
        assert!(matches!(err, SymbolError::SizeLimit { .. }), "{err}");
    }

    #[test]
    fn identity_from_a_parsed_document_matches_identity_from_the_stream() {
        let json = linux_isf(5);
        let streamed = identify(json.as_bytes(), &IdentifyOptions::default()).expect("streamed");
        let loaded = crate::source::load_slice(json.as_bytes(), &DecompressLimits::default())
            .expect("loads");
        let doc = IsfDocument::parse(&loaded.json).expect("parses");
        let parsed = IsfIdentity::from_document(&doc, loaded.provenance).expect("identity");

        assert_eq!(streamed.identifier, parsed.identifier);
        assert_eq!(streamed.counts, parsed.counts);
        assert_eq!(streamed.os, parsed.os);
        assert_eq!(
            streamed.provenance.source_sha256,
            parsed.provenance.source_sha256
        );
    }

    #[test]
    fn a_banner_is_normalised_identically_however_it_is_terminated() {
        assert_eq!(
            normalize_banner(b"Linux version 6.1.0\n\0").unwrap(),
            "Linux version 6.1.0"
        );
        assert_eq!(
            normalize_banner(b"Linux version 6.1.0\n").unwrap(),
            "Linux version 6.1.0"
        );
        assert_eq!(
            normalize_banner(b"Linux version 6.1.0").unwrap(),
            "Linux version 6.1.0"
        );
        assert_eq!(
            normalize_banner(b"Linux version 6.1.0\0trailing junk").unwrap(),
            "Linux version 6.1.0",
            "everything after the NUL is not part of the banner"
        );
    }

    #[test]
    fn a_banner_that_is_not_utf8_is_an_error_rather_than_a_lossy_guess() {
        let err = normalize_banner(&[0x4c, 0x69, 0xff, 0xfe])
            .expect_err("a corrupt banner must not be silently repaired");
        assert!(err.to_string().contains("not valid UTF-8"), "{err}");
    }

    #[test]
    fn a_symbol_name_is_captured_only_once_even_if_it_repeats() {
        // A duplicate key in `symbols` is caught by the admission gate during
        // compilation; identification must not double-capture or mis-count.
        let json = r#"{
            "metadata": {"format": "6.2.0", "linux": {}},
            "symbols": {
              "linux_banner": {"address": 1, "constant_data": "TGludXggdmVyc2lvbiA2LjEuMAoA"},
              "linux_banner": {"address": 2, "constant_data": "QQ=="}
            }
        }"#;
        let identity = identify(json.as_bytes(), &IdentifyOptions::default()).expect("identifies");
        assert_eq!(identity.counts.symbols, 2);
        assert_eq!(identity.identifier.as_deref(), Some("Linux version 6.1.0"));
    }

    #[test]
    fn a_block_that_is_not_an_object_is_refused() {
        let json = r#"{"metadata": {"format": "6.2.0"}, "base_types": []}"#;
        let err = identify(json.as_bytes(), &IdentifyOptions::default())
            .expect_err("base_types must be an object");
        assert!(err.to_string().contains("expected '{'"), "{err}");
    }
}
