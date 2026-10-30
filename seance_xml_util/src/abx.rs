//! Android Binary XML (`ABX`), the encoding Android 12 and later use for
//! `/data/system/packages.xml`, `appops.xml`, the users directory and most
//! other framework settings files.
//!
//! # What an examiner would get wrong without this
//!
//! A file named `packages.xml` on a modern device is not text. It begins
//! `ABX\0` and continues as a token stream written by
//! `com.android.internal.util.BinaryXmlSerializer`. Handed to a text XML
//! parser it stops on byte 0 — and a tool that then reports "0 packages, the
//! walk stopped on a parse error" is honest but useless: the install time,
//! version and installer of every application on every Android 12+ device is
//! in that file and nowhere else on the device in that form.
//!
//! # The format
//!
//! Header `ABX` + one version byte (only `0` exists). Then tokens. Each token
//! byte is `(type << 4) | event`. The low nibble is the XmlPullParser event:
//! `START_DOCUMENT 0, END_DOCUMENT 1, START_TAG 2, END_TAG 3, TEXT 4, CDSECT 5,
//! ENTITY_REF 6, IGNORABLE_WHITESPACE 7, PROCESSING_INSTRUCTION 8, COMMENT 9,
//! DOCDECL 10, ATTRIBUTE 15`. The high nibble is the payload type: `NULL 1,
//! STRING 2, STRING_INTERNED 3, BYTES_HEX 4, BYTES_BASE64 5, INT 6, INT_HEX 7,
//! LONG 8, LONG_HEX 9, FLOAT 10, DOUBLE 11, BOOLEAN_TRUE 12, BOOLEAN_FALSE 13`.
//!
//! Every multi-byte integer is big-endian (Java `DataOutput`). A `STRING`
//! payload is a `u16` byte length followed by that many bytes of Java modified
//! UTF-8. A `STRING_INTERNED` payload is a `u16` index into a table the reader
//! builds as it goes; the index `0xFFFF` means "a `STRING` payload follows —
//! intern it". Tag names are interned strings; an `ATTRIBUTE` token carries its
//! interned name first and then its value in the form the type says.
//!
//! The writer interns at most 65 535 strings and the table is never reset, so
//! an index the reader has not yet assigned is a malformed document, not a
//! forward reference.
//!
//! # Honesty
//!
//! The decoder never panics on truncated or hostile input. A document that
//! ends mid-token returns every event decoded before the break plus an
//! [`AbxError`] naming the byte offset and what was expected there, so a
//! consumer can stamp its parse incomplete instead of taking the prefix as the
//! whole. Strings that are not valid UTF-8 are decoded with replacement
//! characters and counted in [`AbxDocument::lossy_strings`]: a name so decoded
//! is not the name the device holds.

use std::fmt;

/// The `ABX` magic and the one protocol version that exists.
const MAGIC: &[u8; 4] = b"ABX\0";

/// Deepest element nesting the decoder accepts.
///
/// `packages.xml` nests five deep. The decoder does not recurse, so the bound
/// costs nothing on legitimate input; it exists so that a token stream of
/// `START_TAG` forever cannot claim an unbounded open-element stack in the
/// rendered text.
pub const MAX_DEPTH: usize = 256;

/// Most strings the intern table admits — the writer's own limit, since the
/// index `0xFFFF` is the "new string" marker and cannot address a slot.
pub const MAX_INTERNED_STRINGS: usize = 0xFFFF;

/// The most a decoded document may occupy — string bytes plus the fixed
/// size of every event and attribute — before decoding stops with
/// [`AbxError::DecodedTooLarge`]. A 3-byte interned reference expands to up
/// to 65,535 bytes, so without this a few-megabyte file names a document of
/// tens of gigabytes and the process dies before any record says why.
pub const MAX_DECODED_BYTES: usize = 256 * 1024 * 1024;

const EVENT_START_DOCUMENT: u8 = 0;
const EVENT_END_DOCUMENT: u8 = 1;
const EVENT_START_TAG: u8 = 2;
const EVENT_END_TAG: u8 = 3;
const EVENT_TEXT: u8 = 4;
const EVENT_CDSECT: u8 = 5;
const EVENT_ENTITY_REF: u8 = 6;
const EVENT_IGNORABLE_WHITESPACE: u8 = 7;
const EVENT_PROCESSING_INSTRUCTION: u8 = 8;
const EVENT_COMMENT: u8 = 9;
const EVENT_DOCDECL: u8 = 10;
const EVENT_ATTRIBUTE: u8 = 15;

const TYPE_NULL: u8 = 1;
const TYPE_STRING: u8 = 2;
const TYPE_STRING_INTERNED: u8 = 3;
const TYPE_BYTES_HEX: u8 = 4;
const TYPE_BYTES_BASE64: u8 = 5;
const TYPE_INT: u8 = 6;
const TYPE_INT_HEX: u8 = 7;
const TYPE_LONG: u8 = 8;
const TYPE_LONG_HEX: u8 = 9;
const TYPE_FLOAT: u8 = 10;
const TYPE_DOUBLE: u8 = 11;
const TYPE_BOOLEAN_TRUE: u8 = 12;
const TYPE_BOOLEAN_FALSE: u8 = 13;

/// The "new string follows" marker in an interned-string slot.
const INTERN_NEW: u16 = 0xFFFF;

/// True when `bytes` begin with the `ABX` magic.
///
/// Any version byte is accepted here so that an unknown version is refused by
/// the decoder with a reason, rather than being fed to a text parser as if it
/// were XML.
pub fn is_abx(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..3] == b"ABX"
}

/// An attribute value, typed as the writer typed it.
///
/// The type is kept rather than flattened to text because the text form is a
/// rendering choice — `INT_HEX` and `LONG_HEX` render as bare hex like
/// Android's own text writer, and a consumer that wants the number should not
/// have to parse it back.
#[derive(Debug, Clone, PartialEq)]
pub enum AbxValue {
    Null,
    String(String),
    BytesHex(Vec<u8>),
    BytesBase64(Vec<u8>),
    Int(i32),
    IntHex(i32),
    Long(i64),
    LongHex(i64),
    Float(f32),
    Double(f64),
    Bool(bool),
}

impl AbxValue {
    /// The text Android's `FastXmlSerializer` would have written for this
    /// value: ints decimal, `*_HEX` as `Long.toString(v, 16)` — bare
    /// lowercase hex, signed, so `-1` is `-1` and not `ffffffffffffffff` —
    /// booleans `true`/`false`, hex bytes as uppercase pairs, base64 unwrapped.
    ///
    /// Floats and doubles follow `Float.toString`/`Double.toString`: shortest
    /// round-trip digits with at least one fractional digit (`1.0`), scientific
    /// notation as `d.dddE±n` outside `[1e-3, 1e7)`, and `Infinity`/`NaN`.
    pub fn to_text(&self) -> String {
        match self {
            AbxValue::Null => String::new(),
            AbxValue::String(s) => s.clone(),
            AbxValue::BytesHex(b) => b.iter().map(|x| format!("{x:02X}")).collect(),
            AbxValue::BytesBase64(b) => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(b)
            }
            AbxValue::Int(i) => i.to_string(),
            AbxValue::IntHex(i) => signed_hex(i64::from(*i)),
            AbxValue::Long(l) => l.to_string(),
            AbxValue::LongHex(l) => signed_hex(*l),
            AbxValue::Float(f) => java_float_text(f64::from(*f), format!("{f:e}"), f.to_string()),
            AbxValue::Double(d) => java_float_text(*d, format!("{d:e}"), d.to_string()),
            AbxValue::Bool(b) => b.to_string(),
        }
    }
}

/// `Long.toString(v, 16)`: the magnitude in lowercase hex with a leading
/// minus for negatives.
fn signed_hex(v: i64) -> String {
    if v < 0 {
        format!("-{:x}", v.unsigned_abs())
    } else {
        format!("{v:x}")
    }
}

/// `Float.toString` / `Double.toString` from Rust's two shortest-round-trip
/// renderings of the same value: `sci` is `{:e}` (`1.5e0`, `1e10`), `plain`
/// is `{}` (`1.5`, `10000000000`). Java uses plain form with at least one
/// fractional digit for magnitudes in `[1e-3, 1e7)` and `d.dddE±n` elsewhere.
fn java_float_text(v: f64, sci: String, plain: String) -> String {
    if v.is_nan() {
        return "NaN".to_owned();
    }
    if v.is_infinite() {
        return if v > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }
    if v == 0.0 {
        return if v.is_sign_negative() { "-0.0" } else { "0.0" }.to_owned();
    }
    let mag = v.abs();
    if (1e-3..1e7).contains(&mag) {
        return if plain.contains('.') {
            plain
        } else {
            format!("{plain}.0")
        };
    }
    let (mantissa, exponent) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
    let mantissa = if mantissa.contains('.') {
        mantissa.to_owned()
    } else {
        format!("{mantissa}.0")
    };
    format!("{mantissa}E{exponent}")
}

/// XML `Name` production, as far as the text renderer needs it: the first
/// character a letter, `_` or `:`, the rest letters, digits, `-`, `.`, `_`
/// or `:`. A tag or attribute name is written bare into the text form, so a
/// name failing this could carry markup the decoded events do not hold.
pub fn is_xml_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_alphabetic() || first == '_' || first == ':') {
        return false;
    }
    chars.all(|c| c.is_alphanumeric() || matches!(c, '-' | '.' | '_' | ':'))
}

/// One attribute of a start tag.
#[derive(Debug, Clone, PartialEq)]
pub struct AbxAttribute {
    pub name: String,
    pub value: AbxValue,
}

/// One decoded token, in document order.
///
/// Attributes are folded into the `StartTag` that owns them, because that is
/// the only place the format allows them and it is what every consumer wants.
#[derive(Debug, Clone, PartialEq)]
pub enum AbxEvent {
    StartDocument,
    EndDocument,
    StartTag {
        name: String,
        attributes: Vec<AbxAttribute>,
    },
    EndTag {
        name: String,
    },
    Text(String),
    Cdsect(String),
    EntityRef(String),
    IgnorableWhitespace(String),
    ProcessingInstruction(String),
    Comment(String),
    Docdecl(String),
}

/// Everything decoded from one document, complete or not.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AbxDocument {
    pub events: Vec<AbxEvent>,
    /// Strings that were not valid modified UTF-8 and were decoded with
    /// replacement characters. Each one is a value the device holds that this
    /// tool cannot reproduce exactly.
    pub lossy_strings: usize,
}

/// What decoding produced: the events read, and the reason reading stopped
/// if it stopped before `END_DOCUMENT`.
#[derive(Debug, Clone, PartialEq)]
pub struct AbxDecode {
    pub document: AbxDocument,
    /// `None` when `END_DOCUMENT` was reached.
    pub error: Option<AbxError>,
    /// Bytes consumed, including the header. Less than the input length when
    /// the document ended before the bytes did.
    pub bytes_consumed: usize,
}

/// Why decoding stopped. Every variant names the byte offset it stopped at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbxError {
    /// The bytes do not begin with `ABX`.
    NotAbx,
    /// The header names a protocol version this decoder does not know.
    UnsupportedVersion { version: u8 },
    /// The input ended before a token or payload did.
    Truncated {
        /// Where the unfinished item begins.
        offset: usize,
        /// What was expected there, in prose.
        expected: String,
        /// How many bytes of that item are present; the input ends at
        /// `offset + present`.
        present: usize,
    },
    /// A tag or attribute name that is not an XML `Name`, so it cannot be
    /// rendered bare into the text form without changing what it says.
    InvalidName { offset: usize },
    /// The decoded document — strings, events and attributes — passed
    /// [`MAX_DECODED_BYTES`]. Interned strings let a 3-byte reference stand
    /// for 65,535 bytes, so a small file can name a document far larger than
    /// this process should hold.
    DecodedTooLarge { offset: usize, limit: usize },
    /// A token byte whose type or event nibble names nothing in the format.
    UnknownToken { offset: usize, token: u8 },
    /// An interned-string index past the end of the table built so far.
    InternIndexOutOfRange {
        offset: usize,
        index: u16,
        table_len: usize,
    },
    /// More interned strings than the format can address.
    InternTableFull { offset: usize },
    /// An `ATTRIBUTE` token that does not follow a `START_TAG` or another
    /// attribute of the same tag.
    UnexpectedAttribute { offset: usize },
    /// An `END_TAG` with no open element.
    UnbalancedEndTag { offset: usize },
    /// Elements nested deeper than [`MAX_DEPTH`].
    NestingTooDeep { offset: usize, depth: usize },
}

impl AbxError {
    /// The byte offset the error is anchored at, when it has one.
    pub fn offset(&self) -> Option<usize> {
        match self {
            AbxError::NotAbx | AbxError::UnsupportedVersion { .. } => None,
            AbxError::Truncated { offset, .. }
            | AbxError::UnknownToken { offset, .. }
            | AbxError::InternIndexOutOfRange { offset, .. }
            | AbxError::InternTableFull { offset }
            | AbxError::UnexpectedAttribute { offset }
            | AbxError::UnbalancedEndTag { offset }
            | AbxError::InvalidName { offset }
            | AbxError::DecodedTooLarge { offset, .. }
            | AbxError::NestingTooDeep { offset, .. } => Some(*offset),
        }
    }

    /// True when the document simply ended too soon, as opposed to holding
    /// bytes that do not form a document.
    pub fn is_truncation(&self) -> bool {
        matches!(self, AbxError::Truncated { .. })
    }
}

impl fmt::Display for AbxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbxError::NotAbx => write!(f, "the bytes do not begin with the ABX magic"),
            AbxError::UnsupportedVersion { version } => {
                write!(f, "ABX protocol version {version} is not one this decoder knows")
            }
            AbxError::Truncated {
                offset,
                expected,
                present: 0,
            } => {
                write!(f, "the document ends at byte {offset} where {expected} was expected")
            }
            AbxError::Truncated {
                offset,
                expected,
                present,
            } => write!(
                f,
                "the document ends at byte {}, {present} bytes into {expected} that begins at \
                 byte {offset}",
                offset.saturating_add(*present)
            ),
            AbxError::InvalidName { offset } => write!(
                f,
                "byte {offset} holds a tag or attribute name that is not an XML name, which the \
                 text form could not carry faithfully"
            ),
            AbxError::DecodedTooLarge { offset, limit } => write!(
                f,
                "by byte {offset} the decoded document passed the {limit}-byte limit this \
                 decoder holds; interned strings let a small file name a far larger document"
            ),
            AbxError::UnknownToken { offset, token } => {
                write!(f, "byte {offset} holds token 0x{token:02x}, which names no ABX event or type")
            }
            AbxError::InternIndexOutOfRange {
                offset,
                index,
                table_len,
            } => write!(
                f,
                "byte {offset} references interned string {index} but only {table_len} had been defined"
            ),
            AbxError::InternTableFull { offset } => write!(
                f,
                "byte {offset} defines a {}th interned string, more than the format can address",
                MAX_INTERNED_STRINGS.saturating_add(1)
            ),
            AbxError::UnexpectedAttribute { offset } => {
                write!(f, "byte {offset} holds an attribute that follows no start tag")
            }
            AbxError::UnbalancedEndTag { offset } => {
                write!(f, "byte {offset} closes an element that was never opened")
            }
            AbxError::NestingTooDeep { offset, depth } => write!(
                f,
                "byte {offset} opens an element {depth} levels deep, past the {MAX_DEPTH} this decoder admits"
            ),
        }
    }
}

impl std::error::Error for AbxError {}

/// Decode `bytes` as far as they go.
///
/// Never panics. Returns the events decoded before any error together with
/// the error, so a consumer can keep the prefix *and* say it is a prefix.
pub fn decode(bytes: &[u8]) -> AbxDecode {
    let mut decoder = Decoder {
        cursor: Cursor { bytes, pos: 0 },
        interned: Vec::new(),
        document: AbxDocument::default(),
        depth: 0,
        attributes_open: false,
        decoded_bytes: 0,
    };
    let error = decoder.run().err();
    AbxDecode {
        document: decoder.document,
        error,
        bytes_consumed: decoder.cursor.pos,
    }
}

/// A bounds-checked reader over the input. Every read names, on failure,
/// the offset it wanted and what it wanted there.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize, expected: &str) -> Result<&'a [u8], AbxError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| AbxError::Truncated {
                offset: self.pos,
                expected: expected.to_owned(),
                present: self.bytes.len().saturating_sub(self.pos),
            })?;
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self, expected: &str) -> Result<u8, AbxError> {
        Ok(self.take(1, expected)?[0])
    }

    fn u16(&mut self, expected: &str) -> Result<u16, AbxError> {
        let b = self.take(2, expected)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn i32(&mut self, expected: &str) -> Result<i32, AbxError> {
        let b = self.take(4, expected)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i64(&mut self, expected: &str) -> Result<i64, AbxError> {
        let b = self.take(8, expected)?;
        Ok(i64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// A `u16` length followed by that many raw bytes.
    fn sized(&mut self, what: &str) -> Result<&'a [u8], AbxError> {
        let len = usize::from(self.u16(what)?);
        self.take(len, &format!("{len} bytes of string"))
    }
}

struct Decoder<'a> {
    cursor: Cursor<'a>,
    interned: Vec<String>,
    document: AbxDocument,
    /// Open elements, for the nesting bound and the end-tag balance check.
    depth: usize,
    /// True while the last event is a `StartTag` that may still gain
    /// attributes — i.e. nothing but attributes has been read since it.
    attributes_open: bool,
    /// Bytes the decoded document occupies so far, against
    /// [`MAX_DECODED_BYTES`].
    decoded_bytes: usize,
}

impl<'a> Decoder<'a> {
    fn run(&mut self) -> Result<(), AbxError> {
        let header = self.cursor.take(4, "the 4-byte ABX header")?;
        if &header[..3] != b"ABX" {
            return Err(AbxError::NotAbx);
        }
        if header[3] != MAGIC[3] {
            return Err(AbxError::UnsupportedVersion { version: header[3] });
        }

        loop {
            let offset = self.cursor.pos;
            let token = self.cursor.u8("a token byte")?;
            let ty = token >> 4;
            let event = token & 0x0F;
            if !(TYPE_NULL..=TYPE_BOOLEAN_FALSE).contains(&ty) {
                return Err(AbxError::UnknownToken { offset, token });
            }

            if event != EVENT_ATTRIBUTE {
                self.account(std::mem::size_of::<AbxEvent>(), offset)?;
            }

            match event {
                EVENT_ATTRIBUTE => {
                    if !self.attributes_open {
                        return Err(AbxError::UnexpectedAttribute { offset });
                    }
                    // The name is always interned, whatever the value's type.
                    let name = self.interned_string()?;
                    if !is_xml_name(&name) {
                        return Err(AbxError::InvalidName { offset });
                    }
                    let value = self.value_payload(ty, offset, token)?;
                    self.account(std::mem::size_of::<AbxAttribute>(), offset)?;
                    if let Some(AbxEvent::StartTag { attributes, .. }) =
                        self.document.events.last_mut()
                    {
                        attributes.push(AbxAttribute { name, value });
                    }
                    // `attributes_open` stays true: more may follow.
                    continue;
                }
                EVENT_START_DOCUMENT => {
                    self.push(AbxEvent::StartDocument);
                }
                EVENT_END_DOCUMENT => {
                    self.push(AbxEvent::EndDocument);
                    return Ok(());
                }
                EVENT_START_TAG => {
                    let depth = self.depth.saturating_add(1);
                    if depth > MAX_DEPTH {
                        return Err(AbxError::NestingTooDeep { offset, depth });
                    }
                    let name = self.string_payload(ty, offset, token)?;
                    if !is_xml_name(&name) {
                        return Err(AbxError::InvalidName { offset });
                    }
                    self.depth = depth;
                    self.push(AbxEvent::StartTag {
                        name,
                        attributes: Vec::new(),
                    });
                    self.attributes_open = true;
                }
                EVENT_END_TAG => {
                    if self.depth == 0 {
                        return Err(AbxError::UnbalancedEndTag { offset });
                    }
                    let name = self.string_payload(ty, offset, token)?;
                    if !is_xml_name(&name) {
                        return Err(AbxError::InvalidName { offset });
                    }
                    self.depth -= 1;
                    self.push(AbxEvent::EndTag { name });
                }
                EVENT_TEXT => {
                    let s = self.string_payload(ty, offset, token)?;
                    self.push(AbxEvent::Text(s));
                }
                EVENT_CDSECT => {
                    let s = self.string_payload(ty, offset, token)?;
                    self.push(AbxEvent::Cdsect(s));
                }
                EVENT_ENTITY_REF => {
                    let s = self.string_payload(ty, offset, token)?;
                    self.push(AbxEvent::EntityRef(s));
                }
                EVENT_IGNORABLE_WHITESPACE => {
                    let s = self.string_payload(ty, offset, token)?;
                    self.push(AbxEvent::IgnorableWhitespace(s));
                }
                EVENT_PROCESSING_INSTRUCTION => {
                    let s = self.string_payload(ty, offset, token)?;
                    self.push(AbxEvent::ProcessingInstruction(s));
                }
                EVENT_COMMENT => {
                    let s = self.string_payload(ty, offset, token)?;
                    self.push(AbxEvent::Comment(s));
                }
                EVENT_DOCDECL => {
                    let s = self.string_payload(ty, offset, token)?;
                    self.push(AbxEvent::Docdecl(s));
                }
                _ => return Err(AbxError::UnknownToken { offset, token }),
            }
        }
    }

    /// Charge `n` bytes to the decoded document, stopping at the limit.
    fn account(&mut self, n: usize, offset: usize) -> Result<(), AbxError> {
        self.decoded_bytes = self.decoded_bytes.saturating_add(n);
        if self.decoded_bytes > MAX_DECODED_BYTES {
            return Err(AbxError::DecodedTooLarge {
                offset,
                limit: MAX_DECODED_BYTES,
            });
        }
        Ok(())
    }

    /// Append an event that is not an attribute; it closes the attribute
    /// window of any preceding start tag.
    fn push(&mut self, event: AbxEvent) {
        self.attributes_open = false;
        self.document.events.push(event);
    }

    /// A string payload of the given type: plain (`STRING`) or through the
    /// intern table (`STRING_INTERNED`). Tag names, attribute names and every
    /// text-like event arrive this way; the writer only ever uses these two
    /// types for them, so any other type is a malformed token.
    fn string_payload(&mut self, ty: u8, offset: usize, token: u8) -> Result<String, AbxError> {
        match ty {
            TYPE_STRING => self.plain_string("the length of a string"),
            TYPE_STRING_INTERNED => self.interned_string(),
            _ => Err(AbxError::UnknownToken { offset, token }),
        }
    }

    fn plain_string(&mut self, expected: &str) -> Result<String, AbxError> {
        let offset = self.cursor.pos;
        let raw = self.cursor.sized(expected)?;
        self.account(raw.len(), offset)?;
        let (s, lossy) = decode_modified_utf8(raw);
        if lossy {
            self.document.lossy_strings = self.document.lossy_strings.saturating_add(1);
        }
        Ok(s)
    }

    fn interned_string(&mut self) -> Result<String, AbxError> {
        let offset = self.cursor.pos;
        let index = self.cursor.u16("an interned-string index")?;
        if index == INTERN_NEW {
            let s = self.plain_string("the length of a new interned string")?;
            // The writer stops interning once the table is full and keeps
            // emitting the string inline, so a full table is not an error on
            // its own; it only becomes one if the reader would then be asked
            // to store a slot no index can name.
            if self.interned.len() < MAX_INTERNED_STRINGS {
                self.interned.push(s.clone());
            }
            return Ok(s);
        }
        let s = self
            .interned
            .get(usize::from(index))
            .ok_or(AbxError::InternIndexOutOfRange {
                offset,
                index,
                table_len: self.interned.len(),
            })?;
        // The reference is 3 bytes; the string it names may be 65,535.
        // Charge what the document will hold, not what the file spent.
        let len = s.len();
        self.account(len, offset)?;
        Ok(self.interned[usize::from(index)].clone())
    }

    /// An attribute's value, after its name, in the form its type says.
    fn value_payload(&mut self, ty: u8, offset: usize, token: u8) -> Result<AbxValue, AbxError> {
        Ok(match ty {
            TYPE_NULL => AbxValue::Null,
            TYPE_STRING => AbxValue::String(self.plain_string("the length of a string value")?),
            TYPE_STRING_INTERNED => AbxValue::String(self.interned_string()?),
            TYPE_BYTES_HEX => {
                AbxValue::BytesHex(self.cursor.sized("the length of a byte array")?.to_vec())
            }
            TYPE_BYTES_BASE64 => {
                AbxValue::BytesBase64(self.cursor.sized("the length of a byte array")?.to_vec())
            }
            TYPE_INT => AbxValue::Int(self.cursor.i32("a 4-byte int")?),
            TYPE_INT_HEX => AbxValue::IntHex(self.cursor.i32("a 4-byte int")?),
            TYPE_LONG => AbxValue::Long(self.cursor.i64("an 8-byte long")?),
            TYPE_LONG_HEX => AbxValue::LongHex(self.cursor.i64("an 8-byte long")?),
            TYPE_FLOAT => {
                AbxValue::Float(f32::from_bits(self.cursor.i32("a 4-byte float")? as u32))
            }
            TYPE_DOUBLE => {
                AbxValue::Double(f64::from_bits(self.cursor.i64("an 8-byte double")? as u64))
            }
            TYPE_BOOLEAN_TRUE => AbxValue::Bool(true),
            TYPE_BOOLEAN_FALSE => AbxValue::Bool(false),
            // The caller's range check already refused these; say so rather
            // than invent a value if that check ever moves.
            _ => return Err(AbxError::UnknownToken { offset, token }),
        })
    }
}

/// Decode Java modified UTF-8, the encoding `DataOutput::writeUTF` produces.
///
/// It differs from UTF-8 in two ways: `U+0000` is written as the overlong
/// pair `C0 80`, and characters outside the BMP are written as a CESU-8
/// surrogate pair of two 3-byte sequences. Both are decoded exactly. Anything
/// that is neither valid UTF-8 nor one of those two forms — a lone surrogate,
/// a stray continuation byte — becomes `U+FFFD`, and the second return value
/// says so.
fn decode_modified_utf8(bytes: &[u8]) -> (String, bool) {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return (s.to_owned(), false);
    }
    let mut out = String::with_capacity(bytes.len());
    let mut lossy = false;
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if b < 0x80 {
            out.push(b as char);
            i += 1;
            continue;
        }
        let cont = |k: usize| {
            bytes
                .get(i.wrapping_add(k))
                .filter(|c| **c & 0xC0 == 0x80)
                .map(|c| u32::from(*c & 0x3F))
        };
        if b & 0xE0 == 0xC0 {
            if let Some(c1) = cont(1) {
                let cp = (u32::from(b & 0x1F) << 6) | c1;
                // `C0 80` is Java's NUL; any other overlong form is invalid.
                if cp == 0 || cp >= 0x80 {
                    if let Some(ch) = char::from_u32(cp) {
                        out.push(ch);
                        i += 2;
                        continue;
                    }
                }
            }
        } else if b & 0xF0 == 0xE0 {
            if let (Some(c1), Some(c2)) = (cont(1), cont(2)) {
                let cp = (u32::from(b & 0x0F) << 12) | (c1 << 6) | c2;
                if (0xD800..=0xDBFF).contains(&cp) {
                    // A high surrogate: exact only if a low surrogate follows
                    // as its own 3-byte sequence.
                    let low = match (bytes.get(i.wrapping_add(3)), cont(4), cont(5)) {
                        (Some(0xED), Some(d1), Some(d2)) => {
                            let lo = (0xD000) | (d1 << 6) | d2;
                            (0xDC00..=0xDFFF).contains(&lo).then_some(lo)
                        }
                        _ => None,
                    };
                    if let Some(lo) = low {
                        let full = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        if let Some(ch) = char::from_u32(full) {
                            out.push(ch);
                            i += 6;
                            continue;
                        }
                    }
                    lossy = true;
                    out.push('\u{FFFD}');
                    i += 3;
                    continue;
                }
                if cp >= 0x800 {
                    if let Some(ch) = char::from_u32(cp) {
                        out.push(ch);
                        i += 3;
                        continue;
                    }
                    // A lone low surrogate lands here.
                    lossy = true;
                    out.push('\u{FFFD}');
                    i += 3;
                    continue;
                }
            }
        } else if b & 0xF8 == 0xF0 {
            // Not what Java writes, but a standard 4-byte sequence is still
            // one character and is kept as such.
            if let (Some(c1), Some(c2), Some(c3)) = (cont(1), cont(2), cont(3)) {
                let cp = (u32::from(b & 0x07) << 18) | (c1 << 12) | (c2 << 6) | c3;
                if (0x10000..=0x10FFFF).contains(&cp) {
                    if let Some(ch) = char::from_u32(cp) {
                        out.push(ch);
                        i += 4;
                        continue;
                    }
                }
            }
        }
        lossy = true;
        out.push('\u{FFFD}');
        i += 1;
    }
    (out, lossy)
}

/// Render a decoded document as ordinary XML text.
///
/// Attribute values and text are escaped; typed values take the form
/// [`AbxValue::to_text`] gives. Elements are always written as a start/end
/// pair, never self-closed, so an unclosed element from a truncated document
/// renders as far as it was read.
pub fn render_text_xml(document: &AbxDocument) -> String {
    let mut out = String::new();
    for event in &document.events {
        match event {
            AbxEvent::StartDocument | AbxEvent::EndDocument => {}
            AbxEvent::StartTag { name, attributes } => {
                out.push('<');
                out.push_str(name);
                for attribute in attributes {
                    out.push(' ');
                    out.push_str(&attribute.name);
                    out.push_str("=\"");
                    escape_into(&mut out, &attribute.value.to_text(), true);
                    out.push('"');
                }
                out.push('>');
            }
            AbxEvent::EndTag { name } => {
                out.push_str("</");
                out.push_str(name);
                out.push('>');
            }
            AbxEvent::Text(s) | AbxEvent::IgnorableWhitespace(s) => escape_into(&mut out, s, false),
            AbxEvent::Cdsect(s) => {
                out.push_str("<![CDATA[");
                out.push_str(s);
                out.push_str("]]>");
            }
            AbxEvent::EntityRef(s) => {
                out.push('&');
                out.push_str(s);
                out.push(';');
            }
            AbxEvent::ProcessingInstruction(s) => {
                out.push_str("<?");
                out.push_str(s);
                out.push_str("?>");
            }
            AbxEvent::Comment(s) => {
                out.push_str("<!--");
                out.push_str(s);
                out.push_str("-->");
            }
            AbxEvent::Docdecl(s) => {
                out.push_str("<!DOCTYPE");
                out.push_str(s);
                out.push('>');
            }
        }
    }
    out
}

/// Escape `s` for XML. Attribute values additionally escape both quote
/// characters, since the value is written inside double quotes and a text
/// parser must not be able to read a device-chosen string as markup.
fn escape_into(out: &mut String, s: &str, attribute: bool) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attribute => out.push_str("&quot;"),
            '\'' if attribute => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
}

/// Decode and render in one step. Fails on any decode error — use
/// [`decode`] and [`render_text_xml`] to keep the prefix of a broken document.
pub fn to_text_xml(bytes: &[u8]) -> Result<String, AbxError> {
    let decoded = decode(bytes);
    match decoded.error {
        Some(e) => Err(e),
        None => Ok(render_text_xml(&decoded.document)),
    }
}

/// A writer for building ABX fixtures in tests. Mirrors
/// `BinaryXmlSerializer` closely enough that a document it writes decodes to
/// the events that built it, including interned-string reuse.
#[cfg(any(test, feature = "test-support"))]
pub mod fixture {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    pub struct AbxWriter {
        out: Vec<u8>,
        interned: HashMap<String, u16>,
    }

    impl AbxWriter {
        /// A writer with the header and `START_DOCUMENT` already written.
        pub fn new() -> Self {
            let mut w = Self::default();
            w.out.extend_from_slice(MAGIC);
            w.token(TYPE_NULL, EVENT_START_DOCUMENT);
            w
        }

        /// A writer with only the header, for documents that must be shaped
        /// by hand.
        pub fn header_only() -> Self {
            let mut w = Self::default();
            w.out.extend_from_slice(MAGIC);
            w
        }

        pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
            self.out.extend_from_slice(bytes);
            self
        }

        fn token(&mut self, ty: u8, event: u8) {
            self.out.push((ty << 4) | event);
        }

        fn utf(&mut self, s: &[u8]) {
            let len = u16::try_from(s.len()).expect("fixture string fits a u16 length");
            self.out.extend_from_slice(&len.to_be_bytes());
            self.out.extend_from_slice(s);
        }

        fn interned(&mut self, s: &str) {
            if let Some(&index) = self.interned.get(s) {
                self.out.extend_from_slice(&index.to_be_bytes());
            } else {
                let index = u16::try_from(self.interned.len()).expect("fixture intern table fits");
                self.out.extend_from_slice(&INTERN_NEW.to_be_bytes());
                self.utf(s.as_bytes());
                self.interned.insert(s.to_owned(), index);
            }
        }

        pub fn start_tag(&mut self, name: &str) -> &mut Self {
            self.token(TYPE_STRING_INTERNED, EVENT_START_TAG);
            self.interned(name);
            self
        }

        pub fn end_tag(&mut self, name: &str) -> &mut Self {
            self.token(TYPE_STRING_INTERNED, EVENT_END_TAG);
            self.interned(name);
            self
        }

        pub fn end_document(&mut self) -> &mut Self {
            self.token(TYPE_NULL, EVENT_END_DOCUMENT);
            self
        }

        pub fn text(&mut self, s: &str) -> &mut Self {
            self.token(TYPE_STRING, EVENT_TEXT);
            self.utf(s.as_bytes());
            self
        }

        pub fn comment(&mut self, s: &str) -> &mut Self {
            self.token(TYPE_STRING, EVENT_COMMENT);
            self.utf(s.as_bytes());
            self
        }

        pub fn attr_null(&mut self, name: &str) -> &mut Self {
            self.token(TYPE_NULL, EVENT_ATTRIBUTE);
            self.interned(name);
            self
        }

        /// A plain string attribute, as `attribute()` writes: interned name,
        /// uninterned value.
        pub fn attr_str(&mut self, name: &str, value: &str) -> &mut Self {
            self.attr_str_bytes(name, value.as_bytes())
        }

        /// A string attribute whose value bytes are given raw, for strings
        /// that are not valid UTF-8.
        pub fn attr_str_bytes(&mut self, name: &str, value: &[u8]) -> &mut Self {
            self.token(TYPE_STRING, EVENT_ATTRIBUTE);
            self.interned(name);
            self.utf(value);
            self
        }

        /// An interned-string attribute, as `attributeInterned()` writes.
        pub fn attr_interned(&mut self, name: &str, value: &str) -> &mut Self {
            self.token(TYPE_STRING_INTERNED, EVENT_ATTRIBUTE);
            self.interned(name);
            self.interned(value);
            self
        }

        pub fn attr_bytes_hex(&mut self, name: &str, value: &[u8]) -> &mut Self {
            self.token(TYPE_BYTES_HEX, EVENT_ATTRIBUTE);
            self.interned(name);
            self.utf(value);
            self
        }

        pub fn attr_bytes_base64(&mut self, name: &str, value: &[u8]) -> &mut Self {
            self.token(TYPE_BYTES_BASE64, EVENT_ATTRIBUTE);
            self.interned(name);
            self.utf(value);
            self
        }

        pub fn attr_int(&mut self, name: &str, value: i32) -> &mut Self {
            self.token(TYPE_INT, EVENT_ATTRIBUTE);
            self.interned(name);
            self.out.extend_from_slice(&value.to_be_bytes());
            self
        }

        pub fn attr_int_hex(&mut self, name: &str, value: i32) -> &mut Self {
            self.token(TYPE_INT_HEX, EVENT_ATTRIBUTE);
            self.interned(name);
            self.out.extend_from_slice(&value.to_be_bytes());
            self
        }

        pub fn attr_long(&mut self, name: &str, value: i64) -> &mut Self {
            self.token(TYPE_LONG, EVENT_ATTRIBUTE);
            self.interned(name);
            self.out.extend_from_slice(&value.to_be_bytes());
            self
        }

        pub fn attr_long_hex(&mut self, name: &str, value: i64) -> &mut Self {
            self.token(TYPE_LONG_HEX, EVENT_ATTRIBUTE);
            self.interned(name);
            self.out.extend_from_slice(&value.to_be_bytes());
            self
        }

        pub fn attr_float(&mut self, name: &str, value: f32) -> &mut Self {
            self.token(TYPE_FLOAT, EVENT_ATTRIBUTE);
            self.interned(name);
            self.out.extend_from_slice(&value.to_be_bytes());
            self
        }

        pub fn attr_double(&mut self, name: &str, value: f64) -> &mut Self {
            self.token(TYPE_DOUBLE, EVENT_ATTRIBUTE);
            self.interned(name);
            self.out.extend_from_slice(&value.to_be_bytes());
            self
        }

        pub fn attr_bool(&mut self, name: &str, value: bool) -> &mut Self {
            let ty = if value {
                TYPE_BOOLEAN_TRUE
            } else {
                TYPE_BOOLEAN_FALSE
            };
            self.token(ty, EVENT_ATTRIBUTE);
            self.interned(name);
            self
        }

        pub fn finish(&self) -> Vec<u8> {
            self.out.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::AbxWriter;
    use super::*;

    /// The first 67 bytes of `/data/system/packages.xml` from Josh Hickman's
    /// Android 14 reference image, as they lie on disk.
    const HICKMAN_PREFIX: &[u8] = &[
        0x41, 0x42, 0x58, 0x00, 0x10, 0x32, 0xff, 0xff, 0x00, 0x08, 0x70, 0x61, 0x63, 0x6b, 0x61,
        0x67, 0x65, 0x73, 0x32, 0xff, 0xff, 0x00, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
        0x6f, 0xff, 0xff, 0x00, 0x0a, 0x73, 0x64, 0x6b, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
        0x00, 0x00, 0x00, 0x22, 0x6f, 0xff, 0xff, 0x00, 0x0f, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61,
        0x73, 0x65, 0x56, 0x65, 0x72, 0x73, 0x69,
    ];

    fn attr(name: &str, value: AbxValue) -> AbxAttribute {
        AbxAttribute {
            name: name.to_owned(),
            value,
        }
    }

    #[test]
    fn the_magic_is_recognised_and_text_xml_is_not() {
        assert!(is_abx(b"ABX\0\x10"));
        assert!(!is_abx(b"<?xml version=\"1.0\"?>"));
        assert!(!is_abx(b"ABX"), "three bytes are not a header");
        assert!(!is_abx(b""));
    }

    #[test]
    fn the_hickman_android_14_prefix_decodes_to_the_packages_and_version_tags() {
        let decoded = decode(HICKMAN_PREFIX);

        assert_eq!(
            decoded.document.events,
            vec![
                AbxEvent::StartDocument,
                AbxEvent::StartTag {
                    name: "packages".into(),
                    attributes: vec![],
                },
                AbxEvent::StartTag {
                    name: "version".into(),
                    attributes: vec![attr("sdkVersion", AbxValue::Int(34))],
                },
            ]
        );
        // The prefix ends 13 bytes into the 15-byte name "databaseVersion",
        // which begins at byte 54. The error must say so, not just "short".
        assert_eq!(
            decoded.error,
            Some(AbxError::Truncated {
                offset: 54,
                expected: "15 bytes of string".into(),
                present: 13,
            })
        );
        assert_eq!(decoded.bytes_consumed, 54);

        let text = render_text_xml(&decoded.document);
        assert_eq!(text, r#"<packages><version sdkVersion="34">"#);
        assert!(
            to_text_xml(HICKMAN_PREFIX).is_err(),
            "the one-shot renderer must not hand back a prefix as the document"
        );
    }

    #[test]
    fn every_value_type_round_trips_and_renders_as_androids_text_writer_would() {
        let bytes = AbxWriter::new()
            .start_tag("package")
            .attr_null("nothing")
            .attr_str("name", "com.example.app")
            .attr_interned("kind", "system")
            .attr_bytes_hex("cert", &[0xde, 0xad, 0xbe, 0xef])
            .attr_bytes_base64("blob", b"hello")
            .attr_int("userId", -10123)
            .attr_int_hex("flags", 0x4000_8000_u32 as i32)
            .attr_long("version", 242_001_123_456)
            .attr_long_hex("it", 0x018D_46E9_F2F8)
            .attr_float("ratio", 1.5)
            .attr_double("weight", 2.25)
            .attr_bool("enabled", true)
            .attr_bool("hidden", false)
            .text("a < b & c")
            .comment("note")
            .end_tag("package")
            .end_document()
            .finish();

        let decoded = decode(&bytes);
        assert_eq!(decoded.error, None);
        assert_eq!(decoded.bytes_consumed, bytes.len());
        assert_eq!(decoded.document.lossy_strings, 0);

        let AbxEvent::StartTag { name, attributes } = &decoded.document.events[1] else {
            panic!("second event is the start tag");
        };
        assert_eq!(name, "package");
        assert_eq!(
            attributes,
            &[
                attr("nothing", AbxValue::Null),
                attr("name", AbxValue::String("com.example.app".into())),
                attr("kind", AbxValue::String("system".into())),
                attr("cert", AbxValue::BytesHex(vec![0xde, 0xad, 0xbe, 0xef])),
                attr("blob", AbxValue::BytesBase64(b"hello".to_vec())),
                attr("userId", AbxValue::Int(-10123)),
                attr("flags", AbxValue::IntHex(0x4000_8000_u32 as i32)),
                attr("version", AbxValue::Long(242_001_123_456)),
                attr("it", AbxValue::LongHex(0x018D_46E9_F2F8)),
                attr("ratio", AbxValue::Float(1.5)),
                attr("weight", AbxValue::Double(2.25)),
                attr("enabled", AbxValue::Bool(true)),
                attr("hidden", AbxValue::Bool(false)),
            ]
        );
        assert_eq!(
            decoded.document.events[2],
            AbxEvent::Text("a < b & c".into())
        );
        assert_eq!(decoded.document.events[3], AbxEvent::Comment("note".into()));

        let text = render_text_xml(&decoded.document);
        assert_eq!(
            text,
            concat!(
                r#"<package nothing="" name="com.example.app" kind="system" cert="DEADBEEF" "#,
                r#"blob="aGVsbG8=" userId="-10123" flags="40008000" version="242001123456" "#,
                r#"it="18d46e9f2f8" ratio="1.5" weight="2.25" enabled="true" hidden="false">"#,
                "a &lt; b &amp; c<!--note--></package>"
            )
        );
    }

    #[test]
    fn a_second_reference_to_an_interned_string_is_resolved_by_index() {
        // "package" is interned by the first start tag (index 0) and "name" by
        // its attribute (index 1); the second package refers to both by index.
        let bytes = AbxWriter::new()
            .start_tag("packages")
            .start_tag("package")
            .attr_str("name", "com.a")
            .end_tag("package")
            .start_tag("package")
            .attr_str("name", "com.b")
            .end_tag("package")
            .end_tag("packages")
            .end_document()
            .finish();
        // Prove the fixture actually reuses an index rather than re-defining
        // the string: "package" appears in the bytes exactly once.
        assert_eq!(
            bytes.windows(7).filter(|w| *w == b"package").count(),
            2,
            "\"packages\" and \"package\" once each; no repeated definitions"
        );

        let text = to_text_xml(&bytes).expect("a complete document");
        assert_eq!(
            text,
            r#"<packages><package name="com.a"></package><package name="com.b"></package></packages>"#
        );
    }

    #[test]
    fn attribute_values_and_text_are_escaped_in_the_rendered_xml() {
        let bytes = AbxWriter::new()
            .start_tag("p")
            .attr_str("v", r#"a"b<c>d&e'f"#)
            .text("x<y>&\"'")
            .end_tag("p")
            .end_document()
            .finish();
        assert_eq!(
            to_text_xml(&bytes).unwrap(),
            r#"<p v="a&quot;b&lt;c&gt;d&amp;e&apos;f">x&lt;y&gt;&amp;"'</p>"#
        );
    }

    #[test]
    fn a_lone_surrogate_is_decoded_lossily_and_counted() {
        // CESU-8 / modified UTF-8 encodes U+D800 as ED A0 80. Standard UTF-8
        // forbids it, and a Java writer will emit it for a malformed string.
        let bytes = AbxWriter::new()
            .start_tag("p")
            .attr_str_bytes("name", b"com.\xed\xa0\x80x")
            .end_tag("p")
            .end_document()
            .finish();
        let decoded = decode(&bytes);
        assert_eq!(decoded.error, None);
        assert_eq!(decoded.document.lossy_strings, 1);
        let AbxEvent::StartTag { attributes, .. } = &decoded.document.events[1] else {
            panic!("start tag");
        };
        assert_eq!(
            attributes[0].value,
            AbxValue::String("com.\u{FFFD}x".into()),
            "the bytes that could not be a character are a replacement, and the rest survive"
        );
    }

    #[test]
    fn javas_two_byte_nul_and_surrogate_pairs_are_decoded_exactly() {
        // Modified UTF-8 writes U+0000 as C0 80 and U+1F600 as a CESU-8
        // surrogate pair. Neither is valid UTF-8; both are exact, not lossy.
        let bytes = AbxWriter::new()
            .start_tag("p")
            .attr_str_bytes("v", b"a\xc0\x80b\xed\xa0\xbd\xed\xb8\x80")
            .end_tag("p")
            .end_document()
            .finish();
        let decoded = decode(&bytes);
        assert_eq!(decoded.error, None);
        assert_eq!(decoded.document.lossy_strings, 0);
        let AbxEvent::StartTag { attributes, .. } = &decoded.document.events[1] else {
            panic!("start tag");
        };
        assert_eq!(
            attributes[0].value,
            AbxValue::String("a\0b\u{1F600}".into())
        );
    }

    #[test]
    fn truncation_at_every_byte_offset_never_panics_and_names_the_offset() {
        let bytes = AbxWriter::new()
            .start_tag("packages")
            .start_tag("package")
            .attr_str("name", "com.a")
            .attr_long_hex("it", 0x018D_46E9_F2F8)
            .attr_bool("enabled", true)
            .attr_bytes_hex("cert", &[1, 2, 3])
            .text("t")
            .end_tag("package")
            .start_tag("package")
            .attr_str("name", "com.b")
            .end_tag("package")
            .end_tag("packages")
            .end_document()
            .finish();
        assert_eq!(decode(&bytes).error, None, "the whole fixture is valid");

        for cut in 0..bytes.len() {
            let decoded = decode(&bytes[..cut]);
            let error = decoded
                .error
                .unwrap_or_else(|| panic!("a document cut at byte {cut} must not decode clean"));
            match error {
                AbxError::Truncated { offset, .. } => {
                    assert!(
                        offset <= cut,
                        "cut at {cut}: the offset named ({offset}) must lie within the bytes given"
                    );
                }
                other => panic!("cut at {cut}: expected a truncation, got {other:?}"),
            }
            assert!(
                decoded.bytes_consumed <= cut,
                "cut at {cut}: consumed {} bytes of {cut}",
                decoded.bytes_consumed
            );
            // Nothing decoded before the cut may be lost.
            let prefix_text = render_text_xml(&decoded.document);
            assert!(prefix_text.len() <= render_text_xml(&decode(&bytes).document).len());
        }
    }

    #[test]
    fn a_document_that_stops_before_end_document_is_truncated_not_complete() {
        let bytes = AbxWriter::new()
            .start_tag("packages")
            .end_tag("packages")
            .finish();
        let decoded = decode(&bytes);
        assert_eq!(
            decoded.error,
            Some(AbxError::Truncated {
                offset: bytes.len(),
                expected: "a token byte".into(),
                present: 0,
            })
        );
        assert_eq!(decoded.document.events.len(), 3);
    }

    #[test]
    fn nesting_past_the_bound_is_refused_by_name() {
        let mut w = AbxWriter::new();
        for _ in 0..=MAX_DEPTH {
            w.start_tag("d");
        }
        let bytes = w.finish();
        let decoded = decode(&bytes);
        match decoded.error {
            Some(AbxError::NestingTooDeep { depth, offset }) => {
                assert_eq!(depth, MAX_DEPTH + 1);
                assert!(offset < bytes.len());
            }
            other => panic!("expected NestingTooDeep, got {other:?}"),
        }
        assert_eq!(
            decoded.document.events.len(),
            MAX_DEPTH + 1,
            "START_DOCUMENT plus every tag up to the bound is kept"
        );
    }

    #[test]
    fn an_intern_index_past_the_table_is_an_error_not_a_panic() {
        // START_TAG | STRING_INTERNED, index 7 — but no string has been
        // interned yet.
        let bytes = AbxWriter::new()
            .raw(&[(TYPE_STRING_INTERNED << 4) | EVENT_START_TAG, 0x00, 0x07])
            .finish();
        let decoded = decode(&bytes);
        assert_eq!(
            decoded.error,
            Some(AbxError::InternIndexOutOfRange {
                offset: 6,
                index: 7,
                table_len: 0,
            })
        );
    }

    #[test]
    fn a_token_naming_no_event_or_type_is_refused_at_its_offset() {
        // Type nibble 0 is not a type; event nibble 11 is not an event.
        for token in [0x02u8, 0x2b, 0xe2, 0xf2] {
            let bytes = AbxWriter::new().raw(&[token]).finish();
            let decoded = decode(&bytes);
            assert_eq!(
                decoded.error,
                Some(AbxError::UnknownToken { offset: 5, token }),
                "token {token:#04x}"
            );
        }
    }

    #[test]
    fn an_attribute_outside_a_start_tag_is_refused() {
        let bytes = AbxWriter::new()
            .start_tag("p")
            .text("x")
            .attr_int("late", 1)
            .finish();
        let decoded = decode(&bytes);
        assert!(
            matches!(decoded.error, Some(AbxError::UnexpectedAttribute { .. })),
            "{:?}",
            decoded.error
        );
    }

    #[test]
    fn an_end_tag_with_nothing_open_is_refused() {
        let bytes = AbxWriter::new().end_tag("p").finish();
        let decoded = decode(&bytes);
        assert!(
            matches!(
                decoded.error,
                Some(AbxError::UnbalancedEndTag { offset: 5 })
            ),
            "{:?}",
            decoded.error
        );
    }

    #[test]
    fn a_wrong_magic_or_unknown_version_is_refused_by_name() {
        assert_eq!(decode(b"<xml").error, Some(AbxError::NotAbx));
        assert_eq!(
            decode(b"ABX\x01\x10").error,
            Some(AbxError::UnsupportedVersion { version: 1 })
        );
        assert_eq!(
            decode(b"AB").error,
            Some(AbxError::Truncated {
                offset: 0,
                expected: "the 4-byte ABX header".into(),
                present: 2,
            })
        );
    }

    /// The wire values of every type nibble, written by hand from AOSP's
    /// `BinaryXmlSerializer.java` (`TYPE_NULL = 1 << 4` … `TYPE_BOOLEAN_FALSE
    /// = 13 << 4`; `ATTRIBUTE = 15`), so the decoder is checked against the
    /// format and not against the in-crate writer that shares its constants.
    /// A swapped pair of same-width constants — LONG_HEX and DOUBLE, say —
    /// round-trips through `AbxWriter` unnoticed and would render every
    /// install time on a real device as a garbage double.
    #[test]
    fn every_type_nibble_matches_the_aosp_serializer_by_literal_bytes() {
        // Interned attribute name `v`: marker 0xffff, u16 length, bytes.
        const NAME: [u8; 5] = [0xff, 0xff, 0x00, 0x01, b'v'];
        let mut bytes: Vec<u8> = vec![
            0x41, 0x42, 0x58, 0x00, // magic, version 0
            0x10, // START_DOCUMENT (0) | TYPE_NULL (1 << 4)
            0x32, 0xff, 0xff, 0x00, 0x01, b'a', // START_TAG | STRING_INTERNED, "a"
        ];
        // (token, payload) per AOSP: token = ATTRIBUTE (15) | (type << 4).
        let attrs: Vec<(u8, Vec<u8>)> = vec![
            (0x1f, vec![]),                                         // NULL
            (0x2f, vec![0x00, 0x02, b'h', b'i']),                   // STRING
            (0x3f, vec![0xff, 0xff, 0x00, 0x02, b'o', b'k']),       // STRING_INTERNED
            (0x4f, vec![0x00, 0x02, 0xde, 0xad]),                   // BYTES_HEX
            (0x5f, vec![0x00, 0x01, 0xff]),                         // BYTES_BASE64
            (0x6f, vec![0x00, 0x00, 0x00, 0x2a]),                   // INT 42
            (0x7f, vec![0x00, 0x00, 0x00, 0xff]),                   // INT_HEX 0xff
            (0x8f, vec![0, 0, 0, 0, 0, 0, 0x01, 0x00]),             // LONG 256
            (0x9f, vec![0, 0, 0x01, 0x91, 0x0e, 0x5f, 0x57, 0x0c]), // LONG_HEX 0x1910e5f570c
            (0xaf, 1.5f32.to_be_bytes().to_vec()),                  // FLOAT
            (0xbf, 2.25f64.to_be_bytes().to_vec()),                 // DOUBLE
            (0xcf, vec![]),                                         // BOOLEAN_TRUE
            (0xdf, vec![]),                                         // BOOLEAN_FALSE
        ];
        for (token, payload) in &attrs {
            bytes.push(*token);
            bytes.extend_from_slice(&NAME);
            bytes.extend_from_slice(payload);
        }
        bytes.extend_from_slice(&[0x33, 0xff, 0xff, 0x00, 0x01, b'a']); // END_TAG, "a"
        bytes.push(0x11); // END_DOCUMENT | TYPE_NULL

        let decoded = decode(&bytes);
        assert_eq!(decoded.error, None, "{:?}", decoded.error);
        let AbxEvent::StartTag { name, attributes } = &decoded.document.events[1] else {
            panic!(
                "second event is the start tag: {:?}",
                decoded.document.events
            );
        };
        assert_eq!(name, "a");
        let values: Vec<&AbxValue> = attributes.iter().map(|a| &a.value).collect();
        assert_eq!(
            values,
            vec![
                &AbxValue::Null,
                &AbxValue::String("hi".into()),
                &AbxValue::String("ok".into()),
                &AbxValue::BytesHex(vec![0xde, 0xad]),
                &AbxValue::BytesBase64(vec![0xff]),
                &AbxValue::Int(42),
                &AbxValue::IntHex(0xff),
                &AbxValue::Long(256),
                &AbxValue::LongHex(0x1910e5f570c),
                &AbxValue::Float(1.5),
                &AbxValue::Double(2.25),
                &AbxValue::Bool(true),
                &AbxValue::Bool(false),
            ]
        );
        // The load-bearing one: a first-install time renders as bare hex.
        assert_eq!(attributes[8].value.to_text(), "1910e5f570c");
    }

    // -- review findings on the first cut (format lens) -------------------

    /// A 3-byte interned reference expands to up to 65,535 bytes of string;
    /// unbounded, a few-megabyte file decodes to tens of gigabytes and the
    /// ingest dies before any record says why. The decoder stops at a named
    /// limit instead.
    #[test]
    fn interned_string_amplification_is_refused_at_a_named_limit() {
        let mut bytes = vec![
            0x41, 0x42, 0x58, 0x00, 0x10, 0x32, 0xff, 0xff, 0x00, 0x01, b'a',
        ];
        // One 65,535-byte interned comment, then references to it.
        bytes.extend_from_slice(&[0x39, 0xff, 0xff, 0xff, 0xff]);
        bytes.extend(std::iter::repeat_n(b'x', 0xffff));
        let refs = MAX_DECODED_BYTES / 0xffff + 2;
        for _ in 0..refs {
            // Index 1: the tag name "a" took slot 0.
            bytes.extend_from_slice(&[0x39, 0x00, 0x01]);
        }
        bytes.extend_from_slice(&[0x33, 0x00, 0x00, 0x11]);

        let decoded = decode(&bytes);
        let Some(AbxError::DecodedTooLarge { offset, limit }) = decoded.error else {
            panic!("expected DecodedTooLarge, got {:?}", decoded.error);
        };
        assert_eq!(limit, MAX_DECODED_BYTES);
        assert!(offset > 0xffff && offset < bytes.len());
        assert!(!decoded.error.as_ref().unwrap().is_truncation());
        // Whatever was decoded before the stop stays bounded by the limit
        // plus one string: the document did not balloon first.
        let held: usize = decoded
            .document
            .events
            .iter()
            .map(|e| match e {
                AbxEvent::Comment(s) => s.len(),
                _ => 0,
            })
            .sum();
        assert!(held <= MAX_DECODED_BYTES + 0xffff, "{held}");
        let msg = decoded.error.unwrap().to_string();
        assert!(msg.contains("decoded"), "{msg}");
    }

    /// Android's text writer renders `*_HEX` with `Long.toString(v, 16)`,
    /// which is signed: `-1` is "-1", not "ffffffffffffffff".
    #[test]
    fn negative_hex_values_render_signed_as_androids_text_writer_does() {
        assert_eq!(AbxValue::IntHex(-1).to_text(), "-1");
        assert_eq!(AbxValue::IntHex(i32::MIN).to_text(), "-80000000");
        assert_eq!(AbxValue::IntHex(0xff).to_text(), "ff");
        assert_eq!(AbxValue::LongHex(-1).to_text(), "-1");
        assert_eq!(AbxValue::LongHex(i64::MIN).to_text(), "-8000000000000000");
        assert_eq!(AbxValue::LongHex(0x1910e5f570c).to_text(), "1910e5f570c");
    }

    /// `Float.toString` / `Double.toString`: at least one fractional digit,
    /// scientific notation outside [1e-3, 1e7), `Infinity` and `NaN`.
    #[test]
    fn floats_render_as_javas_to_string_would() {
        assert_eq!(AbxValue::Float(1.0).to_text(), "1.0");
        assert_eq!(AbxValue::Float(1.5).to_text(), "1.5");
        assert_eq!(AbxValue::Float(0.001).to_text(), "0.001");
        assert_eq!(AbxValue::Float(1.0e7).to_text(), "1.0E7");
        assert_eq!(AbxValue::Float(1.0e-4).to_text(), "1.0E-4");
        assert_eq!(AbxValue::Float(-2.5e10).to_text(), "-2.5E10");
        assert_eq!(AbxValue::Float(f32::INFINITY).to_text(), "Infinity");
        assert_eq!(AbxValue::Float(f32::NEG_INFINITY).to_text(), "-Infinity");
        assert_eq!(AbxValue::Float(f32::NAN).to_text(), "NaN");
        assert_eq!(AbxValue::Double(1.0).to_text(), "1.0");
        assert_eq!(AbxValue::Double(2.25).to_text(), "2.25");
        assert_eq!(AbxValue::Double(1.0e300).to_text(), "1.0E300");
        assert_eq!(AbxValue::Double(123456789.0).to_text(), "1.23456789E8");
        assert_eq!(AbxValue::Double(0.0).to_text(), "0.0");
        assert_eq!(AbxValue::Double(-0.0).to_text(), "-0.0");
    }

    /// A tag or attribute name is rendered bare into the text form. A name
    /// carrying markup would put attributes into the text that the decoded
    /// events do not hold, so a name that is not an XML Name is refused at
    /// its offset rather than rendered.
    #[test]
    fn a_name_that_is_not_an_xml_name_is_refused_not_rendered() {
        let evil = br#"package name="com.evil""#;
        let mut bytes = vec![
            0x41,
            0x42,
            0x58,
            0x00,
            0x10,
            0x32,
            0xff,
            0xff,
            0x00,
            evil.len() as u8,
        ];
        bytes.extend_from_slice(evil);
        bytes.extend_from_slice(&[0x33, 0xff, 0xff, 0x00, 0x07]);
        bytes.extend_from_slice(b"package");
        bytes.push(0x11);
        let decoded = decode(&bytes);
        assert_eq!(decoded.error, Some(AbxError::InvalidName { offset: 5 }));
        assert_eq!(decoded.document.events, vec![AbxEvent::StartDocument]);
        assert!(!render_text_xml(&decoded.document).contains("com.evil"));

        // An attribute name too.
        let bytes = [
            0x41, 0x42, 0x58, 0x00, 0x10, 0x32, 0xff, 0xff, 0x00, 0x01, b'a', 0xcf, 0xff, 0xff,
            0x00, 0x03, b'x', b'>', b'y', 0x33, 0x00, 0x00, 0x11,
        ];
        let decoded = decode(&bytes);
        assert_eq!(decoded.error, Some(AbxError::InvalidName { offset: 11 }));

        // Names Android actually writes — with digits, dots, dashes, colons,
        // underscores and non-ASCII letters — are fine.
        for name in ["package", "sdk-version", "a.b_c:d1", "élément"] {
            assert!(is_xml_name(name), "{name}");
        }
        for name in ["", "1abc", "a b", "a<b", "a=b", "a/b", "a\"b", "a&b", "-a"] {
            assert!(!is_xml_name(name), "{name}");
        }
    }

    /// The offset a truncation names is where the unfinished item begins;
    /// the message must say how far into it the bytes ran, or a hex view
    /// lands on the wrong byte.
    #[test]
    fn a_truncation_message_names_where_the_bytes_ran_out() {
        let decoded = decode(HICKMAN_PREFIX);
        let err = decoded.error.unwrap();
        assert_eq!(
            err,
            AbxError::Truncated {
                offset: 54,
                expected: "15 bytes of string".into(),
                present: 13,
            }
        );
        let msg = err.to_string();
        assert!(msg.contains("byte 67"), "{msg}");
        assert!(msg.contains("13 bytes into"), "{msg}");
        assert!(msg.contains("begins at byte 54"), "{msg}");

        let clean_end = AbxError::Truncated {
            offset: 10,
            expected: "a token byte".into(),
            present: 0,
        }
        .to_string();
        assert!(clean_end.contains("ends at byte 10"), "{clean_end}");
    }
}
