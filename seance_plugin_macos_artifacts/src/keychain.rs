//! Apple keychains — `login.keychain-db`, `System.keychain`, `*.keychain`.
//!
//! The classic `kych` keychain (the CDSA/`securityd` database, which macOS 11
//! still uses for the login and system keychains) is an **encrypted store with
//! a cleartext index**, and that distinction is the whole of this reader's
//! value. Each item's secret is wrapped under the database's master key. Each
//! item's *attributes* are not: the service, the account, the label, the
//! description, the comment and the creation and modification dates sit in the
//! file in plain text.
//!
//! So a keychain nobody can open still answers **"which services and accounts
//! did this person hold credentials for, and since when"** — which on the
//! reference image is an Apple ID (`e.flatt610@gmail.com`), an Apple account
//! number, an iOS backup, a stored AirPort network password, and eighteen
//! system and application identities, none of which needed a password to read.
//!
//! # The schema is read from the file, not hard-coded
//!
//! A keychain carries its own relational schema in its first tables:
//! `CSSM_DL_DB_SCHEMA_INFO` names every relation, and
//! `CSSM_DL_DB_SCHEMA_ATTRIBUTES` declares every attribute of every relation
//! with its storage format. This reader reads both and decodes each record's
//! attributes **by the file's own declaration**, so a keychain from another OS
//! version with a different attribute set is read rather than mis-read.
//!
//! That is not a stylistic preference. The two reference keychains disagree
//! with each other — eleven relations against twelve, sixteen attributes on the
//! generic-password relation against sixteen but ninety indexes against eighty
//! — and a hard-coded table for one silently mis-attributes the other. It also
//! caught a fact worth having: the `CSSM_DL_DB_SCHEMA_*` relation ids are **1 =
//! ATTRIBUTES and 2 = INDEXES**, which is the reverse of the order the tables
//! appear in, and reading the declaration meant never having to guess.
//!
//! # Where the layout comes from
//!
//! Derived from the two real keychains in the Magnet 2021 macOS image and
//! corroborated by the file's own arithmetic at every step:
//!
//! * the header's `schemaOffset` plus the schema's `schemaSize` lands at the
//!   end of the file;
//! * each table's `recordCount` equals the number of slots in its
//!   record-number array that hold a live record — the test that separates a
//!   live offset from a free-list link, which is what a wrong rule here would
//!   get wrong while still producing plausible records;
//! * every attribute offset resolves inside its own record, and the attribute
//!   data begins exactly where the item's encrypted payload ends
//!   (`24 + 4 × attributes + dataSize`), so there is no slack for a different
//!   header;
//! * and every one of the 23 live generic-password records in
//!   `login.keychain-db`, and all 4 in `System.keychain`, decodes to legible
//!   text with legible ISO dates.
//!
//! # What it will not do
//!
//! **No secret is decrypted and none is guessed.** An item's payload is
//! reported as `locked`, with the reason and with what a lawful recovery
//! attempt needs: the `DbBlob`'s salt and initialisation vector, the iteration
//! count the format fixes, and where in the file the wrapped master key sits.
//! Decryption needs a password or `/var/db/SystemKey`, neither of which this
//! reader is handed, and it is `ROADMAP` §3.1's remaining half.
//!
//! A certificate's data is **not** encrypted, so it is carried out whole as its
//! own artifact and can be hashed, identified and exported like any other file.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use tracing::debug;

use crate::keychain_unlock::{DbBlobCrypto, UnlockError};
use crate::{basename_lower, stamp_incomplete, Staged};

/// Largest keychain this reader stages. The two reference keychains are 37 KB
/// and 81 KB; a login keychain on a long-lived machine reaches single-digit
/// megabytes.
const MAX_KEYCHAIN_BYTES: u64 = 64 * 1024 * 1024;
/// Largest number of relations read from one file's schema.
const MAX_RELATIONS: usize = 256;
/// Largest number of records read from one relation.
const MAX_RECORDS_PER_RELATION: usize = 100_000;
/// Largest number of attributes one relation may declare. The reference
/// keychains declare at most 27.
const MAX_ATTRIBUTES: usize = 256;
/// Longest attribute value rendered. Beyond this the value is reported as its
/// length rather than truncated silently.
const MAX_VALUE_BYTES: usize = 8192;
/// Largest certificate or other plaintext payload carried out as its own
/// artifact.
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// `kych`, at offset 0 of every keychain of this generation.
const KEYCHAIN_MAGIC: &[u8; 4] = b"kych";
/// The only version either reference keychain carries, and the one macOS 11
/// writes.
const KEYCHAIN_VERSION: u32 = 0x0001_0000;
/// Bytes of fixed header before the schema offset can be read.
const HEADER_BYTES: usize = 20;
/// Fixed part of a record before its attribute-offset array.
const RECORD_HEADER_BYTES: usize = 24;

/// `0xFADE0711` — the magic on the `DbBlob` that holds the wrapped master key.
const DB_BLOB_MAGIC: u32 = 0xfade_0711;
/// Offset of the 20-byte PBKDF2 salt within the `DbBlob`.
const DB_BLOB_SALT_AT: usize = 44;
/// Offset of the 8-byte initialisation vector within the `DbBlob`.
const DB_BLOB_IV_AT: usize = 64;
/// PBKDF2 iteration count the format fixes. Not read from the file because the
/// file does not carry it; stated so a recovery attempt does not have to guess.
const DB_BLOB_PBKDF2_ITERATIONS: u32 = 1000;

/// `ssgp` — the tag on a *password* item's payload, wrapped under the master
/// key. Its presence is what makes "this secret is locked" an observation
/// rather than an assumption.
const SSGP_TAG: &[u8; 4] = b"ssgp";

/// How an item's payload is protected, read from the payload's own first four
/// bytes.
///
/// Three forms occur, and they are told apart rather than assumed from the
/// relation: a password's payload is tagged `ssgp`, a key's is a `KeyBlob`
/// carrying the same `0xFADE0711` magic the `DbBlob` does, and a certificate's
/// is raw DER with no wrapper at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wrapping {
    /// Secure Storage Group Password: a password item's wrapped secret.
    Ssgp,
    /// A wrapped key blob.
    KeyBlob,
    /// No wrapper. Correct for a certificate; a finding on anything else.
    None,
}

impl Wrapping {
    fn of(payload: &[u8]) -> Self {
        if payload.starts_with(SSGP_TAG) {
            return Wrapping::Ssgp;
        }
        if payload.len() >= 4
            && u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) == DB_BLOB_MAGIC
        {
            return Wrapping::KeyBlob;
        }
        Wrapping::None
    }

    fn is_wrapped(self) -> bool {
        !matches!(self, Wrapping::None)
    }

    /// Stable label emitted as `secret_wrapping`.
    fn as_str(self) -> &'static str {
        match self {
            Wrapping::Ssgp => "ssgp_master_key",
            Wrapping::KeyBlob => "key_blob_master_key",
            Wrapping::None => "none",
        }
    }
}

// --- CSSM relation identifiers ----------------------------------------------

/// `CSSM_DL_DB_SCHEMA_INFO` — the relation that names every relation. Zero in
/// every keychain, and the only id this reader assumes, because it is the one
/// that has to be read before the file can say anything about itself.
const RELATION_SCHEMA_INFO: u32 = 0;

/// The relation names this reader recognises, and the kind of item each holds.
///
/// A relation the file declares that is not here is still read and its records
/// still emitted, under its declared name — the attribute decode does not
/// depend on knowing what the relation means.
fn relation_kind(id: u32) -> Option<ItemKind> {
    match id {
        0x8000_0000 => Some(ItemKind::GenericPassword),
        0x8000_0001 => Some(ItemKind::InternetPassword),
        0x8000_0002 => Some(ItemKind::AppleSharePassword),
        0x8000_1000 => Some(ItemKind::Certificate),
        0x0000_000f => Some(ItemKind::PublicKey),
        0x0000_0010 => Some(ItemKind::PrivateKey),
        0x0000_0011 => Some(ItemKind::SymmetricKey),
        _ => None,
    }
}

/// What a relation's records are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    /// An application or service password.
    GenericPassword,
    /// A password for a network service, carrying the server, protocol, path
    /// and port it was stored for.
    InternetPassword,
    /// A legacy AFP share password.
    AppleSharePassword,
    /// An X.509 certificate. Its data is **not** encrypted.
    Certificate,
    PublicKey,
    PrivateKey,
    SymmetricKey,
}

impl ItemKind {
    /// Stable label emitted on every record.
    pub fn as_str(self) -> &'static str {
        match self {
            ItemKind::GenericPassword => "generic_password",
            ItemKind::InternetPassword => "internet_password",
            ItemKind::AppleSharePassword => "appleshare_password",
            ItemKind::Certificate => "certificate",
            ItemKind::PublicKey => "public_key",
            ItemKind::PrivateKey => "private_key",
            ItemKind::SymmetricKey => "symmetric_key",
        }
    }

    /// True where this kind of item's payload is expected to be wrapped.
    ///
    /// A certificate's is not — a certificate is public by construction, it is
    /// stored as raw DER, and reporting it as locked would hide evidence
    /// sitting in the clear. A **public key's is**: the keychain wraps key
    /// material of every class, so a public key found unwrapped is unexpected
    /// and worth saying so about.
    fn payload_is_secret(self) -> bool {
        !matches!(self, ItemKind::Certificate)
    }
}

/// Storage format of an attribute, as `CSSM_DB_ATTRIBUTE_FORMAT` numbers them.
///
/// The format is read from the file's own schema, so a value is never decoded
/// as a type the file did not declare it to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttrFormat {
    String,
    SInt32,
    UInt32,
    BigNum,
    Real,
    /// A 16-byte `YYYYMMDDhhmmssZ` string, stored raw rather than
    /// length-prefixed — the one format in this file that is not.
    TimeDate,
    Blob,
    MultiUInt32,
    Complex,
    /// A number the file declared that `CSSM_DB_ATTRIBUTE_FORMAT` does not
    /// define. The value's bytes are reported; no type is assumed for them.
    Unknown(u32),
}

impl AttrFormat {
    fn from_raw(raw: u32) -> Self {
        match raw {
            0 => AttrFormat::String,
            1 => AttrFormat::SInt32,
            2 => AttrFormat::UInt32,
            3 => AttrFormat::BigNum,
            4 => AttrFormat::Real,
            5 => AttrFormat::TimeDate,
            6 => AttrFormat::Blob,
            7 => AttrFormat::MultiUInt32,
            8 => AttrFormat::Complex,
            other => AttrFormat::Unknown(other),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            AttrFormat::String => "string",
            AttrFormat::SInt32 => "sint32",
            AttrFormat::UInt32 => "uint32",
            AttrFormat::BigNum => "big_num",
            AttrFormat::Real => "real",
            AttrFormat::TimeDate => "time_date",
            AttrFormat::Blob => "blob",
            AttrFormat::MultiUInt32 => "multi_uint32",
            AttrFormat::Complex => "complex",
            AttrFormat::Unknown(_) => "unknown",
        }
    }
}

/// One attribute a relation declares.
#[derive(Debug, Clone)]
struct AttrDecl {
    /// The attribute's identifier. On the key relations these are ordinals; on
    /// the password relations they are four-character codes.
    id: u32,
    /// The name the schema gives it, when it gives one. The password relations
    /// name their attributes by code rather than by string, so this is
    /// commonly absent and [`AttrDecl::label`] falls back to the code.
    name: Option<String>,
    format: AttrFormat,
}

/// Four-character codes the password and key relations use for attribute
/// names, and the plain words for them.
///
/// The code itself is always reported, so a code missing from this list costs
/// an examiner a lookup and never a wrong name.
fn fourcc_label(code: &str) -> Option<&'static str> {
    Some(match code {
        "acct" => "account",
        "atyp" => "authentication_type",
        "cdat" => "created",
        "crtr" => "creator_code",
        "cusi" => "has_custom_icon",
        "desc" => "kind_description",
        "gena" => "generic_field",
        "icmt" => "comment",
        "invi" => "invisible",
        "mdat" => "modified",
        "nega" => "negative_entry",
        "path" => "path",
        "port" => "port",
        "prot" => "protected_data",
        "ptcl" => "protocol",
        "scrp" => "script_code",
        "sdmn" => "security_domain",
        "srvr" => "server",
        "svce" => "service",
        "type" => "type_code",
        _ => return None,
    })
}

impl AttrDecl {
    /// The name this attribute is emitted under.
    ///
    /// The schema's own name wins; then the plain word for a known
    /// four-character code; then the code itself; then the number. Nothing is
    /// invented at any step.
    fn label(&self) -> String {
        if let Some(name) = &self.name {
            if !name.is_empty() {
                return name.clone();
            }
        }
        match fourcc(self.id) {
            Some(code) => match fourcc_label(&code) {
                Some(word) => word.to_string(),
                None => code,
            },
            None => format!("attribute_{}", self.id),
        }
    }
}

/// Render a u32 as a four-character code when all four bytes are printable
/// ASCII, which is how the password relations name their attributes and how
/// `crtr` and `type` carry their values.
fn fourcc(value: u32) -> Option<String> {
    let bytes = value.to_be_bytes();
    bytes
        .iter()
        .all(|b| (0x20..=0x7e).contains(b))
        .then(|| String::from_utf8_lossy(&bytes).into_owned())
}

// --- primitive reads ---------------------------------------------------------

fn be_u32(data: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let s = data.get(at..end)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

// --- the file's own schema ---------------------------------------------------

/// A relation: its identifier, the name the file gives it, where its table
/// sits, and what it declares about its records.
#[derive(Debug, Clone)]
struct Relation {
    id: u32,
    name: Option<String>,
    /// Absolute offset of the table header.
    table_at: usize,
    /// `recordCount` the table header declares.
    declared_records: u32,
    /// Offset of the first record within the table, which is also the
    /// threshold that separates a live record offset from a free-list link.
    first_record_at: u32,
    attributes: Vec<AttrDecl>,
}

impl Relation {
    fn label(&self) -> String {
        match &self.name {
            Some(name) if !name.is_empty() => name.clone(),
            _ => match relation_kind(self.id) {
                Some(kind) => kind.as_str().to_string(),
                None => format!("relation_{:#010x}", self.id),
            },
        }
    }
}

/// Why a keychain was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Empty,
    NotAKeychain,
    UnknownVersion(u32),
    SchemaUnreadable,
}

impl Refusal {
    fn tag(self) -> &'static str {
        match self {
            Refusal::Empty => "empty_file",
            Refusal::NotAKeychain => "no_kych_magic",
            Refusal::UnknownVersion(_) => "unknown_keychain_version",
            Refusal::SchemaUnreadable => "schema_unreadable",
        }
    }

    fn detail(self) -> String {
        match self {
            Refusal::Empty => "the file is empty".to_string(),
            Refusal::NotAKeychain => {
                "the first four bytes are not `kych`, so this is not a keychain of this \
                 generation"
                    .to_string()
            }
            Refusal::UnknownVersion(v) => format!(
                "the keychain declares version {v:#010x}, which this reader has not been shown \
                 and will not guess the layout of"
            ),
            Refusal::SchemaUnreadable => {
                "the file's own schema tables could not be read, so what its records mean is \
                 not established and none was decoded"
                    .to_string()
            }
        }
    }
}

/// Read the relation list and each relation's attribute declarations from the
/// file's own schema tables.
fn read_schema(data: &[u8]) -> Result<Vec<Relation>, Refusal> {
    if data.is_empty() {
        return Err(Refusal::Empty);
    }
    if data.len() < HEADER_BYTES || data.get(0..4) != Some(&KEYCHAIN_MAGIC[..]) {
        return Err(Refusal::NotAKeychain);
    }
    let version = be_u32(data, 4).ok_or(Refusal::NotAKeychain)?;
    if version != KEYCHAIN_VERSION {
        return Err(Refusal::UnknownVersion(version));
    }
    let schema_at = be_u32(data, 12).ok_or(Refusal::SchemaUnreadable)? as usize;
    let table_count = be_u32(data, schema_at + 4).ok_or(Refusal::SchemaUnreadable)? as usize;
    if table_count == 0 || table_count > MAX_RELATIONS {
        return Err(Refusal::SchemaUnreadable);
    }

    // Pass one: the table headers, which carry the relation ids.
    let mut relations: Vec<Relation> = Vec::with_capacity(table_count);
    for i in 0..table_count {
        let off_at = schema_at + 8 + 4 * i;
        let table_at = schema_at
            .checked_add(be_u32(data, off_at).ok_or(Refusal::SchemaUnreadable)? as usize)
            .ok_or(Refusal::SchemaUnreadable)?;
        let id = be_u32(data, table_at + 4).ok_or(Refusal::SchemaUnreadable)?;
        let declared_records = be_u32(data, table_at + 8).ok_or(Refusal::SchemaUnreadable)?;
        let first_record_at = be_u32(data, table_at + 12).ok_or(Refusal::SchemaUnreadable)?;
        relations.push(Relation {
            id,
            name: None,
            table_at,
            declared_records,
            first_record_at,
            attributes: Vec::new(),
        });
    }

    // Pass two: `CSSM_DL_DB_SCHEMA_INFO` names every relation. Its own two
    // attributes are the only ones this reader knows without being told, and
    // it is what tells it the rest.
    let info = relations
        .iter()
        .find(|r| r.id == RELATION_SCHEMA_INFO)
        .cloned()
        .ok_or(Refusal::SchemaUnreadable)?;
    let mut names: BTreeMap<u32, String> = BTreeMap::new();
    for record_at in live_records(data, &info) {
        let offs = attribute_offsets(data, record_at, 2);
        let (Some(id_at), Some(name_at)) = (offs[0], offs[1]) else {
            continue;
        };
        let Some(id) = be_u32(data, id_at) else {
            continue;
        };
        if let Some(name) = counted_utf8(data, name_at) {
            names.insert(id, name);
        }
    }
    if names.is_empty() {
        return Err(Refusal::SchemaUnreadable);
    }
    for r in &mut relations {
        r.name = names.get(&r.id).cloned();
    }

    // Pass three: `CSSM_DL_DB_SCHEMA_ATTRIBUTES` declares every attribute of
    // every relation. Found by NAME rather than by number: the
    // `CSSM_DL_DB_SCHEMA_*` ids are 1 = ATTRIBUTES and 2 = INDEXES, the
    // reverse of the order the tables appear in, and reading the name means
    // never having to remember which.
    let attrs_relation = relations
        .iter()
        .find(|r| r.name.as_deref() == Some("CSSM_DL_DB_SCHEMA_ATTRIBUTES"))
        .cloned()
        .ok_or(Refusal::SchemaUnreadable)?;
    let mut declared: BTreeMap<u32, Vec<AttrDecl>> = BTreeMap::new();
    for record_at in live_records(data, &attrs_relation) {
        // The attributes relation declares six attributes of its own:
        // relation id, attribute id, name format, name, name id, and format.
        let offs = attribute_offsets(data, record_at, 6);
        let (Some(rel_at), Some(id_at)) = (offs[0], offs[1]) else {
            continue;
        };
        let (Some(relation), Some(id)) = (be_u32(data, rel_at), be_u32(data, id_at)) else {
            continue;
        };
        let name = offs[3].and_then(|at| counted_utf8(data, at));
        let format = offs[5]
            .and_then(|at| be_u32(data, at))
            .map(AttrFormat::from_raw)
            .unwrap_or(AttrFormat::Unknown(u32::MAX));
        let list = declared.entry(relation).or_default();
        if list.len() < MAX_ATTRIBUTES {
            list.push(AttrDecl { id, name, format });
        }
    }
    for r in &mut relations {
        // The declaration order is the on-disk order of the attribute-offset
        // array, and must not be sorted: the password relations number their
        // attributes by four-character code, so sorting by id would read every
        // value at the wrong offset while still producing legible-looking
        // output.
        if let Some(list) = declared.remove(&r.id) {
            r.attributes = list;
        }
    }
    Ok(relations)
}

/// Absolute offsets of the live records in a relation's table.
///
/// A table's record-number array mixes three things: zero for an unused slot, a
/// **free-list link** (an odd value, being an offset into the array itself with
/// the low bit set), and a **live record offset** (even, and at or past the
/// table's `first_record_at`). Telling the second from the third is the one
/// rule here that a wrong reading would get wrong while still producing
/// plausible records, which is why the caller checks the count it yields
/// against the table's own `recordCount`.
fn live_records(data: &[u8], relation: &Relation) -> Vec<usize> {
    let Some(slots) = be_u32(data, relation.table_at + 24) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for i in 0..slots as usize {
        if out.len() >= MAX_RECORDS_PER_RELATION {
            break;
        }
        let Some(value) = be_u32(data, relation.table_at + 28 + 4 * i) else {
            break;
        };
        if value < relation.first_record_at || value % 2 == 1 {
            continue;
        }
        let Some(at) = relation.table_at.checked_add(value as usize) else {
            continue;
        };
        // A record must at least carry its own header and its offset array.
        if be_u32(data, at).is_some() {
            out.push(at);
        }
    }
    out
}

/// The `count` attribute offsets of the record at `record_at`, absolute, or
/// `None` for an attribute the record does not carry.
///
/// The stored value has its low bit set when the attribute is present and is
/// zero when it is absent. An absent attribute is reported absent: a keychain
/// item with no comment has no comment, and an empty string would be a claim
/// that somebody wrote one.
fn attribute_offsets(data: &[u8], record_at: usize, count: usize) -> Vec<Option<usize>> {
    (0..count)
        .map(|i| {
            let raw = be_u32(data, record_at + RECORD_HEADER_BYTES + 4 * i)?;
            if raw == 0 {
                return None;
            }
            record_at.checked_add((raw & !1) as usize)
        })
        .collect()
}

/// A length-prefixed blob's bytes, bounded by [`MAX_VALUE_BYTES`].
fn counted(data: &[u8], at: usize) -> Option<(&[u8], u32)> {
    let len = be_u32(data, at)?;
    let take = (len as usize).min(MAX_VALUE_BYTES);
    let end = at.checked_add(4)?.checked_add(take)?;
    Some((data.get(at + 4..end)?, len))
}

fn counted_utf8(data: &[u8], at: usize) -> Option<String> {
    let (bytes, _) = counted(data, at)?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// One decoded attribute value.
#[derive(Debug, Clone, PartialEq)]
enum AttrValue {
    Text(String),
    Number(i64),
    /// A four-character code carried in a numeric field, as `crtr` and `type`
    /// do. Both forms are reported: the code is what an examiner recognises,
    /// the number is what the file holds.
    Code {
        code: String,
        raw: u32,
    },
    /// Bytes that are not text. Rendered as hex with the length the file
    /// declared, so a truncation is visible as one.
    Bytes {
        hex: String,
        declared_len: u32,
    },
}

/// Decode one attribute against the format its own schema declared.
fn decode_value(data: &[u8], at: usize, format: AttrFormat) -> Option<AttrValue> {
    match format {
        AttrFormat::SInt32 => {
            let raw = be_u32(data, at)?;
            Some(match fourcc(raw) {
                Some(code) => AttrValue::Code { code, raw },
                None => AttrValue::Number(i64::from(raw as i32)),
            })
        }
        AttrFormat::UInt32 => {
            let raw = be_u32(data, at)?;
            Some(match fourcc(raw) {
                Some(code) => AttrValue::Code { code, raw },
                None => AttrValue::Number(i64::from(raw)),
            })
        }
        // The one format stored raw rather than length-prefixed: sixteen bytes
        // of `YYYYMMDDhhmmssZ` and a NUL.
        AttrFormat::TimeDate => {
            let raw = data.get(at..at.checked_add(16)?)?;
            let cut = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            let text = String::from_utf8_lossy(&raw[..cut]).into_owned();
            // An all-zero date field is the absence of a date, not 1900.
            if text.is_empty() {
                return None;
            }
            Some(AttrValue::Text(text))
        }
        _ => {
            let (bytes, declared) = counted(data, at)?;
            if bytes.is_empty() {
                return None;
            }
            match std::str::from_utf8(bytes) {
                Ok(text)
                    if text
                        .chars()
                        .all(|c| !c.is_control() || c == '\n' || c == '\t') =>
                {
                    Some(AttrValue::Text(text.to_string()))
                }
                _ => Some(AttrValue::Bytes {
                    hex: hex(bytes),
                    declared_len: declared,
                }),
            }
        }
    }
}

/// One decoded keychain record.
#[derive(Debug, Clone)]
struct Item {
    relation: String,
    kind: Option<ItemKind>,
    record_number: u32,
    /// Offset of the record within the file, so a claim can be checked.
    record_at: usize,
    /// Size of the item's payload, as the record's header declares it.
    payload_bytes: u32,
    /// Where the payload begins: immediately after the attribute-offset array.
    payload_at: usize,
    /// How the payload is protected, read from its own first four bytes rather
    /// than assumed from the relation.
    wrapping: Wrapping,
    attributes: Vec<(String, AttrFormat, AttrValue)>,
}

impl Item {
    fn attribute(&self, label: &str) -> Option<&AttrValue> {
        self.attributes
            .iter()
            .find(|(l, _, _)| l == label)
            .map(|(_, _, v)| v)
    }

    fn text(&self, label: &str) -> Option<&str> {
        match self.attribute(label) {
            Some(AttrValue::Text(t)) => Some(t.as_str()),
            _ => None,
        }
    }
}

/// Decode every live record of a relation.
///
/// Returns the items and the number of slots the record-number array offered
/// that could not be decoded, so a relation that is short says so.
fn decode_relation(data: &[u8], relation: &Relation) -> (Vec<Item>, usize) {
    let attrs = &relation.attributes;
    let mut out = Vec::new();
    let mut undecoded = 0usize;
    for record_at in live_records(data, relation) {
        let Some(record_size) = be_u32(data, record_at) else {
            undecoded += 1;
            continue;
        };
        let Some(record_number) = be_u32(data, record_at + 4) else {
            undecoded += 1;
            continue;
        };
        let Some(payload_bytes) = be_u32(data, record_at + 16) else {
            undecoded += 1;
            continue;
        };
        // The payload sits between the attribute-offset array and the first
        // attribute. That the three meet exactly is one of the checks that the
        // header length is right.
        let payload_at = record_at + RECORD_HEADER_BYTES + 4 * attrs.len();
        if payload_at.saturating_add(payload_bytes as usize) > record_at + record_size as usize {
            undecoded += 1;
            continue;
        }
        let wrapping = data
            .get(payload_at..payload_at + payload_bytes.min(4) as usize)
            .map(Wrapping::of)
            .unwrap_or(Wrapping::None);

        let offsets = attribute_offsets(data, record_at, attrs.len());
        let mut decoded = Vec::new();
        for (decl, at) in attrs.iter().zip(offsets) {
            let Some(at) = at else { continue };
            if at >= record_at + record_size as usize {
                continue;
            }
            if let Some(value) = decode_value(data, at, decl.format) {
                decoded.push((decl.label(), decl.format, value));
            }
        }
        out.push(Item {
            relation: relation.label(),
            kind: relation_kind(relation.id),
            record_number,
            record_at,
            payload_bytes,
            payload_at,
            wrapping,
            attributes: decoded,
        });
    }
    (out, undecoded)
}

/// The `DbBlob`'s key-derivation parameters: what a lawful password-recovery
/// attempt needs, and what this reader will never attempt itself.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MasterKeyWrapping {
    version: u32,
    /// Offset of the wrapped master key within the file.
    ciphertext_at: usize,
    ciphertext_bytes: usize,
    /// The 20-byte PBKDF2 salt, hex.
    salt: String,
    /// The 8-byte CBC initialisation vector, hex.
    iv: String,
}

/// Find the `DbBlob` and read its derivation parameters.
///
/// It lives in its own relation (`DBBlob`, `0x80008000`) as a single record
/// whose payload begins with `0xFADE0711`. Located by that magic rather than by
/// a fixed offset, so a keychain that lays its tables out differently is still
/// read — and reported absent rather than guessed at when it is not there.
fn read_master_key_wrapping(data: &[u8], relations: &[Relation]) -> Option<MasterKeyWrapping> {
    for relation in relations {
        if relation.name.as_deref() != Some("DBBlob") && relation.id != 0x8000_8000 {
            continue;
        }
        for record_at in live_records(data, relation) {
            let payload_at = record_at + RECORD_HEADER_BYTES;
            if be_u32(data, payload_at) != Some(DB_BLOB_MAGIC) {
                continue;
            }
            let version = be_u32(data, payload_at + 4)?;
            let crypto_at = be_u32(data, payload_at + 8)? as usize;
            let total = be_u32(data, payload_at + 12)? as usize;
            if crypto_at >= total {
                continue;
            }
            let salt = data.get(payload_at + DB_BLOB_SALT_AT..payload_at + DB_BLOB_SALT_AT + 20)?;
            let iv = data.get(payload_at + DB_BLOB_IV_AT..payload_at + DB_BLOB_IV_AT + 8)?;
            return Some(MasterKeyWrapping {
                version,
                ciphertext_at: payload_at + crypto_at,
                ciphertext_bytes: total - crypto_at,
                salt: hex(salt),
                iv: hex(iv),
            });
        }
    }
    None
}

/// Extract the `DbBlob`'s raw crypto material (salt, IV, wrapped master key)
/// from the relation-located blob, for a password unwrap.
///
/// Located the same relation-aware way as [`read_master_key_wrapping`] — by the
/// file's own `DBBlob` relation and the `0xFADE0711` magic — so a `KeyBlob`
/// carrying the same magic in a key relation is never mistaken for it.
fn locate_db_blob_crypto(data: &[u8], relations: &[Relation]) -> Option<(DbBlobCrypto, u32)> {
    for relation in relations {
        if relation.name.as_deref() != Some("DBBlob") && relation.id != 0x8000_8000 {
            continue;
        }
        for record_at in live_records(data, relation) {
            let payload_at = record_at + RECORD_HEADER_BYTES;
            if be_u32(data, payload_at) != Some(DB_BLOB_MAGIC) {
                continue;
            }
            let version = be_u32(data, payload_at + 4)?;
            let crypto_at = be_u32(data, payload_at + 8)? as usize;
            let total = be_u32(data, payload_at + 12)? as usize;
            if crypto_at >= total {
                continue;
            }
            let salt = data.get(payload_at + DB_BLOB_SALT_AT..payload_at + DB_BLOB_SALT_AT + 20)?;
            let iv = data.get(payload_at + DB_BLOB_IV_AT..payload_at + DB_BLOB_IV_AT + 8)?;
            let ciphertext = data.get(payload_at + crypto_at..payload_at + total)?;
            return Some((
                DbBlobCrypto {
                    salt: salt.try_into().ok()?,
                    iv: iv.try_into().ok()?,
                    ciphertext: ciphertext.to_vec(),
                },
                version,
            ));
        }
    }
    None
}

/// The outcome of unwrapping a keychain's master key with a supplied password.
///
/// The master key is what an item's `ssgp` secret is unwrapped under (see
/// [`crate::keychain_unlock`]). It is held in a buffer zeroed on drop, is not
/// `Clone`, is not serialisable and prints as redacted: it must never reach
/// artifact metadata or a log. The password is not held at all.
pub struct KeychainUnlock {
    master_key: zeroize::Zeroizing<Vec<u8>>,
    /// The `DbBlob` version the key was unwrapped from.
    pub db_blob_version: u32,
}

impl KeychainUnlock {
    /// The recovered database master key bytes.
    pub fn master_key(&self) -> &[u8] {
        &self.master_key
    }
}

impl std::fmt::Debug for KeychainUnlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeychainUnlock")
            .field("master_key", &"<redacted>")
            .field("db_blob_version", &self.db_blob_version)
            .finish()
    }
}

/// Unwrap a `kych` keychain's database master key with `password`.
///
/// Reads the file's own schema to locate the `DbBlob`, then runs the
/// PBKDF2-HMAC-SHA1 -> 3DES-EDE-CBC unwrap. Returns:
///
/// * `Ok(None)` when the bytes are not a readable keychain or carry no
///   `DbBlob`: there is nothing to unlock;
/// * `Err(`[`UnlockError::WrongPassword`]`)` when the password does not open
///   the blob (the decrypted block is not validly padded); and
/// * `Ok(Some(..))` with the recovered master key when it does.
///
/// This unwrap and the wrong-password check are graded on two real
/// third-party keychains with known passwords (`tests/john_keychain_unlock.rs`,
/// `VALIDATION.md` KEYCHAIN-1). Per-item decryption is not: those files hold
/// no items. It never derives, guesses or persists a password.
pub fn unlock_keychain(
    data: &[u8],
    password: &[u8],
) -> Result<Option<KeychainUnlock>, UnlockError> {
    let Ok(relations) = read_schema(data) else {
        return Ok(None);
    };
    let Some((crypto, db_blob_version)) = locate_db_blob_crypto(data, &relations) else {
        return Ok(None);
    };
    let master = crypto.unwrap(password)?;
    Ok(Some(KeychainUnlock {
        master_key: zeroize::Zeroizing::new(master),
        db_blob_version,
    }))
}

/// Unwrap a `kych` keychain's database master key with the bytes of the Mac's `/var/db/SystemKey`,
/// the route `System.keychain` takes in place of a password.
///
/// Same contract as [`unlock_keychain`]: `Ok(None)` when there is no `DbBlob`;
/// `Err(`[`UnlockError::NotASystemKey`]`)` when the bytes are not a SystemKey file;
/// `Err(`[`UnlockError::WrongPassword`]`)` when it is one but does not open this keychain.
/// Graded on a real macOS 11.2.1 `System.keychain` with its own SystemKey
/// (`tests/keychain_system_key.rs`, `VALIDATION.md` `KEYCHAIN-3`).
pub fn unlock_keychain_with_system_key(
    data: &[u8],
    system_key: &[u8],
) -> Result<Option<KeychainUnlock>, UnlockError> {
    let Ok(relations) = read_schema(data) else {
        return Ok(None);
    };
    let Some((crypto, db_blob_version)) = locate_db_blob_crypto(data, &relations) else {
        return Ok(None);
    };
    let master = crypto.unwrap_with_system_key(system_key)?;
    Ok(Some(KeychainUnlock {
        master_key: zeroize::Zeroizing::new(master),
        db_blob_version,
    }))
}

/// One item secret decrypted under an unlocked keychain.
///
/// The bytes are held in a buffer zeroed on drop, are not `Clone`, are not serialisable and print as
/// redacted: they must never reach artifact metadata, a log or a search index. The only caller is the
/// audited per-record reveal; records say the secret decrypted and withhold it.
pub struct DecryptedSecret {
    /// The relation the item lives in.
    pub relation: String,
    pub record_number: u32,
    pub kind: Option<ItemKind>,
    secret: zeroize::Zeroizing<Vec<u8>>,
}

impl DecryptedSecret {
    /// The secret's bytes.
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}

impl std::fmt::Debug for DecryptedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedSecret")
            .field("relation", &self.relation)
            .field("record_number", &self.record_number)
            .field("kind", &self.kind)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// What decrypting every `ssgp` item came to: the ones that decrypted, and for each that did not
/// the item and why, so an item left locked says what stopped it.
#[derive(Debug, Default)]
pub struct SecretDecryption {
    pub decrypted: Vec<DecryptedSecret>,
    /// `(relation, record number, reason)`.
    pub failed: Vec<(String, u32, String)>,
}

/// Decrypt every `ssgp` item of a keychain under its unlocked master key.
///
/// An item's secret is `ssgp`-prefixed: the 20-byte label (which starts with the tag), an 8-byte IV and
/// the 3DES-CBC ciphertext. The label names the symmetric key record that wraps the item key; that
/// record's `KeyBlob` carries the wrapped key between its crypto offset and its total length, unwrapped
/// under the database master key (RFC 3217), and the item key is the 24 bytes after the unwrapped
/// block's 12-byte header. Graded on a real macOS-made keychain with a published answer
/// (`tests/keychain_items_real.rs`, `VALIDATION.md` KEYCHAIN-2).
pub fn decrypt_item_secrets(data: &[u8], unlock: &KeychainUnlock) -> SecretDecryption {
    let mut out = SecretDecryption::default();
    let Ok(relations) = read_schema(data) else {
        return out;
    };
    let Some(master) = unlock
        .master_key()
        .get(..crate::keychain_unlock::DERIVED_KEY_LEN)
        .and_then(|m| <[u8; crate::keychain_unlock::DERIVED_KEY_LEN]>::try_from(m).ok())
    else {
        return out;
    };
    let mut keys: Vec<Item> = Vec::new();
    let mut secrets: Vec<Item> = Vec::new();
    let mut private_keys: Vec<Item> = Vec::new();
    for relation in &relations {
        if relation
            .name
            .as_deref()
            .is_some_and(|n| n.starts_with("CSSM_DL_DB_SCHEMA_") || n == "DBBlob")
        {
            continue;
        }
        for item in decode_relation(data, relation).0 {
            match item.wrapping {
                Wrapping::Ssgp => secrets.push(item),
                Wrapping::KeyBlob if item.kind == Some(ItemKind::SymmetricKey) => keys.push(item),
                Wrapping::KeyBlob if item.kind == Some(ItemKind::PrivateKey) => {
                    private_keys.push(item)
                }
                _ => {}
            }
        }
    }
    let payload = |item: &Item| {
        data.get(item.payload_at..item.payload_at.checked_add(item.payload_bytes as usize)?)
    };
    for item in &secrets {
        let mut fail = |why: String| {
            out.failed
                .push((item.relation.clone(), item.record_number, why))
        };
        let Some(pl) = payload(item) else {
            fail("its payload lies outside the file".to_string());
            continue;
        };
        if pl.len() < 28 + 8 || (pl.len() - 28) % 8 != 0 {
            fail(format!(
                "its {}-byte payload is not label, IV and whole 3DES blocks",
                pl.len()
            ));
            continue;
        }
        let (label, iv, body) = (&pl[..20], &pl[20..28], &pl[28..]);
        let key_record = keys.iter().find(|k| {
            matches!(k.attribute("Label"), Some(AttrValue::Bytes { hex, .. }) if *hex == hex_of(label))
        });
        let Some(key_record) = key_record else {
            fail("no symmetric key record carries its label".to_string());
            continue;
        };
        let Some(blob) = payload(key_record) else {
            fail("its key record's payload lies outside the file".to_string());
            continue;
        };
        let (Some(start), Some(total)) = (be_u32(blob, 8), be_u32(blob, 12)) else {
            fail("its key blob is too short to name its crypto block".to_string());
            continue;
        };
        let Some(wrapped) = blob
            .get(start as usize..total as usize)
            .filter(|w| !w.is_empty())
        else {
            fail("its key blob's crypto block lies outside the blob".to_string());
            continue;
        };
        let unwrapped = match crate::keychain_unlock::unwrap_item_key(&master, wrapped) {
            Ok(k) => zeroize::Zeroizing::new(k),
            Err(e) => {
                fail(format!(
                    "its item key would not unwrap under the master key ({e:?})"
                ));
                continue;
            }
        };
        let Some(item_key) = unwrapped
            .get(12..12 + crate::keychain_unlock::DERIVED_KEY_LEN)
            .and_then(|k| <[u8; crate::keychain_unlock::DERIVED_KEY_LEN]>::try_from(k).ok())
        else {
            fail("its unwrapped key block is shorter than a header and a 3DES key".to_string());
            continue;
        };
        let iv: [u8; 8] = iv.try_into().expect("an 8-byte slice");
        match crate::keychain_unlock::decrypt_ssgp(&item_key, &iv, body) {
            Ok(plain) => out.decrypted.push(DecryptedSecret {
                relation: item.relation.clone(),
                record_number: item.record_number,
                kind: item.kind,
                secret: zeroize::Zeroizing::new(plain),
            }),
            Err(e) => fail(format!(
                "its secret would not decrypt under its item key ({e:?})"
            )),
        }
    }
    // A private key's blob is wrapped directly under the master key by the same RFC 3217 unwrap as an
    // item key (the whole block reversed); what it yields is a 12-byte header and the key as PKCS#8.
    for item in &private_keys {
        let mut fail = |why: String| {
            out.failed
                .push((item.relation.clone(), item.record_number, why))
        };
        let Some(blob) = payload(item) else {
            fail("its payload lies outside the file".to_string());
            continue;
        };
        let (Some(start), Some(total)) = (be_u32(blob, 8), be_u32(blob, 12)) else {
            fail("its key blob is too short to name its crypto block".to_string());
            continue;
        };
        let Some(wrapped) = blob
            .get(start as usize..total as usize)
            .filter(|w| !w.is_empty())
        else {
            fail("its key blob's crypto block lies outside the blob".to_string());
            continue;
        };
        match crate::keychain_unlock::unwrap_item_key(&master, wrapped) {
            Ok(plain) if plain.len() > PRIVATE_KEY_HEADER => out.decrypted.push(DecryptedSecret {
                relation: item.relation.clone(),
                record_number: item.record_number,
                kind: item.kind,
                secret: zeroize::Zeroizing::new(plain[PRIVATE_KEY_HEADER..].to_vec()),
            }),
            Ok(_) => fail("its unwrapped key block is shorter than its header".to_string()),
            Err(e) => fail(format!(
                "its private key would not unwrap under the master key ({e:?})"
            )),
        }
    }
    out
}

/// The header an unwrapped key block carries before the key itself.
const PRIVATE_KEY_HEADER: usize = 12;

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- artifact emission -------------------------------------------------------

pub struct KeychainParser;

/// True when a name is one of the keychain files.
///
/// Used to decide whether a file that failed to parse deserves a refusal
/// record. Selection itself is by the `kych` magic, so a keychain under any
/// name is still read.
fn named_as_keychain(name: &str, path: &str) -> bool {
    let base = basename_lower(name);
    let lower_path = path.to_ascii_lowercase();
    base.ends_with(".keychain")
        || base.ends_with(".keychain-db")
        || lower_path.contains("/library/keychains/")
}

fn provenance(meta: &mut Map<String, Value>, file_name: &str) {
    meta.insert("source_file_name".into(), json!(file_name));
    meta.insert("source_format".into(), json!("apple_keychain_kych"));
}

/// The sentence every locked item carries.
///
/// It names what is missing rather than implying the item is empty: an item
/// whose secret could not be read is not an item with no secret.
const LOCKED_NOTE: &str = "The item's attributes are stored in the clear and are reported in \
     full; its secret is wrapped under the keychain's master key and was not decrypted. The \
     master key is itself wrapped in this file's DbBlob, which a keychain password opens for a \
     user keychain and /var/db/SystemKey opens for System.keychain — neither of which this \
     reader is handed. An absent password here is NOT evidence that the item held none.";

fn item_artifact(artifact: &Artifact, file_name: &str, item: &Item) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("KeychainItem"));
    meta.insert("subtype".into(), json!("keychain_item"));
    provenance(&mut meta, file_name);
    meta.insert("relation".into(), json!(item.relation));
    if let Some(kind) = item.kind {
        meta.insert("item_kind".into(), json!(kind.as_str()));
    }
    meta.insert("record_number".into(), json!(item.record_number));
    meta.insert("record_offset".into(), json!(item.record_at));

    for (label, format, value) in &item.attributes {
        match value {
            AttrValue::Text(text) => meta.insert(label.clone(), json!(text)),
            AttrValue::Number(n) => meta.insert(label.clone(), json!(n)),
            AttrValue::Code { code, raw } => {
                meta.insert(format!("{label}_raw"), json!(raw));
                meta.insert(label.clone(), json!(code))
            }
            AttrValue::Bytes { hex, declared_len } => {
                if *declared_len as usize > MAX_VALUE_BYTES {
                    meta.insert(format!("{label}_bytes"), json!(declared_len));
                }
                meta.insert(label.clone(), json!(format!("0x{hex}")))
            }
        };
        // The format the file itself declared, so a value's type is traceable
        // to the schema rather than to this reader's guess.
        meta.insert(format!("{label}_format"), json!(format.as_str()));
    }

    meta.insert("payload_bytes".into(), json!(item.payload_bytes));
    meta.insert("payload_offset".into(), json!(item.payload_at));
    let secret = item.kind.is_none_or(|k| k.payload_is_secret());
    if item.wrapping.is_wrapped() {
        meta.insert("secret_state".into(), json!("locked"));
        meta.insert("secret_wrapping".into(), json!(item.wrapping.as_str()));
        meta.insert("secret_note".into(), json!(LOCKED_NOTE));
        let what = match item.wrapping {
            Wrapping::Ssgp => "the ssgp tag a password item's wrapped secret carries",
            _ => "the blob magic a wrapped key carries",
        };
        let _ = stamp_incomplete(
            &mut meta,
            "content",
            &[(
                IncompleteReason::Encrypted,
                format!(
                    "the item's {} byte payload begins with {what}, so it is wrapped under the \
                     keychain's master key and was not decrypted",
                    item.payload_bytes
                ),
            )],
        );
    } else if secret && item.payload_bytes > 0 {
        // No `ssgp` tag on a payload that should have one. Reported as its own
        // state rather than folded into "locked": a secret stored unwrapped
        // would be a finding, and so would a payload this reader has
        // misidentified.
        meta.insert("secret_state".into(), json!("not_wrapped_as_expected"));
        meta.insert(
            "secret_note".into(),
            json!(
                "The payload carries neither the ssgp tag a wrapped password has nor the blob \
                   magic a wrapped key has. It has not been decoded and is not reported as a \
                   secret; the offset and length are given so the bytes can be examined."
            ),
        );
        let _ = stamp_incomplete(
            &mut meta,
            "content",
            &[(
                IncompleteReason::UnresolvedStructure,
                "the item's payload is not tagged as a wrapped secret and was not decoded"
                    .to_string(),
            )],
        );
    } else if item.payload_bytes > 0 {
        meta.insert("secret_state".into(), json!("plaintext"));
    } else {
        meta.insert("secret_state".into(), json!("no_payload"));
    }

    meta.insert("name".into(), json!(item_name(item)));
    meta.insert("short_desc".into(), json!(item_short_desc(item)));
    // The creation date puts the item on the timeline: when a credential for a
    // service was first stored is often the fact in question.
    if let Some(date) = item.text("created") {
        meta.insert("created_iso".into(), json!(date));
    }
    if let Some(date) = item.text("modified") {
        meta.insert("modified_iso".into(), json!(date));
    }
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("keychain_item")
}

fn item_name(item: &Item) -> String {
    let what = item
        .text("PrintName")
        .or_else(|| item.text("service"))
        .or_else(|| item.text("server"))
        .or_else(|| item.text("Label"))
        .unwrap_or("(unnamed)");
    match item.text("account") {
        Some(account) if !account.is_empty() => format!("{what} ({account})"),
        _ => what.to_string(),
    }
}

fn item_short_desc(item: &Item) -> String {
    let kind = match item.kind {
        Some(kind) => kind.as_str(),
        None => item.relation.as_str(),
    };
    let mut parts = vec![format!("{kind}: {}", item_name(item))];
    if let Some(server) = item.text("server") {
        parts.push(format!("on {server}"));
    }
    if let Some(created) = item.text("created") {
        parts.push(format!("stored {created}"));
    }
    if item.wrapping.is_wrapped() {
        parts.push("secret locked".to_string());
    }
    parts.join("; ")
}

/// A certificate's DER bytes, carried out as their own artifact so they can be
/// hashed, identified and exported.
///
/// A certificate in a keychain is not encrypted, and describing it as "835
/// bytes of data" while the bytes sit right there is the defect `HUNT-104`
/// closed for plists.
fn payload_artifact(
    artifact: &Artifact,
    file_name: &str,
    item: &Item,
    data: &[u8],
) -> Option<Artifact> {
    if item.kind != Some(ItemKind::Certificate) || item.payload_bytes == 0 {
        return None;
    }
    let take = (item.payload_bytes as usize).min(MAX_PAYLOAD_BYTES);
    let bytes = data.get(item.payload_at..item.payload_at + take)?.to_vec();
    let truncated = take < item.payload_bytes as usize;
    let mut meta = Map::new();
    meta.insert("type".into(), json!("FileEntry"));
    meta.insert("subtype".into(), json!("keychain_certificate"));
    provenance(&mut meta, file_name);
    let label = item
        .text("PrintName")
        .or_else(|| item.text("Alias"))
        .unwrap_or("certificate");
    meta.insert("name".into(), json!(format!("{label}.cer")));
    meta.insert("file_name".into(), json!(format!("{label}.cer")));
    meta.insert("size".into(), json!(bytes.len()));
    meta.insert("record_number".into(), json!(item.record_number));
    meta.insert(
        "short_desc".into(),
        json!(format!(
            "X.509 certificate from the keychain, {} bytes, stored unencrypted",
            bytes.len()
        )),
    );
    if truncated {
        let _ = stamp_incomplete(
            &mut meta,
            "content",
            &[(
                IncompleteReason::CapReached,
                format!(
                    "the certificate declares {} bytes and this reader carries at most \
                     {MAX_PAYLOAD_BYTES}; the artifact holds the first {take}",
                    item.payload_bytes
                ),
            )],
        );
    }
    Some(
        Artifact::new(
            artifact.case_id,
            ArtifactType::FileEntry,
            Some(std::sync::Arc::new(
                seance_core::data_source::ByteSliceDataSource::new(bytes),
            )),
            Value::Object(meta),
        )
        .with_parent(artifact.id)
        .with_subtype("keychain_certificate"),
    )
}

#[allow(clippy::too_many_arguments)]
fn status_artifact(
    artifact: &Artifact,
    file_name: &str,
    staged: &Staged,
    relations: &[Relation],
    items: usize,
    locked: usize,
    undecoded: usize,
    count_disagreements: Vec<String>,
    wrapping: Option<&MasterKeyWrapping>,
) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("KeychainStatus"));
    meta.insert("subtype".into(), json!("keychain_status"));
    provenance(&mut meta, file_name);
    meta.insert("detected".into(), json!(true));
    meta.insert("declared_size".into(), json!(staged.declared));
    meta.insert("bytes_staged".into(), json!(staged.got));
    meta.insert("relations".into(), json!(relations.len()));
    meta.insert("items".into(), json!(items));
    meta.insert("items_with_locked_secret".into(), json!(locked));

    // The relation inventory, which is what says whether this keychain holds
    // passwords at all before any of them is opened.
    let inventory: Vec<Value> = relations
        .iter()
        .map(|r| {
            json!({
                "relation": r.label(),
                "relation_id": r.id,
                "declared_records": r.declared_records,
                "attributes_declared": r.attributes.len(),
            })
        })
        .collect();
    meta.insert("relation_inventory".into(), json!(inventory));

    let mut reasons = Vec::new();
    if let Some(reason) = staged.incomplete_reason() {
        reasons.push((reason, staged.detail(file_name)));
    }
    if undecoded > 0 {
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            format!(
                "{undecoded} record slot(s) named a record whose own header did not fit inside \
                 it; those records were not decoded"
            ),
        ));
    }
    if !count_disagreements.is_empty() {
        meta.insert(
            "record_count_disagreements".into(),
            json!(count_disagreements),
        );
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            format!(
                "{} relation(s) hold a different number of live records than their table header \
                 declares ({}); the rule that separates a live record from a free-list link may \
                 be reading this file wrongly, so the records from those relations are reported \
                 with that caveat",
                count_disagreements.len(),
                count_disagreements.join(", ")
            ),
        ));
    }
    if locked > 0 {
        meta.insert("locked_secret_note".into(), json!(LOCKED_NOTE));
        reasons.push((
            IncompleteReason::Encrypted,
            format!(
                "{locked} item(s) carry a secret wrapped under the keychain's master key, which \
                 was not decrypted; their attributes are complete and their secrets are absent"
            ),
        ));
    }
    let _ = stamp_incomplete(&mut meta, "content", &reasons);

    match wrapping {
        Some(w) => {
            // What a lawful password-recovery attempt needs, in one place. The
            // salt and the initialisation vector are not secrets; the wrapped
            // key is named by offset rather than copied into a record that
            // ends up in a report.
            meta.insert(
                "master_key_wrapping".into(),
                json!({
                    "db_blob_version": w.version,
                    "kdf": "PBKDF2-HMAC-SHA1",
                    "iterations": DB_BLOB_PBKDF2_ITERATIONS,
                    "salt_hex": w.salt,
                    "iv_hex": w.iv,
                    "wrapped_key_offset": w.ciphertext_at,
                    "wrapped_key_bytes": w.ciphertext_bytes,
                    "cipher": "3DES-CBC",
                }),
            );
            meta.insert(
                "master_key_note".into(),
                json!(
                    "These are the parameters a lawful password-recovery attempt needs. The \
                       iteration count is fixed by the format rather than stored in the file, \
                       and is stated here so it does not have to be assumed. Nothing was \
                       decrypted and no password was tried."
                ),
            );
        }
        None => {
            meta.insert(
                "master_key_note".into(),
                json!(
                    "No DbBlob carrying the wrapped master key was found in this file, so the \
                       parameters a recovery attempt needs are not reported. That is a statement \
                       about this file, not about the items: their secrets remain unread."
                ),
            );
        }
    }

    meta.insert(
        "name".into(),
        json!(format!("Keychain parsed: {file_name}")),
    );
    meta.insert(
        "short_desc".into(),
        json!(format!(
            "{file_name}: {items} item(s) across {} relation(s), {locked} with a locked secret",
            relations.len()
        )),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("keychain_status")
}

/// The record that says a file named as a keychain was not read.
fn refusal_artifact(
    artifact: &Artifact,
    file_name: &str,
    staged: &Staged,
    refusal: Refusal,
) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("KeychainStatus"));
    meta.insert("subtype".into(), json!("keychain_not_parsed"));
    provenance(&mut meta, file_name);
    meta.insert("detected".into(), json!(false));
    meta.insert("declared_size".into(), json!(staged.declared));
    meta.insert("bytes_staged".into(), json!(staged.got));
    meta.insert("failure_reason".into(), json!(refusal.tag()));
    meta.insert("failure_detail".into(), json!(refusal.detail()));
    meta.insert(
        "message".into(),
        json!(
            "This file is named as a keychain but was not read, so nothing is reported from \
               it. Absence of credentials here is NOT evidence that the account held none."
        ),
    );
    let reason = staged
        .incomplete_reason()
        .unwrap_or(IncompleteReason::UnresolvedStructure);
    let _ = stamp_incomplete(
        &mut meta,
        "content",
        &[(
            reason,
            format!("{}; {}", staged.detail(file_name), refusal.detail()),
        )],
    );
    meta.insert(
        "name".into(),
        json!(format!("Keychain not parsed: {file_name}")),
    );
    meta.insert(
        "short_desc".into(),
        json!(format!("{file_name} was not parsed: {}", refusal.detail())),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(artifact.id)
    .with_subtype("keychain_not_parsed")
}

/// Try a keychain password, or a `/var/db/SystemKey` (as hex of its 48 bytes), the examiner supplied
/// for this file. Returns the unlocked master key when it opened the `DbBlob`, for the item decryption
/// in [`KeychainParser::process`]; the key stays in that call, zeroed on drop, and never reaches a
/// record. A rejected credential changes nothing and is reported through the credential route; the
/// locked records stand.
fn take_supplied_password(artifact: &Artifact, bytes: &[u8]) -> Option<KeychainUnlock> {
    use seance_core::credential::CredentialKind;
    let cred = seance_core::credential::for_artifact(
        artifact.id,
        &[
            CredentialKind::MacosKeychainPassword,
            CredentialKind::MacosSystemKey,
        ],
    )?;
    let is_system_key = cred.kind() == CredentialKind::MacosSystemKey;
    let tried = if is_system_key {
        match decode_hex(cred.expose_secret()) {
            Some(file) => unlock_keychain_with_system_key(bytes, &file),
            None => Err(UnlockError::NotASystemKey),
        }
    } else {
        unlock_keychain(bytes, cred.expose_secret().as_bytes())
    };
    match tried {
        Ok(Some(unlock)) => {
            cred.accepted();
            Some(unlock)
        }
        Err(UnlockError::WrongPassword) => {
            cred.rejected(if is_system_key {
                "the SystemKey did not open this keychain's DbBlob; the locked record stands"
            } else {
                "the password did not open this keychain's DbBlob; the locked record stands"
            });
            None
        }
        Err(UnlockError::NotASystemKey) => {
            cred.rejected(
                "the value is not a SystemKey: it must be the 48 bytes of /var/db/SystemKey as 96 \
                 hex digits, beginning fade0711",
            );
            None
        }
        Err(UnlockError::NotBlockAligned) => {
            cred.rejected(
                "this keychain's DbBlob is malformed (its wrapped key is not a whole number of \
                 3DES blocks), so no credential can be checked against it",
            );
            None
        }
        Ok(None) => {
            cred.rejected(
                "no DbBlob carrying the wrapped master key was found in this file, so a credential \
                 cannot be checked against it",
            );
            None
        }
    }
}

/// Hex to bytes, ignoring surrounding whitespace; `None` for anything else.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Mark an item whose secret decrypted: the secret is withheld, as the iOS keychain's is, and released
/// only by the audited per-record reveal. An item that did not decrypt keeps its locked record and
/// says what stopped it.
fn stamp_secret(art: &mut Artifact, item: &Item, secrets: &SecretDecryption) {
    let Some(meta) = art.metadata.as_object_mut() else {
        return;
    };
    if let Some(d) = secrets
        .decrypted
        .iter()
        .find(|d| d.relation == item.relation && d.record_number == item.record_number)
    {
        meta.insert("secret_state".into(), json!("withheld"));
        meta.insert("secret_present".into(), json!(true));
        meta.insert("secret_bytes".into(), json!(d.secret().len()));
        meta.insert(
            "secret_statement".into(),
            json!(
                "The item's secret decrypted under the keychain password or SystemKey supplied for this run but is \
                 withheld: it is not in this record, its export, or search, and is not stored."
            ),
        );
        for key in [
            "secret_note",
            "content_incomplete",
            "content_incomplete_reason",
            "content_incomplete_detail",
        ] {
            meta.remove(key);
        }
        if let Some(Value::String(desc)) = meta.get_mut("short_desc") {
            *desc = desc.replace("secret locked", "secret decrypted, withheld");
        }
    } else if let Some((_, _, why)) = secrets
        .failed
        .iter()
        .find(|(r, n, _)| *r == item.relation && *n == item.record_number)
    {
        meta.insert("secret_decrypt_error".into(), json!(why));
    }
}

impl ForensicsModule for KeychainParser {
    fn id(&self) -> &str {
        "macos.keychain"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        let file_name = if name.is_empty() {
            basename_lower(path)
        } else {
            name.to_string()
        };
        let named = named_as_keychain(name, path);

        if ds.size() == 0 {
            if !named {
                return Ok(Vec::new());
            }
            let staged = Staged {
                bytes: Vec::new(),
                declared: 0,
                got: 0,
                capped: false,
            };
            return Ok(vec![refusal_artifact(
                artifact,
                &file_name,
                &staged,
                Refusal::Empty,
            )]);
        }

        let staged = Staged::read(ds.as_ref(), MAX_KEYCHAIN_BYTES);
        let relations = match read_schema(&staged.bytes) {
            Ok(relations) => relations,
            Err(refusal) => {
                if !named {
                    return Ok(Vec::new());
                }
                debug!(
                    artifact = %artifact.id,
                    file = %file_name,
                    reason = refusal.tag(),
                    "named as a keychain but was not read"
                );
                return Ok(vec![refusal_artifact(
                    artifact, &file_name, &staged, refusal,
                )]);
            }
        };

        let wrapping = read_master_key_wrapping(&staged.bytes, &relations);
        let unlock = take_supplied_password(artifact, &staged.bytes);
        let secrets = unlock
            .as_ref()
            .map(|u| decrypt_item_secrets(&staged.bytes, u));
        let mut out: Vec<Artifact> = Vec::new();
        let mut items = 0usize;
        let mut locked = 0usize;
        let mut undecoded = 0usize;
        let mut disagreements = Vec::new();

        for relation in &relations {
            // The schema relations describe the file; they are not evidence
            // about the machine, and emitting 155 attribute declarations as
            // records would bury the twenty-three that are.
            if relation
                .name
                .as_deref()
                .is_some_and(|n| n.starts_with("CSSM_DL_DB_SCHEMA_") || n == "DBBlob")
            {
                continue;
            }
            let (decoded, short) = decode_relation(&staged.bytes, relation);
            undecoded += short;
            if decoded.len() != relation.declared_records as usize {
                disagreements.push(format!(
                    "{} declares {} record(s), {} decoded",
                    relation.label(),
                    relation.declared_records,
                    decoded.len()
                ));
            }
            for item in &decoded {
                let mut record = item_artifact(artifact, &file_name, item);
                let decrypted = secrets.as_ref().is_some_and(|s| {
                    s.decrypted.iter().any(|d| {
                        d.relation == item.relation && d.record_number == item.record_number
                    })
                });
                if let Some(s) = &secrets {
                    stamp_secret(&mut record, item, s);
                }
                if item.wrapping.is_wrapped() && !decrypted {
                    locked += 1;
                }
                if let Some(cert) = payload_artifact(artifact, &file_name, item, &staged.bytes) {
                    out.push(cert);
                }
                out.push(record);
                items += 1;
            }
        }

        let mut status = status_artifact(
            artifact,
            &file_name,
            &staged,
            &relations,
            items,
            locked,
            undecoded,
            disagreements,
            wrapping.as_ref(),
        );
        if let (Some(_), Some(secrets), Some(meta)) =
            (&unlock, &secrets, status.metadata.as_object_mut())
        {
            meta.insert("password_state".into(), json!("accepted"));
            meta.insert("master_key_unwrapped".into(), json!(true));
            meta.insert(
                "items_secret_decrypted".into(),
                json!(secrets.decrypted.len()),
            );
            meta.insert(
                "items_secret_not_decrypted".into(),
                json!(secrets.failed.len()),
            );
            meta.insert(
                "password_note".into(),
                json!(format!(
                    "The supplied password or SystemKey opened this keychain's DbBlob and {} item secret(s) \
                     decrypted under it; they are withheld, not written to any record. Only \
                     `ssgp` password items are decrypted: a private key stays locked, and {} \
                     password item(s) did not decrypt (each says why).",
                    secrets.decrypted.len(),
                    secrets.failed.len()
                )),
            );
        }
        out.push(status);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
    }
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_core::test_support::TruncatedSource;
    use std::sync::Arc;
    use uuid::Uuid;

    // --- fixture construction ------------------------------------------------
    //
    // A keychain is written from literal offsets rather than through the
    // reader's own structures, so a mistake in those cannot make a test agree
    // with itself.

    fn be(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    /// A length-prefixed blob, padded to a four-byte boundary so the next
    /// attribute lands on an offset whose low bit is free to carry the
    /// presence flag.
    fn blob(bytes: &[u8]) -> Vec<u8> {
        let mut out = be(bytes.len() as u32).to_vec();
        out.extend_from_slice(bytes);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out
    }

    fn text_blob(s: &str) -> Vec<u8> {
        blob(s.as_bytes())
    }

    /// A `TIME_DATE`: sixteen raw bytes, not length-prefixed. The one format in
    /// this file that is not, which is why it has its own builder.
    fn date(s: &str) -> Vec<u8> {
        let mut out = s.as_bytes().to_vec();
        out.resize(16, 0);
        out
    }

    fn u32_attr(v: u32) -> Vec<u8> {
        be(v).to_vec()
    }

    /// One record: the fixed header, the attribute-offset array, the payload,
    /// then the attribute values in declaration order.
    fn record(number: u32, payload: &[u8], attrs: &[Option<Vec<u8>>]) -> Vec<u8> {
        let header = 24 + 4 * attrs.len();
        let mut values = Vec::new();
        let mut offsets = Vec::new();
        let mut at = header + payload.len();
        // The payload ends where the attributes begin; pad so the first
        // attribute is four-aligned, exactly as the real files are.
        let pad = (4 - at % 4) % 4;
        let mut lead = vec![0u8; pad];
        at += pad;
        for attr in attrs {
            match attr {
                Some(bytes) => {
                    // Bit 0 set marks the attribute present.
                    offsets.push(at as u32 | 1);
                    values.extend_from_slice(bytes);
                    at += bytes.len();
                }
                None => offsets.push(0),
            }
        }
        let size = header + payload.len() + pad + values.len();
        let mut out = be(size as u32).to_vec();
        out.extend_from_slice(&be(number));
        out.extend_from_slice(&be(1)); // CreateVersion
        out.extend_from_slice(&be(0)); // RecordVersion
        out.extend_from_slice(&be(payload.len() as u32));
        out.extend_from_slice(&be(0)); // SemanticInformation
        for o in &offsets {
            out.extend_from_slice(&be(*o));
        }
        out.extend_from_slice(payload);
        out.append(&mut lead);
        out.extend_from_slice(&values);
        assert_eq!(out.len(), size, "the record's own size field must be right");
        out
    }

    /// One table: the header, the record-number array, the records, and a
    /// minimal index area.
    ///
    /// `declared` overrides the record count the header states, so a test can
    /// make the header disagree with the records.
    fn table(id: u32, records: &[Vec<u8>], declared: Option<u32>) -> Vec<u8> {
        let slots = records.len();
        let first = 28 + 4 * slots;
        let mut offsets = Vec::new();
        let mut body = Vec::new();
        let mut at = first;
        for r in records {
            offsets.push(at as u32);
            body.extend_from_slice(r);
            at += r.len();
        }
        let indexes = at;
        let size = indexes + 8;
        let mut out = be(size as u32).to_vec();
        out.extend_from_slice(&be(id));
        out.extend_from_slice(&be(declared.unwrap_or(slots as u32)));
        out.extend_from_slice(&be(first as u32));
        out.extend_from_slice(&be(indexes as u32));
        out.extend_from_slice(&be(0)); // FreeListHead
        out.extend_from_slice(&be(slots as u32));
        for o in &offsets {
            out.extend_from_slice(&be(*o));
        }
        out.extend_from_slice(&body);
        out.extend_from_slice(&[0u8; 8]);
        out
    }

    /// Assemble a whole keychain from its tables.
    fn keychain(tables: &[Vec<u8>]) -> Vec<u8> {
        keychain_versioned(KEYCHAIN_VERSION, tables)
    }

    fn keychain_versioned(version: u32, tables: &[Vec<u8>]) -> Vec<u8> {
        let schema_at = 20usize;
        let directory = 8 + 4 * tables.len();
        let mut offsets = Vec::new();
        let mut body = Vec::new();
        let mut at = directory;
        for t in tables {
            offsets.push(at as u32);
            body.extend_from_slice(t);
            at += t.len();
        }
        let schema_size = directory + body.len();
        let mut out = KEYCHAIN_MAGIC.to_vec();
        out.extend_from_slice(&be(version));
        out.extend_from_slice(&be(16)); // headerSize
        out.extend_from_slice(&be(schema_at as u32));
        out.extend_from_slice(&be(0)); // authOffset
        out.extend_from_slice(&be(schema_size as u32));
        out.extend_from_slice(&be(tables.len() as u32));
        for o in &offsets {
            out.extend_from_slice(&be(*o));
        }
        out.extend_from_slice(&body);
        out
    }

    /// A `CSSM_DL_DB_SCHEMA_INFO` record: relation id and relation name.
    fn info_record(number: u32, id: u32, name: &str) -> Vec<u8> {
        record(number, &[], &[Some(u32_attr(id)), Some(text_blob(name))])
    }

    /// A `CSSM_DL_DB_SCHEMA_ATTRIBUTES` record declaring one attribute of one
    /// relation.
    fn attr_record(
        number: u32,
        relation: u32,
        attr_id: u32,
        name: Option<&str>,
        format: u32,
    ) -> Vec<u8> {
        record(
            number,
            &[],
            &[
                Some(u32_attr(relation)),
                Some(u32_attr(attr_id)),
                Some(u32_attr(if name.is_some() { 0 } else { 1 })),
                name.map(text_blob),
                Some(u32_attr(0)),
                Some(u32_attr(format)),
            ],
        )
    }

    fn code(s: &str) -> u32 {
        let b = s.as_bytes();
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }

    const GENERIC: u32 = 0x8000_0000;
    const CERT: u32 = 0x8000_1000;
    const FMT_SINT32: u32 = 1;
    const FMT_UINT32: u32 = 2;
    const FMT_TIME: u32 = 5;
    const FMT_BLOB: u32 = 6;

    /// The declaration order the real files use for the generic-password
    /// relation, whose first two attributes are dates and whose numeric ids
    /// are four-character codes in no sorted order.
    fn generic_attr_decls() -> Vec<Vec<u8>> {
        let decls: &[(u32, Option<&str>, u32)] = &[
            (code("cdat"), None, FMT_TIME),
            (code("mdat"), None, FMT_TIME),
            (code("desc"), None, FMT_BLOB),
            (code("icmt"), None, FMT_BLOB),
            (code("crtr"), None, FMT_UINT32),
            (code("invi"), None, FMT_SINT32),
            (7, Some("PrintName"), FMT_BLOB),
            (code("acct"), None, FMT_BLOB),
            (code("svce"), None, FMT_BLOB),
            (code("zzzz"), None, FMT_BLOB),
        ];
        decls
            .iter()
            .enumerate()
            .map(|(i, (id, name, fmt))| attr_record(i as u32, GENERIC, *id, *name, *fmt))
            .collect()
    }

    /// Positions within the generic-password relation's attribute list above.
    const A_CDAT: usize = 0;
    const A_MDAT: usize = 1;
    const A_DESC: usize = 2;
    const A_ICMT: usize = 3;
    const A_CRTR: usize = 4;
    const A_INVI: usize = 5;
    const A_PRINT: usize = 6;
    const A_ACCT: usize = 7;
    const A_SVCE: usize = 8;
    const A_ZZZZ: usize = 9;

    fn no_attrs() -> Vec<Option<Vec<u8>>> {
        vec![None; 10]
    }

    /// A wrapped secret, as the file stores one: the `ssgp` tag then
    /// ciphertext.
    fn wrapped(len: usize) -> Vec<u8> {
        let mut out = SSGP_TAG.to_vec();
        out.extend(std::iter::repeat_n(0xa5u8, len));
        out
    }

    /// A `DbBlob` record carrying the master-key wrapping parameters.
    fn db_blob() -> Vec<u8> {
        let mut payload = be(DB_BLOB_MAGIC).to_vec();
        payload.extend_from_slice(&be(0x0000_0200)); // version
        payload.extend_from_slice(&be(120)); // startCryptoBlob
        payload.extend_from_slice(&be(168)); // totalLength
        payload.resize(DB_BLOB_SALT_AT, 0);
        payload.extend(std::iter::repeat_n(0x11u8, 20)); // salt
        assert_eq!(payload.len(), DB_BLOB_IV_AT);
        payload.extend(std::iter::repeat_n(0x22u8, 8)); // iv
        payload.resize(168, 0x33);
        record(0, &payload, &[])
    }

    /// A keychain holding the schema, a generic-password relation with the
    /// given records, and a `DbBlob`.
    fn keychain_with(records: &[Vec<u8>]) -> Vec<u8> {
        let mut info = vec![
            info_record(0, 0, "CSSM_DL_DB_SCHEMA_INFO"),
            info_record(1, 1, "CSSM_DL_DB_SCHEMA_ATTRIBUTES"),
            info_record(2, GENERIC, "APPL_DB_RECORD_GENERIC_PASSWORD"),
            info_record(3, 0x8000_8000, "DBBlob"),
        ];
        let info_table = table(0, &std::mem::take(&mut info), None);
        let attrs_table = table(1, &generic_attr_decls(), None);
        let generic_table = table(GENERIC, records, None);
        let blob_table = table(0x8000_8000, &[db_blob()], None);
        keychain(&[info_table, attrs_table, generic_table, blob_table])
    }

    fn run(bytes: Vec<u8>, name: &str, path_str: &str) -> Vec<Artifact> {
        run_source(Arc::new(ByteSliceDataSource::new(bytes)), name, path_str)
    }

    fn run_source(src: Arc<dyn DataSource>, name: &str, path_str: &str) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(src),
            json!({ "name": name, "path": path_str }),
        );
        KeychainParser
            .process(&art)
            .expect("never fails the pipeline")
    }

    fn of_type<'a>(out: &'a [Artifact], wanted: &str) -> Vec<&'a Value> {
        out.iter()
            .map(|a| &a.metadata)
            .filter(|m| m.get("type").and_then(|v| v.as_str()) == Some(wanted))
            .collect()
    }

    fn status_of(out: &[Artifact]) -> &Value {
        of_type(out, "KeychainStatus")
            .first()
            .copied()
            .expect("every read or refused keychain produces a status row")
    }

    fn s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
        v.get(key).and_then(|x| x.as_str())
    }
    fn n(v: &Value, key: &str) -> Option<i64> {
        v.get(key).and_then(|x| x.as_i64())
    }

    const LOGIN_PATH: &str = "/Users/eliflatt/Library/Keychains/login.keychain-db";

    // --- decoding -------------------------------------------------------------

    #[test]
    fn a_hand_written_keychain_decodes_its_items_from_its_own_schema() {
        let mut attrs = no_attrs();
        attrs[A_CDAT] = Some(date("20210212003531Z"));
        attrs[A_MDAT] = Some(date("20210405223108Z"));
        attrs[A_PRINT] = Some(text_blob("e.flatt610@gmail.com"));
        attrs[A_ACCT] = Some(text_blob("20118734345"));
        attrs[A_SVCE] = Some(text_blob("iCloud"));
        let bytes = keychain_with(&[record(21, &wrapped(72), &attrs)]);

        let out = run(bytes, "login.keychain-db", LOGIN_PATH);
        let items = of_type(&out, "KeychainItem");
        assert_eq!(items.len(), 1);
        let item = items[0];
        assert_eq!(s(item, "item_kind"), Some("generic_password"));
        assert_eq!(s(item, "relation"), Some("APPL_DB_RECORD_GENERIC_PASSWORD"));
        assert_eq!(n(item, "record_number"), Some(21));
        assert_eq!(s(item, "PrintName"), Some("e.flatt610@gmail.com"));
        assert_eq!(s(item, "account"), Some("20118734345"));
        assert_eq!(s(item, "service"), Some("iCloud"));
        assert_eq!(s(item, "created"), Some("20210212003531Z"));
        assert_eq!(s(item, "modified"), Some("20210405223108Z"));
        assert_eq!(s(item, "created_iso"), Some("20210212003531Z"));
        // The format each value was decoded under comes from the file's own
        // schema, and is emitted so the decode is traceable to it.
        assert_eq!(s(item, "service_format"), Some("blob"));
        assert_eq!(s(item, "created_format"), Some("time_date"));
        assert_eq!(s(item, "name"), Some("e.flatt610@gmail.com (20118734345)"));
    }

    /// The regression this reader would be worst without.
    ///
    /// The password relations number their attributes by four-character code,
    /// so the declaration order and the numeric order are different. Sorting
    /// by id would read every value at the wrong offset — and because the
    /// values are all short strings and dates, the output would still look
    /// entirely legible. Here `cdat` (0x63646174) sorts after `PrintName` (7)
    /// and `acct` (0x61636374) sorts before it, so a sorted read puts the
    /// account where the date belongs.
    #[test]
    fn the_attribute_order_is_the_schemas_own_and_not_the_attribute_ids() {
        let decls = generic_attr_decls();
        assert!(
            decls.len() == 10,
            "the fixture declares ten attributes in the real file's order"
        );
        let mut attrs = no_attrs();
        attrs[A_CDAT] = Some(date("20210212003531Z"));
        attrs[A_PRINT] = Some(text_blob("Safari Session State Key"));
        attrs[A_ACCT] = Some(text_blob("an-account"));
        let out = run(
            keychain_with(&[record(1, &wrapped(8), &attrs)]),
            "login.keychain-db",
            LOGIN_PATH,
        );
        let item = of_type(&out, "KeychainItem")[0];
        assert_eq!(
            s(item, "created"),
            Some("20210212003531Z"),
            "the date must come from the first declared attribute, not from wherever its id sorts"
        );
        assert_eq!(s(item, "PrintName"), Some("Safari Session State Key"));
        assert_eq!(s(item, "account"), Some("an-account"));
        assert!(
            item.get("service").is_none(),
            "an attribute the record does not carry must be absent, not shifted in from the \
             next one"
        );
    }

    #[test]
    fn an_absent_attribute_is_absent_and_not_an_empty_string() {
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("MetadataKeychain"));
        attrs[A_SVCE] = Some(text_blob("MetadataKeychain"));
        // No comment, no description, no account.
        let out = run(
            keychain_with(&[record(46, &wrapped(44), &attrs)]),
            "login.keychain-db",
            LOGIN_PATH,
        );
        let item = of_type(&out, "KeychainItem")[0];
        for absent in ["comment", "kind_description", "account", "created"] {
            assert!(
                item.get(absent).is_none(),
                "{absent} must be absent: an item with no comment has no comment, and an empty \
                 string would claim somebody wrote one"
            );
        }
        assert_eq!(s(item, "service"), Some("MetadataKeychain"));
    }

    #[test]
    fn an_empty_blob_is_absent_rather_than_an_empty_value() {
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("Call History User Data Key"));
        // The real file carries a zero-length account blob on several items.
        attrs[A_ACCT] = Some(blob(b""));
        let out = run(
            keychain_with(&[record(34, &wrapped(56), &attrs)]),
            "login.keychain-db",
            LOGIN_PATH,
        );
        let item = of_type(&out, "KeychainItem")[0];
        assert!(item.get("account").is_none());
    }

    /// The description and the comment are the two attributes that say what a
    /// key is *for*, and they are in the clear. On the real keychain one of
    /// them reads "Used to encrypt window snapshots to ensure privacy", which
    /// is the whole answer to what that item is without decrypting anything.
    #[test]
    fn the_description_and_comment_that_say_what_an_item_is_for_are_read() {
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("Apple Persistent State Encryption"));
        attrs[A_DESC] = Some(text_blob("Handoff Decryption Key"));
        attrs[A_ICMT] = Some(text_blob(
            "Used by the persistent state feature to encrypt window snapshots to ensure privacy.",
        ));
        let out = run(
            keychain_with(&[record(29, &wrapped(64), &attrs)]),
            "login.keychain-db",
            LOGIN_PATH,
        );
        let item = of_type(&out, "KeychainItem")[0];
        assert_eq!(s(item, "kind_description"), Some("Handoff Decryption Key"));
        assert!(s(item, "comment")
            .expect("the comment")
            .contains("encrypt window snapshots"));
        assert!(
            s(item, "short_desc")
                .expect("a description")
                .contains("secret locked"),
            "the row's own summary must say the secret was not recovered"
        );
    }

    #[test]
    fn a_four_character_code_in_a_numeric_field_is_shown_both_ways() {
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("iOS Backup"));
        attrs[A_CRTR] = Some(u32_attr(code("aapl")));
        attrs[A_INVI] = Some(u32_attr(0));
        let out = run(
            keychain_with(&[record(28, &wrapped(40), &attrs)]),
            "login.keychain-db",
            LOGIN_PATH,
        );
        let item = of_type(&out, "KeychainItem")[0];
        assert_eq!(
            s(item, "creator_code"),
            Some("aapl"),
            "the code is what an examiner recognises"
        );
        assert_eq!(
            n(item, "creator_code_raw"),
            Some(i64::from(code("aapl"))),
            "and the number is what the file holds"
        );
        assert_eq!(
            n(item, "invisible"),
            Some(0),
            "a numeric field whose bytes are not printable is reported as a number"
        );
    }

    #[test]
    fn an_unknown_attribute_code_is_reported_as_the_code_and_not_renamed() {
        let mut attrs = no_attrs();
        attrs[A_ZZZZ] = Some(text_blob("something"));
        let out = run(
            keychain_with(&[record(1, &wrapped(8), &attrs)]),
            "login.keychain-db",
            LOGIN_PATH,
        );
        let item = of_type(&out, "KeychainItem")[0];
        assert_eq!(
            s(item, "zzzz"),
            Some("something"),
            "an attribute code this reader has no plain word for keeps the code, which costs a \
             lookup and never a wrong name"
        );
    }

    #[test]
    fn a_non_text_attribute_is_rendered_as_the_bytes_it_is() {
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("BeaconStore"));
        attrs[A_ZZZZ] = Some(blob(&[0xf5, 0x59, 0x87, 0x53]));
        let out = run(
            keychain_with(&[record(38, &wrapped(24), &attrs)]),
            "login.keychain-db",
            LOGIN_PATH,
        );
        let item = of_type(&out, "KeychainItem")[0];
        assert_eq!(s(item, "zzzz"), Some("0xf5598753"));
    }

    // --- secrets --------------------------------------------------------------

    #[test]
    fn a_locked_secret_is_reported_as_locked_and_never_as_absent() {
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("iCloud"));
        attrs[A_ACCT] = Some(text_blob("20118734345"));
        let out = run(
            keychain_with(&[record(21, &wrapped(72), &attrs)]),
            "login.keychain-db",
            LOGIN_PATH,
        );
        let item = of_type(&out, "KeychainItem")[0];
        assert_eq!(s(item, "secret_state"), Some("locked"));
        assert_eq!(s(item, "secret_wrapping"), Some("ssgp_master_key"));
        assert_eq!(n(item, "payload_bytes"), Some(76));
        assert_eq!(s(item, "content_incomplete_reason"), Some("encrypted"));
        assert!(s(item, "secret_note")
            .expect("a note")
            .contains("NOT evidence that the item held none"));
        assert_eq!(n(status_of(&out), "items_with_locked_secret"), Some(1));
    }

    #[test]
    fn a_payload_with_no_ssgp_tag_is_not_reported_as_a_secret() {
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("odd item"));
        // Eight bytes of payload with no ssgp tag. A secret stored unwrapped
        // would be a finding, and so would a payload this reader has
        // misidentified; either way it must not be read as a secret.
        let out = run(
            keychain_with(&[record(1, &[0u8; 8], &attrs)]),
            "login.keychain-db",
            LOGIN_PATH,
        );
        let item = of_type(&out, "KeychainItem")[0];
        assert_eq!(s(item, "secret_state"), Some("not_wrapped_as_expected"));
        assert_eq!(
            s(item, "content_incomplete_reason"),
            Some("unresolved_structure")
        );
        assert_eq!(n(status_of(&out), "items_with_locked_secret"), Some(0));
    }

    #[test]
    fn an_item_with_no_payload_says_so_rather_than_being_called_locked() {
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("no payload"));
        let out = run(
            keychain_with(&[record(1, &[], &attrs)]),
            "login.keychain-db",
            LOGIN_PATH,
        );
        assert_eq!(
            s(of_type(&out, "KeychainItem")[0], "secret_state"),
            Some("no_payload")
        );
    }

    #[test]
    fn the_parameters_a_recovery_attempt_needs_are_reported_and_nothing_is_decrypted() {
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("iCloud"));
        let out = run(
            keychain_with(&[record(21, &wrapped(72), &attrs)]),
            "login.keychain-db",
            LOGIN_PATH,
        );
        let st = status_of(&out);
        let w = &st["master_key_wrapping"];
        assert_eq!(w["kdf"], json!("PBKDF2-HMAC-SHA1"));
        assert_eq!(w["iterations"], json!(1000));
        assert_eq!(w["cipher"], json!("3DES-CBC"));
        assert_eq!(w["salt_hex"], json!("11".repeat(20)));
        assert_eq!(w["iv_hex"], json!("22".repeat(8)));
        assert_eq!(w["wrapped_key_bytes"], json!(48));
        assert!(s(st, "master_key_note")
            .expect("a note")
            .contains("Nothing was decrypted and no password was tried"));
        // The wrapped key is named by offset, not copied into a record that
        // ends up in a report.
        assert!(w.get("wrapped_key_hex").is_none());
        let at = w["wrapped_key_offset"].as_u64().expect("an offset");
        assert!(at > 0);
    }

    #[test]
    fn a_keychain_with_no_db_blob_says_the_recovery_parameters_are_not_reported() {
        // A keychain whose DbBlob relation is absent: the items' secrets are
        // still unread, and that must not read as "there is nothing to
        // recover".
        let info_table = table(
            0,
            &[
                info_record(0, 0, "CSSM_DL_DB_SCHEMA_INFO"),
                info_record(1, 1, "CSSM_DL_DB_SCHEMA_ATTRIBUTES"),
                info_record(2, GENERIC, "APPL_DB_RECORD_GENERIC_PASSWORD"),
            ],
            None,
        );
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("iCloud"));
        let bytes = keychain(&[
            info_table,
            table(1, &generic_attr_decls(), None),
            table(GENERIC, &[record(1, &wrapped(8), &attrs)], None),
        ]);
        let out = run(bytes, "login.keychain-db", LOGIN_PATH);
        let st = status_of(&out);
        assert!(st.get("master_key_wrapping").is_none());
        assert!(s(st, "master_key_note")
            .expect("a note")
            .contains("their secrets remain unread"));
        assert_eq!(
            s(of_type(&out, "KeychainItem")[0], "secret_state"),
            Some("locked")
        );
    }

    // --- certificates ---------------------------------------------------------

    #[test]
    fn a_certificate_is_carried_out_as_its_own_artifact_because_it_is_not_encrypted() {
        // A certificate relation with two declared attributes and a DER
        // payload that carries no ssgp tag, which is how the real files store
        // them.
        let cert_attrs: &[(u32, Option<&str>, u32)] = &[
            (1, Some("PrintName"), FMT_BLOB),
            (2, Some("Alias"), FMT_BLOB),
        ];
        let decls: Vec<Vec<u8>> = cert_attrs
            .iter()
            .enumerate()
            .map(|(i, (id, name, fmt))| attr_record(i as u32, CERT, *id, *name, *fmt))
            .collect();
        let der = vec![0x30u8, 0x82, 0x03, 0x3f, 0x11, 0x22, 0x33];
        let rec = record(
            0,
            &der,
            &[
                Some(text_blob("com.apple.systemdefault")),
                Some(text_blob("com.apple.systemdefault")),
            ],
        );
        let bytes = keychain(&[
            table(
                0,
                &[
                    info_record(0, 0, "CSSM_DL_DB_SCHEMA_INFO"),
                    info_record(1, 1, "CSSM_DL_DB_SCHEMA_ATTRIBUTES"),
                    info_record(2, CERT, "APPL_DB_RECORD_X509_CERTIFICATE"),
                ],
                None,
            ),
            table(1, &decls, None),
            table(CERT, &[rec], None),
        ]);
        let out = run(
            bytes,
            "System.keychain",
            "/Library/Keychains/System.keychain",
        );

        let item = of_type(&out, "KeychainItem")[0];
        assert_eq!(s(item, "item_kind"), Some("certificate"));
        assert_eq!(
            s(item, "secret_state"),
            Some("plaintext"),
            "a certificate is public by construction; reporting it as locked would hide evidence \
             sitting in the clear"
        );
        assert!(
            item.get("content_incomplete").is_none(),
            "nothing about a certificate in a keychain is incomplete"
        );

        let files: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();
        assert_eq!(files.len(), 1, "the certificate's bytes are carried out");
        assert_eq!(
            s(&files[0].metadata, "name"),
            Some("com.apple.systemdefault.cer")
        );
        assert_eq!(n(&files[0].metadata, "size"), Some(der.len() as i64));
        let src = files[0].data.as_ref().expect("the bytes are attached");
        let mut buf = vec![0u8; der.len()];
        assert_eq!(src.read_at(0, &mut buf).unwrap(), der.len());
        assert_eq!(buf, der, "the artifact holds the certificate's own bytes");
    }

    // --- structure and honesty ------------------------------------------------

    #[test]
    fn the_schema_relations_are_not_emitted_as_evidence() {
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("iCloud"));
        let out = run(
            keychain_with(&[record(1, &wrapped(8), &attrs)]),
            "login.keychain-db",
            LOGIN_PATH,
        );
        assert_eq!(
            of_type(&out, "KeychainItem").len(),
            1,
            "ten attribute declarations and four relation names describe the file, not the \
             machine; emitting them would bury the one item that is evidence"
        );
        // They are still inventoried on the status row, so what the file
        // declares is visible.
        let inventory = status_of(&out)["relation_inventory"]
            .as_array()
            .expect("an inventory");
        assert_eq!(inventory.len(), 4);
        assert!(inventory
            .iter()
            .any(|r| r["relation"] == json!("CSSM_DL_DB_SCHEMA_ATTRIBUTES")));
    }

    #[test]
    fn a_record_count_that_disagrees_with_the_table_header_is_reported() {
        // The header claims five records where one is present. The rule that
        // separates a live record from a free-list link is the one thing here
        // that could be wrong while still producing plausible records, so a
        // disagreement must be reported rather than resolved silently.
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("iCloud"));
        let bytes = keychain(&[
            table(
                0,
                &[
                    info_record(0, 0, "CSSM_DL_DB_SCHEMA_INFO"),
                    info_record(1, 1, "CSSM_DL_DB_SCHEMA_ATTRIBUTES"),
                    info_record(2, GENERIC, "APPL_DB_RECORD_GENERIC_PASSWORD"),
                ],
                None,
            ),
            table(1, &generic_attr_decls(), None),
            table(GENERIC, &[record(1, &wrapped(8), &attrs)], Some(5)),
        ]);
        let out = run(bytes, "login.keychain-db", LOGIN_PATH);
        let st = status_of(&out);
        let d = st["record_count_disagreements"]
            .as_array()
            .expect("the disagreement is named");
        assert_eq!(d.len(), 1);
        assert!(d[0].as_str().unwrap().contains("declares 5"));
        assert_eq!(
            s(st, "content_incomplete_reason"),
            Some("unresolved_structure")
        );
        // The item is still reported: it was read, and the caveat travels on
        // the status row.
        assert_eq!(of_type(&out, "KeychainItem").len(), 1);
    }

    #[test]
    fn a_file_that_is_not_a_keychain_is_passed_over_in_silence() {
        for bytes in [
            b"#!/bin/sh\n".to_vec(),
            vec![0u8; 4096],
            b"SQLite format 3\0".to_vec(),
        ] {
            let out = run(bytes, "notes.txt", "/Users/eliflatt/notes.txt");
            assert!(out.is_empty());
        }
    }

    #[test]
    fn a_file_named_as_a_keychain_that_will_not_parse_is_reported_rather_than_dropped() {
        let out = run(vec![0x81u8; 4096], "login.keychain-db", LOGIN_PATH);
        assert_eq!(out.len(), 1);
        let st = status_of(&out);
        assert_eq!(st["detected"], json!(false));
        assert_eq!(s(st, "failure_reason"), Some("no_kych_magic"));
        assert!(s(st, "message")
            .expect("a message")
            .contains("NOT evidence that the account held none"));
    }

    #[test]
    fn an_empty_keychain_file_is_reported_because_a_wiped_one_is_a_finding() {
        let out = run(Vec::new(), "login.keychain-db", LOGIN_PATH);
        assert_eq!(out.len(), 1);
        assert_eq!(s(status_of(&out), "failure_reason"), Some("empty_file"));
    }

    #[test]
    fn an_unknown_keychain_version_is_refused_rather_than_guessed_at() {
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("iCloud"));
        let bytes = keychain_versioned(
            0x0002_0000,
            &[
                table(0, &[info_record(0, 0, "CSSM_DL_DB_SCHEMA_INFO")], None),
                table(1, &generic_attr_decls(), None),
                table(GENERIC, &[record(1, &wrapped(8), &attrs)], None),
            ],
        );
        let out = run(bytes, "login.keychain-db", LOGIN_PATH);
        let st = status_of(&out);
        assert_eq!(s(st, "failure_reason"), Some("unknown_keychain_version"));
        assert!(s(st, "failure_detail")
            .expect("a detail")
            .contains("will not guess the layout"));
        assert!(of_type(&out, "KeychainItem").is_empty());
    }

    #[test]
    fn a_keychain_whose_schema_cannot_be_read_yields_no_items_and_says_why() {
        // `kych` and the right version, but the schema offset points nowhere
        // useful. Decoding records against a schema that was not read would be
        // decoding them against a guess.
        let mut bytes = keychain_with(&[]);
        let past_the_end = be(bytes.len() as u32 - 4);
        bytes[12..16].copy_from_slice(&past_the_end);
        let out = run(bytes, "login.keychain-db", LOGIN_PATH);
        assert_eq!(
            s(status_of(&out), "failure_reason"),
            Some("schema_unreadable")
        );
    }

    #[test]
    fn a_keychain_under_any_name_is_read_because_selection_is_by_content() {
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("iCloud"));
        let out = run(
            keychain_with(&[record(1, &wrapped(8), &attrs)]),
            "carved-000456.bin",
            "/carved/carved-000456.bin",
        );
        assert_eq!(of_type(&out, "KeychainItem").len(), 1);
    }

    #[test]
    fn a_short_read_is_reported_rather_than_read_as_the_whole_keychain() {
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("iCloud"));
        let mut bytes = keychain_with(&[record(1, &wrapped(8), &attrs)]);
        let full = bytes.len();
        bytes.truncate(full - 16);
        let out = run_source(
            Arc::new(TruncatedSource::new(bytes, full as u64)),
            "login.keychain-db",
            LOGIN_PATH,
        );
        let st = status_of(&out);
        assert_eq!(n(st, "declared_size"), Some(full as i64));
        assert!(n(st, "bytes_staged").unwrap() < full as i64);
        assert!(st.get("content_incomplete").is_some());
    }

    #[test]
    fn every_emitted_record_names_its_source_file_and_format() {
        let mut attrs = no_attrs();
        attrs[A_PRINT] = Some(text_blob("iCloud"));
        let out = run(
            keychain_with(&[record(1, &wrapped(8), &attrs)]),
            "login.keychain-db",
            LOGIN_PATH,
        );
        for a in &out {
            assert_eq!(s(&a.metadata, "source_format"), Some("apple_keychain_kych"));
            assert_eq!(
                s(&a.metadata, "source_file_name"),
                Some("login.keychain-db")
            );
        }
    }

    // --- the real keychains ---------------------------------------------------

    /// **The two real keychains from the Magnet 2021 macOS image**, read
    /// through the production path.
    ///
    /// The answers asserted here are the ones an examiner would put in a
    /// report, and none of them needed a password: the account's Apple ID, the
    /// Apple account number, the fact of an iOS backup, and a stored AirPort
    /// network password in the system keychain.
    #[test]
    fn the_real_macos_keychains_read_as_the_accounts_they_hold() {
        let root = home("ctf-evidence/macos2021/tree");
        let login = root.join("Users/eliflatt/Library/Keychains/login.keychain-db");
        let system = root.join("Library/Keychains/System.keychain");
        let (Ok(login_bytes), Ok(system_bytes)) = (std::fs::read(&login), std::fs::read(&system))
        else {
            eprintln!("skipping: the macOS corpus keychains are not present (gitignored)");
            return;
        };
        assert_eq!(login_bytes.len(), 83_168);
        assert_eq!(system_bytes.len(), 37_904);

        // --- the user's login keychain ---
        let out = run(
            login_bytes,
            "login.keychain-db",
            "/private/var/root/../Users/eliflatt/Library/Keychains/login.keychain-db",
        );
        let st = status_of(&out);
        assert_eq!(n(st, "relations"), Some(11));
        assert!(
            st.get("record_count_disagreements").is_none(),
            "every relation's live-record count matches its own table header; a disagreement \
             means the free-list rule is reading this file wrongly"
        );
        let items = of_type(&out, "KeychainItem");
        assert_eq!(
            items.len(),
            52,
            "23 generic passwords, 23 symmetric keys, 3 public and 3 private keys"
        );
        assert_eq!(
            n(st, "items_with_locked_secret"),
            Some(52),
            "every item in a user keychain carries a wrapped secret"
        );

        let generic: Vec<&&Value> = items
            .iter()
            .filter(|i| s(i, "item_kind") == Some("generic_password"))
            .collect();
        assert_eq!(generic.len(), 23);

        let icloud = generic
            .iter()
            .find(|i| s(i, "service") == Some("iCloud"))
            .expect("the account's iCloud credential");
        assert_eq!(
            s(icloud, "PrintName"),
            Some("e.flatt610@gmail.com"),
            "the Apple ID, in the clear, out of a keychain nobody can open"
        );
        assert_eq!(s(icloud, "account"), Some("20118734345"));
        assert_eq!(s(icloud, "created"), Some("20210212003531Z"));
        assert_eq!(s(icloud, "secret_state"), Some("locked"));

        let backup = generic
            .iter()
            .find(|i| s(i, "service") == Some("iOS Backup"))
            .expect("an iOS backup was made on this machine");
        assert_eq!(
            s(backup, "account"),
            Some("518e8d766f9b3e76db216f35fdb6b0604e50f61b")
        );
        assert_eq!(s(backup, "creator_code"), Some("aapl"));

        // A comment the file carries verbatim, which is what says what a key
        // is for without decrypting it.
        let persistent = generic
            .iter()
            .find(|i| s(i, "service") == Some("Apple Persistent State Encryption"))
            .expect("the window-snapshot key");
        assert!(s(persistent, "comment")
            .expect("its comment")
            .contains("encrypt window snapshots"));

        let services: Vec<&str> = generic.iter().filter_map(|i| s(i, "service")).collect();
        for expected in [
            "com.apple.assistant",
            "com.apple.continuity.encryption",
            "ProtectedCloudStorage",
        ] {
            assert!(
                services.contains(&expected),
                "{expected} is in this keychain; got {services:?}"
            );
        }
        assert_eq!(
            services.len(),
            22,
            "twenty-two of the twenty-three name a service; the twenty-third carries an empty \
             service blob and is reported with no service rather than with an empty one"
        );
        let webcrypto = generic
            .iter()
            .find(|i| s(i, "PrintName") == Some("Safari WebCrypto Master Key"))
            .expect("the item whose service blob is empty is still reported");
        assert!(
            webcrypto.get("service").is_none(),
            "an empty service blob is an absent service, not an empty string"
        );
        assert_eq!(
            s(webcrypto, "account"),
            Some("com.apple.WebKit.WebCrypto.master+com.apple.Safari")
        );
        // Not one secret was read, and every item says so.
        for item in &items {
            assert_eq!(s(item, "secret_state"), Some("locked"));
            assert_eq!(s(item, "content_incomplete_reason"), Some("encrypted"));
        }
        let w = &st["master_key_wrapping"];
        assert_eq!(w["db_blob_version"], json!(0x0000_0200));
        assert_eq!(w["iterations"], json!(1000));
        assert_eq!(
            w["salt_hex"].as_str().expect("a salt").len(),
            40,
            "twenty bytes of PBKDF2 salt"
        );

        // --- the system keychain ---
        let out = run(
            system_bytes,
            "System.keychain",
            "/Library/Keychains/System.keychain",
        );
        let st = status_of(&out);
        assert_eq!(n(st, "relations"), Some(12));
        assert!(st.get("record_count_disagreements").is_none());
        let items = of_type(&out, "KeychainItem");

        let airport = items
            .iter()
            .find(|i| s(i, "service") == Some("AirPort"))
            .expect("a stored wireless network password");
        assert_eq!(
            s(airport, "PrintName"),
            Some("Guest"),
            "the SSID whose password this machine stored"
        );
        assert_eq!(
            s(airport, "kind_description"),
            Some("AirPort network password")
        );
        assert_eq!(s(airport, "secret_state"), Some("locked"));

        // Certificates are not encrypted, and their bytes are carried out.
        let certs: Vec<&&Value> = items
            .iter()
            .filter(|i| s(i, "item_kind") == Some("certificate"))
            .collect();
        assert_eq!(certs.len(), 2);
        for cert in &certs {
            assert_eq!(s(cert, "secret_state"), Some("plaintext"));
        }
        let names: Vec<&str> = certs.iter().filter_map(|c| s(c, "PrintName")).collect();
        assert!(names.contains(&"com.apple.systemdefault"));
        assert!(names.contains(&"com.apple.kerberos.kdc"));

        let files: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();
        assert_eq!(files.len(), 2, "both certificates are carried out whole");
        for f in &files {
            let size = n(&f.metadata, "size").expect("a size");
            assert!(size > 800, "a real certificate, not a stub: {size} bytes");
            let src = f.data.as_ref().expect("the bytes are attached");
            let mut head = [0u8; 2];
            assert_eq!(src.read_at(0, &mut head).unwrap(), 2);
            assert_eq!(
                head[0], 0x30,
                "DER: a SEQUENCE tag is the first byte of an X.509 certificate"
            );
        }

        let w = &st["master_key_wrapping"];
        assert_eq!(
            w["db_blob_version"],
            json!(0x0000_0100),
            "the system keychain's DbBlob is the older version, which is why the version is \
             read rather than assumed"
        );
    }
}
