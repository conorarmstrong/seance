//! TLS on a reassembled stream: who was asked for, what was agreed, and the
//! certificate the server presented (`ROADMAP` §4.3 stage 2).
//!
//! # What is readable in an encrypted conversation
//!
//! The handshake is in the clear until the cipher changes, and it carries the
//! three things an examiner most often needs from traffic they cannot read:
//!
//! * the **server name** the client asked for (`server_name`, "SNI"), which is
//!   the only place a domain appears when the DNS was resolved elsewhere or
//!   over an encrypted resolver;
//! * the **client's fingerprint** — the exact list of ciphers, extensions,
//!   groups and point formats it offered, in order, summarised as JA3. Two
//!   hosts running the same malware family offer the same list, and it is
//!   nothing like the list any browser offers;
//! * before TLS 1.3, the server's **certificate**, whose names, issuer and
//!   validity window are read by [`crate::x509`].
//!
//! # TLS 1.3 encrypts the certificate, and that is a finding, not an absence
//!
//! From TLS 1.3 the certificate is inside the encrypted extensions, so a
//! capture holds the server name and no certificate at all. "No certificate
//! was presented" and "the certificate cannot be seen in this version of the
//! protocol" are different statements, and only the first is a fact about the
//! server — so [`Handshake::certificates_unavailable`] says which applies and
//! the record carries the sentence.
//!
//! # Read up to the change of cipher, and not one byte past it
//!
//! Everything after a `ChangeCipherSpec` (or, in TLS 1.3, after the first
//! application-data record) is ciphertext. It is counted, so the reader knows
//! the conversation continued, and it is never parsed: a "handshake message"
//! read out of ciphertext is noise presented as evidence.

use std::collections::BTreeSet;

/// Records walked in one direction. A long-lived connection holds many more;
/// the handshake is in the first few, and past this the walk stops and says
/// so.
pub const MAX_RECORDS: usize = 4096;

/// Bytes of cleartext handshake assembled in one direction. A certificate
/// chain is the large part of it and rarely exceeds a few tens of kilobytes.
pub const MAX_HANDSHAKE_BYTES: usize = 256 * 1024;

/// Certificates read from one chain.
pub const MAX_CERTIFICATES: usize = 16;

/// The largest a TLS record may be: 2^14 bytes of plaintext plus the 2048
/// bytes of expansion RFC 5246 and RFC 8446 allow a protected record. A
/// record claiming more than this is not a TLS record.
pub const MAX_RECORD_LENGTH: usize = 16_384 + 2_048;

const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
const CONTENT_APPLICATION_DATA: u8 = 23;

const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_SERVER_HELLO: u8 = 2;
const HANDSHAKE_CERTIFICATE: u8 = 11;

/// Which end of the conversation these bytes came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

/// Whether these bytes begin a TLS stream, and which end sent them.
///
/// Strict on purpose, and on the record layer rather than on a port: the first
/// byte must be a handshake record, its version must be one TLS has used, and
/// the first handshake byte must be a hello. A great deal of binary traffic
/// begins with a byte that is not 22, and no traffic that begins with `GET `
/// is TLS.
pub fn sniff(bytes: &[u8]) -> Option<Side> {
    let record = record_at(bytes, 0)?;
    if record.content_type != CONTENT_HANDSHAKE {
        return None;
    }
    match bytes.get(5).copied()? {
        HANDSHAKE_CLIENT_HELLO => Some(Side::Client),
        HANDSHAKE_SERVER_HELLO => Some(Side::Server),
        _ => None,
    }
}

/// One record's header, as declared.
struct RecordHeader {
    content_type: u8,
    version: u16,
    length: usize,
}

/// Read a record header at `offset`, or refuse it.
fn record_at(bytes: &[u8], offset: usize) -> Option<RecordHeader> {
    let header = bytes.get(offset..offset.checked_add(5)?)?;
    let content_type = header[0];
    if !matches!(
        content_type,
        CONTENT_CHANGE_CIPHER_SPEC | CONTENT_ALERT | CONTENT_HANDSHAKE | CONTENT_APPLICATION_DATA
    ) {
        return None;
    }
    // Every TLS and SSL 3 version is 3.x; the record layer of TLS 1.3 still
    // says 3.3. A major version that is not 3 is not TLS.
    if header[1] != 3 || header[2] > 4 {
        return None;
    }
    Some(RecordHeader {
        content_type,
        version: u16::from_be_bytes([header[1], header[2]]),
        length: usize::from(u16::from_be_bytes([header[3], header[4]])),
    })
}

/// Why the walk over one direction's records stopped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Stop {
    /// The prefix ended exactly at a record boundary: everything in it was
    /// walked.
    #[default]
    EndOfPrefix,
    /// The prefix ends inside a record. The record's own length says how much
    /// is missing, and the bytes present are not read as a whole record.
    PartialRecord {
        at: u64,
        declared: usize,
        present: usize,
    },
    /// A record claiming more than [`MAX_RECORD_LENGTH`].
    RecordTooLong { at: u64, declared: usize },
    /// Bytes that are not a TLS record where one should begin. The stream was
    /// TLS up to here, so this is a fact about these bytes and not about the
    /// stream.
    NotARecord { at: u64 },
    /// [`MAX_RECORDS`] records were walked.
    RecordCeiling { at: u64 },
    /// The cleartext handshake reached [`MAX_HANDSHAKE_BYTES`].
    HandshakeCeiling { at: u64 },
}

impl Stop {
    pub fn as_str(&self) -> &'static str {
        match self {
            Stop::EndOfPrefix => "end_of_prefix",
            Stop::PartialRecord { .. } => "partial_record",
            Stop::RecordTooLong { .. } => "record_too_long",
            Stop::NotARecord { .. } => "not_a_record",
            Stop::RecordCeiling { .. } => "record_ceiling",
            Stop::HandshakeCeiling { .. } => "handshake_ceiling",
        }
    }

    /// Whether the walk saw every record in the readable prefix.
    pub fn is_complete(&self) -> bool {
        matches!(self, Stop::EndOfPrefix)
    }

    pub fn statement(&self) -> String {
        match self {
            Stop::EndOfPrefix => {
                "Every record in the readable bytes of this direction was walked.".to_string()
            }
            Stop::PartialRecord {
                at,
                declared,
                present,
            } => format!(
                "The readable bytes ended inside the record at offset {at}, which declared \
                 {declared} bytes and has {present}; it was not read."
            ),
            Stop::RecordTooLong { at, declared } => format!(
                "The record at offset {at} declared {declared} bytes, which is more than a TLS \
                 record may hold ({MAX_RECORD_LENGTH}); the walk stopped rather than trusting \
                 the length."
            ),
            Stop::NotARecord { at } => format!(
                "The bytes at offset {at} are not a TLS record header. The stream was TLS up to \
                 here; what follows was not read."
            ),
            Stop::RecordCeiling { at } => format!(
                "This build walks {MAX_RECORDS} records of one direction; the walk stopped at \
                 offset {at} and the records after it were not read."
            ),
            Stop::HandshakeCeiling { at } => format!(
                "The cleartext handshake reached this build's ceiling of {MAX_HANDSHAKE_BYTES} \
                 bytes at offset {at}; the rest was not assembled."
            ),
        }
    }
}

/// Why a direction that should have carried a certificate does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificatesUnavailable {
    /// TLS 1.3 was negotiated, which encrypts the certificate. A capture
    /// cannot hold it, whatever the server sent.
    EncryptedByTls13,
    /// The version in use sends the certificate in the clear and this
    /// conversation's cleartext holds none: a resumed session, a handshake
    /// that failed before it, or a certificate in bytes the capture lost.
    NotInTheCleartext,
    /// There is no `ServerHello` in the cleartext at all, so the version is
    /// not known and neither of the other two reasons can be claimed. A
    /// server that answered with an alert, a handshake that died, or a
    /// capture holding only one side of the conversation reaches this — and a
    /// record that carried no reason would read as a server that presented no
    /// certificate.
    NoServerHello,
}

impl CertificatesUnavailable {
    pub fn as_str(&self) -> &'static str {
        match self {
            CertificatesUnavailable::EncryptedByTls13 => "encrypted_by_tls13",
            CertificatesUnavailable::NotInTheCleartext => "not_in_the_cleartext",
            CertificatesUnavailable::NoServerHello => "no_server_hello_in_the_cleartext",
        }
    }

    pub fn statement(&self) -> &'static str {
        match self {
            CertificatesUnavailable::EncryptedByTls13 => {
                "This conversation negotiated TLS 1.3, which sends the server's certificate \
                 inside the encrypted extensions. NO CAPTURE OF TLS 1.3 CAN HOLD THE \
                 CERTIFICATE: its absence here says nothing about what the server presented."
            }
            CertificatesUnavailable::NotInTheCleartext => {
                "This conversation's version sends the certificate in the clear, and the \
                 cleartext this capture holds contains none. The session may have been resumed \
                 from an earlier one (whose handshake carried it), the handshake may have failed \
                 before it, or the bytes that carried it may be missing from the capture."
            }
            CertificatesUnavailable::NoServerHello => {
                "There is no ServerHello in this conversation's cleartext, so this build does \
                 not know which version was negotiated and cannot say whether a certificate \
                 could have been visible at all. The server may have answered with an alert, \
                 the handshake may have died, or the capture may hold only one side of the \
                 conversation. THE ABSENCE OF A CERTIFICATE HERE SAYS NOTHING ABOUT WHAT THE \
                 SERVER PRESENTED."
            }
        }
    }
}

/// What one direction of a conversation said in the clear.
#[derive(Debug, Clone, Default)]
pub struct Handshake {
    /// Records walked, whatever their content type.
    pub records: usize,
    /// Every version the record layer stated, which is not the version
    /// negotiated.
    pub record_versions: BTreeSet<u16>,
    /// Cleartext handshake messages read.
    pub handshake_messages: usize,
    /// Whether the assembled handshake ended inside a message.
    pub handshake_message_truncated: bool,
    pub client_hello: Option<ClientHello>,
    pub server_hello: Option<ServerHello>,
    /// The chain as sent, each entry the certificate's DER.
    pub certificates: Vec<Vec<u8>>,
    /// Whether the `Certificate` message's own lengths added up.
    pub certificate_chain_complete: bool,
    pub certificates_beyond_cap: usize,
    /// Cleartext alerts, as (level, description). An `unknown_ca` here is the
    /// client refusing the certificate, which is worth reading.
    pub alerts: Vec<(u8, u8)>,
    /// Where the cipher changed, after which nothing is parsed.
    pub change_cipher_spec_at: Option<u64>,
    /// Records this build did not parse because they are encrypted.
    pub encrypted_records: usize,
    pub stop: Stop,
}

impl Handshake {
    /// Whether every record in the readable prefix was walked and every
    /// message in the cleartext handshake was whole.
    pub fn is_complete(&self) -> bool {
        self.stop.is_complete() && !self.handshake_message_truncated
    }

    /// The version in use, as far as this direction states it.
    pub fn negotiated_version(&self) -> Option<u16> {
        self.server_hello
            .as_ref()
            .map(ServerHello::negotiated_version)
    }

    /// Why this direction carries no certificate, where that needs saying.
    /// `None` when it carries one, or when it is not the direction that would.
    pub fn certificates_unavailable(&self) -> Option<CertificatesUnavailable> {
        if !self.certificates.is_empty() {
            return None;
        }
        // Three states, not two. Without a ServerHello the version is not
        // known, and a record carrying no reason at all would read as a
        // server that presented no certificate.
        let Some(version) = self.negotiated_version() else {
            return Some(CertificatesUnavailable::NoServerHello);
        };
        Some(if version >= 0x0304 {
            CertificatesUnavailable::EncryptedByTls13
        } else {
            CertificatesUnavailable::NotInTheCleartext
        })
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "records": self.records,
            "record_versions": self.record_versions.iter().map(|v| version_name(*v))
                .collect::<Vec<_>>(),
            "handshake_messages": self.handshake_messages,
            "handshake_message_truncated": self.handshake_message_truncated,
            "certificates": self.certificates.len(),
            "certificate_chain_complete": self.certificate_chain_complete,
            "certificates_beyond_cap": self.certificates_beyond_cap,
            "alerts": self.alerts.iter().map(|(level, description)| serde_json::json!({
                "level": alert_level_name(*level),
                "description": alert_description_name(*description),
                "description_number": description,
            })).collect::<Vec<_>>(),
            "change_cipher_spec_at": self.change_cipher_spec_at,
            "encrypted_records": self.encrypted_records,
            "stop": self.stop.as_str(),
            "stop_statement": self.stop.statement(),
            "complete": self.is_complete(),
        })
    }
}

/// What a client offered.
#[derive(Debug, Clone, Default)]
pub struct ClientHello {
    /// The version in the hello's own field, which from TLS 1.3 is frozen at
    /// 1.2 and says nothing about what was offered.
    pub legacy_version: u16,
    /// A non-empty session id is an attempt to resume a session whose
    /// handshake — and certificate — this capture may not hold.
    pub session_id_bytes: usize,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    /// Extension types in the order sent, which is what a fingerprint is of.
    pub extensions: Vec<u16>,
    pub server_name: Option<String>,
    /// `server_name` entries that were not a host name.
    pub other_server_names: usize,
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    /// GREASE values seen and deliberately left out of the lists above: they
    /// are values no implementation implements, sent to keep middleboxes
    /// honest, and counting them would make one client's fingerprint unique.
    pub grease_values: usize,
    /// The encrypted-client-hello extension. Where it is present the server
    /// name may be absent BY DESIGN, and its absence is not a finding.
    pub encrypted_client_hello: bool,
    pub early_data: bool,
    pub ja3: String,
    pub ja3_md5: String,
    /// Whether the hello's own bytes ran out before its fields did.
    pub truncated: bool,
}

impl ClientHello {
    /// The highest version this client offered: the `supported_versions`
    /// extension where it sent one, and the legacy field where it did not.
    pub fn highest_version_offered(&self) -> Option<u16> {
        self.supported_versions
            .iter()
            .copied()
            .max()
            .or(Some(self.legacy_version))
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "legacy_version": version_name(self.legacy_version),
            "highest_version_offered": self.highest_version_offered().map(version_name),
            "session_id_bytes": self.session_id_bytes,
            "server_name": self.server_name,
            "other_server_names": self.other_server_names,
            "alpn": self.alpn,
            "cipher_suites": self.cipher_suites,
            "cipher_suite_names": self.cipher_suites.iter()
                .map(|c| cipher_name(*c).map(str::to_string)
                    .unwrap_or_else(|| format!("0x{c:04X}")))
                .collect::<Vec<_>>(),
            "known_weak_ciphers_offered": self.cipher_suites.iter()
                .filter(|c| cipher_is_known_weak(**c)).count(),
            "extensions": self.extensions,
            "supported_versions": self.supported_versions.iter().map(|v| version_name(*v))
                .collect::<Vec<_>>(),
            "supported_groups": self.supported_groups,
            "ec_point_formats": self.ec_point_formats,
            "signature_algorithms": self.signature_algorithms,
            "grease_values": self.grease_values,
            "encrypted_client_hello": self.encrypted_client_hello,
            "early_data": self.early_data,
            "ja3": self.ja3,
            "ja3_md5": self.ja3_md5,
            "truncated": self.truncated,
        })
    }
}

/// What a server agreed to.
#[derive(Debug, Clone, Default)]
pub struct ServerHello {
    pub legacy_version: u16,
    pub session_id_bytes: usize,
    pub cipher_suite: u16,
    pub compression_method: u8,
    pub extensions: Vec<u16>,
    /// The version from the `supported_versions` extension, which overrides
    /// the legacy field from TLS 1.3.
    pub supported_version: Option<u16>,
    pub alpn: Option<String>,
    pub truncated: bool,
}

impl ServerHello {
    /// The version in use: the extension where the server sent one, the
    /// legacy field where it did not.
    pub fn negotiated_version(&self) -> u16 {
        self.supported_version.unwrap_or(self.legacy_version)
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "legacy_version": version_name(self.legacy_version),
            "negotiated_version": version_name(self.negotiated_version()),
            "negotiated_version_number": self.negotiated_version(),
            "session_id_bytes": self.session_id_bytes,
            "cipher_suite": self.cipher_suite,
            "cipher_suite_name": cipher_name(self.cipher_suite).map(str::to_string)
                .unwrap_or_else(|| format!("0x{:04X}", self.cipher_suite)),
            "cipher_is_known_weak": cipher_is_known_weak(self.cipher_suite),
            "extensions": self.extensions,
            "alpn": self.alpn,
            "truncated": self.truncated,
        })
    }
}

/// Read one direction's records, and what the cleartext handshake said.
///
/// `None` when the bytes are not TLS at all: a session record with every
/// field empty is worse than no record, because it says a conversation was
/// TLS when nothing about it was read.
pub fn read_direction(prefix: &[u8]) -> Option<Handshake> {
    sniff(prefix)?;
    let mut out = Handshake::default();
    let mut handshake: Vec<u8> = Vec::new();
    let mut offset = 0usize;
    // Everything after the cipher changes is ciphertext. In TLS 1.3 the
    // change-cipher-spec record is a compatibility relic and the real switch
    // is the first application-data record, so either closes the cleartext.
    let mut encrypted = false;
    loop {
        if offset == prefix.len() {
            out.stop = Stop::EndOfPrefix;
            break;
        }
        if out.records >= MAX_RECORDS {
            out.stop = Stop::RecordCeiling { at: offset as u64 };
            break;
        }
        let Some(header) = record_at(prefix, offset) else {
            // Fewer than five bytes left is a cut header, not a foreign one.
            out.stop = if prefix.len().saturating_sub(offset) < 5 {
                Stop::PartialRecord {
                    at: offset as u64,
                    declared: 5,
                    present: prefix.len() - offset,
                }
            } else {
                Stop::NotARecord { at: offset as u64 }
            };
            break;
        };
        if header.length > MAX_RECORD_LENGTH {
            out.stop = Stop::RecordTooLong {
                at: offset as u64,
                declared: header.length,
            };
            break;
        }
        let body_start = offset + 5;
        let Some(body) = prefix.get(body_start..body_start + header.length) else {
            out.stop = Stop::PartialRecord {
                at: offset as u64,
                declared: header.length,
                present: prefix.len().saturating_sub(body_start),
            };
            break;
        };
        out.records += 1;
        out.record_versions.insert(header.version);
        match header.content_type {
            CONTENT_CHANGE_CIPHER_SPEC => {
                out.change_cipher_spec_at = Some(offset as u64);
                encrypted = true;
            }
            CONTENT_APPLICATION_DATA => {
                out.encrypted_records += 1;
                encrypted = true;
            }
            CONTENT_ALERT if !encrypted => {
                if body.len() >= 2 {
                    out.alerts.push((body[0], body[1]));
                }
            }
            CONTENT_HANDSHAKE if !encrypted => {
                if handshake.len().saturating_add(body.len()) > MAX_HANDSHAKE_BYTES {
                    out.stop = Stop::HandshakeCeiling { at: offset as u64 };
                    break;
                }
                handshake.extend_from_slice(body);
            }
            // A handshake or alert record after the change of cipher is
            // ciphertext that happens to be labelled; it is counted and not
            // read.
            _ => out.encrypted_records += 1,
        }
        offset = body_start + header.length;
    }
    read_handshake(&handshake, &mut out);
    Some(out)
}

/// Walk the assembled cleartext handshake, message by message.
///
/// The messages are read from the assembled buffer rather than per record on
/// purpose: TLS is free to split one message across records and to pack
/// several into one, and a certificate chain too large for a single record is
/// the ordinary case.
fn read_handshake(bytes: &[u8], out: &mut Handshake) {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let Some(header) = bytes.get(offset..offset + 4) else {
            out.handshake_message_truncated = true;
            return;
        };
        let kind = header[0];
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]))
            | (usize::from(header[1]) << 16);
        let body_start = offset + 4;
        let Some(body) = bytes.get(body_start..body_start + length) else {
            out.handshake_message_truncated = true;
            return;
        };
        out.handshake_messages += 1;
        match kind {
            HANDSHAKE_CLIENT_HELLO => out.client_hello = Some(read_client_hello(body)),
            HANDSHAKE_SERVER_HELLO => out.server_hello = Some(read_server_hello(body)),
            HANDSHAKE_CERTIFICATE => read_certificates(body, out),
            _ => {}
        }
        offset = body_start + length;
    }
}

/// The certificate chain, in the order the server sent it — which is the order
/// it claims the chain runs in, leaf first.
fn read_certificates(body: &[u8], out: &mut Handshake) {
    let Some(total) = body
        .get(0..3)
        .map(|b| usize::from(u16::from_be_bytes([b[1], b[2]])) | (usize::from(b[0]) << 16))
    else {
        return;
    };
    let Some(list) = body.get(3..3 + total) else {
        // The message's own length disagrees with the chain's: neither is
        // trusted over the other, and nothing is read from the difference.
        out.certificate_chain_complete = false;
        return;
    };
    let mut offset = 0usize;
    while offset < list.len() {
        let Some(header) = list.get(offset..offset + 3) else {
            out.certificate_chain_complete = false;
            return;
        };
        let length = usize::from(u16::from_be_bytes([header[1], header[2]]))
            | (usize::from(header[0]) << 16);
        let start = offset + 3;
        let Some(der) = list.get(start..start + length) else {
            out.certificate_chain_complete = false;
            return;
        };
        if out.certificates.len() >= MAX_CERTIFICATES {
            out.certificates_beyond_cap += 1;
        } else {
            out.certificates.push(der.to_vec());
        }
        offset = start + length;
    }
    out.certificate_chain_complete = true;
}

/// The sixteen GREASE values (RFC 8701). A value no implementation
/// implements, sent to keep middleboxes honest.
fn is_grease(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && high & 0x0f == 0x0a
}

/// A cursor over a hello's body, which is a sequence of length-prefixed
/// vectors and can end anywhere.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
    truncated: bool,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor {
            bytes,
            at: 0,
            truncated: false,
        }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.bytes.get(self.at..end);
        match out {
            Some(bytes) => {
                self.at = end;
                Some(bytes)
            }
            None => {
                self.truncated = true;
                None
            }
        }
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    /// A vector whose length is one byte, then that many bytes.
    fn vector8(&mut self) -> Option<&'a [u8]> {
        let length = self.u8()? as usize;
        self.take(length)
    }

    /// A vector whose length is two bytes.
    fn vector16(&mut self) -> Option<&'a [u8]> {
        let length = self.u16()? as usize;
        self.take(length)
    }
}

/// Every u16 in a byte string, which is how TLS writes a list of them.
fn u16s(bytes: &[u8]) -> Vec<u16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect()
}

fn read_client_hello(body: &[u8]) -> ClientHello {
    let mut out = ClientHello::default();
    let mut cursor = Cursor::new(body);
    out.legacy_version = cursor.u16().unwrap_or_default();
    let _random = cursor.take(32);
    out.session_id_bytes = cursor.vector8().map_or(0, <[u8]>::len);
    let suites = cursor.vector16().unwrap_or(&[]);
    for suite in u16s(suites) {
        if is_grease(suite) {
            out.grease_values += 1;
        } else {
            out.cipher_suites.push(suite);
        }
    }
    out.compression_methods = cursor.vector8().unwrap_or(&[]).to_vec();
    let extensions = cursor.vector16().unwrap_or(&[]);
    read_extensions(extensions, |kind, value| match kind {
        0 => read_server_name(value, &mut out),
        10 => {
            for group in u16s(value.get(2..).unwrap_or(&[])) {
                if is_grease(group) {
                    out.grease_values += 1;
                } else {
                    out.supported_groups.push(group);
                }
            }
        }
        11 => {
            out.ec_point_formats = value
                .first()
                .and_then(|n| value.get(1..1 + usize::from(*n)))
                .unwrap_or(&[])
                .to_vec()
        }
        13 => out.signature_algorithms = u16s(value.get(2..).unwrap_or(&[])),
        16 => out.alpn = read_alpn(value),
        42 => out.early_data = true,
        43 => {
            for version in u16s(value.get(1..).unwrap_or(&[])) {
                if is_grease(version) {
                    out.grease_values += 1;
                } else {
                    out.supported_versions.push(version);
                }
            }
        }
        // The encrypted-client-hello extension (RFC 9660's code point, which
        // the drafts also used).
        0xfe0d => out.encrypted_client_hello = true,
        _ => {}
    });
    for kind in extension_types(extensions) {
        if is_grease(kind) {
            out.grease_values += 1;
        } else {
            out.extensions.push(kind);
        }
    }
    out.truncated = cursor.truncated;
    let ja3 = ja3_string(&out);
    out.ja3_md5 = seance_core::hashing::compute_hashes(ja3.as_bytes()).md5;
    out.ja3 = ja3;
    out
}

/// The JA3 string: the hello's own version, its cipher suites, its extension
/// types, its supported groups and its EC point formats, each list joined with
/// `-` and the five fields joined with `,`. GREASE values are left out, as the
/// specification requires — a fingerprint that included them would be unique
/// per connection and would identify nothing.
fn ja3_string(hello: &ClientHello) -> String {
    let join_u16 = |values: &[u16]| {
        values
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join("-")
    };
    format!(
        "{},{},{},{},{}",
        hello.legacy_version,
        join_u16(&hello.cipher_suites),
        join_u16(&hello.extensions),
        join_u16(&hello.supported_groups),
        hello
            .ec_point_formats
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("-")
    )
}

fn read_server_hello(body: &[u8]) -> ServerHello {
    let mut out = ServerHello::default();
    let mut cursor = Cursor::new(body);
    out.legacy_version = cursor.u16().unwrap_or_default();
    let _random = cursor.take(32);
    out.session_id_bytes = cursor.vector8().map_or(0, <[u8]>::len);
    out.cipher_suite = cursor.u16().unwrap_or_default();
    out.compression_method = cursor.u8().unwrap_or_default();
    let extensions = cursor.vector16().unwrap_or(&[]);
    read_extensions(extensions, |kind, value| match kind {
        16 => out.alpn = read_alpn(value).into_iter().next(),
        43 => out.supported_version = u16s(value).first().copied(),
        _ => {}
    });
    out.extensions = extension_types(extensions)
        .into_iter()
        .filter(|k| !is_grease(*k))
        .collect();
    out.truncated = cursor.truncated;
    out
}

/// Walk an extension block, handing each type and its value to `f`.
fn read_extensions(bytes: &[u8], mut f: impl FnMut(u16, &[u8])) {
    let mut cursor = Cursor::new(bytes);
    while cursor.at < bytes.len() {
        let Some(kind) = cursor.u16() else { return };
        let Some(value) = cursor.vector16() else {
            return;
        };
        f(kind, value);
    }
}

/// The extension types in the order they were sent.
fn extension_types(bytes: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    read_extensions(bytes, |kind, _| out.push(kind));
    out
}

/// The `server_name` extension: a list of names, of which the host name is
/// the one anybody sends. Others are counted, because a name of another kind
/// is still a name that was sent.
fn read_server_name(value: &[u8], out: &mut ClientHello) {
    let mut cursor = Cursor::new(value);
    let Some(list) = cursor.vector16() else {
        return;
    };
    let mut inner = Cursor::new(list);
    while inner.at < list.len() {
        let Some(kind) = inner.u8() else { return };
        let Some(name) = inner.vector16() else { return };
        if kind == 0 {
            if out.server_name.is_none() {
                out.server_name = Some(String::from_utf8_lossy(name).to_string());
            }
        } else {
            out.other_server_names += 1;
        }
    }
}

/// The `application_layer_protocol_negotiation` extension: the protocols
/// offered, or the one selected, in the order sent.
fn read_alpn(value: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = Cursor::new(value);
    let Some(list) = cursor.vector16() else {
        return out;
    };
    let mut inner = Cursor::new(list);
    while inner.at < list.len() {
        let Some(name) = inner.vector8() else {
            return out;
        };
        out.push(String::from_utf8_lossy(name).to_string());
    }
    out
}

/// A version number as the name it is known by. `0x0300` is SSL 3, which no
/// client should offer and some malware still does.
pub fn version_name(version: u16) -> &'static str {
    match version {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "unknown version",
    }
}

/// The cipher suites this build names. A suite it does not name is reported by
/// its number, which is the evidence.
pub fn cipher_name(suite: u16) -> Option<&'static str> {
    Some(match suite {
        0x0000 => "TLS_NULL_WITH_NULL_NULL",
        0x0001 => "TLS_RSA_WITH_NULL_MD5",
        0x0002 => "TLS_RSA_WITH_NULL_SHA",
        0x0003 => "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        0x0004 => "TLS_RSA_WITH_RC4_128_MD5",
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA",
        0x000A => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0033 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x0039 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        0x003C => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003D => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x0067 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        0x006B => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x009E => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009F => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        0xC009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xC00A => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xC013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xC014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xC023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xC024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xC027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xC028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xCCA9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xCCAA => "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        _ => return None,
    })
}

/// Whether a suite is one of the enumerated broken ones: no encryption at
/// all, export-grade keys, RC4, single DES or triple DES, or an MD5 MAC. An
/// enumerated list rather than a rule over names, so what it flags is
/// auditable, and it says nothing about a suite this build cannot name.
pub fn cipher_is_known_weak(suite: u16) -> bool {
    matches!(
        suite,
        0x0000 | 0x0001 | 0x0002 | 0x0003 | 0x0004 | 0x0005 | 0x000A
    )
}

fn alert_level_name(level: u8) -> &'static str {
    match level {
        1 => "warning",
        2 => "fatal",
        _ => "unknown level",
    }
}

/// The alert descriptions worth reading by name. `unknown_ca` and
/// `certificate_expired` are a client refusing a certificate, which is a
/// finding about the server it was offered by.
fn alert_description_name(description: u8) -> &'static str {
    match description {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        21 => "decryption_failed",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        90 => "user_canceled",
        100 => "no_renegotiation",
        109 => "missing_extension",
        112 => "unrecognized_name",
        120 => "no_application_protocol",
        _ => "unknown description",
    }
}

/// Sessions one capture will hand up as records.
///
/// One per conversation the stream table can hold. Every session is parsed
/// and held whatever this says; it bounds only the records written. It was
/// 10,000, and on DFIR Madness Case 001 an RDP brute force that negotiated TLS
/// on some fourteen thousand connections spent it, so every session later in
/// the capture — the whole post-compromise period — had no record.
pub const MAX_SESSIONS_PER_CAPTURE: usize = crate::reassemble::MAX_STREAMS / 2;

/// One TCP conversation's TLS, as far as the two reassembled streams allow.
#[derive(Debug, Clone)]
pub struct Session {
    pub flow: crate::flows::FlowKey,
    /// The endpoint whose bytes were a ClientHello, and the one that answered.
    pub client: crate::flows::Endpoint,
    pub server: crate::flows::Endpoint,
    pub client_side: Option<Handshake>,
    pub server_side: Option<Handshake>,
    /// What each direction's stream offered the reader, and what it could
    /// not: the gaps, the overlap conflicts, the reassembler's own ceiling
    /// and whether the connection's start was captured. Without these a
    /// session read from a stream with a hole in it reads as one read in
    /// full, because [`read_direction`] is only ever handed the contiguous
    /// prefix and cannot see what was withheld from it.
    pub client_stream: crate::http::StreamFacts,
    pub server_stream: crate::http::StreamFacts,
    /// The chain the server presented, parsed. Shorter than the chain sent
    /// where a certificate would not parse; `unparsable_certificates` says so.
    pub certificates: Vec<crate::x509::Certificate>,
    pub unparsable_certificates: usize,
}

impl Session {
    /// The name the client asked for, which is the one thing an encrypted
    /// conversation reliably states.
    pub fn server_name(&self) -> Option<&str> {
        self.client_side
            .as_ref()?
            .client_hello
            .as_ref()?
            .server_name
            .as_deref()
    }

    /// Whether this capture holds the client's `ClientHello` at all.
    ///
    /// Every field read out of that message — the server name, the
    /// fingerprint, the ciphers offered, whether resumption was attempted —
    /// is absent for two entirely different reasons: the client did not send
    /// it, or the capture does not hold the client's half. This is what tells
    /// them apart, and the record carries it beside the fields so none of
    /// them has to be read as a claim about the client.
    pub fn client_hello_read(&self) -> bool {
        self.client_side
            .as_ref()
            .is_some_and(|h| h.client_hello.is_some())
    }

    /// The version in use, from the server's own hello.
    pub fn negotiated_version(&self) -> Option<u16> {
        self.server_side.as_ref()?.negotiated_version()
    }

    /// Why the certificate is not here, where that needs saying.
    pub fn certificates_unavailable(&self) -> Option<CertificatesUnavailable> {
        if !self.certificates.is_empty() {
            return None;
        }
        match self.server_side.as_ref() {
            Some(handshake) => handshake.certificates_unavailable(),
            // The server's direction is not in this capture at all, which is
            // the same statement as a direction with no ServerHello in it:
            // nothing here is evidence about what the server presented.
            None => Some(CertificatesUnavailable::NoServerHello),
        }
    }

    /// Whether both directions were walked end to end — of the records in the
    /// prefix, AND of the stream the prefix came from.
    pub fn is_complete(&self) -> bool {
        [self.client_side.as_ref(), self.server_side.as_ref()]
            .iter()
            .flatten()
            .all(|h| h.is_complete())
            && self.unparsable_certificates == 0
            && [&self.client_stream, &self.server_stream]
                .iter()
                .all(|f| !f.present || f.is_complete())
    }
}

/// Read every TCP conversation's TLS.
///
/// Both halves are needed, as for HTTP: the streams hold the bytes and the
/// flow table holds which endpoint sent them. Which side is the client is
/// decided by which one sent a ClientHello, not by who this capture saw speak
/// first — a capture that begins mid-connection has no handshake to tell it.
pub fn sessions(
    flows: &crate::flows::FlowTable,
    streams: &[crate::reassemble::Stream],
) -> Vec<Session> {
    use crate::flows::{Direction, FlowKey};
    use crate::reassemble::{index_streams, stream_of};
    let mut out = Vec::new();
    // Indexed once, for the reason `http::conversations` builds one.
    let index = index_streams(streams);
    for flow in flows.flows() {
        let key = FlowKey::new(flow.protocol, flow.initiator, flow.responder);
        fn prefix(s: Option<&crate::reassemble::Stream>) -> &[u8] {
            s.map_or(&[][..], |s| s.contiguous_prefix())
        }
        let outbound = stream_of(&index, key, Direction::Out);
        let inbound = stream_of(&index, key, Direction::In);
        let out_side = sniff(prefix(outbound));
        let in_side = sniff(prefix(inbound));
        if out_side.is_none() && in_side.is_none() {
            continue;
        }
        // The client is the side that sent the ClientHello. Where only one
        // direction is readable, the other side's role follows from it.
        let client_is_initiator = match (out_side, in_side) {
            (Some(Side::Client), _) => true,
            (_, Some(Side::Client)) => false,
            (Some(Side::Server), _) => false,
            (_, Some(Side::Server)) => true,
            (None, None) => continue,
        };
        let (client_stream, server_stream) = if client_is_initiator {
            (outbound, inbound)
        } else {
            (inbound, outbound)
        };
        let (client, server) = if client_is_initiator {
            (flow.initiator, flow.responder)
        } else {
            (flow.responder, flow.initiator)
        };
        let client_side = read_direction(prefix(client_stream));
        let server_side = read_direction(prefix(server_stream));

        let mut certificates = Vec::new();
        let mut unparsable = 0usize;
        if let Some(handshake) = server_side.as_ref() {
            for der in &handshake.certificates {
                match crate::x509::Certificate::parse(der) {
                    Some(certificate) => certificates.push(certificate),
                    // A certificate that will not parse is counted, not
                    // dropped: the server sent one and this build could not
                    // read it, which is a different thing from no certificate.
                    None => unparsable += 1,
                }
            }
        }
        out.push(Session {
            flow: key,
            client,
            server,
            client_side,
            server_side,
            client_stream: crate::http::StreamFacts::of_stream(client_stream),
            server_stream: crate::http::StreamFacts::of_stream(server_stream),
            certificates,
            unparsable_certificates: unparsable,
        });
    }
    out
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tls_tests;
