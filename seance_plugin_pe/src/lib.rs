// the guard reads as the question being asked -- is this extension one of the
// module kinds -- and the pattern clippy prefers spreads it across three arms.
#![allow(clippy::redundant_guards)]
#![forbid(unsafe_code)]
//! PE / Authenticode analyser — a SigCheck-style module for Windows executables.
//!
//! Self-selects Windows PE files (`MZ`/`PE`) by content and emits one
//! `PeSignature` [`ParsedRecord`](ArtifactType::ParsedRecord) carrying what an
//! examiner needs to judge an executable:
//!
//! - **Authenticode**: is it signed? by whom (signer subject)? the issuing CA,
//!   certificate validity window, and — crucially — whether the signature is
//!   *internally intact* (we recompute the Authenticode PE hash and compare it
//!   to the digest inside the signature). We do NOT claim OS-level trust-chain
//!   validation (that needs a Microsoft/CA root store); "integrity: valid" means
//!   the bytes match what was signed, not that the signer is trusted.
//! - **Version resource**: CompanyName, ProductName, FileDescription,
//!   OriginalFilename, FileVersion, … — often the quickest tell on a dropped
//!   binary (missing/forged version blocks).
//! - **imphash**: the import-table hash used to cluster malware families.
//! - **Header facts + section entropy**: machine, subsystem, compile timestamp,
//!   and the highest section entropy (a packing hint).
//!
//! Robustness: a non-PE file, a truncated header, or a malformed signature never
//! panics and never fails the pipeline — the module simply emits less.

use der::{Decode, Reader};
use goblin::pe::PE;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{read_capped, read_exact_or_fail, IncompleteReason},
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Map, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tracing::debug;

/// Cap the bytes we pull for a single executable. PE analysis only needs the
/// headers, resource section, and the trailing certificate table, but those can
/// be anywhere, so we read the whole file up to a sane ceiling.
const MAX_PE_BYTES: u64 = 256 * 1024 * 1024;

pub struct PeSignatureParser;

impl ForensicsModule for PeSignatureParser {
    fn id(&self) -> &str {
        "plugin.executable.pe_signature"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(Vec::new());
        }
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        // Self-select by the DOS `MZ` magic, not filename. The read loops so a
        // chunked source that returns one byte per call is not mis-rejected.
        let mut head = [0u8; 2];
        if read_exact_or_fail(data.as_ref(), 0, &mut head, "DOS MZ magic").is_err()
            || head != [0x4D, 0x5A]
        {
            return Ok(Vec::new());
        }
        let declared = data.size();
        let bytes = read_capped(data.as_ref(), MAX_PE_BYTES);
        let analysed = bytes.len() as u64;
        let name = artifact.metadata.get("name").and_then(|v| v.as_str());
        let Some(record) = analyze(&bytes) else {
            // The DOS `MZ` magic already matched: this file claims to be a
            // Windows executable. Emitting nothing puts it beside every non-PE
            // file in the case, so a corrupt or deliberately malformed binary
            // reads as "not examined / not an executable" (B6-010).
            debug!(
                "PeSignatureParser: {} matched MZ but would not parse as a PE",
                artifact.id
            );
            return Ok(vec![unparsable_pe_record(
                artifact, name, analysed, declared,
            )]);
        };
        debug!(
            "PeSignatureParser produced a record for artifact {}",
            artifact.id
        );
        let mut record = record;
        // The certificate table lives at the very end of a signed image, so a
        // capped or short read makes a signed binary look unsigned. Never let
        // "we did not read that far" render as "this file is not signed"
        // (B2-052): say so, and withdraw the signature verdict.
        if analysed < declared {
            let reason = if declared > MAX_PE_BYTES {
                IncompleteReason::CapReached
            } else {
                IncompleteReason::ShortRead
            };
            record.insert("analysis_incomplete".into(), json!(true));
            record.insert("analysis_incomplete_reason".into(), json!(reason.as_str()));
            // B6-009: `analysis_incomplete` is local to this crate. The
            // frontend's incompleteness reader and the court report's
            // completeness census key on the standard pair, so a signed binary
            // that we could not read far enough to verify was invisible to both.
            record.insert("content_incomplete".into(), json!(true));
            record.insert("content_incomplete_reason".into(), json!(reason.as_str()));
            record.insert("bytes_analysed".into(), json!(analysed));
            record.insert("declared_size".into(), json!(declared));
            record.insert("max_analysis_bytes".into(), json!(MAX_PE_BYTES));
            record.insert(
                "message".into(),
                json!(
                    "Only part of this executable was read; the certificate table sits at \
                       the end of a signed image, so its signature could not be judged"
                ),
            );
            if record.get("signed") == Some(&json!(false)) {
                record.insert("signed".into(), Value::Null);
                record.insert(
                    "signature_integrity".into(),
                    json!("unverified (file not read in full; certificate table not reached)"),
                );
            }
        }
        if let Some(name) = name {
            record.insert("source_name".into(), json!(name));
        }
        carry_provenance(&mut record, artifact);
        Ok(vec![Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            Value::Object(record),
        )
        .with_parent(artifact.id)])
    }
}

/// The record emitted for a file that begins with `MZ` but will not parse as a
/// PE at all.
///
/// A silent empty result would file this executable beside every text document
/// in the case: no PE record, nothing saying it was even looked at. "We could
/// not read it" and "there was nothing to read" must not render the same way,
/// least of all for a dropped binary an examiner is trying to attribute.
fn unparsable_pe_record(
    artifact: &Artifact,
    name: Option<&str>,
    analysed: u64,
    declared: u64,
) -> Artifact {
    let mut m = Map::new();
    m.insert("type".into(), json!("PeSignature"));
    m.insert("subtype".into(), json!("pe_analysis"));
    m.insert("status".into(), json!("pe_unparsable"));
    // Not `false`: whether this image is signed is unknown, not answered.
    m.insert("signed".into(), Value::Null);
    m.insert(
        "signature_integrity".into(),
        json!("unverified (the file could not be parsed as a PE image)"),
    );
    m.insert("content_incomplete".into(), json!(true));
    m.insert(
        "content_incomplete_reason".into(),
        json!(if analysed < declared {
            IncompleteReason::ShortRead.as_str()
        } else {
            IncompleteReason::UnresolvedStructure.as_str()
        }),
    );
    m.insert("analysis_incomplete".into(), json!(true));
    m.insert(
        "analysis_incomplete_reason".into(),
        json!(IncompleteReason::UnresolvedStructure.as_str()),
    );
    m.insert("bytes_analysed".into(), json!(analysed));
    m.insert("declared_size".into(), json!(declared));
    m.insert(
        "message".into(),
        json!(
            "This file carries the DOS `MZ` magic but its PE headers could not be parsed, \
               so no signature, version resource or imphash could be produced. That is not \
               evidence the file is unsigned or is not an executable"
        ),
    );
    if let Some(n) = name {
        m.insert("source_name".into(), json!(n));
        m.insert("name".into(), json!(format!("PE image (unparsable): {n}")));
    } else {
        m.insert("name".into(), json!("PE image (unparsable)"));
    }
    carry_provenance(&mut m, artifact);
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(m),
    )
    .with_parent(artifact.id)
}

/// Carry the source artifact's **provenance** onto the PE record.
///
/// Where an executable *was* is as much a fact about it as what it is signed
/// with, and it is a fact only the source artifact holds: an alternate data
/// stream, a file carved out of another file's slack, a deleted entry. The PE
/// record is what the findings layer reads (`seance_plugin_findings`), and a
/// module that subscribes to parsed records cannot walk back to the file the
/// record came from — so a PE-in-an-ADS lead is only possible if the record
/// says it came from one.
///
/// Copied, never derived. Each key is written by the parser that established it
/// (`is_ads` by the MFT plugin, `carving_source` by the carver), and absence
/// here means the source did not say, not that the answer is no.
fn carry_provenance(m: &mut Map<String, Value>, artifact: &Artifact) {
    if artifact.metadata.get("is_ads").and_then(|v| v.as_bool()) == Some(true) {
        m.insert("in_alternate_data_stream".into(), json!(true));
        for key in ["stream_name", "parent_file"] {
            if let Some(v) = artifact.metadata.get(key) {
                m.insert(key.into(), v.clone());
            }
        }
    }
    if let Some(v) = artifact.metadata.get("carving_source") {
        m.insert("carving_source".into(), v.clone());
        // A carved file's `parent_file` is the file whose slack held it.
        if let Some(p) = artifact.metadata.get("parent_file") {
            m.entry("parent_file").or_insert_with(|| p.clone());
        }
    }
    if artifact.metadata.get("deleted").and_then(|v| v.as_bool()) == Some(true) {
        m.insert("source_deleted".into(), json!(true));
    }
}

/// Parse a PE and assemble its analysis record. Returns `None` only when goblin
/// cannot parse the file as a PE at all.
///
/// Attribute-certificate enumeration is turned OFF. goblin's default rejects the
/// WHOLE image when the certificate table runs past the end of the buffer, which
/// is the normal state of a truncated acquisition, of any image past the read
/// cap, and of a binary whose security directory was edited. Letting it refuse
/// would drop the executable from the analysis entirely — no record, no
/// incompleteness flag, nothing to say an executable was even examined. The
/// certificate bytes are read directly by `authenticode` below, which reports an
/// out-of-range table as an unknown signature rather than as absence (B2-169).
fn analyze(data: &[u8]) -> Option<Map<String, Value>> {
    let pe = PE::parse_with_opts(
        data,
        &goblin::pe::options::ParseOptions {
            resolve_rva: true,
            parse_attribute_certificates: false,
        },
    )
    .ok()?;
    let mut m = Map::new();
    m.insert("type".into(), json!("PeSignature"));
    m.insert("subtype".into(), json!("pe_analysis"));
    m.insert("is_dll".into(), json!(pe.is_lib));
    m.insert(
        "machine".into(),
        json!(machine_name(pe.header.coff_header.machine)),
    );
    m.insert(
        "compile_timestamp".into(),
        json!(pe.header.coff_header.time_date_stamp),
    );
    if let Some(opt) = pe.header.optional_header.as_ref() {
        m.insert(
            "pe_type".into(),
            json!(if opt.standard_fields.magic == 0x20b {
                "PE32+"
            } else {
                "PE32"
            }),
        );
        m.insert(
            "subsystem".into(),
            json!(subsystem_name(opt.windows_fields.subsystem)),
        );
    }

    if let Some(h) = imphash(&pe) {
        m.insert("imphash".into(), json!(h));
    }
    if let Some((name, ent)) = max_section_entropy(&pe, data) {
        m.insert("max_section_entropy".into(), json!(ent));
        m.insert("max_entropy_section".into(), json!(name));
        // >7.2 bits/byte across a whole section is the usual packed/encrypted tell.
        m.insert("likely_packed".into(), json!(ent > 7.2));
    }

    // Version resource (best-effort; absent on many malicious droppers).
    let ver = version_info(&pe, data);
    if !ver.is_empty() {
        m.insert("version_info".into(), Value::Object(ver));
    }

    // Authenticode.
    let sig = authenticode(&pe, data);
    // Null, not false: an unreadable certificate table leaves the question open.
    m.insert(
        "signed".into(),
        if sig.table_unreadable {
            Value::Null
        } else {
            json!(sig.signed)
        },
    );
    if let Some(p) = sig.publisher {
        m.insert("publisher".into(), json!(p));
    }
    if let Some(i) = sig.issuer {
        m.insert("cert_issuer".into(), json!(i));
    }
    if let Some(v) = sig.not_before {
        m.insert("cert_not_before".into(), json!(v));
    }
    if let Some(v) = sig.not_after {
        m.insert("cert_not_after".into(), json!(v));
    }
    if let Some(a) = sig.digest_algo {
        m.insert("digest_algorithm".into(), json!(a));
    }
    if let Some(v) = sig.integrity {
        m.insert("signature_integrity".into(), json!(v));
    }
    Some(m)
}

fn machine_name(m: u16) -> String {
    match m {
        0x014c => "x86 (i386)",
        0x8664 => "x64 (AMD64)",
        0x01c0 | 0x01c4 => "ARM",
        0xaa64 => "ARM64",
        0x0200 => "IA64",
        other => return format!("0x{other:04x}"),
    }
    .to_string()
}

fn subsystem_name(s: u16) -> String {
    match s {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows Console",
        5 => "OS/2 Console",
        7 => "POSIX Console",
        9 => "Windows CE GUI",
        10 => "EFI Application",
        other => return format!("0x{other:04x}"),
    }
    .to_string()
}

/// The import hash: `md5` of the comma-joined `dllbase.function` list (lowercase,
/// extensions .dll/.ocx/.sys stripped from the library name), in import-table
/// order. Ordinal-only imports contribute `dllbase.ord<N>`.
fn imphash(pe: &PE) -> Option<String> {
    let parts: Vec<String> = pe
        .imports
        .iter()
        .map(|imp| imphash_entry(imp.dll, &imp.name, imp.ordinal))
        .collect();
    if parts.is_empty() {
        return None;
    }
    let mut h = md5::Md5::new();
    h.update(parts.join(",").as_bytes());
    Some(hex(&h.finalize()))
}

/// One `dllbase.function` imphash entry: library lowercased with a
/// .dll/.ocx/.sys extension stripped, function lowercased (or `ord<N>`).
fn imphash_entry(dll: &str, name: &str, ordinal: u16) -> String {
    let dll = dll.to_ascii_lowercase();
    let base = match dll.rsplit_once('.') {
        Some((b, ext)) if matches!(ext, "dll" | "ocx" | "sys") => b.to_string(),
        _ => dll.clone(),
    };
    let func = if name.is_empty() {
        format!("ord{ordinal}")
    } else {
        name.to_ascii_lowercase()
    };
    format!("{base}.{func}")
}

/// Highest Shannon entropy across the section raw data, with the section name.
fn max_section_entropy(pe: &PE, data: &[u8]) -> Option<(String, f64)> {
    let mut best: Option<(String, f64)> = None;
    for s in &pe.sections {
        let start = s.pointer_to_raw_data as usize;
        let len = s.size_of_raw_data as usize;
        let end = start.checked_add(len)?;
        if len == 0 || end > data.len() {
            continue;
        }
        let e = shannon_entropy(&data[start..end]);
        let name = s.name().unwrap_or("?").to_string();
        if best.as_ref().map(|(_, b)| e > *b).unwrap_or(true) {
            best = Some((name, e));
        }
    }
    best
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Authenticode
// ---------------------------------------------------------------------------

#[derive(Default)]
struct SigInfo {
    signed: bool,
    /// The image declares a certificate table, but the range it names does not
    /// lie inside the bytes analysed. The signature verdict is then unknown, not
    /// negative: `signed` must be published as null, never `false`.
    table_unreadable: bool,
    publisher: Option<String>,
    issuer: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
    digest_algo: Option<String>,
    integrity: Option<String>,
}

fn authenticode(pe: &PE, data: &[u8]) -> SigInfo {
    let mut out = SigInfo::default();
    let Some(dir) = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|o| o.data_directories.get_certificate_table())
    else {
        return out;
    };
    let off = dir.virtual_address as usize; // security dir uses a file offset
    let size = dir.size as usize;
    if size == 0 {
        // No certificate table at all: the image is genuinely unsigned.
        return out;
    }
    // The image names a certificate table but it does not lie inside the bytes
    // we hold: the security directory is corrupt or was tampered with, or the
    // image is truncated. "The signature could not be read" is a different fact
    // from "this file is not signed", and it is the one that matters when the
    // security directory is exactly what an attacker edited (B2-169).
    let end = off.checked_add(size);
    if size <= 8 || end.map(|e| e > data.len()).unwrap_or(true) {
        out.table_unreadable = true;
        out.integrity = Some(format!(
            "unverified (certificate table at offset {off} declares {size} bytes, outside the \
             {} bytes analysed)",
            data.len()
        ));
        return out;
    }
    out.signed = true;
    // WIN_CERTIFICATE: dwLength(4) wRevision(2) wCertificateType(2), then PKCS#7.
    // The data-directory size is 8-byte padded, so slice the PKCS#7 to its exact
    // DER TLV length — a strict DER decoder rejects the trailing padding.
    let body = &data[off + 8..off + size];
    let pkcs7 = match der_tlv_len(body) {
        Some(n) if n <= body.len() => &body[..n],
        _ => body,
    };
    let Ok(ci) = cms::content_info::ContentInfo::from_der(pkcs7) else {
        out.integrity = Some("unverified (signature not parseable)".into());
        return out;
    };
    let Ok(sd) = ci.content.decode_as::<cms::signed_data::SignedData>() else {
        out.integrity = Some("unverified (not PKCS#7 SignedData)".into());
        return out;
    };

    // Signer certificate: match the signerInfo's issuer+serial against the bag.
    if let Some(cert) = signer_cert(&sd) {
        out.publisher = Some(rdn_to_string(&cert.tbs_certificate.subject));
        out.issuer = Some(rdn_to_string(&cert.tbs_certificate.issuer));
        out.not_before = Some(cert.tbs_certificate.validity.not_before.to_string());
        out.not_after = Some(cert.tbs_certificate.validity.not_after.to_string());
    }

    // Expected Authenticode digest lives in SpcIndirectDataContent.messageDigest.
    match expected_digest(&sd) {
        Some((algo, expected)) => {
            out.digest_algo = Some(algo.clone());
            let computed = authenticode_hash(data, pe, &algo);
            out.integrity = Some(match computed {
                Some(c) if c == expected => "valid (bytes match the signed digest)".into(),
                Some(_) => "MISMATCH — file does not match its signature".into(),
                None => "unverified (unsupported digest algorithm)".into(),
            });
        }
        None => {
            out.integrity = Some("unverified (no indirect-data digest)".into());
        }
    }
    out
}

/// Find the end-entity signer certificate that matches the first SignerInfo's
/// issuer-and-serial.
fn signer_cert(sd: &cms::signed_data::SignedData) -> Option<x509_cert::Certificate> {
    let si = sd.signer_infos.0.iter().next()?;
    let (issuer, serial) = match &si.sid {
        cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(isn) => {
            (isn.issuer.clone(), isn.serial_number.clone())
        }
        _ => return None,
    };
    let certs = sd.certificates.as_ref()?;
    for choice in certs.0.iter() {
        if let cms::cert::CertificateChoices::Certificate(c) = choice {
            if c.tbs_certificate.issuer == issuer && c.tbs_certificate.serial_number == serial {
                return Some(c.clone());
            }
        }
    }
    None
}

/// Pull `(algorithm, digest)` from the signed SpcIndirectDataContent:
/// `SEQUENCE { data ..., messageDigest DigestInfo { algId, digest OCTET STRING } }`.
fn expected_digest(sd: &cms::signed_data::SignedData) -> Option<(String, Vec<u8>)> {
    let econtent = sd.encap_content_info.econtent.as_ref()?;
    // econtent is the SpcIndirectDataContent SEQUENCE; its .value() is the two
    // child elements concatenated: [0] SpcAttribute (skip), [1] DigestInfo.
    // Read them sequentially — from_der would reject the "trailing" 2nd element.
    let mut reader = der::SliceReader::new(econtent.value()).ok()?;
    let _spc: der::asn1::AnyRef = reader.decode().ok()?;
    let digest_info: der::asn1::AnyRef = reader.decode().ok()?;
    // DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }
    let mut di = der::SliceReader::new(digest_info.value()).ok()?;
    let alg: x509_cert::spki::AlgorithmIdentifierOwned = di.decode().ok()?;
    let digest: der::asn1::OctetString = di.decode().ok()?;
    Some((oid_digest_name(&alg.oid), digest.as_bytes().to_vec()))
}

/// Total size of the DER TLV at the start of `buf` (tag + length + content),
/// so a PKCS#7 blob can be sliced off exactly, ignoring any trailing padding.
fn der_tlv_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 {
        return None;
    }
    let first = buf[1];
    if first & 0x80 == 0 {
        return Some(2 + first as usize);
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || buf.len() < 2 + n {
        return None;
    }
    let mut len = 0usize;
    for &b in &buf[2..2 + n] {
        len = (len << 8) | b as usize;
    }
    Some(2 + n + len)
}

fn oid_digest_name(oid: &const_oid::ObjectIdentifier) -> String {
    match oid.to_string().as_str() {
        "2.16.840.1.101.3.4.2.1" => "sha256".into(),
        "2.16.840.1.101.3.4.2.2" => "sha384".into(),
        "2.16.840.1.101.3.4.2.3" => "sha512".into(),
        "1.3.14.3.2.26" => "sha1".into(),
        other => other.to_string(),
    }
}

/// Compute the Authenticode PE hash: the bytes of the signed image except the
/// optional-header checksum and the certificate-table data-directory entry,
/// ending where the attribute certificate table begins.
///
/// Forensic meaning: this digest is what `signature_integrity` compares against
/// the digest inside the PKCS#7 blob. A wrong answer here is not a missing
/// finding, it is a false one — either "MISMATCH — file does not match its
/// signature" against an untouched Microsoft binary (a fabricated tampering
/// allegation), or a "valid" verdict on a patched executable.
///
/// # Where the hash ends, and why that is the whole of it
///
/// Authenticode hashes the image up to `FileLength - SizeOfCertTable` and
/// **nothing at or after that point**. In a file a signing tool wrote, the
/// certificate table is last, so that boundary and the end of the file are the
/// same byte and the distinction never shows. It shows on evidence.
///
/// This function used to hash `[cert_end..]` as "any trailing data after the
/// cert table". On the Magnet 2022 Linux image that produced **231 Strong
/// findings of "modified after it was signed" against 231 binaries that were
/// not modified at all** (`HUNT-123`). They were carved from unallocated
/// space, and a carve's end offset is a guess: every one of the 231 overshot
/// the certificate table — by 8 bytes at the least, 504 at the median and
/// 97,824 at the worst — so the hash covered bytes that were never part of the
/// signed image. Stopping at `cert_off` reproduces the signed digest for
/// **231 of 231**; hashing the overshoot reproduced it for none.
///
/// The carve was right and the hasher was wrong: those 231 are intact,
/// signature-verifiable binaries recovered from free space, which is a result
/// worth having and was being reported as tampering.
///
/// No synthetic padding is added to the hashed stream. The 8-byte alignment
/// rule in the Authenticode specification applies to a file that carries *no*
/// certificate table, where the digest is taken over the file zero-padded to
/// the offset a signature would be appended at. This function only ever runs on
/// an image that already has an embedded certificate table, and the signing
/// tool aligned that table when it wrote it: any alignment bytes before it are
/// real file bytes, already covered by the range hashed below. Injecting zeros
/// on top of them would hash bytes that are not in the evidence.
fn authenticode_hash(data: &[u8], pe: &PE, algo: &str) -> Option<Vec<u8>> {
    let e_lfanew = u32::from_le_bytes(data.get(0x3c..0x40)?.try_into().ok()?) as usize;
    let opt = e_lfanew.checked_add(24)?; // COFF header is 20 bytes + 4-byte sig
    let magic = u16::from_le_bytes(data.get(opt..opt + 2)?.try_into().ok()?);
    let checksum_off = opt.checked_add(64)?;
    let dd_off = opt.checked_add(if magic == 0x20b { 112 } else { 96 })?;
    let sec_entry_off = dd_off.checked_add(4 * 8)?; // security dir is index 4
    let dir = pe
        .header
        .optional_header
        .as_ref()?
        .data_directories
        .get_certificate_table()?;
    let cert_off = dir.virtual_address as usize;
    let cert_end = cert_off.checked_add(dir.size as usize)?;
    if checksum_off + 4 > data.len()
        || sec_entry_off + 8 > data.len()
        || cert_end > data.len()
        || cert_off < sec_entry_off + 8
    {
        return None;
    }

    let mut hasher = Hasher::new(algo)?;
    hasher.update(&data[..checksum_off]); // start .. checksum
    hasher.update(&data[checksum_off + 4..sec_entry_off]); // checksum .. sec dir entry
    hasher.update(&data[sec_entry_off + 8..cert_off]); // sec dir entry .. cert table
                                                       // And it stops there. Anything at or after the certificate table is
                                                       // outside the signed image: appended bytes, or -- on a carved file -- the
                                                       // overshoot past the end the carver guessed at. See above.
    Some(hasher.finalize())
}

/// Minimal dynamic hasher over the algorithms Authenticode uses in practice.
enum Hasher {
    Sha256(Sha256),
    Sha1(Sha1),
}

impl Hasher {
    fn new(algo: &str) -> Option<Self> {
        match algo {
            "sha256" => Some(Hasher::Sha256(Sha256::new())),
            "sha1" => Some(Hasher::Sha1(Sha1::new())),
            _ => None,
        }
    }
    fn update(&mut self, b: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(b),
            Hasher::Sha1(h) => h.update(b),
        }
    }
    fn finalize(self) -> Vec<u8> {
        match self {
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha1(h) => h.finalize().to_vec(),
        }
    }
}

fn rdn_to_string(name: &x509_cert::name::Name) -> String {
    // x509-cert renders Name as an RFC 4514 string; keep it verbatim.
    name.to_string()
}

// ---------------------------------------------------------------------------
// Version resource (VS_VERSIONINFO)
// ---------------------------------------------------------------------------

const RT_VERSION: u32 = 16;

/// Extract the StringFileInfo key/value pairs from the PE's version resource.
fn version_info(pe: &PE, data: &[u8]) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(blob) = version_resource_bytes(pe, data) else {
        return out;
    };
    let mut fields: Vec<(String, String)> = Vec::new();
    walk_version(blob, &mut fields, 0);
    const WANTED: &[&str] = &[
        "CompanyName",
        "ProductName",
        "FileDescription",
        "OriginalFilename",
        "InternalName",
        "FileVersion",
        "ProductVersion",
        "LegalCopyright",
    ];
    for (k, v) in fields {
        if WANTED.contains(&k.as_str()) && !v.is_empty() {
            out.entry(k).or_insert(json!(v));
        }
    }
    out
}

/// Locate the RT_VERSION resource data and return its bytes.
fn version_resource_bytes<'a>(pe: &PE, data: &'a [u8]) -> Option<&'a [u8]> {
    let rsrc = pe
        .sections
        .iter()
        .find(|s| s.name().ok() == Some(".rsrc"))?;
    let sec_start = rsrc.pointer_to_raw_data as usize;
    let sec_rva = rsrc.virtual_address as usize;
    let sec_len = rsrc.size_of_raw_data as usize;
    let sec = data.get(sec_start..sec_start.checked_add(sec_len)?)?;

    // Level 1: find the RT_VERSION type directory.
    let l1 = res_entry_by_id(sec, 0, RT_VERSION)?;
    // Level 2: first name/id entry -> subdirectory.
    let l2 = res_first_subdir(sec, l1)?;
    // Level 3: first language -> data entry (not a subdirectory).
    let data_entry = res_first_data(sec, l2)?;
    // IMAGE_RESOURCE_DATA_ENTRY { OffsetToData(RVA) u32, Size u32, ... }
    let rva = u32::from_le_bytes(sec.get(data_entry..data_entry + 4)?.try_into().ok()?) as usize;
    let size =
        u32::from_le_bytes(sec.get(data_entry + 4..data_entry + 8)?.try_into().ok()?) as usize;
    let file_off = sec_start + rva.checked_sub(sec_rva)?;
    data.get(file_off..file_off.checked_add(size)?)
}

/// In an IMAGE_RESOURCE_DIRECTORY at `dir_off` (relative to `sec`), find the
/// entry whose id == `id` and return the offset it points at.
fn res_entry_by_id(sec: &[u8], dir_off: usize, id: u32) -> Option<usize> {
    let n_named =
        u16::from_le_bytes(sec.get(dir_off + 12..dir_off + 14)?.try_into().ok()?) as usize;
    let n_id = u16::from_le_bytes(sec.get(dir_off + 14..dir_off + 16)?.try_into().ok()?) as usize;
    let first = dir_off + 16;
    for i in 0..(n_named + n_id) {
        let e = first + i * 8;
        let name = u32::from_le_bytes(sec.get(e..e + 4)?.try_into().ok()?);
        let off = u32::from_le_bytes(sec.get(e + 4..e + 8)?.try_into().ok()?);
        // High bit clear on `name` => it's an integer id.
        if name & 0x8000_0000 == 0 && name == id {
            return Some((off & 0x7fff_ffff) as usize);
        }
    }
    None
}

fn res_first_subdir(sec: &[u8], dir_off: usize) -> Option<usize> {
    let n_named =
        u16::from_le_bytes(sec.get(dir_off + 12..dir_off + 14)?.try_into().ok()?) as usize;
    let n_id = u16::from_le_bytes(sec.get(dir_off + 14..dir_off + 16)?.try_into().ok()?) as usize;
    let e = dir_off + 16;
    if n_named + n_id == 0 {
        return None;
    }
    let off = u32::from_le_bytes(sec.get(e + 4..e + 8)?.try_into().ok()?);
    // Subdirectory entries have the high bit set.
    Some((off & 0x7fff_ffff) as usize)
}

fn res_first_data(sec: &[u8], dir_off: usize) -> Option<usize> {
    let n_named =
        u16::from_le_bytes(sec.get(dir_off + 12..dir_off + 14)?.try_into().ok()?) as usize;
    let n_id = u16::from_le_bytes(sec.get(dir_off + 14..dir_off + 16)?.try_into().ok()?) as usize;
    let e = dir_off + 16;
    if n_named + n_id == 0 {
        return None;
    }
    let off = u32::from_le_bytes(sec.get(e + 4..e + 8)?.try_into().ok()?);
    // A leaf entry (high bit clear) points at an IMAGE_RESOURCE_DATA_ENTRY.
    Some((off & 0x7fff_ffff) as usize)
}

/// Recursively walk a VS_VERSIONINFO block tree, collecting `(szKey, value)`
/// pairs for every text-typed leaf. Bounded by `depth` and block lengths.
fn walk_version(buf: &[u8], out: &mut Vec<(String, String)>, depth: usize) {
    if depth > 8 {
        return;
    }
    let mut pos = 0usize;
    while pos + 6 <= buf.len() {
        let w_length = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as usize;
        let w_value_length = u16::from_le_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        let w_type = u16::from_le_bytes([buf[pos + 4], buf[pos + 5]]);
        if w_length < 6 || pos + w_length > buf.len() {
            break;
        }
        let block = &buf[pos..pos + w_length];
        // szKey: UTF-16 until a null unit, starting at offset 6.
        let (key, key_end) = read_utf16z(block, 6);
        let value_off = align4(key_end);
        if w_type == 1 && w_value_length > 0 {
            // Text value: w_value_length is in UTF-16 units.
            let vbytes = value_off + w_value_length * 2;
            if vbytes <= block.len() {
                let (val, _) = read_utf16z(block, value_off);
                if !key.is_empty() {
                    out.push((key.clone(), val));
                }
            }
        }
        // Children follow the (aligned) value; recurse into them.
        let child_off = align4(value_off + w_value_length * (if w_type == 1 { 2 } else { 1 }));
        if child_off < block.len() {
            walk_version(&block[child_off..], out, depth + 1);
        }
        pos += align4(w_length);
        if align4(w_length) == 0 {
            break;
        }
    }
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Read a UTF-16LE null-terminated string starting at `start`; returns the
/// decoded string and the offset just past its terminator.
fn read_utf16z(buf: &[u8], start: usize) -> (String, usize) {
    let mut units: Vec<u16> = Vec::new();
    let mut i = start;
    while i + 1 < buf.len() {
        let u = u16::from_le_bytes([buf[i], buf[i + 1]]);
        i += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    (String::from_utf16_lossy(&units), i)
}

#[cfg(test)]
mod tests;
