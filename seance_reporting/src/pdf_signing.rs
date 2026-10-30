use std::path::Path;

use lopdf::dictionary;
use lopdf::Object;
use openssl::pkcs7::Pkcs7Flags;
use openssl::stack::Stack;
use openssl::x509::X509;
use thiserror::Error;
use tracing::info;

/// Maximum hex-encoded signature size in bytes.
/// Typical PKCS#7 signatures are 2-4 KB; 8192 hex chars = 4096 bytes of DER.
const SIGNATURE_PLACEHOLDER_LENGTH: usize = 8192;

/// Sentinel value for ByteRange placeholder integers.
/// Must be exactly 10 digits so in-place replacement preserves byte offsets.
const BYTE_RANGE_SENTINEL: i64 = 9_999_999_999;

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Failed to read certificate file {}: {}", .0.display(), .1)]
    CertificateReadError(std::path::PathBuf, std::io::Error),

    #[error("Failed to read private key file {}: {}", .0.display(), .1)]
    PrivateKeyReadError(std::path::PathBuf, std::io::Error),

    #[error("Failed to parse certificate: {0}")]
    CertificateParseError(String),

    #[error("Failed to parse private key: {0}")]
    PrivateKeyParseError(String),

    #[error("Private key does not match certificate")]
    KeyMismatch,

    #[error("OpenSSL error: {0}")]
    OpenSslError(#[from] openssl::error::ErrorStack),

    #[error("PDF error: {0}")]
    PdfError(#[from] lopdf::Error),

    #[error("Signature too large for placeholder ({actual} > {max})")]
    SignatureTooLarge { actual: usize, max: usize },

    #[error("ByteRange placeholder not found in serialized PDF")]
    ByteRangePlaceholderNotFound,

    #[error("Contents placeholder not found in serialized PDF")]
    ContentsPlaceholderNotFound,
}

/// Configuration for PDF digital signing.
///
/// Constructed via [`SigningConfig::from_files`], which reads and validates
/// the certificate and key at startup. The PEM bytes are cached so that
/// [`sign_pdf`] never touches the filesystem.
#[derive(Debug, Clone)]
pub struct SigningConfig {
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    pub signer_name: Option<String>,
    pub reason: Option<String>,
}

impl SigningConfig {
    /// Load a signing configuration from PEM files on disk.
    ///
    /// Reads both files, verifies the certificate and key parse correctly and
    /// that the key matches the certificate. Returns an error immediately if
    /// anything is wrong, so callers can fail fast at startup.
    pub fn from_files(
        cert_path: &Path,
        key_path: &Path,
        signer_name: Option<String>,
        reason: Option<String>,
    ) -> Result<Self, SigningError> {
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| SigningError::CertificateReadError(cert_path.to_path_buf(), e))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|e| SigningError::PrivateKeyReadError(key_path.to_path_buf(), e))?;

        // Validate cert and key parse correctly
        let cert = X509::from_pem(&cert_pem)
            .map_err(|e| SigningError::CertificateParseError(e.to_string()))?;
        let pkey = openssl::pkey::PKey::private_key_from_pem(&key_pem)
            .map_err(|e| SigningError::PrivateKeyParseError(e.to_string()))?;

        // Verify the key matches the certificate
        let cert_pubkey = cert.public_key()?;
        if !cert_pubkey.public_eq(&pkey) {
            return Err(SigningError::KeyMismatch);
        }

        info!("Signing config validated: cert and key match");
        Ok(Self {
            cert_pem,
            key_pem,
            signer_name,
            reason,
        })
    }
}

/// Sign a PDF with a PKCS#7 detached signature.
///
/// The signature is embedded as an invisible annotation with an AcroForm,
/// compatible with Adobe Reader and other PDF signature validators.
///
/// Certificate and key bytes are read from the cached [`SigningConfig`] —
/// no filesystem access occurs during signing.
pub fn sign_pdf(pdf_bytes: &[u8], config: &SigningConfig) -> Result<Vec<u8>, SigningError> {
    sign_pdf_at(pdf_bytes, config, chrono::Utc::now())
}

/// [`sign_pdf`] with the signature dictionary's `M` (signing time) supplied,
/// so a test can hold the output to a reference byte for byte. The PKCS#7
/// object itself still carries OpenSSL's own signing-time attribute.
fn sign_pdf_at(
    pdf_bytes: &[u8],
    config: &SigningConfig,
    signed_at: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<u8>, SigningError> {
    // Parse cert and key from cached PEM bytes
    let cert = X509::from_pem(&config.cert_pem)
        .map_err(|e| SigningError::CertificateParseError(e.to_string()))?;
    let pkey = openssl::pkey::PKey::private_key_from_pem(&config.key_pem)
        .map_err(|e| SigningError::PrivateKeyParseError(e.to_string()))?;

    // Parse the PDF
    let mut doc = lopdf::Document::load_mem(pdf_bytes)?;

    // Build the Contents placeholder: hex string of zeros
    let contents_placeholder = "0".repeat(SIGNATURE_PLACEHOLDER_LENGTH);

    // PDF date string: D:YYYYMMDDHHmmSS+00'00'
    let pdf_date = signed_at.format("D:%Y%m%d%H%M%S+00'00'").to_string();

    // Build the signature dictionary with a real ByteRange array (sentinel values)
    let mut sig_dict = dictionary! {
        "Type" => Object::Name(b"Sig".to_vec()),
        "Filter" => Object::Name(b"Adobe.PPKLite".to_vec()),
        "SubFilter" => Object::Name(b"adbe.pkcs7.detached".to_vec()),
        "ByteRange" => Object::Array(vec![
            Object::Integer(BYTE_RANGE_SENTINEL),
            Object::Integer(BYTE_RANGE_SENTINEL),
            Object::Integer(BYTE_RANGE_SENTINEL),
            Object::Integer(BYTE_RANGE_SENTINEL),
        ]),
        "Contents" => Object::String(vec![0u8; SIGNATURE_PLACEHOLDER_LENGTH / 2], lopdf::StringFormat::Hexadecimal),
        "M" => Object::String(pdf_date.as_bytes().to_vec(), lopdf::StringFormat::Literal),
    };

    if let Some(ref name) = config.signer_name {
        sig_dict.set(
            "Name",
            Object::String(name.as_bytes().to_vec(), lopdf::StringFormat::Literal),
        );
    }
    if let Some(ref reason) = config.reason {
        sig_dict.set(
            "Reason",
            Object::String(reason.as_bytes().to_vec(), lopdf::StringFormat::Literal),
        );
    }

    let sig_obj_id = doc.add_object(sig_dict);

    // Get the first page to attach the annotation
    let pages = doc.get_pages();
    let first_page_id = *pages
        .values()
        .next()
        .ok_or(SigningError::PdfError(lopdf::Error::PageNumberNotFound(1)))?;

    // Build invisible signature field widget annotation
    let sig_field = dictionary! {
        "Type" => Object::Name(b"Annot".to_vec()),
        "Subtype" => Object::Name(b"Widget".to_vec()),
        "FT" => Object::Name(b"Sig".to_vec()),
        "T" => Object::String(b"Signature1".to_vec(), lopdf::StringFormat::Literal),
        "V" => Object::Reference(sig_obj_id),
        "Rect" => Object::Array(vec![
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(0),
        ]),
        "F" => Object::Integer(132), // Hidden + Print
        "P" => Object::Reference(first_page_id),
    };

    let sig_field_id = doc.add_object(sig_field);

    // Add annotation to the first page's Annots array
    let page = doc.get_object_mut(first_page_id)?.as_dict_mut()?;
    match page.get_mut(b"Annots") {
        Ok(annots_obj) => {
            if let Object::Array(ref mut arr) = annots_obj {
                arr.push(Object::Reference(sig_field_id));
            }
        }
        Err(_) => {
            page.set(
                "Annots",
                Object::Array(vec![Object::Reference(sig_field_id)]),
            );
        }
    }

    // Add AcroForm to the document catalog
    let acro_form = dictionary! {
        "Fields" => Object::Array(vec![Object::Reference(sig_field_id)]),
        "SigFlags" => Object::Integer(3), // SignaturesExist | AppendOnly
    };
    let acro_form_id = doc.add_object(Object::Dictionary(acro_form));

    // Get catalog object ID from trailer Root reference
    let catalog_id = doc
        .trailer
        .get(b"Root")
        .and_then(|obj| obj.as_reference())
        .map_err(SigningError::PdfError)?;

    let catalog = doc.get_object_mut(catalog_id)?.as_dict_mut()?;
    catalog.set("AcroForm", Object::Reference(acro_form_id));

    // The loaded trailer still carries the SOURCE file's cross-reference
    // chain: `Prev` (and `XRefStm`) are byte offsets into the file we read,
    // and lopdf copies them into the trailer it writes. In the rewritten file
    // they point at nothing, so a reader following the chain finds no xref
    // there — qpdf reports the signed copy as damaged and rebuilds the table
    // by scanning, and lopdf refuses to open it at all. The writer emits one
    // complete cross-reference section, so there is no previous one to name.
    doc.trailer.remove(b"Prev");
    doc.trailer.remove(b"XRefStm");

    // Serialize the PDF to bytes
    let mut serialized = Vec::new();
    doc.save_to(&mut serialized)
        .map_err(|e| SigningError::PdfError(lopdf::Error::IO(e)))?;

    // Find the Contents hex placeholder in the serialized PDF
    // lopdf serializes hex strings as <HEXHEXHEX...>
    let contents_marker = format!("<{}>", contents_placeholder);
    let contents_offset = find_bytes(&serialized, contents_marker.as_bytes())
        .ok_or(SigningError::ContentsPlaceholderNotFound)?;

    // Find the ByteRange sentinel array in the serialized PDF
    // lopdf serializes as [9999999999 9999999999 9999999999 9999999999]
    let br_marker = format!(
        "[{} {} {} {}]",
        BYTE_RANGE_SENTINEL, BYTE_RANGE_SENTINEL, BYTE_RANGE_SENTINEL, BYTE_RANGE_SENTINEL
    );
    let br_offset = find_bytes(&serialized, br_marker.as_bytes())
        .ok_or(SigningError::ByteRangePlaceholderNotFound)?;

    // ByteRange = [0, len1, off2, len2]. The hole is the whole Contents string
    // object, both delimiters included (PDF 32000-1 §12.8.1; HUNT-156).
    let before_contents_len = contents_offset;
    let after_contents_offset = contents_offset + contents_marker.len();
    let after_contents_len = serialized.len() - after_contents_offset;

    // Format ByteRange values as 10-digit zero-padded integers (same width as sentinels)
    let new_byte_range = format!(
        "[{:010} {:010} {:010} {:010}]",
        0, before_contents_len, after_contents_offset, after_contents_len
    );

    // Replace ByteRange sentinel in-place (same byte width)
    serialized[br_offset..br_offset + br_marker.len()].copy_from_slice(new_byte_range.as_bytes());

    // The bytes to sign are the two ByteRange runs. Rather than copy them
    // into a second buffer the size of the PDF, close the gap between them
    // in place: the tail shifts down over the placeholder, the buffer keeps
    // its capacity, and the signature is spliced back into the same gap
    // below. Peak memory is one copy of the file, not two.
    let contents_value_offset = contents_offset + 1; // skip '<'
    let gap: Vec<u8> = serialized
        .drain(before_contents_len..after_contents_offset)
        .collect();
    debug_assert_eq!(serialized.len(), before_contents_len + after_contents_len);

    // Create the PKCS#7 detached signature
    let certs = Stack::new()?;
    let flags = Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY | Pkcs7Flags::NOSMIMECAP;
    let pkcs7 = openssl::pkcs7::Pkcs7::sign(&cert, &pkey, &certs, &serialized, flags)?;

    // DER-encode the PKCS#7 signature
    let der_bytes = pkcs7.to_der()?;
    let hex_signature = hex::encode_upper(&der_bytes);

    // Verify the signature fits in the placeholder
    if hex_signature.len() > SIGNATURE_PLACEHOLDER_LENGTH {
        return Err(SigningError::SignatureTooLarge {
            actual: hex_signature.len(),
            max: SIGNATURE_PLACEHOLDER_LENGTH,
        });
    }

    // Pad the hex signature to fill the placeholder
    let padded_signature = format!(
        "{:0<width$}",
        hex_signature,
        width = SIGNATURE_PLACEHOLDER_LENGTH
    );

    // Reopen the gap with the signature between its delimiters
    serialized.splice(
        before_contents_len..before_contents_len,
        std::iter::once(gap[0])
            .chain(padded_signature.bytes())
            .chain(gap[1 + SIGNATURE_PLACEHOLDER_LENGTH..].iter().copied()),
    );
    debug_assert_eq!(
        &serialized[contents_value_offset..contents_value_offset + SIGNATURE_PLACEHOLDER_LENGTH],
        padded_signature.as_bytes()
    );

    info!(
        "PDF signed successfully ({} byte signature, {} byte PDF)",
        der_bytes.len(),
        serialized.len()
    );

    Ok(serialized)
}

/// Byte offset of the first occurrence of `needle` in `haystack`.
///
/// Scans for the needle's first byte and compares the rest only at a hit:
/// the placeholders this looks for sit at the far end of the file, so the
/// old window-by-window compare read the whole PDF twice through a slice
/// comparison per position (65 ms a pass on an 18 MB file, release).
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let (&first, rest) = needle.split_first()?;
    let mut from = 0;
    while from + needle.len() <= haystack.len() {
        let hit = from + haystack[from..].iter().position(|&b| b == first)?;
        if haystack.get(hit + 1..hit + needle.len()) == Some(rest) {
            return Some(hit);
        }
        from = hit + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Generate a minimal test PDF using printpdf.
    fn generate_test_pdf() -> Vec<u8> {
        use printpdf::*;

        let (doc, page1, layer1) = PdfDocument::new("Test PDF", Mm(210.0), Mm(297.0), "Layer 1");
        let current_layer = doc.get_page(page1).get_layer(layer1);
        let font = doc.add_builtin_font(BuiltinFont::Helvetica).unwrap();
        current_layer.use_text("Hello, signed world!", 14.0, Mm(10.0), Mm(280.0), &font);
        doc.save_to_bytes().unwrap()
    }

    /// Generate a self-signed certificate and key pair for testing.
    fn generate_test_cert() -> (Vec<u8>, Vec<u8>) {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "Test Signer")
            .unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        (
            cert.to_pem().unwrap(),
            pkey.private_key_to_pem_pkcs8().unwrap(),
        )
    }

    /// Write PEM bytes to temp files and construct a SigningConfig.
    fn create_test_config(cert_pem: &[u8], key_pem: &[u8]) -> (tempfile::TempDir, SigningConfig) {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        std::fs::File::create(&cert_path)
            .unwrap()
            .write_all(cert_pem)
            .unwrap();
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(key_pem)
            .unwrap();

        let config = SigningConfig::from_files(&cert_path, &key_path, None, None).unwrap();
        (dir, config)
    }

    #[test]
    fn test_sign_pdf_produces_valid_output() {
        let pdf_bytes = generate_test_pdf();
        let (cert_pem, key_pem) = generate_test_cert();
        let (_dir, mut config) = create_test_config(&cert_pem, &key_pem);
        config.signer_name = Some("Test Signer".to_string());
        config.reason = Some("Test signing".to_string());

        let signed = sign_pdf(&pdf_bytes, &config).unwrap();

        assert!(signed.starts_with(b"%PDF-"));
        assert!(signed.len() > pdf_bytes.len());
        assert!(find_bytes(&signed, b"adbe.pkcs7.detached").is_some());
    }

    #[test]
    fn test_sign_pdf_signature_is_valid_pkcs7() {
        let pdf_bytes = generate_test_pdf();
        let (cert_pem, key_pem) = generate_test_cert();
        let (_dir, config) = create_test_config(&cert_pem, &key_pem);

        let signed = sign_pdf(&pdf_bytes, &config).unwrap();

        // Parse the signed PDF and extract the signature dictionary
        let doc = lopdf::Document::load_mem(&signed).unwrap();
        let mut found_sig = false;

        for obj in doc.objects.values() {
            if let Ok(dict) = obj.as_dict() {
                let is_sig = dict
                    .get(b"Type")
                    .and_then(|t| t.as_name())
                    .map(|n| n == b"Sig")
                    .unwrap_or(false);

                if !is_sig {
                    continue;
                }
                found_sig = true;

                // Verify ByteRange is a real array with sensible values
                let byte_range = dict.get(b"ByteRange").unwrap().as_array().unwrap();
                assert_eq!(byte_range.len(), 4);
                assert_eq!(byte_range[0].as_i64().unwrap(), 0);
                let len1 = byte_range[1].as_i64().unwrap();
                let off2 = byte_range[2].as_i64().unwrap();
                let len2 = byte_range[3].as_i64().unwrap();
                assert!(len1 > 0);
                assert!(off2 > len1);
                assert!(len2 > 0);
                assert_eq!(
                    (off2 + len2) as usize,
                    signed.len(),
                    "ByteRange should cover to end of file"
                );

                // Verify Contents is a parseable PKCS#7 DER structure
                if let Object::String(ref contents_bytes, _) = dict.get(b"Contents").unwrap() {
                    // lopdf decodes the hex string back to raw bytes for us.
                    // Trailing zero-padding is harmless — OpenSSL reads the
                    // ASN.1 length from the DER header and ignores the rest.
                    let _pkcs7 = openssl::pkcs7::Pkcs7::from_der(contents_bytes)
                        .expect("Contents should be valid PKCS#7 DER");
                } else {
                    panic!("Contents should be a string object");
                }
            }
        }
        assert!(found_sig, "Signed PDF should contain a Sig dictionary");
    }

    #[test]
    fn test_from_files_valid() {
        let (cert_pem, key_pem) = generate_test_cert();
        let (_dir, _config) = create_test_config(&cert_pem, &key_pem);
        // create_test_config calls from_files internally; reaching here means success
    }

    #[test]
    fn test_from_files_missing_cert() {
        let result = SigningConfig::from_files(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
            None,
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SigningError::CertificateReadError(..)),
            "Expected CertificateReadError, got: {err}"
        );
    }

    #[test]
    fn test_from_files_mismatched_key() {
        let (cert_pem, _key_pem) = generate_test_cert();
        let (_cert_pem2, key_pem2) = generate_test_cert();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        std::fs::File::create(&cert_path)
            .unwrap()
            .write_all(&cert_pem)
            .unwrap();
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(&key_pem2) // different key!
            .unwrap();

        let result = SigningConfig::from_files(&cert_path, &key_path, None, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SigningError::KeyMismatch),
            "Expected KeyMismatch, got: {err}"
        );
    }

    #[test]
    fn test_unsigned_pdf_is_valid() {
        let pdf_bytes = generate_test_pdf();
        assert!(pdf_bytes.starts_with(b"%PDF-"));
        assert!(pdf_bytes.len() > 100);
    }

    /// ROADMAP §5.10. The signature bytes can never be pinned — OpenSSL stamps
    /// its own signing time into the PKCS#7 — so the reference is the signed
    /// file with the Contents hex value blanked: every offset, the ByteRange,
    /// and every byte the signature covers.
    mod reference {
        use super::*;
        use std::time::Instant;

        fn fixed_time() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::parse_from_rfc3339("2026-09-19T12:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc)
        }

        fn fnv1a(bytes: &[u8]) -> u64 {
            bytes.iter().fold(0xcbf29ce484222325u64, |h, b| {
                (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
            })
        }

        /// A PDF written by hand, so its bytes are the same on every run
        /// (printpdf stamps a creation date into the ones it makes).
        fn handwritten_pdf() -> Vec<u8> {
            let mut out = Vec::new();
            let mut offsets = Vec::new();
            out.extend_from_slice(b"%PDF-1.4\n");
            let objects: [&[u8]; 4] = [
                b"<< /Type /Catalog /Pages 2 0 R >>",
                b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
                b"<< /Length 44 >>\nstream\nBT /F1 12 Tf 72 720 Td (Exhibit A) Tj ET\nendstream",
            ];
            for (i, body) in objects.iter().enumerate() {
                offsets.push(out.len());
                out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
                out.extend_from_slice(body);
                out.extend_from_slice(b"\nendobj\n");
            }
            let xref = out.len();
            out.extend_from_slice(b"xref\n0 5\n0000000000 65535 f \n");
            for o in offsets {
                out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
            }
            out.extend_from_slice(
                format!("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n")
                    .as_bytes(),
            );
            out
        }

        /// The signed file with its signature hex blanked to the placeholder.
        fn masked(signed: &[u8]) -> Vec<u8> {
            let doc = lopdf::Document::load_mem(signed).unwrap();
            let sig = doc
                .objects
                .values()
                .filter_map(|o| o.as_dict().ok())
                .find(|d| d.get(b"Type").and_then(|t| t.as_name()).ok() == Some(b"Sig"))
                .expect("a Sig dictionary");
            let range = sig.get(b"ByteRange").unwrap().as_array().unwrap();
            let len1 = range[1].as_i64().unwrap() as usize;
            let off2 = range[2].as_i64().unwrap() as usize;
            let mut out = signed.to_vec();
            out[len1 + 1..off2 - 1].fill(b'0');
            out
        }

        /// The bytes the ByteRange names, verified against the certificate
        /// that signed them: the proof that what was signed is what the file
        /// says was signed.
        fn assert_signature_verifies(signed: &[u8], cert_pem: &[u8]) {
            let doc = lopdf::Document::load_mem(signed).unwrap();
            let sig = doc
                .objects
                .values()
                .filter_map(|o| o.as_dict().ok())
                .find(|d| d.get(b"Type").and_then(|t| t.as_name()).ok() == Some(b"Sig"))
                .expect("a Sig dictionary");
            let range = sig.get(b"ByteRange").unwrap().as_array().unwrap();
            let (off1, len1, off2, len2) = (
                range[0].as_i64().unwrap() as usize,
                range[1].as_i64().unwrap() as usize,
                range[2].as_i64().unwrap() as usize,
                range[3].as_i64().unwrap() as usize,
            );
            let mut covered = Vec::with_capacity(len1 + len2);
            covered.extend_from_slice(&signed[off1..off1 + len1]);
            covered.extend_from_slice(&signed[off2..off2 + len2]);
            let Object::String(contents, _) = sig.get(b"Contents").unwrap() else {
                panic!("Contents should be a string");
            };
            let pkcs7 = openssl::pkcs7::Pkcs7::from_der(contents).unwrap();
            let cert = X509::from_pem(cert_pem).unwrap();
            let mut store = openssl::x509::store::X509StoreBuilder::new().unwrap();
            store.add_cert(cert).unwrap();
            let store = store.build();
            let certs = Stack::new().unwrap();
            pkcs7
                .verify(
                    &certs,
                    &store,
                    Some(&covered),
                    None,
                    Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY,
                )
                .expect("the PKCS#7 signature must verify over the ByteRange bytes");
        }

        /// HUNT-156: the hole is exactly the Contents string, `<` and `>`
        /// included (PDF 32000-1 §12.8.1). pyHanko graded the old one-late
        /// hole's coverage "unclear" and the file as modified after signing.
        #[test]
        fn the_byte_range_hole_is_the_contents_string_with_both_delimiters() {
            let (cert_pem, key_pem) = generate_test_cert();
            let (_dir, config) = create_test_config(&cert_pem, &key_pem);
            let signed = sign_pdf_at(&handwritten_pdf(), &config, fixed_time()).unwrap();
            let doc = lopdf::Document::load_mem(&signed).unwrap();
            let sig = doc
                .objects
                .values()
                .filter_map(|o| o.as_dict().ok())
                .find(|d| d.get(b"Type").and_then(|t| t.as_name()).ok() == Some(b"Sig"))
                .expect("a Sig dictionary");
            let range = sig.get(b"ByteRange").unwrap().as_array().unwrap();
            let len1 = range[1].as_i64().unwrap() as usize;
            let off2 = range[2].as_i64().unwrap() as usize;
            assert_eq!(signed[len1], b'<', "the opening delimiter is unsigned");
            assert_eq!(signed[off2 - 1], b'>', "the closing delimiter is unsigned");
            assert_eq!(off2 - len1, SIGNATURE_PLACEHOLDER_LENGTH + 2);
            assert!(signed[len1 + 1..off2 - 1].iter().all(u8::is_ascii_hexdigit));
        }

        #[test]
        fn a_handwritten_pdf_signs_to_the_bytes_it_did_before() {
            let (cert_pem, key_pem) = generate_test_cert();
            let (_dir, config) = create_test_config(&cert_pem, &key_pem);
            let signed = sign_pdf_at(&handwritten_pdf(), &config, fixed_time()).unwrap();
            assert_signature_verifies(&signed, &cert_pem);
            let masked = masked(&signed);
            // Captured 2026-09-19 from the copy-and-scan implementation;
            // re-pinned 2026-09-23 when HUNT-156 moved the hole one byte
            // earlier, which changes only the ByteRange's first length.
            assert_eq!(masked.len(), 8977);
            assert_eq!(fnv1a(&masked), 0xd9a611cc4c5c09c5);
        }

        #[test]
        fn a_real_manual_signs_to_the_bytes_it_did_before() {
            let path = std::path::Path::new("../reference/FTK_Enterprise_8.0-User_Guide.pdf");
            let Ok(pdf) = std::fs::read(path) else {
                eprintln!("skipping: {} absent (gitignored corpus)", path.display());
                return;
            };
            let (cert_pem, key_pem) = generate_test_cert();
            let (_dir, config) = create_test_config(&cert_pem, &key_pem);
            let start = Instant::now();
            let signed = sign_pdf_at(&pdf, &config, fixed_time()).unwrap();
            let elapsed = start.elapsed();
            assert_signature_verifies(&signed, &cert_pem);
            let masked = masked(&signed);
            let start = Instant::now();
            let scan = find_bytes(
                &signed,
                format!("<{}>", "0".repeat(SIGNATURE_PLACEHOLDER_LENGTH)).as_bytes(),
            );
            let scan_elapsed = start.elapsed();
            assert!(scan.is_none(), "the placeholder is gone from a signed file");
            // Captured 2026-09-19 from the copy-and-scan implementation, once
            // the stale `Prev` had been dropped from the trailer. Timings on
            // this host, debug / release: signed in 1.15 s / 354 ms, of which
            // each of the two placeholder scans was 232 ms / 65 ms.
            // Re-pinned 2026-09-23 for HUNT-156, as above.
            assert_eq!(signed.len(), 18_210_726);
            assert_eq!(fnv1a(&masked), 0x5f4597be413445f6);
            eprintln!(
                "manual: {} bytes in, {} bytes out, signed in {elapsed:?}; \
                 a full placeholder scan {scan_elapsed:?}",
                pdf.len(),
                signed.len(),
            );
        }
    }
}
