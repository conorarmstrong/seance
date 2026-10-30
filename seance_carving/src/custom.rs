//! User-defined carving signatures.
//!
//! Lets an examiner add file types the built-in signatures don't cover by
//! declaring a header (and optional footer) in a JSON file, without a code
//! change. Each spec becomes a [`CustomSignature`] registered into the same
//! [`SignatureRegistry`] the built-in formats use.
//!
//! ```json
//! {
//!   "signatures": [
//!     {
//!       "name": "AcmeLog",
//!       "extension": "acme",
//!       "header": "AC 4D 45 4C 4F 47",
//!       "footer": "0A 45 4F 46",
//!       "max_size": 1048576
//!     }
//!   ]
//! }
//! ```

use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use serde::Deserialize;
use std::sync::Arc;

/// Fallback size cap when a spec omits `max_size` (16 MiB).
const DEFAULT_MAX_SIZE: u64 = 16 * 1024 * 1024;

/// One user-declared signature.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomSignatureSpec {
    /// Human-readable name shown on carved artifacts.
    pub name: String,
    /// File extension for recovered files (default `bin`).
    #[serde(default)]
    pub extension: Option<String>,
    /// Header magic as a hex string; whitespace, `:` and `,` are ignored.
    pub header: String,
    /// Byte offset of the header within the file (default 0).
    #[serde(default)]
    pub header_offset: u16,
    /// Optional footer magic (hex); recovery stops just after its first match
    /// past the header. Without it, files run to `max_size` / the next header.
    #[serde(default)]
    pub footer: Option<String>,
    /// Maximum recovered size in bytes (default 16 MiB).
    #[serde(default)]
    pub max_size: Option<u64>,
    /// Minimum plausible size in bytes (default: header length).
    #[serde(default)]
    pub min_size: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct CustomDefsFile {
    signatures: Vec<CustomSignatureSpec>,
}

/// A carving signature built from a [`CustomSignatureSpec`].
struct CustomSignature {
    name: String,
    ext: String,
    exts: Vec<&'static str>,
    header: Vec<u8>,
    header_offset: u16,
    footer: Option<Vec<u8>>,
    max_size: u64,
    min_size: u64,
}

impl FileSignature for CustomSignature {
    fn name(&self) -> &str {
        &self.name
    }

    fn extensions(&self) -> &[&str] {
        &self.exts
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let off = self.header_offset as usize;
        let end = off.checked_add(self.header.len())?;
        if buf.len() >= end && buf[off..end] == self.header[..] {
            Some(RecoveryInit {
                min_filesize: self.min_size,
                extension: self.ext.clone(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        let Some(footer) = &self.footer else {
            return DataCheckResult::Continue;
        };
        if footer.is_empty() {
            return DataCheckResult::Continue;
        }
        // On the first block, skip past the header so a footer that also appears
        // inside the header can't stop recovery immediately.
        let start = if recovery.file_size == 0 {
            self.header_offset as usize + self.header.len()
        } else {
            0
        };
        // SIMD substring search (a carve scans this per block across potentially
        // gigabytes), carrying the last footer.len()-1 bytes of each block so a
        // footer that straddles a block boundary is still found.
        match footer_end_spanning(buf, recovery, footer, start) {
            Some(end) => DataCheckResult::Stop(end),
            None => DataCheckResult::Continue,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        self.max_size
    }
}

/// Parse and register every signature in a custom-defs JSON document, returning
/// how many were registered. Fails the whole load on the first malformed spec
/// (an invalid definition should be fixed, not silently skipped).
pub fn register_custom_signatures(
    registry: &mut SignatureRegistry,
    json: &str,
) -> Result<usize, String> {
    let file: CustomDefsFile =
        serde_json::from_str(json).map_err(|e| format!("parsing custom carver defs: {e}"))?;
    let mut count = 0;
    for spec in file.signatures {
        let header = parse_hex(&spec.header)
            .map_err(|e| format!("signature '{}': invalid header: {e}", spec.name))?;
        if header.is_empty() {
            return Err(format!("signature '{}': header is empty", spec.name));
        }
        let footer = match spec.footer.as_deref() {
            Some(f) if !f.trim().is_empty() => Some(
                parse_hex(f)
                    .map_err(|e| format!("signature '{}': invalid footer: {e}", spec.name))?,
            ),
            _ => None,
        };
        let ext = spec.extension.unwrap_or_else(|| "bin".to_string());
        // Custom sigs are registered once at startup and live for the whole
        // process, so leaking the extension to satisfy `&'static str` is fine.
        let ext_static: &'static str = Box::leak(ext.clone().into_boxed_str());
        let header_len = header.len() as u64;
        let min_size = spec.min_size.unwrap_or(header_len).max(header_len);
        let max_size = spec.max_size.unwrap_or(DEFAULT_MAX_SIZE).max(min_size);
        let offset = spec.header_offset;
        let sig = Arc::new(CustomSignature {
            name: spec.name,
            ext,
            exts: vec![ext_static],
            header: header.clone(),
            header_offset: offset,
            footer,
            max_size,
            min_size,
        });
        registry.register(offset, &header, sig);
        count += 1;
    }
    Ok(count)
}

/// Parse a hex string into bytes, ignoring whitespace, `:` and `,` separators.
fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != ',')
        .collect();
    // Reject non-hex characters first: after this every char is one byte, so the
    // byte-index slicing below is on char boundaries and len() is the digit count.
    if let Some(c) = cleaned.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!("'{c}' is not a hex digit"));
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err(format!(
            "hex string has an odd number of digits ({})",
            cleaned.len()
        ));
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|_| format!("'{}' is not a hex byte", &cleaned[i..i + 2]))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_registry(json: &str) -> SignatureRegistry {
        let mut reg = SignatureRegistry::new();
        register_custom_signatures(&mut reg, json).unwrap();
        reg
    }

    #[test]
    fn parse_hex_ignores_separators() {
        assert_eq!(parse_hex("DEADBEEF").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            parse_hex("de ad be ef").unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert_eq!(
            parse_hex("DE:AD,BE EF").unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn parse_hex_rejects_bad_input() {
        assert!(parse_hex("ABC").is_err()); // odd length
        assert!(parse_hex("ZZ").is_err()); // non-hex digit
        assert!(parse_hex("A\u{e9}B").is_err()); // non-ASCII: no slicing panic
    }

    #[test]
    fn matches_header_and_stops_at_footer() {
        let json = r#"{ "signatures": [
            { "name": "AcmeLog", "extension": "acme", "header": "DEADC0DE",
              "footer": "454F46", "max_size": 1048576 } ] }"#;
        let reg = build_registry(json);

        let mut data = vec![0xDE, 0xAD, 0xC0, 0xDE]; // header (4)
        data.extend_from_slice(b"payload"); //             body (7)
        data.extend_from_slice(&[0x45, 0x4F, 0x46]); //     footer "EOF" (3)
        data.extend_from_slice(b"trailing junk");

        let matches = reg.find_matches(&data);
        assert_eq!(matches.len(), 1, "header should match at offset 0");
        let (sig, off) = &matches[0];
        assert_eq!(*off, 0);

        let init = sig.header_check(&data, 0).expect("header check passes");
        assert_eq!(init.extension, "acme");

        let mut rec = FileRecovery::from_init(&init, 0);
        match sig.data_check(&data, &mut rec) {
            DataCheckResult::Stop(end) => assert_eq!(end, 14), // 4 + 7 + 3
            other => panic!("expected Stop, got {other:?}"),
        }
        assert_eq!(sig.name(), "AcmeLog");
        assert_eq!(sig.max_file_size(), 1_048_576);
    }

    #[test]
    fn footer_in_continuation_block_offsets_by_accumulated_size() {
        // A footer found in a later block must report end relative to the bytes
        // already recovered (recovery.file_size), not just this block.
        let json = r#"{ "signatures": [
            { "name": "AcmeLog", "header": "DEADC0DE", "footer": "454F46" } ] }"#;
        let reg = build_registry(json);
        let (sig, _) = &reg.find_matches(&[0xDE, 0xAD, 0xC0, 0xDE])[0];

        // Second block: no header here, footer "EOF" sits 5 bytes in.
        let block = [b'a', b'b', b'c', b'd', b'e', 0x45, 0x4F, 0x46, b'z'];
        let init = sig.header_check(&[0xDE, 0xAD, 0xC0, 0xDE], 0).unwrap();
        let mut rec = FileRecovery::from_init(&init, 0);
        rec.file_size = 4096; // bytes carried over from earlier blocks
        match sig.data_check(&block, &mut rec) {
            // 4096 accumulated + 5 (offset in block) + 3 (footer len)
            DataCheckResult::Stop(end) => assert_eq!(end, 4096 + 8),
            other => panic!("expected Stop, got {other:?}"),
        }
    }

    /// A footer that begins in one block and ends in the next is found, at every
    /// split of its bytes across the boundary.
    #[test]
    fn a_footer_split_across_two_blocks_is_found() {
        let json = r#"{ "signatures": [
            { "name": "AcmeLog", "header": "DEADC0DE", "footer": "0A454F46" } ] }"#;
        let reg = build_registry(json);
        let (sig, _) = &reg.find_matches(&[0xDE, 0xAD, 0xC0, 0xDE])[0];
        let init = sig.header_check(&[0xDE, 0xAD, 0xC0, 0xDE], 0).unwrap();
        for split in 1..4 {
            let mut file = vec![0xDE, 0xAD, 0xC0, 0xDE];
            file.resize(512 - split, b'a');
            file.extend_from_slice(b"\nEOF"); // footer: `split` bytes in block 0
            let end = file.len() as u64;
            file.extend_from_slice(&[b'z'; 200]);
            let mut rec = FileRecovery::from_init(&init, 0);
            let (first, second) = file.split_at(512);
            assert_eq!(sig.data_check(first, &mut rec), DataCheckResult::Continue);
            rec.file_size = 512;
            assert_eq!(
                sig.data_check(second, &mut rec),
                DataCheckResult::Stop(end),
                "split {split}"
            );
        }
    }

    #[test]
    fn no_footer_continues_and_defaults_extension() {
        let json = r#"{ "signatures": [
            { "name": "NoFoot", "header": "CAFEBABE", "max_size": 4096 } ] }"#;
        let reg = build_registry(json);
        let data = [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0];
        let (sig, _) = &reg.find_matches(&data)[0];
        let init = sig.header_check(&data, 0).unwrap();
        assert_eq!(init.extension, "bin"); // default when none given
        let mut rec = FileRecovery::from_init(&init, 0);
        assert_eq!(sig.data_check(&data, &mut rec), DataCheckResult::Continue);
        assert_eq!(sig.max_file_size(), 4096);
    }

    #[test]
    fn rejects_malformed_defs() {
        let mut reg = SignatureRegistry::new();
        // Empty header.
        assert!(register_custom_signatures(
            &mut reg,
            r#"{ "signatures": [ { "name": "x", "header": "" } ] }"#
        )
        .is_err());
        // Odd-length hex.
        assert!(register_custom_signatures(
            &mut reg,
            r#"{ "signatures": [ { "name": "x", "header": "ABC" } ] }"#
        )
        .is_err());
        // Not JSON at all.
        assert!(register_custom_signatures(&mut reg, "not json").is_err());
    }
}
