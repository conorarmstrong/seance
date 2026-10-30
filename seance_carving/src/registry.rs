use crate::signature::FileSignature;
use std::collections::HashMap;
use std::sync::Arc;

/// A registered signature with its magic byte pattern for matching.
#[derive(Clone)]
pub(crate) struct RegisteredSig {
    pub pattern: Vec<u8>,
    pub signature: Arc<dyn FileSignature>,
}

/// First-byte dispatch table: signatures bucketed by `pattern[0]`. Direct-
/// indexed by the byte (0..=255) so the per-block lookup is an array index, not
/// a SipHash probe of a `HashMap<u8, _>`. Boxed because the 256-slot array is
/// large and there is one per registered offset.
type ByFirstByte = Box<[Vec<RegisteredSig>; 256]>;

fn empty_by_first_byte() -> ByFirstByte {
    Box::new(std::array::from_fn(|_| Vec::new()))
}

/// Registry of file signatures indexed by (offset, first_byte) for fast lookup.
///
/// Maps `offset -> first_byte -> list of signatures to check`. Offsets are few
/// (mostly 0), so the outer map is a HashMap; the inner first-byte dispatch is a
/// flat 256-slot array (see [`ByFirstByte`]) to keep `find_matches` -- run on
/// every scanned block -- off the hashing path.
pub struct SignatureRegistry {
    index: HashMap<u16, ByFirstByte>,
}

impl SignatureRegistry {
    pub fn new() -> Self {
        Self {
            index: HashMap::new(),
        }
    }

    /// Register a signature pattern at a specific byte offset.
    ///
    /// - `offset`: byte offset where the pattern appears in the file header
    /// - `pattern`: the magic bytes to match
    /// - `sig`: the file signature implementation
    pub fn register(&mut self, offset: u16, pattern: &[u8], sig: Arc<dyn FileSignature>) {
        if pattern.is_empty() {
            return;
        }
        let first_byte = pattern[0];
        let by_first_byte = self.index.entry(offset).or_insert_with(empty_by_first_byte);
        by_first_byte[first_byte as usize].push(RegisteredSig {
            pattern: pattern.to_vec(),
            signature: sig,
        });
    }

    /// Find all signatures whose patterns match within the given buffer.
    ///
    /// Returns a list of (signature, match_offset) tuples.
    pub fn find_matches(&self, buf: &[u8]) -> Vec<(Arc<dyn FileSignature>, usize)> {
        let mut matches = Vec::new();

        for (&offset, by_first_byte) in &self.index {
            let off = offset as usize;
            if off >= buf.len() {
                continue;
            }
            let first = buf[off];
            for reg in &by_first_byte[first as usize] {
                let end = off + reg.pattern.len();
                if end <= buf.len() && buf[off..end] == reg.pattern[..] {
                    matches.push((reg.signature.clone(), off));
                }
            }
        }

        matches
    }

    /// Every registration as `(offset, pattern, signature)`, so a test can
    /// plant each magic in filler and ask whether the signature would accept
    /// it (CARVE-015).
    #[cfg(test)]
    pub(crate) fn registrations(&self) -> Vec<(u16, Vec<u8>, Arc<dyn FileSignature>)> {
        let mut out = Vec::new();
        for (&offset, by_first_byte) in &self.index {
            for bucket in by_first_byte.iter() {
                for reg in bucket {
                    out.push((offset, reg.pattern.clone(), reg.signature.clone()));
                }
            }
        }
        out.sort_by(|a, b| a.2.name().cmp(b.2.name()).then(a.0.cmp(&b.0)));
        out
    }

    /// The most bytes from a file's start any registration needs shown: the
    /// furthest end of a registered magic, or what its signature asks for with
    /// `header_window`. The engine reads ahead this far only when it exceeds
    /// one block.
    pub fn max_header_window(&self) -> usize {
        self.index
            .iter()
            .flat_map(|(&offset, by_first_byte)| {
                by_first_byte.iter().flatten().map(move |reg| {
                    (offset as usize + reg.pattern.len()).max(reg.signature.header_window())
                })
            })
            .max()
            .unwrap_or(0)
    }

    /// Returns true if no signatures are registered.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
}

impl Default for SignatureRegistry {
    fn default() -> Self {
        Self::new()
    }
}
