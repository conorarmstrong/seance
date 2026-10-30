//! Finding the Darwin kernel banner in physical memory.
//!
//! macOS publishes its kernel identity as a plain string in the `version`
//! character array: `Darwin Kernel Version 18.7.0: Thu Jun 20 18:42:21 PDT
//! 2019; root:xnu-4903.270.47~4/RELEASE_X86_64`. That string is what ties an
//! image to a symbol pack, and — because the array's unslid address is declared
//! in the pack — it is also what yields the kernel slide.
//!
//! # Why a scan and not a fixed address
//!
//! macOS relocates the kernel at every boot (kernel ASLR), so no symbol's
//! address in a Kernel Debug Kit pack is the address it will have in an image.
//! The banner is the anchor: it is textual, it is unique, and its unslid
//! address is known, so `slide = where_it_is - where_the_pack_says_it_is`.
//!
//! # What is deliberately not done here
//!
//! The banner is *not* treated as proof on its own. A machine's memory can hold
//! several copies of the string — in the kernel's data segment, in a cached
//! copy of the kernel file, in a `sysctl` buffer, in a log — and only one of
//! them yields a usable slide. Every hit is offered to
//! [`crate::automagic`], which accepts one only after the slide it implies has
//! been cross-checked against `version_major` and `version_minor` and then used
//! to read the banner back through the address space it produced.
//!
//! **Unvalidated.** See [`crate::unvalidated`]: this has never been run against
//! a real macOS capture.

use seance_memory::scan::{scan_layer, RegexScanner, ScanConfig, ScanError, ScanOutcome};
use seance_memory::MemoryLayer;

/// The banner pattern.
///
/// Bounded on purpose. The observed banners across the 129 Kernel Debug Kit
/// packs in this repository are 94 to 103 bytes long, so 240 printable bytes is
/// generous margin; an unbounded quantifier would let a run of printable
/// rubbish following a truncated banner be swallowed into the match and change
/// the string that is compared against the pack.
pub const DARWIN_BANNER_PATTERN: &str =
    r"Darwin Kernel Version \d{1,3}\.\d{1,3}\.\d{1,3}: [ -~]{1,240}";

/// Longest banner this module will reconstruct from a hit.
pub const MAX_BANNER_BYTES: usize = 512;

/// The Darwin release a banner names.
///
/// Darwin numbering, not the marketing number: Darwin 18 is macOS 10.14. The
/// two are kept apart because only the first is in the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DarwinVersion {
    /// Darwin major, e.g. 18 for macOS 10.14.
    pub major: u32,
    /// Darwin minor.
    pub minor: u32,
    /// Darwin patch.
    pub patch: u32,
}

impl DarwinVersion {
    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "darwin_major": self.major,
            "darwin_minor": self.minor,
            "darwin_patch": self.patch,
        })
    }
}

impl std::fmt::Display for DarwinVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// One banner found in the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BannerHit {
    /// Where the first byte of `text` was found, in the scanned layer's address
    /// space. For a physical scan this is a physical address.
    pub address: u64,
    /// The banner, NUL-trimmed and normalised the same way
    /// [`seance_symbols::normalize_banner`] normalises the pack's copy, so the
    /// two are comparable byte for byte.
    pub text: String,
    /// The release the banner names.
    pub version: DarwinVersion,
}

/// What one banner sweep found, and what it could not look at.
#[derive(Debug, Clone)]
pub struct BannerScan {
    /// Distinct banners, in ascending address order. Duplicates of the same
    /// text at different addresses are all kept: only one of them normally
    /// yields a working slide, and discarding the others would decide that
    /// question here.
    pub hits: Vec<BannerHit>,
    /// The sweep's own account of what it covered.
    pub outcome: ScanOutcome,
}

impl BannerScan {
    /// Whether every mapped byte was examined.
    ///
    /// A sweep that found no banner and was not complete has not established
    /// that the image holds none.
    pub fn is_complete(&self) -> bool {
        self.outcome.is_complete()
    }

    /// Serializable form for the discovery record.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "banners_found": self.hits.len(),
            "distinct_banners": self.distinct_texts(),
            "scan": self.outcome.to_json(),
            "scan_complete": self.is_complete(),
        })
    }

    /// The distinct banner strings found, for a failure record to name.
    pub fn distinct_texts(&self) -> Vec<String> {
        let mut texts: Vec<String> = self.hits.iter().map(|hit| hit.text.clone()).collect();
        texts.sort();
        texts.dedup();
        texts
    }
}

/// Parse the release out of a banner.
///
/// Returns `None` for a string that does not carry three dotted numbers after
/// the fixed prefix. Never guesses a component: a banner whose version cannot be
/// read cannot be cross-checked against `version_major`, which is the only
/// independent check discovery has.
pub fn parse_darwin_version(text: &str) -> Option<DarwinVersion> {
    const PREFIX: &str = "Darwin Kernel Version ";
    let rest = text.strip_prefix(PREFIX)?;
    let numbers = rest.split(':').next()?;
    let mut parts = numbers.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(DarwinVersion {
        major,
        minor,
        patch,
    })
}

/// Sweep `layer` for Darwin kernel banners.
///
/// Runs over the layer's *mapped* bytes only; unacquired regions are recorded in
/// the returned [`ScanOutcome`] rather than read through, so "no banner found"
/// and "we could not look at two thirds of the image" stay different answers.
pub fn scan_for_banners(
    layer: &dyn MemoryLayer,
    config: &ScanConfig,
) -> Result<BannerScan, ScanError> {
    let scanner = RegexScanner::new("darwin_kernel_banner", DARWIN_BANNER_PATTERN)?;
    let outcome = scan_layer(layer, &scanner, config)?;

    let mut hits = Vec::with_capacity(outcome.hits.len());
    for hit in &outcome.hits {
        let Some(banner) = read_banner_at(layer, hit.address, hit.length as usize) else {
            // The scanner matched these bytes a moment ago, so a failure to read
            // them back is a fault in the layer rather than a banner that is not
            // there. Dropping it costs nothing an examiner can use — the sweep's
            // own outcome already records what could not be read — and keeping a
            // half-read banner would put a truncated string into the comparison
            // that selects a symbol pack.
            continue;
        };
        let Some(version) = parse_darwin_version(&banner) else {
            continue;
        };
        hits.push(BannerHit {
            address: hit.address,
            text: banner,
            version,
        });
    }

    Ok(BannerScan { hits, outcome })
}

/// Read a banner back out of the layer and normalise it.
///
/// `matched` is the length the scanner reported, which is the whole banner when
/// the string is followed by its NUL — the usual case, since the pattern only
/// accepts printable bytes. Reading is capped at [`MAX_BANNER_BYTES`].
fn read_banner_at(layer: &dyn MemoryLayer, address: u64, matched: usize) -> Option<String> {
    let len = matched.clamp(1, MAX_BANNER_BYTES);
    let mut buffer = vec![0u8; len];
    let read = layer.read_at(address, &mut buffer).ok()?;
    if read == 0 {
        return None;
    }
    buffer.truncate(read);
    // Same normalisation both sides. dwarf2json leaves a trailing NUL and
    // newline on the pack's copy and upstream strips it on only one side, which
    // is how two byte-identical banners come to compare unequal.
    seance_symbols::normalize_banner(&buffer).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use seance_memory::PhysicalLayer;
    use std::sync::Arc;

    const REAL_BANNER: &str = "Darwin Kernel Version 18.7.0: Thu Jun 20 18:42:21 PDT 2019; \
                               root:xnu-4903.270.47~4/RELEASE_X86_64";

    #[test]
    fn the_release_is_read_out_of_a_real_banner() {
        // Taken verbatim from Kernel_Debug_Kit_10.14.6_Build_18G84's `version`
        // constant data, so the parser is tested against the bytes it will meet.
        let version = parse_darwin_version(REAL_BANNER).expect("a well-formed banner");
        assert_eq!(
            version,
            DarwinVersion {
                major: 18,
                minor: 7,
                patch: 0
            }
        );
    }

    #[test]
    fn a_banner_missing_a_version_component_is_refused_rather_than_defaulted() {
        // A zero-filled default here would be compared against `version_major`
        // and either reject a correct pack or, worse, accept a wrong one.
        assert!(parse_darwin_version("Darwin Kernel Version 18.7: x").is_none());
        assert!(parse_darwin_version("Darwin Kernel Version 18.7.0.1: x").is_none());
        assert!(parse_darwin_version("Linux version 6.1.0").is_none());
        assert!(parse_darwin_version("Darwin Kernel Version a.b.c: x").is_none());
    }

    fn layer_containing(payload: Vec<u8>) -> Arc<dyn MemoryLayer> {
        let source: Arc<dyn seance_core::data_source::DataSource> =
            Arc::new(ByteSliceDataSource::new(payload));
        Arc::new(PhysicalLayer::raw(source).expect("a non-empty layer"))
    }

    #[test]
    fn a_banner_planted_in_memory_is_found_with_its_address() {
        let mut image = vec![0u8; 0x2000];
        let at = 0x1100usize;
        image[at..at + REAL_BANNER.len()].copy_from_slice(REAL_BANNER.as_bytes());
        let layer = layer_containing(image);

        let scan = scan_for_banners(layer.as_ref(), &ScanConfig::default()).expect("a scan");
        assert_eq!(scan.hits.len(), 1, "{:?}", scan.hits);
        assert_eq!(scan.hits[0].address, at as u64);
        assert_eq!(scan.hits[0].text, REAL_BANNER);
        assert_eq!(scan.hits[0].version.major, 18);
        assert!(scan.is_complete());
    }

    #[test]
    fn two_copies_of_one_banner_are_both_kept() {
        // Only one copy normally yields a working slide. Deduplicating here
        // would decide which one that is, in the module least able to tell.
        let mut image = vec![0u8; 0x4000];
        for at in [0x0100usize, 0x2100] {
            image[at..at + REAL_BANNER.len()].copy_from_slice(REAL_BANNER.as_bytes());
        }
        let layer = layer_containing(image);
        let scan = scan_for_banners(layer.as_ref(), &ScanConfig::default()).expect("a scan");
        assert_eq!(scan.hits.len(), 2);
        assert_eq!(scan.distinct_texts().len(), 1);
    }

    #[test]
    fn an_image_with_no_banner_yields_no_hits_and_a_complete_sweep() {
        // Both halves matter: the emptiness is only meaningful because the
        // sweep says it looked at everything.
        let layer = layer_containing(vec![0x41u8; 0x2000]);
        let scan = scan_for_banners(layer.as_ref(), &ScanConfig::default()).expect("a scan");
        assert!(scan.hits.is_empty());
        assert!(scan.is_complete());
    }
}
