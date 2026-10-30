#![forbid(unsafe_code)]
//! Feature extraction over raw byte streams, in the spirit of bulk_extractor.
//!
//! Séance's parsers and carver are *file*-oriented: they reconstruct and read
//! files. bulk_extractor works the other way — it sweeps *every byte* for
//! selectors, keys, packets and encoded spans, reaching into slack, unallocated
//! space and the interior of compressed/encoded data that a file parser never
//! opens. This crate provides that capability as pure, independently-tested
//! algorithms; the `ForensicsModule` wrappers that feed results into the pipeline
//! live in the consuming plugin.
//!
//! The modules map onto the bulk_extractor gap analysis in
//! `ROADMAP.md` §2.1 ("Recursive decode-and-rescan substrate + feature scanners"):
//!
//! - [`aes`] — recover AES keys from a memory image by their key schedules
//!   (feeds the decryption plugins; nothing else in Séance does this).
//! - [`net`] — carve IP packets from a stream and reassemble a pcap (recovers
//!   historical traffic the live memory `netscan` cannot see).
//! - [`features`] — selectors (email, URL, card, SSN, IBAN, VIN, GPS, …) over
//!   raw bytes, each with device-offset provenance.
//! - [`histogram`] — aggregate feature hits into a per-value frequency count
//!   (bulk_extractor's `*_histogram.txt` deliverable).
//! - [`wordlist`] — harvest a frequency-ranked password wordlist (feeds the
//!   `seance_crack` cracker).
//! - [`decode`] — lift base64/gzip/xor spans into child buffers for re-scanning.

pub mod aes;
pub mod camellia;
pub mod decode;
pub mod features;
pub mod histogram;
pub mod kuznyechik;
pub mod net;
pub mod serpent;
pub mod twofish;
pub mod wordlist;

pub use aes::{scan_for_keys, AesBits, RecoveredKey};
pub use decode::{decode_base64_spans, decode_gzip_members, decode_xor, Base64Scan, Decoded};
pub use features::{FeatureHit, FeatureScanner};
pub use histogram::{FeatureHistogram, HistogramEntry, KindTotals, MAX_DISTINCT_VALUES};
pub use net::{carve_packets, write_pcap, CarvedPacket};
pub use wordlist::{build_wordlist, Word, WordlistConfig};
