#![forbid(unsafe_code)]
//! Project VIC / CAID interoperability and open perceptual hashing.
//!
//! This crate is the interop layer a CSAM-triage unit needs and the thing whose
//! absence [`documentation/COMPARISON.md`] flagged as disqualifying: it reads
//! and writes the **VICS data model** (the internationally-agreed JSON that
//! Project VIC US and CAID UK use to share categorised-media hash sets), and it
//! computes an **open perceptual hash** (PDQ) so near-duplicate derivatives —
//! re-encoded, resized, cropped — surface alongside exact matches.
//!
//! # What this crate deliberately does not contain
//!
//! - **No real hash sets.** Actual VIC/CAID data is law-enforcement restricted.
//!   This crate ships the *format*; tests run against synthetic fixtures only.
//!   The posture is identical to the Windows 11 BitLocker corpus: the capability
//!   is in-tree, the sensitive data is not.
//! - **No PhotoDNA.** PhotoDNA is Microsoft-licensed and provisioned to law
//!   enforcement through forensic-tool developers. This crate models the
//!   *field* (so a VICS file's PhotoDNA hashes round-trip untouched) and defines
//!   the [`RobustHasher`] trait a site can implement against its own licensed
//!   library — but no algorithm is bundled.
//!
//! # Evidence grading
//!
//! Matching results carry a grade using the same wire names as the memory tier's
//! `Evidence` enum, because an examiner reads them in the same reports:
//!
//! - an **exact** cryptographic-hash match is [`MatchGrade::Confirmed`] — a
//!   SHA-256 collision is not a defence, so this is the one automatic top grade;
//! - a **perceptual** ("near") match is [`MatchGrade::Scanned`] — a lead, never
//!   an identification, and it always carries the distance and the threshold.
//!
//! A PDQ hash additionally carries [`PDQ_VARIANT`] and [`PDQ_INTEROP_NOTE`]
//! (stamped by [`stamp_pdq_interop`]): this pipeline is not yet validated
//! against Meta's reference vectors, and a hash labelled only `"pdq"` would read
//! to an examiner as if it were. The same split runs through
//! [`RobustMatch`]: `algorithm` names the family, `variant` names the pipeline
//! that actually computed the probe.

pub mod classify;
pub mod cluster;
pub mod model;
pub mod pdq;
pub mod phash;
pub mod robust;

pub use classify::{ClassifierFlag, ContentClassifier};
pub use cluster::cluster_pdq;
pub use model::{Category, VicsError, VicsFile, VicsMedia};
pub use pdq::{pdq_interop_stamp, stamp_pdq_interop, PdqHash, PDQ_INTEROP_NOTE, PDQ_VARIANT};
pub use phash::{AHash, DHash, PHash};
pub use robust::{MatchGrade, PdqBackend, RobustHasher, RobustMatch};
