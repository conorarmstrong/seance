//! The hand-built page-table fixtures the two walkers share.
//!
//! One physical image whose tables a test writes by hand, and the borrowed
//! pieces a walk needs to run over it. It lives in its own module rather than
//! inside one walker's test module because both the upward walk
//! ([`super::walk`]) and the downward enumeration ([`super::enumerate`]) are
//! tested against the same hierarchies: two copies of the builder would drift,
//! and a fixture that no longer matches the other walker's is how two walkers
//! come to disagree about the same bytes while both their tests pass.
//!
//! Test-only, and deliberately not `pub`: nothing outside this crate builds a
//! memory image by writing page-table entries at literal addresses.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use seance_core::data_source::ByteSliceDataSource;

use crate::physical::PhysicalLayer;
use crate::translate::cache::TableCache;
use crate::translate::spec::{PagingMode, PagingSpec, PteSemantics};
use crate::translate::walk::{PageWalk, TranslationPolicy};

pub const IMAGE_SIZE: usize = 0x40_0000;

/// A physical memory image whose page tables a test writes by hand.
///
/// Everything the walker reads comes from these bytes, so a test proves the
/// walk and nothing else.
pub struct Image {
    /// The bytes themselves. A test truncates them to prove a table that
    /// straddles the end of the acquisition.
    pub bytes: Vec<u8>,
}

impl Image {
    pub fn new() -> Self {
        Self {
            bytes: vec![0u8; IMAGE_SIZE],
        }
    }

    /// Write an 8-byte entry at `table + index * 8`.
    pub fn entry64(&mut self, table: u64, index: u64, value: u64) {
        let at = (table + index * 8) as usize;
        self.bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Write a 4-byte entry at `table + index * 4`.
    pub fn entry32(&mut self, table: u64, index: u64, value: u32) {
        let at = (table + index * 4) as usize;
        self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    pub fn fill(&mut self, at: u64, len: usize, byte: u8) {
        let at = at as usize;
        self.bytes[at..at + len].fill(byte);
    }

    pub fn layer(self) -> PhysicalLayer {
        PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(self.bytes)))
            .expect("a non-empty image")
    }
}

/// The pieces a walk borrows, kept alive together for a test.
pub struct Harness {
    physical: PhysicalLayer,
    spec: PagingSpec,
    /// The entry memo. A test asserts it is untouched, since a walk that
    /// refused before reading anything must have memoised nothing.
    pub cache: TableCache,
    /// The policy in force. A test reads it back to state which half of a
    /// pair of assertions it is exercising.
    pub policy: TranslationPolicy,
    /// How many translations the uniform-table heuristic has refused. A test
    /// asserts on it directly, since zero is the measured statement that the
    /// heuristic never fired.
    pub suppressed: AtomicU64,
}

impl Harness {
    pub fn new(image: Image, mode: PagingMode, semantics: PteSemantics) -> Self {
        Self {
            physical: image.layer(),
            // These fixtures were written against the pre-Windows-8
            // `PageFileLow` position, so the harness states it. A spec that
            // is not told stays silent about the pagefile index, which is
            // the behaviour `an_unknown_build_does_not_name_a_pagefile`
            // covers.
            spec: PagingSpec::new(mode, semantics).with_win8_pagefile_layout(false),
            cache: TableCache::new(),
            policy: TranslationPolicy::default(),
            suppressed: AtomicU64::new(0),
        }
    }

    pub fn without_uniform_suppression(mut self) -> Self {
        self.policy.suppress_uniform_tables = false;
        self
    }

    /// Whether the spec in force would accept this address at all, for a test
    /// asserting that a reported address is one the hardware could issue.
    pub fn spec_is_canonical(&self, va: u64) -> bool {
        self.spec.is_canonical(va)
    }

    pub fn walk(&self) -> PageWalk<'_> {
        PageWalk::new(
            &self.physical,
            &self.spec,
            &self.cache,
            self.policy,
            &self.suppressed,
        )
    }
}
