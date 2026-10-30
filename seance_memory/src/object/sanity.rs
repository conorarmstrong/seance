//! [`StructReader::check_struct`]: could this address plausibly hold this
//! structure?
//!
//! Pool scanning finds candidates by matching a four-byte tag, and a four-byte
//! tag matches by accident constantly — in a page of compressed data, in a
//! string table, in the middle of a JPEG. Every false positive that survives
//! becomes a row in a report: a "process" with a plausible PID, a plausible
//! name assembled from whatever bytes followed, and a creation time from 1804.
//!
//! So a candidate is checked structurally before it is believed, and the checks
//! here are the cheap ones that do not need OS knowledge:
//!
//! - **Alignment.** Kernel objects are allocated pointer-aligned or better; an
//!   address that is not is a tag match inside data.
//! - **The structure fits in the address space**, and every byte of it was
//!   acquired. A candidate half of which is in an unmapped page cannot be
//!   confirmed or denied, and confirming it would mean reading fabricated
//!   bytes.
//! - **Pointers are canonical.** On x86-64 the hardware requires bits 63:48 to
//!   replicate bit 47; a member declared as a pointer that holds anything else
//!   was never a pointer. It is the single most discriminating cheap test
//!   available, because random bytes fail it about 65,535 times out of 65,536.
//!
//! What is *not* here: "is this pointer in kernel space", "is this PID sane",
//! "does the object header's type index match". Those are real and necessary
//! checks, and every one of them depends on the OS and the build, so they
//! belong with the plugin that knows which OS it is looking at. This module
//! answers only the question any structure in any address space can be asked.
//!
//! A failed check is a *finding*, not an error: [`check_struct`] returns
//! [`Plausibility`] listing everything wrong with the candidate, and returns
//! `Err` only when the question itself could not be asked.
//!
//! [`check_struct`]: StructReader::check_struct

use seance_symbols::TypeKind;

use super::error::ObjError;
use super::reader::StructReader;
use crate::layer::{backed_len, LayerError, MemoryHole};

/// How many pointer members a single candidate check will read.
///
/// Pool scanning runs this over every tag match in gigabytes of memory, so the
/// work per candidate is bounded. The first few pointers of a structure are
/// where the discrimination is anyway.
pub const MAX_CHECKED_POINTERS: usize = 64;

/// One reason a candidate address is not a plausible home for a structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlausibilityFailure {
    /// The address does not meet the required alignment.
    Misaligned {
        /// The candidate address.
        address: u64,
        /// The alignment it was checked against.
        alignment: u64,
    },
    /// The structure would extend past the top of the address space.
    ExtendsPastTheAddressSpace {
        /// The last byte the structure would occupy.
        last: u64,
        /// The highest addressable byte in the layer.
        max_address: u64,
    },
    /// Some of the structure's bytes were never acquired, so the candidate can
    /// neither be confirmed nor denied.
    NotFullyBacked(MemoryHole),
    /// A member declared as a pointer holds a value no canonical address space
    /// can contain.
    NonCanonicalPointer {
        /// The member.
        member: String,
        /// The value it held.
        value: u64,
    },
    /// A pointer member could not be read even though the structure appeared to
    /// be backed. Recorded rather than ignored: it means the layer disagrees
    /// with itself, which is worth knowing.
    Unreadable {
        /// The member.
        member: String,
        /// Why it could not be read.
        detail: String,
    },
}

impl PlausibilityFailure {
    /// Stable identifier for artifact metadata and log lines.
    pub fn as_str(&self) -> &'static str {
        match self {
            PlausibilityFailure::Misaligned { .. } => "misaligned",
            PlausibilityFailure::ExtendsPastTheAddressSpace { .. } => "extends_past_address_space",
            PlausibilityFailure::NotFullyBacked(_) => "not_fully_backed",
            PlausibilityFailure::NonCanonicalPointer { .. } => "non_canonical_pointer",
            PlausibilityFailure::Unreadable { .. } => "unreadable",
        }
    }
}

impl std::fmt::Display for PlausibilityFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlausibilityFailure::Misaligned { address, alignment } => {
                write!(f, "{address:#x} is not aligned to {alignment} byte(s)")
            }
            PlausibilityFailure::ExtendsPastTheAddressSpace { last, max_address } => write!(
                f,
                "the structure would end at {last:#x}, past the top of the address space \
                 ({max_address:#x})"
            ),
            PlausibilityFailure::NotFullyBacked(hole) => {
                write!(f, "part of the structure was never acquired: {hole}")
            }
            PlausibilityFailure::NonCanonicalPointer { member, value } => write!(
                f,
                "'{member}' holds {value:#x}, which is not a canonical address"
            ),
            PlausibilityFailure::Unreadable { member, detail } => {
                write!(f, "'{member}' could not be read: {detail}")
            }
        }
    }
}

/// The verdict on one candidate address.
///
/// Carries every reason rather than the first, because a scanner tuning its
/// false-positive rate needs to know which test did the work.
#[derive(Debug, Clone)]
pub struct Plausibility {
    /// The candidate address.
    pub address: u64,
    /// The structure it was checked against.
    pub type_name: String,
    /// The structure's declared size.
    pub size: u64,
    /// The alignment it was checked against.
    pub alignment: u64,
    /// How many pointer members were actually read.
    pub pointers_checked: usize,
    /// Everything wrong with the candidate. Empty means plausible.
    pub failures: Vec<PlausibilityFailure>,
}

impl Plausibility {
    /// Whether nothing structural rules this candidate out.
    ///
    /// "Plausible" is the strongest claim this module makes. It is not "this is
    /// an `_EPROCESS`"; it is "nothing about the address space says it cannot
    /// be", which is what a scanner needs before spending a full parse on it.
    pub fn is_plausible(&self) -> bool {
        self.failures.is_empty()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "type": self.type_name,
            "size": self.size,
            "alignment": self.alignment,
            "pointers_checked": self.pointers_checked,
            "plausible": self.is_plausible(),
            "failures": self
                .failures
                .iter()
                .map(|failure| serde_json::json!({
                    "class": failure.as_str(),
                    "detail": failure.to_string(),
                }))
                .collect::<Vec<_>>(),
        })
    }
}

/// Whether a value can be an address in a `pointer_size`-byte address space.
///
/// On x86-64 (and on AArch64's split halves) the hardware requires bits 63:48
/// to replicate bit 47, so only the bottom and top 128 TiB of the 64-bit range
/// are addressable at all. A "pointer" holding anything else was never a
/// pointer — it is data that happened to sit where a pointer would be — which
/// makes this the cheapest high-yield test a pool scanner has.
///
/// Null is canonical: a null pointer is a legitimate value with a meaning.
pub fn is_canonical(value: u64, pointer_size: u8) -> bool {
    match pointer_size {
        4 => value <= u64::from(u32::MAX),
        8 => {
            let top = value >> 47;
            top == 0 || top == 0x1_FFFF
        }
        _ => false,
    }
}

impl StructReader {
    /// Could `address` plausibly hold a structure of this type?
    ///
    /// Aligned to the guest pointer width, which is the weakest alignment any
    /// kernel allocator produces. Use [`StructReader::check_struct_aligned`]
    /// when the allocator's granularity is known — Windows pool allocations are
    /// 16-byte aligned on x64 — because a stricter alignment discards more
    /// false positives.
    pub fn check_struct(&self, address: u64, type_name: &str) -> Result<Plausibility, ObjError> {
        let alignment = u64::from(self.pointer_size()?);
        self.check_struct_aligned(address, type_name, alignment)
    }

    /// [`StructReader::check_struct`] with an explicit alignment requirement.
    ///
    /// An `alignment` of 0 or 1 imposes none.
    ///
    /// # Errors
    ///
    /// Only when the question cannot be asked: an unknown type, a type that is
    /// not an aggregate, or one whose declared size is zero. A candidate that
    /// simply fails the checks is `Ok` with a non-empty
    /// [`Plausibility::failures`], because "this address is not a process" is
    /// an answer, not a failure.
    pub fn check_struct_aligned(
        &self,
        address: u64,
        type_name: &str,
        alignment: u64,
    ) -> Result<Plausibility, ObjError> {
        let size = self.symbols().aggregate(type_name)?.size;
        if size == 0 {
            return Err(seance_symbols::SymbolError::malformed(format!(
                "'{type_name}' declares a size of 0, so no address can be checked against it"
            ))
            .into());
        }
        let pointer_size = self.pointer_size()?;
        let alignment = alignment.max(1);
        let max_address = self.layer().max_address();
        let mut failures = Vec::new();

        if !address.is_multiple_of(alignment) {
            failures.push(PlausibilityFailure::Misaligned { address, alignment });
        }

        // Does the whole structure fit inside the address space, and was every
        // byte of it acquired? Both are asked through `mapping`, so this cannot
        // drift out of agreement with what a read would actually do.
        match address.checked_add(size - 1) {
            None => failures.push(PlausibilityFailure::ExtendsPastTheAddressSpace {
                last: u64::MAX,
                max_address,
            }),
            Some(last) if last > max_address => {
                failures.push(PlausibilityFailure::ExtendsPastTheAddressSpace { last, max_address })
            }
            // `backed_len`, not `covered_len`: a layer over a compressed
            // acquisition returns a run per whole frame, so summing run
            // lengths reports a structure as over-covered and rejects one the
            // evidence entirely holds. The same comparison, at a different
            // caller, refused every page of a real capture.
            Some(last) => match self.layer().mapping(address, size) {
                Ok(runs) if backed_len(&runs, address, size) == size => {}
                Ok(_) => failures
                    .push(PlausibilityFailure::ExtendsPastTheAddressSpace { last, max_address }),
                Err(LayerError::Hole(hole)) => {
                    failures.push(PlausibilityFailure::NotFullyBacked(hole))
                }
                Err(LayerError::OutOfRange { .. }) => failures
                    .push(PlausibilityFailure::ExtendsPastTheAddressSpace { last, max_address }),
                Err(other) => return Err(other.into()),
            },
        }

        // Only worth reading pointers out of a candidate that is entirely
        // there; otherwise every read fails for a reason already recorded.
        let mut pointers_checked = 0usize;
        if failures.is_empty() {
            let object = self.object(address, type_name)?;
            let aggregate = self.symbols().aggregate(type_name)?;
            for member in &aggregate.members {
                if pointers_checked >= MAX_CHECKED_POINTERS {
                    break;
                }
                let is_pointer = matches!(
                    self.symbols().entry(member.ty),
                    Ok(entry) if matches!(entry.kind, TypeKind::Pointer { .. })
                );
                if !is_pointer {
                    continue;
                }
                pointers_checked += 1;
                match object.pointer(&member.name) {
                    Ok(value) => {
                        if !is_canonical(value, pointer_size) {
                            failures.push(PlausibilityFailure::NonCanonicalPointer {
                                member: member.name.to_string(),
                                value,
                            });
                        }
                    }
                    Err(err) => failures.push(PlausibilityFailure::Unreadable {
                        member: member.name.to_string(),
                        detail: err.to_string(),
                    }),
                }
            }
        }

        Ok(Plausibility {
            address,
            type_name: type_name.to_string(),
            size,
            alignment,
            pointers_checked,
            failures,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::MemoryLayer;
    use crate::object::test_support::{
        fixture, fixture32, MAX_ADDRESS, NODE32_A, PROC_A, PROC_E, PROC_STRADDLE,
    };
    use std::sync::Arc;

    /// A layer that reports whole frames, as one over a compressed acquisition
    /// does. Delegates everything except `mapping`, which widens each run to a
    /// frame boundary the way an encoded run must.
    #[derive(Debug)]
    struct FramedLayer {
        inner: Arc<dyn MemoryLayer>,
        frame: u64,
    }

    impl seance_core::data_source::DataSource for FramedLayer {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.as_data_source().read_at(offset, buf)
        }
        fn size(&self) -> u64 {
            self.inner.as_data_source().size()
        }
    }

    impl MemoryLayer for FramedLayer {
        fn min_address(&self) -> u64 {
            self.inner.min_address()
        }
        fn max_address(&self) -> u64 {
            self.inner.max_address()
        }
        fn mapping(
            &self,
            offset: u64,
            length: u64,
        ) -> Result<Vec<crate::layer::MappedRange>, LayerError> {
            // Ask the real layer first, so holes and out-of-range keep their
            // own meaning; only the run *shape* changes.
            let runs = self.inner.mapping(offset, length)?;
            if runs.is_empty() {
                return Ok(runs);
            }
            let first = runs[0].offset - (runs[0].offset % self.frame);
            let last_end = runs[runs.len() - 1].end();
            let end = last_end.div_ceil(self.frame) * self.frame;
            let mut widened = Vec::new();
            let mut at = first;
            while at < end {
                widened.push(crate::layer::MappedRange::identity(at, self.frame, at));
                at += self.frame;
            }
            Ok(widened)
        }
        fn layer_meta(&self) -> &crate::meta::LayerMeta {
            self.inner.layer_meta()
        }
        fn as_data_source(&self) -> &dyn seance_core::data_source::DataSource {
            self
        }
    }

    /// A structure the evidence entirely holds stays plausible when the layer
    /// beneath describes it with runs wider than the structure.
    ///
    /// The plausibility check asks whether every byte of a candidate was
    /// acquired. It used to ask by summing the run lengths and requiring the
    /// total to equal the structure's size — which, against a layer that
    /// projects whole frames, is never true. Every candidate would then be
    /// rejected as extending past the address space: a scan over a compressed
    /// capture would find nothing and say so in the language of a bounds error.
    #[test]
    fn a_structure_stays_plausible_over_a_layer_that_projects_whole_frames() {
        let plain = fixture();
        let framed: Arc<dyn MemoryLayer> = Arc::new(FramedLayer {
            inner: Arc::clone(plain.layer()),
            frame: 0x1000,
        });
        let reader = StructReader::new(framed, Arc::clone(plain.symbols()));

        let verdict = reader.check_struct(PROC_A, "proc").unwrap();
        assert!(
            verdict.is_plausible(),
            "a structure the evidence holds must stay plausible when the layer \
             beneath widens its runs: {:?}",
            verdict.failures
        );
        assert_eq!(verdict.size, 104);
    }

    /// And a structure that genuinely runs off the acquisition is still caught.
    #[test]
    fn a_structure_past_the_acquisition_is_still_refused_over_whole_frame_runs() {
        let plain = fixture();
        let framed: Arc<dyn MemoryLayer> = Arc::new(FramedLayer {
            inner: Arc::clone(plain.layer()),
            frame: 0x1000,
        });
        let reader = StructReader::new(framed, Arc::clone(plain.symbols()));

        let verdict = reader.check_struct(PROC_STRADDLE, "proc").unwrap();
        assert!(
            !verdict.is_plausible(),
            "a structure running past the end of the acquisition must still be \
             refused; widening runs must not buy plausibility"
        );
    }

    #[test]
    fn a_real_structure_at_its_real_address_is_plausible() {
        let reader = fixture();
        let verdict = reader.check_struct(PROC_A, "proc").unwrap();
        assert!(verdict.is_plausible(), "{:?}", verdict.failures);
        assert_eq!(verdict.size, 104);
        assert_eq!(verdict.alignment, 8);
        assert_eq!(
            verdict.pointers_checked, 2,
            "`parent` and `handler` are the pointer members; `links` is embedded"
        );
        assert_eq!(verdict.to_json()["plausible"], true);
    }

    #[test]
    fn a_misaligned_candidate_is_rejected() {
        // A tag match one byte into a structure is a tag match inside data.
        let reader = fixture();
        let verdict = reader.check_struct(PROC_A + 1, "proc").unwrap();
        assert!(!verdict.is_plausible());
        assert!(verdict
            .failures
            .iter()
            .any(|f| matches!(f, PlausibilityFailure::Misaligned { alignment: 8, .. })));
        assert_eq!(verdict.failures[0].as_str(), "misaligned");
    }

    #[test]
    fn alignment_can_be_tightened_to_the_allocator_that_produced_the_object() {
        let reader = fixture();
        // 0x1100 is 16-byte aligned; 0x1108 is not.
        assert!(reader
            .check_struct_aligned(PROC_A, "proc", 16)
            .unwrap()
            .is_plausible());
        assert!(!reader
            .check_struct_aligned(PROC_A + 8, "proc", 16)
            .unwrap()
            .is_plausible());
        // And an alignment of zero imposes none rather than dividing by zero.
        let verdict = reader.check_struct_aligned(PROC_A + 1, "proc", 0).unwrap();
        assert_eq!(verdict.alignment, 1);
        assert!(
            !verdict
                .failures
                .iter()
                .any(|f| matches!(f, PlausibilityFailure::Misaligned { .. })),
            "no alignment was required, so none can have been violated"
        );
    }

    #[test]
    fn the_default_alignment_follows_the_pointer_width_the_table_declares() {
        // Requiring eight-byte alignment in a four-byte address space would
        // discard half of every real allocation as a false positive.
        let reader = fixture32();
        let verdict = reader.check_struct(NODE32_A, "node32").unwrap();
        assert!(verdict.is_plausible(), "{:?}", verdict.failures);
        assert_eq!(verdict.alignment, 4);
        assert_eq!(verdict.size, 20);
        assert_eq!(
            verdict.pointers_checked, 1,
            "`next_node` is the only pointer member; `links` is embedded"
        );
    }

    #[test]
    fn a_candidate_that_would_run_off_the_top_of_the_space_is_rejected() {
        let reader = fixture();
        let address = MAX_ADDRESS - 7;
        let verdict = reader.check_struct(address, "proc").unwrap();
        assert!(!verdict.is_plausible());
        assert!(verdict
            .failures
            .iter()
            .any(|f| matches!(f, PlausibilityFailure::ExtendsPastTheAddressSpace { .. })));
        assert_eq!(
            verdict.pointers_checked, 0,
            "nothing is read out of a candidate that does not fit"
        );
    }

    #[test]
    fn a_candidate_straddling_unacquired_memory_is_rejected_with_the_hole() {
        // Neither confirmable nor deniable: half its bytes were never captured,
        // and treating the missing half as zeros would confirm almost anything.
        let reader = fixture();
        let verdict = reader
            .check_struct_aligned(PROC_STRADDLE, "proc", 4)
            .unwrap();
        assert!(!verdict.is_plausible());
        let hole = verdict
            .failures
            .iter()
            .find_map(|f| match f {
                PlausibilityFailure::NotFullyBacked(hole) => Some(*hole),
                _ => None,
            })
            .expect("the unmapped range must be named");
        assert_eq!(hole.address, 0x2000);
        assert_eq!(
            verdict.to_json()["failures"][0]["class"],
            "not_fully_backed"
        );
    }

    #[test]
    fn a_non_canonical_pointer_rejects_a_candidate() {
        let reader = fixture();
        let verdict = reader.check_struct(PROC_E, "proc").unwrap();
        assert!(!verdict.is_plausible());
        assert!(verdict.failures.iter().any(|f| matches!(
            f,
            PlausibilityFailure::NonCanonicalPointer {
                value: 0x0000_8000_0000_0000,
                ..
            }
        )));
        assert!(verdict.failures[0].to_string().contains("parent"));
    }

    #[test]
    fn canonical_form_is_judged_at_the_declared_pointer_width() {
        // The bottom and top 128 TiB, and nothing between them.
        assert!(is_canonical(0, 8), "null is a legitimate value");
        assert!(is_canonical(0x0000_7FFF_FFFF_FFFF, 8));
        assert!(!is_canonical(0x0000_8000_0000_0000, 8));
        assert!(!is_canonical(0xFFFF_7FFF_FFFF_FFFF, 8));
        assert!(is_canonical(0xFFFF_8000_0000_0000, 8));
        assert!(is_canonical(0xFFFF_FFFF_FFFF_FFFF, 8));

        // A 32-bit space has no canonical hole, but nothing above 4 GiB either.
        assert!(is_canonical(0xFFFF_FFFF, 4));
        assert!(!is_canonical(0x1_0000_0000, 4));

        // A width the ISF should never have declared is never plausible.
        assert!(!is_canonical(0, 2));
    }

    #[test]
    fn asking_about_something_that_is_not_a_structure_is_an_error_not_a_verdict() {
        let reader = fixture();
        assert!(reader.check_struct(PROC_A, "int").is_err());
        assert!(reader.check_struct(PROC_A, "no_such_type").is_err());
    }
}
