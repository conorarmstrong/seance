//! Opening one process's own address space.
//!
//! A `task_struct` lives in the kernel's address space; a process's environment
//! block and its shell history do not. They live in the process's own user
//! memory, reachable only through that process's page tables, whose root the
//! kernel keeps in `mm_struct.pgd`.
//!
//! `pgd` is a **kernel virtual** address. The hardware wants a physical one, so
//! the root is obtained by translating `pgd` through the kernel's own address
//! space — the same step Volatility 3 takes in `task.add_process_layer`. Doing
//! it any other way means subtracting a direct-map constant that varies by
//! kernel version and configuration, which is exactly the class of hardcoded
//! constant this tier exists to avoid.
//!
//! ## Why "no address space" is four different answers
//!
//! [`SpaceRefusal`] keeps them apart, because a stage that renders them the same
//! reports "this process had no environment" for a kernel thread, for a page
//! that was swapped out, and for a build whose `mm_struct` this tool could not
//! read — three sentences an examiner acts on differently, and only the first of
//! which is a fact about the machine.

use std::sync::Arc;

use seance_memory::binding::{BuildBinding, Field};
use seance_memory::layer::MemoryLayer;
use seance_memory::object::Obj;
use seance_memory::translate::{PagingSpec, TranslationPolicy, VirtualLayer};

use crate::error::StageError;
use crate::profile::LinuxProfile;

/// One process's own address space.
pub struct ProcessSpace {
    /// The address space, read the same way the kernel's is.
    pub layer: Arc<dyn MemoryLayer>,
    /// The kernel virtual address of the page-table root, as `mm_struct.pgd`
    /// held it.
    pub pgd_virtual: u64,
    /// The physical address that translated to, which is the root the hardware
    /// was using.
    pub dtb: u64,
}

/// Why a process's address space could not be opened.
///
/// Only [`SpaceRefusal::NoUserAddressSpace`] is a fact about the machine.
/// Everything else is a limit of the evidence or of this tool, and a stage must
/// report the two differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpaceRefusal {
    /// This task has no user address space. A kernel thread. Nothing was missed
    /// and there was never anything to read.
    NoUserAddressSpace,
    /// This build declares no `mm_struct.pgd`, so the question could not be put.
    PageTableRootNotDeclared {
        /// The member the build does not have.
        member: &'static str,
    },
    /// The `mm_struct`'s bytes, or the `pgd` inside it, would not read.
    Unreadable(String),
    /// `pgd` was read and does not translate, so the page-table root it names
    /// was not captured by this acquisition.
    RootNotAcquired(String),
    /// The address space could not be built over that root.
    Refused(String),
}

impl SpaceRefusal {
    /// Whether this refusal means evidence is missing, as opposed to there
    /// being none to miss.
    ///
    /// A kernel thread with no user memory is not a gap: there is no
    /// environment and no shell history to find, and counting it as
    /// incompleteness would tell an examiner that evidence was missed when none
    /// existed. Every other refusal here IS a gap.
    pub fn is_a_gap(&self) -> bool {
        !matches!(self, SpaceRefusal::NoUserAddressSpace)
    }

    /// Stable machine-readable class, for artifact metadata.
    pub fn class(&self) -> &'static str {
        match self {
            SpaceRefusal::NoUserAddressSpace => "no_user_address_space",
            SpaceRefusal::PageTableRootNotDeclared { .. } => "page_table_root_not_declared",
            SpaceRefusal::Unreadable(_) => "unreadable",
            SpaceRefusal::RootNotAcquired(_) => "root_not_acquired",
            SpaceRefusal::Refused(_) => "refused",
        }
    }

    /// One sentence an examiner reads.
    pub fn detail(&self) -> String {
        match self {
            SpaceRefusal::NoUserAddressSpace => {
                "this task has no user address space, so there was never any user memory to read"
                    .to_string()
            }
            SpaceRefusal::PageTableRootNotDeclared { member } => format!(
                "this kernel build's memory descriptor declares no '{member}' member, so this \
                 process's own address space could not be opened"
            ),
            SpaceRefusal::Unreadable(detail) => format!(
                "this process's memory descriptor could not be read, so its address space could \
                 not be opened: {detail}"
            ),
            SpaceRefusal::RootNotAcquired(detail) => format!(
                "this process's page-table root was not captured by the acquisition, so its \
                 memory cannot be reached: {detail}"
            ),
            SpaceRefusal::Refused(detail) => format!(
                "an address space could not be built over this process's page-table root: \
                 {detail}"
            ),
        }
    }

    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "class": self.class(),
            "detail": self.detail(),
            "is_a_gap": self.is_a_gap(),
        })
    }
}

/// The `mm_struct` a task points at, or why there is none to open.
///
/// # Errors
///
/// [`StageError`] only for a lookup the stage never declared, which is a
/// programming error. A task with no memory descriptor is `Ok(Err(..))`.
pub fn memory_descriptor(
    layout: &BuildBinding,
    task: &Obj,
    mm_key: &'static str,
) -> Result<Result<Obj, SpaceRefusal>, StageError> {
    let bound = layout.member(mm_key)?;
    let Some(path) = bound.member() else {
        return Ok(Err(SpaceRefusal::PageTableRootNotDeclared {
            member: bound.candidates()[0],
        }));
    };
    Ok(match task.follow(path) {
        Ok(Some(mm)) => Ok(mm),
        // A null `mm` is the kernel's own way of saying "kernel thread". It is
        // the one refusal here that is a finding rather than a gap.
        Ok(None) => Err(SpaceRefusal::NoUserAddressSpace),
        Err(err) => Err(SpaceRefusal::Unreadable(err.to_string())),
    })
}

/// The paging spec a process's own space is read under, given the kernel's.
///
/// On Intel the same spec: one root register (`CR3`) serves both halves. On
/// arm64 the kernel's spec is a TTBR1 regime, and `mm->pgd` is what the
/// kernel loads into **TTBR0_EL1**, the bottom half of the address space; so
/// a process is read under the TTBR0 regime of the same granule and width.
/// Linux sets `T0SZ` equal to `T1SZ` in every configuration this build
/// decodes (a 52-bit user space is FEAT_LVA/LPA2, which discovery does not offer), and sets
/// `TBI0` unconditionally (`arch/arm64/mm/proc.S`, `__cpu_setup`), so the
/// process regime ignores the top byte of a user pointer as the hardware did
/// and a tagged pointer translates. The conventions for non-present entries
/// carry over unchanged.
pub fn process_paging(kernel: PagingSpec) -> PagingSpec {
    use seance_memory::translate::{Arm64Regime, PagingMode, Ttbr};
    let Some(regime) = kernel.mode().arm64() else {
        return kernel;
    };
    if regime.ttbr() == Ttbr::Ttbr0 {
        return kernel;
    }
    match Arm64Regime::new(regime.granule(), Ttbr::Ttbr0, regime.va_bits()) {
        Ok(user) => PagingSpec::new(
            PagingMode::Arm64(user.with_top_byte_ignore(true)),
            kernel.semantics(),
        ),
        // Unreachable: the width was already accepted for TTBR1.
        Err(_) => kernel,
    }
}

/// Open a process's own address space from its memory descriptor.
///
/// # Errors
///
/// [`StageError`] only for a lookup the stage never declared. Every way a real
/// process can fail to yield an address space is `Ok(Err(..))`, because a stage
/// must go on to the next process rather than abandon the machine.
pub fn open(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    mm: &Obj,
    pgd_key: &'static str,
) -> Result<Result<ProcessSpace, SpaceRefusal>, StageError> {
    let pgd_virtual = match layout.read_pointer(mm, pgd_key)? {
        Field::Known(0) => {
            return Ok(Err(SpaceRefusal::Unreadable(
                "the memory descriptor's page-table root is null".to_string(),
            )))
        }
        Field::Known(value) => value,
        Field::NotDeclared { member } => {
            return Ok(Err(SpaceRefusal::PageTableRootNotDeclared { member }))
        }
        Field::NotApplicable => {
            return Ok(Err(SpaceRefusal::Unreadable(
                "the memory descriptor states it has no page-table root".to_string(),
            )))
        }
        Field::Unavailable(detail) => return Ok(Err(SpaceRefusal::Unreadable(detail))),
    };

    // The root is a kernel virtual address; the hardware used the physical one.
    // Translating it through the kernel's own space is the only route that does
    // not hardcode a direct-map constant.
    let Some(kernel) = profile.kernel_space.as_virtual() else {
        return Ok(Err(SpaceRefusal::Refused(
            "the kernel address space is not a translated layer, so a process page-table root \
             cannot be resolved through it"
                .to_string(),
        )));
    };
    let dtb = match kernel.translate(pgd_virtual) {
        Ok(translation) => translation.phys,
        Err(err) => return Ok(Err(SpaceRefusal::RootNotAcquired(err.to_string()))),
    };

    match VirtualLayer::with_cache(
        Arc::clone(&profile.physical),
        dtb,
        process_paging(profile.paging),
        TranslationPolicy::default(),
        Arc::clone(&profile.cache),
    ) {
        // Attach any swap areas the examiner supplied, so a page this process
        // wrote out to swap resolves to its bytes through this layer rather than
        // staying a hole. Empty is the ordinary case and leaves the layer as it
        // was.
        Ok(layer) => Ok(Ok(ProcessSpace {
            layer: Arc::new(layer.with_swap(profile.swap.clone())) as Arc<dyn MemoryLayer>,
            pgd_virtual,
            dtb,
        })),
        Err(err) => Ok(Err(SpaceRefusal::Refused(err.to_string()))),
    }
}

/// Read `length` bytes from a process's address space, page by page, keeping the
/// contiguous runs that were acquired.
///
/// Returns each run as `(address, bytes)`, plus the total number of bytes that
/// could not be read. Deliberately **not** a single buffer with the gaps filled:
/// a search across a fabricated region can match bytes that were never in the
/// evidence, and a pointer assembled half from real memory and half from
/// invented zeros is a pointer the machine never held.
pub fn read_runs(layer: &dyn MemoryLayer, start: u64, length: u64, budget: u64) -> ReadRuns {
    const PAGE: u64 = 0x1000;
    let mut runs: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut unread: u64 = 0;
    let mut read: u64 = 0;
    let mut capped = false;
    let mut at = start;
    let end = start.saturating_add(length);

    while at < end {
        if read >= budget {
            capped = true;
            unread = unread.saturating_add(end - at);
            break;
        }
        // Stop at the next page boundary, so an unacquired page costs that page
        // and not whatever else a straddling read happened to cover.
        let to_page_end = PAGE - (at & (PAGE - 1));
        let want = to_page_end.min(end - at) as usize;
        let mut page = vec![0u8; want];
        let ok = seance_core::io::read_exact_or_fail(
            layer.as_data_source(),
            at,
            &mut page,
            "a page of process memory",
        )
        .is_ok();
        if ok {
            read = read.saturating_add(want as u64);
            // Extend the run in place when this page follows the last one, so a
            // pointer straddling two acquired pages is still found.
            let follows_last = runs
                .last()
                .is_some_and(|(start, bytes)| start.saturating_add(bytes.len() as u64) == at);
            if follows_last {
                if let Some((_, bytes)) = runs.last_mut() {
                    bytes.extend_from_slice(&page);
                }
            } else {
                runs.push((at, page));
            }
        } else {
            unread = unread.saturating_add(want as u64);
        }
        at = at.saturating_add(want as u64);
    }

    ReadRuns {
        runs,
        bytes_read: read,
        bytes_unread: unread,
        capped,
    }
}

/// The acquired runs of a requested range, and what was not acquired.
pub struct ReadRuns {
    /// Contiguous acquired runs, each `(address, bytes)`, in ascending order.
    pub runs: Vec<(u64, Vec<u8>)>,
    /// Bytes actually read.
    pub bytes_read: u64,
    /// Bytes in the requested range that could not be read, including anything
    /// above a budget that fired.
    pub bytes_unread: u64,
    /// Whether the byte budget stopped the read. The remainder is counted in
    /// `bytes_unread`.
    pub capped: bool,
}

impl ReadRuns {
    /// Whether every byte of the requested range was read.
    pub fn is_complete(&self) -> bool {
        self.bytes_unread == 0 && !self.capped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_memory::PhysicalLayer;

    #[test]
    fn only_a_kernel_thread_is_not_a_gap() {
        // The distinction the type exists for. Three of these mean an examiner
        // should know evidence is missing; one means there was none to miss.
        assert!(!SpaceRefusal::NoUserAddressSpace.is_a_gap());
        assert!(SpaceRefusal::Unreadable("swapped out".into()).is_a_gap());
        assert!(SpaceRefusal::RootNotAcquired("not captured".into()).is_a_gap());
        assert!(SpaceRefusal::Refused("bad root".into()).is_a_gap());
        assert!(SpaceRefusal::PageTableRootNotDeclared { member: "pgd" }.is_a_gap());
    }

    #[test]
    fn every_refusal_reads_as_a_sentence_and_has_a_stable_class() {
        for refusal in [
            SpaceRefusal::NoUserAddressSpace,
            SpaceRefusal::PageTableRootNotDeclared { member: "pgd" },
            SpaceRefusal::Unreadable("x".into()),
            SpaceRefusal::RootNotAcquired("x".into()),
            SpaceRefusal::Refused("x".into()),
        ] {
            assert!(!refusal.class().is_empty());
            assert!(refusal.detail().len() > 20, "{}", refusal.detail());
            assert_eq!(refusal.to_json()["class"], refusal.class());
        }
    }

    #[test]
    fn an_arm64_process_space_is_rooted_under_ttbr0_rules() {
        // `mm->pgd` on arm64 is loaded into TTBR0_EL1, whose half of the
        // address space is the bottom one. Reading it with the kernel's TTBR1
        // spec would refuse every user address as non-canonical — or, with a
        // spec that accepted them, walk them through the wrong regime.
        use seance_memory::translate::{Arm64Granule, Arm64Regime, PagingMode, PteSemantics, Ttbr};
        for (granule, bits) in [(Arm64Granule::Kb4, 48u8), (Arm64Granule::Kb4, 39)] {
            let kernel = PagingSpec::new(
                PagingMode::Arm64(Arm64Regime::new(granule, Ttbr::Ttbr1, bits).unwrap()),
                PteSemantics::Linux,
            );
            let process = process_paging(kernel);
            let regime = process.mode().arm64().expect("still arm64");
            assert_eq!(regime.ttbr(), Ttbr::Ttbr0);
            assert_eq!((regime.granule(), regime.va_bits()), (granule, bits));
            assert_eq!(process.semantics(), PteSemantics::Linux);
            let user = 0x0000_0040_0000_1000u64 & ((1u64 << bits) - 1);
            assert!(process.is_canonical(user), "{user:#x}");
            assert!(!process.is_canonical(u64::MAX << bits), "a kernel address");
            // Linux sets TCR_EL1.TBI0 unconditionally (proc.S `__cpu_setup`),
            // so a tagged user pointer is one the hardware translated.
            assert!(regime.tbi(), "TBI0 is on for every Linux arm64 process");
            let tagged = user | (0x2a << 56);
            assert!(process.is_canonical(tagged), "{tagged:#x}");
        }
        // Intel is untouched: one root register, one spec.
        let intel = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Linux);
        assert_eq!(process_paging(intel).mode(), PagingMode::Intel32e);
    }

    fn flat(bytes: Vec<u8>) -> PhysicalLayer {
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        PhysicalLayer::raw(source).expect("a non-empty image")
    }

    #[test]
    fn a_read_returns_the_acquired_runs_and_counts_what_it_could_not_reach() {
        let layer = flat(vec![0xAB; 0x3000]);
        let runs = read_runs(&layer, 0, 0x3000, u64::MAX);
        assert!(runs.is_complete());
        assert_eq!(runs.runs.len(), 1, "adjacent pages join into one run");
        assert_eq!(runs.runs[0].0, 0);
        assert_eq!(runs.runs[0].1.len(), 0x3000);
        assert_eq!(runs.bytes_unread, 0);

        // Past the end of the image: nothing was acquired there, and it is
        // counted rather than filled in.
        let short = read_runs(&layer, 0x2000, 0x3000, u64::MAX);
        assert!(!short.is_complete());
        assert_eq!(short.bytes_read, 0x1000);
        assert_eq!(short.bytes_unread, 0x2000);
    }

    #[test]
    fn a_budget_that_fires_is_recorded_rather_than_silently_shortening_the_search() {
        let layer = flat(vec![0xAB; 0x8000]);
        let runs = read_runs(&layer, 0, 0x8000, 0x2000);
        assert!(runs.capped);
        assert!(!runs.is_complete());
        assert_eq!(runs.bytes_read, 0x2000);
        assert_eq!(runs.bytes_unread, 0x6000);
    }
}
