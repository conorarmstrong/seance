//! What every Windows analysis stage needs before it can read anything.
//!
//! A memory image on its own is a flat array of bytes. To read a process list
//! from it you need three things that are not in the image's header, because it
//! has no header: the directory table base to translate virtual addresses, the
//! kernel's load address to anchor symbol lookups, and a symbol table matching
//! the exact kernel build that was running. Discovering those three is what
//! Volatility calls *automagic*, and everything in this crate consumes the
//! result rather than rediscovering it.
//!
//! The type is deliberately not constructible from parts a caller guessed at.
//! A profile records *how* each fact was established, because "the DTB was read
//! from the KdDebuggerDataBlock" and "the DTB was the best of nine candidates
//! from a self-referencing-entry scan" support very different confidence in
//! everything downstream, and an examiner is entitled to see which one applies.

use std::sync::Arc;

use seance_memory::translate::SwapFile;
use seance_memory::{Architecture, MemoryLayer};
use seance_symbols::{AdmissionState, SymbolTable};

/// How a fact about the image was established, and that fact paired with it.
///
/// Both were declared in this file. They are not Windows ideas — every OS tier
/// discovers a page-table base, a kernel load address and a symbol match, and
/// every one of them can arrive by reading a structure the image points at or
/// by scanning until something looks right — so they live in
/// [`seance_memory::binding`] and are re-exported here. Ordering is strongest
/// first, which is what makes [`WindowsProfile::weakest_evidence`] a `max`.
pub use seance_memory::binding::{Evidence, Found};

/// The Windows kernel build a symbol table was matched against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelBuild {
    /// PDB name, normally `ntoskrnl.pdb` or `ntkrnlmp.pdb`.
    pub pdb: String,
    /// PDB GUID, uppercase hex, as it appears in the debug directory.
    pub guid: String,
    /// PDB age.
    pub age: u32,
    /// `NtBuildLab` when it was readable.
    pub build_lab: Option<String>,
    /// Major version, e.g. 10 for Windows 10 and 11.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Build number, e.g. 22000 for Windows 11 21H2. This is the fact that
    /// decides structure layouts that moved between builds, so it is not
    /// optional: a stage that needs it and does not have it must fail closed
    /// rather than assume a layout.
    pub build: Option<u32>,
    /// Which structure the build number came from: `"kuser_shared_data"` when
    /// the kernel stated it directly, `"nt_build_lab"` when it was taken from
    /// the leading field of the build-lab string because this build's
    /// `_KUSER_SHARED_DATA` declares no `NtBuildNumber` (Windows XP, among
    /// others). `None` when no build number was established at all.
    ///
    /// Recorded because a report must not imply the kernel stated a number it
    /// only implied.
    pub build_source: Option<&'static str>,
}

impl KernelBuild {
    /// Whether this build is Windows 8 or later.
    ///
    /// Several kernel structures changed layout at this boundary — most
    /// notably `MMPTE_SOFTWARE`, whose `PageFileLow` field moved from bits 4:1
    /// to bits 15:12 — so a stage that decodes one of them must branch on this
    /// rather than pick a layout and hope.
    ///
    /// Returns `None` when the build number was never established, which means
    /// the caller must fail closed instead of choosing a branch.
    pub fn is_win8_or_later(&self) -> Option<bool> {
        let build = self.build?;
        if self.major > 6 {
            return Some(true);
        }
        if self.major < 6 {
            return Some(false);
        }
        // 6.2 is Windows 8; 6.1 is Windows 7.
        Some(self.minor >= 2 || build >= 9200)
    }
}

/// Everything discovery established about a Windows memory image.
///
/// Held by every analysis stage in this crate. Construction is the job of
/// [`crate::automagic`]; nothing else builds one from parts.
#[derive(Clone)]
pub struct WindowsProfile {
    /// The kernel address space: virtual addresses translated through the
    /// system DTB. This is what almost every stage reads through.
    pub kernel_space: Arc<dyn MemoryLayer>,
    /// The physical layer underneath, for pool scanning, which works on
    /// physical memory precisely because it is looking for objects that the
    /// virtual address space no longer links to.
    pub physical: Arc<dyn MemoryLayer>,
    /// Symbols for the running kernel build.
    pub symbols: Arc<SymbolTable>,
    /// Pagefiles the examiner attached, carried so a per-process address space
    /// resolves a swapped page the same way the kernel space does.
    ///
    /// Empty unless supplied through
    /// [`crate::automagic::DiscoveryOptions::pagefiles`]. Most swapped pages
    /// belong to a *process*, not the kernel, so a profile that dropped these
    /// would leave the feature working only where it matters least.
    pub pagefiles: Vec<SwapFile>,
    /// Directory table base used to build `kernel_space`.
    pub dtb: Found<u64>,
    /// Virtual address the kernel image is loaded at.
    pub kernel_base: Found<u64>,
    /// `KdDebuggerDataBlock`, when it was located.
    pub kdbg: Option<Found<u64>>,
    /// The build the symbols were matched to.
    pub build: KernelBuild,
    /// Pointer width of the kernel address space.
    pub architecture: Architecture,
}

impl std::fmt::Debug for WindowsProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsProfile")
            .field("dtb", &format_args!("{:#x}", self.dtb.value))
            .field(
                "kernel_base",
                &format_args!("{:#x}", self.kernel_base.value),
            )
            .field("build", &self.build)
            .field("architecture", &self.architecture)
            .finish_non_exhaustive()
    }
}

impl WindowsProfile {
    /// Whether the kernel is 64-bit.
    pub fn is_64bit(&self) -> bool {
        matches!(self.architecture, Architecture::X64 | Architecture::Arm64)
    }

    /// Pointer width in bytes.
    pub fn pointer_size(&self) -> u64 {
        if self.is_64bit() {
            8
        } else {
            4
        }
    }

    /// The weakest evidence behind any fact in this profile.
    ///
    /// A result is only as trustworthy as the shakiest thing it rests on, so
    /// this is what a finding derived from the profile should carry, not the
    /// strongest fact in it.
    pub fn weakest_evidence(&self) -> Evidence {
        let mut weakest = self.dtb.evidence.max(self.kernel_base.evidence);
        if let Some(kdbg) = self.kdbg {
            weakest = weakest.max(kdbg.evidence);
        }
        weakest
    }

    /// Whether the symbol table passed every admission gate.
    pub fn symbols_verified(&self) -> bool {
        self.symbols.state() == AdmissionState::Verified
    }

    /// Serializable form for the image-profile artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "dtb": self.dtb.value,
            "dtb_evidence": self.dtb.evidence.as_str(),
            "kernel_base": self.kernel_base.value,
            "kernel_base_evidence": self.kernel_base.evidence.as_str(),
            "kdbg": self.kdbg.map(|k| k.value),
            "kdbg_evidence": self.kdbg.map(|k| k.evidence.as_str()),
            "architecture": format!("{:?}", self.architecture),
            "pointer_size": self.pointer_size(),
            "pdb": self.build.pdb,
            "pdb_guid": self.build.guid,
            "pdb_age": self.build.age,
            "build_lab": self.build.build_lab,
            "nt_major": self.build.major,
            "nt_minor": self.build.minor,
            "nt_build": self.build.build,
            "nt_build_source": self.build.build_source,
            "symbols_state": format!("{:?}", self.symbols.state()),
            "symbols_sha256": self.symbols.provenance().to_json(),
            "weakest_evidence": self.weakest_evidence().as_str(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_orders_from_strongest_to_weakest() {
        assert!(Evidence::Confirmed < Evidence::Validated);
        assert!(Evidence::Validated < Evidence::Scanned);
        assert!(Evidence::Scanned < Evidence::Supplied);
    }

    #[test]
    fn a_build_without_a_number_cannot_answer_the_win8_question() {
        // The point of returning Option here: a stage that needs the answer has
        // to fail closed rather than default to one layout and silently decode
        // a field from the wrong bits.
        let build = KernelBuild {
            pdb: "ntoskrnl.pdb".into(),
            guid: "0".repeat(32),
            age: 1,
            build_lab: None,
            major: 6,
            minor: 1,
            build: None,
            build_source: None,
        };
        assert_eq!(build.is_win8_or_later(), None);
    }

    #[test]
    fn the_win8_boundary_falls_between_seven_and_eight() {
        let at = |major, minor, build| KernelBuild {
            pdb: "ntoskrnl.pdb".into(),
            guid: "0".repeat(32),
            age: 1,
            build_lab: None,
            major,
            minor,
            build: Some(build),
            build_source: None,
        };
        assert_eq!(at(5, 2, 3790).is_win8_or_later(), Some(false)); // XP x64
        assert_eq!(at(6, 1, 7601).is_win8_or_later(), Some(false)); // 7 SP1
        assert_eq!(at(6, 2, 9200).is_win8_or_later(), Some(true)); // 8
        assert_eq!(at(10, 0, 22000).is_win8_or_later(), Some(true)); // 11
    }
}
