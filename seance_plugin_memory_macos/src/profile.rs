//! What every macOS analysis stage needs before it can read anything.
//!
//! A memory image is a flat array of bytes. To read a process list out of one
//! you need four things that are not in it: the kernel slide, so a symbol's
//! address in a Kernel Debug Kit pack becomes the address it has in this image;
//! the page-table base, to translate that address; a symbol table for the exact
//! kernel build; and the address space the first three produce. Discovering them
//! is [`crate::automagic`]'s job, and everything else in this crate consumes the
//! result rather than rediscovering it.
//!
//! The type is deliberately not constructible from parts a caller guessed at.
//! It records *how* each fact was established, because "the page-table base was
//! read out of `IdlePML4` through a bootstrap address space and then used to
//! read the kernel banner back" and "the page-table base was the best-looking
//! candidate from a scan" support very different confidence in everything
//! downstream.
//!
//! **Unvalidated.** See [`crate::unvalidated`]: no part of this has been run
//! against a real macOS capture.

use std::sync::Arc;

use seance_memory::binding::{Evidence, Found};
use seance_memory::object::StructReader;
use seance_memory::MemoryLayer;
use seance_symbols::{AdmissionState, SymbolTable};

use crate::banner::DarwinVersion;

/// Base of the 64-bit macOS kernel's virtual address range.
///
/// Every symbol in a 64-bit Kernel Debug Kit pack is expressed relative to this,
/// and the kernel is mapped so that `physical = virtual - KERNEL_VIRTUAL_BASE`
/// before the slide is applied. This is the constant Volatility 3's
/// `MacIntelStacker.virtual_to_physical_address` uses, and it is the only
/// address arithmetic in this crate that is not read from symbols.
pub const KERNEL_VIRTUAL_BASE: u64 = 0xFFFF_FF80_0000_0000;

/// The unslid virtual→physical mapping the boot-time kernel image uses.
///
/// Only valid for addresses inside the kernel's own mapping, and only before the
/// slide is added. Returns `None` for an address below the base, which is not a
/// kernel address at all — a caller must not fall back to the address itself,
/// because that would silently read from low physical memory.
pub fn kernel_virtual_to_physical(address: u64) -> Option<u64> {
    address.checked_sub(KERNEL_VIRTUAL_BASE)
}

/// Everything discovery established about a macOS memory image.
///
/// Held by every analysis stage in this crate. Construction is
/// [`crate::automagic`]'s job; nothing else builds one from parts.
#[derive(Clone)]
pub struct MacProfile {
    /// The kernel address space: virtual addresses translated through the
    /// system page-table base. Every stage reads through this.
    pub kernel_space: Arc<dyn MemoryLayer>,
    /// The physical layer underneath.
    pub physical: Arc<dyn MemoryLayer>,
    /// Symbols for the running kernel build.
    pub symbols: Arc<SymbolTable>,
    /// Page-table base used to build `kernel_space`.
    pub dtb: Found<u64>,
    /// Kernel ASLR slide: what to add to every address the symbol pack declares.
    pub slide: Found<u64>,
    /// Virtual address the kernel Mach-O header is loaded at, which is
    /// `_mh_execute_header` plus the slide.
    pub kernel_base: Found<u64>,
    /// The banner the image carries, which is also the identity the symbol pack
    /// was admitted under.
    pub banner: String,
    /// The Darwin release the banner names.
    pub version: DarwinVersion,
    /// Where the symbol pack came from.
    pub isf_path: std::path::PathBuf,
}

impl std::fmt::Debug for MacProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacProfile")
            .field("dtb", &format_args!("{:#x}", self.dtb.value))
            .field("slide", &format_args!("{:#x}", self.slide.value))
            .field(
                "kernel_base",
                &format_args!("{:#x}", self.kernel_base.value),
            )
            .field("version", &format_args!("{}", self.version))
            .finish_non_exhaustive()
    }
}

impl MacProfile {
    /// The address a symbol has *in this image*.
    ///
    /// Every symbol lookup in this crate goes through here. A stage that reached
    /// past it to [`SymbolTable::symbol_address`] would read the unslid address
    /// — which on a booted machine is not mapped at all, and on an unlucky one
    /// is mapped to something else entirely.
    ///
    /// # Errors
    ///
    /// The symbol table's own error when this build declares no such symbol.
    /// Never a zero: a symbol that does not exist and a symbol at address zero
    /// must not read alike. Also an error when the declared address plus the
    /// slide leaves the 64-bit address space — wrapping would produce a low
    /// address that translates to something, and everything read through it
    /// would parse.
    pub fn symbol(&self, name: &str) -> Result<u64, seance_symbols::SymbolError> {
        let declared = self.symbols.symbol_address(name)?;
        declared.checked_add(self.slide.value).ok_or_else(|| {
            seance_symbols::SymbolError::malformed(format!(
                "'{name}' is declared at {declared:#x} and the kernel slide is {:#x}; their sum \
                 leaves the 64-bit address space, so this symbol has no address in this image",
                self.slide.value
            ))
        })
    }

    /// Whether this build declares a symbol at all.
    pub fn has_symbol(&self, name: &str) -> bool {
        self.symbols.has_symbol(name)
    }

    /// A reader over the kernel address space.
    pub fn reader(&self) -> StructReader {
        StructReader::new(Arc::clone(&self.kernel_space), Arc::clone(&self.symbols))
    }

    /// The weakest evidence behind any fact in this profile.
    ///
    /// A result is only as trustworthy as the shakiest thing it rests on, so
    /// this is what a finding derived from the profile carries — not the
    /// strongest fact in it.
    pub fn weakest_evidence(&self) -> Evidence {
        self.dtb
            .evidence
            .max(self.slide.evidence)
            .max(self.kernel_base.evidence)
    }

    /// Whether the symbol table passed every admission gate.
    pub fn symbols_verified(&self) -> bool {
        self.symbols.state() == AdmissionState::Verified
    }

    /// Serializable form for the image-profile artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "dtb": self.dtb.value,
            "dtb_hex": format!("{:#x}", self.dtb.value),
            "dtb_evidence": self.dtb.evidence.as_str(),
            "kernel_slide": self.slide.value,
            "kernel_slide_hex": format!("{:#x}", self.slide.value),
            "kernel_slide_evidence": self.slide.evidence.as_str(),
            "kernel_base": self.kernel_base.value,
            "kernel_base_hex": format!("{:#x}", self.kernel_base.value),
            "kernel_base_evidence": self.kernel_base.evidence.as_str(),
            "kernel_banner": self.banner,
            "darwin_version": self.version.to_json(),
            "paging_mode": "intel32e",
            "pointer_size": self.symbols.pointer_size(),
            "symbols_path": self.isf_path.display().to_string(),
            "symbols_state": self.symbols.state().as_str(),
            "symbols_verified": self.symbols_verified(),
            "symbols_sha256": self.symbols.provenance().to_json(),
            "weakest_evidence": self.weakest_evidence().as_str(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kernel_address_maps_below_its_base_and_a_user_address_does_not() {
        // The `else` branch Volatility takes for a low address subtracts a
        // different constant and produces a physical address in the exabytes.
        // Refusing is the only honest answer: an address below the kernel base
        // is not a kernel address, and reading "wherever that lands" is how a
        // discovery settles on a page that parses and is not the kernel's.
        assert_eq!(
            kernel_virtual_to_physical(0xFFFF_FF80_0010_0000),
            Some(0x100000)
        );
        assert_eq!(kernel_virtual_to_physical(KERNEL_VIRTUAL_BASE), Some(0));
        assert_eq!(kernel_virtual_to_physical(0x0000_0000_005E_A9B8), None);
    }

    #[test]
    fn the_weakest_evidence_is_the_one_a_finding_carries() {
        // Ordering is strongest-first, so the weakest link is a `max`.
        let weakest = Evidence::Confirmed
            .max(Evidence::Scanned)
            .max(Evidence::Validated);
        assert_eq!(weakest, Evidence::Scanned);
    }
}
