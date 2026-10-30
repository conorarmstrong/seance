//! # macOS memory analysis — **UNVALIDATED**
//!
//! > **Read this before using any result this crate produces.**
//! >
//! > No macOS memory image and no macOS oracle existed anywhere in this
//! > environment when this tier was written. Every line of it was derived from
//! > two things: the 129 Apple Kernel Debug Kit symbol packs under
//! > `reference/volatility3/volatility3/symbols`, and Volatility 3's macOS
//! > plugins read as source. **Not one result has ever been compared against a
//! > capture of a real Mac.**
//! >
//! > Every artifact this crate emits therefore carries a marker saying so — see
//! > [`unvalidated`] — and that marker is applied in the three functions that
//! > are the only ways a record leaves here. In a forensic tool, analysis code
//! > that presents unvalidated results as findings is worse than a documented
//! > gap, because an examiner cannot tell the difference. The marker is how they
//! > can.
//!
//! ## What this tier does
//!
//! `seance_memory` can translate a virtual address and read a struct member at a
//! symbol-declared offset. That is a general capability with no opinion about
//! operating systems. This crate holds the macOS-specific knowledge that turns
//! it into evidence: where the kernel banner is, how the kernel slide is
//! recovered from it, which variable holds the page-table base, how `allproc`
//! and the Mach task queue are shaped, and where the loaded kernel extensions
//! hang.
//!
//! | Stage | What it establishes |
//! |---|---|
//! | `macos_processes` | the BSD process list, from `allproc` |
//! | `macos_task_processes` | the Mach task queue, resolved to processes |
//! | `macos_process_cross_view` | which listing saw each process |
//! | `macos_kernel_extensions` | loaded kexts, from the `kmod` chain |
//!
//! Four stages, and no more. A stage that could not be written with confidence
//! from the symbol definitions alone is **absent**, not guessed: an absent stage
//! is honest, and a guessed one puts a plausible wrong answer in a case file.
//! What is missing and why is in `honest_gaps` in the delivery note and in the
//! module docs of [`automagic`].
//!
//! ## What the symbol store actually holds
//!
//! Surveyed directly from the 129 packs present when this was written:
//!
//! | | packs | Darwin | marketing | usable |
//! |---|---|---|---|---|
//! | 64-bit | 117 | 12–19 | OS X 10.8 – macOS 10.15.4 | yes |
//! | 32-bit | 12 | 10–11 | Mac OS X 10.6 – 10.7 | **no** |
//!
//! Every one of the 117 declares each symbol and structure member this crate
//! reads: `version`, `version_major`, `version_minor`, `BootPML4`, `IdlePML4`,
//! `_mh_execute_header`, `allproc`, `tasks`, `kmod`, `nprocs`; and `proc`,
//! `proclist`, `task`, `queue_entry`, `kmod_info`, `timeval` with the members
//! named in [`process`] and [`kext`]. The 12 thirty-two-bit packs declare no
//! kernel banner at all, so no image can be matched to them, and no `BootPML4`
//! to bootstrap from; they are refused by name rather than attempted.
//!
//! macOS 11 and later, and every Apple-silicon Mac, have no pack here at all.
//!
//! ## Why every offset comes from the symbol pack
//!
//! `proc.p_pid` sits at offset 16 on Darwin 12 through 17 and at offset 96 on
//! Darwin 18 — one Apple release apart. `proc.p_start` is at 1048, 1064, 960 and
//! 928 across four packs. A hardcoded offset would produce a complete,
//! confident, entirely wrong process list on every build but one, and nothing
//! downstream could tell. So every member is declared through
//! [`seance_memory::binding`] and resolved against the build in hand, and a
//! member this build does not have is `not_declared` — an answer — rather than a
//! stage failure.
//!
//! ## Reaching the orchestrator
//!
//! [`macos_memory_module`] is the registrable `ForensicsModule`, and it **is**
//! registered: `seance_api::modules::build_module_set` puts it beside the
//! Windows and Linux tiers, and both binaries build their pipeline from that one
//! list. For a long time it was not, and the reasoning was that unvalidated
//! results should not reach an examiner. That had the sign backwards. It did not
//! keep anything from an examiner except the analysis: a Mac capture was
//! identified as a memory image, examined by nothing, and every stage reported
//! `did_not_run` — which is what a case shows for a machine that was running
//! nothing at all. The marker below is the disclosure; silence never was one.
#![forbid(unsafe_code)]

pub mod automagic;
pub mod banner;
pub mod fields;
pub mod isf_index;
pub mod kext;
pub mod module;
pub mod process;
pub mod profile;
pub mod unvalidated;

pub use automagic::{discover_reported, DiscoveryError, DiscoveryOptions, DiscoveryReport};
pub use banner::{scan_for_banners, BannerHit, BannerScan, DarwinVersion};
pub use isf_index::{build_index, MacIsfEntry, MacIsfIndex};
pub use kext::{Kext, KextList, KextSymbols};
pub use module::{macos_memory_module, MacMemoryAnalysis, MODULE_ID, MODULE_VERSION, STAGES};
pub use process::{CrossView, MacProcess, ProcessList, ProcessSymbols, TaskSymbols};
pub use profile::MacProfile;
pub use unvalidated::{unvalidated_stamp, VALIDATION_NOTICE, VALIDATION_STATE};

#[cfg(test)]
mod crate_tests {
    use super::*;
    use seance_core::module::ForensicsModule;

    /// The check that this crate is not the thing it was written to avoid.
    ///
    /// This project has three times shipped an analysis tier that could not be
    /// reached: once a dispatch that returned an empty vector, once 3,750 lines
    /// of real code with no crate root, and once this crate — complete, tested,
    /// and in no binary's module list. All of them passed their unit tests.
    ///
    /// So: the public entry point exists, it produces the trait object the
    /// orchestrator registers, and it answers with the module identity and
    /// subscription that make it reachable. The last link, the registration
    /// itself, is outside this crate and is held by
    /// `seance_api::modules::tests::a_capture_of_each_supported_operating_system_reaches_a_memory_analysis`.
    #[test]
    fn the_public_entry_point_produces_a_registrable_module() {
        let module = macos_memory_module();
        let as_trait: &dyn ForensicsModule = &module;
        assert_eq!(as_trait.id(), MODULE_ID);
        assert_eq!(as_trait.version(), MODULE_VERSION);
        assert_eq!(
            as_trait.subscribes_to(),
            vec![seance_core::artifact::ArtifactType::ParsedRecord]
        );
    }

    /// Every stage the module can run is declared once, in one table.
    #[test]
    fn the_stage_table_is_the_only_list_of_stages() {
        // The non-emptiness guard is a compile-time assertion, not a runtime
        // one. `STAGES` is a const table, so `!STAGES.is_empty()` is a
        // tautology at runtime — it can never fail, which makes it precisely
        // the vacuous check it was written to prevent: it exists so the loop
        // below cannot pass by iterating nothing. Asserted in const context, it
        // actually holds that line, and an empty table stops the build.
        const _: () = assert!(
            !STAGES.is_empty(),
            "the stage table is empty, so the per-stage checks below would pass \
             without examining anything"
        );

        for stage in STAGES {
            assert!(
                stage.key.starts_with("macos_"),
                "stage key {:?} is not namespaced to this tier",
                stage.key
            );
        }
    }
}
