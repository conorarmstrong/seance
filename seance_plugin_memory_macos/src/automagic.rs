//! Discovery: turning a flat macOS image into an address space, a symbol table
//! and a slide.
//!
//! # The chain, and why every link is checked
//!
//! macOS gives no header to read any of this out of. The chain is:
//!
//! 1. **Find the banner.** Sweep physical memory for `Darwin Kernel Version …`
//!    ([`crate::banner`]). Several copies normally exist.
//! 2. **Match a symbol pack.** The banner is the pack's declared identity, so
//!    the match is exact or there is none ([`crate::isf_index`]).
//! 3. **Derive the slide.** `slide = where the banner is − where the pack says
//!    the `version` array is`, with the pack's address mapped through the
//!    kernel's own unslid virtual→physical relation.
//! 4. **Cross-check the slide.** Read `version_major` and `version_minor` at
//!    that slide and require them to equal the numbers *inside* the banner
//!    string. This is the step that rejects the copies of the banner that are
//!    not the kernel's `version` array — a cached copy of the kernel file, a
//!    log line, a `sysctl` buffer — every one of which yields a slide that is
//!    arithmetically fine and physically wrong.
//! 5. **Bootstrap an address space.** `BootPML4` is at a known unslid address,
//!    so the slide gives its physical address, and that is enough page-table
//!    root to read one kernel variable.
//! 6. **Read the real page-table base.** `IdlePML4` holds it, as a 32-bit
//!    physical address.
//! 7. **Confirm by using it.** Build the kernel address space on that base and
//!    read the banner *back*, virtually, at the address the pack declares plus
//!    the slide. If the string that comes back is not the string the sweep
//!    found, the whole chain is rejected and the next banner copy is tried.
//!
//! Step 7 is the one that makes the rest reportable. Without it, a slide that
//! survived step 4 by coincidence produces an address space that translates,
//! and every structure read through it parses into confident nonsense.
//!
//! # What is refused rather than guessed
//!
//! * **32-bit macOS** (Mac OS X 10.6 and 10.7, Darwin 10–11). Those kernels use
//!   32-bit or PAE paging and a different virtual base, and the twelve packs of
//!   that era in this repository declare neither a banner nor `BootPML4`, so
//!   there is nothing to match an image against and nothing to bootstrap from.
//!   Refused by name, so an examiner is told the tool cannot do it rather than
//!   being handed a wrong answer.
//! * **Apple silicon.** ARM64 translation is structurally different — two
//!   directory bases, a configurable granule, a start level derived from
//!   `TCR_EL1` — and `seance_memory::translate` implements Intel modes only.
//!   No pack in this store is an ARM64 kernel.
//! * **A pack whose admission gate failed.** Never admitted "because it is the
//!   only one available".
//!
//! **Unvalidated.** See [`crate::unvalidated`]: this chain has never been run
//! against a real macOS capture. It is transcribed from Volatility 3's
//! `framework/automagic/mac.py` and from the symbol packs themselves.

use std::path::PathBuf;
use std::sync::Arc;

use seance_memory::binding::{Evidence, Found};
use seance_memory::scan::{ScanConfig, ScanError};
use seance_memory::translate::{PagingMode, PagingSpec, PteSemantics, VirtualLayer};
use seance_memory::MemoryLayer;
use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable, ValidationOptions};
use tracing::debug;

use crate::banner::{scan_for_banners, BannerHit, BannerScan};
use crate::isf_index::{
    build_index, MacIsfIndex, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILES, DEFAULT_MAX_IDENTIFIED,
};
use crate::profile::{kernel_virtual_to_physical, MacProfile};

/// Symbols discovery cannot proceed without, with what each is for.
///
/// Checked up front so a pack missing one of them is refused by name, before any
/// arithmetic is done with the others.
pub const REQUIRED_SYMBOLS: [(&str, &str); 6] = [
    ("version", "the kernel banner, which anchors the slide"),
    (
        "version_major",
        "the independent cross-check that rejects a banner copy which is not the kernel's",
    ),
    ("version_minor", "the second half of that cross-check"),
    (
        "BootPML4",
        "the boot page-table root, which bootstraps enough address space to read the real one",
    ),
    ("IdlePML4", "the running page-table base"),
    (
        "_mh_execute_header",
        "the kernel image's load address, which anchors every kernel-text address in a report",
    ),
];

/// Caps and tuning for one discovery.
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    /// Geometry and caps for the banner sweep.
    pub scan: ScanConfig,
    /// Ceiling on symbol files enumerated.
    pub max_isf_files: usize,
    /// Directory levels the symbol search descends.
    pub max_isf_depth: usize,
    /// Ceiling on symbol files opened and identified.
    pub max_isf_identified: usize,
    /// Ceiling on banner copies tried as slide anchors. A machine holds a
    /// handful; a cap stops a pathological image from turning discovery into a
    /// full sweep of every printable string it contains.
    pub max_banner_candidates: usize,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            scan: ScanConfig::default(),
            max_isf_files: DEFAULT_MAX_FILES,
            max_isf_depth: DEFAULT_MAX_DEPTH,
            max_isf_identified: DEFAULT_MAX_IDENTIFIED,
            max_banner_candidates: 64,
        }
    }
}

/// Why discovery could not profile an image.
///
/// Each variant is written to be acted on: the banner an examiner needs to fetch
/// symbols for, the pack that was rejected and by which gate, the release the
/// tool does not support.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// The banner sweep itself could not run.
    #[error("the image could not be swept for a kernel banner: {0}")]
    Scan(#[from] ScanError),

    /// No Darwin banner anywhere in the mapped bytes.
    #[error(
        "no Darwin kernel banner was found in this image, so it was not identified as a macOS \
         capture (the sweep examined {bytes_scanned} byte(s) and was {completeness})"
    )]
    NoBanner {
        /// Addressable bytes actually examined.
        bytes_scanned: u64,
        /// `"complete"` or `"incomplete"`. An incomplete sweep that found
        /// nothing has not shown the image holds nothing.
        completeness: &'static str,
    },

    /// A banner was found and no symbol pack declares it.
    #[error(
        "this image is macOS {version} but no symbol pack in the search path declares its kernel \
         banner ({banner:?}); {packs_indexed} pack(s) were indexed, {skipped_no_banner} macOS \
         pack(s) declared no banner at all and could not be matched to any image"
    )]
    NoSymbols {
        /// The banner the image carries. This is the string to fetch symbols for.
        banner: String,
        /// The release it names.
        version: String,
        /// Packs successfully indexed.
        packs_indexed: usize,
        /// macOS packs that carry no identity — the 32-bit 10.6/10.7 kits.
        skipped_no_banner: usize,
    },

    /// The pack matched and would not compile, or its admission gate refused it.
    #[error("the symbol pack {path:?} could not be admitted for this kernel: {detail}")]
    SymbolsRejected {
        /// Where the pack is.
        path: PathBuf,
        /// What the gate said.
        detail: String,
    },

    /// The kernel is one this tier does not implement.
    #[error("this macOS image is not one this analysis can read: {detail}")]
    Unsupported {
        /// What is unsupported, and why refusing beats guessing.
        detail: String,
    },

    /// Every banner copy was tried and none produced a usable address space.
    #[error(
        "the kernel slide could not be established for {banner:?}: {candidates} banner \
         copy/copies were tried and none produced an address space the banner could be read back \
         through ({detail})"
    )]
    SlideNotEstablished {
        /// The banner that was matched.
        banner: String,
        /// How many copies were tried.
        candidates: usize,
        /// Why the last one failed, as an example of the class.
        detail: String,
    },
}

impl DiscoveryError {
    /// Whether this refusal means the image is simply not a macOS capture.
    ///
    /// Exactly one case qualifies: a **complete** sweep of every mapped byte
    /// found no Darwin banner. That is the Windows crash dump handed to the
    /// macOS tier, and the honest response is to produce nothing rather than to
    /// file a failure record on every non-Mac image in the case.
    ///
    /// A sweep that could **not** examine everything and found no banner is a
    /// different statement — the image may well be macOS and the bytes that
    /// would say so were never acquired — so it does not qualify, and the
    /// caller reports it.
    pub fn means_not_macos(&self) -> bool {
        matches!(
            self,
            DiscoveryError::NoBanner {
                completeness: "complete",
                ..
            }
        )
    }
}

/// One banner copy that was tried as a slide anchor, and what became of it.
///
/// Kept because "we tried nine copies and all nine failed at the
/// `version_major` check" and "we tried one and it failed to translate" send an
/// examiner to different places.
#[derive(Debug, Clone)]
pub struct SlideAttempt {
    /// Where the banner copy was, physically.
    pub banner_address: u64,
    /// The slide it implied, when the subtraction was possible.
    pub slide: Option<u64>,
    /// How far the chain got before it stopped.
    pub outcome: String,
    /// Whether this attempt produced the profile.
    pub accepted: bool,
}

impl SlideAttempt {
    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "banner_address": self.banner_address,
            "banner_address_hex": format!("{:#x}", self.banner_address),
            "slide": self.slide,
            "slide_hex": self.slide.map(|s| format!("{s:#x}")),
            "outcome": self.outcome,
            "accepted": self.accepted,
        })
    }
}

/// What discovery did, whether or not it succeeded.
#[derive(Debug, Clone)]
pub struct DiscoveryReport {
    /// The banner sweep.
    pub banners: BannerScan,
    /// The symbol-pack index.
    pub index: MacIsfIndex,
    /// Every slide anchor tried.
    pub attempts: Vec<SlideAttempt>,
    /// Directories searched for symbol packs.
    pub symbol_dirs: Vec<PathBuf>,
}

impl DiscoveryReport {
    /// Serializable form for the profile artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "banner_sweep": self.banners.to_json(),
            "symbol_index": self.index.to_json(),
            "slide_attempts": self.attempts.iter().map(SlideAttempt::to_json).collect::<Vec<_>>(),
            "symbol_dirs_searched": self
                .symbol_dirs
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
        })
    }
}

/// The paging mode every 64-bit macOS kernel in this store uses.
fn paging_spec() -> PagingSpec {
    // `Bare` and not `Windows`: transition, prototype and software PTE
    // conventions are Windows kernel conventions. Applying them to a macOS entry
    // would decode a non-present entry into a pagefile reference that does not
    // exist, and read bytes from wherever that arithmetic landed.
    PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare)
}

/// Profile a macOS image, reporting how each fact was established.
pub fn discover_reported(
    physical: Arc<dyn MemoryLayer>,
    symbol_dirs: &[PathBuf],
    options: &DiscoveryOptions,
) -> Result<(MacProfile, DiscoveryReport), DiscoveryError> {
    let banners = scan_for_banners(physical.as_ref(), &options.scan)?;
    if banners.hits.is_empty() {
        return Err(DiscoveryError::NoBanner {
            bytes_scanned: banners.outcome.bytes_scanned,
            completeness: if banners.is_complete() {
                "complete"
            } else {
                "incomplete"
            },
        });
    }

    let index = build_index(
        symbol_dirs,
        options.max_isf_files,
        options.max_isf_depth,
        options.max_isf_identified,
    );

    // The banners the store can actually analyse, in the order they were found.
    let matched: Option<(&BannerHit, PathBuf)> = banners
        .hits
        .iter()
        .find_map(|hit| index.lookup(&hit.text).map(|e| (hit, e.path.clone())));

    let Some((first, isf_path)) = matched else {
        let hit = &banners.hits[0];
        return Err(DiscoveryError::NoSymbols {
            banner: hit.text.clone(),
            version: hit.version.to_string(),
            packs_indexed: index.len(),
            skipped_no_banner: index.skipped_no_banner,
        });
    };
    let banner = first.text.clone();
    let version = first.version;

    // Admission is on the banner. `expect_identifier` makes the gate compare the
    // pack's declared identity against the string found in the image, so a pack
    // whose file name says one kernel and whose contents say another is refused
    // here rather than silently used.
    let compile_options = CompileOptions {
        validation: ValidationOptions::new().expect_identifier(banner.clone()),
        ..CompileOptions::default()
    };
    let symbols =
        SymbolTable::compile_path(&isf_path, &DecompressLimits::default(), &compile_options)
            .map_err(|e| DiscoveryError::SymbolsRejected {
                path: isf_path.clone(),
                detail: e.to_string(),
            })?;
    if !symbols.state().permits_analysis() {
        return Err(DiscoveryError::SymbolsRejected {
            path: isf_path.clone(),
            detail: format!(
                "the admission gate returned {}, and a table that did not pass is never used \
                 because it is the only one available",
                symbols.state().as_str()
            ),
        });
    }

    // 32-bit macOS is refused by name rather than attempted. See the module
    // docs: the paging mode, the virtual base and the bootstrap symbol all
    // differ, and no pack of that era carries an identity to match against.
    if symbols.pointer_size() != 8 {
        return Err(DiscoveryError::Unsupported {
            detail: format!(
                "the symbol pack declares a {}-byte pointer, so this is a 32-bit macOS kernel \
                 (Mac OS X 10.6/10.7). This analysis implements 64-bit IA-32e paging only; a \
                 32-bit walk would need a different virtual base and a different bootstrap \
                 symbol, and producing one by guessing would yield a plausible and wrong process \
                 list",
                symbols.pointer_size()
            ),
        });
    }

    for (name, purpose) in REQUIRED_SYMBOLS {
        if !symbols.has_symbol(name) {
            return Err(DiscoveryError::Unsupported {
                detail: format!(
                    "the symbol pack for this kernel declares no '{name}', which is {purpose}"
                ),
            });
        }
    }

    // Where the pack says the `version` array lives, unslid and in physical
    // terms. Every candidate's implied slide is measured from this one number,
    // so it is established once and its absence is a refusal rather than a
    // per-candidate failure.
    let version_declared =
        symbols
            .symbol_address("version")
            .map_err(|e| DiscoveryError::SymbolsRejected {
                path: isf_path.clone(),
                detail: format!("the pack declares no readable 'version' symbol: {e}"),
            })?;
    let version_phys = kernel_virtual_to_physical(version_declared).ok_or_else(|| {
        DiscoveryError::Unsupported {
            detail: format!(
                "'version' is declared at {version_declared:#x}, which is below the 64-bit macOS \
                 kernel base, so this pack does not describe a 64-bit kernel"
            ),
        }
    })?;

    let symbols = Arc::new(symbols);
    let mut attempts: Vec<SlideAttempt> = Vec::new();

    // Every copy of *this* banner is a slide candidate. They are tried in
    // address order, and the first that survives the whole chain wins. Cloned
    // out of the sweep so the sweep itself can be handed to the report.
    let candidates: Vec<BannerHit> = banners
        .hits
        .iter()
        .filter(|hit| hit.text == banner)
        .take(options.max_banner_candidates)
        .cloned()
        .collect();

    for hit in &candidates {
        match try_candidate(&physical, &symbols, hit) {
            Ok((slide, dtb, kernel_space, kernel_base)) => {
                attempts.push(SlideAttempt {
                    banner_address: hit.address,
                    slide: Some(slide),
                    outcome: "the banner read back through the resulting address space".to_string(),
                    accepted: true,
                });
                debug!(
                    "plugin.memory.macos: slide {:#x}, page-table base {:#x}, kernel at {:#x}",
                    slide, dtb, kernel_base
                );
                let profile = MacProfile {
                    kernel_space,
                    physical: Arc::clone(&physical),
                    symbols: Arc::clone(&symbols),
                    // Read out of `IdlePML4`, which the image itself holds, and
                    // then confirmed by using it. Graded `Validated` rather than
                    // `Confirmed` because reaching that variable at all depended
                    // on the scanned slide: the base is no stronger than the
                    // anchor it was found through.
                    dtb: Found::new(dtb, Evidence::Validated),
                    // Scanned, then cross-checked against `version_major` and
                    // `version_minor`, then confirmed by reading the banner back.
                    slide: Found::new(slide, Evidence::Validated),
                    kernel_base: Found::new(kernel_base, Evidence::Validated),
                    banner: banner.clone(),
                    version,
                    isf_path: isf_path.clone(),
                };
                let report = DiscoveryReport {
                    banners,
                    index,
                    attempts,
                    symbol_dirs: symbol_dirs.to_vec(),
                };
                return Ok((profile, report));
            }
            Err(reason) => attempts.push(SlideAttempt {
                banner_address: hit.address,
                slide: hit.address.checked_sub(version_phys),
                outcome: reason,
                accepted: false,
            }),
        }
    }

    let detail = attempts
        .last()
        .map(|a| a.outcome.clone())
        .unwrap_or_else(|| "no banner copy was tried".to_string());
    Err(DiscoveryError::SlideNotEstablished {
        banner,
        candidates: candidates.len(),
        detail,
    })
}

/// Try one banner copy as the slide anchor.
///
/// Returns the slide, the page-table base, the kernel address space and the
/// kernel load address, or the sentence saying where the chain stopped.
///
/// Every failure here is a `String` rather than an error type because none of
/// them is fatal: the next copy of the banner may well work, and only the
/// exhaustion of all of them is a finding.
fn try_candidate(
    physical: &Arc<dyn MemoryLayer>,
    symbols: &Arc<SymbolTable>,
    hit: &BannerHit,
) -> Result<(u64, u64, Arc<dyn MemoryLayer>, u64), String> {
    let declared = |name: &str| -> Result<u64, String> {
        symbols
            .symbol_address(name)
            .map_err(|e| format!("the symbol pack could not answer for '{name}': {e}"))
    };
    let unslid_phys = |name: &str| -> Result<u64, String> {
        let address = declared(name)?;
        kernel_virtual_to_physical(address).ok_or_else(|| {
            format!(
                "'{name}' is declared at {address:#x}, which is below the 64-bit kernel base, so \
                 this pack is not a 64-bit kernel's"
            )
        })
    };
    // Every address in this chain is a declared address plus the slide. Checked
    // rather than wrapping: a wrapped sum is a small address that translates
    // fine, and every byte read through it would parse into a wrong answer.
    let slid = |what: &str, base: u64, slide: u64| -> Result<u64, String> {
        base.checked_add(slide).ok_or_else(|| {
            format!(
                "{what} at {base:#x} plus the slide {slide:#x} leaves the 64-bit address space, \
                 so this slide cannot be the kernel's"
            )
        })
    };

    let version_phys = unslid_phys("version")?;
    let slide = hit.address.checked_sub(version_phys).ok_or_else(|| {
        format!(
            "the banner at {:#x} lies below the unslid address of 'version' ({version_phys:#x}), \
             so it is not the kernel's own copy",
            hit.address
        )
    })?;
    // The kernel is relocated by whole pages. A slide that is not page-aligned
    // is arithmetic that happened to work, not a relocation.
    if slide % 0x1000 != 0 {
        return Err(format!(
            "the implied slide {slide:#x} is not page-aligned, so this copy of the banner is not \
             the kernel's 'version' array"
        ));
    }

    // The independent check. The banner *string* states the release; the kernel
    // *variables* state it too, and they are 100 bytes away in a structure this
    // copy would have to be a genuine `version` array to satisfy.
    let major_at = slid("'version_major'", unslid_phys("version_major")?, slide)?;
    let major = read_u32_at(physical.as_ref(), major_at)
        .map_err(|e| format!("'version_major' could not be read at this slide: {e}"))?;
    if major != hit.version.major {
        return Err(format!(
            "'version_major' reads {major} at this slide and the banner says {}, so the slide is \
             wrong",
            hit.version.major
        ));
    }
    let minor_at = slid("'version_minor'", unslid_phys("version_minor")?, slide)?;
    let minor = read_u32_at(physical.as_ref(), minor_at)
        .map_err(|e| format!("'version_minor' could not be read at this slide: {e}"))?;
    if minor != hit.version.minor {
        return Err(format!(
            "'version_minor' reads {minor} at this slide and the banner says {}, so the slide is \
             wrong",
            hit.version.minor
        ));
    }

    // Bootstrap: enough address space to read one variable.
    let boot_pml4 = slid("'BootPML4'", unslid_phys("BootPML4")?, slide)?;
    let bootstrap =
        VirtualLayer::new(Arc::clone(physical), boot_pml4, paging_spec()).map_err(|e| {
            format!("the boot page tables at {boot_pml4:#x} are not a usable page-table root: {e}")
        })?;

    // `IdlePML4` holds the running page-table base as a 32-bit physical address.
    let idle_pml4_va = slid("'IdlePML4'", declared("IdlePML4")?, slide)?;
    let dtb = u64::from(
        read_u32_at(&bootstrap, idle_pml4_va)
            .map_err(|e| format!("'IdlePML4' could not be read through the boot tables: {e}"))?,
    );
    if dtb == 0 || dtb % 0x1000 != 0 {
        return Err(format!(
            "'IdlePML4' holds {dtb:#x}, which is not a page-aligned page-table base"
        ));
    }

    let kernel_space = VirtualLayer::new(Arc::clone(physical), dtb, paging_spec())
        .map_err(|e| format!("the page-table base {dtb:#x} does not root an address space: {e}"))?;
    let kernel_space: Arc<dyn MemoryLayer> = Arc::new(kernel_space);

    // The confirmation. Read the banner back, virtually, at the address the pack
    // declares plus the slide. A chain that survives to here and fails this has
    // produced an address space that translates and is not the kernel's.
    let banner_va = slid("'version'", declared("version")?, slide)?;
    let mut buffer = vec![0u8; crate::banner::MAX_BANNER_BYTES];
    let read = kernel_space
        .read_at(banner_va, &mut buffer)
        .map_err(|e| format!("the banner could not be read back at {banner_va:#x}: {e}"))?;
    buffer.truncate(read);
    let echoed = seance_symbols::normalize_banner(&buffer)
        .map_err(|e| format!("the bytes read back at {banner_va:#x} are not a banner: {e}"))?;
    if echoed != hit.text {
        return Err(format!(
            "the address space built from this slide holds {echoed:?} where the kernel banner \
             should be, so it is not the kernel's address space"
        ));
    }

    let kernel_base = slid(
        "'_mh_execute_header'",
        declared("_mh_execute_header")?,
        slide,
    )?;
    Ok((slide, dtb, kernel_space, kernel_base))
}

/// Read a little-endian `u32` at `address`, refusing a short read.
///
/// A short read here would be three bytes of a page-table base and one byte of
/// nothing, which is a number, parses, and is wrong.
fn read_u32_at(layer: &dyn MemoryLayer, address: u64) -> Result<u32, String> {
    let mut buffer = [0u8; 4];
    let read = layer
        .read_at(address, &mut buffer)
        .map_err(|e| format!("{address:#x}: {e}"))?;
    if read != buffer.len() {
        return Err(format!(
            "{address:#x}: {read} of 4 byte(s) were acquired, so the value is not established"
        ));
    }
    Ok(u32::from_le_bytes(buffer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_memory::PhysicalLayer;

    fn physical_layer(bytes: Vec<u8>) -> Arc<dyn MemoryLayer> {
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        Arc::new(PhysicalLayer::raw(source).expect("a non-empty layer"))
    }

    #[test]
    fn an_image_with_no_banner_is_reported_as_not_macos_rather_than_as_empty() {
        // The distinction the module exists for: this image was looked at and
        // is not a macOS capture, which is a different statement from "the
        // macOS analysis found no processes".
        let physical = physical_layer(vec![0u8; 0x4000]);
        let err = discover_reported(physical, &[], &DiscoveryOptions::default())
            .expect_err("an image with no Darwin banner cannot be profiled");
        match err {
            DiscoveryError::NoBanner {
                bytes_scanned,
                completeness,
            } => {
                assert!(bytes_scanned > 0);
                assert_eq!(completeness, "complete");
            }
            other => panic!("wrong refusal: {other}"),
        }
    }

    #[test]
    fn a_banner_with_no_symbol_pack_names_the_banner_to_fetch() {
        // The one thing that turns a failed analysis into a successful one is
        // the banner string, so it is in the error rather than in a log line.
        const BANNER: &str = "Darwin Kernel Version 19.6.0: Thu Oct 29 22:56:45 PDT 2020; \
                              root:xnu-6153.141.2.2~1/RELEASE_X86_64";
        let mut image = vec![0u8; 0x4000];
        image[0x800..0x800 + BANNER.len()].copy_from_slice(BANNER.as_bytes());
        let physical = physical_layer(image);

        let err = discover_reported(physical, &[], &DiscoveryOptions::default())
            .expect_err("no pack is indexed");
        match err {
            DiscoveryError::NoSymbols {
                banner,
                version,
                packs_indexed,
                ..
            } => {
                assert_eq!(banner, BANNER);
                assert_eq!(version, "19.6.0");
                assert_eq!(packs_indexed, 0);
            }
            other => panic!("wrong refusal: {other}"),
        }
    }

    #[test]
    fn a_short_read_of_a_page_table_base_is_refused_rather_than_zero_extended() {
        // Three bytes of a base and one byte of nothing is a number that parses.
        let layer = physical_layer(vec![0xAAu8; 2]);
        let err = read_u32_at(layer.as_ref(), 0).expect_err("a two-byte source cannot hold a u32");
        assert!(err.contains("of 4 byte(s)"), "{err}");
    }

    #[test]
    fn every_symbol_discovery_depends_on_is_declared_with_what_it_is_for() {
        // A required symbol added without a purpose produces a refusal an
        // examiner cannot act on.
        for (name, purpose) in REQUIRED_SYMBOLS {
            assert!(!name.is_empty());
            assert!(
                purpose.len() > 20,
                "'{name}' is required with no useful statement of what it is for"
            );
        }
    }

    #[test]
    fn the_paging_spec_does_not_apply_windows_pte_conventions_to_a_mac_kernel() {
        // A macOS non-present entry decoded under Windows semantics becomes a
        // pagefile reference that does not exist, and the read lands wherever
        // that arithmetic points.
        let spec = paging_spec();
        assert_eq!(spec.mode(), PagingMode::Intel32e);
        assert_eq!(spec.semantics(), PteSemantics::Bare);
    }
}
