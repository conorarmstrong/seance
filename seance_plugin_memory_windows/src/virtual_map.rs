//! The kernel's system virtual-address map (`ROADMAP` §5.3, upstream's
//! `virtmap`).
//!
//! # What an examiner learns
//!
//! How the kernel carved up its half of the address space: where the
//! non-paged pool is, where the paged pool is, where driver images load, where
//! the PFN database and the system cache lie. It is the map every other
//! kernel-side stage's addresses are read against — a pool allocation whose
//! address falls in no pool region, or a "driver" whose image lies outside the
//! driver-image region, is a finding — and it is what lets a pool sweep be
//! bounded to the region that can hold what it looks for.
//!
//! # Where it comes from, and how a region gets its name
//!
//! Windows 10 and later keep the assignments in `MiState`, the
//! `_MI_SYSTEM_INFORMATION` global: `Vs.SystemVaRegions` is an array of
//! `_MI_SYSTEM_VA_ASSIGNMENT` (`BaseAddress`, `NumberOfBytes`). **Its index is
//! not the region's type.** On the Windows 11 26200 capture the array is 18
//! long against 20 enumeration values, slot 0 — which would be `MiVaUnused` by
//! index — holds a 12.5 TiB assignment, and the kernel image lies in slot 17.
//! The kernel's own answer to "what is this address for" is the byte array
//! `Vs.SystemVaType`, one entry per top-level page-table slot of the kernel
//! half (256 entries of 512 GiB under four-level paging), and that is what
//! names a region here: the type recorded for the region's first slice,
//! looked up in the build's `_MI_SYSTEM_VA_TYPE` enumeration, with a note
//! when the slices a region spans do not all carry the same type. Every path
//! is resolved from the symbol table, the slice size from `MmSystemRangeStart`
//! and the array's declared length, and nothing from a constant.
//!
//! Older builds describe the space differently and this stage does not read
//! them; on such a build it reports that it cannot, naming the symbol it did
//! not find.
//!
//! # Two checks against facts established elsewhere
//!
//! The kernel's own load address was established by discovery before this
//! stage ran; it must fall inside a region, and that region's type must be
//! one that holds images — `MiVaDriverImages` on the Windows 11 26200
//! capture, where the kernel image itself lives in the driver-image region,
//! or `MiVaBootLoaded`. `MmPfnDatabase`, a pointer the kernel keeps, must
//! fall in the region typed as the PFN database. A map that fails either was
//! read through the wrong offsets, and is marked incomplete rather than
//! published as a layout of the machine.
//!
//! # How much of each type is in use
//!
//! `Vs.SystemVaTypeCount` keeps one count per `_MI_SYSTEM_VA_TYPE` value. It
//! was expected to count 512 GiB slices of the type map; measured on the
//! 26200 capture it does not. Its unit is the kernel's dynamic-VA granule,
//! derived here from `SystemVa.DynamicBitMap<Type>` (region bytes over the
//! bitmap's `MaximumSize`: 2 MiB on 26200), and every type with a bitmap has
//! its count checked against the bitmap's set bits. On 26200 five types
//! match exactly and two (system PTEs, non-cached mappings) exceed their
//! bitmap; none falls below. The counts are published only when none falls
//! below and every bitmap gives the same unit; otherwise they are withheld
//! with the reason, and a count below its bitmap marks the record
//! incomplete. The non-paged pool has no bitmap and is published unchecked.

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::object::{is_canonical, StructReader};
use seance_memory::Incomplete;
use seance_symbols::TypeKind;
use serde_json::{json, Value};

use crate::profile::WindowsProfile;

/// Region slots this walk will read. The declared array is 18 long on
/// Windows 11 26200; a symbol table declaring more than this is not a kernel.
pub const MAX_REGIONS: u64 = 256;

/// Bits of one dynamic bitmap this stage will read: 2^24, 32 TiB of 2 MiB
/// units. The 26200 bitmaps declare 32,768.
pub const MAX_BITMAP_BITS: u64 = 1 << 24;

/// What `type_counts` says about itself, on every record.
pub const TYPE_COUNT_BASIS: &str =
    "`counts` is `Vs.SystemVaTypeCount`, one entry per `_MI_SYSTEM_VA_TYPE` value, in units of \
     `granule_bytes`. It is NOT a count of 512 GiB slices: that was measured false on the \
     Windows 11 26200 capture. The unit is derived, not assumed: each \
     `SystemVa.DynamicBitMap<Type>` spans its region at region bytes / `MaximumSize` per bit \
     (2 MiB on 26200), and each type's count is checked against its bitmap's set bits. On \
     26200 five types (paged pool, system cache, driver images, kernel stacks, system data \
     views) equal their bitmap exactly; system PTEs and non-cached mappings exceed it, and \
     there a one-off page-table walk found the count equal to the present page-directory \
     entries in the type's slices. The counts are published only when no count is below its \
     bitmap and every bitmap's unit agrees; a type with no bitmap (the non-paged pool) is \
     published unchecked. Measured on one build, 26200, and no other.";

/// What stops the whole survey.
#[derive(Debug, Clone)]
pub enum VirtualMapError {
    Unsupported { detail: String },
}

impl VirtualMapError {
    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::Unsupported {
            detail: detail.into(),
        }
    }

    pub fn class(&self) -> &'static str {
        match self {
            Self::Unsupported { .. } => "unsupported_build",
        }
    }
}

impl std::fmt::Display for VirtualMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { detail } => write!(f, "{detail}"),
        }
    }
}

/// How the map is reached on this build.
#[derive(Debug, Clone)]
pub struct VirtualMapSymbols {
    /// `MiState`, in kernel virtual space.
    pub mi_state: u64,
    /// The path from `_MI_SYSTEM_INFORMATION` to the region array.
    pub regions_path: String,
    /// Declared slots in the array.
    pub regions_declared: u64,
    /// The path to the per-slice type array, and its declared length, when
    /// this build has one. Without it no region can be named.
    pub type_map: Option<(String, u64)>,
    /// `MmSystemRangeStart`, the global holding where the kernel half begins;
    /// with the type array's length it gives the slice size.
    pub system_range_start: Option<u64>,
    /// `MmPfnDatabase`, the global pointing at the PFN database.
    pub pfn_database: Option<u64>,
    /// Whether `_MI_SYSTEM_VA_TYPE` is declared, which is what turns a type
    /// number into a name.
    pub type_enum_declared: bool,
    /// The path to `Vs.SystemVaTypeCount` and its declared length, when this
    /// build has an eight-byte-per-entry one.
    pub type_counts: Option<(String, u64)>,
    /// Each `SystemVa.DynamicBitMap<Type>` this build declares, as (type
    /// value, type name, path): the kernel's own allocation bitmap for that
    /// type, which the counts are checked against. Found by taking every
    /// `MiVa<Type>` constant of the enumeration and asking whether the build
    /// declares the matching member, so nothing is a list typed here.
    pub dynamic_bitmaps: Vec<(u64, String, String)>,
}

impl VirtualMapSymbols {
    /// Resolve what this build declares.
    ///
    /// # Errors
    ///
    /// [`VirtualMapError::Unsupported`] naming what is absent: `MiState`, the
    /// `_MI_SYSTEM_INFORMATION` type, or the `Vs.SystemVaRegions` array.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, VirtualMapError> {
        let rva = profile.symbols.symbol_address("MiState").map_err(|_| {
            VirtualMapError::unsupported(
                "this build's symbol table has no 'MiState', so the system virtual-address \
                 regions cannot be located. Builds before Windows 10 describe the space through \
                 a per-directory-entry type array this stage does not read.",
            )
        })?;
        let mi_state = profile.kernel_base.value.checked_add(rva).ok_or_else(|| {
            VirtualMapError::unsupported("the address of 'MiState' does not fit in 64 bits")
        })?;
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        let regions_path = "Vs.SystemVaRegions".to_string();
        let shape = reader
            .array_shape("_MI_SYSTEM_INFORMATION", &regions_path)
            .map_err(|err| {
                VirtualMapError::unsupported(format!(
                    "this build declares no '_MI_SYSTEM_INFORMATION.{regions_path}' array, so \
                     the region assignments cannot be read: {err}"
                ))
            })?;
        if shape.total > MAX_REGIONS {
            return Err(VirtualMapError::unsupported(format!(
                "'_MI_SYSTEM_INFORMATION.{regions_path}' declares {} slot(s), above the \
                 {MAX_REGIONS} this stage will read",
                shape.total
            )));
        }
        let type_map = reader
            .array_shape("_MI_SYSTEM_INFORMATION", "Vs.SystemVaType")
            .ok()
            .filter(|shape| shape.total > 0 && shape.element_size == 1)
            .map(|shape| ("Vs.SystemVaType".to_string(), shape.total));
        let global = |name: &str| -> Option<u64> {
            profile
                .symbols
                .symbol_address(name)
                .ok()
                .and_then(|rva| profile.kernel_base.value.checked_add(rva))
        };
        let type_counts = reader
            .array_shape("_MI_SYSTEM_INFORMATION", "Vs.SystemVaTypeCount")
            .ok()
            .filter(|shape| shape.total > 0 && shape.total <= 256 && shape.element_size == 8)
            .map(|shape| ("Vs.SystemVaTypeCount".to_string(), shape.total));
        let mut dynamic_bitmaps = Vec::new();
        if let Some(names) = type_enum(profile) {
            for constant in &names.constants {
                let Some(suffix) = constant.name.strip_prefix("MiVa") else {
                    continue;
                };
                let Ok(value) = u64::try_from(constant.value) else {
                    continue;
                };
                let path = format!("SystemVa.DynamicBitMap{suffix}");
                if reader
                    .member_offset("_MI_SYSTEM_INFORMATION", &path)
                    .is_ok()
                {
                    dynamic_bitmaps.push((value, constant.name.to_string(), path));
                }
            }
        }
        Ok(Self {
            mi_state,
            regions_path,
            regions_declared: shape.total,
            type_map,
            type_counts,
            dynamic_bitmaps,
            system_range_start: global("MmSystemRangeStart"),
            pfn_database: global("MmPfnDatabase"),
            type_enum_declared: profile.symbols.has_type("_MI_SYSTEM_VA_TYPE"),
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "mi_state": format!("{:#018x}", self.mi_state),
            "regions_path": self.regions_path,
            "regions_declared": self.regions_declared,
            "type_map": self.type_map.as_ref().map(|(path, count)| json!({"path": path, "slices": count})),
            "system_range_start_symbol": self.system_range_start.map(|a| format!("{a:#018x}")),
            "pfn_database_symbol": self.pfn_database.map(|a| format!("{a:#018x}")),
            "type_enum_declared": self.type_enum_declared,
            "type_counts": self.type_counts.as_ref().map(|(path, count)| json!({"path": path, "entries": count})),
            "dynamic_bitmaps": self.dynamic_bitmaps.iter().map(|(value, name, path)| json!({
                "type_value": value, "type_name": name, "path": path
            })).collect::<Vec<_>>(),
        })
    }
}

/// One region.
#[derive(Debug, Clone)]
pub struct VirtualMapRegion {
    /// Slot in the array. Not the region's type.
    pub index: u64,
    /// The type the kernel's per-slice map records for the region's first
    /// slice. `None` when the map, the slice size or the slice would not read.
    pub type_value: Option<u64>,
    /// The enumeration's name for that value, when it declares one.
    pub type_name: Option<String>,
    /// Whether every slice the region spans carries the same type. `None` when
    /// the slices could not all be read.
    pub type_uniform: Option<bool>,
    pub base: u64,
    pub bytes: u64,
}

impl VirtualMapRegion {
    /// A slot the kernel never assigned.
    pub fn is_empty(&self) -> bool {
        self.base == 0 && self.bytes == 0
    }

    /// The last byte, inclusive; `None` for an empty slot or one whose extent
    /// leaves the address space.
    pub fn end(&self) -> Option<u64> {
        if self.is_empty() || self.bytes == 0 {
            return None;
        }
        self.base.checked_add(self.bytes - 1)
    }

    pub fn contains(&self, address: u64) -> bool {
        self.end()
            .is_some_and(|end| self.base <= address && address <= end)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "index": self.index,
            "type_value": self.type_value,
            "type_name": self.type_name,
            "type_uniform": self.type_uniform,
            "base": format!("{:#018x}", self.base),
            "bytes": self.bytes,
            "end": self.end().map(|e| format!("{e:#018x}")),
            "empty": self.is_empty(),
        })
    }
}

/// Which region holds the kernel.
#[derive(Debug, Clone)]
pub struct PlacedKernel {
    pub index: u64,
    pub type_name: Option<String>,
}

/// One cross-check of the map against a fact from elsewhere.
#[derive(Debug, Clone)]
pub struct MapCheck {
    pub name: &'static str,
    /// `None` when the check could not be made.
    pub passed: Option<bool>,
    pub detail: String,
}

impl MapCheck {
    pub fn to_json(&self) -> Value {
        json!({"name": self.name, "passed": self.passed, "detail": self.detail})
    }
}

/// What one survey produced.
#[derive(Debug, Clone)]
pub struct VirtualMapSurvey {
    pub symbols: VirtualMapSymbols,
    pub regions_declared: u64,
    pub regions: Vec<VirtualMapRegion>,
    /// Slots that would not read.
    pub regions_unreadable: Vec<(u64, String)>,
    /// Slots with a non-canonical base.
    pub regions_non_canonical: u64,
    /// The region the profile's kernel base falls in, when one does.
    pub kernel_base_region: Option<PlacedKernel>,
    /// Pairs of region indices whose extents overlap.
    pub overlaps: Vec<(u64, u64)>,
    /// The slice size the type map was read with, when it could be derived.
    pub slice_bytes: Option<u64>,
    /// Why no region could be named, when none could.
    pub naming_unavailable: Option<String>,
    /// The cross-checks against facts established elsewhere.
    pub checks: Vec<MapCheck>,
    /// `Vs.SystemVaTypeCount`, indexed by `_MI_SYSTEM_VA_TYPE`, in units of
    /// [`Self::type_count_granule`] bytes. Published only when every dynamic
    /// bitmap the build declares was read and no count fell below its
    /// bitmap's set bits.
    pub type_counts: Option<Vec<u64>>,
    /// Bytes per counted unit, derived from the bitmaps: a region's bytes over
    /// its bitmap's `MaximumSize`.
    pub type_count_granule: Option<u64>,
    /// One cross-check per `SystemVa.DynamicBitMap<Type>` this build declares.
    pub type_count_checks: Vec<TypeCountCheck>,
    /// Why the counts are not published, when they are not.
    pub type_counts_withheld: Option<String>,
}

/// One type's count set against the kernel's own allocation bitmap for it.
#[derive(Debug, Clone)]
pub struct TypeCountCheck {
    pub type_value: u64,
    pub type_name: Option<String>,
    /// `SystemVaTypeCount[type]`.
    pub count: u64,
    /// Bits set in `SystemVa.DynamicBitMap<Type>`; `None` when it would not read.
    pub bits_set: Option<u64>,
    /// Bytes per bit: the region's bytes over the bitmap's `MaximumSize`.
    pub granule: Option<u64>,
    /// Whether the count is at least the bitmap's set bits. `None` when the
    /// bitmap would not read.
    pub holds: Option<bool>,
    pub detail: String,
}

impl TypeCountCheck {
    pub fn to_json(&self) -> Value {
        json!({
            "type_value": self.type_value,
            "type_name": self.type_name,
            "count": self.count,
            "bits_set": self.bits_set,
            "granule_bytes": self.granule,
            "holds": self.holds,
            "exact": self.bits_set.map(|b| b == self.count),
            "detail": self.detail,
        })
    }
}

impl VirtualMapSurvey {
    pub fn regions_in_use(&self) -> usize {
        self.regions.iter().filter(|r| !r.is_empty()).count()
    }

    /// The region holding `address`, when one does.
    pub fn region_of(&self, address: u64) -> Option<&VirtualMapRegion> {
        self.regions.iter().find(|r| r.contains(address))
    }

    /// Every slot read, the kernel placed in one, and no cross-check failed.
    pub fn is_complete(&self) -> bool {
        self.regions_unreadable.is_empty()
            && self.regions_non_canonical == 0
            && self.kernel_base_region.is_some()
            && self.checks.iter().all(|c| c.passed != Some(false))
            && self
                .type_count_checks
                .iter()
                .all(|c| c.holds != Some(false))
    }

    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        for (index, detail) in &self.regions_unreadable {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!("region slot {index} could not be read: {detail}"),
            ));
        }
        if self.regions_non_canonical > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} region(s) have a base that is not a canonical address, which is not a \
                     layout the kernel produces",
                    self.regions_non_canonical
                ),
            ));
        }
        if self.kernel_base_region.is_none() {
            out.push(Incomplete::new(
                IncompleteReason::Unvalidated,
                "the kernel's own load address falls in none of these regions, so the map was \
                 not read through offsets that check out and its regions are not vouched for"
                    .to_string(),
            ));
        }
        for check in self.checks.iter().filter(|c| c.passed == Some(false)) {
            out.push(Incomplete::new(
                IncompleteReason::Unvalidated,
                format!("the '{}' cross-check failed: {}", check.name, check.detail),
            ));
        }
        for check in self
            .type_count_checks
            .iter()
            .filter(|c| c.holds == Some(false))
        {
            out.push(Incomplete::new(
                IncompleteReason::Unvalidated,
                format!(
                    "`SystemVaTypeCount` for {} is below the kernel's own allocation bitmap for \
                     that type, so the counts were not read through offsets that check out and \
                     are not published: {}",
                    check
                        .type_name
                        .clone()
                        .unwrap_or_else(|| format!("type {}", check.type_value)),
                    check.detail
                ),
            ));
        }
        out
    }

    pub fn describe(&self) -> String {
        format!(
            "{} of {} declared system virtual-address region slot(s) are assigned; the kernel \
             at the profile's load address lies in {}.{}",
            self.regions_in_use(),
            self.regions_declared,
            match &self.kernel_base_region {
                Some(placed) => format!(
                    "slot {} ({})",
                    placed.index,
                    placed
                        .type_name
                        .clone()
                        .unwrap_or_else(|| "unnamed".to_string())
                ),
                None => "NONE of them, which means this map does not check out".to_string(),
            },
            if self.overlaps.is_empty() {
                String::new()
            } else {
                format!(" {} pair(s) of regions overlap.", self.overlaps.len())
            }
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "symbols": self.symbols.to_json(),
            "regions_declared": self.regions_declared,
            "regions": self.regions.iter().map(VirtualMapRegion::to_json).collect::<Vec<_>>(),
            "regions_in_use": self.regions_in_use(),
            "regions_unreadable": self.regions_unreadable.iter().map(|(i, d)| json!({"index": i, "detail": d})).collect::<Vec<_>>(),
            "regions_non_canonical": self.regions_non_canonical,
            "kernel_base_in_a_region": self.kernel_base_region.is_some(),
            "kernel_base_region": self.kernel_base_region.as_ref().map(|p| json!({
                "index": p.index, "type_name": p.type_name
            })),
            "overlaps": self.overlaps.iter().map(|(a, b)| json!([a, b])).collect::<Vec<_>>(),
            "slice_bytes": self.slice_bytes,
            "naming_unavailable": self.naming_unavailable,
            "naming_basis":
                "A region's slot index is NOT its type: on Windows 11 26200 the array has 18 slots \
                 against 20 enumeration values and the kernel image lies in slot 17. Each region \
                 is named from the kernel's own per-slice type map (`Vs.SystemVaType`, one byte \
                 per top-level page-table slot of the kernel half): the type recorded for the \
                 region's first slice, looked up in this build's `_MI_SYSTEM_VA_TYPE` \
                 enumeration, with `type_uniform` saying whether every slice the region spans \
                 agrees. A region whose type could not be read carries its slot only.",
            "type_counts": {
                "counts": self.type_counts,
                "granule_bytes": self.type_count_granule,
                "withheld": self.type_counts_withheld,
                "checks": self.type_count_checks.iter().map(TypeCountCheck::to_json).collect::<Vec<_>>(),
                "basis": TYPE_COUNT_BASIS,
            },
            "checks": self.checks.iter().map(MapCheck::to_json).collect::<Vec<_>>(),
            "check_basis":
                "Two facts established elsewhere are placed on the map: the kernel's load \
                 address, which discovery found before this stage ran, must lie in a region \
                 typed for images (boot-loaded, or driver images -- where Windows 11 26200 \
                 puts it); and `MmPfnDatabase`, a pointer the kernel keeps, must lie in the \
                 region typed as the PFN database. A map that fails either was read through \
                 the wrong offsets and is marked incomplete rather than published as the \
                 machine's layout.",
            "statement": self.describe(),
            "content_complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Read every region assignment.
/// How [`pool_sweep_region`] chose the region to sweep for key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolRegionBasis {
    /// The region the type map names `MiVaNonPagedPool`.
    Label,
    /// The type map's `MiVaNonPagedPool` region holds none of the loader entries, which are non-paged pool
    /// allocations, so the region that holds most of them was taken instead.
    LoaderEntries,
}

/// The region to sweep for key material in non-paged pool. It is the one the type map names `MiVaNonPagedPool`,
/// unless that region holds none of the loader entries (`_KLDR_DATA_TABLE_ENTRY`, tag `MmLd`, whose pool header
/// says non-paged on every build measured): on Windows Server 2022 build 20348.587 all 145 of them lie in the
/// region the map names `MiVaPagedPool`, and the sweep of the labelled region found no key schedule at all
/// where the capture holds the keys of ten cipher layers; Windows 10 build 14393 shows the same. The region holding
/// the majority of the entries is then the one swept.
pub fn pool_sweep_region<'a>(
    regions: &'a [VirtualMapRegion],
    loader_entries: &[u64],
) -> Option<(&'a VirtualMapRegion, PoolRegionBasis)> {
    let labelled = regions
        .iter()
        .find(|r| r.type_name.as_deref() == Some("MiVaNonPagedPool") && !r.is_empty());
    let held = |r: &VirtualMapRegion| loader_entries.iter().filter(|e| r.contains(**e)).count();
    let placed: usize = regions.iter().map(held).sum();
    if placed == 0 || labelled.is_some_and(|r| held(r) > 0) {
        return labelled.map(|r| (r, PoolRegionBasis::Label));
    }
    let majority = regions
        .iter()
        .filter(|r| !r.is_empty())
        .max_by_key(|r| held(r))
        .filter(|r| held(r) * 2 > placed);
    match majority {
        Some(r) => Some((r, PoolRegionBasis::LoaderEntries)),
        None => labelled.map(|r| (r, PoolRegionBasis::Label)),
    }
}

pub fn survey_virtual_map(
    profile: &WindowsProfile,
    symbols: &VirtualMapSymbols,
) -> VirtualMapSurvey {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let pointer = reader.pointer_size().unwrap_or(8);
    let names = type_enum(profile);

    let mut survey = VirtualMapSurvey {
        symbols: symbols.clone(),
        regions_declared: symbols.regions_declared,
        regions: Vec::new(),
        regions_unreadable: Vec::new(),
        regions_non_canonical: 0,
        kernel_base_region: None,
        overlaps: Vec::new(),
        slice_bytes: None,
        naming_unavailable: None,
        checks: Vec::new(),
        type_counts: None,
        type_count_granule: None,
        type_count_checks: Vec::new(),
        type_counts_withheld: None,
    };

    let state = match reader.object(symbols.mi_state, "_MI_SYSTEM_INFORMATION") {
        Ok(state) => state,
        Err(err) => {
            survey
                .regions_unreadable
                .push((0, format!("'MiState' would not read: {err}")));
            return survey;
        }
    };

    // The slice size: the kernel half divided by the type map's length.
    let mut slicer: Option<(String, u64, u64)> = None;
    match (&symbols.type_map, symbols.system_range_start) {
        (Some((path, count)), Some(at)) => match reader.read_pointer_at(at) {
            Ok(start) => {
                let half = (1u128 << 64) - u128::from(start);
                let slice = half / u128::from(*count);
                match u64::try_from(slice) {
                    Ok(slice) if slice > 0 && half.is_multiple_of(u128::from(*count)) => {
                        survey.slice_bytes = Some(slice);
                        slicer = Some((path.clone(), start, slice));
                    }
                    _ => {
                        survey.naming_unavailable = Some(format!(
                            "the kernel half from {start:#018x} does not divide into {count} \
                             equal slices, so the type map could not be indexed"
                        ))
                    }
                }
            }
            Err(err) => {
                survey.naming_unavailable =
                    Some(format!("`MmSystemRangeStart` would not read: {err}"))
            }
        },
        (None, _) => {
            survey.naming_unavailable = Some(
                "this build declares no `Vs.SystemVaType` array, so no region can be named".into(),
            )
        }
        (_, None) => {
            survey.naming_unavailable = Some(
                "this build's symbol table has no `MmSystemRangeStart`, so the type map could \
                 not be indexed"
                    .into(),
            )
        }
    }
    let type_at = |address: u64| -> Option<u64> {
        let (path, start, slice) = slicer.as_ref()?;
        let index = address.checked_sub(*start)? / slice;
        state.element_int(path, index).ok()?.as_u64()
    };

    for index in 0..symbols.regions_declared {
        let assignment = match state.element_object(&symbols.regions_path, index) {
            Ok(a) => a,
            Err(err) => {
                survey.regions_unreadable.push((index, err.to_string()));
                continue;
            }
        };
        let (base, bytes) = match (
            assignment.pointer("BaseAddress"),
            assignment.unsigned("NumberOfBytes"),
        ) {
            (Ok(base), Ok(bytes)) => (base, bytes),
            (Err(err), _) | (_, Err(err)) => {
                survey.regions_unreadable.push((index, err.to_string()));
                continue;
            }
        };
        let empty = base == 0 && bytes == 0;
        let type_value = if empty { None } else { type_at(base) };
        let type_uniform = match (type_value, slicer.as_ref()) {
            (Some(first), Some((_, _, slice))) if bytes > 0 => {
                let mut uniform = Some(true);
                let mut cursor = base;
                let end = base.saturating_add(bytes - 1);
                while cursor < end {
                    let Some(next) = cursor.checked_add(*slice) else {
                        break;
                    };
                    if next > end {
                        break;
                    }
                    match type_at(next) {
                        Some(t) if t == first => {}
                        Some(_) => {
                            uniform = Some(false);
                            break;
                        }
                        None => {
                            uniform = None;
                            break;
                        }
                    }
                    cursor = next;
                }
                uniform
            }
            _ => None,
        };
        let region = VirtualMapRegion {
            index,
            type_value,
            type_name: type_value.and_then(|value| {
                names
                    .as_ref()
                    .and_then(|e| e.name_of(i128::from(value)))
                    .map(str::to_string)
            }),
            type_uniform,
            base,
            bytes,
        };
        if !region.is_empty() && !is_canonical(base, pointer) {
            survey.regions_non_canonical += 1;
        }
        survey.regions.push(region);
    }

    let kernel_base = profile.kernel_base.value;
    survey.kernel_base_region = survey.region_of(kernel_base).map(|r| PlacedKernel {
        index: r.index,
        type_name: r.type_name.clone(),
    });

    // Cross-check one: the kernel lies in a region typed for images. Measured
    // on Windows 11 26200 that is `MiVaDriverImages`, not the boot-loaded
    // region an older layout would predict, so both are image regions here.
    survey.checks.push(match &survey.kernel_base_region {
        Some(placed) => MapCheck {
            name: "kernel_in_an_image_region",
            passed: placed
                .type_name
                .as_deref()
                .map(|n| n == "MiVaBootLoaded" || n == "MiVaDriverImages"),
            detail: format!(
                "the kernel at {kernel_base:#018x} lies in slot {}, typed {}",
                placed.index,
                placed
                    .type_name
                    .clone()
                    .unwrap_or_else(|| "(unnamed)".into())
            ),
        },
        None => MapCheck {
            name: "kernel_in_an_image_region",
            passed: Some(false),
            detail: format!("the kernel at {kernel_base:#018x} lies in no region"),
        },
    });
    // Cross-check two: the PFN database pointer lies in the region typed as it.
    survey.checks.push(
        match symbols.pfn_database.map(|at| reader.read_pointer_at(at)) {
            Some(Ok(pfn)) if pfn != 0 => match survey.region_of(pfn) {
                Some(region) => MapCheck {
                    name: "pfn_database_in_its_region",
                    passed: region.type_name.as_deref().map(|n| n == "MiVaPfnDatabase"),
                    detail: format!(
                        "`MmPfnDatabase` reads {pfn:#018x}, in slot {}, typed {}",
                        region.index,
                        region
                            .type_name
                            .clone()
                            .unwrap_or_else(|| "(unnamed)".into())
                    ),
                },
                None => MapCheck {
                    name: "pfn_database_in_its_region",
                    passed: Some(false),
                    detail: format!("`MmPfnDatabase` reads {pfn:#018x}, which lies in no region"),
                },
            },
            Some(Ok(_)) => MapCheck {
                name: "pfn_database_in_its_region",
                passed: None,
                detail: "`MmPfnDatabase` reads zero".into(),
            },
            Some(Err(err)) => MapCheck {
                name: "pfn_database_in_its_region",
                passed: None,
                detail: format!("`MmPfnDatabase` would not read: {err}"),
            },
            None => MapCheck {
                name: "pfn_database_in_its_region",
                passed: None,
                detail: "this build's symbol table has no `MmPfnDatabase`".into(),
            },
        },
    );

    check_type_counts(&reader, &state, symbols, &mut survey);

    for (a, first) in survey.regions.iter().enumerate() {
        let Some(first_end) = first.end() else {
            continue;
        };
        for second in survey.regions.iter().skip(a + 1) {
            let Some(second_end) = second.end() else {
                continue;
            };
            if first.base <= second_end && second.base <= first_end {
                survey.overlaps.push((first.index, second.index));
            }
        }
    }
    survey
}

/// Read `Vs.SystemVaTypeCount`, check each count against the kernel's own
/// allocation bitmap for its type, and publish the counts only when every
/// check holds and every bitmap gives the same unit.
fn check_type_counts(
    reader: &StructReader,
    state: &seance_memory::object::Obj,
    symbols: &VirtualMapSymbols,
    survey: &mut VirtualMapSurvey,
) {
    let Some((path, entries)) = &symbols.type_counts else {
        survey.type_counts_withheld =
            Some("this build declares no eight-byte `Vs.SystemVaTypeCount` array".into());
        return;
    };
    let mut counts = Vec::with_capacity(*entries as usize);
    for index in 0..*entries {
        match state.element_int(path, index).ok().and_then(|v| v.as_u64()) {
            Some(count) => counts.push(count),
            None => {
                survey.type_counts_withheld = Some(format!("`{path}[{index}]` would not read"));
                return;
            }
        }
    }
    if symbols.dynamic_bitmaps.is_empty() {
        survey.type_counts_withheld = Some(
            "this build declares no `SystemVa.DynamicBitMap<Type>` to check the counts \
             against, so their unit is not established"
                .into(),
        );
        return;
    }
    for (type_value, type_name, bitmap) in &symbols.dynamic_bitmaps {
        let Some(&count) = usize::try_from(*type_value)
            .ok()
            .and_then(|i| counts.get(i))
        else {
            continue;
        };
        let (bits_set, granule, detail) = read_bitmap(reader, state, bitmap, &survey.regions);
        let holds = bits_set.map(|set| count >= set);
        survey.type_count_checks.push(TypeCountCheck {
            type_value: *type_value,
            type_name: Some(type_name.clone()),
            count,
            bits_set,
            granule,
            holds,
            detail,
        });
    }
    let granules: Vec<u64> = survey
        .type_count_checks
        .iter()
        .filter_map(|c| c.granule)
        .collect();
    let granule = granules
        .first()
        .copied()
        .filter(|g| granules.iter().all(|x| x == g));
    let failed: Vec<String> = survey
        .type_count_checks
        .iter()
        .filter(|c| c.holds != Some(true))
        .map(|c| {
            c.type_name
                .clone()
                .unwrap_or_else(|| c.type_value.to_string())
        })
        .collect();
    if !failed.is_empty() {
        survey.type_counts_withheld = Some(format!(
            "the count for {} is below its bitmap or the bitmap would not read, so the counts \
             are not published",
            failed.join(", ")
        ));
    } else if granule.is_none() {
        survey.type_counts_withheld = Some(
            "the bitmaps do not give one unit (region bytes over `MaximumSize`), so the \
             counts' unit is not established and they are not published"
                .into(),
        );
    } else {
        survey.type_count_granule = granule;
        survey.type_counts = Some(counts);
    }
}

/// One `_MI_DYNAMIC_BITMAP`: its set bits (bounded by [`MAX_BITMAP_BITS`])
/// and its unit, the bytes of the region holding `BaseVa` over `MaximumSize`.
fn read_bitmap(
    reader: &StructReader,
    state: &seance_memory::object::Obj,
    path: &str,
    regions: &[VirtualMapRegion],
) -> (Option<u64>, Option<u64>, String) {
    let field = |name: &str| format!("{path}.{name}");
    let (bits, buffer) = match (
        state.unsigned(&field("Bitmap.SizeOfBitMap")),
        state.pointer(&field("Bitmap.Buffer")),
    ) {
        (Ok(bits), Ok(buffer)) => (bits, buffer),
        (Err(err), _) | (_, Err(err)) => {
            return (None, None, format!("`{path}` would not read: {err}"))
        }
    };
    if bits > MAX_BITMAP_BITS {
        return (
            None,
            None,
            format!("`{path}` declares {bits} bits, above the {MAX_BITMAP_BITS} this stage reads"),
        );
    }
    let granule = match (
        state.unsigned(&field("MaximumSize")),
        state.pointer(&field("BaseVa")),
    ) {
        (Ok(maximum), Ok(base)) if maximum > 0 => regions
            .iter()
            .find(|r| r.contains(base))
            .filter(|r| r.bytes.is_multiple_of(maximum))
            .map(|r| r.bytes / maximum),
        _ => None,
    };
    let mut set = 0u64;
    let mut word = 0u64;
    while word * 64 < bits {
        let value = match reader.read_pointer_at(buffer.wrapping_add(word * 8)) {
            Ok(value) => value,
            Err(err) => {
                return (
                    None,
                    granule,
                    format!("`{path}` buffer word {word} would not read: {err}"),
                )
            }
        };
        let live = bits - word * 64;
        let masked = if live >= 64 {
            value
        } else {
            value & ((1u64 << live) - 1)
        };
        set += u64::from(masked.count_ones());
        word += 1;
    }
    (
        Some(set),
        granule,
        format!(
            "{set} of {bits} bit(s) set in `{path}`{}",
            granule.map_or_else(String::new, |g| format!(", {g} bytes per bit"))
        ),
    )
}

/// The `_MI_SYSTEM_VA_TYPE` enumeration, when this build declares it.
fn type_enum(profile: &WindowsProfile) -> Option<seance_symbols::EnumInfo> {
    let id = profile.symbols.type_id("_MI_SYSTEM_VA_TYPE").ok()?;
    match &profile.symbols.entry(id).ok()?.kind {
        TypeKind::Enum(info) => Some(info.clone()),
        _ => None,
    }
}
