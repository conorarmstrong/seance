//! Each loaded hive's cell routines (`ROADMAP` §5.3, upstream's
//! `getcellroutine`).
//!
//! # What an examiner learns
//!
//! Every registry read the kernel makes goes through the hive's own
//! `_HHIVE.GetCellRoutine`, a function pointer stored in the hive structure
//! rather than called directly. Redirecting that pointer is how a rootkit
//! hides registry keys from everything that reads the registry through the
//! kernel — the keys exist, and every reader is handed a view without them.
//! `ReleaseCellRoutine` is its pair. This stage reads both pointers on every
//! hive the `CmpHiveListHead` list holds and says where each one lands.
//!
//! # Three answers, and which one the record can give
//!
//! A routine lands **in the kernel at a named function** — `HvpGetCellPaged`
//! and `HvpReleaseCellPaged` on all 38 hives of the one build measured,
//! Windows 11 26200; the kernel's flat-hive routine has not been observed
//! here — which is the ordinary case and is stated with the symbol's name,
//! whatever the symbol is. It lands **in another loaded module**,
//! which is named. Or it lands **in no loaded module at all**, which is the
//! strongest signal and is claimed only when the loaded-module map was walked
//! whole; with a map that was not, the record says the question could not be
//! settled rather than clearing the hive.
//!
//! A pointer that lands inside the kernel but **not at a symbol's start** is
//! reported as the nearest symbol plus its offset, never as the function: a
//! hook that jumps into the middle of the real routine has that shape.

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::object::StructReader;
use seance_memory::Incomplete;
use serde_json::{json, Value};

use crate::kernel_hooks::{ModuleMap, Ownership};
use crate::profile::WindowsProfile;
use crate::registry::hivelist::{list_hives, HiveListing};

/// What stops the whole survey.
#[derive(Debug, Clone)]
pub enum HiveCellRoutineError {
    Unsupported {
        detail: String,
    },
    /// The hive list could not be walked at all.
    HiveList {
        detail: String,
    },
}

impl HiveCellRoutineError {
    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::Unsupported {
            detail: detail.into(),
        }
    }

    pub fn class(&self) -> &'static str {
        match self {
            Self::Unsupported { .. } => "unsupported_build",
            Self::HiveList { .. } => "hive_list_unavailable",
        }
    }
}

impl std::fmt::Display for HiveCellRoutineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { detail } | Self::HiveList { detail } => write!(f, "{detail}"),
        }
    }
}

/// How the routines are reached on this build.
#[derive(Debug, Clone)]
pub struct HiveCellRoutineSymbols {
    /// The `_CMHIVE` member holding the `_HHIVE`.
    pub hive_member: String,
    pub get_cell_routine: String,
    /// `None` on a build whose `_HHIVE` declares no release routine.
    pub release_cell_routine: Option<String>,
}

impl HiveCellRoutineSymbols {
    /// Resolve what this build declares.
    ///
    /// # Errors
    ///
    /// [`HiveCellRoutineError::Unsupported`] when `_CMHIVE`, its embedded
    /// `_HHIVE` or `GetCellRoutine` is undeclared.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, HiveCellRoutineError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        for type_name in ["_CMHIVE", "_HHIVE"] {
            if !profile.symbols.has_type(type_name) {
                return Err(HiveCellRoutineError::unsupported(format!(
                    "this build's symbol table declares no '{type_name}', so no hive's cell \
                     routine can be read"
                )));
            }
        }
        if !reader.has_member("_CMHIVE", "Hive") {
            return Err(HiveCellRoutineError::unsupported(
                "this build's '_CMHIVE' embeds no 'Hive', so the _HHIVE cannot be reached from \
                 the hive list",
            ));
        }
        if !reader.has_member("_HHIVE", "GetCellRoutine") {
            return Err(HiveCellRoutineError::unsupported(
                "this build's '_HHIVE' declares no 'GetCellRoutine', so there is no pointer to \
                 examine",
            ));
        }
        Ok(Self {
            hive_member: "Hive".to_string(),
            get_cell_routine: "GetCellRoutine".to_string(),
            release_cell_routine: reader
                .has_member("_HHIVE", "ReleaseCellRoutine")
                .then(|| "ReleaseCellRoutine".to_string()),
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "hive_member": self.hive_member,
            "get_cell_routine": self.get_cell_routine,
            "release_cell_routine": self.release_cell_routine,
        })
    }
}

/// Where one routine pointer landed.
#[derive(Debug, Clone)]
pub struct RoutinePointer {
    pub address: u64,
    /// The kernel symbol at or below the address, when the address is in the
    /// kernel image and the symbol table covers it.
    pub symbol: Option<String>,
    /// How far past that symbol's start the address lies. Zero is the
    /// function itself.
    pub symbol_offset: Option<u64>,
    /// Which loaded module holds the address, from the shared map.
    pub ownership: Ownership,
    /// Whether the address lies outside the kernel image. `None` when the
    /// module map could not support either answer.
    pub outside_the_kernel: Option<bool>,
}

impl RoutinePointer {
    /// The pointer is exactly a named kernel function.
    pub fn at_a_symbol(&self) -> bool {
        self.symbol.is_some() && self.symbol_offset == Some(0)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "address": format!("{:#018x}", self.address),
            "symbol": self.symbol,
            "symbol_offset": self.symbol_offset,
            "at_a_symbol": self.at_a_symbol(),
            "ownership": self.ownership.to_json(),
            "outside_the_kernel": self.outside_the_kernel,
        })
    }
}

/// One hive.
#[derive(Debug, Clone)]
pub struct HiveRoutines {
    pub cmhive: u64,
    pub name: Option<String>,
    /// `None` when the hive's `_HHIVE` would not read; see `unreadable`.
    pub get_cell: Option<RoutinePointer>,
    /// `None` when undeclared on this build or unreadable.
    pub release_cell: Option<RoutinePointer>,
    pub unreadable: Option<String>,
}

impl HiveRoutines {
    fn routines(&self) -> impl Iterator<Item = &RoutinePointer> {
        self.get_cell.iter().chain(self.release_cell.iter())
    }

    /// Any routine lands outside the kernel image.
    pub fn has_a_routine_outside_the_kernel(&self) -> bool {
        self.routines().any(|r| r.outside_the_kernel == Some(true))
    }

    /// Any routine lands in the kernel but not at a symbol's start.
    pub fn has_a_routine_off_a_symbol(&self) -> bool {
        self.routines()
            .any(|r| r.outside_the_kernel == Some(false) && !r.at_a_symbol())
    }

    pub fn to_json(&self) -> Value {
        json!({
            "type": "MemoryHiveCellRoutines",
            "name": format!(
                "cell routines of {}",
                self.name.clone().unwrap_or_else(|| format!("the hive at {:#018x}", self.cmhive))
            ),
            "cmhive": format!("{:#018x}", self.cmhive),
            "hive_name": self.name,
            "get_cell_routine": self.get_cell.as_ref().map(RoutinePointer::to_json),
            "release_cell_routine": self.release_cell.as_ref().map(RoutinePointer::to_json),
            "routine_outside_the_kernel": self.has_a_routine_outside_the_kernel(),
            "routine_off_a_symbol": self.has_a_routine_off_a_symbol(),
            "unreadable": self.unreadable,
        })
    }
}

/// What one survey produced.
#[derive(Debug, Clone)]
pub struct HiveCellRoutineSurvey {
    pub symbols: HiveCellRoutineSymbols,
    pub hives: Vec<HiveRoutines>,
    /// Whether the hive list was walked end to end with nothing rejected.
    pub hive_list_complete: bool,
    /// Whether the module map could support an "outside every module" claim.
    pub module_map_authoritative: bool,
    pub notes: Vec<String>,
}

impl HiveCellRoutineSurvey {
    pub fn hives_with_a_routine_outside_the_kernel(&self) -> usize {
        self.hives
            .iter()
            .filter(|h| h.has_a_routine_outside_the_kernel())
            .count()
    }

    pub fn hives_with_a_routine_off_a_symbol(&self) -> usize {
        self.hives
            .iter()
            .filter(|h| h.has_a_routine_off_a_symbol())
            .count()
    }

    pub fn hives_unreadable(&self) -> usize {
        self.hives.iter().filter(|h| h.unreadable.is_some()).count()
    }

    /// Every hive reached, every routine read, and the map good enough to
    /// place each one.
    pub fn is_complete(&self) -> bool {
        self.hive_list_complete && self.module_map_authoritative && self.hives_unreadable() == 0
    }

    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if !self.hive_list_complete {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                "the hive list did not walk end to end, so a hive it did not reach was not \
                 examined and this is not every hive on the machine"
                    .to_string(),
            ));
        }
        if !self.module_map_authoritative {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                "the loaded-module map is not authoritative, so a routine outside the kernel \
                 image could not be placed and no hive is cleared on that question"
                    .to_string(),
            ));
        }
        for hive in self.hives.iter().filter(|h| h.unreadable.is_some()) {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "the hive at {:#018x} could not be read: {}",
                    hive.cmhive,
                    hive.unreadable.clone().unwrap_or_default()
                ),
            ));
        }
        out
    }

    pub fn describe(&self) -> String {
        format!(
            "{} hive(s) examined; {} carry a cell routine outside the kernel image, {} carry \
             one inside the kernel but not at a function's start, and {} could not be read.{}",
            self.hives.len(),
            self.hives_with_a_routine_outside_the_kernel(),
            self.hives_with_a_routine_off_a_symbol(),
            self.hives_unreadable(),
            if self.module_map_authoritative {
                String::new()
            } else {
                " The module map was not authoritative, so 'outside the kernel' was not \
                 decidable for any hive."
                    .to_string()
            }
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "symbols": self.symbols.to_json(),
            "release_cell_routine_declared": self.symbols.release_cell_routine.is_some(),
            "hives": self.hives.iter().map(HiveRoutines::to_json).collect::<Vec<_>>(),
            "hives_examined": self.hives.len(),
            "hives_with_a_routine_outside_the_kernel": self.hives_with_a_routine_outside_the_kernel(),
            "hives_with_a_routine_off_a_symbol": self.hives_with_a_routine_off_a_symbol(),
            "hives_unreadable": self.hives_unreadable(),
            "hive_list_complete": self.hive_list_complete,
            "module_map_authoritative": self.module_map_authoritative,
            "basis":
                "Each hive's `_HHIVE.GetCellRoutine` (and `ReleaseCellRoutine` where declared) \
                 is read and placed: inside the kernel image at a named symbol, inside it at an \
                 offset from the nearest symbol, inside another loaded module, or in no loaded \
                 module. The last is claimed only when the loaded-module list was walked whole. \
                 A routine outside the kernel is where a registry-hiding hook lives; it is a \
                 signal, and the record names the module rather than judging it.",
            "statement": self.describe(),
            "notes": self.notes,
            "content_complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Read every loaded hive's cell routines.
///
/// # Errors
///
/// [`HiveCellRoutineError::HiveList`] when the hive list cannot be walked at
/// all; a hive that will not read is a row with the reason on it.
pub fn survey_hive_cell_routines(
    profile: &WindowsProfile,
    symbols: &HiveCellRoutineSymbols,
    modules: &ModuleMap,
) -> HiveCellRoutineSurvey {
    let listing = match list_hives(profile) {
        Ok(listing) => listing,
        Err(err) => {
            return HiveCellRoutineSurvey {
                symbols: symbols.clone(),
                hives: Vec::new(),
                hive_list_complete: false,
                module_map_authoritative: modules.is_authoritative(),
                notes: vec![format!(
                    "the hive list could not be walked, so no hive was examined: {err}"
                )],
            }
        }
    };
    survey_from_listing(profile, symbols, modules, &listing)
}

/// The survey over a hive list already walked.
pub fn survey_from_listing(
    profile: &WindowsProfile,
    symbols: &HiveCellRoutineSymbols,
    modules: &ModuleMap,
    listing: &HiveListing,
) -> HiveCellRoutineSurvey {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let kernel_range = modules
        .owner_of(profile.kernel_base.value)
        .map(|range| (range.base, range.end));

    let mut survey = HiveCellRoutineSurvey {
        symbols: symbols.clone(),
        hives: Vec::new(),
        hive_list_complete: listing.is_complete(),
        module_map_authoritative: modules.is_authoritative(),
        notes: Vec::new(),
    };
    if kernel_range.is_none() {
        survey.notes.push(format!(
            "the kernel base {:#018x} lies in no module the map holds, so no routine could be \
             placed inside the kernel image or named from its symbols",
            profile.kernel_base.value
        ));
    }

    for hive in &listing.hives {
        let mut record = HiveRoutines {
            cmhive: hive.address,
            name: hive.name.path().map(str::to_string),
            get_cell: None,
            release_cell: None,
            unreadable: None,
        };
        let hhive = reader
            .object(hive.address, "_CMHIVE")
            .and_then(|cm| cm.embedded(&symbols.hive_member));
        let hhive = match hhive {
            Ok(h) => h,
            Err(err) => {
                record.unreadable = Some(err.to_string());
                survey.hives.push(record);
                continue;
            }
        };
        match hhive.pointer(&symbols.get_cell_routine) {
            Ok(address) => {
                record.get_cell = Some(place(profile, modules, kernel_range, address));
            }
            Err(err) => {
                record.unreadable = Some(format!(
                    "'{}' would not read: {err}",
                    symbols.get_cell_routine
                ))
            }
        }
        if let Some(member) = &symbols.release_cell_routine {
            if let Ok(address) = hhive.pointer(member) {
                record.release_cell = Some(place(profile, modules, kernel_range, address));
            }
        }
        survey.hives.push(record);
    }
    survey
}

/// Place one pointer: module, kernel symbol and the outside-the-kernel verdict.
fn place(
    profile: &WindowsProfile,
    modules: &ModuleMap,
    kernel_range: Option<(u64, u64)>,
    address: u64,
) -> RoutinePointer {
    let ownership = modules.attribute(address);
    let in_kernel_by_map = kernel_range.map(|(base, end)| base <= address && address <= end);
    let (symbol, symbol_offset) = match address.checked_sub(profile.kernel_base.value) {
        Some(rva) if in_kernel_by_map == Some(true) => profile
            .symbols
            .nearest_symbol(rva)
            .map(|(entry, distance)| (Some(entry.name.to_string()), Some(distance)))
            .unwrap_or((None, None)),
        _ => (None, None),
    };
    let outside_the_kernel = match (&ownership, in_kernel_by_map) {
        (Ownership::InModule { .. }, Some(inside)) => Some(!inside),
        (Ownership::InModule { .. }, None) => None,
        (Ownership::OutsideAnyModule, _) => Some(true),
        (Ownership::Undetermined(_), _) => None,
    };
    RoutinePointer {
        address,
        symbol,
        symbol_offset,
        ownership,
        outside_the_kernel,
    }
}
