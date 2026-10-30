//! Loaded kernel extensions, walked from the kernel's `kmod` chain.
//!
//! macOS keeps its loaded kexts on a singly-linked chain of `kmod_info`
//! structures whose head is the `kmod` pointer variable. Each entry carries the
//! bundle identifier, the version string, the load address, the size and a
//! reference count — which is `kextstat` output, recovered from RAM rather than
//! asked of a machine that may be lying.
//!
//! # What this stage does not claim
//!
//! It does **not** say a kext is unsigned, malicious, or hidden. The chain is
//! the kernel's own record of what it loaded; something that unlinked itself
//! from the chain is by definition not on it, and this stage has no second
//! listing to compare against, so it cannot produce a concealment finding and
//! does not pretend to. What it does produce is the inventory, complete or
//! honestly marked short.
//!
//! All 117 sixty-four-bit Kernel Debug Kit packs in
//! `reference/volatility3/volatility3/symbols` declare `kmod` and every
//! `kmod_info` member named here.
//!
//! **Unvalidated.** See [`crate::unvalidated`]: this has never been run against
//! a real macOS capture. It is transcribed from Volatility 3's
//! `plugins/mac/lsmod.py` and from the symbol packs.

use std::collections::HashSet;

use seance_core::io::IncompleteReason;
use seance_memory::binding::{
    BindError, BuildBinding, Field, MemberSet, MemberSpec, Necessity, TypeSpec,
};
use seance_memory::object::ObjError;
use serde_json::json;

use crate::fields::{int_field, pointer_field, required_path, text_field, unsigned_field};
use crate::module::STAGE_KERNEL_EXTENSIONS;
use crate::process::ChainStop;
use crate::profile::MacProfile;

/// Ceiling on chain entries. A Mac loads tens of kexts; reaching this means the
/// chain is wrong, not that the machine was busy.
pub const DEFAULT_MAX_KEXTS: usize = 4_096;

/// What the kext walk needs from the symbol pack.
pub const KEXT_LAYOUT: MemberSet = MemberSet::new(
    STAGE_KERNEL_EXTENSIONS,
    &[TypeSpec {
        key: "kmod_info",
        candidates: &["kmod_info"],
        necessity: Necessity::Required {
            without_it: "there is no kernel-extension structure to read, so no loaded extension \
                         can be described at all",
        },
    }],
    &[
        MemberSpec {
            key: "next",
            types: &["kmod_info"],
            members: &["next"],
            necessity: Necessity::Required {
                without_it: "the chain cannot be followed past its first entry, and a one-entry \
                             answer would read as a machine with a single kernel extension \
                             loaded, which no Mac has",
            },
        },
        MemberSpec::new("name", &["kmod_info"], &["name"]),
        MemberSpec::new("version", &["kmod_info"], &["version"]),
        MemberSpec::new("address", &["kmod_info"], &["address"]),
        MemberSpec::new("size", &["kmod_info"], &["size"]),
        MemberSpec::new("header_size", &["kmod_info"], &["hdr_size"]),
        MemberSpec::new("reference_count", &["kmod_info"], &["reference_count"]),
        MemberSpec::new("id", &["kmod_info"], &["id"]),
        MemberSpec::new("info_version", &["kmod_info"], &["info_version"]),
        MemberSpec::new("start", &["kmod_info"], &["start"]),
        MemberSpec::new("stop", &["kmod_info"], &["stop"]),
    ],
);

/// The kext stage could not run.
#[derive(Debug, thiserror::Error)]
pub enum KextError {
    /// The symbol pack does not support this stage on this build.
    #[error(transparent)]
    Bind(#[from] BindError),
    /// A symbol the stage needs is absent.
    #[error(transparent)]
    Symbols(#[from] seance_symbols::SymbolError),
    /// A structure could not be read.
    #[error(transparent)]
    Object(#[from] ObjError),
    /// The stage refused for a reason of its own.
    #[error("{0}")]
    Refused(String),
}

/// One loaded kernel extension.
#[derive(Debug, Clone)]
pub struct Kext {
    /// Address of the `kmod_info` structure.
    pub address: u64,
    /// Bundle identifier, e.g. `com.apple.iokit.IOHIDFamily`.
    pub name: Field<String>,
    /// Version string as the kext declared it.
    pub version: Field<String>,
    /// Load address of the extension's code.
    ///
    /// `u64` and not `i64`: this is a kernel pointer held in an unsigned
    /// member, and on every 64-bit pack here it is above `i64::MAX`.
    pub load_address: Field<u64>,
    /// Size of the loaded extension, in bytes.
    pub size: Field<u64>,
    /// Size of the Mach-O header portion.
    pub header_size: Field<u64>,
    /// How many other things hold a reference to it.
    pub reference_count: Field<i64>,
    /// The kernel's own identifier for the extension.
    pub id: Field<i64>,
    /// `kmod_info` structure version, which is what tells a reader whether the
    /// remaining members mean what this stage assumes they mean.
    pub info_version: Field<i64>,
    /// Entry point.
    pub start: Field<u64>,
    /// Exit point.
    pub stop: Field<u64>,
}

impl Kext {
    /// Serializable form for one row.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "kmod_info_address": self.address,
            "kmod_info_address_hex": format!("{:#x}", self.address),
            "bundle_id": self.name.to_json(),
            "version": self.version.to_json(),
            "load_address": self.load_address.to_json_address(),
            "size": self.size.to_json(),
            "header_size": self.header_size.to_json(),
            "reference_count": self.reference_count.to_json_with(|v| json!(v)),
            "kmod_id": self.id.to_json_with(|v| json!(v)),
            "kmod_info_version": self.info_version.to_json_with(|v| json!(v)),
            "start_address": self.start.to_json_address(),
            "stop_address": self.stop.to_json_address(),
        })
    }
}

/// The loaded-extension inventory.
#[derive(Debug, Clone)]
pub struct KextList {
    /// The extensions reached, in chain order.
    pub kexts: Vec<Kext>,
    /// Why the walk ended.
    pub stop: ChainStop,
}

impl KextList {
    /// Whether the whole chain was enumerated.
    pub fn is_complete(&self) -> bool {
        self.stop.is_complete()
    }

    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "name": "macOS loaded kernel extensions",
            "kext_count": self.kexts.len(),
            "kexts": self.kexts.iter().map(Kext::to_json).collect::<Vec<_>>(),
            "walk": self.stop.to_json(),
            "incomplete": self
                .stop
                .incomplete()
                .map(|i| vec![i.to_json()])
                .unwrap_or_default(),
        })
    }
}

/// The symbol facts the kext walk resolved for this build.
#[derive(Debug, Clone)]
pub struct KextSymbols {
    binding: BuildBinding,
    kmod_info_type: &'static str,
    kmod_info_size: u64,
}

impl KextSymbols {
    /// Resolve [`KEXT_LAYOUT`] against this image's kernel build.
    pub fn from_profile(profile: &MacProfile) -> Result<Self, KextError> {
        let reader = profile.reader();
        let binding = KEXT_LAYOUT.bind(&reader)?;
        let bound = binding.type_of("kmod_info")?;
        let kmod_info_type = bound.type_name().ok_or_else(|| {
            KextError::Refused("this build declares no 'kmod_info' structure".to_string())
        })?;
        let kmod_info_size = bound.size().ok_or_else(|| {
            KextError::Refused(
                "this build declares a 'kmod_info' structure with no size, so no entry can be \
                 bounds-checked before it is read"
                    .to_string(),
            )
        })?;
        Ok(Self {
            binding,
            kmod_info_type,
            kmod_info_size,
        })
    }

    /// How each declaration resolved on this build.
    pub fn to_json(&self) -> serde_json::Value {
        self.binding.to_json()
    }
}

/// Tuning for one walk.
#[derive(Debug, Clone, Copy)]
pub struct KextWalkConfig {
    /// Ceiling on entries.
    pub max_kexts: usize,
}

impl Default for KextWalkConfig {
    fn default() -> Self {
        Self {
            max_kexts: DEFAULT_MAX_KEXTS,
        }
    }
}

/// Walk the `kmod` chain.
///
/// The chain is null-terminated, so a null forward link is its natural end and
/// is reported as complete.
///
/// # A note on the declared type of `kmod`
///
/// The packs declare `kmod` as a pointer to `kmod_info_64_v1` on most builds and
/// to `kmod_info_32_v1` on others, while the members this stage reads are on
/// `kmod_info`. The head is therefore read as a raw pointer and the structure at
/// the far end is read as `kmod_info`, exactly as Volatility 3's `lsmod` does.
/// This is the one place in the crate where a declared pointer subtype is
/// deliberately not followed, and the reason it is safe is that `kmod_info` is
/// the type whose members are declared and read: nothing is assumed about the
/// layout of the type the pointer names.
pub fn list_kexts(
    profile: &MacProfile,
    symbols: &KextSymbols,
    config: &KextWalkConfig,
) -> Result<KextList, KextError> {
    let reader = profile.reader();
    let head_address = profile.symbol("kmod")?;
    let mut current = reader.read_pointer_at(head_address)?;

    let next_path = required_path(
        &symbols.binding,
        "next",
        "the chain cannot be followed past its first entry, and a one-entry answer would read as \
         a machine with a single kernel extension loaded",
    )
    .map_err(KextError::Refused)?;

    let mut kexts = Vec::new();
    let mut visited: HashSet<u64> = HashSet::new();

    let stop = loop {
        if current == 0 {
            break ChainStop::Terminated;
        }
        if kexts.len() >= config.max_kexts {
            break ChainStop::CapReached {
                cap: config.max_kexts,
            };
        }
        if !visited.insert(current) {
            break ChainStop::Cycle { address: current };
        }
        if !profile
            .kernel_space
            .is_valid(current, symbols.kmod_info_size)
        {
            break ChainStop::Unreadable {
                at: Some(current),
                detail: format!(
                    "the {} byte(s) of the kmod_info at {current:#x} were not acquired",
                    symbols.kmod_info_size
                ),
                reason: IncompleteReason::ShortRead,
            };
        }

        let object = match reader.object(current, symbols.kmod_info_type) {
            Ok(object) => object,
            Err(err) => {
                break ChainStop::Unreadable {
                    at: Some(current),
                    detail: err.to_string(),
                    reason: IncompleteReason::UnresolvedStructure,
                }
            }
        };

        kexts.push(Kext {
            address: current,
            name: text_field(&symbols.binding, &object, "name"),
            version: text_field(&symbols.binding, &object, "version"),
            load_address: unsigned_field(&symbols.binding, &object, "address"),
            size: unsigned_field(&symbols.binding, &object, "size"),
            header_size: unsigned_field(&symbols.binding, &object, "header_size"),
            reference_count: int_field(&symbols.binding, &object, "reference_count"),
            id: int_field(&symbols.binding, &object, "id"),
            info_version: int_field(&symbols.binding, &object, "info_version"),
            start: pointer_field(&symbols.binding, &object, "start"),
            stop: pointer_field(&symbols.binding, &object, "stop"),
        });

        current = match object.pointer(next_path) {
            Ok(next) => next,
            Err(err) => {
                break ChainStop::Unreadable {
                    at: Some(current),
                    detail: err.to_string(),
                    reason: IncompleteReason::UnresolvedStructure,
                }
            }
        };
    };

    Ok(KextList { kexts, stop })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kext(name: &str) -> Kext {
        Kext {
            address: 0xffff_ff7f_8000_0000,
            name: Field::Known(name.to_string()),
            version: Field::Known("1.0.0".to_string()),
            load_address: Field::Known(0xffff_ff7f_8000_1000),
            size: Field::Known(0x2000),
            header_size: Field::Known(0x1000),
            reference_count: Field::Known(3),
            id: Field::Known(7),
            info_version: Field::Known(1),
            start: Field::Known(0x1100),
            stop: Field::Known(0x1200),
        }
    }

    #[test]
    fn a_complete_chain_reports_its_count_as_a_total() {
        let list = KextList {
            kexts: vec![kext("com.apple.iokit.IOHIDFamily")],
            stop: ChainStop::Terminated,
        };
        let json = list.to_json();
        assert_eq!(json["kext_count"], json!(1));
        assert_eq!(json["walk"]["complete"], json!(true));
        assert!(json["incomplete"].as_array().expect("an array").is_empty());
    }

    #[test]
    fn a_capped_chain_is_never_reported_as_a_machine_with_few_extensions() {
        // "Twelve kexts loaded" and "we stopped counting at twelve" are
        // opposite findings when the question is what was loaded.
        let list = KextList {
            kexts: vec![kext("a")],
            stop: ChainStop::CapReached { cap: 1 },
        };
        assert!(!list.is_complete());
        let json = list.to_json();
        assert_eq!(json["walk"]["complete"], json!(false));
        assert!(!json["incomplete"].as_array().expect("an array").is_empty());
        assert!(list.stop.incomplete().is_some());
    }

    #[test]
    fn every_required_declaration_says_what_is_lost_without_it() {
        for spec in KEXT_LAYOUT.members {
            if let Necessity::Required { without_it } = spec.necessity {
                assert!(
                    without_it.len() > 30,
                    "{} is required with no useful justification",
                    spec.key
                );
            }
        }
        for spec in KEXT_LAYOUT.types {
            if let Necessity::Required { without_it } = spec.necessity {
                assert!(without_it.len() > 30, "{} lacks a justification", spec.key);
            }
        }
    }

    #[test]
    fn a_kext_row_keeps_its_pointers_in_exact_form() {
        // A JSON number is an IEEE double and a kernel pointer above 2^53
        // arrives rounded. A load address quoted in a report has to be the
        // address that was read.
        let mut row = kext("com.apple.driver.AppleAPIC");
        row.start = Field::Known(0xffff_ff7f_8123_4567);
        let json = row.to_json();
        assert_eq!(
            json["start_address"]["value_hex"],
            json!("0xffffff7f81234567")
        );
        // And the load address, which is the one held in an *unsigned integer*
        // member rather than a pointer member. Read as a signed 64-bit value it
        // would not fit and every kext would report its load address as
        // unavailable, which reads as damaged evidence rather than as a bug.
        assert_eq!(json["load_address"]["kind"], json!("known"));
        assert_eq!(
            json["load_address"]["value_hex"],
            json!("0xffffff7f80001000")
        );
    }
}
