//! A skeleton key in the LSA — what the evidence supports, and a route it does
//! not (`ROADMAP` §5.3).
//!
//! # What a skeleton key is
//!
//! A patch inside `lsass.exe` that makes one attacker-chosen password work for
//! **every** domain account while each account's real password keeps working
//! too. The published implementation patches `cryptdll.dll`'s RC4-HMAC
//! descriptor so Kerberos pre-authentication succeeds against a key the
//! attacker knows. Nothing on disk changes, no account is modified, and no
//! event is logged: the effect is that authentication succeeds where it should
//! not.
//!
//! # The two routes, and the honest scope of each
//!
//! **(a) The export prologue, which this build runs.** `CDLocateCSystem` is an
//! exported function of `cryptdll.dll`, so it can be located from the module's
//! own export table with no symbols at all and classified by the same decoder
//! the ETW check uses ([`crate::tamper_etw::classify`]) — a function that
//! returns immediately, traps, or whose first control transfer leaves the
//! module. A hooked `CDLocateCSystem` is one of the two shapes the technique
//! has taken.
//!
//! **(b) The `CSystems` descriptor table, which this build does not run and
//! says so permanently.** The stronger signal is an RC4-HMAC descriptor whose
//! function pointer leaves `cryptdll`. Reaching it needs the layout of
//! `cryptdll`'s own descriptor structure, and **nobody publishes it**: Microsoft
//! ships `cryptdll.pdb` as a *public* PDB — names, no structure layouts —
//! exactly as it ships `tcpip.pdb`, which
//! `seance_memory/tests/KNOWN_ANSWERS.md` already records as 10,376 symbols and
//! **zero types**. So this route is not "blocked pending an ISF": an ISF of a
//! public PDB would give the address of the `CSystems` global and nothing
//! whatever about the entry layout the check reads. It is named on every record
//! as a route that did not run, with what it would have established, and that
//! is the honest form of it rather than a promise.
//!
//! # A machine with no reachable `lsass.exe` is not a clean machine
//!
//! If no `lsass.exe` is in the process list, or its `cryptdll` is not mapped,
//! or its pages are not resident, the group reports **not assessed** with the
//! reason. A memory image whose `lsass` the walk never reached says nothing
//! about whether that machine had a skeleton key, and an empty result that read
//! as "no skeleton key" would be the worst kind of false absence: the question
//! is asked precisely when domain authentication is in doubt.
//!
//! Expected count on any clean capture: **zero, on both routes** — one of which
//! did not run.

use serde_json::{json, Value};

use crate::modules::{ModuleSymbols, ModuleWalkConfig, ProcessSpace};
use crate::process::ProcessList;
use crate::profile::WindowsProfile;
use crate::tamper::TamperError;
use crate::tamper_etw::{classify, Classification, PROLOGUE_BYTES};

/// The module the key lives in.
pub const CRYPTDLL: &str = "cryptdll.dll";

/// The process the module lives in.
pub const LSASS: &str = "lsass.exe";

/// The export this build classifies.
pub const EXPORT: &str = "CDLocateCSystem";

/// Why the `CSystems` route is named rather than run.
pub const CSYSTEMS_ROUTE: &str =
    "NOT RUN, and not pending an ISF either. The stronger signal is a `CSystems` descriptor \
     whose function pointer leaves cryptdll, and reaching it needs the layout of that \
     descriptor -- which nobody publishes. Microsoft ships cryptdll.pdb as a PUBLIC PDB: \
     function and global names, no structure layouts, exactly as it ships tcpip.pdb, which this \
     project already records as 10,376 symbols and ZERO types. An ISF built from it would give \
     the address of the `CSystems` global and nothing about the entry layout this route would \
     read. What it would have established, and this build therefore does not: whether an \
     RC4-HMAC descriptor's function pointer had been redirected out of the module while the \
     exported entry point was left intact.";

/// One `lsass.exe` examined.
#[derive(Debug, Clone)]
pub struct LsassProcess {
    pub process: u64,
    pub pid: Option<u64>,
    /// Where `cryptdll.dll` is mapped in this process.
    pub cryptdll_base: u64,
    /// Whether the mapping was corroborated as an image mapping.
    pub image_mapped: Option<bool>,
    /// Where `CDLocateCSystem` is.
    pub export_address: u64,
    pub prologue: Vec<u8>,
    pub classification: Classification,
}

impl LsassProcess {
    pub fn is_signal(&self) -> bool {
        self.classification.is_signal()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "type": "MemorySkeletonKeyCheck",
            "name": format!(
                "{EXPORT} in lsass.exe (pid {}): {}",
                self.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
                self.classification.as_str()
            ),
            "process_address": format!("{:#018x}", self.process),
            "pid": self.pid,
            "module": CRYPTDLL,
            "module_base": format!("{:#018x}", self.cryptdll_base),
            "image_mapped": self.image_mapped,
            "export": EXPORT,
            "export_address": format!("{:#018x}", self.export_address),
            "prologue": self
                .prologue
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
            "classification": self.classification.as_str(),
            "is_signal": self.is_signal(),
            "route_run": "export_prologue",
            "route_not_run": "csystems_descriptor_table",
            "route_not_run_detail": CSYSTEMS_ROUTE,
        })
    }
}

/// What the check produced.
#[derive(Debug, Clone)]
pub struct SkeletonOutcome {
    /// The `lsass.exe` processes examined.
    pub examined: Vec<LsassProcess>,
    /// How many processes in the list were named `lsass.exe`.
    pub lsass_found: u64,
    /// Each `lsass.exe` that could not be assessed, with the reason.
    pub unassessed: Vec<(u64, String)>,
    pub notes: Vec<String>,
}

impl SkeletonOutcome {
    pub fn signals(&self) -> usize {
        self.examined.iter().filter(|p| p.is_signal()).count()
    }

    /// Whether this run assessed anything at all.
    ///
    /// **A false here is not a clean machine.** It is a machine whose `lsass`
    /// this image could not be asked about.
    pub fn assessed_anything(&self) -> bool {
        !self.examined.is_empty()
    }

    pub fn describe(&self) -> String {
        if !self.assessed_anything() {
            return format!(
                "No `lsass.exe` could be examined on this image ({} found in the process list, \
                 {} of them unassessable). NOTHING here is a statement about whether this \
                 machine had a skeleton key: the question was not reached. One of the two \
                 routes does not run on any build -- see `route_not_run_detail`.",
                self.lsass_found,
                self.unassessed.len()
            );
        }
        format!(
            "{} `lsass.exe` process(es) were examined and {} of them show a patched \
             `{EXPORT}`. The second route -- the `CSystems` descriptor table -- did not run on \
             this or any build, and its absence is on every record rather than implied.",
            self.examined.len(),
            self.signals()
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "lsass_processes": self.examined.iter().map(LsassProcess::to_json).collect::<Vec<_>>(),
            "lsass_examined": self.examined.len(),
            "lsass_found": self.lsass_found,
            "signals": self.signals(),
            "assessed_anything": self.assessed_anything(),
            "unassessed": self
                .unassessed
                .iter()
                .map(|(process, reason)| json!({
                    "process_address": format!("{process:#018x}"),
                    "reason": reason,
                }))
                .collect::<Vec<_>>(),
            "statement": self.describe(),
            "route_run": "export_prologue",
            "route_not_run": "csystems_descriptor_table",
            "route_not_run_detail": CSYSTEMS_ROUTE,
            "notes": self.notes,
            // Never complete: one of the two routes does not run at all, so the
            // check's own coverage is bounded on every build.
            "content_incomplete": true,
            "content_incomplete_reason":
                seance_core::io::IncompleteReason::UnresolvedStructure.as_str(),
        })
    }
}

/// Whether a process name is `lsass.exe`.
///
/// Compared on the whole name, case-insensitively, and never as a substring: a
/// process called `lsass.exe.old` or `notlsass.exe` is not the LSA, and a
/// **substring** match is how a check comes to examine the wrong process and
/// report the right one's name.
pub fn is_lsass(name: &str) -> bool {
    // `ImageFileName` is fifteen bytes, so a long name arrives truncated. The
    // comparison is therefore against the truncation too -- `lsass.exe` fits,
    // so this only matters for the negative cases.
    name.trim_end_matches('\0').eq_ignore_ascii_case(LSASS)
}

/// Examine every `lsass.exe`.
///
/// # Errors
///
/// [`TamperError::Unsupported`] when this build's loader entries cannot be
/// described — without them `cryptdll` cannot be located in any process, so
/// neither route can run and an empty result would read as a machine with no
/// skeleton key.
pub fn examine_skeleton_key(
    profile: &WindowsProfile,
    processes: &ProcessList,
) -> Result<SkeletonOutcome, TamperError> {
    let symbols = ModuleSymbols::from_profile(profile).map_err(|err| {
        TamperError::unsupported(format!(
            "this build's loader entries cannot be described: {err}. Without them cryptdll \
             cannot be located inside lsass, so neither skeleton-key route can run and nothing \
             is said about whether this machine's domain authentication had been subverted."
        ))
    })?;
    let bitness = if profile.architecture == seance_memory::Architecture::X86 {
        32
    } else {
        64
    };
    let vad = crate::vad::VadSymbols::from_profile(profile).ok();

    let mut out = SkeletonOutcome {
        examined: Vec::new(),
        lsass_found: 0,
        unassessed: Vec::new(),
        notes: Vec::new(),
    };

    for entry in &processes.processes {
        let name = entry.image_file_name.known().cloned().unwrap_or_default();
        if !is_lsass(&name) {
            continue;
        }
        out.lsass_found += 1;
        match examine_one(profile, &symbols, vad.as_ref(), entry, bitness) {
            Ok(row) => out.examined.push(row),
            Err(reason) => out.unassessed.push((entry.address, reason)),
        }
    }

    if out.lsass_found == 0 {
        out.notes.push(
            "no process in this list is named lsass.exe. On a running Windows machine there is \
             always exactly one, so this is a statement about the process list rather than \
             about the machine: either the walk did not reach it or the name could not be read. \
             Nothing is claimed about a skeleton key."
                .to_string(),
        );
    }
    Ok(out)
}

fn examine_one(
    profile: &WindowsProfile,
    symbols: &ModuleSymbols,
    vad: Option<&crate::vad::VadSymbols>,
    entry: &crate::process::ProcessRecord,
    bitness: u32,
) -> Result<LsassProcess, String> {
    let space = ProcessSpace::build(
        profile,
        symbols,
        entry.address,
        &ModuleWalkConfig::default(),
    )
    .map_err(|err| format!("this lsass.exe has no readable address space: {err}"))?;
    let copy =
        crate::tamper_etw::find_module(profile, symbols, vad, entry.address, &space, CRYPTDLL)
            .map_err(|why| {
                format!(
                    "{why}. cryptdll is loaded on demand, so its absence here is not by itself \
             suspicious -- but it does mean this route could not be run on this process."
                )
            })?;

    let layer = space.layer();
    let headers = crate::dump::read_pe_headers(layer.as_ref(), copy.base).map_err(|err| {
        format!(
            "cryptdll's headers at {:#x} would not read: {err}",
            copy.base
        )
    })?;
    let table = crate::dump::read_exports(
        layer.as_ref(),
        &headers,
        &crate::dump::ImportConfig::default(),
    )
    .map_err(|err| format!("cryptdll's export table would not read: {err}"))?;

    let target = table.by_name(EXPORT).ok_or_else(|| {
        format!(
            "cryptdll at {:#x} does not export {EXPORT}{}",
            copy.base,
            if table.truncated {
                ", and its export table was truncated by a cap -- so this is 'not found in what \
                 was read' rather than 'not exported'"
            } else {
                ""
            }
        )
    })?;
    if let Some(forwarder) = target.forwarder.as_deref() {
        return Err(format!(
            "{EXPORT} is forwarded to {forwarder} in this copy, so the function does not live \
             in cryptdll at all and its prologue is not here to classify"
        ));
    }
    let export_address = copy.base.saturating_add(target.rva as u64);
    let mut prologue = vec![0u8; PROLOGUE_BYTES];
    layer
        .read_at(export_address, &mut prologue)
        .map_err(|err| format!("{EXPORT}'s first bytes would not read: {err}"))?;

    let classification = classify(&prologue, export_address, bitness, (copy.base, copy.end));
    Ok(LsassProcess {
        process: entry.address,
        pid: entry.pid.known().copied(),
        cryptdll_base: copy.base,
        image_mapped: copy.image_mapped,
        export_address,
        prologue,
        classification,
    })
}
