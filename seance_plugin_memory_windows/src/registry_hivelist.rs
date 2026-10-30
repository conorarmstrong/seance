//! `hivelist`: every registry hive the kernel had loaded, and where it came
//! from.
//!
//! The kernel keeps its loaded hives on one doubly-linked list whose head is
//! the exported `CmpHiveListHead`, threaded through `_CMHIVE.HiveList`. Walking
//! it is the first thing any registry analysis of a memory image does, because
//! a hive's address is the only handle everything else takes: [`crate::registry::space::HiveSpace`]
//! opens one, `printkey` reads through one, and a key path means nothing without
//! the hive it was read from.
//!
//! # What the list says, and what it does not
//!
//! Each `_CMHIVE` carries up to three `_UNICODE_STRING`s naming its backing
//! file — `FileFullPath`, `FileUserName`, `HiveRootPath` — and which of them is
//! populated varies by Windows version and by how the hive was mounted. Some
//! hives have **none of them**, legitimately: `\REGISTRY\MACHINE\HARDWARE` is
//! built at boot and never written anywhere. That is why an unnamed hive is
//! [`HiveName::NoBackingFile`] and not an empty string: "this hive has no file"
//! and "we could not read this hive's file name" are different facts, and an
//! empty string in a report is indistinguishable from a failed read.
//!
//! # Why the list is walked in both directions
//!
//! A `_CMHIVE` whose page is not resident breaks the forward walk at that
//! entry, and every hive after it is lost — but the list is doubly linked, so
//! the far end of it is still reachable backwards from the head. Upstream does
//! this and it is worth copying: the hives on the far side of an unreadable one
//! are real evidence. What is *not* copied is upstream's habit of stopping
//! silently; here both walks record why they ended, and a hive whose signature
//! does not check out is moved to [`HiveListing::rejected`] rather than dropped.

use std::collections::HashSet;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::meta::Incomplete;
use seance_memory::object::{ListSpec, ListStop, Obj, StructReader};

use crate::profile::WindowsProfile;
use crate::registry::error::RegistryError;
use crate::registry::key::decode_utf16le;
use crate::registry::space::{unsigned_member, HIVE_SIGNATURE};

/// The kernel symbol the hive list hangs off.
pub const HIVE_LIST_HEAD: &str = "CmpHiveListHead";

/// Ceiling on the hives one walk will report.
///
/// A busy Windows 11 machine has a few dozen loaded hives; a hundred thousand
/// means the link chain is wrong, not that the machine was busy.
pub const MAX_HIVES: usize = 4_096;

/// Which way round the list an entry was reached.
///
/// Recorded per hive because it is provenance: a hive found only by walking
/// backwards was on the far side of something unreadable, and an examiner is
/// entitled to know which of the rows in front of them are in that position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkDirection {
    /// Reached by following `Flink` from the head.
    Forward,
    /// Reached by following `Blink` from the head, after the forward walk
    /// stopped early.
    Backward,
}

impl WalkDirection {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            WalkDirection::Forward => "forward",
            WalkDirection::Backward => "backward",
        }
    }

    /// The `_LIST_ENTRY` member this direction follows.
    fn member(self) -> &'static str {
        match self {
            WalkDirection::Forward => "Flink",
            WalkDirection::Backward => "Blink",
        }
    }
}

/// Which `_CMHIVE` member a hive's name came from.
///
/// Reported beside the name because the three are not equivalent:
/// `FileFullPath` is the full NT device path, `FileUserName` is what the caller
/// asked for when the hive was loaded, and `HiveRootPath` is the registry path
/// it is mounted at. Two hives can be told apart by which one is populated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HiveNameSource {
    /// `_CMHIVE.FileFullPath`, e.g. `\Device\HarddiskVolume1\WINDOWS\...`.
    FileFullPath,
    /// `_CMHIVE.FileUserName`.
    FileUserName,
    /// `_CMHIVE.HiveRootPath`, e.g. `\REGISTRY\USER\S-1-5-21-...`.
    HiveRootPath,
}

impl HiveNameSource {
    /// The member name, which is also the stable identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            HiveNameSource::FileFullPath => "FileFullPath",
            HiveNameSource::FileUserName => "FileUserName",
            HiveNameSource::HiveRootPath => "HiveRootPath",
        }
    }
}

/// What a hive is called, or why it is not called anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HiveName {
    /// The hive names a backing file.
    Path {
        /// The path, decoded from UTF-16LE.
        text: String,
        /// Which member it came from.
        source: HiveNameSource,
        /// Whether every code unit decoded cleanly.
        well_formed: bool,
    },
    /// The hive names no file, and said so: every path member it has is empty.
    ///
    /// The volatile hives are like this — `\REGISTRY\MACHINE\HARDWARE` is
    /// rebuilt at every boot and has never been written to disk. An explicit
    /// marker rather than an empty string, because the two must not render the
    /// same.
    NoBackingFile,
    /// The name could not be read, and here is why.
    Unavailable(Incomplete),
}

impl HiveName {
    /// The path, if there is one.
    pub fn path(&self) -> Option<&str> {
        match self {
            HiveName::Path { text, .. } => Some(text),
            _ => None,
        }
    }

    /// The last `\`-separated component of the path — the hive's file name.
    pub fn file_name(&self) -> Option<&str> {
        self.path()
            .map(|path| path.rsplit('\\').next().unwrap_or(path))
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            HiveName::Path {
                text,
                source,
                well_formed,
            } => serde_json::json!({
                "kind": "path",
                "text": text,
                "source": source.as_str(),
                "well_formed": well_formed,
            }),
            HiveName::NoBackingFile => serde_json::json!({"kind": "no_backing_file"}),
            HiveName::Unavailable(incomplete) => serde_json::json!({
                "kind": "unavailable",
                "incomplete": incomplete.to_json(),
            }),
        }
    }
}

/// One loaded registry hive.
#[derive(Debug, Clone)]
pub struct HiveRecord {
    /// Address of the `_CMHIVE` in the kernel address space.
    ///
    /// The handle everything downstream takes, and the provenance every key
    /// recovered from this hive carries.
    pub address: u64,
    /// What the hive is called.
    pub name: HiveName,
    /// Which way round the list it was reached.
    pub direction: WalkDirection,
}

impl HiveRecord {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "name": self.name.to_json(),
            "direction": self.direction.as_str(),
        })
    }
}

/// A structure on the hive list that is not a hive.
///
/// Kept rather than discarded. A `_CMHIVE` whose `_HHIVE.Signature` is wrong is
/// either a hive whose header was paged out or a link chain that has been
/// tampered with, and both are worth a line in the report; neither belongs in
/// the list of hives, because everything downstream would try to parse it.
#[derive(Debug, Clone)]
pub struct RejectedHive {
    /// Where the candidate was.
    pub address: u64,
    /// Why it was not accepted.
    pub reason: String,
    /// Which way round the list it was reached.
    pub direction: WalkDirection,
}

impl RejectedHive {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "reason": self.reason,
            "direction": self.direction.as_str(),
        })
    }
}

/// Everything the hive-list walk found, and everything it could not.
#[derive(Debug, Clone)]
pub struct HiveListing {
    /// Address of `CmpHiveListHead` in the kernel address space.
    pub head: u64,
    /// The hives, in the order they were reached.
    pub hives: Vec<HiveRecord>,
    /// Structures on the list that did not check out as hives.
    pub rejected: Vec<RejectedHive>,
    /// Everything that stopped the walk being exhaustive.
    pub incomplete: Vec<Incomplete>,
}

impl HiveListing {
    /// Whether the list was walked end to end with nothing rejected.
    ///
    /// A caller that reports a hive count without reporting this has published
    /// a number it cannot vouch for: a list that stopped at an unreadable entry
    /// is short, and a short list of hives looks exactly like a machine with
    /// fewer hives.
    pub fn is_complete(&self) -> bool {
        self.incomplete.is_empty() && self.rejected.is_empty()
    }

    /// Hives whose name contains `needle`, compared case-insensitively.
    pub fn matching(&self, needle: &str) -> Vec<&HiveRecord> {
        let needle = needle.to_lowercase();
        self.hives
            .iter()
            .filter(|hive| {
                hive.name
                    .path()
                    .is_some_and(|path| path.to_lowercase().contains(&needle))
            })
            .collect()
    }

    /// Serializable form for the hive-list artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "head": self.head,
            "count": self.hives.len(),
            "complete": self.is_complete(),
            "hives": self.hives.iter().map(HiveRecord::to_json).collect::<Vec<_>>(),
            "rejected": self.rejected.iter().map(RejectedHive::to_json).collect::<Vec<_>>(),
            "incomplete": self.incomplete.iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Walk `CmpHiveListHead` and report every loaded hive.
///
/// # Errors
///
/// Only for failures that make the walk impossible to start: no
/// `CmpHiveListHead` in the symbol table, a kernel base plus symbol address
/// that does not fit in 64 bits, or a symbol table with no `_CMHIVE`. Failures
/// *during* the walk are not errors — they are recorded in
/// [`HiveListing::incomplete`] beside the hives that were found, because the
/// hives before the failure are evidence and discarding them protects nobody.
pub fn list_hives(profile: &WindowsProfile) -> Result<HiveListing, RegistryError> {
    let rva = profile.symbols.symbol_address(HIVE_LIST_HEAD)?;
    let head = profile.kernel_base.value.checked_add(rva).ok_or_else(|| {
        RegistryError::Overflow(format!(
            "the kernel base {:#x} plus '{HIVE_LIST_HEAD}' at {rva:#x} does not fit in 64 bits",
            profile.kernel_base.value
        ))
    })?;
    list_hives_from(profile, head)
}

/// Walk a hive list whose head address is already known.
///
/// Separated so an examiner who has recovered `CmpHiveListHead` by other means
/// — a pool scan, a second symbol table — can use the same walk.
pub fn list_hives_from(profile: &WindowsProfile, head: u64) -> Result<HiveListing, RegistryError> {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );

    let mut listing = HiveListing {
        head,
        hives: Vec::new(),
        rejected: Vec::new(),
        incomplete: Vec::new(),
    };
    let mut seen: HashSet<u64> = HashSet::new();

    let forward_stop = walk(
        &reader,
        head,
        WalkDirection::Forward,
        &mut seen,
        &mut listing,
    )?;
    if !forward_stop.is_complete() {
        note_stop(&mut listing, &forward_stop, WalkDirection::Forward);
        // The list is doubly linked, so the hives past the break are still
        // reachable from the other end. Anything already seen is skipped, which
        // is what makes the two walks meet in the middle rather than duplicate.
        let backward_stop = walk(
            &reader,
            head,
            WalkDirection::Backward,
            &mut seen,
            &mut listing,
        )?;
        note_stop(&mut listing, &backward_stop, WalkDirection::Backward);
    }

    Ok(listing)
}

/// Record why a walk ended, when it did not end by coming back to the head.
fn note_stop(listing: &mut HiveListing, stop: &ListStop, direction: WalkDirection) {
    if let Some(incomplete) = stop.incomplete() {
        listing.incomplete.push(Incomplete::new(
            incomplete.reason,
            format!(
                "walking the hive list {}: {}",
                direction.as_str(),
                incomplete.detail
            ),
        ));
    }
}

/// One pass over the list in one direction.
fn walk(
    reader: &StructReader,
    head: u64,
    direction: WalkDirection,
    seen: &mut HashSet<u64>,
    listing: &mut HiveListing,
) -> Result<ListStop, RegistryError> {
    let spec = ListSpec::new("_LIST_ENTRY", direction.member())
        .in_container("_CMHIVE", "HiveList")
        .with_max_entries(MAX_HIVES);
    let walk = reader.walk_list(head, &spec)?;
    let (entries, stop) = walk.walk_to_end();

    for entry in entries {
        let address = entry.address();
        if !seen.insert(address) {
            continue;
        }
        match validate(&entry) {
            Ok(()) => listing.hives.push(HiveRecord {
                address,
                name: hive_name(&entry),
                direction,
            }),
            Err(err) => listing.rejected.push(RejectedHive {
                address,
                reason: err.to_string(),
                direction,
            }),
        }
    }
    Ok(stop)
}

/// Whether a candidate really is a hive.
fn validate(cmhive: &Obj) -> Result<(), RegistryError> {
    let hive = cmhive.embedded("Hive")?;
    let signature = unsigned_member(&hive, "Signature")?;
    if signature != HIVE_SIGNATURE {
        return Err(RegistryError::HiveSignature {
            address: cmhive.address(),
            found: signature,
            expected: HIVE_SIGNATURE,
        });
    }
    Ok(())
}

/// The first populated path member of a `_CMHIVE`, or why there is not one.
///
/// The order is upstream's and it is the right one: the full device path first,
/// because it is the most specific, then the name the loader was given, then
/// the registry mount point.
fn hive_name(cmhive: &Obj) -> HiveName {
    let candidates = [
        HiveNameSource::FileFullPath,
        HiveNameSource::FileUserName,
        HiveNameSource::HiveRootPath,
    ];
    let mut considered = 0usize;
    let mut failure: Option<Incomplete> = None;

    for source in candidates {
        if !cmhive.has_member(source.as_str()) {
            continue;
        }
        considered += 1;
        match unicode_string(cmhive, source.as_str()) {
            Ok(Some((text, well_formed))) => {
                return HiveName::Path {
                    text,
                    source,
                    well_formed,
                }
            }
            Ok(None) => {}
            Err(err) => {
                failure.get_or_insert_with(|| err.to_incomplete());
            }
        }
    }

    if considered == 0 {
        return HiveName::Unavailable(Incomplete::new(
            IncompleteReason::UnresolvedStructure,
            "this build's _CMHIVE declares none of FileFullPath, FileUserName or HiveRootPath, so \
             the hive cannot be named"
                .to_string(),
        ));
    }
    match failure {
        Some(incomplete) => HiveName::Unavailable(incomplete),
        // Every path member this build has was readable and empty. The hive
        // genuinely has no backing file.
        None => HiveName::NoBackingFile,
    }
}

/// Read a `_UNICODE_STRING` member, distinguishing "empty" from "unreadable".
///
/// `Ok(None)` means the string is genuinely zero-length. An unreadable buffer
/// is an error, never an empty string: a hive whose name is in a paged-out
/// allocation would otherwise be reported as a hive with no name, which is a
/// different hive.
fn unicode_string(obj: &Obj, path: &str) -> Result<Option<(String, bool)>, RegistryError> {
    let length = unsigned_member(obj, &format!("{path}.Length"))?;
    if length == 0 {
        return Ok(None);
    }
    let buffer = obj.pointer(&format!("{path}.Buffer"))?;
    if buffer == 0 {
        return Err(RegistryError::Malformed(format!(
            "'{}.{path}' declares {length} byte(s) of text and a null buffer",
            obj.type_name()
        )));
    }
    let bytes = obj.reader().read_bytes(buffer, length)?;
    Ok(Some(decode_utf16le(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::test_support::{
        broken_forward_profile, xp_profile, XP_CMHIVE, XP_JUNK_CMHIVE, XP_UNNAMED_CMHIVE,
    };

    #[test]
    fn the_walk_starts_at_the_kernel_base_plus_the_symbols_address() {
        let profile = xp_profile();
        let listing = list_hives(&profile).expect("the fixture declares CmpHiveListHead");
        let expected =
            profile.kernel_base.value + profile.symbols.symbol_address(HIVE_LIST_HEAD).unwrap();
        assert_eq!(listing.head, expected);
    }

    #[test]
    fn every_hive_on_the_list_is_reported_with_its_address_and_its_path() {
        let profile = xp_profile();
        let listing = list_hives(&profile).unwrap();
        let addresses: Vec<u64> = listing.hives.iter().map(|hive| hive.address).collect();
        assert_eq!(addresses, vec![XP_CMHIVE, XP_UNNAMED_CMHIVE]);

        let named = &listing.hives[0];
        assert_eq!(
            named.name.path(),
            Some("\\Device\\HarddiskVolume1\\Documents and Settings\\Sarah\\NTUSER.DAT")
        );
        assert_eq!(named.name.file_name(), Some("NTUSER.DAT"));
        assert_eq!(named.direction, WalkDirection::Forward);
        match &named.name {
            HiveName::Path { source, .. } => assert_eq!(*source, HiveNameSource::FileFullPath),
            other => panic!("expected a path, got {other:?}"),
        }
    }

    #[test]
    fn a_hive_with_no_backing_file_is_marked_and_not_given_an_empty_name() {
        // The volatile hives are like this. An empty string here is
        // indistinguishable from a name we failed to read.
        let profile = xp_profile();
        let listing = list_hives(&profile).unwrap();
        let unnamed = listing
            .hives
            .iter()
            .find(|hive| hive.address == XP_UNNAMED_CMHIVE)
            .expect("the unnamed hive is on the list");
        assert_eq!(unnamed.name, HiveName::NoBackingFile);
        assert_eq!(unnamed.name.path(), None);
        assert_eq!(unnamed.name.to_json()["kind"], "no_backing_file");
    }

    #[test]
    fn a_structure_on_the_list_that_is_not_a_hive_is_rejected_and_still_reported() {
        // Dropping it would hide a spliced list; listing it as a hive would
        // hand a bogus address to everything downstream.
        let profile = xp_profile();
        let listing = list_hives(&profile).unwrap();
        assert_eq!(listing.rejected.len(), 1);
        assert_eq!(listing.rejected[0].address, XP_JUNK_CMHIVE);
        assert!(listing.rejected[0].reason.contains("0xbee0bee0"));
        assert!(
            !listing.is_complete(),
            "a list with a rejected entry is not a clean list"
        );
        assert!(
            !listing
                .hives
                .iter()
                .any(|hive| hive.address == XP_JUNK_CMHIVE),
            "a rejected structure must not appear as a hive"
        );
    }

    #[test]
    fn a_forward_walk_that_breaks_is_finished_from_the_other_end_of_the_list() {
        // The hives past an unreadable _CMHIVE are still evidence, and the list
        // is doubly linked, so they are still reachable. What must not happen is
        // that they vanish and the count looks plausible.
        let profile = broken_forward_profile();
        let listing = list_hives(&profile).unwrap();

        assert!(
            listing
                .hives
                .iter()
                .any(|h| h.direction == WalkDirection::Backward),
            "the hive past the break must be recovered backwards"
        );
        assert!(
            !listing.incomplete.is_empty(),
            "and the break itself must be declared"
        );
        assert!(
            listing.incomplete[0].detail.contains("forward"),
            "{:?}",
            listing.incomplete
        );
        assert!(!listing.is_complete());
    }

    #[test]
    fn a_hive_reached_from_both_directions_is_reported_once() {
        let profile = broken_forward_profile();
        let listing = list_hives(&profile).unwrap();
        let mut addresses: Vec<u64> = listing.hives.iter().map(|hive| hive.address).collect();
        let count = addresses.len();
        addresses.sort_unstable();
        addresses.dedup();
        assert_eq!(addresses.len(), count, "no hive may be listed twice");
    }

    #[test]
    fn a_table_with_no_hive_list_symbol_fails_closed_rather_than_scanning() {
        let profile = crate::registry::test_support::win8_profile();
        // The 64-bit fixture deliberately declares no CmpHiveListHead, so the
        // walk cannot start and says which symbol it needed.
        let err = list_hives(&profile).expect_err("there is no head to walk from");
        assert!(err.to_string().contains(HIVE_LIST_HEAD), "{err}");
    }

    #[test]
    fn the_listing_serialises_everything_a_report_needs() {
        let profile = xp_profile();
        let listing = list_hives(&profile).unwrap();
        let json = listing.to_json();
        assert_eq!(json["count"], 2);
        assert_eq!(json["complete"], false);
        assert_eq!(json["hives"][0]["address"], XP_CMHIVE);
        assert_eq!(json["hives"][1]["name"]["kind"], "no_backing_file");
        assert_eq!(json["rejected"][0]["address"], XP_JUNK_CMHIVE);
    }

    #[test]
    fn a_name_filter_matches_case_insensitively_on_the_path() {
        let profile = xp_profile();
        let listing = list_hives(&profile).unwrap();
        assert_eq!(listing.matching("ntuser.dat").len(), 1);
        assert_eq!(listing.matching("SOFTWARE").len(), 0);
    }
}
