#![forbid(unsafe_code)]
//! NTFS `$Secure:$SDS` security-descriptor parser (MFTECmd `--sds` parity).
//!
//! # What the artifact is
//!
//! NTFS 3.0 stopped storing a security descriptor inside every MFT record.
//! Instead each record's `$STANDARD_INFORMATION` carries a 4-byte `security_id`
//! that indexes a single volume-wide store: the `$SDS` stream of the `$Secure`
//! metadata file (MFT record 9). Decoding `$SDS` therefore recovers, for the
//! whole volume in one pass:
//!
//! - the **owner** and **primary group** SID of every file and directory,
//! - the **DACL** — which principals were allowed or denied which access, and
//! - the **SACL** — what was audited, plus the mandatory integrity label.
//!
//! Descriptors are never deleted from `$SDS`, only appended, so the owner of a
//! **deleted** file is still recoverable as long as its MFT record retains the
//! `security_id`.
//!
//! # What an examiner learns
//!
//! Ownership attribution ("which account created this webshell"), access-control
//! tampering (`Everyone: Full Control`, broken inheritance, a taken-over owner),
//! and the integrity level that marks content written by a sandboxed or
//! downloaded process.
//!
//! # How this module is reached
//!
//! `seance_plugin_mft` emits every named `$DATA` stream of every MFT record as
//! its own `FileEntry` artifact with a data source attached, so on any NTFS
//! volume ingest the `$Secure:$SDS` stream arrives here as a `FileEntry` with
//! `stream_name == "$SDS"` and `parent_file == "$Secure"`. A stream extracted
//! by hand (MFTECmd, `icat`) arrives as a `FileEntry`, `SystemArtifact` or
//! `RawEvidence` named `$SDS`, and is handled the same way. Nothing else is
//! accepted: another file's alternate data stream that happens to be called
//! `$SDS` is not the descriptor store and is left alone.
//!
//! # Fail-closed behaviour
//!
//! - A stream that matches the gate but has no data source is not a silent skip
//!   and not a decline: it produces the store record, stamped
//!   `content_incomplete` / `inventory_incomplete` with the producer's reason
//!   (or `no_data_source`), and no descriptors.
//! - A descriptor that cannot be decoded is still emitted, carrying
//!   `security_descriptor_error` and its `security_id`, so the id reads as
//!   *unresolvable* rather than disappearing from the store.
//! - Every cap and short read reaches the artifact (`read_incomplete`,
//!   `entry_cap_reached`, `oversize_entries_refused`, `dacl_truncated`, …), and
//!   the store record carries a single `store_listing_incomplete` boolean so a
//!   partial listing can never be read as the whole store — and, since those
//!   are this module's own words, the shared `inventory_incomplete` (and, for a
//!   short read, `content_incomplete`) pair with a `_detail` sentence.
//! - A descriptor recovered from the 256 KiB mirror is labelled
//!   `recovered_from_mirror` with the primary copy's offset and failure.
//! - No `TimelineEvent` is produced: a security descriptor carries no timestamp
//!   of its own, and inventing one would fabricate evidence.

pub mod sds;
pub mod wellknown;

#[cfg(test)]
mod sds_tests;
#[cfg(test)]
mod tests;

use sds::{Ace, AclPresence, EntryOrigin, SdsEntry, SdsScan, SecurityDescriptor};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{read_capped, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Map, Value};
use tracing::{debug, info, warn};
use wellknown::{
    ace_effect, ace_flag_names, ace_type_name, control_flag_names, describe_access_mask, ObjectKind,
};

/// Module id used for registration and stamped on every record.
pub const MODULE_ID: &str = "plugin.windows.secure_sds";

/// `ParsedRecord` discriminator for one unique security descriptor.
pub const RECORD_TYPE_DESCRIPTOR: &str = "NtfsSecurityDescriptor";

/// `ParsedRecord` discriminator for the per-stream provenance summary.
pub const RECORD_TYPE_STORE: &str = "NtfsSecurityDescriptorStore";

/// Hostile-input ceiling on the `$SDS` bytes pulled into memory. A real store
/// is kilobytes to a few megabytes; 64 MiB is a ceiling, not an expectation,
/// and reaching it sets `read_incomplete` on the store record.
const MAX_SDS_BYTES: u64 = 64 * 1024 * 1024;

/// `INHERITED_ACE`: the ACE was propagated from the parent container rather
/// than set on this object.
const ACE_FLAG_INHERITED: u8 = 0x10;

/// Parser for the NTFS `$Secure:$SDS` security-descriptor store.
///
/// Registered as `plugin.windows.secure_sds`. Produces one
/// [`RECORD_TYPE_DESCRIPTOR`] record per unique `security_id` plus one
/// [`RECORD_TYPE_STORE`] record describing the scan itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct SecureSdsParser;

impl SecureSdsParser {
    /// Construct the parser. It holds no state and is cheap to clone.
    pub fn new() -> Self {
        Self
    }
}

impl ForensicsModule for SecureSdsParser {
    fn id(&self) -> &str {
        MODULE_ID
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        // The $SDS stream reaches us as an alternate data stream FileEntry from
        // the MFT parser, or as a hand-extracted file in one of the other two
        // shapes. FileSystem artifacts are deliberately absent: locating record
        // 9 in a raw volume is the MFT parser's job, and duplicating it here
        // would give two answers that could disagree.
        vec![
            ArtifactType::FileEntry,
            ArtifactType::SystemArtifact,
            ArtifactType::RawEvidence,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let Some(source) = sds_source_label(artifact) else {
            return Ok(Vec::new());
        };

        // A matching stream with no readable bytes must not pass silently:
        // returning nothing would look identical to "this volume has no
        // descriptors", which is the one thing $Secure can never be. Nor is it
        // refused as a wrong input — `InvalidInputFormat` is folded into the
        // processing log's "declined" row beside files this module was never
        // for (HUNT-178). It is the store, unread, and the store record says
        // so in the shared vocabulary, with the producer's reason when it gave
        // one (a bare `$MFT` carries `volume_not_in_evidence`).
        let Some(data) = artifact.data.as_ref() else {
            let cause = if artifact
                .metadata
                .get("volume_not_in_evidence")
                .and_then(|v| v.as_bool())
                == Some(true)
            {
                "volume_not_in_evidence"
            } else {
                "no_data_source"
            };
            // The shared pairs carry a word the census and the frontend know;
            // the cause is this record's own `read_incomplete`.
            let reason = upstream_incomplete_reason(artifact)
                .and_then(IncompleteReason::from_str)
                .unwrap_or(IncompleteReason::UnresolvedStructure)
                .as_str();
            warn!(
                "$SDS {}: the descriptor store has no data source ({}); none of its \
                 descriptors can be read",
                source, cause
            );
            return Ok(vec![unread_store_record(artifact, &source, reason, cause)]);
        };

        let declared_size = data.size();
        let bytes = read_capped(data.as_ref(), MAX_SDS_BYTES);
        let read_incomplete = if (bytes.len() as u64) < declared_size {
            Some(if declared_size > MAX_SDS_BYTES {
                IncompleteReason::CapReached
            } else {
                IncompleteReason::ShortRead
            })
        } else {
            None
        };
        if let Some(reason) = read_incomplete {
            warn!(
                "$SDS {}: read {} of {} bytes ({}); descriptors past that point are not in this scan",
                source,
                bytes.len(),
                declared_size,
                reason.as_str()
            );
        }

        let scan = sds::parse_sds(&bytes);
        info!(
            "$SDS {}: {} unique security descriptor(s), {} duplicate copies, {} mirror \
             recoveries, {} undecodable",
            source,
            scan.entries.len(),
            scan.duplicate_copies,
            scan.mirror_recoveries,
            scan.failed_entries
        );
        if scan.entry_cap_reached {
            warn!(
                "$SDS {}: stopped at the {}-entry cap; the store holds more descriptors \
                 than were extracted",
                source,
                sds::MAX_SDS_ENTRIES
            );
        }
        if scan.oversize_entries > 0 {
            warn!(
                "$SDS {}: {} entry header(s) declared more than the {}-byte ceiling and \
                 were refused; those security ids are absent from this listing",
                source,
                scan.oversize_entries,
                sds::MAX_SDS_ENTRY_SIZE
            );
        }

        let mut produced = Vec::with_capacity(scan.entries.len() + 1);
        produced.push(store_record(
            artifact,
            &source,
            declared_size,
            bytes.len(),
            read_incomplete,
            &scan,
        ));
        for entry in &scan.entries {
            produced.push(descriptor_record(artifact, &source, entry));
        }
        debug!(
            "$SDS {}: emitted {} artifact(s) from {} bytes",
            source,
            produced.len(),
            bytes.len()
        );
        Ok(produced)
    }
}

/// Read a string field from artifact metadata, or `""` when it is absent or not
/// a string. Only used for gating, never for values written to a record.
fn meta_str<'a>(meta: &'a Value, key: &str) -> &'a str {
    meta.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

/// Last path component, treating both separators as delimiters. The stream
/// suffix (`…:$SDS`) is deliberately preserved.
fn basename(value: &str) -> String {
    value
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(value)
        .to_ascii_lowercase()
}

/// Decide whether this artifact is the `$Secure:$SDS` stream, and return a
/// human label for it.
///
/// The gate is deliberately narrow. A user file may legitimately carry an
/// alternate data stream named `$SDS`; parsing that as the descriptor store
/// would attribute invented owners and ACLs to real files, so a stream is
/// accepted only when it belongs to `$Secure` or was extracted under a name
/// that identifies it as the store.
fn sds_source_label(artifact: &Artifact) -> Option<String> {
    let meta = &artifact.metadata;

    if meta.get("is_directory").and_then(|v| v.as_bool()) == Some(true) {
        return None;
    }

    let name = match meta_str(meta, "name") {
        "" => meta_str(meta, "file_name"),
        n => n,
    };
    let path = match meta_str(meta, "path") {
        "" => meta_str(meta, "source_path"),
        p => p,
    };
    let label = || {
        if path.is_empty() {
            name.to_string()
        } else {
            path.to_string()
        }
    };

    // The MFT parser's alternate-data-stream FileEntry: name "$Secure:$SDS",
    // stream_name "$SDS", parent_file "$Secure".
    if meta_str(meta, "stream_name").eq_ignore_ascii_case("$SDS") {
        let owned_by_secure = meta_str(meta, "parent_file").eq_ignore_ascii_case("$Secure")
            || basename(name).starts_with("$secure:")
            || basename(path).starts_with("$secure:");
        return owned_by_secure.then(label);
    }

    // A stream extracted to a standalone file. MFTECmd and icat-style exports
    // use these names; anything else is not treated as the store.
    const EXTRACTED_NAMES: [&str; 4] = ["$sds", "$secure:$sds", "$secure_$sds", "$secure.$sds"];
    for candidate in [basename(name), basename(path)] {
        if EXTRACTED_NAMES.contains(&candidate.as_str()) {
            return Some(label());
        }
    }
    None
}

/// Build the per-stream provenance record.
///
/// This record exists so that "the volume has 412 descriptors" and "we stopped
/// after 412 because a cap was hit" can never look the same, and so that a
/// stream that decoded to nothing still leaves proof the store was examined.
fn store_record(
    parent: &Artifact,
    source: &str,
    declared_size: u64,
    bytes_scanned: usize,
    read_incomplete: Option<IncompleteReason>,
    scan: &SdsScan,
) -> Artifact {
    let mut m = Map::new();
    m.insert("type".into(), json!(RECORD_TYPE_STORE));
    m.insert("subtype".into(), json!("ntfs_secure_sds_store"));
    m.insert("source_module".into(), json!(MODULE_ID));
    m.insert("name".into(), json!("$Secure:$SDS descriptor store"));
    m.insert("source_stream".into(), json!(source));
    m.insert("stream_size_bytes".into(), json!(declared_size));
    m.insert("bytes_scanned".into(), json!(bytes_scanned));
    m.insert(
        "security_block_size_bytes".into(),
        json!(sds::SDS_BLOCK_SIZE),
    );
    m.insert("unique_security_ids".into(), json!(scan.entries.len()));
    m.insert("duplicate_copies".into(), json!(scan.duplicate_copies));
    m.insert("mirror_recoveries".into(), json!(scan.mirror_recoveries));
    m.insert("undecodable_descriptors".into(), json!(scan.failed_entries));
    m.insert(
        "entries_past_end_of_stream".into(),
        json!(scan.entries_past_end),
    );
    m.insert("entry_cap_reached".into(), json!(scan.entry_cap_reached));
    m.insert(
        "oversize_entries_refused".into(),
        json!(scan.oversize_entries),
    );
    if scan.oversize_entries > 0 {
        m.insert(
            "oversize_entries_note".into(),
            json!(format!(
                "{} entry header(s) declared more than the {}-byte ceiling this parser \
                 accepts and were refused rather than read. Those security ids are NOT in \
                 this listing; their absence is a limit of this scan, not of the volume.",
                scan.oversize_entries,
                sds::MAX_SDS_ENTRY_SIZE
            )),
        );
    }
    if let Some(reason) = read_incomplete {
        m.insert("read_incomplete".into(), json!(reason.as_str()));
    }
    // One boolean an examiner (and the UI) can read without re-deriving it from
    // three separate counters.
    m.insert(
        "store_listing_incomplete".into(),
        json!(read_incomplete.is_some() || scan.incomplete()),
    );
    // The same facts in the shared vocabulary, which is what the frontend and
    // the incompleteness census read; the two keys above are this module's own
    // and nothing outside it looks at them (HUNT-178). A short read is a
    // content gap AND, because of it, a listing gap; a cap or a refused entry
    // leaves the bytes whole and only the listing short.
    if let Some(reason) = read_incomplete {
        stamp_pair(
            &mut m,
            "content",
            reason.as_str(),
            &format!(
                "{bytes_scanned} of the stream's {declared_size} bytes were read; the \
                 descriptors past that point are not in this scan"
            ),
        );
    }
    if read_incomplete.is_some() || scan.incomplete() {
        let reason = match read_incomplete {
            Some(r) => r.as_str(),
            None => IncompleteReason::CapReached.as_str(),
        };
        stamp_pair(
            &mut m,
            "inventory",
            reason,
            &format!(
                "This listing of $SDS security descriptors is not the whole store ({} \
                 unique id(s) listed; entry cap reached: {}; {} entry header(s) refused as \
                 oversize; {} entry(ies) past the end of the stream{}). A security id \
                 absent from it is not shown to be absent from the volume",
                scan.entries.len(),
                scan.entry_cap_reached,
                scan.oversize_entries,
                scan.entries_past_end,
                if read_incomplete.is_some() {
                    "; the stream was not read in full"
                } else {
                    ""
                },
            ),
        );
    }

    let mut short_desc = format!(
        "$SDS: {} unique security descriptor(s) from {} bytes",
        scan.entries.len(),
        bytes_scanned
    );
    if scan.mirror_recoveries > 0 {
        short_desc.push_str(&format!(
            "; {} recovered from the 256 KiB mirror",
            scan.mirror_recoveries
        ));
    }
    if scan.failed_entries > 0 {
        short_desc.push_str(&format!("; {} undecodable", scan.failed_entries));
    }
    if scan.oversize_entries > 0 {
        short_desc.push_str(&format!(
            "; {} entry header(s) refused as oversize",
            scan.oversize_entries
        ));
    }
    if read_incomplete.is_some() || scan.incomplete() {
        short_desc.push_str("; INCOMPLETE - not the whole store");
    }
    m.insert("short_desc".into(), json!(short_desc));

    Artifact::new(
        parent.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(m),
    )
    .with_parent(parent.id)
}

/// Stamp one scope of the shared incompleteness vocabulary
/// (`<scope>_incomplete`, `_reason`, `_detail`).
fn stamp_pair(m: &mut Map<String, Value>, scope: &str, reason: &str, detail: &str) {
    m.insert(format!("{scope}_incomplete"), json!(true));
    m.insert(format!("{scope}_incomplete_reason"), json!(reason));
    m.insert(format!("{scope}_incomplete_detail"), json!(detail));
}

/// The reason the producer stamped on the stream itself, when it said the
/// stream's content is incomplete.
fn upstream_incomplete_reason(artifact: &Artifact) -> Option<&str> {
    let m = &artifact.metadata;
    if m.get("content_incomplete").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    m.get("content_incomplete_reason").and_then(|v| v.as_str())
}

/// The store record for a `$SDS` stream that was identified and could not be
/// read at all: no descriptors, and a record that says why rather than an
/// empty result that reads as "this volume has none".
fn unread_store_record(parent: &Artifact, source: &str, reason: &str, cause: &str) -> Artifact {
    let mut m = Map::new();
    m.insert("type".into(), json!(RECORD_TYPE_STORE));
    m.insert("subtype".into(), json!("ntfs_secure_sds_store"));
    m.insert("source_module".into(), json!(MODULE_ID));
    m.insert("name".into(), json!("$Secure:$SDS descriptor store"));
    m.insert("source_stream".into(), json!(source));
    if let Some(size) = parent.metadata.get("size").and_then(|v| v.as_u64()) {
        m.insert("stream_size_bytes".into(), json!(size));
    }
    m.insert("bytes_scanned".into(), json!(0));
    m.insert("unique_security_ids".into(), json!(0));
    m.insert("read_incomplete".into(), json!(cause));
    m.insert("store_listing_incomplete".into(), json!(true));
    let detail = format!(
        "The $SDS security descriptor store ({source}) was identified but has no readable \
         content ({cause}), so none of its descriptors were read: the owner and ACL of every \
         file on this volume are unknown to this case, not absent from it"
    );
    stamp_pair(&mut m, "content", reason, &detail);
    stamp_pair(&mut m, "inventory", reason, &detail);
    m.insert(
        "short_desc".into(),
        json!(format!(
            "$SDS: NOT READ ({cause}) - no descriptors were examined"
        )),
    );
    Artifact::new(
        parent.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(m),
    )
    .with_parent(parent.id)
}

/// Build one record for a unique `security_id`.
fn descriptor_record(parent: &Artifact, source: &str, entry: &SdsEntry) -> Artifact {
    let mut m = Map::new();
    m.insert("type".into(), json!(RECORD_TYPE_DESCRIPTOR));
    m.insert("subtype".into(), json!("ntfs_security_descriptor"));
    m.insert("source_module".into(), json!(MODULE_ID));
    m.insert("source_stream".into(), json!(source));
    m.insert(
        "name".into(),
        json!(format!("Security id {}", entry.security_id)),
    );
    m.insert("security_id".into(), json!(entry.security_id));
    m.insert("descriptor_hash".into(), json!(entry.hash));
    m.insert("sds_offset".into(), json!(entry.stream_offset));
    m.insert("sds_declared_offset".into(), json!(entry.declared_offset));
    m.insert("entry_size".into(), json!(entry.entry_size));
    if entry.offset_mismatch {
        // The store's own bookkeeping disagrees with where the entry sits. The
        // descriptor is still decoded, but the disagreement is evidence of
        // damage or manipulation and must be visible.
        m.insert("sds_offset_mismatch".into(), json!(true));
    }

    match &entry.origin {
        EntryOrigin::Primary => {
            m.insert("recovered_from_mirror".into(), json!(false));
        }
        EntryOrigin::MirrorRecovered {
            primary_offset,
            mirror_offset,
            primary_error,
        } => {
            m.insert("recovered_from_mirror".into(), json!(true));
            m.insert("mirror_offset".into(), json!(mirror_offset));
            m.insert("primary_copy_offset".into(), json!(primary_offset));
            m.insert("primary_copy_error".into(), json!(primary_error));
        }
    }

    match &entry.descriptor {
        Ok(descriptor) => add_descriptor_fields(&mut m, entry, descriptor),
        Err(e) => {
            m.insert("security_descriptor_error".into(), json!(e.to_string()));
            m.insert(
                "short_desc".into(),
                json!(format!(
                    "Security id {}: descriptor could not be decoded ({e})",
                    entry.security_id
                )),
            );
        }
    }

    Artifact::new(
        parent.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(m),
    )
    .with_parent(parent.id)
}

/// Stamp a decoded descriptor onto the record metadata.
fn add_descriptor_fields(m: &mut Map<String, Value>, entry: &SdsEntry, d: &SecurityDescriptor) {
    m.insert("descriptor_revision".into(), json!(d.revision));
    m.insert("control_flags".into(), json!(d.control));
    m.insert(
        "control_flags_hex".into(),
        json!(format!("0x{:04X}", d.control)),
    );
    m.insert(
        "control_flag_names".into(),
        json!(control_flag_names(d.control)),
    );

    match (&d.owner, &d.owner_error) {
        (Some(sid), _) => {
            m.insert("owner_sid".into(), json!(sid.to_string()));
            if let Some(name) = sid.friendly_name() {
                m.insert("owner_name".into(), json!(name));
            }
        }
        (None, Some(e)) => {
            m.insert("owner_error".into(), json!(e));
        }
        (None, None) => {}
    }
    match (&d.group, &d.group_error) {
        (Some(sid), _) => {
            m.insert("group_sid".into(), json!(sid.to_string()));
            if let Some(name) = sid.friendly_name() {
                m.insert("group_name".into(), json!(name));
            }
        }
        (None, Some(e)) => {
            m.insert("group_error".into(), json!(e));
        }
        (None, None) => {}
    }

    add_acl_fields(m, "dacl", &d.dacl);
    add_acl_fields(m, "sacl", &d.sacl);

    if let Some(level) = d.integrity_level() {
        m.insert("integrity_level".into(), json!(level));
    }
    m.insert("dacl_protected".into(), json!(d.dacl_protected()));
    m.insert(
        "sacl_protected".into(),
        json!(d.control & sds::SE_SACL_PROTECTED != 0),
    );
    m.insert(
        "dacl_auto_inherited".into(),
        json!(d.control & sds::SE_DACL_AUTO_INHERITED != 0),
    );
    // No DACL at all means every principal has full access — the opposite of a
    // DACL that is present and empty, which grants nobody anything.
    m.insert("no_dacl_full_access".into(), json!(d.no_dacl_full_access()));
    m.insert("descriptor_partial".into(), json!(d.partial));

    let summary = d.permission_summary();
    m.insert("permission_summary".into(), json!(summary));
    m.insert(
        "short_desc".into(),
        json!(format!("Security id {}: {summary}", entry.security_id)),
    );
}

/// Stamp one ACL (`dacl` or `sacl`) onto the record metadata.
///
/// `<prefix>_state` always says which of the four states applies, so an absent
/// ACL, a NULL ACL, an empty ACL and an unreadable ACL are distinguishable
/// downstream without re-deriving them from the control flags.
fn add_acl_fields(m: &mut Map<String, Value>, prefix: &str, presence: &AclPresence) {
    m.insert(format!("{prefix}_state"), json!(presence.state()));
    match presence {
        AclPresence::Absent | AclPresence::Null => {}
        AclPresence::Unreadable(e) => {
            m.insert(format!("{prefix}_error"), json!(e));
        }
        AclPresence::Present(acl) => {
            m.insert(format!("{prefix}_revision"), json!(acl.revision));
            m.insert(
                format!("{prefix}_declared_ace_count"),
                json!(acl.declared_ace_count),
            );
            m.insert(format!("{prefix}_ace_count"), json!(acl.aces.len()));
            let aces: Vec<Value> = acl.aces.iter().map(ace_json).collect();
            m.insert(prefix.to_string(), Value::Array(aces));
            m.insert(format!("{prefix}_truncated"), json!(acl.truncated));
            if let Some(reason) = &acl.truncation_reason {
                m.insert(format!("{prefix}_truncation_reason"), json!(reason));
            }
        }
    }
}

/// Render one ACE for the record's `dacl`/`sacl` array.
///
/// Raw `ace_type`, `flags` and `access_mask` are always present beside their
/// decoded names, so a bit the naming tables do not know about is still carried
/// to the examiner instead of being dropped.
fn ace_json(ace: &Ace) -> Value {
    let mut m = Map::new();
    m.insert("ace_type".into(), json!(ace.ace_type));
    if let Some(name) = ace_type_name(ace.ace_type) {
        m.insert("ace_type_name".into(), json!(name));
    }
    m.insert("effect".into(), json!(ace_effect(ace.ace_type)));
    m.insert("flags".into(), json!(ace.flags));
    m.insert("flag_names".into(), json!(ace_flag_names(ace.flags)));
    m.insert(
        "inherited".into(),
        json!(ace.flags & ACE_FLAG_INHERITED != 0),
    );
    m.insert("ace_size".into(), json!(ace.size));
    if let Some(mask) = ace.access_mask {
        m.insert("access_mask".into(), json!(mask));
        m.insert("access_mask_hex".into(), json!(format!("0x{mask:08X}")));
        // `$Secure:$SDS` describes files and directories, so the object kind
        // is not in doubt here. A registry key's ACL is rendered through the
        // same functions with `ObjectKind::RegistryKey`, because the low 16
        // bits mean different things on the two (§2.5).
        m.insert(
            "access_mask_desc".into(),
            json!(describe_access_mask(ObjectKind::File, mask)),
        );
        m.insert(
            "access_rights".into(),
            json!(wellknown::access_right_names(ObjectKind::File, mask)),
        );
    }
    if let Some(sid) = &ace.sid {
        m.insert("sid".into(), json!(sid.to_string()));
        if let Some(name) = sid.friendly_name() {
            m.insert("sid_name".into(), json!(name));
        }
    }
    if let Some(flags) = ace.object_flags {
        m.insert("object_flags".into(), json!(flags));
    }
    if let Some(e) = &ace.body_error {
        m.insert("ace_error".into(), json!(e));
    }
    Value::Object(m)
}
