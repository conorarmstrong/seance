//! Module tests: gating, artifact shape and the fail-closed contract.
//!
//! These exercise the path the product actually takes — `MftParser` emits the
//! `$Secure:$SDS` alternate data stream as a `FileEntry`, the orchestrator
//! routes it here, and this module turns it into browsable records — so a
//! regression that stops the plugin firing is caught here, not only in the
//! decoder tests.

use crate::sds_tests::{
    ace_bytes, acl_bytes, canonical_descriptor, descriptor_bytes, sds_entry, sid_bytes,
};
use crate::{SecureSdsParser, MODULE_ID, RECORD_TYPE_DESCRIPTOR, RECORD_TYPE_STORE};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::module::{ForensicsModule, InputCapability};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

use seance_core::test_support::TruncatedSource;

/// Metadata the MFT parser stamps on the `$Secure:$SDS` alternate data stream.
fn sds_ads_metadata() -> Value {
    serde_json::json!({
        "name": "$Secure:$SDS",
        "stream_name": "$SDS",
        "parent_file": "$Secure",
        "is_ads": true,
        "path": "/$Secure:$SDS",
        "parent_path": "/",
    })
}

fn artifact_with(metadata: Value, data: Option<Arc<dyn DataSource>>) -> Artifact {
    Artifact::new(Uuid::new_v4(), ArtifactType::FileEntry, data, metadata)
}

fn run(stream: Vec<u8>) -> Vec<Artifact> {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(stream));
    SecureSdsParser::new()
        .process(&artifact_with(sds_ads_metadata(), Some(data)))
        .expect("a readable $SDS stream must process cleanly")
}

fn records_of_type<'a>(artifacts: &'a [Artifact], record_type: &str) -> Vec<&'a Artifact> {
    artifacts
        .iter()
        .filter(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some(record_type))
        .collect()
}

/// Two descriptors laid out as NTFS writes them, the second following the first
/// on the next 16-byte boundary.
fn two_descriptor_stream() -> Vec<u8> {
    let first = canonical_descriptor();
    let everyone = sid_bytes(1, &[0]);
    let dacl = acl_bytes(2, &[ace_bytes(0x00, 0x00, 0x001F_01FF, &everyone)]);
    let second = descriptor_bytes(
        crate::sds::SE_SELF_RELATIVE | crate::sds::SE_DACL_PRESENT,
        Some(&everyone),
        None,
        None,
        Some(&dacl),
    );

    let mut stream = sds_entry(0x1111_1111, 256, 0, &first);
    let offset = stream.len() as u64;
    stream.extend_from_slice(&sds_entry(0x2222_2222, 257, offset, &second));
    stream
}

#[test]
fn the_module_identifies_itself_for_registration_and_subscribes_to_stream_inputs() {
    let parser = SecureSdsParser::new();
    assert_eq!(parser.id(), MODULE_ID);
    assert_eq!(parser.id(), "plugin.windows.secure_sds");
    assert_eq!(parser.input_capability(), InputCapability::Stream);
    let subscriptions = parser.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileEntry));
    assert!(subscriptions.contains(&ArtifactType::SystemArtifact));
    assert!(subscriptions.contains(&ArtifactType::RawEvidence));
}

#[test]
fn the_secure_sds_stream_yields_one_record_per_unique_security_id_plus_a_store_summary() {
    let produced = run(two_descriptor_stream());
    let descriptors = records_of_type(&produced, RECORD_TYPE_DESCRIPTOR);
    let stores = records_of_type(&produced, RECORD_TYPE_STORE);

    assert_eq!(descriptors.len(), 2);
    assert_eq!(stores.len(), 1);
    assert_eq!(produced.len(), 3);
    assert!(produced
        .iter()
        .all(|a| a.artifact_type == ArtifactType::ParsedRecord));

    let store = &stores[0].metadata;
    assert_eq!(store["unique_security_ids"], 2);
    assert_eq!(store["mirror_recoveries"], 0);
    assert_eq!(store["undecodable_descriptors"], 0);
    assert_eq!(store["entry_cap_reached"].as_bool(), Some(false));
    assert_eq!(store["source_module"], MODULE_ID);
    assert!(store.get("read_incomplete").is_none());
    assert_eq!(store["oversize_entries_refused"], 0);
    assert_eq!(
        store["store_listing_incomplete"].as_bool(),
        Some(false),
        "a whole store must say so, or the flag stops meaning anything"
    );
}

#[test]
fn an_entry_refused_for_its_declared_size_marks_the_store_listing_incomplete() {
    // The store holds one readable descriptor and one header whose declared
    // size this parser refuses. Reporting "1 descriptor" without saying an id
    // was refused would read as a complete inventory of the volume's owners.
    let mut stream = two_descriptor_stream();
    let refused_at = stream.len();
    stream.resize(refused_at + 4096, 0);
    stream[refused_at..refused_at + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    stream[refused_at + 4..refused_at + 8].copy_from_slice(&258u32.to_le_bytes());
    stream[refused_at + 8..refused_at + 16].copy_from_slice(&(refused_at as u64).to_le_bytes());
    stream[refused_at + 16..refused_at + 20]
        .copy_from_slice(&(crate::sds::MAX_SDS_ENTRY_SIZE + 1).to_le_bytes());

    let produced = run(stream);
    let store = &records_of_type(&produced, RECORD_TYPE_STORE)[0].metadata;

    assert_eq!(store["oversize_entries_refused"], 1);
    assert_eq!(store["store_listing_incomplete"].as_bool(), Some(true));
    assert!(store["oversize_entries_note"]
        .as_str()
        .unwrap_or_default()
        .contains("not of the volume"));
    assert!(store["short_desc"]
        .as_str()
        .unwrap_or_default()
        .contains("INCOMPLETE"));
    // The descriptors that were readable are still extracted.
    assert_eq!(records_of_type(&produced, RECORD_TYPE_DESCRIPTOR).len(), 2);
}

#[test]
fn a_record_carries_the_owner_group_dacl_and_a_readable_permission_summary() {
    let produced = run(two_descriptor_stream());
    let descriptors = records_of_type(&produced, RECORD_TYPE_DESCRIPTOR);
    let m = &descriptors[0].metadata;

    assert_eq!(m["security_id"], 256);
    assert_eq!(m["descriptor_hash"], 0x1111_1111u32);
    assert_eq!(m["sds_offset"], 0);
    assert_eq!(m["owner_sid"], "S-1-5-32-544");
    assert_eq!(m["owner_name"], "Administrators");
    assert_eq!(m["group_sid"], "S-1-5-21-1-2-3-513");
    assert_eq!(m["group_name"], "Domain Users (RID 513)");
    assert_eq!(m["dacl_state"], "present");
    assert_eq!(m["dacl_ace_count"], 4);
    assert_eq!(m["sacl_state"], "present");
    assert_eq!(m["integrity_level"], "Medium");
    assert_eq!(m["no_dacl_full_access"].as_bool(), Some(false));
    assert_eq!(m["descriptor_partial"].as_bool(), Some(false));
    assert_eq!(m["recovered_from_mirror"].as_bool(), Some(false));
    assert!(m.get("security_descriptor_error").is_none());

    let summary = m["permission_summary"]
        .as_str()
        .expect("a summary is stamped");
    assert!(summary.contains("Owner: Administrators"), "got {summary}");
    assert!(summary.contains("Integrity: Medium"), "got {summary}");

    let aces = m["dacl"].as_array().expect("the DACL is a structured list");
    assert_eq!(aces.len(), 4);
    assert_eq!(aces[0]["effect"], "allow");
    assert_eq!(aces[0]["sid"], "S-1-5-18");
    assert_eq!(aces[0]["sid_name"], "Local System");
    assert_eq!(aces[0]["access_mask"], 0x001F_01FFu32);
    assert_eq!(aces[0]["access_mask_hex"], "0x001F01FF");
    assert_eq!(aces[0]["access_mask_desc"], "Full Control (0x001F01FF)");
    assert_eq!(aces[3]["effect"], "deny");
    assert_eq!(aces[3]["sid_name"], "Guests");

    let sacl = m["sacl"].as_array().expect("the SACL is a structured list");
    assert_eq!(sacl[0]["ace_type_name"], "SYSTEM_MANDATORY_LABEL_ACE_TYPE");
}

#[test]
fn a_world_writable_descriptor_is_visible_through_its_trustee_and_mask() {
    let produced = run(two_descriptor_stream());
    let descriptors = records_of_type(&produced, RECORD_TYPE_DESCRIPTOR);
    let m = &descriptors[1].metadata;
    assert_eq!(m["security_id"], 257);
    assert_eq!(m["owner_sid"], "S-1-1-0");
    assert_eq!(m["owner_name"], "Everyone");
    let aces = m["dacl"].as_array().expect("the DACL is a structured list");
    assert_eq!(aces[0]["sid_name"], "Everyone");
    assert_eq!(aces[0]["access_mask_desc"], "Full Control (0x001F01FF)");
}

#[test]
fn every_produced_record_keeps_the_case_and_parent_of_the_stream_it_came_from() {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(two_descriptor_stream()));
    let input = artifact_with(sds_ads_metadata(), Some(data));
    let produced = SecureSdsParser::new()
        .process(&input)
        .expect("the stream must process cleanly");

    assert!(!produced.is_empty());
    for record in &produced {
        assert_eq!(record.case_id, input.case_id, "chain of custody: same case");
        assert_eq!(
            record.parent_id,
            Some(input.id),
            "chain of custody: parented to the $SDS stream"
        );
    }
}

#[test]
fn no_timeline_events_are_emitted_because_a_descriptor_carries_no_timestamp() {
    let produced = run(two_descriptor_stream());
    assert!(
        !produced
            .iter()
            .any(|a| a.artifact_type == ArtifactType::TimelineEvent),
        "a security descriptor has no time of its own; inventing one would fabricate evidence"
    );
}

#[test]
fn an_undecodable_descriptor_is_still_reported_with_its_security_id_and_the_reason() {
    let mut damaged = canonical_descriptor();
    damaged[0] = 0x5A; // an impossible descriptor revision
    let produced = run(sds_entry(9, 4538, 0, &damaged));

    let descriptors = records_of_type(&produced, RECORD_TYPE_DESCRIPTOR);
    assert_eq!(descriptors.len(), 1, "the id must not silently disappear");
    let m = &descriptors[0].metadata;
    assert_eq!(m["security_id"], 4538);
    let error = m["security_descriptor_error"]
        .as_str()
        .expect("the failure must be named on the record");
    assert!(error.contains("revision"), "got {error}");
    assert!(
        m.get("owner_sid").is_none(),
        "a failed descriptor must never carry a fabricated owner"
    );

    let store = &records_of_type(&produced, RECORD_TYPE_STORE)[0].metadata;
    assert_eq!(store["undecodable_descriptors"], 1);
    assert_eq!(store["unique_security_ids"], 1);
}

#[test]
fn a_descriptor_recovered_from_the_mirror_says_so_on_the_record() {
    let good = canonical_descriptor();
    let mut damaged = good.clone();
    damaged[0] = 0x5A;

    let mut stream = sds_entry(0xC0FF_EE00, 512, 0, &damaged);
    stream.resize(crate::sds::SDS_BLOCK_SIZE, 0);
    stream.extend_from_slice(&sds_entry(0xC0FF_EE00, 512, 0, &good));

    let produced = run(stream);
    let descriptors = records_of_type(&produced, RECORD_TYPE_DESCRIPTOR);
    assert_eq!(descriptors.len(), 1);
    let m = &descriptors[0].metadata;
    assert_eq!(m["recovered_from_mirror"].as_bool(), Some(true));
    assert_eq!(m["mirror_offset"], crate::sds::SDS_BLOCK_SIZE as u64);
    assert_eq!(m["primary_copy_offset"], 0);
    assert!(m["primary_copy_error"]
        .as_str()
        .unwrap_or_default()
        .contains("revision"));
    assert_eq!(
        m["owner_name"], "Administrators",
        "the recovered descriptor must still decode fully"
    );

    let store = &records_of_type(&produced, RECORD_TYPE_STORE)[0].metadata;
    assert_eq!(store["mirror_recoveries"], 1);
    assert!(store["short_desc"]
        .as_str()
        .unwrap_or_default()
        .contains("recovered from the 256 KiB mirror"));
}

#[test]
fn an_empty_stream_still_records_that_the_store_was_examined() {
    let produced = run(Vec::new());
    let stores = records_of_type(&produced, RECORD_TYPE_STORE);
    assert_eq!(produced.len(), 1);
    assert_eq!(stores[0].metadata["unique_security_ids"], 0);
    assert_eq!(stores[0].metadata["bytes_scanned"], 0);
}

#[test]
fn a_short_read_marks_the_store_incomplete_instead_of_reporting_a_partial_scan_as_whole() {
    let data: Arc<dyn DataSource> = Arc::new(TruncatedSource::halved(two_descriptor_stream()));
    let produced = SecureSdsParser::new()
        .process(&artifact_with(sds_ads_metadata(), Some(data)))
        .expect("a short read degrades, it does not fail the pipeline");

    let store = &records_of_type(&produced, RECORD_TYPE_STORE)[0].metadata;
    assert_eq!(store["read_incomplete"], "short_read");
    assert!(store["short_desc"]
        .as_str()
        .unwrap_or_default()
        .contains("INCOMPLETE"));
    // The descriptors that were readable are still extracted.
    assert_eq!(records_of_type(&produced, RECORD_TYPE_DESCRIPTOR).len(), 2);
}

/// HUNT-178: the right input with nothing to read was refused with
/// `InvalidInputFormat`, which the orchestrator logs at debug and folds into
/// "declined the input" — the same row as a file this module was never for.
/// It is the store, and it could not be read: that is published as the store
/// record, stamped in the shared vocabulary, carrying the producer's own reason
/// when it gave one (a bare `$MFT` has no volume to read the stream from).
#[test]
fn a_matching_stream_with_no_data_source_is_reported_as_unread_not_declined() {
    let produced = SecureSdsParser::new()
        .process(&artifact_with(sds_ads_metadata(), None))
        .expect("the store was identified; that it could not be read is a result");
    let stores = records_of_type(&produced, RECORD_TYPE_STORE);
    assert_eq!(produced.len(), 1);
    let store = &stores[0].metadata;
    assert_eq!(store["content_incomplete"], true);
    assert_eq!(store["content_incomplete_reason"], "unresolved_structure");
    assert_eq!(store["read_incomplete"], "no_data_source");
    assert_eq!(store["inventory_incomplete"], true);
    assert!(store["inventory_incomplete_detail"]
        .as_str()
        .is_some_and(|d| d.contains("$SDS")));
    assert_eq!(store["store_listing_incomplete"], true);

    let mut from_bare_mft = sds_ads_metadata();
    from_bare_mft["content_incomplete"] = serde_json::json!(true);
    from_bare_mft["content_incomplete_reason"] = serde_json::json!("unresolved_structure");
    from_bare_mft["volume_not_in_evidence"] = serde_json::json!(true);
    let produced = SecureSdsParser::new()
        .process(&artifact_with(from_bare_mft, None))
        .expect("processed");
    let store = &records_of_type(&produced, RECORD_TYPE_STORE)[0].metadata;
    assert_eq!(store["content_incomplete_reason"], "unresolved_structure");
    assert_eq!(store["read_incomplete"], "volume_not_in_evidence");
}

/// HUNT-178: `read_incomplete` and `store_listing_incomplete` are this
/// module's own words; the frontend and the census read only the shared pair.
/// A short read must be stamped as both — the bytes, and so the listing.
#[test]
fn a_short_read_is_stamped_in_the_shared_incompleteness_vocabulary() {
    let data: Arc<dyn DataSource> = Arc::new(TruncatedSource::halved(two_descriptor_stream()));
    let produced = SecureSdsParser::new()
        .process(&artifact_with(sds_ads_metadata(), Some(data)))
        .expect("processed");
    let store = &records_of_type(&produced, RECORD_TYPE_STORE)[0].metadata;
    assert_eq!(store["content_incomplete"], true);
    assert_eq!(store["content_incomplete_reason"], "short_read");
    assert_eq!(store["inventory_incomplete"], true);
    assert_eq!(store["inventory_incomplete_reason"], "short_read");
    assert!(store["inventory_incomplete_detail"].as_str().is_some());
}

/// A listing cut short by a refused entry (not a short read) is an inventory
/// gap only: the bytes were all read.
#[test]
fn a_refused_entry_stamps_the_listing_not_the_content() {
    let mut stream = two_descriptor_stream();
    let refused_at = stream.len();
    stream.resize(refused_at + 4096, 0);
    stream[refused_at..refused_at + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    stream[refused_at + 4..refused_at + 8].copy_from_slice(&258u32.to_le_bytes());
    stream[refused_at + 8..refused_at + 16].copy_from_slice(&(refused_at as u64).to_le_bytes());
    stream[refused_at + 16..refused_at + 20]
        .copy_from_slice(&(crate::sds::MAX_SDS_ENTRY_SIZE + 1).to_le_bytes());
    let produced = run(stream);
    let store = &records_of_type(&produced, RECORD_TYPE_STORE)[0].metadata;
    assert_eq!(store["inventory_incomplete"], true);
    assert!(store.get("content_incomplete").is_none());

    // And a whole store carries neither.
    let produced = run(two_descriptor_stream());
    let store = &records_of_type(&produced, RECORD_TYPE_STORE)[0].metadata;
    assert!(store.get("inventory_incomplete").is_none());
    assert!(store.get("content_incomplete").is_none());
}

#[test]
fn a_stream_named_sds_on_a_file_other_than_secure_is_left_alone() {
    // A user file may legitimately carry an ADS called $SDS. Parsing it as the
    // descriptor store would invent owners and ACLs for real files.
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(two_descriptor_stream()));
    let metadata = serde_json::json!({
        "name": "invoice.docx:$SDS",
        "stream_name": "$SDS",
        "parent_file": "invoice.docx",
        "path": "/Users/jsmith/invoice.docx:$SDS",
    });
    let produced = SecureSdsParser::new()
        .process(&artifact_with(metadata, Some(data)))
        .expect("a non-target artifact is skipped, not an error");
    assert!(produced.is_empty());
}

#[test]
fn artifacts_that_are_not_the_descriptor_store_are_skipped() {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(two_descriptor_stream()));
    for metadata in [
        serde_json::json!({ "name": "notes.txt", "path": "/Users/jsmith/notes.txt" }),
        serde_json::json!({ "name": "$Secure", "path": "/$Secure" }),
        serde_json::json!({ "name": "$Secure:$SDH", "stream_name": "$SDH", "parent_file": "$Secure" }),
        serde_json::json!({ "name": "$SDS", "is_directory": true }),
        serde_json::json!({}),
    ] {
        let produced = SecureSdsParser::new()
            .process(&artifact_with(metadata.clone(), Some(data.clone())))
            .expect("a non-target artifact is skipped, not an error");
        assert!(produced.is_empty(), "unexpectedly parsed {metadata}");
    }
}

#[test]
fn a_stream_extracted_to_a_standalone_file_is_recognised_by_its_name() {
    for name in ["$SDS", "$Secure_$SDS", "$Secure.$SDS", "$Secure:$SDS"] {
        let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(two_descriptor_stream()));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::SystemArtifact,
            Some(data),
            serde_json::json!({ "name": name, "source_path": format!("/exports/{name}") }),
        );
        let produced = SecureSdsParser::new()
            .process(&artifact)
            .expect("an extracted stream must process cleanly");
        assert_eq!(
            records_of_type(&produced, RECORD_TYPE_DESCRIPTOR).len(),
            2,
            "extracted stream named {name} was not recognised"
        );
    }
}

/// HUNT-178, graded on a real volume (`reference/dfir_ntfs/test_data/
/// ntfs_index.raw.gz`, NTFS at sector 128; gitignored, absent in CI): every
/// file's `$STANDARD_INFORMATION` `security_id`, as the MFT parser now
/// publishes it, names a descriptor this module decodes from the same volume's
/// `$Secure:$SDS` — so the id on a `FileEntry` and the id on a descriptor
/// record are the same key, and a join on it resolves.
#[test]
fn every_security_id_on_a_real_volume_resolves_to_a_decoded_descriptor() {
    use std::io::Read;
    let path = std::path::Path::new("../reference/dfir_ntfs/test_data/ntfs_index.raw.gz");
    if !path.exists() {
        eprintln!("skipping: {path:?} not present (gitignored corpus, absent in CI)");
        return;
    }
    let mut image = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).expect("open"))
        .read_to_end(&mut image)
        .expect("decompress");
    let volume = image[128 * 512..].to_vec();
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(Arc::new(ByteSliceDataSource::new(volume))),
        serde_json::json!({ "filesystem_type": "NTFS" }),
    );
    let produced = seance_plugin_mft::MftParser::new()
        .process(&fs)
        .expect("the MFT parser reads the real volume");

    let sds = produced
        .iter()
        .find(|a| a.metadata["name"] == "$Secure:$SDS")
        .expect("$Secure:$SDS is emitted");
    let decoded = SecureSdsParser::new()
        .process(sds)
        .expect("the $SDS decodes");
    let store = &records_of_type(&decoded, RECORD_TYPE_STORE)[0].metadata;
    assert_eq!(store["store_listing_incomplete"], false, "{store}");
    let ids: std::collections::HashSet<u64> = records_of_type(&decoded, RECORD_TYPE_DESCRIPTOR)
        .iter()
        .filter_map(|d| d.metadata["security_id"].as_u64())
        .collect();

    let keyed: Vec<(&str, u64)> = produced
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .filter_map(|a| {
            Some((
                a.metadata["name"].as_str()?,
                a.metadata.get("security_id")?.as_u64()?,
            ))
        })
        .collect();
    assert!(
        keyed.len() > 20,
        "the volume's records carry a security_id: {}",
        keyed.len()
    );
    // Record 28 (`$Repair`) really carries security_id 0 in its 72-byte
    // $STANDARD_INFORMATION — read off the raw record, not inferred. 0 is not
    // an $SDS key (NTFS numbers them from 0x100); it is published as found
    // and resolves to nothing, which is the truth about that record.
    assert_eq!(
        keyed
            .iter()
            .filter(|(_, id)| *id == 0)
            .map(|(n, _)| *n)
            .collect::<Vec<_>>(),
        vec!["$Repair"]
    );
    let unresolved: Vec<&(&str, u64)> = keyed
        .iter()
        .filter(|(_, id)| *id != 0 && !ids.contains(id))
        .collect();
    assert!(
        unresolved.is_empty(),
        "every published security_id names a decoded descriptor; unresolved: {unresolved:?}"
    );
}

/// HUNT-178, the join the file view performs, on the same real volume: the UI
/// takes a file's `security_id`, finds the store record whose `$Secure:$SDS`
/// stream entry shares the file's parent (the volume the MFT parser read), and
/// looks for the descriptor under that stream entry only. This pins the
/// parentage that scoping rests on, and resolves one ordinary file end to end.
#[test]
fn the_file_views_volume_scoped_join_resolves_on_a_real_volume() {
    use std::io::Read;
    let path = std::path::Path::new("../reference/dfir_ntfs/test_data/ntfs_index.raw.gz");
    if !path.exists() {
        eprintln!("skipping: {path:?} not present (gitignored corpus, absent in CI)");
        return;
    }
    let mut image = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).expect("open"))
        .read_to_end(&mut image)
        .expect("decompress");
    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(Arc::new(ByteSliceDataSource::new(
            image[128 * 512..].to_vec(),
        ))),
        serde_json::json!({ "filesystem_type": "NTFS" }),
    );
    let produced = seance_plugin_mft::MftParser::new()
        .process(&fs)
        .expect("the MFT parser reads the real volume");
    let sds = produced
        .iter()
        .find(|a| a.metadata["name"] == "$Secure:$SDS")
        .expect("$Secure:$SDS is emitted");
    assert_eq!(
        sds.parent_id,
        Some(fs.id),
        "the stream hangs under the volume"
    );
    let decoded = SecureSdsParser::new().process(sds).expect("decodes");
    for record in &decoded {
        assert_eq!(
            record.parent_id,
            Some(sds.id),
            "every record hangs under the stream"
        );
    }
    // An ordinary file with a non-zero id: same parent as the stream, and its
    // id names exactly one descriptor under that stream.
    let file = produced
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .find(|a| {
            a.metadata["security_id"].as_u64().is_some_and(|id| id != 0)
                && !a.metadata["name"].as_str().unwrap_or("$").starts_with('$')
        })
        .expect("an ordinary file carries a security_id");
    assert_eq!(
        file.parent_id, sds.parent_id,
        "file and stream share the volume"
    );
    let id = file.metadata["security_id"].as_u64().unwrap();
    let matches: Vec<&Artifact> = records_of_type(&decoded, RECORD_TYPE_DESCRIPTOR)
        .into_iter()
        .filter(|d| d.metadata["security_id"].as_u64() == Some(id))
        .collect();
    assert_eq!(matches.len(), 1);
    let d = &matches[0].metadata;
    assert!(
        d["owner_sid"]
            .as_str()
            .is_some_and(|s| s.starts_with("S-1-")),
        "{d}"
    );
    eprintln!(
        "{} -> security_id {id}: owner {} group {} dacl {} ({} ACEs), hash {}, sds_offset {}",
        file.metadata["name"],
        d["owner_sid"],
        d["group_sid"],
        d["dacl_state"],
        d["dacl"].as_array().map_or(0, |a| a.len()),
        d["descriptor_hash"],
        d["sds_offset"]
    );
}
