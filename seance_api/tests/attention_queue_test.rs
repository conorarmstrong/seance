//! The queue of recoverable problems (`ROADMAP.md` §2.11).
//!
//! A case can hold the sentence "this iOS backup is encrypted and no password
//! was provided: no files from it are in this case" and offer the examiner
//! nowhere to act on it. The statement was honest and the next step was
//! invisible.
//!
//! Two assertions carry the weight, and neither is about listing things.
//!
//! [`a_problem_this_build_cannot_fix_is_still_on_the_queue_and_says_so`]: a
//! dead affordance on a forensic tool is worse than no affordance — an examiner
//! who types a password into a field that cannot reach the decryptor concludes
//! the password is wrong. So the queue distinguishes "supply it here", "supply
//! it at start-up and ingest again" and "this build cannot read it", and the
//! last two offer no field. Since HUNT-120 the volume decryptors, the 7z
//! expander and the Signal parser take a secret per artifact, so their rows
//! are "supply it here" through the credential route.
//!
//! [`an_empty_queue_does_not_read_as_a_complete_examination`]: the queue is
//! about what can still be *done*, not about what was read. Every response says
//! so, because an empty queue is otherwise the most natural thing in the world
//! to read as a clean case.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use seance_api::{router_with_auth, AppState, AuthConfig, EvidenceRootPolicy};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_core::orchestrator::{CancellationHandle, Orchestrator};
use seance_db::SqliteConnection;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::util::ServiceExt;
use uuid::Uuid;

async fn setup(records: Vec<(Option<Uuid>, Value)>) -> (axum::Router, Uuid) {
    let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
    db.initialize().await.unwrap();
    let case_id = db.create_case("Attention", "examiner").await.unwrap();
    for (parent, meta) in records {
        let mut a = Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta);
        a.parent_id = parent;
        db.record_artifact(&a).await.unwrap();
    }
    let orchestrator = Orchestrator::new(Some(db.clone()), 100);
    let app = router_with_auth(
        AppState {
            db: db.clone(),
            orchestrator_sender: orchestrator.task_submitter(),
            event_sender: orchestrator.event_sender(),
            ad_hoc_sender: orchestrator.ad_hoc_submitter(),
            status_sender: orchestrator.status_sender(),
            active_tasks: orchestrator.active_tasks(),
            search_service: None,
            ingestion_service: orchestrator.ingestion_service(),
            module_registry: vec![],
            signing_config: None,
            evidence_roots: EvidenceRootPolicy::unrestricted(),
            cancellation: CancellationHandle::new(),
        },
        Some(AuthConfig {
            jwt_secret: "t".into(),
            admin_username: "admin".into(),
            admin_password_hash: String::new(),
            enabled: false,
        }),
    );
    (app, case_id)
}

async fn get(app: &axum::Router, uri: String) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// An encrypted iOS backup as the parser reports one.
fn encrypted_ios_backup() -> Value {
    json!({
        "type": "IosBackupInfo",
        "subtype": "ios_backup_incomplete",
        "status": "encrypted_no_password",
        "name": "iOS backup (encrypted, not extracted)",
        "content_incomplete": true,
        "content_incomplete_reason": "encrypted",
        "inventory_incomplete": true,
        "inventory_incomplete_reason": "encrypted",
        "message": "iOS backup is encrypted and no password was provided.",
    })
}

fn undecrypted_volume(scheme: &str) -> Value {
    json!({
        "type": "VolumeDecryption",
        "subtype": "unlock_failed",
        "status": "UnlockFailed",
        "scheme": scheme,
        "volume_name": "vol1",
        "name": format!("{scheme} volume 'vol1': unlock FAILED, contents not decrypted"),
        "content_incomplete": true,
        "content_incomplete_reason": "encrypted",
        "content_incomplete_detail": "The contents of this volume are NOT in the case.",
    })
}

#[tokio::test]
async fn an_encrypted_backup_reaches_the_queue_with_the_field_that_unlocks_it() {
    let source = Uuid::new_v4();
    let (app, case_id) = setup(vec![(Some(source), encrypted_ios_backup())]).await;

    let (status, body) = get(&app, format!("/api/v1/cases/{case_id}/attention")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{body}");
    let item = &items[0];
    assert_eq!(item["record_type"], "IosBackupInfo");
    assert_eq!(item["count"], 1);
    assert_eq!(item["problem"], "An encrypted iOS backup was not extracted");
    // The action the UI switches on: a field, a module and a key that really
    // reaches it.
    assert_eq!(item["action"]["kind"], "supply_secret");
    assert_eq!(item["action"]["module_id"], "plugin.mobile.ios_backup");
    assert_eq!(item["action"]["secret_key"], "ios_backup_password");
    assert_eq!(item["action"]["label"], "The backup's password");
    // SEC-204: the password goes to the credential route (zeroed, audited by
    // kind and outcome), not into `run_module`'s retired `secrets` map.
    assert_eq!(item["action"]["route"], "credential");
    // And the guidance says what happens to the password, which is the first
    // question an examiner asks before typing one.
    assert!(item["guidance"]
        .as_str()
        .unwrap()
        .contains("never written to the case"));

    // The module is re-run on the artifact the backup IS, not on the status
    // record — a status record has no bytes, so running a decryptor on it
    // would do nothing at all.
    assert_eq!(item["examples"][0]["target_id"], json!(source));
    assert_ne!(item["examples"][0]["artifact_id"], json!(source));

    assert_eq!(body["actionable_artifacts"], 1);
}

/// LUKS and BitLocker both report through `VolumeDecryption` and need different
/// instructions. A queue that merged them would give one of them the wrong one.
#[tokio::test]
async fn two_schemes_reporting_through_one_record_type_get_their_own_instructions() {
    let (app, case_id) = setup(vec![
        (Some(Uuid::new_v4()), undecrypted_volume("LUKS")),
        (Some(Uuid::new_v4()), undecrypted_volume("BitLocker")),
    ])
    .await;

    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/attention")).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{body}");

    let luks = items
        .iter()
        .find(|i| i["scheme"] == "LUKS")
        .expect("a LUKS row");
    let bitlocker = items
        .iter()
        .find(|i| i["scheme"] == "BitLocker")
        .expect("a BitLocker row");

    // Both offer a field now (HUNT-120): the secret reaches the decryptor for
    // this volume and this run through the credential route.
    for item in [luks, bitlocker] {
        assert_eq!(item["action"]["kind"], "supply_secret");
        assert_eq!(item["action"]["route"], "credential");
        // And each says the absence of files under the volume is a decryption
        // failure, not evidence the volume was empty.
        assert!(item["guidance"]
            .as_str()
            .unwrap()
            .contains("decryption failure"));
    }
    assert_eq!(luks["action"]["module_id"], "plugin.crypto.luks_decryptor");
    assert_eq!(luks["action"]["secret_key"], "luks_passphrase");
    assert_eq!(
        bitlocker["action"]["module_id"],
        "plugin.crypto.bitlocker_decryptor"
    );
    assert_eq!(
        bitlocker["action"]["secret_key"],
        "bitlocker_recovery_password"
    );
    // A BitLocker volume opens with either secret; the row offers both.
    assert_eq!(
        bitlocker["action"]["alternatives"][0]["secret_key"],
        "bitlocker_password"
    );
    // Each names the recovery route for a password nobody has.
    assert!(luks["guidance"].as_str().unwrap().contains("crack-luks"));
    assert!(bitlocker["guidance"]
        .as_str()
        .unwrap()
        .contains("crack-bitlocker"));
}

/// HUNT-196: a LUKS volume nobody supplied a passphrase for reaches the queue.
///
/// The record comes from the real decryptor, not a hand-written fixture: the
/// module used to return nothing when no passphrase was configured, so a locked
/// LUKS volume never produced a `VolumeDecryption` record and never reached
/// this queue.
#[tokio::test]
async fn a_luks_volume_with_no_passphrase_reaches_the_queue() {
    use seance_core::data_source::ByteSliceDataSource;
    use seance_core::module::ForensicsModule;

    // A LUKS1 phdr as `cryptsetup luksFormat --type luks1` lays it out:
    // magic, version 1, cipher `aes` / `xts-plain64`, hash `sha256`, a
    // 64-byte key and one enabled keyslot. No keyslot material is needed —
    // nothing is unlocked.
    let mut img = vec![0u8; 8192];
    img[..6].copy_from_slice(b"LUKS\xba\xbe");
    img[6..8].copy_from_slice(&1u16.to_be_bytes());
    img[8..11].copy_from_slice(b"aes");
    img[40..51].copy_from_slice(b"xts-plain64");
    img[72..78].copy_from_slice(b"sha256");
    img[104..108].copy_from_slice(&4096u32.to_be_bytes());
    img[108..112].copy_from_slice(&64u32.to_be_bytes());
    img[208..212].copy_from_slice(&0x00AC_71F3u32.to_be_bytes());

    let volume = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::Partition,
        Some(Arc::new(ByteSliceDataSource::new(img))),
        json!({ "name": "sda2" }),
    );
    let out = seance_plugin_luks::LuksDecryptor::new()
        .process(&volume)
        .expect("a locked volume is not a pipeline failure");
    assert_eq!(out.len(), 1, "a locked LUKS volume must produce a record");

    let (app, case_id) = setup(vec![(Some(volume.id), out[0].metadata.clone())]).await;
    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/attention")).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{body}");
    let item = &items[0];
    assert_eq!(item["record_type"], "VolumeDecryption");
    assert_eq!(item["scheme"], "LUKS");
    assert_eq!(item["problem"], "A LUKS volume was not decrypted");
    assert_eq!(item["action"]["kind"], "supply_secret");
    assert_eq!(item["action"]["route"], "credential");
    // The re-run target is the volume, not the status record.
    assert_eq!(item["examples"][0]["target_id"], json!(volume.id));
    assert_eq!(body["actionable_artifacts"], 1);
}

/// HUNT-171: a header-encrypted 7z reaches the queue with a field, and the
/// field is the credential route's; its content-encrypted entries reach it
/// saying plainly that no password brings 7z content into the case.
#[tokio::test]
async fn a_locked_7z_gets_a_field_and_its_encrypted_entries_an_honest_no() {
    use seance_core::data_source::ByteSliceDataSource;
    use seance_core::module::ForensicsModule;
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../seance_container_archive/tests/fixtures");
    let mut records = Vec::new();
    for fixture in ["password_header.7z", "password_content.7z"] {
        let archive = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(ByteSliceDataSource::new(
                std::fs::read(fixtures.join(fixture)).unwrap(),
            ))),
            json!({ "name": fixture, "subtype": "7z" }),
        );
        for out in seance_container_archive::SevenZipExpanderModule
            .process(&archive)
            .unwrap()
        {
            records.push((Some(archive.id), out.metadata));
        }
    }
    let (app, case_id) = setup(records).await;
    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/attention")).await;
    let items = body["items"].as_array().unwrap();
    let header = items
        .iter()
        .find(|i| i["record_type"] == "ArchiveScanStatus")
        .expect("the header-encrypted archive's row");
    assert_eq!(header["action"]["kind"], "supply_secret");
    assert_eq!(header["action"]["route"], "credential");
    assert_eq!(header["action"]["secret_key"], "sevenz_password");
    let entries = items
        .iter()
        .find(|i| i["record_type"] == "Unknown" && i["scheme"] == "7z_aes256_sha256")
        .expect("the encrypted entries' row");
    assert_eq!(entries["action"]["kind"], "unsupported");
    assert!(entries["guidance"]
        .as_str()
        .unwrap()
        .contains("does not extract 7z content"));
}

/// HUNT-227: the Signal for iOS store's row takes its key spec.
#[tokio::test]
async fn the_signal_ios_store_gets_a_key_spec_field() {
    let (app, case_id) = setup(vec![(
        Some(Uuid::new_v4()),
        json!({
            "type": "SignalIncomplete",
            "subtype": "parse_incomplete",
            "status": "StoreEncrypted",
            "scheme": "sqlcipher4_raw_key_plaintext_header",
            "content_incomplete": true,
            "content_incomplete_reason": "encrypted",
        }),
    )])
    .await;
    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/attention")).await;
    let item = &body["items"][0];
    assert_eq!(item["action"]["kind"], "supply_secret");
    assert_eq!(item["action"]["route"], "credential");
    assert_eq!(item["action"]["secret_key"], "signal_ios_key_spec");
    assert_eq!(item["action"]["module_id"], "plugin.messaging.signal");
}

/// ROADMAP §5.7 (owner decision (c) part b): a crypt14 or crypt15 WhatsApp
/// backup whose key is not in the case takes the key as the `whatsapp_key`
/// credential (a crypt15's is its 64-digit end-to-end root key).
#[tokio::test]
async fn a_whatsapp_backup_awaiting_its_key_gets_a_key_field_for_crypt14_and_crypt15() {
    let (app, case_id) = setup(vec![
        (
            Some(Uuid::new_v4()),
            json!({
                "type": "WhatsAppBackup",
                "status": "AwaitingKey",
                "scheme": "crypt14",
                "credential_kind": "whatsapp_key",
                "content_incomplete": true,
                "content_incomplete_reason": "encrypted",
            }),
        ),
        (
            Some(Uuid::new_v4()),
            json!({
                "type": "WhatsAppBackup",
                "status": "AwaitingKey",
                "scheme": "crypt15",
                "credential_kind": "whatsapp_key",
                "content_incomplete": true,
                "content_incomplete_reason": "encrypted",
            }),
        ),
    ])
    .await;
    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/attention")).await;
    let items = body["items"].as_array().unwrap();
    for scheme in ["crypt14", "crypt15"] {
        let row = items
            .iter()
            .find(|i| i["record_type"] == "WhatsAppBackup" && i["scheme"] == scheme)
            .unwrap_or_else(|| panic!("the {scheme} row"));
        assert_eq!(row["action"]["kind"], "supply_secret", "{scheme}");
        assert_eq!(row["action"]["route"], "credential", "{scheme}");
        assert_eq!(row["action"]["secret_key"], "whatsapp_key", "{scheme}");
        assert_eq!(row["action"]["module_id"], "plugin.messaging.whatsapp");
    }
}

/// A dead affordance on a forensic tool is worse than none: an examiner who
/// types a password into a field that cannot reach the decryptor concludes the
/// password is wrong.
#[tokio::test]
async fn a_problem_this_build_cannot_fix_is_still_on_the_queue_and_says_so() {
    let (app, case_id) = setup(vec![(
        Some(Uuid::new_v4()),
        json!({
            "type": "AndroidBackupWarning",
            "record_type": "android_backup_status",
            "status": "EncryptedNotSupported",
            "name": "Android backup (encrypted, not extracted)",
            "content_incomplete": true,
            "content_incomplete_reason": "encrypted",
        }),
    )])
    .await;

    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/attention")).await;
    let item = &body["items"][0];
    assert_eq!(item["action"]["kind"], "unsupported");
    assert!(item["guidance"]
        .as_str()
        .unwrap()
        .contains("no password field is offered"));
    // It is on the queue: a problem nobody can fix is still a problem the case
    // holds, and dropping it would make the queue read as the whole of what is
    // outstanding when it was a filtered subset.
    assert_eq!(body["artifacts"], 1);
    // But it is not counted as something to act on.
    assert_eq!(body["actionable_artifacts"], 0);
}

/// A blockage this build has no instruction for is listed with no instruction,
/// rather than dropped or given a guess.
#[tokio::test]
async fn an_unrecognised_blockage_is_listed_without_an_invented_instruction() {
    let (app, case_id) = setup(vec![(
        None,
        json!({
            "type": "SomeFutureFormat",
            "name": "a thing",
            "content_incomplete": true,
            "content_incomplete_reason": "encrypted",
        }),
    )])
    .await;

    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/attention")).await;
    let item = &body["items"][0];
    assert_eq!(item["record_type"], "SomeFutureFormat");
    assert!(item["action"].is_null());
    assert!(item["problem"].is_null());
    assert!(item["unrecognised_note"]
        .as_str()
        .unwrap()
        .contains("no instruction for this kind of blockage"));
    // With no parent, the artifact is its own target rather than a null one.
    assert_eq!(
        item["examples"][0]["target_id"],
        item["examples"][0]["artifact_id"]
    );
}

/// The queue is about what can still be done, not about what was read. An
/// empty one is otherwise the most natural thing in the world to read as a
/// clean case.
#[tokio::test]
async fn an_empty_queue_does_not_read_as_a_complete_examination() {
    let (app, case_id) = setup(vec![(
        None,
        json!({
            // Incomplete, and not recoverable from a screen: a cap that bit
            // needs a different build, not a password.
            "type": "NtfsFileName",
            "name": "huge.bin",
            "content_incomplete": true,
            "content_incomplete_reason": "cap_reached",
        }),
    )])
    .await;

    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/attention")).await;
    assert_eq!(body["artifacts"], 0, "a cap is not a queue item: {body}");
    let note = body["scope_note"].as_str().unwrap();
    assert!(
        note.contains("NOT the case's completeness record"),
        "{note}"
    );
    assert!(note.contains("incompleteness census"));
    assert_eq!(body["reasons_examined"], json!(["encrypted"]));
}

/// A later run that DID read the content answers the earlier statement of
/// incompleteness. Leaving it on the queue would ask an examiner to act on a
/// problem that is already solved.
#[tokio::test]
async fn a_superseded_statement_of_incompleteness_leaves_the_queue() {
    let mut superseded = encrypted_ios_backup();
    superseded["superseded"] = json!(true);
    let (app, case_id) = setup(vec![(Some(Uuid::new_v4()), superseded)]).await;

    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/attention")).await;
    assert_eq!(body["artifacts"], 0, "{body}");
}

/// A queue row needs a handful of examples to act on, not all of them — and
/// says when it is showing a subset.
#[tokio::test]
async fn a_large_group_names_a_subset_and_says_so() {
    let records: Vec<(Option<Uuid>, Value)> = (0..14)
        .map(|_| (Some(Uuid::new_v4()), encrypted_ios_backup()))
        .collect();
    let (app, case_id) = setup(records).await;

    let (_, body) = get(&app, format!("/api/v1/cases/{case_id}/attention")).await;
    let item = &body["items"][0];
    assert_eq!(item["count"], 14);
    assert_eq!(item["examples"].as_array().unwrap().len(), 10);
    assert_eq!(item["examples_truncated"], true);
}

/// A remedy naming a module this build does not register would offer an action
/// that silently does nothing.
#[test]
fn attention_remedies_name_registered_modules() {
    use seance_core::orchestrator::Orchestrator;

    let dir = tempfile::tempdir().expect("temp dir");
    let search = Arc::new(seance_search::SearchService::new(dir.path()).expect("search service"));
    let orchestrator = Orchestrator::new(None, 10);
    let modules = seance_api::modules::build_module_set(
        &orchestrator,
        seance_api::modules::ModuleSetOptions {
            search_service: search,
            carver_defs: None,
            unlock: Default::default(),
            yara_rules: None,
            memory_regex: None,
            memory_strings: None,
        },
    )
    .expect("module set builds");
    let registered: Vec<String> = modules.iter().map(|m| m.id().to_string()).collect();

    let mut missing = Vec::new();
    for remedy in seance_api::REMEDIES {
        if let seance_api::RemedyAction::SupplySecret {
            module_id,
            secret_key,
            route,
            alternatives,
            ..
        } = remedy.action
        {
            if !registered.iter().any(|r| r == module_id) {
                missing.push(module_id);
            }
            // A credential-route row must name a kind the route takes, and
            // that kind must be consumed by the module the row names — or the
            // field would send the secret somewhere that never reads it.
            if route == seance_api::SecretRoute::Credential {
                for key in
                    std::iter::once(secret_key).chain(alternatives.iter().map(|a| a.secret_key))
                {
                    let kind = seance_core::credential::CredentialKind::parse(key)
                        .unwrap_or_else(|| panic!("{key} is not a credential kind"));
                    assert_eq!(kind.module_id(), module_id, "{key}");
                }
            }
        }
    }
    assert!(
        missing.is_empty(),
        "these remedies name modules this build does not register, so the action they offer \
         would silently do nothing: {missing:?}"
    );
    assert!(
        !seance_api::REMEDIES.is_empty(),
        "the attention queue must know about at least one recoverable problem"
    );
}
