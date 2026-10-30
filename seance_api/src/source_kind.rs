//! "What kind of exhibit is this?" — a mobile source-type triage label per
//! evidence source, compiled from records the parsers already wrote (ROADMAP
//! §1.4).
//!
//! Nothing is detected here. A source is labelled only from **marker records**:
//! record types (with, where a type alone is not enough, a field value and a
//! path the parser recorded) that only a mobile operating system's own files,
//! or a mobile backup, produce. Three rules shape what this says:
//!
//! * **A name is not evidence of content.** The root's file name and extension
//!   are never a basis: `android.tar` renamed `disk.raw` gets the same label.
//! * **Containment, not identity.** Kinds are additive: a laptop image that
//!   holds an iPhone backup is labelled `ios_backup` — "this source holds an iOS
//!   backup" — never `ios_device`. Three plausible iOS markers were rejected on
//!   a real macOS case (`PhotoAsset`, `iMessage` and `InstalledAppSummary` from
//!   `applicationState.db` all fire on a Mac), and `PowerLogSummary` /
//!   `CachedLocationSummary` count only where the store sat at its iOS path,
//!   because a Mac keeps the same stores elsewhere.
//! * **Absence needs a finished walk.** A marker found is evidence whatever the
//!   state of the walk that found it. The absence of every marker is stated
//!   (`none_recognised`) only for a source whose newest ingest run completed,
//!   that produced records, whose marker listings were not capped, and under
//!   which no mobile store was left unread. Anything else is `not_assessed`,
//!   with the reason — "we did not look" never renders as "there is none".

use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

/// The kinds a source can be labelled with. Order is the order they are listed.
pub const KINDS: &[&str] = &[
    "android_device",
    "android_backup",
    "ios_device",
    "ios_backup",
];

/// What a marker record must carry, beyond its type, to count.
#[derive(Debug, Clone, Copy)]
pub struct Marker {
    /// The record type, as the parser writes it under `type`.
    pub record_type: &'static str,
    /// The kind it evidences.
    pub kind: &'static str,
    /// A field that must hold one of the listed values, or `None`.
    pub field: Option<(&'static str, &'static [&'static str])>,
    /// Path fragments, one of which the nearest ancestor file's path must
    /// contain; empty when the type needs no path corroboration.
    pub path_contains: &'static [&'static str],
    /// Which parser writes it and from what, for `looked_for`.
    pub written_by: &'static str,
}

/// The marker vocabulary. Every entry is a type some plugin in this tree emits
/// under `type` (pinned by `seance_tests`' vocabulary test).
pub const MARKERS: &[Marker] = &[
    Marker {
        record_type: "MobileDeviceInfo",
        kind: "android_device",
        field: Some(("platform", &["android"])),
        path_contains: &[],
        written_by: "the Android device-facts reader (settings_*.xml, build.prop, telephony.db)",
    },
    Marker {
        record_type: "BluetoothPairing",
        kind: "android_device",
        field: Some(("platform", &["android"])),
        path_contains: &[],
        written_by: "the Android Bluetooth reader (bt_config.conf)",
    },
    Marker {
        record_type: "AndroidSmsSummary",
        kind: "android_device",
        field: None,
        path_contains: &[],
        written_by: "the Android SMS/MMS reader (mmssms.db)",
    },
    Marker {
        record_type: "AndroidCalendarSummary",
        kind: "android_device",
        field: Some(("source", &["android_calendar"])),
        path_contains: &[],
        written_by: "the Android calendar reader (calendar.db)",
    },
    Marker {
        record_type: "AndroidNote",
        kind: "android_device",
        field: Some(("source", &["google_keep"])),
        path_contains: &[],
        written_by: "the Google Keep reader (keep.db)",
    },
    Marker {
        record_type: "InstalledAppSummary",
        kind: "android_device",
        field: Some(("source", &["packages.xml", "packages.list"])),
        path_contains: &[],
        written_by: "the installed-apps reader, from Android's packages.xml or packages.list \
                     (not applicationState.db, which a Mac also holds)",
    },
    Marker {
        record_type: "AndroidBackupSummary",
        kind: "android_backup",
        field: None,
        path_contains: &[],
        written_by: "the adb backup (.ab) reader, for a backup it walked to the archive's end",
    },
    Marker {
        record_type: "AndroidBackupWarning",
        kind: "android_backup",
        field: None,
        path_contains: &[],
        written_by: "the adb backup (.ab) reader, for a backup it recognised and did not \
                     unpack whole",
    },
    Marker {
        record_type: "PowerLogSummary",
        kind: "ios_device",
        field: Some(("platform", &["iOS"])),
        path_contains: &["var/containers/Shared/SystemGroup/"],
        written_by: "the iOS PowerLog reader, where the store sat at its iOS path (a Mac keeps \
                     the same store under /private/var/db/powerlog)",
    },
    Marker {
        record_type: "CachedLocationSummary",
        kind: "ios_device",
        field: Some(("source", &["com.apple.routined"])),
        path_contains: &["var/mobile/"],
        written_by: "the iOS routined cache reader, where the store sat under /var/mobile",
    },
    Marker {
        record_type: "IosBackupInfo",
        kind: "ios_backup",
        field: None,
        path_contains: &[],
        written_by: "the iOS backup readers (Manifest.plist, Info.plist, Manifest.db, or a \
                     backup directory's own status)",
    },
];

/// Record types that say a store a mobile parser selected could not be read.
/// They are not markers — the parser opens same-named macOS stores too — but a
/// source carrying one cannot be said to hold no mobile evidence, because the
/// store that would have said so was not read.
pub const UNREAD_STORE_TYPES: &[&str] = &["IosArtifactParseStatus"];

/// How far the newest ingest run of a source got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkState {
    Completed,
    Running,
    Interrupted(Option<String>),
    Cancelled(Option<String>),
    /// No ingest run is recorded for this source (a case ingested before runs
    /// were recorded).
    NoRunRecorded,
}

impl WalkState {
    /// From an ingest run's `status` and `detail`.
    pub fn from_run(status: &str, detail: Option<&str>) -> Self {
        let detail = detail.map(str::to_string);
        match status {
            "completed" => Self::Completed,
            "running" => Self::Running,
            "cancelled" => Self::Cancelled(detail),
            _ => Self::Interrupted(detail),
        }
    }

    fn token(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Running => "running",
            Self::Interrupted(_) => "interrupted",
            Self::Cancelled(_) => "cancelled",
            Self::NoRunRecorded => "no_run_recorded",
        }
    }
}

/// One evidence source (a root artifact) and what is known of its walk.
#[derive(Debug, Clone)]
pub struct SourceFacts {
    pub id: Uuid,
    pub name: String,
    pub walk: WalkState,
    /// Whether anything is recorded under the source, where it was looked up.
    pub has_records: Option<bool>,
}

/// One candidate record, attributed to its root.
#[derive(Debug, Clone)]
pub struct MarkerRecord {
    pub root: Uuid,
    pub record_id: Uuid,
    pub metadata: Value,
    /// The path of the nearest ancestor that carries one (the file the record
    /// was parsed from), where the walk found one.
    pub file_path: Option<String>,
}

/// Most basis entries quoted per kind per source; the count beside them is
/// the full number.
const BASIS_PER_KIND: usize = 5;

fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
}

/// The marker a record satisfies, if any: its type, the field value, and the
/// path the store sat at must all agree with the vocabulary.
pub fn marker_for(record: &MarkerRecord) -> Option<&'static Marker> {
    let ty = text(&record.metadata, "type")?;
    MARKERS.iter().find(|m| {
        m.record_type == ty
            && m.field.is_none_or(|(key, values)| {
                text(&record.metadata, key).is_some_and(|v| values.contains(&v))
            })
            && (m.path_contains.is_empty()
                || record
                    .file_path
                    .as_deref()
                    .or_else(|| text(&record.metadata, "source_file"))
                    .is_some_and(|p| m.path_contains.iter().any(|f| p.contains(f))))
    })
}

/// Whether a record whose root could not be reached may be a marker or an
/// unread mobile store. Its path is not known (the walk that would have found
/// the file it came from stopped), so a marker that needs path corroboration
/// counts when its own `source_file` is absent — the path that would rule it
/// out was not seen — and does not when that `source_file` fails the check.
fn could_be_marker(metadata: &Value) -> bool {
    let Some(ty) = text(metadata, "type") else {
        return false;
    };
    UNREAD_STORE_TYPES.contains(&ty)
        || MARKERS.iter().any(|m| {
            m.record_type == ty
                && m.field.is_none_or(|(key, values)| {
                    text(metadata, key).is_some_and(|v| values.contains(&v))
                })
                && (m.path_contains.is_empty()
                    || text(metadata, "source_file")
                        .is_none_or(|p| m.path_contains.iter().any(|f| p.contains(f))))
        })
}

/// The vocabulary as the response states it, so an empty result names what was
/// looked for rather than reading as "no mobile evidence exists".
fn looked_for() -> Value {
    Value::Array(
        MARKERS
            .iter()
            .map(|m| {
                json!({
                    "record_type": m.record_type,
                    "kind": m.kind,
                    "requires_field": m.field.map(|(k, v)| json!({ "field": k, "one_of": v })),
                    "requires_path_containing": m.path_contains,
                    "written_by": m.written_by,
                })
            })
            .collect(),
    )
}

/// Compile the per-source label.
///
/// `capped_types` names the marker types whose listing stopped at its cap;
/// `unattributed` holds the metadata of candidate records whose root could not
/// be reached (a missing parent, a parent in another case, the depth cap). Any
/// of them that may be a marker or an unread store stops every source being
/// called `none_recognised`: it could be that source's.
pub fn compile_source_kinds(
    sources: &[SourceFacts],
    records: &[MarkerRecord],
    capped_types: &[String],
    unattributed: &[Value],
) -> Value {
    // Per root: kind -> (count, quoted basis); and the unread stores.
    let mut found: BTreeMap<Uuid, BTreeMap<&'static str, (usize, Vec<Value>)>> = BTreeMap::new();
    let mut unread: BTreeMap<Uuid, Vec<String>> = BTreeMap::new();
    for record in records {
        if let Some(marker) = marker_for(record) {
            let entry = found
                .entry(record.root)
                .or_default()
                .entry(marker.kind)
                .or_insert((0, Vec::new()));
            entry.0 += 1;
            if entry.1.len() < BASIS_PER_KIND {
                let corroborated_by = marker.field.and_then(|(key, _)| {
                    text(&record.metadata, key).map(|v| json!({ "field": key, "value": v }))
                });
                entry.1.push(json!({
                    "record_id": record.record_id,
                    "record_type": marker.record_type,
                    "corroborated_by": corroborated_by,
                    "source_file": text(&record.metadata, "source_file")
                        .or(record.file_path.as_deref())
                        .or_else(|| text(&record.metadata, "file_name"))
                        .or_else(|| text(&record.metadata, "source")),
                }));
            }
        } else if text(&record.metadata, "type").is_some_and(|t| UNREAD_STORE_TYPES.contains(&t)) {
            let what = text(&record.metadata, "file_name")
                .or(record.file_path.as_deref())
                .unwrap_or("a store")
                .to_string();
            unread.entry(record.root).or_default().push(what);
        }
    }

    let capped = !capped_types.is_empty();
    // A marker whose root could not be reached may belong to any source.
    let lost_markers = unattributed.iter().filter(|m| could_be_marker(m)).count();
    let rows: Vec<Value> = sources
        .iter()
        .map(|s| {
            let by_kind = found.get(&s.id);
            let kinds: Vec<&str> = KINDS
                .iter()
                .copied()
                .filter(|k| by_kind.is_some_and(|m| m.contains_key(k)))
                .collect();
            let basis: Vec<Value> = kinds
                .iter()
                .map(|k| {
                    let (count, quoted) = &by_kind.unwrap()[k];
                    json!({ "kind": k, "marker_records": count, "records": quoted })
                })
                .collect();

            // Why the absence of (further) kinds cannot be stated, if it cannot.
            let not_assessed_reason: Option<String> = match &s.walk {
                WalkState::NoRunRecorded => Some(
                    "no ingest run recorded for this source, so whether its walk finished is not \
                     known; the absence of a marker is not a statement here"
                        .to_string(),
                ),
                WalkState::Running => Some(
                    "its walk is still running; markers not yet reached are not ruled out"
                        .to_string(),
                ),
                WalkState::Interrupted(d) | WalkState::Cancelled(d) => Some(format!(
                    "its walk did not end ({}){}; the records it had written were looked at, \
                     and what the walk never reached was not",
                    s.walk.token(),
                    d.as_deref().map(|d| format!(": {d}")).unwrap_or_default()
                )),
                WalkState::Completed if s.has_records != Some(true) => Some(
                    "its walk completed with no records recorded under it, so there was \
                     nothing to look at"
                        .to_string(),
                ),
                WalkState::Completed => None,
            }
            .or_else(|| {
                capped.then(|| {
                    format!(
                        "the listing of {} stopped at its cap, so a marker beyond it is not \
                         ruled out",
                        capped_types.join(", ")
                    )
                })
            })
            .or_else(|| {
                unread.get(&s.id).map(|stores| {
                    format!(
                        "a mobile store under it could not be read ({}), and a store not read \
                         cannot say it holds nothing",
                        stores.join(", ")
                    )
                })
            })
            .or_else(|| {
                (lost_markers > 0).then(|| {
                    format!(
                        "{lost_markers} marker record(s) in this case could not be traced to \
                         the source they came from (a missing parent, a parent in another \
                         case, or a chain deeper than {MAX_WALK}), and one may be this \
                         source's"
                    )
                })
            });

            let assessed = not_assessed_reason.is_none();
            let label = match kinds.as_slice() {
                [one] => (*one).to_string(),
                [_, _, ..] => "mixed".to_string(),
                [] if assessed => "none_recognised".to_string(),
                [] => "not_assessed".to_string(),
            };
            json!({
                "source_artifact_id": s.id,
                "name": s.name,
                "label": label,
                "kinds": kinds,
                "basis": basis,
                "assessed": assessed,
                "not_assessed_reason": not_assessed_reason,
                "walk_state": s.walk.token(),
                "has_records": s.has_records,
                "capped": capped,
            })
        })
        .collect();

    json!({
        "sources": rows,
        "looked_for": looked_for(),
        "capped_types": capped_types,
        "unattributed": lost_markers,
        "unattributed_candidates": unattributed.len(),
        "message": "A label names the kinds of mobile evidence the parsers recorded under a \
                    source, from marker records only; the source's name is never a basis. \
                    none_recognised is stated only for a source whose walk completed and \
                    produced records, with no capped listing, no unread mobile store and no \
                    marker record left untraced to its source; every other absence is \
                    not_assessed with its reason. unattributed counts the marker records \
                    whose source could not be reached; unattributed_candidates counts every \
                    listed record whose source could not be reached, markers or not.",
    })
}

/// The most marker records listed per type. A type whose listing reaches it
/// is named in `capped_types`, and no source is then called free of markers.
pub const MARKER_LISTING_CAP: usize = 2_000;

/// Assess every root in `roots` (id, display name): list the marker and
/// unread-store records case-wide, attribute each to its root by the upward
/// parent walk, take each root's walk state from its newest ingest run, and
/// compile. `source_id` scopes the response to one root.
pub async fn assess(
    db: &seance_db::SqliteConnection,
    case_id: Uuid,
    roots: Vec<(Uuid, String)>,
    source_id: Option<Uuid>,
    cap: usize,
) -> anyhow::Result<Value> {
    use seance_core::db::DatabaseConnection;

    let roots: Vec<(Uuid, String)> = roots
        .into_iter()
        .filter(|(id, _)| source_id.is_none_or(|s| s == *id))
        .collect();

    // Walk state. The orchestrator stamps a root's own record with the state
    // its run closed in (`processing_state`), which costs one read per root.
    // A root without the stamp is either still running or from before runs
    // were recorded, and only then is the ingest-run table read: that listing
    // counts every closed run's subtree at read time, measured at ~10 s on a
    // 1.75M-artifact case, which a triage label must not pay by default.
    let mut walks: BTreeMap<Uuid, WalkState> = BTreeMap::new();
    let mut unstamped = false;
    for (id, _) in &roots {
        let meta = db.get_artifact(*id).await?.map(|a| a.metadata);
        let field = |k: &str| {
            meta.as_ref()
                .and_then(|m| m.get(k))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        match field("processing_state") {
            Some(state) => {
                let detail = field("incomplete_detail");
                walks.insert(*id, WalkState::from_run(&state, detail.as_deref()));
            }
            None => unstamped = true,
        }
    }
    if unstamped {
        let mut newest: BTreeMap<Uuid, WalkState> = BTreeMap::new();
        for run in db.list_ingest_runs(case_id).await? {
            newest
                .entry(run.source_artifact_id)
                .or_insert_with(|| WalkState::from_run(&run.status, run.detail.as_deref()));
        }
        for (id, _) in &roots {
            if !walks.contains_key(id) {
                walks.insert(*id, newest.remove(id).unwrap_or(WalkState::NoRunRecorded));
            }
        }
    }

    // The candidate records, case-wide, one listing per type under the cap.
    let mut types: Vec<&str> = MARKERS.iter().map(|m| m.record_type).collect();
    types.extend(UNREAD_STORE_TYPES.iter().copied());
    types.dedup();
    let page_size = cap.clamp(1, 500) as u32;
    let mut candidates = Vec::new();
    let mut capped_types = Vec::new();
    for ty in types {
        let mut listed = 0usize;
        let mut page = 1u32;
        loop {
            let (records, total) = db
                .list_records_by_type(case_id, ty, None, page, page_size)
                .await?;
            let n = records.len();
            for r in records {
                if listed == cap {
                    break;
                }
                listed += 1;
                candidates.push(r);
            }
            if listed == cap && (total as usize) > cap {
                capped_types.push(ty.to_string());
                break;
            }
            if n < page_size as usize || listed == cap {
                break;
            }
            page += 1;
        }
    }

    // Attribute each to its root.
    let mut memo: std::collections::HashMap<Uuid, Option<(Uuid, Option<String>)>> =
        std::collections::HashMap::new();
    let mut records = Vec::with_capacity(candidates.len());
    let mut unattributed: Vec<Value> = Vec::new();
    for r in candidates {
        match root_of(db, case_id, &r, &mut memo).await? {
            Some((root, file_path)) => records.push(MarkerRecord {
                root,
                record_id: r.id,
                metadata: r.metadata,
                file_path,
            }),
            None => unattributed.push(r.metadata),
        }
    }

    let mut sources: Vec<SourceFacts> = Vec::with_capacity(roots.len());
    for (id, name) in roots {
        // Whether anything is recorded under it: one child is enough.
        let children = db
            .get_child_artifacts(case_id, Some(id), Some(1), 0)
            .await?;
        sources.push(SourceFacts {
            id,
            name,
            walk: walks.remove(&id).unwrap_or(WalkState::NoRunRecorded),
            has_records: Some(
                !children.items.is_empty() || children.has_more || children.undecodable > 0,
            ),
        });
    }
    // Records under a root outside the scope are not this response's to count.
    // Records whose root could not be reached are kept: any of them may be the
    // scoped source's, and dropping them would let it read as free of markers.
    if let Some(scope) = source_id {
        records.retain(|r| r.root == scope);
    }
    Ok(compile_source_kinds(
        &sources,
        &records,
        &capped_types,
        &unattributed,
    ))
}

/// The most parents walked from a record to its root, as the ancestors route.
const MAX_WALK: usize = 64;

/// The root a record descends from, and the path of the nearest ancestor that
/// carries one. `None` when the walk leaves the case (a parent in another case
/// is not followed — BUG-015), reaches a missing parent, or passes the depth
/// cap. `memo` maps an artifact already walked to (its root, the nearest path
/// at or above it), so records parsed from one file cost one walk.
async fn root_of(
    db: &seance_db::SqliteConnection,
    case_id: Uuid,
    record: &seance_core::artifact::Artifact,
    memo: &mut std::collections::HashMap<Uuid, Option<(Uuid, Option<String>)>>,
) -> anyhow::Result<Option<(Uuid, Option<String>)>> {
    use seance_core::db::DatabaseConnection;
    let Some(first) = record.parent_id else {
        // A record that is itself a root is attributed to itself.
        return Ok(Some((record.id, None)));
    };
    // Each artifact walked, with its own path (not its ancestors').
    let mut visited: Vec<(Uuid, Option<String>)> = Vec::new();
    // What lies above the last artifact walked: a root found, a memo hit, or
    // nothing (the walk stopped).
    let mut above: Option<(Uuid, Option<String>)> = None;
    let mut next = Some(first);
    while let Some(id) = next.take() {
        if let Some(known) = memo.get(&id) {
            above = known.clone();
            break;
        }
        if visited.len() >= MAX_WALK {
            break;
        }
        let Some(a) = db.get_artifact(id).await? else {
            break;
        };
        if a.case_id != case_id {
            break;
        }
        let own = a
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        visited.push((id, own));
        match a.parent_id {
            Some(p) => next = Some(p),
            None => above = Some((id, None)),
        }
    }
    // Fill the memo from the top down, so each entry's nearest path is the
    // first one met at or above it.
    let mut carried = above.clone();
    for (id, own) in visited.iter().rev() {
        carried = carried.map(|(root, path)| (root, own.clone().or(path)));
        memo.insert(*id, carried.clone());
    }
    Ok(carried)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(root: Uuid, metadata: Value, path: Option<&str>) -> MarkerRecord {
        MarkerRecord {
            root,
            record_id: Uuid::new_v4(),
            metadata,
            file_path: path.map(str::to_string),
        }
    }

    fn source(id: Uuid, name: &str, walk: WalkState, has_records: Option<bool>) -> SourceFacts {
        SourceFacts {
            id,
            name: name.into(),
            walk,
            has_records,
        }
    }

    fn row(out: &Value, id: Uuid) -> Value {
        out["sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["source_artifact_id"] == json!(id))
            .cloned()
            .unwrap_or_else(|| panic!("no row for {id}: {out}"))
    }

    /// The Pixel 3 case's marker set, as the parsers write it (shapes from the
    /// literal emission sites in the plugins).
    fn pixel_markers(root: Uuid) -> Vec<MarkerRecord> {
        vec![
            rec(
                root,
                json!({"type":"MobileDeviceInfo","platform":"android","source_kind":"android_settings",
                       "source_file":"/data/system/users/0/settings_system.xml"}),
                Some("/data/system/users/0/settings_system.xml"),
            ),
            rec(
                root,
                json!({"type":"BluetoothPairing","platform":"android",
                       "source_file":"/data/misc/bluedroid/bt_config.conf"}),
                Some("/data/misc/bluedroid/bt_config.conf"),
            ),
            rec(
                root,
                json!({"type":"AndroidSmsSummary","file_name":"mmssms.db","message_count":2}),
                None,
            ),
            rec(
                root,
                json!({"type":"AndroidCalendarSummary","source":"android_calendar","event_count":1}),
                None,
            ),
            rec(
                root,
                json!({"type":"AndroidNote","source":"google_keep"}),
                None,
            ),
            rec(
                root,
                json!({"type":"InstalledAppSummary","source":"packages.xml","app_count":213}),
                None,
            ),
        ]
    }

    #[test]
    fn an_android_extraction_is_labelled_from_the_records_the_parsers_wrote_and_not_from_its_file_name(
    ) {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let sources = [
            source(a, "android.tar", WalkState::Completed, Some(true)),
            source(b, "disk.raw", WalkState::Completed, Some(true)),
        ];
        let mut records = pixel_markers(a);
        records.extend(pixel_markers(b));
        let out = compile_source_kinds(&sources, &records, &[], &[]);
        let (ra, rb) = (row(&out, a), row(&out, b));
        assert_eq!(ra["label"], "android_device");
        assert_eq!(ra["kinds"], json!(["android_device"]));
        assert_eq!(ra["label"], rb["label"]);
        assert_eq!(ra["kinds"], rb["kinds"]);
        assert_eq!(
            ra["basis"].as_array().unwrap().len(),
            rb["basis"].as_array().unwrap().len()
        );
        // The basis quotes the record it rests on, never the root's name.
        let basis = ra["basis"].to_string();
        assert!(basis.contains("MobileDeviceInfo"), "{basis}");
        assert!(basis.contains("settings_system.xml"), "{basis}");
        assert!(!basis.contains("android.tar"), "{basis}");
    }

    #[test]
    fn a_mac_image_holding_an_iphone_backup_is_labelled_for_the_backup_it_holds_and_not_as_a_phone()
    {
        let mac = Uuid::new_v4();
        let sources = [source(
            mac,
            "macos2021.E01",
            WalkState::Completed,
            Some(true),
        )];
        let manifest =
            "/eliflatt/Library/Application Support/MobileSync/Backup/00008030/Manifest.plist";
        let info = "/eliflatt/Library/Application Support/MobileSync/Backup/00008030/Info.plist";
        let mut records = vec![
            rec(mac, json!({"type":"PhotoAsset"}), None),
            rec(mac, json!({"type":"iMessage"}), None),
            rec(
                mac,
                json!({"type":"InstalledAppSummary","source":"applicationState.db","app_count":2}),
                None,
            ),
        ];
        for (kind, path) in [("Manifest.plist", manifest), ("Info.plist", info)] {
            records.push(rec(
                mac,
                json!({"type":"IosBackupInfo","subtype":"manifest_in_evidence",
                       "source_kind":kind,"source_file":path}),
                Some(path),
            ));
        }
        let out = compile_source_kinds(&sources, &records, &[], &[]);
        let r = row(&out, mac);
        assert_eq!(r["label"], "ios_backup");
        assert_eq!(r["kinds"], json!(["ios_backup"]));
        assert!(!r["kinds"].to_string().contains("ios_device"));
    }

    #[test]
    fn the_macos_photo_library_the_imessage_store_and_applicationstate_db_are_not_mobile_markers() {
        let root = Uuid::new_v4();
        for metadata in [
            json!({"type":"PhotoAsset"}),
            json!({"type":"iMessage"}),
            json!({"type":"InstalledAppSummary","source":"applicationState.db"}),
            // The same stores at a Mac's paths.
            json!({"type":"PowerLogSummary","platform":"iOS"}),
            json!({"type":"CachedLocationSummary","platform":"iOS","source":"com.apple.routined"}),
        ] {
            let path = match metadata["type"].as_str().unwrap() {
                "PowerLogSummary" => {
                    Some("/private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL")
                }
                "CachedLocationSummary" => {
                    Some("/Users/eliflatt/Library/Caches/com.apple.routined/Cache.sqlite")
                }
                _ => None,
            };
            let r = rec(root, metadata.clone(), path);
            assert!(marker_for(&r).is_none(), "{metadata} is not a marker");
        }
        // And at their iOS paths they are.
        let power = rec(
            root,
            json!({"type":"PowerLogSummary","platform":"iOS"}),
            Some("/private/var/containers/Shared/SystemGroup/F3EF9636-FF64-40BB-9B94-D34F2694F64E/Library/BatteryLife/CurrentPowerlog.PLSQL"),
        );
        assert_eq!(marker_for(&power).map(|m| m.kind), Some("ios_device"));
        let routined = rec(
            root,
            json!({"type":"CachedLocationSummary","platform":"iOS","source":"com.apple.routined"}),
            Some("/private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite"),
        );
        assert_eq!(marker_for(&routined).map(|m| m.kind), Some("ios_device"));
    }

    #[test]
    fn a_source_that_produced_no_records_is_not_assessed_rather_than_not_mobile() {
        let root = Uuid::new_v4();
        let out = compile_source_kinds(
            &[source(root, "x.E01", WalkState::Completed, Some(false))],
            &[],
            &[],
            &[],
        );
        let r = row(&out, root);
        assert_eq!(r["label"], "not_assessed");
        assert_eq!(r["assessed"], false);
        assert!(r["not_assessed_reason"]
            .as_str()
            .unwrap()
            .contains("no records"));
    }

    #[test]
    fn a_source_whose_walk_was_interrupted_says_the_assessment_is_over_an_unfinished_walk() {
        let root = Uuid::new_v4();
        let out = compile_source_kinds(
            &[source(
                root,
                "x.E01",
                WalkState::Interrupted(Some("the process stopped".into())),
                Some(true),
            )],
            &[],
            &[],
            &[],
        );
        let r = row(&out, root);
        assert_eq!(r["label"], "not_assessed");
        assert_eq!(r["walk_state"], "interrupted");
        let why = r["not_assessed_reason"].as_str().unwrap();
        assert!(why.contains("did not end"), "{why}");
        assert!(why.contains("the process stopped"), "{why}");
    }

    #[test]
    fn a_source_with_no_recorded_ingest_run_is_not_assessed_even_with_records() {
        let root = Uuid::new_v4();
        let out = compile_source_kinds(
            &[source(root, "old.E01", WalkState::NoRunRecorded, None)],
            &[rec(root, json!({"type":"PhotoAsset"}), None)],
            &[],
            &[],
        );
        let r = row(&out, root);
        assert_eq!(r["label"], "not_assessed");
        assert_eq!(r["walk_state"], "no_run_recorded");
        assert!(r["not_assessed_reason"]
            .as_str()
            .unwrap()
            .contains("no ingest run recorded"));
    }

    #[test]
    fn none_recognised_requires_a_completed_run_and_a_nonzero_count_and_lists_looked_for() {
        let root = Uuid::new_v4();
        let out = compile_source_kinds(
            &[source(root, "linux.E01", WalkState::Completed, Some(true))],
            &[],
            &[],
            &[],
        );
        let r = row(&out, root);
        assert_eq!(r["label"], "none_recognised");
        assert_eq!(r["assessed"], true);
        assert_eq!(r["kinds"], json!([]));
        assert!(r["not_assessed_reason"].is_null());
        let looked_for = out["looked_for"].as_array().unwrap();
        assert_eq!(looked_for.len(), MARKERS.len());
        assert!(looked_for
            .iter()
            .any(|m| m["record_type"] == "MobileDeviceInfo" && m["kind"] == "android_device"));
    }

    #[test]
    fn an_assessment_that_hit_its_record_cap_says_so() {
        let root = Uuid::new_v4();
        let other = Uuid::new_v4();
        let out = compile_source_kinds(
            &[
                source(root, "a", WalkState::Completed, Some(true)),
                source(other, "b", WalkState::Completed, Some(true)),
            ],
            &[rec(
                other,
                json!({"type":"BluetoothPairing","platform":"android"}),
                None,
            )],
            &["BluetoothPairing".to_string()],
            &[],
        );
        assert_eq!(out["capped_types"], json!(["BluetoothPairing"]));
        let r = row(&out, root);
        assert_eq!(r["label"], "not_assessed");
        assert_eq!(r["capped"], true);
        assert!(r["not_assessed_reason"].as_str().unwrap().contains("cap"));
        // What was found is still reported.
        let o = row(&out, other);
        assert_eq!(o["label"], "android_device");
        assert_eq!(o["capped"], true);
        assert_eq!(o["assessed"], false);
    }

    #[test]
    fn a_marker_found_on_an_unfinished_walk_is_still_reported() {
        let root = Uuid::new_v4();
        for walk in [
            WalkState::Running,
            WalkState::Interrupted(None),
            WalkState::Cancelled(None),
            WalkState::NoRunRecorded,
        ] {
            let out = compile_source_kinds(
                &[source(root, "p", walk.clone(), None)],
                &pixel_markers(root),
                &[],
                &[],
            );
            let r = row(&out, root);
            assert_eq!(r["label"], "android_device", "{walk:?}");
            assert_eq!(r["assessed"], false, "{walk:?}");
            assert!(r["not_assessed_reason"].is_string(), "{walk:?}");
        }
    }

    #[test]
    fn two_kinds_in_one_source_are_mixed_and_list_both() {
        let root = Uuid::new_v4();
        let mut records = pixel_markers(root);
        records.push(rec(
            root,
            json!({"type":"IosBackupInfo","subtype":"manifest_in_evidence"}),
            Some("/sdcard/Backup/Manifest.plist"),
        ));
        let out = compile_source_kinds(
            &[source(root, "p", WalkState::Completed, Some(true))],
            &records,
            &[],
            &[],
        );
        let r = row(&out, root);
        assert_eq!(r["label"], "mixed");
        assert_eq!(r["kinds"], json!(["android_device", "ios_backup"]));
    }

    #[test]
    fn an_unread_mobile_store_stops_a_source_being_called_free_of_mobile_evidence() {
        let root = Uuid::new_v4();
        let out = compile_source_kinds(
            &[source(root, "p", WalkState::Completed, Some(true))],
            &[rec(
                root,
                json!({"type":"IosArtifactParseStatus","status":"DatabaseUnreadable",
                       "file_name":"sms.db"}),
                None,
            )],
            &[],
            &[],
        );
        let r = row(&out, root);
        assert_eq!(r["label"], "not_assessed");
        assert!(r["not_assessed_reason"]
            .as_str()
            .unwrap()
            .contains("sms.db"));
    }

    #[test]
    fn records_whose_root_could_not_be_reached_are_counted_not_dropped() {
        let lost = vec![json!({"type":"AndroidSmsSummary"}); 3];
        let out = compile_source_kinds(&[], &[], &[], &lost);
        assert_eq!(out["unattributed"], 3);
    }

    fn completed(root: Uuid) -> Vec<SourceFacts> {
        vec![source(root, "x.E01", WalkState::Completed, Some(true))]
    }

    /// A real marker that lost its way to a root may belong to any source, so
    /// no source can be called free of markers while it is outstanding.
    #[test]
    fn a_marker_whose_root_could_not_be_reached_stops_every_source_being_none_recognised() {
        let root = Uuid::new_v4();
        let lost = [
            json!({"type":"AndroidSmsSummary","file_name":"mmssms.db"}),
            json!({"type":"IosBackupInfo","subtype":"manifest_in_evidence"}),
        ];
        let out = compile_source_kinds(&completed(root), &[], &[], &lost);
        let r = row(&out, root);
        assert_eq!(r["label"], "not_assessed", "{out}");
        assert_eq!(r["assessed"], false);
        let reason = r["not_assessed_reason"].as_str().unwrap();
        assert!(reason.contains("2 marker record(s)"), "{reason}");
        assert_eq!(out["unattributed"], 2, "{out}");
    }

    #[test]
    fn an_unread_store_whose_root_could_not_be_reached_also_stops_none_recognised() {
        let root = Uuid::new_v4();
        let lost = [json!({"type":"IosArtifactParseStatus","file_name":"sms.db"})];
        let out = compile_source_kinds(&completed(root), &[], &[], &lost);
        assert_eq!(row(&out, root)["label"], "not_assessed", "{out}");
    }

    /// Candidates that are not markers (applicationState.db, a Mac PowerLog)
    /// are listed only to be rejected; losing one loses no marker.
    #[test]
    fn an_unattributed_candidate_that_is_not_a_marker_neither_blocks_nor_counts() {
        let root = Uuid::new_v4();
        let lost = [
            json!({"type":"InstalledAppSummary","source":"applicationState.db"}),
            json!({"type":"PowerLogSummary","platform":"iOS",
                   "source_file":"/private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL"}),
        ];
        let out = compile_source_kinds(&completed(root), &[], &[], &lost);
        assert_eq!(row(&out, root)["label"], "none_recognised", "{out}");
        assert_eq!(out["unattributed"], 0, "{out}");
        assert_eq!(out["unattributed_candidates"], 2, "{out}");
    }

    /// The reasons are read aloud and put in a tooltip: no run of spaces
    /// from a line-continued literal may reach them.
    #[test]
    fn no_not_assessed_reason_carries_a_run_of_spaces() {
        let root = Uuid::new_v4();
        let walks = [
            WalkState::NoRunRecorded,
            WalkState::Running,
            WalkState::Interrupted(Some("stopped".into())),
            WalkState::Cancelled(None),
        ];
        let mut reasons = Vec::new();
        for walk in walks {
            let out = compile_source_kinds(&[source(root, "x", walk, Some(true))], &[], &[], &[]);
            reasons.push(row(&out, root)["not_assessed_reason"].clone());
        }
        let out = compile_source_kinds(
            &[source(root, "x", WalkState::Completed, Some(false))],
            &[],
            &[],
            &[],
        );
        reasons.push(row(&out, root)["not_assessed_reason"].clone());
        let out = compile_source_kinds(&completed(root), &[], &["AndroidNote".into()], &[]);
        reasons.push(row(&out, root)["not_assessed_reason"].clone());
        let unread = [rec(
            root,
            json!({"type":"IosArtifactParseStatus","file_name":"sms.db"}),
            None,
        )];
        let out = compile_source_kinds(&completed(root), &unread, &[], &[]);
        reasons.push(row(&out, root)["not_assessed_reason"].clone());
        let lost = [json!({"type":"AndroidSmsSummary"})];
        let out = compile_source_kinds(&completed(root), &[], &[], &lost);
        reasons.push(row(&out, root)["not_assessed_reason"].clone());
        for r in reasons {
            let r = r.as_str().unwrap_or_else(|| panic!("no reason: {r}"));
            assert!(!r.contains("  "), "a run of spaces in: {r:?}");
        }
    }
}
