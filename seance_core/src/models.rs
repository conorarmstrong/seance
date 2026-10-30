use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CaseResponse {
    pub id: Uuid,
    pub name: String,
    pub status: String,
    pub reference_number: Option<String>,
    pub examiner_name: Option<String>,
    pub created_at: String,
    pub last_accessed_at: Option<String>,
}

/// Examiner and handling detail for a court-standard report.
///
/// Separate from [`CaseResponse`] because it has one consumer. Every field is
/// optional and absent when never recorded, so a report omits it rather than
/// asserting a default.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CaseExaminerDetails {
    pub role: Option<String>,
    pub organisation: Option<String>,
    pub contact: Option<String>,
    pub qualifications: Option<String>,
    /// Handling marking for the report, e.g. "RESTRICTED".
    pub report_classification: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateCaseRequest {
    pub name: Option<String>,
    pub reference_number: Option<String>,
    pub examiner_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateCaseRequest {
    pub name: Option<String>,
    pub reference_number: Option<String>,
    pub examiner_name: Option<String>,
    // Court-report detail. Absent from the request means "leave unchanged",
    // which is why these are Option like everything else here.
    pub examiner_role: Option<String>,
    pub examiner_organisation: Option<String>,
    pub examiner_contact: Option<String>,
    pub examiner_qualifications: Option<String>,
    pub report_classification: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CaseStats {
    pub total_artifacts: i64,
    pub artifact_counts_by_type: std::collections::HashMap<String, i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimelineEventResponse {
    pub id: Uuid,
    pub case_id: Uuid,
    pub artifact_id: Uuid,
    pub timestamp: i64,
    /// Sub-second component of `timestamp` in nanoseconds (0..=999_999_999).
    /// 0 for whole-second sources (D5).
    #[serde(default)]
    pub timestamp_subsec_nanos: i64,
    /// Seconds east of UTC of the source's timezone, or None when the source
    /// supplied a bare Unix-integer timestamp with no recoverable offset (D6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_utc_offset_seconds: Option<i32>,
    pub timestamp_desc: String,
    pub source_module: String,
    pub short_desc: String,
    pub full_details: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_tagged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic_fields: Option<std::collections::HashMap<String, serde_json::Value>>,
}

/// One GPS point for the interactive case map. Serializes to the shape the
/// frontend `GpsPoint` expects (`type`, `sourceName`), so the map can render
/// straight from a single request instead of scanning every record type client
/// side (which also silently capped at 500 records/type).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GeoMapPoint {
    /// Record artifact id (also the jump-to-artifact target).
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub lat: f64,
    pub lon: f64,
    pub camera: Option<String>,
    pub timestamp: Option<String>,
    #[serde(rename = "sourceName")]
    pub source_name: Option<String>,
    /// Artifact id of the image these coordinates came from (the EXIF record's
    /// parent FileEntry), for a thumbnail preview. None for non-photo points.
    #[serde(rename = "imageId")]
    pub image_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaginatedTimelineResponse {
    pub events: Vec<TimelineEventResponse>,
    pub pagination: PaginationMetadata,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaginationMetadata {
    pub total_count: i64,
    pub page: i64,
    pub page_size: i64,
    pub total_pages: i64,
    pub has_next: bool,
    pub has_previous: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
pub struct TimelineTag {
    #[sqlx(try_from = "Vec<u8>")]
    pub id: Uuid,
    #[sqlx(try_from = "Vec<u8>")]
    pub case_id: Uuid,
    #[sqlx(try_from = "Vec<u8>")]
    pub event_id: Uuid,
    pub examiner: Option<String>,
    pub note: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateTagRequest {
    pub event_id: Uuid,
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateTagRequest {
    pub note: String,
}

// JSON Field Schema Discovery
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimelineSchemaField {
    pub path: String,
    pub field_type: String,
    pub frequency: i64,
    pub sample_value: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimelineSchema {
    pub available_fields: Vec<TimelineSchemaField>,
    /// True when the fields were discovered from a SAMPLE of the case's events
    /// rather than all of them.
    ///
    /// Field discovery reads a bounded number of events. On a case with more
    /// events than that, a field that appears only in the unread remainder is
    /// missing from this list entirely, and every `frequency` is a count within
    /// the sample, not a prevalence in the case. Without this flag a filter UI
    /// presents a partial field list as the complete schema of the evidence.
    #[serde(default)]
    pub sampled: bool,
    /// How many events were actually read to build this schema.
    #[serde(default)]
    pub sample_size: i64,
    /// How many timeline events the case holds in total.
    #[serde(default)]
    pub total_events: i64,
    /// Events in the sample whose `full_details` could not be read or parsed as
    /// a JSON object, and so contributed no fields. Non-zero means the sample
    /// itself is short.
    #[serde(default)]
    pub undecodable_events: i64,
}

// Bookmark System Models

/// Category (folder) for organizing bookmarks. A folder may sit under another
/// folder of the same case (`parent_id`); the top level has none.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkCategory {
    pub id: Uuid,
    pub case_id: Uuid,
    pub name: String,
    pub color: String,
    pub created_at: i64,
    /// The folder this one sits under, or `None` at the top level.
    #[serde(default)]
    pub parent_id: Option<Uuid>,
}

/// Generic artifact bookmark with notes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBookmark {
    pub id: Uuid,
    pub case_id: Uuid,
    pub artifact_id: Uuid,
    pub category_id: Option<Uuid>,
    pub category_name: Option<String>, // Denormalized for convenience
    pub category_color: Option<String>,
    pub note: Option<String>,
    pub examiner: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Bookmark with artifact details for list views
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkWithArtifact {
    pub bookmark: ArtifactBookmark,
    pub artifact_type: String,
    pub artifact_name: String,
    /// Source path within the evidence (provenance for a finding), if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    /// Byte offset of the artifact within its source evidence (provenance for
    /// independently re-verifying a finding), if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_offset: Option<i64>,
}

// Hash Set Models

/// Information about a hash set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashSetInfo {
    pub id: Uuid,
    pub case_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub set_type: String,       // "known" or "notable"
    pub hash_algorithm: String, // "md5", "sha1", "sha256"
    pub entry_count: i64,
    pub imported_at: i64,
}

/// Result of a hash lookup against hash sets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashSetMatch {
    pub hash_value: String,
    pub hash_set_name: String,
    pub hash_set_id: Uuid,
    pub set_type: String,
    pub product_name: Option<String>,
}

/// Each folder's full path, `Parent / Child`, keyed by folder id.
///
/// Two folders may share a name under different parents, so a report that names
/// a bookmark's folder by its own name alone would not say which one. A folder
/// whose ancestry cannot be followed to the top (a parent missing from
/// `categories`, or a cycle) is given the path it could be followed to and is
/// marked with a leading `…/`, so a broken chain is visible rather than passed
/// off as a top-level folder. Distinct folders whose paths would read the same
/// (same-named siblings) get a ` [xxxxxxxx]` suffix, the start of the folder
/// id, so two folders are never one path.
pub fn bookmark_folder_paths(
    categories: &[BookmarkCategory],
) -> std::collections::HashMap<Uuid, String> {
    let by_id: std::collections::HashMap<Uuid, &BookmarkCategory> =
        categories.iter().map(|c| (c.id, c)).collect();
    let mut paths: std::collections::HashMap<Uuid, String> = categories
        .iter()
        .map(|c| {
            let mut names = vec![c.name.as_str()];
            let mut seen = std::collections::HashSet::from([c.id]);
            let mut next = c.parent_id;
            let mut complete = true;
            while let Some(pid) = next {
                match by_id.get(&pid) {
                    Some(p) if seen.insert(pid) => {
                        names.push(p.name.as_str());
                        next = p.parent_id;
                    }
                    _ => {
                        complete = false;
                        break;
                    }
                }
            }
            names.reverse();
            let joined = names.join(" / ");
            (
                c.id,
                if complete {
                    joined
                } else {
                    format!("…/ {joined}")
                },
            )
        })
        .collect();
    // Two distinct folders that spell the same path (same-named siblings) would
    // be indistinguishable in a report. Tell them apart by the start of their
    // id, so a bookmark's folder is never ambiguous; unique paths are untouched.
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for path in paths.values() {
        *counts.entry(path.clone()).or_default() += 1;
    }
    for (id, path) in paths.iter_mut() {
        if counts.get(path.as_str()).copied().unwrap_or(0) > 1 {
            let short = id.simple().to_string();
            path.push_str(&format!(" [{}]", &short[..8]));
        }
    }
    paths
}

#[cfg(test)]
mod folder_path_tests {
    use super::*;

    fn folder(name: &str, parent: Option<Uuid>) -> BookmarkCategory {
        BookmarkCategory {
            id: Uuid::new_v4(),
            case_id: Uuid::nil(),
            name: name.into(),
            color: "#000".into(),
            created_at: 0,
            parent_id: parent,
        }
    }

    #[test]
    fn a_nested_folder_is_named_by_its_whole_path() {
        let top = folder("Exfiltration", None);
        let mid = folder("USB", Some(top.id));
        let leaf = folder("Device A", Some(mid.id));
        let paths = bookmark_folder_paths(&[leaf.clone(), top.clone(), mid.clone()]);
        assert_eq!(paths[&top.id], "Exfiltration");
        assert_eq!(paths[&leaf.id], "Exfiltration / USB / Device A");
    }

    #[test]
    fn two_folders_with_one_name_stay_distinguishable() {
        let a = folder("Notes", None);
        let b = folder("Notes", None);
        let under_a = folder("Misc", Some(a.id));
        let under_b = folder("Misc", Some(b.id));
        let paths =
            bookmark_folder_paths(&[a.clone(), b.clone(), under_a.clone(), under_b.clone()]);
        assert_ne!(paths[&under_a.id], paths[&under_b.id]);
        assert!(paths[&under_a.id].starts_with("Notes / Misc ["));
        assert!(paths[&under_b.id].starts_with("Notes / Misc ["));
        // A path nothing else shares is left as it was.
        let lone = folder("Solo", None);
        assert_eq!(
            bookmark_folder_paths(std::slice::from_ref(&lone))[&lone.id],
            "Solo"
        );
    }

    #[test]
    fn a_broken_chain_is_marked_not_shown_as_top_level() {
        let orphan = folder("Lost", Some(Uuid::new_v4()));
        let paths = bookmark_folder_paths(std::slice::from_ref(&orphan));
        assert_eq!(paths[&orphan.id], "…/ Lost");
    }

    #[test]
    fn a_cycle_terminates_and_is_marked() {
        let mut a = folder("A", None);
        let b = folder("B", Some(a.id));
        a.parent_id = Some(b.id);
        let paths = bookmark_folder_paths(&[a.clone(), b.clone()]);
        assert!(paths[&a.id].starts_with("…/"), "{}", paths[&a.id]);
        assert!(paths[&b.id].starts_with("…/"), "{}", paths[&b.id]);
    }
}
