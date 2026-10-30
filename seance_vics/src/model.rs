//! The VICS data model: import and export of the Project VIC / CAID JSON.
//!
//! The VICS model is an OData-shaped document with a top-level `value` array of
//! media objects. Real files carry more fields than any one tool consumes, so
//! the design rule here is **lossless round-trip**: the fields Séance acts on
//! (hashes, category, victim/series/tags) are modelled explicitly, and every
//! other field is preserved verbatim in [`VicsMedia::extra`] so an import →
//! categorise → export cycle never silently drops a partner's data.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Errors from reading or writing a VICS document.
#[derive(Debug, thiserror::Error)]
pub enum VicsError {
    #[error("VICS JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    /// The document parsed but is not a VICS file (no `value` array, or the
    /// legacy flat form when the OData form was required).
    #[error("not a recognised VICS document: {0}")]
    NotVics(String),
}

/// A VIC media category.
///
/// The number is the wire value shared between tools; the friendly name is what
/// an examiner reads. The VIC scheme's canonical numbering is modelled by
/// [`Category::friendly_name`] as a convenience, but an unknown number is kept
/// rather than rejected — the scheme is extended over time and a file from a
/// newer model must survive a round trip through an older build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Category(pub i64);

impl Category {
    /// The canonical Project VIC friendly name for the well-known categories,
    /// or `None` for a number this build does not recognise.
    ///
    /// Numbering follows the Project VIC US scheme. Categories 1 and 2 are the
    /// pertinent CSAM tiers; the rest classify non-pertinent or comparison
    /// material. A `None` return is not an error — see the type note.
    pub fn friendly_name(self) -> Option<&'static str> {
        Some(match self.0 {
            0 => "Non-pertinent",
            1 => "CAM — Child Abuse Material",
            2 => "Child Exploitive / Age Difficult (Non-CAM)",
            3 => "CGI / Animation (child)",
            4 => "Comparison / known adult",
            _ => return None,
        })
    }

    /// Whether this category denotes pertinent CSAM under the VIC scheme
    /// (categories 1 and 2). Used only to drive triage counts and the
    /// blur-by-default review controls, never to make an assertion about a file.
    pub fn is_pertinent(self) -> bool {
        matches!(self.0, 1 | 2)
    }
}

/// One media object in a VICS file.
///
/// Field names match the VICS/OData model so serde reads and writes real files.
/// Everything not modelled explicitly is captured in [`Self::extra`] and written
/// back unchanged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VicsMedia {
    /// Stable media identifier (GUID) from the originating tool.
    #[serde(rename = "MediaID", skip_serializing_if = "Option::is_none", default)]
    pub media_id: Option<String>,

    /// VIC category. Absent in a not-yet-categorised export.
    #[serde(rename = "Category", skip_serializing_if = "Option::is_none", default)]
    pub category: Option<Category>,

    /// MD5, lower-case hex. The primary matching key in most VIC/CAID sets.
    #[serde(rename = "MD5", skip_serializing_if = "Option::is_none", default)]
    pub md5: Option<String>,

    /// SHA-1, lower-case hex.
    #[serde(rename = "SHA1", skip_serializing_if = "Option::is_none", default)]
    pub sha1: Option<String>,

    /// PhotoDNA robust hash, base64. Modelled so it round-trips; Séance does not
    /// compute or interpret it without a licensed back-end (see [`crate::robust`]).
    #[serde(rename = "PhotoDNA", skip_serializing_if = "Option::is_none", default)]
    pub photodna: Option<String>,

    /// Whether the depicted victim has been identified — the field that lets a
    /// unit focus effort on *unknown* victims.
    #[serde(
        rename = "VictimIdentified",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub victim_identified: Option<bool>,

    /// Named series/collection this media belongs to.
    #[serde(rename = "Series", skip_serializing_if = "Option::is_none", default)]
    pub series: Option<String>,

    /// Free-form tags shared between partners.
    #[serde(rename = "Tags", skip_serializing_if = "Vec::is_empty", default)]
    pub tags: Vec<String>,

    /// Every field not modelled above, preserved verbatim for lossless export.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl VicsMedia {
    /// A minimal categorised entry keyed by MD5 — the common case when Séance
    /// exports its own categorisations.
    pub fn from_md5(md5: impl Into<String>, category: Category) -> Self {
        Self {
            media_id: None,
            category: Some(category),
            md5: Some(md5.into()),
            sha1: None,
            photodna: None,
            victim_identified: None,
            series: None,
            tags: Vec::new(),
            extra: BTreeMap::new(),
        }
    }
}

/// A whole VICS document.
///
/// The OData envelope fields (`odata.metadata` and friends) are captured in
/// [`Self::envelope`] and written back unchanged, so a file from a partner tool
/// keeps its provenance metadata through a round trip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VicsFile {
    /// The media objects.
    pub value: Vec<VicsMedia>,

    /// OData envelope keys (e.g. `odata.metadata`), preserved verbatim.
    #[serde(flatten)]
    pub envelope: BTreeMap<String, serde_json::Value>,
}

impl VicsFile {
    /// Parse a VICS document from JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, VicsError> {
        // Distinguish "malformed JSON" from "valid JSON that is not VICS": the
        // latter is the far more common operator error (pointing at the wrong
        // file) and deserves a message that says so rather than a serde
        // "missing field `value`" that reads as a bug.
        let doc: serde_json::Value = serde_json::from_slice(bytes)?;
        if !doc.get("value").map(|v| v.is_array()).unwrap_or(false) {
            return Err(VicsError::NotVics(
                "top-level object has no `value` array".to_string(),
            ));
        }
        Ok(serde_json::from_value(doc)?)
    }

    /// Serialise to pretty JSON bytes suitable for a VICS export folder.
    pub fn to_json(&self) -> Result<Vec<u8>, VicsError> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    /// Build a document from a set of Séance categorisations keyed by MD5.
    pub fn from_categorisations(entries: impl IntoIterator<Item = (String, Category)>) -> Self {
        Self {
            value: entries
                .into_iter()
                .map(|(md5, cat)| VicsMedia::from_md5(md5, cat))
                .collect(),
            envelope: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic VICS document with the OData envelope, extra media fields,
    /// and a mix of populated/absent optionals — the shape a partner tool emits.
    const SAMPLE: &str = r#"{
        "odata.metadata": "http://projectvic.org/$metadata#Media",
        "value": [
            {
                "MediaID": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
                "Category": 1,
                "MD5": "d41d8cd98f00b204e9800998ecf8427e",
                "SHA1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "PhotoDNA": "AAECAwQF",
                "VictimIdentified": false,
                "Series": "Operation Example",
                "Tags": ["reviewed", "priority"],
                "SubmittedBy": "agency-x",
                "IsDistributed": true
            }
        ]
    }"#;

    #[test]
    fn round_trip_preserves_every_field() {
        let file = VicsFile::from_json(SAMPLE.as_bytes()).expect("parse");
        assert_eq!(file.value.len(), 1);
        let m = &file.value[0];
        assert_eq!(m.category, Some(Category(1)));
        assert_eq!(m.md5.as_deref(), Some("d41d8cd98f00b204e9800998ecf8427e"));
        assert_eq!(m.photodna.as_deref(), Some("AAECAwQF"));
        assert_eq!(m.victim_identified, Some(false));
        assert_eq!(m.tags, vec!["reviewed", "priority"]);
        // Unmodelled media fields survive in `extra`.
        assert_eq!(
            m.extra.get("SubmittedBy").and_then(|v| v.as_str()),
            Some("agency-x")
        );
        assert_eq!(
            m.extra.get("IsDistributed").and_then(|v| v.as_bool()),
            Some(true)
        );
        // OData envelope survives at the top level.
        assert!(file.envelope.contains_key("odata.metadata"));

        // Re-serialise and re-parse: the model must be a fixed point.
        let bytes = file.to_json().expect("serialise");
        let again = VicsFile::from_json(&bytes).expect("reparse");
        assert_eq!(file, again, "round trip must be lossless");
    }

    #[test]
    fn category_survives_import_categorise_export() {
        // Start uncategorised, categorise, export, re-import: the category is
        // exactly what we set. This is the interop half the comparison called out.
        let doc = VicsFile::from_categorisations([(
            "5d41402abc4b2a76b9719d911017c592".to_string(),
            Category(2),
        )]);
        let bytes = doc.to_json().unwrap();
        let back = VicsFile::from_json(&bytes).unwrap();
        assert_eq!(back.value[0].category, Some(Category(2)));
        assert_eq!(
            back.value[0].md5.as_deref(),
            Some("5d41402abc4b2a76b9719d911017c592")
        );
    }

    #[test]
    fn friendly_names_for_known_categories_and_none_for_unknown() {
        assert_eq!(
            Category(1).friendly_name(),
            Some("CAM — Child Abuse Material")
        );
        assert_eq!(Category(0).friendly_name(), Some("Non-pertinent"));
        assert_eq!(Category(99).friendly_name(), None); // future scheme value
        assert!(Category(1).is_pertinent());
        assert!(Category(2).is_pertinent());
        assert!(!Category(0).is_pertinent());
        assert!(!Category(4).is_pertinent());
    }

    #[test]
    fn a_future_category_number_round_trips_unrecognised() {
        // A number this build has no name for must not be lost or rejected.
        let json = r#"{"value":[{"MD5":"aa","Category":42}]}"#;
        let file = VicsFile::from_json(json.as_bytes()).unwrap();
        assert_eq!(file.value[0].category, Some(Category(42)));
        let bytes = file.to_json().unwrap();
        let back = VicsFile::from_json(&bytes).unwrap();
        assert_eq!(back.value[0].category, Some(Category(42)));
    }

    #[test]
    fn valid_json_that_is_not_vics_is_reported_clearly() {
        let err = VicsFile::from_json(br#"{"hello":"world"}"#).unwrap_err();
        assert!(matches!(err, VicsError::NotVics(_)));
        // A flat MD5 list is valid JSON but not the OData form.
        let err = VicsFile::from_json(br#"["aa","bb"]"#).unwrap_err();
        assert!(matches!(err, VicsError::NotVics(_)));
    }

    #[test]
    fn malformed_json_is_distinct_from_not_vics() {
        let err = VicsFile::from_json(b"{ not json").unwrap_err();
        assert!(matches!(err, VicsError::Json(_)));
    }

    #[test]
    fn empty_optionals_are_omitted_not_written_as_null() {
        // A minimal entry must not emit a wall of `null`s that a strict partner
        // parser might reject.
        let doc = VicsFile::from_categorisations([("abc".to_string(), Category(1))]);
        let text = String::from_utf8(doc.to_json().unwrap()).unwrap();
        assert!(!text.contains("null"), "no null fields: {text}");
        assert!(!text.contains("SHA1"));
        assert!(text.contains("MD5"));
        assert!(text.contains("Category"));
    }
}
