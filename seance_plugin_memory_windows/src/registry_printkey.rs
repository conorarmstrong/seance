//! `printkey`: resolve a key path inside a hive and list what is under it.
//!
//! The registry has no path index. A path is resolved the way the kernel
//! resolves it: start at the root key the hive's base block names, enumerate
//! that key's subkeys, find the one whose name matches the first component,
//! and repeat. Every step is a walk of a subkey index, so every step can fail
//! in the ways [`crate::registry::key::CellReader::subkeys`] documents, and
//! this module's job is to make sure that a failure at step three is never
//! reported as "the key does not exist".
//!
//! # Absence is a claim, and it needs evidence
//!
//! "`\Software\Microsoft\Windows\CurrentVersion\Run` has no values" is an
//! assertion about the suspect's machine. It is only true if the enumeration
//! that produced it was complete. When a subkey index cell was paged out, the
//! honest answer is that the key was not found *and the search was not
//! exhaustive*, which is why [`RegistryError::KeyNotFound`] carries that
//! distinction in the message an examiner reads.
//!
//! # Name comparison
//!
//! Registry key names are case-insensitive, so the match is too. The comparison
//! is a simple lowercase fold, which is what Windows does for the ASCII names
//! that key paths are made of in practice; it is not full Unicode case folding,
//! and a name that differs only in the case of a non-ASCII character will not
//! match. Stated here because a silent non-match would look like a missing key.

use std::sync::Arc;

use seance_memory::meta::Incomplete;

use crate::profile::{Evidence, WindowsProfile};
use crate::registry::error::RegistryError;
use crate::registry::key::{CellReader, KeyNode, Subkeys, ValueData, Values};
use crate::registry::space::HiveSpace;

/// Ceiling on the components of a key path.
///
/// The deepest paths Windows itself uses are around fifteen components. Sixty
/// four is far beyond anything real and far below a path that could be used to
/// make this walk expensive.
pub const MAX_PATH_DEPTH: usize = 64;

/// One key, everything under it, and how the walk that found it went.
#[derive(Debug, Clone)]
pub struct KeyListing {
    /// Address of the `_CMHIVE` the key came from.
    ///
    /// Provenance, and not decoration: cell indices are per-hive, so a key path
    /// without a hive address does not identify anything.
    pub hive: u64,
    /// The path as resolved, joined with backslashes, starting at the root
    /// key's own name.
    pub path: String,
    /// Every key from the hive root to this one.
    pub chain: Vec<KeyNode>,
    /// The key the path named.
    pub node: KeyNode,
    /// Its subkeys.
    pub subkeys: Subkeys,
    /// Its values.
    pub values: Values,
    /// How the hive's root cell was established, which every key below it
    /// inherits: a tree hanging off a probed root is weaker evidence than one
    /// hanging off a root the hive stated itself.
    pub root_evidence: Evidence,
}

impl KeyListing {
    /// Whether everything under this key was recovered.
    ///
    /// Three separate things have to hold, and a value whose *data* was paged
    /// out counts against it just as much as a subkey index that could not be
    /// walked: a listing where one value's contents are missing is not a
    /// complete listing, however complete the list of names is.
    pub fn is_complete(&self) -> bool {
        self.subkeys.is_complete()
            && self.values.is_complete()
            && self
                .values
                .values
                .iter()
                .all(|value| value.data.is_available())
    }

    /// Everything that stopped this listing being exhaustive.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut all = self.subkeys.incomplete.clone();
        all.extend(self.values.incomplete.iter().cloned());
        for value in &self.values.values {
            if let ValueData::Unavailable(incomplete) = &value.data {
                all.push(Incomplete::new(
                    incomplete.reason,
                    format!(
                        "the data of the value '{}' could not be read: {}",
                        value.name.text, incomplete.detail
                    ),
                ));
            }
        }
        all
    }

    /// Serializable form for the printkey artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "hive": self.hive,
            "path": self.path,
            "root_evidence": self.root_evidence.as_str(),
            "complete": self.is_complete(),
            "key": self.node.to_json(),
            "subkeys": self.subkeys.keys.iter().map(KeyNode::to_json).collect::<Vec<_>>(),
            "subkeys_declared": self.subkeys.declared,
            "values": self.values.values.iter().map(|value| value.to_json()).collect::<Vec<_>>(),
            "values_declared": self.values.declared,
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Split a key path into its components, ignoring empty ones.
///
/// `\Software\\Microsoft\` and `Software\Microsoft` name the same key, and a
/// caller that pasted a path out of `regedit` should not get a different answer
/// from one that typed it.
pub fn path_components(path: &str) -> Vec<&str> {
    path.split('\\')
        .filter(|component| !component.is_empty())
        .collect()
}

/// Resolve a key path, returning every key from the hive root to the target.
///
/// `path` of `None`, or one with no components, resolves to the root key
/// itself.
///
/// # Errors
///
/// [`RegistryError::KeyNotFound`] naming the first component that did not
/// resolve and how far the walk got, and saying whether the search that failed
/// was itself complete.
pub fn resolve_key(reader: &CellReader, path: Option<&str>) -> Result<Vec<KeyNode>, RegistryError> {
    let root = reader.hive().root_cell()?;
    let mut chain = vec![reader.key_node(root.value)?];

    let components = path.map(path_components).unwrap_or_default();
    if components.len() > MAX_PATH_DEPTH {
        return Err(RegistryError::Cap {
            what: "components in a registry key path",
            cap: MAX_PATH_DEPTH as u64,
        });
    }

    for component in components {
        // `chain` is never empty: it starts with the root and only grows.
        let Some(parent) = chain.last() else {
            return Err(RegistryError::Malformed(
                "the key path walk lost its way with no key to continue from".to_string(),
            ));
        };
        let subkeys = reader.subkeys(parent);
        let wanted = component.to_lowercase();
        let found = subkeys
            .keys
            .into_iter()
            .find(|key| key.name.text.to_lowercase() == wanted);
        match found {
            Some(key) => chain.push(key),
            None => {
                return Err(RegistryError::KeyNotFound {
                    found: join_names(&chain),
                    missing: component.to_string(),
                    certainty: if subkeys.incomplete.is_empty() {
                        "that key's subkey index was read in full, so the subkey was not there"
                    } else {
                        "that key's subkey index could not be read in full, so this is not proof \
                         that the subkey was absent"
                    },
                })
            }
        }
    }
    Ok(chain)
}

/// Resolve a key path and list its subkeys and values.
pub fn print_key(reader: &CellReader, path: Option<&str>) -> Result<KeyListing, RegistryError> {
    let root_evidence = reader.hive().root_cell()?.evidence;
    let chain = resolve_key(reader, path)?;
    let Some(node) = chain.last().cloned() else {
        return Err(RegistryError::Malformed(
            "the key path resolved to no key at all".to_string(),
        ));
    };
    let subkeys = reader.subkeys(&node);
    let values = reader.values(&node);
    Ok(KeyListing {
        hive: reader.hive().cmhive_address(),
        path: join_names(&chain),
        chain,
        node,
        subkeys,
        values,
        root_evidence,
    })
}

/// Open the hive at `cmhive` and list one key inside it.
///
/// The whole of `printkey` in one call, for a caller that has a hive address
/// from [`crate::registry::hivelist::list_hives`] and a path.
///
/// The hive is opened with [`HiveSpace::open_for_image`], so on Windows 10
/// build 17063 and later the bins are read through the Registry process the
/// kernel maps them into. Opening against the kernel's space there yields a
/// hive whose cells are almost all holes, which reads as a registry that was
/// almost entirely empty.
pub fn print_key_in_hive(
    profile: &WindowsProfile,
    cmhive: u64,
    path: Option<&str>,
) -> Result<KeyListing, RegistryError> {
    let hive = HiveSpace::open_for_image(profile, cmhive)?;
    let reader = CellReader::new(Arc::clone(&hive))?;
    print_key(&reader, path)
}

/// Join a chain of keys into a backslash-separated path.
fn join_names(chain: &[KeyNode]) -> String {
    chain
        .iter()
        .map(|key| key.name.text.as_str())
        .collect::<Vec<_>>()
        .join("\\")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::key::{RegValueType, RegistryData};
    use crate::registry::test_support::{xp_profile, XP_CMHIVE, XP_UNNAMED_CMHIVE};

    fn reader() -> CellReader {
        let profile = xp_profile();
        let hive = HiveSpace::open(&profile, XP_CMHIVE).expect("the fixture hive opens");
        CellReader::new(hive).expect("the fixture symbols describe the registry types")
    }

    #[test]
    fn a_path_splits_the_same_way_however_a_user_pasted_it() {
        assert_eq!(path_components("Sarah"), vec!["Sarah"]);
        assert_eq!(path_components("\\Sarah\\"), vec!["Sarah"]);
        assert_eq!(path_components("\\\\Sarah\\\\Deep"), vec!["Sarah", "Deep"]);
        assert!(path_components("").is_empty());
        assert!(path_components("\\").is_empty());
    }

    #[test]
    fn no_path_at_all_resolves_to_the_hives_root_key() {
        let reader = reader();
        let chain = resolve_key(&reader, None).expect("the root always resolves");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].name.text, "ROOT");
        assert!(chain[0].is_hive_root());
    }

    #[test]
    fn a_key_path_resolves_through_the_subkey_index_one_component_at_a_time() {
        let reader = reader();
        let chain = resolve_key(&reader, Some("Sarah")).expect("Sarah is under the root");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].name.text, "Sarah");
        assert_eq!(chain[1].parent, chain[0].cell);
    }

    #[test]
    fn key_names_match_without_regard_to_case_because_the_registry_does_not_have_any() {
        let reader = reader();
        for spelling in ["sarah", "SARAH", "SaRaH"] {
            let chain = resolve_key(&reader, Some(spelling))
                .unwrap_or_else(|err| panic!("'{spelling}' must resolve: {err}"));
            assert_eq!(chain[1].name.text, "Sarah");
        }
    }

    #[test]
    fn a_key_that_is_not_there_says_how_far_the_walk_got_and_how_sure_it_is() {
        let reader = reader();
        let err =
            resolve_key(&reader, Some("Sarah\\Nowhere")).expect_err("there is no such subkey");
        match &err {
            RegistryError::KeyNotFound {
                found,
                missing,
                certainty,
            } => {
                assert_eq!(found, "ROOT\\Sarah");
                assert_eq!(missing, "Nowhere");
                assert!(
                    certainty.contains("read in full"),
                    "a complete search must say so: {certainty}"
                );
            }
            other => panic!("expected a not-found, got {other}"),
        }
        assert_eq!(err.class(), "key_not_found");
    }

    #[test]
    fn a_key_missing_from_an_index_that_could_not_be_read_is_not_reported_as_absent() {
        // The distinction the whole module turns on: an unreadable subkey index
        // cannot prove that a key was not there, and saying otherwise puts a
        // claim about the suspect's machine into the record that rests on a
        // paged-out page.
        let profile = xp_profile();
        let hive = HiveSpace::open(&profile, XP_UNNAMED_CMHIVE).unwrap();
        let reader = CellReader::new(hive).unwrap();
        let err = resolve_key(&reader, Some("Anything"))
            .expect_err("the second hive's subkey index is in the unacquired window");
        match &err {
            RegistryError::KeyNotFound { certainty, .. } => assert!(
                certainty.contains("not proof"),
                "an incomplete search must say so: {certainty}"
            ),
            other => panic!("expected a not-found, got {other}"),
        }
    }

    #[test]
    fn a_path_deeper_than_the_cap_is_refused_before_any_reads() {
        let reader = reader();
        let deep = vec!["a"; MAX_PATH_DEPTH + 1].join("\\");
        let err = resolve_key(&reader, Some(&deep)).expect_err("the cap fires first");
        assert_eq!(err.class(), "cap");
    }

    #[test]
    fn printkey_lists_the_subkeys_and_the_values_of_the_key_it_resolved() {
        let reader = reader();
        let listing = print_key(&reader, Some("Sarah")).expect("Sarah resolves");
        assert_eq!(listing.hive, XP_CMHIVE);
        assert_eq!(listing.path, "ROOT\\Sarah");
        assert_eq!(listing.chain.len(), 2);
        assert!(listing.subkeys.keys.is_empty());
        assert_eq!(listing.values.values.len(), 4);
        assert_eq!(listing.root_evidence, Evidence::Confirmed);

        let names: Vec<&str> = listing
            .values
            .values
            .iter()
            .map(|value| value.name.text.as_str())
            .collect();
        assert_eq!(names, vec!["Path", "Count", "", "List"]);
    }

    #[test]
    fn printkey_at_the_root_lists_every_subkey_from_both_stores() {
        let reader = reader();
        let listing = print_key(&reader, None).expect("the root resolves");
        assert_eq!(listing.path, "ROOT");
        assert_eq!(listing.subkeys.keys.len(), 4);
        assert!(listing
            .subkeys
            .keys
            .iter()
            .any(|key| key.is_volatile() && key.name.text == "Volatile"));
    }

    #[test]
    fn a_listing_that_could_not_be_completed_says_so_rather_than_looking_short() {
        let reader = reader();
        let listing = print_key(&reader, Some("Test")).expect("Test resolves");
        assert!(
            !listing.is_complete(),
            "Test declares a subkey its index does not list"
        );
        assert!(!listing.incomplete().is_empty());
    }

    #[test]
    fn a_listing_serialises_the_key_its_values_and_its_gaps() {
        let reader = reader();
        let listing = print_key(&reader, Some("Sarah")).unwrap();
        let json = listing.to_json();
        assert_eq!(json["hive"], XP_CMHIVE);
        assert_eq!(json["path"], "ROOT\\Sarah");
        assert_eq!(json["root_evidence"], "confirmed");
        assert_eq!(json["values_declared"], 4);
        assert_eq!(json["values"][0]["type"], "REG_SZ");
        assert_eq!(json["values"][2]["data"]["available"], false);
        assert_eq!(
            json["complete"], false,
            "one value's data was never acquired, so the listing is not complete"
        );
        assert_eq!(json["incomplete"][0]["reason"], "short_read");
    }

    #[test]
    fn the_one_call_entry_point_opens_the_hive_and_lists_the_key() {
        let profile = xp_profile();
        let listing = print_key_in_hive(&profile, XP_CMHIVE, Some("\\Sarah\\"))
            .expect("the hive opens and the key resolves");
        assert_eq!(listing.path, "ROOT\\Sarah");
        let path_value = listing
            .values
            .values
            .iter()
            .find(|value| value.name.text == "Path")
            .expect("the string value is listed");
        assert_eq!(path_value.value_type, RegValueType::Sz);
        match &path_value.data {
            ValueData::Available { decoded, .. } => match decoded {
                RegistryData::Text(text) => assert_eq!(text.text, "abc"),
                other => panic!("expected text, got {other:?}"),
            },
            other => panic!("expected available data, got {other:?}"),
        }
    }

    #[test]
    fn opening_a_hive_at_an_address_that_is_not_one_fails_before_any_key_is_reported() {
        let profile = xp_profile();
        let err = print_key_in_hive(&profile, XP_CMHIVE + 0x400, None)
            .expect_err("a structure with no hive signature must not be walked");
        assert_eq!(err.class(), "hive_signature");
    }
}
