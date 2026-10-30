//! Wi-Fi history — `com.apple.wifi.known-networks.plist` (and legacy
//! `com.apple.airport.preferences.plist`).
//!
//! Every network the Mac has joined, with when it was added and last joined —
//! a movement/location trail. The modern (Big Sur+) file is a dict keyed by
//! `wifi.network.ssid.<SSID>`; each value carries the SSID, `AddedAt`,
//! `JoinedByUserAt`/`UpdatedAt` dates and the supported security types. The
//! legacy file nests the same under a `KnownNetworks` dict. Both are handled.

use anyhow::Result;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::info;

use crate::{basename_lower, to_rfc3339, Staged};

/// Largest known-networks plist read into memory. These are KBs.
const MAX_PLIST_BYTES: u64 = 16 * 1024 * 1024;

/// Emits one `WifiNetwork` record per known network.
pub struct WifiKnownNetworksParser;

fn is_wifi_plist(name: &str) -> bool {
    let b = basename_lower(name);
    b.contains("known-networks") || b.contains("airport.preferences")
}

/// A plist `Date` as Unix seconds.
fn plist_date_unix(v: &plist::Value) -> Option<i64> {
    if let plist::Value::Date(d) = v {
        let st: std::time::SystemTime = (*d).into();
        st.duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|dur| dur.as_secs() as i64)
    } else {
        None
    }
}

/// SSID from a network dict: a `SSID` field (Data or String), else the key.
fn ssid_of(key: &str, dict: &plist::Dictionary) -> String {
    if let Some(v) = dict.get("SSID_STR").and_then(|v| v.as_string()) {
        return v.to_string();
    }
    match dict.get("SSID") {
        Some(plist::Value::String(s)) => return s.clone(),
        Some(plist::Value::Data(b)) => return String::from_utf8_lossy(b).into_owned(),
        _ => {}
    }
    // Fall back to the key suffix used by the modern format.
    key.strip_prefix("wifi.network.ssid.")
        .unwrap_or(key)
        .to_string()
}

/// Emit a record for one network dict. `first`/`last` timestamps come from any of
/// the several date fields Apple has used across versions.
fn network_record(
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    ssid: &str,
    dict: &plist::Dictionary,
    staged: &Staged,
    file_name: &str,
) -> Artifact {
    let added = dict.get("AddedAt").and_then(plist_date_unix);
    let joined = dict
        .get("JoinedByUserAt")
        .or_else(|| dict.get("JoinedBySystemAt"))
        .or_else(|| dict.get("LastAutoJoinAt"))
        .or_else(|| dict.get("UpdatedAt"))
        .and_then(plist_date_unix);

    let security: Vec<String> = dict
        .get("SupportedSecurityTypes")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_string().map(String::from))
                .collect()
        })
        .or_else(|| {
            dict.get("SupportedSecurityTypes")
                .and_then(|v| v.as_string())
                .map(|s| vec![s.to_string()])
        })
        .unwrap_or_default();

    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!("WifiNetwork"));
    meta.insert("subtype".into(), json!("known_network"));
    meta.insert("ssid".into(), json!(ssid));
    meta.insert("added_at".into(), json!(added));
    meta.insert("last_joined".into(), json!(joined));
    if let Some(r) = added.and_then(to_rfc3339) {
        meta.insert("added_at_rfc3339".into(), json!(r));
    }
    if let Some(r) = joined.and_then(to_rfc3339) {
        meta.insert("last_joined_rfc3339".into(), json!(r));
    }
    if !security.is_empty() {
        meta.insert("security_types".into(), json!(security));
    }
    meta.insert("name".into(), json!(format!("Wi-Fi network: {ssid}")));
    // A network read out of a partial plist is still a real network, but the
    // networks after the cut are missing and this record must not read as if
    // the join history were complete.
    staged.stamp(file_name, &mut meta);

    Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta.into())
        .with_parent(parent_id)
        .with_subtype("known_network")
}

impl ForensicsModule for WifiKnownNetworksParser {
    fn id(&self) -> &str {
        "macos.wifi_known_networks"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !is_wifi_plist(name) {
            return Ok(Vec::new());
        }
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        let staged = Staged::read(ds.as_ref(), MAX_PLIST_BYTES);

        // A plist keeps its trailer (binary) or closing tags (XML) at the end,
        // so a prefix usually will not parse at all. Returning nothing for a
        // file this parser selected by name would delete the join history from
        // the case with no trace; the marker is that trace.
        let lost = "so the networks this machine joined could not be read from it";
        //
        // A file staged in full that will not parse, or whose root is not a
        // dictionary, is the same trace for a different reason: the file was
        // there and could not be read, which is not "no known networks"
        // (HUNT-179).
        let value = match plist::from_bytes::<plist::Value>(&staged.bytes) {
            Ok(value) => value,
            Err(e) => {
                return Ok(vec![staged.unreadable_marker(
                    artifact.case_id,
                    artifact.id,
                    "WifiNetworkIncomplete",
                    name,
                    "ParseFailed",
                    &format!("did not parse as a property list ({e})"),
                    lost,
                )]);
            }
        };
        let Some(top) = value.as_dictionary() else {
            return Ok(vec![staged.unreadable_marker(
                artifact.case_id,
                artifact.id,
                "WifiNetworkIncomplete",
                name,
                "UnexpectedLayout",
                "its root is not the dictionary of networks this reader knows",
                lost,
            )]);
        };

        let mut out = Vec::new();

        // Modern: top-level keys "wifi.network.ssid.<SSID>" -> network dict.
        for (key, val) in top.iter() {
            if key.starts_with("wifi.network.ssid.") {
                if let Some(d) = val.as_dictionary() {
                    let ssid = ssid_of(key, d);
                    out.push(network_record(
                        artifact.case_id,
                        artifact.id,
                        &ssid,
                        d,
                        &staged,
                        name,
                    ));
                }
            }
        }
        // Legacy: KnownNetworks -> dict of network dicts.
        if let Some(known) = top.get("KnownNetworks").and_then(|v| v.as_dictionary()) {
            for (key, val) in known.iter() {
                if let Some(d) = val.as_dictionary() {
                    let ssid = ssid_of(key, d);
                    out.push(network_record(
                        artifact.case_id,
                        artifact.id,
                        &ssid,
                        d,
                        &staged,
                        name,
                    ));
                }
            }
        }
        // A partial read that yielded no networks at all still has to say the
        // file was there and was not read in full.
        if out.is_empty() {
            out.extend(staged.incomplete_marker(
                artifact.case_id,
                artifact.id,
                "WifiNetworkIncomplete",
                name,
                lost,
            ));
        }

        info!(
            "WifiKnownNetworksParser: {} networks from {name}",
            out.len()
        );
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
    }
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_core::test_support::TruncatedSource;
    use std::sync::Arc;
    use uuid::Uuid;

    fn run(bytes: Vec<u8>, name: &str) -> Vec<Artifact> {
        run_source(Arc::new(ByteSliceDataSource::new(bytes)), name)
    }

    fn run_source(src: Arc<dyn DataSource>, name: &str) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(src),
            json!({ "name": name }),
        );
        WifiKnownNetworksParser.process(&art).unwrap()
    }

    fn known_networks_xml() -> Vec<u8> {
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\
             <plist version=\"1.0\"><dict>\
               <key>wifi.network.ssid.HomeWiFi</key><dict>\
                 <key>AddedAt</key><date>2022-01-02T03:04:05Z</date>\
               </dict>\
             </dict></plist>"
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn parses_modern_known_networks_with_dates() {
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\
             <plist version=\"1.0\"><dict>\
               <key>wifi.network.ssid.HomeWiFi</key><dict>\
                 <key>AddedAt</key><date>2022-01-02T03:04:05Z</date>\
                 <key>JoinedByUserAt</key><date>2023-06-07T08:09:10Z</date>\
                 <key>SupportedSecurityTypes</key><array><string>WPA2 Personal</string></array>\
               </dict>\
             </dict></plist>";
        let out = run(
            xml.as_bytes().to_vec(),
            "com.apple.wifi.known-networks.plist",
        );
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["ssid"], json!("HomeWiFi"));
        assert_eq!(
            m["added_at_rfc3339"].as_str().unwrap(),
            "2022-01-02T03:04:05+00:00"
        );
        assert_eq!(
            m["last_joined_rfc3339"].as_str().unwrap(),
            "2023-06-07T08:09:10+00:00"
        );
        assert_eq!(m["security_types"], json!(["WPA2 Personal"]));
    }

    #[test]
    fn parses_legacy_airport_preferences() {
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\
             <plist version=\"1.0\"><dict><key>KnownNetworks</key><dict>\
               <key>wifi0</key><dict>\
                 <key>SSID_STR</key><string>CoffeeShop</string>\
                 <key>LastAutoJoinAt</key><date>2020-05-05T05:05:05Z</date>\
               </dict>\
             </dict></dict></plist>";
        let out = run(
            xml.as_bytes().to_vec(),
            "com.apple.airport.preferences.plist",
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["ssid"], json!("CoffeeShop"));
        assert_eq!(
            out[0].metadata["last_joined_rfc3339"].as_str().unwrap(),
            "2020-05-05T05:05:05+00:00"
        );
    }

    #[test]
    fn ignores_unrelated_plists() {
        let xml = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict></dict></plist>";
        assert!(run(xml.as_bytes().to_vec(), "com.apple.finder.plist").is_empty());
    }

    /// A plist keeps its closing tags at the end, so a prefix does not parse.
    /// Returning nothing deleted the machine's join history from the case with
    /// no record that the file had ever been seen.
    #[test]
    fn a_known_networks_plist_not_staged_in_full_is_still_reported() {
        let full = known_networks_xml();
        let cut = full.len() / 2;
        let src: Arc<dyn DataSource> = Arc::new(TruncatedSource::cut_to(full, cut));
        let out = run_source(src, "com.apple.wifi.known-networks.plist");
        assert_eq!(out.len(), 1, "the file must not vanish");
        let m = &out[0].metadata;
        assert_eq!(m["type"], json!("WifiNetworkIncomplete"));
        assert_eq!(m["content_incomplete"], json!(true));
        assert_eq!(m["content_incomplete_reason"], json!("short_read"));
    }

    /// The narrow case where the document ends before the read did: the
    /// networks parse, but the ones past the cut are missing, so no record may
    /// present the join history as complete.
    #[test]
    fn networks_parsed_from_a_partial_read_are_marked_incomplete() {
        let src: Arc<dyn DataSource> = Arc::new(TruncatedSource::halved(known_networks_xml()));
        let out = run_source(src, "com.apple.wifi.known-networks.plist");
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["ssid"], json!("HomeWiFi"));
        assert_eq!(m["content_incomplete"], json!(true));
        assert_eq!(m["content_incomplete_reason"], json!("short_read"));
    }

    /// A file read in full carries no incompleteness stamp: the flag has to
    /// mean something when it is there.
    #[test]
    fn a_fully_read_known_networks_plist_carries_no_incompleteness_stamp() {
        let out = run(known_networks_xml(), "com.apple.wifi.known-networks.plist");
        assert_eq!(out.len(), 1);
        assert!(out[0].metadata.get("content_incomplete").is_none());
    }

    /// HUNT-179. A known-networks plist staged in full that does not parse
    /// returned an empty list with no record — read as "no known networks".
    #[test]
    fn a_known_networks_plist_that_will_not_parse_is_reported() {
        let out = run(
            b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>wifi".to_vec(),
            "com.apple.wifi.known-networks.plist",
        );
        assert_eq!(out.len(), 1, "the file must not vanish: {out:?}");
        let m = &out[0].metadata;
        assert_eq!(m["type"], json!("WifiNetworkIncomplete"));
        assert_eq!(m["status"], json!("ParseFailed"));
        assert_eq!(m["content_incomplete"], json!(true));
        assert_eq!(
            m["content_incomplete_reason"],
            json!("unresolved_structure")
        );
    }

    /// A root that is not a dictionary is not a layout this reader knows.
    #[test]
    fn a_known_networks_plist_whose_root_is_not_a_dictionary_is_reported() {
        let xml = "<?xml version=\"1.0\"?><plist version=\"1.0\"><array>\
                   <string>HomeWiFi</string></array></plist>";
        let out = run(
            xml.as_bytes().to_vec(),
            "com.apple.wifi.known-networks.plist",
        );
        assert_eq!(out.len(), 1, "the file must not vanish: {out:?}");
        assert_eq!(out[0].metadata["status"], json!("UnexpectedLayout"));
    }

    /// The real file from the Magnet 2021 macOS image (gitignored corpus;
    /// skipped where absent) still reads as networks, with no marker.
    #[test]
    fn the_real_known_networks_plist_reads_without_a_marker() {
        let path = home(
            "ctf-evidence/macos2021/tree/Library/Preferences/\
             com.apple.wifi.known-networks.plist",
        );
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!(
                "skipping: {} not present (gitignored corpus)",
                path.display()
            );
            return;
        };
        let out = run(bytes, "com.apple.wifi.known-networks.plist");
        assert!(!out.is_empty());
        assert!(
            out.iter().all(|a| a.metadata["type"] == "WifiNetwork"),
            "{out:?}"
        );
    }
}
