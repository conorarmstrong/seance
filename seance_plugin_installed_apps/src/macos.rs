//! What is installed on a Mac.
//!
//! `InstalledApp` records came from Android's package manager and iOS's
//! `applicationState.db`; on a macOS exhibit nothing inventoried anything, so
//! "what was on this machine, and at what version" had no answer without
//! opening bundles one at a time (found grading the Magnet 2021 macOS image,
//! whose seventh question is the version of Finder — `HUNT-110`).
//!
//! A Mac states this in each application's own `Info.plist`. This reader takes
//! the bundle's identifier, name, marketing version and build version, and
//! records where it was installed — which is what separates an Apple
//! application in `/System/Applications` from one a person put in
//! `/Applications`, and both from one running out of a user's Downloads folder.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::debug;

/// Ceiling on one bundle's `Info.plist`. These are kilobytes; a few large ones
/// embed icons and document types and reach a megabyte or two.
const MAX_INFO_PLIST_BYTES: usize = 16 * 1024 * 1024;

/// The bundle an `Info.plist` path belongs to, when it is an application's own.
///
/// Only the bundle's top level counts: `Safari.app/Contents/Info.plist` is
/// Safari, while `Safari.app/Contents/XPCServices/…/Info.plist` and every
/// framework inside it describe parts of Safari, not separate installed
/// applications. Counting those would make one application read as thirty.
pub fn application_bundle(path: &str) -> Option<BundleLocation> {
    let normalised = path.replace('\\', "/");
    if !normalised.ends_with("/Contents/Info.plist") {
        return None;
    }
    let bundle = normalised.trim_end_matches("/Contents/Info.plist");
    if !bundle.ends_with(".app") {
        return None;
    }
    // A `.app` inside another bundle is a component of it.
    let inner = bundle.trim_end_matches(".app");
    if inner.contains(".app/") || inner.contains(".framework/") || inner.contains(".bundle/") {
        return None;
    }
    let name = bundle.rsplit('/').next()?.trim_end_matches(".app");
    Some(BundleLocation {
        bundle_path: bundle.to_string(),
        bundle_name: name.to_string(),
        installed_in: installed_in(bundle),
    })
}

/// Where an application lives, which is part of what it is — when the path this
/// case holds says so.
///
/// A subtree ingested on its own (`/Applications` walked as a root) gives paths
/// like `/Safari.app/Contents/Info.plist`, which state nothing about where the
/// folder sat on the machine. Answering "elsewhere" there would be a finding —
/// "this application was NOT in /Applications" — drawn from a path that never
/// said. `None` means the path does not say, and the record omits the field.
fn installed_in(bundle: &str) -> Option<&'static str> {
    let lower = bundle.to_ascii_lowercase();
    if lower.contains("/system/applications/") || lower.contains("/system/library/coreservices/") {
        Some("system")
    } else if lower.contains("/applications/") {
        Some("applications")
    } else if lower.contains("/users/") || lower.contains("/home/") {
        Some("user")
    } else {
        None
    }
}

/// An application bundle's path, name and where it was installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleLocation {
    pub bundle_path: String,
    pub bundle_name: String,
    /// Where the path says it was installed, or `None` when the path this case
    /// holds does not say.
    pub installed_in: Option<&'static str>,
}

/// The keys an application's `Info.plist` states its identity under.
const FIELDS: &[(&str, &str)] = &[
    ("package", "CFBundleIdentifier"),
    ("display_name", "CFBundleDisplayName"),
    ("bundle_name", "CFBundleName"),
    ("version", "CFBundleShortVersionString"),
    ("build_version", "CFBundleVersion"),
    ("executable", "CFBundleExecutable"),
    ("minimum_system_version", "LSMinimumSystemVersion"),
    ("built_with_sdk", "DTSDKName"),
];

/// Reads macOS application bundles into installed-application records.
#[derive(Debug, Default)]
pub struct MacInstalledAppsParser;

impl MacInstalledAppsParser {
    pub fn new() -> Self {
        Self
    }
}

impl ForensicsModule for MacInstalledAppsParser {
    fn id(&self) -> &str {
        "plugin.macos.installed_apps"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let Some(bundle) = application_bundle(path) else {
            return Ok(Vec::new());
        };
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(Vec::new());
        }
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        let size = data.size() as usize;
        let want = size.min(MAX_INFO_PLIST_BYTES);
        let mut buf = vec![0u8; want];
        let read = data
            .read_at(0, &mut buf)
            .map_err(|e| ModuleError::ParsingError(format!("reading {path}: {e}")))?;
        buf.truncate(read);

        let value = match plist::Value::from_reader(std::io::Cursor::new(&buf)) {
            Ok(value) => value,
            Err(e) => {
                // The bundle is an application by its path, and its own
                // description of itself will not parse. Saying nothing would
                // leave it out of the inventory as though it were not there.
                debug!("{path} did not parse as a plist: {e}");
                return Ok(vec![unreadable_bundle(artifact, &bundle, path, &e)]);
            }
        };
        let Some(dict) = value.as_dictionary() else {
            return Ok(vec![unreadable_bundle_reason(
                artifact,
                &bundle,
                path,
                "this bundle's Info.plist is not a dictionary, so nothing in it names the \
                 application",
            )]);
        };

        let mut metadata = serde_json::Map::new();
        metadata.insert("type".into(), json!("InstalledApp"));
        metadata.insert("analysis_type".into(), json!("installed_app"));
        metadata.insert("subtype".into(), json!("InstalledApp"));
        metadata.insert("platform".into(), json!("macOS"));
        metadata.insert("source".into(), json!("Info.plist"));
        metadata.insert("source_file".into(), json!(path));
        metadata.insert("bundle_path".into(), json!(bundle.bundle_path));
        if let Some(installed_in) = bundle.installed_in {
            metadata.insert("installed_in".into(), json!(installed_in));
        }
        for (field, key) in FIELDS {
            if let Some(found) = dict.get(key).and_then(|v| v.as_string()) {
                if !found.is_empty() {
                    metadata.insert((*field).to_string(), json!(found));
                }
            }
        }
        // The name shown to an examiner: what the bundle calls itself, falling
        // back to the folder's own name, which is what Finder shows.
        let name = metadata
            .get("display_name")
            .or_else(|| metadata.get("bundle_name"))
            .and_then(|v| v.as_str())
            .unwrap_or(&bundle.bundle_name)
            .to_string();
        metadata.insert("name".into(), json!(name));
        // An application with no bundle identifier is still installed; it is
        // named by its folder rather than dropped.
        if !metadata.contains_key("package") {
            metadata.insert("package".into(), json!(bundle.bundle_name));
            metadata.insert("package_source".into(), json!("bundle folder name"));
        }

        Ok(vec![Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            serde_json::Value::Object(metadata),
        )
        .with_parent(artifact.id)])
    }
}

fn unreadable_bundle(
    artifact: &Artifact,
    bundle: &BundleLocation,
    path: &str,
    error: &plist::Error,
) -> Artifact {
    unreadable_bundle_reason(
        artifact,
        bundle,
        path,
        &format!("this bundle's Info.plist did not parse ({error})"),
    )
}

fn unreadable_bundle_reason(
    artifact: &Artifact,
    bundle: &BundleLocation,
    path: &str,
    detail: &str,
) -> Artifact {
    let mut record = Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "InstalledApp",
            "analysis_type": "installed_app",
            "subtype": "InstalledApp",
            "platform": "macOS",
            "source": "Info.plist",
            "source_file": path,
            "bundle_path": bundle.bundle_path,
            "name": bundle.bundle_name,
            "package": bundle.bundle_name,
            "package_source": "bundle folder name",
            "content_incomplete": true,
            "content_incomplete_reason": "unresolved_structure",
            "content_incomplete_detail": detail,
        }),
    );
    if let Some(installed_in) = bundle.installed_in {
        if let Some(object) = record.metadata.as_object_mut() {
            object.insert("installed_in".to_string(), json!(installed_in));
        }
    }
    record.with_parent(artifact.id)
}

#[cfg(test)]
#[path = "tests_macos.rs"]
mod tests;
