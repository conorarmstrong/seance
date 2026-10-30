#![forbid(unsafe_code)]
//! macOS Plist Parser Module
//!
//! Parses both binary and XML property list (.plist) files commonly used in macOS.
//! Extracts structured data from configuration files, preferences, and metadata.

#[cfg(test)]
mod tests;

pub mod keyed_archive;
use anyhow::{Context, Result};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{ByteSliceDataSource, DataSource},
    io::{read_capped, read_full, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Largest plist we will load into memory (100 MiB). A property list is
/// kilobytes in practice; anything past this is not parsed.
const MAX_PLIST_BYTES: u64 = 100 * 1024 * 1024;

pub struct PlistParser;

impl PlistParser {
    /// Parse plist data and convert to JSON. Test entry point; `process`
    /// goes through `content_and_stop` on a tree it has already decoded.
    #[cfg(test)]
    fn parse_plist_data(&self, data: &[u8]) -> Result<serde_json::Value> {
        // Try to parse as plist (handles both binary and XML)
        let plist_value =
            plist::from_bytes::<plist::Value>(data).context("Failed to parse plist data")?;
        Ok(Self::content_and_stop(&plist_value).0)
    }

    /// The record's content for an already-parsed plist: the literal rendering,
    /// and beside it the resolved graph when the file is a keyed archive.
    ///
    /// Split from the parse so `process` decodes the bytes once and reads the
    /// same value tree twice — for the embedded blobs and for the content.
    /// Parsing twice doubled the transient allocation of every property list
    /// in a walk, which is a folder of small files reaching gigabytes (HUNT-114).
    ///
    /// Returned with the bound that first stopped any keyed-archive resolution
    /// in it — top level or nested — if one did, which the record stamps as
    /// incompleteness whatever the rendered size (HUNT-223).
    fn content_and_stop(plist_value: &plist::Value) -> (serde_json::Value, Option<&'static str>) {
        // One allowance for the whole file: the top-level resolution, the
        // literal rendering, and every archive nested inside a `Data` value
        // under either of them draw on it, so a nested archive cannot restart
        // the bounds for itself (HUNT-146).
        let mut budget = keyed_archive::Budget::new(RESOLVE_NODE_BUDGET);

        // Most property lists on a modern Apple device are NSKeyedArchiver
        // archives: a flat `$objects` array knitted together by UID references.
        // Rendered literally that is a numbered list of fragments, with the
        // structure — which account owns which token, which file a recent-items
        // entry names — living only in the references. Resolve it when it is
        // one.
        //
        // The literal rendering is kept beside the resolved graph. Resolution
        // follows references and makes decisions about cycles and bounds, and an
        // examiner has to be able to see what was on disk rather than only this
        // module's reading of it.
        //
        // The archive is resolved first, so the reading the record is about has
        // the first claim on the shared allowance.
        if let plist::Value::Dictionary(dict) = plist_value {
            if let Some(resolved) = keyed_archive::resolve_in(dict, &mut budget, 0) {
                let raw = plist_value_to_json_in(plist_value, 0, &mut budget);
                let content = serde_json::json!({
                    "keyed_archive": resolved,
                    "raw": raw,
                });
                return (content, budget.first_stop());
            }
        }

        let content = plist_value_to_json_in(plist_value, 0, &mut budget);
        (content, budget.first_stop())
    }

    /// Whether a decoded plist is an `NSKeyedArchiver` archive — asked of the
    /// value tree, not of the rendered content, because an ordinary plist may
    /// happen to have keys named `keyed_archive` and `raw`.
    fn is_archive(plist_value: &plist::Value) -> bool {
        matches!(plist_value, plist::Value::Dictionary(d) if keyed_archive::is_keyed_archive(d))
    }

    /// Classify a keyed archive from what it archived, not from this module's
    /// `{keyed_archive, raw}` wrapper around it.
    ///
    /// Run on the wrapper, every archive on a machine recorded `key_count: 2`,
    /// `sample_keys: [keyed_archive, raw]` and `plist_type: Generic` — the same
    /// three values for a recent-items list, a login-items list and a `.nib`
    /// (HUNT-177). The archive's own top level is `$top`, so its keys are what
    /// `key_count` and `sample_keys` report, and the class of the object under
    /// `$top.root` — the object the archiver was asked to encode — is named.
    fn classify_archive(metadata: &mut serde_json::Value, content: &serde_json::Value) {
        metadata["plist_type"] = json!("Keyed Archive");
        metadata["archive_format"] = json!("NSKeyedArchiver");
        let top = &content["keyed_archive"]["root"];
        match top.as_object() {
            Some(obj) => {
                metadata["key_count"] = json!(obj.len());
                let sample_keys: Vec<_> = obj.keys().take(10).collect();
                metadata["sample_keys"] = json!(sample_keys);
            }
            None => {
                // `$top` that is not a dictionary is not how Foundation writes
                // one; say nothing about keys rather than describe the wrapper.
                if let Some(obj) = metadata.as_object_mut() {
                    obj.remove("key_count");
                    obj.remove("sample_keys");
                }
            }
        }
        if let Some(class) = top["root"]["$class"]["$classname"].as_str() {
            metadata["archive_root_class"] = json!(class);
        }
    }

    /// Detect if data is a plist file
    fn is_plist(&self, data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }

        // Check for binary plist signature: "bplist" at offset 0
        if data.len() >= 6 && &data[0..6] == b"bplist" {
            return true;
        }

        // Check for XML plist signature: "<?xml" at start or "<plist" nearby
        if data.len() >= 5 && &data[0..5] == b"<?xml" {
            // Look for "<plist" in first 200 bytes
            let search_len = std::cmp::min(200, data.len());
            if let Ok(s) = std::str::from_utf8(&data[0..search_len]) {
                if s.contains("<plist") {
                    return true;
                }
            }
        }

        // Check for "<plist" at start (some XML plists omit XML declaration)
        if data.len() >= 6 && &data[0..6] == b"<plist" {
            return true;
        }

        false
    }

    /// Extract metadata from parsed plist content
    fn extract_plist_metadata(&self, content: &serde_json::Value, name: &str) -> serde_json::Value {
        let mut metadata = json!({
            "type": "PlistFile",
            "filename": name,
            "source": "PlistParser"
        });

        // Try to detect plist type based on content patterns
        if let Some(obj) = content.as_object() {
            metadata["key_count"] = json!(obj.len());

            // Sample some keys
            let sample_keys: Vec<_> = obj.keys().take(10).collect();
            metadata["sample_keys"] = json!(sample_keys);

            // Detect common plist types
            if obj.contains_key("CFBundleIdentifier") {
                metadata["plist_type"] = json!("Bundle Info");
            } else if obj.contains_key("LastUsedDate") || obj.contains_key("RecentApplications") {
                metadata["plist_type"] = json!("User Preferences");
            } else if obj.contains_key("Items") && obj.contains_key("Name") {
                metadata["plist_type"] = json!("Bookmark");
            } else {
                metadata["plist_type"] = json!("Generic");
            }
        } else if content.is_array() {
            metadata["plist_type"] = json!("Array");
            if let Some(arr) = content.as_array() {
                metadata["array_length"] = json!(arr.len());
            }
        }

        metadata
    }
}

impl ForensicsModule for PlistParser {
    fn id(&self) -> &str {
        "plugin.macos.plist_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::SystemArtifact]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let mut produced_artifacts = Vec::new();

        // Check if we have a data source
        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds,
            None => return Ok(produced_artifacts),
        };

        // Get filename
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Read the data
        let size = data_source.size();

        // Cheap header probe, used only to decide whether a file we are about to
        // skip was in fact a plist. Without it a skip marker would be emitted for
        // every large or truncated file in the image, which is noise, not honesty.
        let mut head = [0u8; 256];
        let head_len = read_full(data_source.as_ref(), 0, &mut head);
        let looks_like_plist = self.is_plist(&head[..head_len]);

        if size > MAX_PLIST_BYTES {
            // Too large to load. Leave a record saying so: a silent skip makes an
            // unparsed 500 MiB plist look identical to one that held nothing
            // (B2-112).
            debug!("Skipping large file: {} ({} bytes)", name, size);
            if looks_like_plist {
                produced_artifacts.push(skipped_marker(
                    artifact,
                    name,
                    "OverSizeCap",
                    IncompleteReason::CapReached,
                    "Plist exceeds the parser size cap; it was not parsed",
                    size,
                ));
            }
            return Ok(produced_artifacts);
        }

        // Read the whole declared size, tolerating short reads from a windowed
        // source. A short read must NOT be treated as a full-size, zero-padded
        // success: a truncated plist could otherwise parse "valid" with a tail
        // of fabricated zero bytes. Fail closed by refusing to parse it.
        let buffer = read_capped(data_source.as_ref(), size);
        if (buffer.len() as u64) != size {
            warn!(
                "Plist {}: short read ({} of {} bytes); refusing to parse truncated data",
                name,
                buffer.len(),
                size
            );
            // Fail closed AND say so: refusing to parse must not look like a
            // file that simply had nothing in it. Only for files that really are
            // plists — everything else is not ours to report on.
            if looks_like_plist {
                produced_artifacts.push(skipped_marker(
                    artifact,
                    name,
                    "ShortRead",
                    IncompleteReason::ShortRead,
                    "Plist ended before its declared size; it was not parsed",
                    size,
                ));
            }
            return Ok(produced_artifacts);
        }

        // Check if this is a plist file
        if !self.is_plist(&buffer) {
            // Not a plist, skip silently
            return Ok(produced_artifacts);
        }

        info!("Detected plist file: {}", name);

        // Parse the plist
        // The plist as its own value tree, for the blobs the JSON form can only
        // describe. A profile picture, a certificate, an embedded image: the
        // record said `<data 789838 bytes: 4d4d002a…>` and there it stopped, so
        // a question answered by those bytes — hash it, look at it, export it —
        // could not be answered from the evidence holding them (HUNT-104).
        let mut walk = BlobWalk::default();
        // Decoded once; the blob walk and the content rendering read the same
        // tree. The bytes are dropped before the content is built, so the
        // buffer, the value tree and the JSON never coexist at their peak.
        let parsed = plist::from_bytes::<plist::Value>(&buffer)
            .context("Failed to parse plist data")
            .inspect(|value| {
                walk.collect(value, "");
            });
        drop(buffer);

        match parsed.map(|value| (Self::content_and_stop(&value), Self::is_archive(&value))) {
            Ok(((parsed_content, resolution_stop), is_archive)) => {
                // Extract metadata
                let mut metadata = self.extract_plist_metadata(&parsed_content, name);
                if is_archive {
                    Self::classify_archive(&mut metadata, &parsed_content);
                }
                let BlobWalk {
                    out: blobs,
                    capped: blobs_capped,
                    oversize,
                } = walk;
                metadata["data_blobs_extracted"] = json!(blobs.len());
                let mut left_behind = Vec::new();
                if blobs_capped {
                    metadata["data_blobs_capped"] = json!(true);
                    left_behind.push(format!(
                        "this plist carries more than {MAX_EXTRACTED_BLOBS} embedded data \
                         values; the ones past that are described in the record and not \
                         extracted as files"
                    ));
                }
                // A value too large to carry out is described in `content` as
                // `<data N bytes: …>` and nothing more. Without this the record
                // said every embedded file had been extracted when one had
                // been left behind (HUNT-177).
                if !oversize.is_empty() {
                    metadata["data_blobs_oversize"] = json!(oversize
                        .iter()
                        .map(|(key_path, size)| json!({ "key_path": key_path, "size": size }))
                        .collect::<Vec<_>>());
                    let named = oversize
                        .iter()
                        .map(|(key_path, size)| format!("`{key_path}` ({size} bytes)"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    left_behind.push(format!(
                        "embedded data larger than the {MAX_EXTRACTED_BLOB}-byte extraction cap \
                         was not extracted as a file and is described in the record only by \
                         its length and first bytes: {named}"
                    ));
                }
                if !left_behind.is_empty() {
                    metadata["inventory_incomplete"] = json!(true);
                    metadata["inventory_incomplete_reason"] =
                        json!(IncompleteReason::CapReached.as_str());
                    metadata["inventory_incomplete_detail"] = json!(left_behind.join("; "));
                }

                // Add the parsed content (limit size to prevent huge artifacts).
                // Measured with a writer that stops at the cap rather than by
                // building the whole string: a resolved archive can run to
                // megabytes, and serialising it in full only to discard it was
                // part of what took the server out of memory on a folder of
                // property lists (HUNT-112).
                let measured = measure_json_to_cap(&parsed_content, CONTENT_CAP_BYTES);
                if let Some(len) = measured {
                    let _ = len;
                    metadata["content"] = parsed_content;
                    // Stored whole — but a keyed-archive resolution a bound
                    // stopped short is not the whole archive, whatever its
                    // rendered size. `keyed_archive.truncated` inside the
                    // content is not read by search, export or the court
                    // completeness census; the standard pair is (HUNT-223).
                    if let Some(reason) = resolution_stop {
                        metadata["content_incomplete"] = json!(true);
                        metadata["content_incomplete_reason"] =
                            json!(IncompleteReason::CapReached.as_str());
                        metadata["content_incomplete_detail"] =
                            json!(if reason == PLIST_NESTING_BOUND {
                                format!(
                                    "a binary plist nested in this one lies past the plist \
                                     nesting bound ({MAX_NESTED_PLIST_DEPTH} levels) and was \
                                     not opened; its values are not in the record"
                                )
                            } else {
                                format!(
                                    "a keyed-archive resolution in this plist was stopped by \
                                     its {reason} bound; the objects past it are not in the \
                                     resolved graph"
                                )
                            });
                    }
                } else {
                    metadata["content_size_at_least"] = json!(CONTENT_CAP_BYTES);
                    metadata["content_note"] = json!("Content too large to include (>100KB)");

                    // Include a preview — a preview, and not the content under
                    // another name. Cloning ten keys whole made this the whole
                    // file whenever the file had ten keys or fewer, which is
                    // exactly the shape of a resolved keyed archive: one record
                    // in an ordinary macOS folder reached 295 MB (HUNT-112).
                    if let Some(obj) = parsed_content.as_object() {
                        metadata["content_preview"] = preview_of(obj, PREVIEW_CAP_BYTES);
                    }
                    // The record holds ten keys of a plist that parsed whole.
                    // `content_note` is prose; search, export and the court
                    // completeness census read `content_incomplete`, so without
                    // the standard pair a preference file whose values are the
                    // finding presents as fully parsed and a keyword search over
                    // the case reports the value as absent (B5-036).
                    metadata["content_incomplete"] = json!(true);
                    metadata["content_incomplete_reason"] =
                        json!(IncompleteReason::CapReached.as_str());
                }

                let plist_artifact =
                    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
                        .with_parent(artifact.id);

                let plist_id = plist_artifact.id;
                produced_artifacts.push(plist_artifact);

                // Each carried-out blob becomes a file of its own, hanging off
                // the plist record, with its bytes attached — so the hasher,
                // the signature reader, the gallery and an export all see it.
                for (key_path, bytes) in blobs {
                    let size = bytes.len();
                    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
                    produced_artifacts.push(
                        Artifact::new(
                            artifact.case_id,
                            ArtifactType::FileEntry,
                            Some(data),
                            json!({
                                "type": "PlistDataBlob",
                                "name": format!("{name}:{key_path}"),
                                "key_path": key_path,
                                "size": size,
                                "source": "plist_data",
                                "source_file": name,
                            }),
                        )
                        .with_parent(plist_id),
                    );
                }

                info!("Successfully parsed plist: {}", name);
            }
            Err(e) => {
                // The magic already said this is a plist. Returning nothing
                // makes a corrupt one indistinguishable from a file that was
                // never a plist, and the settings it holds absent from the case
                // with nothing saying why (B5-020).
                warn!("Failed to parse plist {}: {}", name, e);
                let mut marker = skipped_marker(
                    artifact,
                    name,
                    "ParseFailed",
                    IncompleteReason::UnresolvedStructure,
                    "The file's magic identifies it as a plist and it could not be parsed; no \
                     values were extracted",
                    size,
                );
                marker.metadata["error"] = json!(e.to_string());
                produced_artifacts.push(marker);
            }
        }

        Ok(produced_artifacts)
    }
}

/// Convert plist::Value to serde_json::Value
/// How many times a plist nested inside a `Data` field will be opened.
///
/// A bound on structure taken from evidence. Real files nest once or twice —
/// an archive inside a preference value — while a crafted one can nest until
/// the stack gives out.
const MAX_NESTED_PLIST_DEPTH: usize = 8;

/// The bound named on a record whose nested plist was left unopened at
/// [`MAX_NESTED_PLIST_DEPTH`].
const PLIST_NESTING_BOUND: &str = "plist nesting";

/// How much hex of an opaque blob to show.
const DATA_PREVIEW_BYTES: usize = 32;

/// Render a value with an allowance of its own. Test entry point; `process`
/// renders through [`PlistParser::content_and_stop`], which shares one allowance
/// across the whole file.
#[cfg(test)]
pub(crate) fn plist_value_to_json(value: &plist::Value) -> serde_json::Value {
    plist_value_to_json_in(
        value,
        0,
        &mut keyed_archive::Budget::new(RESOLVE_NODE_BUDGET),
    )
}

/// Render `value`, met at plist nesting depth `depth`, charging any archive
/// nested inside it to `budget`.
///
/// The keyed-archive walker re-enters here for its scalar leaves with its own
/// depth and the file's budget; it used to re-enter through a wrapper that
/// restarted both, so an archive inside an archive was opened with no bound
/// across levels (HUNT-177).
pub(crate) fn plist_value_to_json_in(
    value: &plist::Value,
    depth: usize,
    budget: &mut keyed_archive::Budget,
) -> serde_json::Value {
    match value {
        plist::Value::Boolean(b) => json!(b),
        plist::Value::Integer(i) => {
            // A plist integer may be an unsigned value larger than `i64::MAX`.
            // `as_signed()` returns `None` for those, and `json!(None)` would
            // silently drop the value to JSON `null`. Fall back to the unsigned
            // form, then to a decimal string, so a large key is never lost.
            if let Some(s) = i.as_signed() {
                json!(s)
            } else if let Some(u) = i.as_unsigned() {
                json!(u)
            } else {
                json!(i.to_string())
            }
        }
        plist::Value::Real(f) => json!(f),
        plist::Value::String(s) => json!(s),
        plist::Value::Data(d) => nested_or_opaque(d, depth, budget),
        plist::Value::Date(d) => {
            // Emit a stable RFC 3339 string (the plist XML date form) rather than
            // relying on the `Debug` representation, which is not a value-format
            // contract. This is what the timeline/search/export paths expect.
            json!(d.to_xml_format())
        }
        plist::Value::Array(arr) => {
            let converted: Vec<_> = arr
                .iter()
                .map(|v| plist_value_to_json_in(v, depth, budget))
                .collect();
            json!(converted)
        }
        plist::Value::Dictionary(dict) => {
            let converted: serde_json::Map<_, _> = dict
                .iter()
                .map(|(k, v)| (k.clone(), plist_value_to_json_in(v, depth, budget)))
                .collect();
            json!(converted)
        }
        plist::Value::Uid(u) => json!(format!("UID({})", u.get())),
        _ => json!(null),
    }
}

/// Smallest `Data` value carried out of a plist as an artifact of its own.
///
/// A preference file is full of small blobs — a window position, a checksum, a
/// token — and an artifact for each would bury a case in noise. A kilobyte is
/// the line: below it a blob is configuration, above it the plist is carrying
/// a *file*.
const MIN_EXTRACTED_BLOB: usize = 1024;

/// Largest blob carried out, so one hostile plist cannot make a case of itself.
const MAX_EXTRACTED_BLOB: usize = 64 * 1024 * 1024;

/// Most blobs carried out of one plist.
const MAX_EXTRACTED_BLOBS: usize = 64;

/// Every opaque `Data` value in the plist worth carrying out, with the key path
/// that addresses it, and an account of the ones that were not.
///
/// A nested plist is skipped: its contents are already in the record, and a
/// second copy as an opaque blob would be the same evidence twice.
#[derive(Default)]
struct BlobWalk {
    /// The blobs carried out.
    out: Vec<(String, Vec<u8>)>,
    /// A blob that qualified was met after `MAX_EXTRACTED_BLOBS` were taken.
    capped: bool,
    /// Blobs over `MAX_EXTRACTED_BLOB`, by key path and size — left behind,
    /// and said to be (HUNT-177).
    oversize: Vec<(String, usize)>,
}

impl BlobWalk {
    fn collect(&mut self, value: &plist::Value, path: &str) {
        match value {
            plist::Value::Data(bytes) => {
                if bytes.starts_with(b"bplist") || bytes.len() < MIN_EXTRACTED_BLOB {
                    return;
                }
                if bytes.len() > MAX_EXTRACTED_BLOB {
                    self.oversize.push((path.to_string(), bytes.len()));
                } else if self.out.len() >= MAX_EXTRACTED_BLOBS {
                    // Raised by a blob that would have been carried out, not by
                    // whatever value happens to follow the sixty-fourth: a
                    // plist that gave up every blob it held is not capped.
                    self.capped = true;
                } else {
                    self.out.push((path.to_string(), bytes.clone()));
                }
            }
            plist::Value::Array(arr) => {
                for (i, v) in arr.iter().enumerate() {
                    self.collect(v, &format!("{path}[{i}]"));
                }
            }
            plist::Value::Dictionary(dict) => {
                for (k, v) in dict.iter() {
                    let child = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    self.collect(v, &child);
                }
            }
            _ => {}
        }
    }
}

/// Whether a `Data` value will be opened as a plist of its own at plist
/// nesting depth `depth`, rather than described.
pub(crate) fn opens_as_nested_plist(bytes: &[u8], depth: usize) -> bool {
    depth < MAX_NESTED_PLIST_DEPTH && bytes.len() >= 8 && bytes.starts_with(b"bplist")
}

/// A `Data` field: opened if it holds a plist, described if it does not.
///
/// # Why this is not just a hex preview
///
/// macOS and iOS routinely store one plist inside another — an
/// `NSKeyedArchiver` archive as the value of a preference key is the ordinary
/// case, not an exotic one. Such a value begins `bplist`, and rendering it as
/// the first thirty-two bytes of hex loses everything it contains: the recent
/// documents, the account name, the bookmark. The bytes were present and were
/// discarded at the point of display.
///
/// So a blob that announces itself as a plist is parsed as one, recursively and
/// to a bounded depth. A blob that does not is described — length first, then a
/// short preview — because its length is often the only thing that can honestly
/// be said about it.
///
/// `depth` is how many `Data` values were already opened to reach this one, on
/// either path — the literal rendering or the keyed-archive walker — and
/// `budget` is the file's one allowance, so an archive nested here is resolved
/// one level deeper and against what is left, not afresh (HUNT-146, HUNT-177).
pub(crate) fn nested_or_opaque(
    bytes: &[u8],
    depth: usize,
    budget: &mut keyed_archive::Budget,
) -> serde_json::Value {
    if opens_as_nested_plist(bytes, depth) {
        if let Ok(inner) = plist::from_bytes::<plist::Value>(bytes) {
            // An archive nested inside another plist is still an archive.
            // Resolved before the literal rendering, as at the top level.
            let resolved = match &inner {
                plist::Value::Dictionary(d) => keyed_archive::resolve_in(d, budget, depth + 1),
                _ => None,
            };
            let rendered = plist_value_to_json_in(&inner, depth + 1, budget);
            return json!({
                "nested_plist": rendered,
                "keyed_archive": resolved,
                "byte_length": bytes.len(),
            });
        }
        // It claimed to be a plist and would not parse. That is a fact about
        // the file, and saying so beats presenting it as an opaque blob.
        return json!({
            "byte_length": bytes.len(),
            "hex_preview": hex::encode(&bytes[..std::cmp::min(DATA_PREVIEW_BYTES, bytes.len())]),
            "note": "begins with the binary plist magic but did not parse",
        });
    }
    // A plist the nesting bound stopped short of opening is not an opaque blob,
    // and presenting it as one would hide that there was more to read.
    if bytes.len() >= 8 && bytes.starts_with(b"bplist") {
        // Said on the record too, not only here inside the content, which
        // search, export and the completeness census do not read (HUNT-231).
        budget.note_stop(PLIST_NESTING_BOUND);
        return json!({
            "byte_length": bytes.len(),
            "hex_preview": hex::encode(&bytes[..std::cmp::min(DATA_PREVIEW_BYTES, bytes.len())]),
            "note": format!(
                "a binary plist nested {depth} levels deep, at the nesting bound \
                 ({MAX_NESTED_PLIST_DEPTH}); not opened"
            ),
        });
    }
    json!(format!(
        "<data {} bytes: {}>",
        bytes.len(),
        hex::encode(&bytes[..std::cmp::min(DATA_PREVIEW_BYTES, bytes.len())])
    ))
}

/// A record stating that a property list was located but **not** parsed.
///
/// Forensic meaning: plists carry account identities, device configuration and
/// app state. When one is skipped, the examiner must be able to see that it was
/// skipped — a silent empty result makes "too large to read" and "the file held
/// nothing" render identically, and only one of those is a finding.
fn skipped_marker(
    artifact: &Artifact,
    name: &str,
    status: &str,
    reason: IncompleteReason,
    message: &str,
    declared_size: u64,
) -> Artifact {
    let metadata = json!({
        "type": "PlistParseStatus",
        "subtype": "plist_not_parsed",
        "status": status,
        "content_incomplete": true,
        "content_incomplete_reason": reason.as_str(),
        // The sentence has to land on the key the examiner-facing reader shows.
        // `frontend/src/lib/incompleteness.ts` keys it off `<flag>_detail` and
        // reads nothing named `message`, so without this the person the stamp
        // exists for meets the machine token alone and never learns WHICH plist
        // was skipped or why. `message` is kept beside it for existing readers.
        "content_incomplete_detail": message,
        "file_name": name,
        "declared_size": declared_size,
        "max_size": MAX_PLIST_BYTES,
        "message": message,
        "name": format!("Plist not parsed: {name}"),
    });
    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
        .with_parent(artifact.id)
}
/// How much serialised JSON a record may carry as `content`.
const CONTENT_CAP_BYTES: usize = 100_000;

/// How much serialised JSON a record's preview may carry.
const PREVIEW_CAP_BYTES: usize = 8_000;

/// A preview of a parsed plist: the first keys that fit inside `cap`, in the
/// file's own order, with a value too large for what is left replaced by a
/// marker naming its size.
///
/// Every key met is named even when its value is left out, because "this file
/// has a `PictureData` key" and "this file does not" are different findings and
/// a preview that silently drops the key makes them look the same.
fn preview_of(
    object: &serde_json::Map<String, serde_json::Value>,
    cap: usize,
) -> serde_json::Value {
    const MAX_KEYS: usize = 10;
    let mut preview = serde_json::Map::new();
    let mut budget = cap;
    let mut omitted = 0usize;
    for (key, value) in object.iter().take(MAX_KEYS) {
        match measure_json_to_cap(value, budget) {
            Some(len) => {
                budget = budget.saturating_sub(len);
                preview.insert(key.clone(), value.clone());
            }
            None => {
                omitted += 1;
                preview.insert(
                    key.clone(),
                    json!({
                        "$omitted": "this value is larger than the preview; the record's \
                                     content was too large to carry and this is a sketch of it"
                    }),
                );
            }
        }
    }
    if object.len() > MAX_KEYS {
        preview.insert(
            "$keys_not_shown".to_string(),
            json!(object.len() - MAX_KEYS),
        );
    }
    if omitted > 0 {
        preview.insert("$values_omitted".to_string(), json!(omitted));
    }
    serde_json::Value::Object(preview)
}

/// How many values a resolved keyed archive may hold.
///
/// Sized to what a record can carry: the resolved form is discarded above
/// [`CONTENT_CAP_BYTES`], so resolving far past that is work nothing reads —
/// and on a folder of compiled `.nib` files it was about 45 MB of transient
/// allocation per file, tens of files a second, which is how an ingest reached
/// 28 GB resident (`HUNT-112`). A truncated resolution says so in the record.
const RESOLVE_NODE_BUDGET: usize = 20_000;

/// Serialised length of `value`, or `None` once it passes `cap`.
///
/// Serialises into a counting sink that stops at the cap, so an enormous value
/// is never materialised as a string merely to find out that it is enormous.
fn measure_json_to_cap(value: &serde_json::Value, cap: usize) -> Option<usize> {
    struct Counter {
        written: usize,
        cap: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written += buf.len();
            if self.written > self.cap {
                return Err(std::io::Error::other("over cap"));
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { written: 0, cap };
    match serde_json::to_writer(&mut counter, value) {
        Ok(()) => Some(counter.written),
        Err(_) => None,
    }
}
